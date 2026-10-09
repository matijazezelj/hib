import { accountEnv } from "../providers/spawn";
import type { AgentDriver, AgentEvent, Decision, StartOptions, ToolCall } from "./driver";
import { commandRuleKey, short } from "./driver";
import { Queue } from "./queue";

/**
 * Codex via `codex app-server` (JSON-RPC over stdio). Commands and patches run in the workspace-write
 * sandbox with approvalPolicy "untrusted", so each one is sent to hib for approval.
 */
// Items that are conversation, not actions.
const QUIET_ITEMS = new Set(["userMessage", "agentMessage", "reasoning", "plan", "contextCompaction", "hookPrompt", "enteredReviewMode", "exitedReviewMode", "commandExecution", "fileChange", "mcpToolCall"]);

export function describeOther(it: any): ToolCall {
  if (it.type === "webSearch") {
    const a = it.action ?? {};
    const what = a.type === "openPage" ? `open ${a.url ?? ""}` : a.type === "findInPage" ? `find "${a.pattern ?? ""}" in ${a.url ?? ""}` : `search "${(a.queries ?? [a.query ?? it.query]).filter(Boolean).join('", "')}"`;
    return { id: it.id, name: "webSearch", kind: "web", title: `web ${short(what)}` };
  }
  if (it.type === "imageView") return { id: it.id, name: "imageView", kind: "read", title: `View image ${it.path ?? ""}`, path: it.path };
  return { id: it.id, name: it.type, kind: "other", title: `${it.type}${it.tool ? ` ${it.tool}` : it.name ? ` ${it.name}` : ""}` };
}

export class CodexDriver implements AgentDriver {
  readonly provider = "codex";
  private proc?: ReturnType<typeof Bun.spawn>;
  private nextId = 1;
  private calls = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void }>();
  private serverRequests = new Map<string, number | string>(); // permission id -> JSON-RPC id
  private fileItems = new Map<string, ToolCall>();
  private threadId?: string;
  private turnId?: string;
  private q?: Queue<AgentEvent>;
  private opts!: StartOptions;

  private send(m: unknown) {
    const stdin = this.proc!.stdin as any;
    stdin.write(JSON.stringify(m) + "\n");
    stdin.flush();
  }

  private request<T = any>(method: string, params: unknown): Promise<T> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.calls.set(id, { resolve, reject });
      this.send({ id, method, params });
    });
  }

  async start(opts: StartOptions) {
    this.opts = opts;
    const args = ["codex", "app-server", "--listen", "stdio://"];
    if (opts.mcp) {
      const k = `mcp_servers.${opts.mcp.name}`;
      const env = Object.entries(opts.mcp.env).map(([n, v]) => `${n}=${JSON.stringify(v)}`).join(", ");
      args.push("-c", `${k}.command=${JSON.stringify(opts.mcp.command)}`, "-c", `${k}.args=${JSON.stringify(opts.mcp.args)}`, "-c", `${k}.env={${env}}`, "-c", `${k}.tool_timeout_sec=600`, "-c", `${k}.default_tools_approval_mode="approve"`);
    }
    if (opts.sandbox) {
      // A permission profile on top of Codex's workspace sandbox (writes in the folder, no network) that also hides
      // hib's home and credentials from commands. Replaces the thread's sandbox mode (the two can't both be set).
      const deny = opts.sandbox.denyRead.map((p) => `${JSON.stringify(p)}="deny"`).join(", ");
      args.push("-c", 'default_permissions="hib"', "-c", 'permissions.hib.extends=":workspace"', "-c", `permissions.hib.filesystem={${deny}}`);
    }
    this.proc = Bun.spawn(args, { cwd: opts.cwd, env: accountEnv(opts.account), stdin: "pipe", stdout: "pipe", stderr: "pipe" });
    this.readLoop();
    new Response(this.proc.stderr as ReadableStream).text().catch(() => {}); // tracing logs; drained, not fatal
    await this.request("initialize", { clientInfo: { name: "hib", title: "hib", version: "0.1" }, capabilities: { experimentalApi: false, requestAttestation: false } });
    this.send({ method: "initialized" });
    const params = { model: opts.model, cwd: opts.cwd, approvalPolicy: "untrusted", ...(opts.sandbox ? {} : { sandbox: "workspace-write" }), ...(opts.system ? { developerInstructions: opts.system } : {}) };
    const r = opts.resume ? await this.request("thread/resume", { ...params, threadId: opts.resume, excludeTurns: true }) : await this.request("thread/start", params);
    this.threadId = r.thread.id;
  }

  private async readLoop() {
    const dec = new TextDecoder();
    let buf = "";
    for await (const chunk of this.proc!.stdout as ReadableStream<Uint8Array>) {
      buf += dec.decode(chunk, { stream: true });
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (!line) continue;
        let m: any;
        try {
          m = JSON.parse(line);
        } catch {
          continue;
        }
        // Server ids start at 0: a message with both id and method is a request to us.
        if (m.id !== undefined && m.method) this.onServerRequest(m);
        else if (m.id !== undefined) {
          const c = this.calls.get(m.id);
          this.calls.delete(m.id);
          if (m.error) c?.reject(new Error(m.error.message ?? JSON.stringify(m.error)));
          else c?.resolve(m.result);
        } else if (m.method) this.onNotification(m.method, m.params ?? {});
      }
    }
    for (const c of this.calls.values()) c.reject(new Error("codex app-server exited"));
    this.q?.push({ type: "error", message: "codex app-server exited" });
    this.q?.end();
  }

  private onServerRequest(m: any) {
    const pid = `cx_${m.id}_${Date.now().toString(36)}`;
    if (m.method === "item/commandExecution/requestApproval") {
      const cmd: string = m.params.commandActions?.[0]?.command ?? m.params.command ?? "";
      this.serverRequests.set(pid, m.id);
      // A command asking for more than the sandbox gives (network, extra paths, running unsandboxed) is never a plain
      // command: kind "other" keeps auto mode and "always" rules from approving it. Codex 0.160 marks such a request
      // only with a `reason` ("May I run … outside the sandbox?"); plain approvals carry none.
      const widens = ["reason", "additionalPermissions", "networkApprovalContext", "sandboxPermissions"].some((k) => m.params[k] != null && m.params[k] !== "use_default");
      this.q?.push({
        type: "permission",
        id: pid,
        call: widens
          ? { id: m.params.itemId, name: "shell", kind: "other", title: `$ ${short(cmd)} (asks to go beyond the sandbox${m.params.reason ? `: ${short(m.params.reason, 80)}` : ""})`, command: cmd }
          : { id: m.params.itemId, name: "shell", kind: "command", title: `$ ${short(cmd)}`, command: cmd },
        ruleKey: widens ? `command:exact:widen:${cmd}` : commandRuleKey("command", cmd),
      });
    } else if (m.method === "item/fileChange/requestApproval") {
      this.serverRequests.set(pid, m.id);
      const call = this.fileItems.get(m.params.itemId) ?? { id: m.params.itemId, name: "edit", kind: "edit" as const, title: "Edit files" };
      this.q?.push({ type: "permission", id: pid, call, ruleKey: "edit" });
    } else {
      // Unknown request types are refused rather than silently allowed.
      this.send({ id: m.id, error: { code: -32601, message: `hib does not handle ${m.method}` } });
    }
  }

  private onNotification(method: string, p: any) {
    const q = this.q;
    switch (method) {
      case "item/agentMessage/delta":
        q?.push({ type: "text", delta: p.delta });
        break;
      case "item/started": {
        const it = p.item;
        if (it.type === "commandExecution") {
          const cmd = it.commandActions?.[0]?.command ?? it.command;
          q?.push({ type: "tool_call", call: { id: it.id, name: "shell", kind: "command", title: `$ ${short(cmd)}`, command: cmd } });
        } else if (it.type === "fileChange") {
          const changes = it.changes ?? [];
          const paths = changes.map((c: any) => this.rel(c.path));
          const call: ToolCall = {
            id: it.id,
            name: "edit",
            kind: "edit",
            title: `${changes.some((c: any) => c.kind?.type === "add") ? "Write" : "Edit"} ${paths.join(", ")}`,
            path: paths[0],
            paths: changes.map((c: any) => c.path),
            // New files arrive as raw content; mark their lines as additions.
            diff: { path: paths[0] ?? "", unified: changes.map((c: any) => `--- ${this.rel(c.path)}\n+++ ${this.rel(c.path)}\n${c.kind?.type === "add" ? String(c.diff).replace(/\n$/, "").split("\n").map((l: string) => "+" + l).join("\n") : c.diff}`).join("\n") },
          };
          this.fileItems.set(it.id, call);
          q?.push({ type: "tool_call", call });
        } else if (it.type === "mcpToolCall") {
          q?.push({ type: "tool_call", call: { id: it.id, name: `${it.server}.${it.tool}`, kind: "other", title: `${it.server}.${it.tool}` } });
        } else if (it.id && !QUIET_ITEMS.has(it.type)) {
          // Anything else the agent does (web search, subagents, image tools…) must still show up in the egress log.
          q?.push({ type: "tool_call", call: describeOther(it) });
        }
        break;
      }
      case "item/completed": {
        const it = p.item;
        if (it.type === "commandExecution") q?.push({ type: "tool_result", id: it.id, ok: it.status === "completed" && it.exitCode === 0, output: it.status === "declined" ? "declined" : it.aggregatedOutput });
        else if (it.type === "fileChange") q?.push({ type: "tool_result", id: it.id, ok: it.status === "completed", output: it.status === "declined" ? "declined" : undefined });
        else if (it.type === "mcpToolCall") q?.push({ type: "tool_result", id: it.id, ok: it.status === "completed" });
        else if (it.id && !QUIET_ITEMS.has(it.type)) {
          // webSearch only knows its query once completed; re-send the call so the log has it.
          if (it.type === "webSearch") q?.push({ type: "tool_call", call: describeOther(it) });
          q?.push({ type: "tool_result", id: it.id, ok: !it.status || it.status === "completed" });
        }
        else if (it.type === "agentMessage" && it.phase === "commentary") q?.push({ type: "text", delta: "\n\n" });
        break;
      }
      case "turn/started":
        this.turnId = p.turn?.id;
        break;
      case "thread/tokenUsage/updated":
        if (p.tokenUsage?.last) q?.push({ type: "usage", in: p.tokenUsage.last.inputTokens ?? 0, out: (p.tokenUsage.last.outputTokens ?? 0) + (p.tokenUsage.last.reasoningOutputTokens ?? 0) });
        break;
      case "account/rateLimits/updated": {
        const rl = p.rateLimits ?? {};
        for (const w of [rl.primary, rl.secondary].filter(Boolean)) {
          const mins = w.windowDurationMins;
          const window = mins % 1440 === 0 ? `${mins / 1440}d` : mins % 60 === 0 ? `${mins / 60}h` : `${mins}m`;
          q?.push({ type: "quota", window, usedPct: (w.usedPercent ?? 0) / 100, resetsAt: w.resetsAt });
        }
        if (rl.rateLimitReachedType) q?.push({ type: "rate_limited", message: `codex limit reached: ${rl.rateLimitReachedType}` });
        break;
      }
      case "turn/completed":
        if (p.turn?.error) q?.push({ type: "error", message: p.turn.error.message ?? "turn failed" });
        q?.push({ type: "turn_done" });
        q?.end();
        this.q = undefined;
        break;
      case "error":
        if (!p.willRetry) q?.push({ type: "error", message: p.error?.message ?? "codex error" });
        break;
    }
  }

  private rel(p: string): string {
    return p.startsWith(this.opts.cwd + "/") ? p.slice(this.opts.cwd.length + 1) : p;
  }

  turn(text: string): AsyncIterable<AgentEvent> {
    const q = new Queue<AgentEvent>();
    this.q = q;
    q.push({ type: "session", nativeId: this.threadId! });
    this.request("turn/start", { threadId: this.threadId, input: [{ type: "text", text, text_elements: [] }] }).catch((e) => {
      q.push({ type: "error", message: e.message });
      q.end();
    });
    return q;
  }

  answer(permissionId: string, d: Decision) {
    const id = this.serverRequests.get(permissionId);
    if (id === undefined) return;
    this.serverRequests.delete(permissionId);
    this.send({ id, result: { decision: d.behavior === "allow" ? "accept" : "decline" } });
  }

  /** turn/interrupt, falling back to killing the process if the turn doesn't end (the thread resumes later). */
  async interrupt() {
    const q = this.q;
    setTimeout(() => {
      if (this.q === q && q) {
        this.proc?.kill();
        q.push({ type: "error", message: "interrupted" });
        q.end();
      }
    }, 5000);
    if (this.threadId && this.turnId) await Promise.race([this.request("turn/interrupt", { threadId: this.threadId, turnId: this.turnId }), Bun.sleep(5000)]).catch(() => {});
  }

  get alive() {
    return !!this.proc && this.proc.exitCode === null && !this.proc.killed;
  }

  async close() {
    if (!this.proc) return;
    this.proc.kill();
    await this.proc.exited;
  }
}
