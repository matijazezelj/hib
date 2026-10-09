import { accountEnv } from "../providers/spawn";
import { parseClaudeLine } from "../providers/claude-cli";
import type { AgentDriver, AgentEvent, Decision, StartOptions, ToolCall, ToolKind } from "./driver";
import { commandRuleKey, short } from "./driver";
import { Queue } from "./queue";

const SECRET_READS = ["~/.hib/**", "~/.claude/**", "~/.claude.json", "~/.claude-*/**", "~/.codex/**", "~/.ssh/**", "~/.aws/**", "~/.gnupg/**", "~/.config/gh/**"].map((p) => `Read(${p})`);

const GIT_WRITES = ["Edit(./.git/**)"]; // Edit rules cover every file-editing tool (Write, NotebookEdit)

const KIND: Record<string, ToolKind> = {
  Read: "read", Write: "edit", Edit: "edit", NotebookEdit: "edit", Bash: "command",
  Grep: "search", Glob: "search", WebFetch: "web", WebSearch: "web",
};

function describe(id: string, name: string, input: any, cwd: string): ToolCall {
  const rel = (p?: string) => (p && p.startsWith(cwd + "/") ? p.slice(cwd.length + 1) : p);
  const kind = KIND[name] ?? "other";
  const path = rel(input?.file_path ?? input?.notebook_path ?? input?.path);
  const call: ToolCall = { id, name, kind, title: name };
  if (name === "Bash") Object.assign(call, { command: input.command, title: `$ ${short(input.command ?? "")}` });
  // A sandboxed command reaching a host for the first time.
  else if (name === "SandboxNetworkAccess") Object.assign(call, { kind: "web", host: String(input?.host ?? ""), title: `Network: ${short(String(input?.host ?? "?"))}` });
  else if (name === "Grep" || name === "Glob") call.title = `${name} ${short(input.pattern ?? "")}${path ? ` in ${path}` : ""}`;
  else if (path) Object.assign(call, { path, title: `${name} ${path}` });
  else if (name === "WebFetch" && input?.url) {
    const url = String(input.url);
    let host = "";
    try {
      host = new URL(url).host;
    } catch {}
    Object.assign(call, { title: `WebFetch ${host || short(url)}`, outbound: { host: host || "(unparseable URL)", url, text: input.prompt ? String(input.prompt) : undefined } });
  } else if (name === "WebSearch" && input?.query) {
    const domains = [...(input.allowed_domains ?? [])].join(", ");
    Object.assign(call, { title: `WebSearch ${short(String(input.query))}`, outbound: { host: domains ? `web search (${domains})` : "web search", text: String(input.query) } });
  } else if (input?.url || input?.query) call.title = `${name} ${short(input.url ?? input.query)}`;
  const absPath = input?.file_path ?? input?.notebook_path;
  if (kind === "edit" && absPath) call.paths = [absPath];
  if (name === "Edit") call.diff = { path: path ?? "", before: input.old_string, after: input.new_string };
  if (name === "Write") call.diff = { path: path ?? "", after: input.content };
  return call;
}

function resultText(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.map((c: any) => (c.type === "text" ? c.text : "")).join("");
  return "";
}

/**
 * Claude Code as a long-lived stream-json process. `--permission-prompt-tool stdio` routes every
 * permission prompt to us as a `can_use_tool` control request (without it they are denied silently).
 */
export class ClaudeDriver implements AgentDriver {
  readonly provider = "claude";
  private proc?: ReturnType<typeof Bun.spawn>;
  private q?: Queue<AgentEvent>;
  private requests = new Map<string, { requestId: string; input: unknown }>();
  private cwd = "";

  private send(m: unknown) {
    const stdin = this.proc!.stdin as any;
    stdin.write(JSON.stringify(m) + "\n");
    stdin.flush();
  }

  async start(opts: StartOptions) {
    this.cwd = opts.cwd;
    const args = [
      "claude", "-p",
      "--input-format", "stream-json", "--output-format", "stream-json", "--verbose", "--include-partial-messages",
      "--model", opts.model,
      "--permission-prompts", "host", "--permission-prompt-tool", "stdio",
    ];
    if (opts.resume) args.push("--resume", opts.resume);
    if (opts.system) args.push("--append-system-prompt", opts.system);
    // Agents never read hib's or the CLIs' credentials, whatever else is allowed.
    // Nor do they write git internals (hooks and config run outside any sandbox); Claude checks this itself too.
    // Web tools send data off the machine: they always come to hib for approval, whatever allow rules or pre-approved
    // sites the user's own Claude settings have (ask rules win over allow rules).
    // `//` makes a rule path absolute; each entry may be a file or a folder.
    const denyReads = (opts.denyReads ?? []).flatMap((p) => [`Read(/${p})`, `Read(/${p}/**)`]);
    const permissions: Record<string, string[]> = { deny: [...SECRET_READS, ...denyReads, ...GIT_WRITES], ask: ["WebFetch", "WebSearch"] };
    if (opts.askReads) {
      // Reads (and read-only Bash like `cat`) are normally auto-allowed; asking shows every file before its content leaves.
      permissions.ask = ["Read", "Grep", "Glob", "NotebookRead", "Bash", "Task", "Agent", "WebFetch", "WebSearch"];
      // Repo-committed .claude settings (allow rules, hooks) and MCP servers can't loosen a sensitive session.
      args.push("--setting-sources", "user", "--strict-mcp-config");
    }
    if (opts.mcp) {
      const { name, ...server } = opts.mcp;
      args.push("--mcp-config", JSON.stringify({ mcpServers: { [name]: { type: "stdio", ...server } } }));
      permissions.allow = [`mcp__${name}`]; // hib's own tool: no prompt
    }
    // Claude Code's Bash sandbox (Seatbelt on macOS, bubblewrap on Linux) confines every command and whatever it starts:
    // writes stay in the folder, the network is closed, and the denied paths can't be read. Approval still goes through hib
    // (autoAllowBashIfSandboxed off), and a command can't ask to leave the sandbox (allowUnsandboxedCommands off).
    const sandbox = opts.sandbox
      ? { enabled: true, failIfUnavailable: true, autoAllowBashIfSandboxed: false, allowUnsandboxedCommands: false, filesystem: { denyRead: opts.sandbox.denyRead }, network: { allowedDomains: [] } }
      : undefined;
    args.push("--settings", JSON.stringify({ permissions, ...(sandbox ? { sandbox } : {}) }));
    this.proc = Bun.spawn(args, { cwd: opts.cwd, env: accountEnv(opts.account), stdin: "pipe", stdout: "pipe", stderr: "pipe" });
    this.readLoop();
  }

  private async readLoop() {
    const dec = new TextDecoder();
    let buf = "";
    const stderr = new Response(this.proc!.stderr as ReadableStream).text();
    for await (const chunk of this.proc!.stdout as ReadableStream<Uint8Array>) {
      buf += dec.decode(chunk, { stream: true });
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (!line) continue;
        try {
          this.onMessage(JSON.parse(line));
        } catch {}
      }
    }
    const err = (await stderr).trim();
    this.q?.push({ type: "error", message: err ? `claude exited: ${short(err, 400)}` : "claude exited" });
    this.q?.end();
  }

  private onMessage(m: any) {
    const q = this.q;
    if (!q) return;
    switch (m.type) {
      case "system":
        if (m.subtype === "init") q.push({ type: "session", nativeId: m.session_id });
        break;
      case "stream_event":
        for (const e of parseClaudeLine(m)) if (e.type === "text") q.push(e);
        break;
      case "assistant":
        for (const b of m.message?.content ?? []) if (b.type === "tool_use") q.push({ type: "tool_call", call: describe(b.id, b.name, b.input, this.cwd) });
        break;
      case "user":
        for (const b of Array.isArray(m.message?.content) ? m.message.content : [])
          if (b.type === "tool_result") q.push({ type: "tool_result", id: b.tool_use_id, ok: !b.is_error, output: short(resultText(b.content), 20_000) });
        break;
      case "rate_limit_event":
        for (const e of parseClaudeLine(m)) {
          if (e.type === "quota") q.push({ type: "quota", ...e.quota });
          if (e.type === "rate_limited") q.push({ type: "rate_limited", message: e.message ?? "rate limited", resetsAt: e.resetsAt });
        }
        break;
      case "control_request":
        if (m.request?.subtype === "can_use_tool") {
          const r = m.request;
          const pid = `cl_${m.request_id}`;
          this.requests.set(pid, { requestId: m.request_id, input: r.input });
          const call = describe(r.tool_use_id ?? pid, r.tool_name, r.input, this.cwd);
          const ruleKey =
            r.tool_name === "Bash"
              ? commandRuleKey("Bash", String(r.input?.command ?? ""))
              : KIND[r.tool_name] === "edit"
                ? "edit"
                : // "always" for a read covers that directory only
                  r.tool_name === "Read" && call.path
                  ? `read:${call.path.includes("/") ? call.path.slice(0, call.path.lastIndexOf("/")) : "."}`
                  : r.tool_name === "SandboxNetworkAccess"
                    ? `net:${r.input?.host ?? ""}` // "always" opens that host only
                    : r.tool_name === "WebFetch" && call.outbound
                      ? `WebFetch:${call.outbound.host}` // and fetches from that host only
                      : r.tool_name;
          q.push({ type: "permission", id: pid, call, ruleKey, input: r.input });
        } else this.send({ type: "control_response", response: { subtype: "error", request_id: m.request_id, error: `hib does not handle ${m.request?.subtype}` } });
        break;
      case "result":
        for (const e of parseClaudeLine(m)) if (e.type === "usage" || e.type === "error" || e.type === "rate_limited") q.push(e as AgentEvent);
        q.push({ type: "turn_done" });
        q.end();
        this.q = undefined;
        break;
    }
  }

  turn(text: string): AsyncIterable<AgentEvent> {
    this.q = new Queue<AgentEvent>();
    this.send({ type: "user", message: { role: "user", content: text }, parent_tool_use_id: null });
    return this.q;
  }

  answer(permissionId: string, d: Decision) {
    const r = this.requests.get(permissionId);
    if (!r) return;
    this.requests.delete(permissionId);
    const response = d.behavior === "allow" ? { behavior: "allow", updatedInput: d.updatedInput ?? r.input } : { behavior: "deny", message: d.message };
    this.send({ type: "control_response", response: { subtype: "success", request_id: r.requestId, response } });
  }

  /** Asks the CLI to stop; if the turn hasn't ended a few seconds later, kills it (the session resumes natively). */
  async interrupt() {
    const q = this.q;
    try {
      this.send({ type: "control_request", request_id: `int_${Date.now()}`, request: { subtype: "interrupt" } });
    } catch {}
    setTimeout(() => {
      if (this.q === q && q) {
        this.proc?.kill();
        q.push({ type: "error", message: "interrupted" });
        q.end();
      }
    }, 5000);
  }

  get alive() {
    return !!this.proc && this.proc.exitCode === null && !this.proc.killed;
  }

  async close() {
    if (!this.proc) return;
    try {
      (this.proc.stdin as any)?.end();
    } catch {}
    const t = setTimeout(() => this.proc?.kill(), 2000);
    await this.proc.exited;
    clearTimeout(t);
  }
}
