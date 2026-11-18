import { closeSync, constants, fstatSync, openSync, readSync, rmSync } from "node:fs";
import type { Stats } from "node:fs";
import { join } from "node:path";
import { accountEnv } from "../providers/spawn";
import { parseClaudeLine } from "../providers/claude-cli";
import type { AgentDriver, AgentEvent, Decision, StartOptions, ToolCall, ToolKind } from "./driver";
import { commandRuleKey, sessionFirst, short } from "./driver";
import { inScope } from "./scope";
import { Queue } from "./queue";

const SECRET_READS = ["~/.hib/**", "~/.claude/**", "~/.claude.json", "~/.claude-*/**", "~/.codex/**", "~/.ssh/**", "~/.aws/**", "~/.gnupg/**", "~/.config/gh/**"].map((p) => `Read(${p})`);

const GIT_WRITES = ["Edit(./.git/**)"]; // Edit rules cover every file-editing tool (Write, NotebookEdit)

const KIND: Record<string, ToolKind> = {
  Read: "read", Write: "edit", Edit: "edit", NotebookEdit: "edit", Bash: "command",
  Grep: "search", Glob: "search", WebFetch: "web", WebSearch: "web",
};

/** The key an "always" answer is stored under for this call. */
export function ruleKeyFor(name: string, input: any, call: ToolCall): string {
  return name === "Bash"
    ? commandRuleKey("Bash", String(input?.command ?? ""))
    : KIND[name] === "edit"
      ? "edit"
      : // "always" for a read covers that directory only
        name === "Read" && call.path
        ? `read:${call.path.includes("/") ? call.path.slice(0, call.path.lastIndexOf("/")) : "."}`
        : name === "SandboxNetworkAccess"
          ? `net:${input?.host ?? ""}` // "always" opens that host only
          : name === "WebFetch" && call.outbound
            ? `WebFetch:${call.outbound.host}` // and fetches from that host only
            : KIND[name]
              ? name
              : `${name}:exact:${short(JSON.stringify(input ?? null), 2000)}`; // MCP and unknown tools: "always" covers this exact call
}

export function describe(id: string, name: string, input: any, cwd: string): ToolCall {
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

/** The command line and environment a Claude session starts with. */
export function claudeLaunch(opts: StartOptions): { args: string[]; env: Record<string, string> } {
  const args = [
    "claude", "-p",
    "--input-format", "stream-json", "--output-format", "stream-json", "--verbose", "--include-partial-messages",
    "--model", opts.model,
    "--permission-prompts", "host", "--permission-prompt-tool", "stdio",
    // Ask mode whatever your settings' defaultMode says, and only your own settings: a repo's .claude/ settings could
    // add allow rules that decide calls before hib sees them, or hooks that run outside the sandbox.
    "--permission-mode", "manual", "--setting-sources", "user",
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
    // Sensitive sessions also ignore every MCP server but hib's own.
    args.push("--strict-mcp-config");
  }
  if (opts.mcp) {
    const { name, ...server } = opts.mcp;
    args.push("--mcp-config", JSON.stringify({ mcpServers: { [name]: { type: "stdio", ...server } } }));
    permissions.allow = [`mcp__${name}`]; // hib's own tool: no prompt
  }
  // A trusted MCP server reaches the agent only through hib's guard: the same server from the user's own config is denied.
  for (const n of opts.hideMcp ?? []) permissions.deny!.push(`mcp__${n}`);
  // Claude Code's Bash sandbox (Seatbelt on macOS, bubblewrap on Linux) confines every command and whatever it starts:
  // writes stay in the folder, the network is closed, and the denied paths can't be read. Approval still goes through hib
  // (autoAllowBashIfSandboxed off), and a command can't ask to leave the sandbox (allowUnsandboxedCommands off).
  // Sensitive sessions: commands write their output into the capture folder (see wrapCommand), the only place outside
  // the workspace they may write.
  const allowWrite = opts.captureDir ? { allowWrite: [opts.captureDir] } : {};
  const sandbox = opts.sandbox
    ? { enabled: true, failIfUnavailable: true, autoAllowBashIfSandboxed: false, allowUnsandboxedCommands: false, filesystem: { denyRead: opts.sandbox.denyRead, ...(opts.sandbox.allowRead ? { allowRead: opts.sandbox.allowRead } : {}), ...allowWrite }, network: { allowedDomains: [] } }
    : undefined;
  if (opts.captureDir) {
    // The file tools can't read raw output there (a command can: its own output is captured and guarded in turn), and
    // Monitor, which streams a command's output to the model as it comes, isn't available.
    permissions.deny!.push(`Read(/${opts.captureDir})`, `Read(/${opts.captureDir}/**)`, "Monitor");
  }
  const env = accountEnv(opts.account);
  // Sensitive sessions don't load or write auto-memory: notes from earlier work (names, case details) would go out
  // unguarded in every session, and the agent could write new ones. Both switches, as Claude Code checks either.
  const memory = opts.askReads ? { autoMemoryEnabled: false } : {};
  if (opts.askReads) env.CLAUDE_CODE_DISABLE_AUTO_MEMORY = "1";
  args.push("--settings", JSON.stringify({ permissions, ...memory, ...(sandbox ? { sandbox } : {}) }));
  return { args, env: sessionFirst(env, opts.session) };
}

/**
 * Claude Code as a long-lived stream-json process. `--permission-prompt-tool stdio` routes every
 * permission prompt to us as a `can_use_tool` control request (without it they are denied silently).
 */
export class ClaudeDriver implements AgentDriver {
  readonly provider = "claude";
  private proc?: ReturnType<typeof Bun.spawn>;
  private q?: Queue<AgentEvent>;
  private requests = new Map<string, { requestId: string; input: unknown; tool?: string; useId?: string }>();
  private controls = new Map<string, (response: any) => void>(); // control requests hib sent, by request_id
  private outputs = new Map<string, { requestId: string; response: any }>(); // hook calls waiting for answerOutput()
  private captureDir?: string;
  private pins = new Map<string, { dev: number; ino: number }>(); // capture files hib made, by tool_use_id
  private cwd = "";

  private send(m: unknown) {
    const stdin = this.proc!.stdin as any;
    stdin.write(JSON.stringify(m) + "\n");
    stdin.flush();
  }

  async start(opts: StartOptions) {
    this.cwd = opts.cwd;
    this.captureDir = opts.captureDir;
    const { argv: args, env } = (({ args, env }) => inScope(args, env, opts.scope))(claudeLaunch(opts));
    this.proc = Bun.spawn(args, { cwd: opts.cwd, env, stdin: "pipe", stdout: "pipe", stderr: "pipe" });
    this.readLoop();
    if (opts.captureDir) await this.registerOutputHook();
  }

  /**
   * Sensitive sessions: hib's PostToolUse hook, registered over the control channel so it runs in the daemon, gets each
   * command's captured output to guard. Without it confirmed, the session doesn't start: commands would still write
   * only to the capture folder, but the agent would see none of their output.
   */
  private async registerOutputHook() {
    const id = `init_${crypto.randomUUID()}`;
    const reply = new Promise<any>((resolve, reject) => {
      this.controls.set(id, resolve);
      setTimeout(() => reject(new Error("no answer to initialize")), 30_000).unref?.();
    });
    this.send({ type: "control_request", request_id: id, request: { subtype: "initialize", hooks: { PostToolUse: [{ matcher: "Bash", hookCallbackIds: [OUTPUT_HOOK], timeout: 600 }] } } });
    let r: any;
    try {
      r = await reply;
    } catch (e: any) {
      r = { subtype: "error", error: e?.message ?? String(e) };
    } finally {
      this.controls.delete(id);
    }
    if (r?.subtype !== "success" || r?.response?.hooks_applied !== true) {
      this.proc?.kill();
      throw new Error(`hib won't start a sensitive session without its command-output guard: Claude Code didn't register hib's output hook (${r?.error ?? "hooks_applied not confirmed"}). Check this Claude Code version with bun test/manual/output-guard-probe.ts`);
    }
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
    if (m.type === "control_response") {
      const id = m.response?.request_id;
      if (id) this.controls.get(id)?.(m.response);
      return;
    }
    const q = this.q;
    if (!q) {
      // A hook outside a turn (none expected): never leave the CLI waiting, and never pass output on unguarded.
      if (m.type === "control_request" && m.request?.subtype === "hook_callback") this.send({ type: "control_response", response: { subtype: "success", request_id: m.request_id, response: this.withheld(m.request?.input) } });
      return;
    }
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
          this.requests.set(pid, { requestId: m.request_id, input: r.input, tool: r.tool_name, useId: r.tool_use_id });
          const call = describe(r.tool_use_id ?? pid, r.tool_name, r.input, this.cwd);
          const ruleKey = ruleKeyFor(r.tool_name, r.input, call);
          q.push({ type: "permission", id: pid, call, ruleKey, input: r.input });
        } else if (m.request?.subtype === "hook_callback") {
          const input = m.request.input ?? {};
          const tr = input.tool_response;
          if (m.request.callback_id !== OUTPUT_HOOK || input.hook_event_name !== "PostToolUse" || input.tool_name !== "Bash" || !this.captureDir || !tr || typeof tr !== "object") {
            this.send({ type: "control_response", response: { subtype: "success", request_id: m.request_id, response: {} } });
            break;
          }
          const pid = `out_${m.request_id}`;
          this.outputs.set(pid, { requestId: m.request_id, response: tr });
          // What the command printed went to its capture file; what the tool itself returned is only the "[exit N]"
          // line, unless something wrote to the shell's own output: both are guarded.
          // A command still running in the background (it outlived its timeout) keeps its file: a later `cat` of it is
          // a command too, so its output comes back guarded.
          const useId = String(input.tool_use_id ?? "");
          const captured = readCapture(this.captureDir, useId, this.pins.get(useId), !tr.backgroundTaskId);
          if (!tr.backgroundTaskId) this.pins.delete(useId);
          const rest = [tr.stdout, tr.stderr].filter((x) => typeof x === "string" && x.trim()).join("\n");
          q.push({ type: "output", id: pid, callId: String(input.tool_use_id ?? ""), text: [captured, rest].filter(Boolean).join("\n") });
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
    let input: any = d.behavior === "allow" ? (d.updatedInput ?? r.input) : undefined;
    // Sensitive sessions: every command that runs, however it was allowed (asked, "always", auto), writes its output to
    // a capture file; the tool result carries only the exit status, and the hook gives the model the guarded output.
    if (input && this.captureDir && r.tool === "Bash" && typeof input === "object" && typeof input.command === "string") {
      const file = capturePath(this.captureDir, r.useId);
      try {
        this.pins.set(r.useId ?? "", makeCapture(file));
        input = { ...input, command: wrapCommand(input.command, file), run_in_background: false };
      } catch (e: any) {
        d = { behavior: "deny", message: `hib couldn't prepare this command's output capture (${e?.code ?? e?.message ?? e}), so it didn't run` };
        input = undefined;
      }
    }
    const response = d.behavior === "allow" ? { behavior: "allow", updatedInput: input } : { behavior: "deny", message: d.message };
    this.send({ type: "control_response", response: { subtype: "success", request_id: r.requestId, response } });
  }

  answerOutput(id: string, text: string) {
    const o = this.outputs.get(id);
    if (!o) return;
    this.outputs.delete(id);
    // The Bash result shape; a value Claude Code rejects is ignored, and then the model sees only "[exit N]".
    const out = { ...o.response, stdout: text, stderr: "", isImage: false };
    this.send({ type: "control_response", response: { subtype: "success", request_id: o.requestId, response: { hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: out } } } });
  }

  private withheld(input: any) {
    const tr = input?.tool_response;
    if (input?.tool_name !== "Bash" || !tr || typeof tr !== "object") return {};
    return { hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: { ...tr, stdout: "[hib withheld this output]", stderr: "", isImage: false } } };
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

const OUTPUT_HOOK = "hib_output";
const MAX_CAPTURE = 1 << 20; // bytes read from a capture file
const MAX_SHOWN = 60_000; // characters of it the model gets, before the guard runs

/** The capture file for one tool call: in hib's folder, named by the call's id (characters a shell won't read as syntax). */
export function capturePath(dir: string, useId?: string): string {
  const name = (useId ?? "").replace(/[^A-Za-z0-9_-]/g, "") || `call_${crypto.randomUUID().slice(0, 8)}`;
  return join(dir, name);
}

/**
 * The command as it runs in a sensitive session: one quoted string for `eval`, so nothing in it (a `)`, a heredoc) can
 * end hib's redirect early, run in a subshell, so `exit 3` ends only the command. Everything it prints goes to the capture
 * file; the tool's own output is just the exit status. A failing or killed command then shows the model nothing raw
 * (Claude Code passes a failed tool's output on without hooks), nor does Claude's transcript.
 */
export function wrapCommand(command: string, file: string): string {
  return `(\neval '${command.replaceAll("'", `'\\''`)}'\n) > '${file}' 2>&1\nprintf '[exit %s]\\n' "$?"`;
}

/** The capture file for a call, made by hib before the command runs: the one file readCapture will accept for it. */
export function makeCapture(path: string): { dev: number; ino: number } {
  rmSync(path, { force: true });
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    const st = fstatSync(fd);
    return { dev: st.dev, ino: st.ino };
  } finally {
    closeSync(fd);
  }
}

/** Cuts at the last line break before `max`, so a value on the cut line isn't halved (half an address would pass). */
function cutAtLine(text: string, max: number): string {
  if (text.length <= max) return text;
  const nl = text.lastIndexOf("\n", max);
  return text.slice(0, nl > 0 ? nl : 0);
}

/**
 * A capture file's text, then (unless `remove` is false) removed. It must be the file hib made for the call (`pin`:
 * same device and inode), opened without following a symlink, a regular file with one link, owned by this user, and is
 * capped in size: the command chose what to put at that path, and must not get hib to read a file the sandbox keeps from
 * it (a data file renamed onto it would otherwise pass every other check).
 */
export function readCapture(dir: string, useId: string | undefined, pin: { dev: number; ino: number } | undefined, remove = true): string {
  const path = capturePath(dir, useId);
  let fd: number | undefined;
  try {
    if (!pin) return "[hib withheld this output: the command didn't run through hib's capture]";
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const st: Stats = fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || st.dev !== pin.dev || st.ino !== pin.ino || (process.getuid && st.uid !== process.getuid()))
      return "[hib withheld this output: its capture file was replaced]";
    const buf = Buffer.alloc(Math.min(st.size, MAX_CAPTURE));
    const n = buf.length ? readSync(fd, buf, 0, buf.length, 0) : 0;
    let text = buf.subarray(0, n).toString("utf8");
    const cut = st.size > n || text.length > MAX_SHOWN;
    if (st.size > n) text = cutAtLine(text, text.length - 1); // the last line may be partial
    text = cutAtLine(text, MAX_SHOWN);
    return cut ? `${text}\n[hib cut the output here: ${st.size.toLocaleString("en")} bytes in all]` : text;
  } catch (e: any) {
    return e?.code === "ENOENT" ? "" : `[hib couldn't read this output: ${e?.code ?? "error"}]`;
  } finally {
    if (fd !== undefined) closeSync(fd);
    try {
      if (remove) rmSync(path, { force: true });
    } catch {}
  }
}
