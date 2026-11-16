import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, normalize, resolve } from "node:path";
import { describe, ruleKeyFor } from "./claude-driver";
import type { AgentDriver, AgentEvent, Decision, StartOptions } from "./driver";
import { Queue } from "./queue";

/**
 * A stand-in agent for acceptance tests, loaded only when `[testing] script_dir` is set. It replays a script of tool
 * calls through hib's real permission, data-rule, protected-file and home-watch paths, shaped exactly as Claude Code
 * shapes them, so the security events it causes are the ones a real session would write. No agent CLI runs: process
 * telemetry (Falco) sees nothing of it, and commands are never executed.
 *
 * The prompt names the script with `hib-script:<name>`; it is read from `<script_dir>/<name>.json`, an array of steps:
 *   { "say": "text" }                           assistant text
 *   { "edit": "path", "content": "..." }        Write, asks first; written if allowed
 *   { "command": "cat data.csv" }               Bash, asks first; never run
 *   { "network": "example.com" }                a sandboxed command reaching a new host, asks first
 *   { "fetch": "https://example.com/x" }        WebFetch, asks first; nothing is fetched
 *   { "write": "path", "content": "..." }       a write hib isn't asked about (as through a swapped symlink)
 * Paths are relative to the workspace, or "~/..." for the home folder; nothing else, and no "..".
 */
export class ScriptDriver implements AgentDriver {
  readonly provider = "script";
  private cwd = "";
  private waiters = new Map<string, (d: Decision) => void>();
  private n = 0;
  private closed = false;

  constructor(private dir: string, private home = homedir()) {}

  async start(o: StartOptions) {
    this.cwd = realpathSync(o.cwd);
  }

  get alive() {
    return !this.closed;
  }

  turn(prompt: string): AsyncIterable<AgentEvent> {
    const q = new Queue<AgentEvent>();
    q.push({ type: "session", nativeId: `script-${crypto.randomUUID().slice(0, 8)}` });
    this.run(prompt, q)
      .catch((e) => q.push({ type: "error", message: `script: ${e?.message ?? e}` }))
      .finally(() => {
        q.push({ type: "turn_done" });
        q.end();
      });
    return q;
  }

  answer(id: string, d: Decision) {
    this.waiters.get(id)?.(d);
    this.waiters.delete(id);
  }

  async interrupt() {
    for (const [id] of this.waiters) this.answer(id, { behavior: "deny", message: "interrupted" });
  }

  async close() {
    this.closed = true;
    await this.interrupt();
  }

  private load(prompt: string): Step[] {
    const m = /\bhib-script:([a-z0-9_-]{1,64})\b/.exec(prompt);
    if (!m) throw new Error("no hib-script:<name> in the message");
    const steps = JSON.parse(readFileSync(join(this.dir, `${m[1]}.json`), "utf8"));
    if (!Array.isArray(steps)) throw new Error(`${m[1]}.json is not an array of steps`);
    return steps;
  }

  /** A script path, absolute; only inside the workspace or the home folder. */
  private path(p: unknown): string {
    if (typeof p !== "string" || !p || p.split(/[\\/]/).includes("..")) throw new Error(`bad path ${JSON.stringify(p)}`);
    if (isAbsolute(p)) throw new Error(`absolute path ${p}: use a workspace-relative path or ~/...`);
    return p.startsWith("~/") ? normalize(join(this.home, p.slice(2))) : resolve(this.cwd, p);
  }

  private write(abs: string, content: unknown) {
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, String(content ?? ""));
  }

  /** One tool call through hib: asks, then reports the result the CLI would. */
  private async ask(q: Queue<AgentEvent>, name: string, input: any, perform: () => string): Promise<void> {
    const id = `sc_${++this.n}`;
    const call = describe(id, name, input, this.cwd);
    const decision = new Promise<Decision>((r) => this.waiters.set(id, r));
    q.push({ type: "permission", id, call, ruleKey: ruleKeyFor(name, input, call), input });
    const d = await decision;
    if (d.behavior === "deny") return void q.push({ type: "tool_result", id, ok: false, output: `denied: ${d.message}` });
    q.push({ type: "tool_call", call });
    q.push({ type: "tool_result", id, ok: true, output: perform() });
  }

  private async run(prompt: string, q: Queue<AgentEvent>) {
    for (const s of this.load(prompt)) {
      if (this.closed) return;
      if ("say" in s) q.push({ type: "text", delta: String(s.say) });
      else if ("edit" in s) {
        const abs = this.path(s.edit);
        await this.ask(q, "Write", { file_path: abs, content: String(s.content ?? "") }, () => (this.write(abs, s.content), "written"));
      } else if ("command" in s) await this.ask(q, "Bash", { command: String(s.command) }, () => "not run (script driver)");
      else if ("network" in s) await this.ask(q, "SandboxNetworkAccess", { host: String(s.network) }, () => "allowed (script driver)");
      else if ("fetch" in s) await this.ask(q, "WebFetch", { url: String(s.fetch), prompt: "" }, () => "not fetched (script driver)");
      else if ("write" in s) {
        const abs = this.path(s.write);
        this.write(abs, s.content);
      } else throw new Error(`unknown step ${JSON.stringify(s).slice(0, 80)}`);
    }
  }
}

type Step =
  | { say: string }
  | { edit: string; content?: string }
  | { command: string }
  | { network: string }
  | { fetch: string }
  | { write: string; content?: string };
