import type { Account } from "../config";

export type ToolKind = "read" | "edit" | "command" | "search" | "web" | "other";

interface Diff {
  path: string;
  unified?: string; // unified diff when the CLI provides one
  before?: string; // otherwise old/new text (Edit) or new content (Write)
  after?: string;
}

export interface ToolCall {
  id: string;
  name: string;
  kind: ToolKind;
  title: string; // one line for the timeline, e.g. "Edit src/a.ts" or "$ bun test"
  path?: string;
  paths?: string[]; // every file an edit touches (absolute or workspace-relative)
  command?: string;
  host?: string; // a sandboxed command reaching the network
  outbound?: Outbound; // a web tool: what would leave the machine, and where to
  diff?: Diff;
}

/** A web fetch or search, shown in full before it's approved. */
export interface Outbound {
  host: string; // destination ("web search" for searches)
  url?: string; // full URL, query string included
  text?: string; // what else goes with it: the fetch prompt, or the search query
  findings?: string[]; // guard categories found in url/text (secrets, identifiers)
  placeholders?: number; // [HIB…] placeholders in it; they leave as placeholders, never as real values
}

export type AgentEvent =
  | { type: "session"; nativeId: string }
  | { type: "text"; delta: string }
  | { type: "tool_call"; call: ToolCall }
  | { type: "tool_result"; id: string; ok: boolean; output?: string }
  | { type: "permission"; id: string; call: ToolCall; ruleKey: string; input?: unknown } // driver waits for answer()
  | { type: "usage"; in: number; out: number }
  | { type: "quota"; window: string; usedPct: number; resetsAt?: number }
  | { type: "rate_limited"; message: string; resetsAt?: number }
  | { type: "error"; message: string }
  | { type: "turn_done" };

export type Decision = { behavior: "allow"; updatedInput?: unknown } | { behavior: "deny"; message: string };

export interface StartOptions {
  cwd: string;
  model: string;
  account: Account;
  resume?: string; // native session/thread id
  system?: string;
  askReads?: boolean; // sensitive workspaces: file reads need approval too
  mcp?: McpServer; // hib's own tools (the advisor), launched by the CLI
  sandbox?: Sandbox; // OS-level confinement for the agent's commands
  denyReads?: string[]; // absolute paths the CLI's own file tools may never read (they run outside the sandbox)
}

/** What the agent's commands (and every process they start) may not touch, whatever is approved. */
export interface Sandbox {
  denyRead: string[]; // absolute paths: hib's home, credentials, other accounts' logins
}

export interface McpServer {
  name: string;
  command: string;
  args: string[];
  env: Record<string, string>;
}

/** A long-lived agent CLI process for one workspace session. */
export interface AgentDriver {
  readonly provider: string;
  start(opts: StartOptions): Promise<void>;
  /** Runs one user turn; yields until turn_done. Permission events block the CLI until answer(). */
  turn(text: string): AsyncIterable<AgentEvent>;
  answer(permissionId: string, decision: Decision): void;
  interrupt(): Promise<void>;
  close(): Promise<void>;
  readonly alive: boolean;
}

/**
 * Key for "always allow" rules. A plain command is keyed by its program; anything compound
 * (pipes, chains, substitutions, redirects) only matches itself, so `cat x; rm -rf y` never rides on "cat".
 */
const RUNS_ARBITRARY = /^(python[\d.]*|pypy\d*|node|nodejs|bun|bunx|deno|npx|ruby|perl|php|lua|tclsh|osascript|sh|bash|zsh|dash|ksh|fish|env|xargs|find|awk|gawk|sed|nice|nohup|time|timeout|watch|command|exec|eval|source|busybox|sudo|doas)$/;

export function commandRuleKey(prefix: string, command: string): string {
  const cmd = command.trim();
  if (/[;&|`$<>\n\\]|\(/.test(cmd)) return `${prefix}:exact:${cmd}`;
  // Interpreters and wrappers run whatever their arguments say ("python -c …", "env sh", "xargs rm"), so a program-level
  // rule would cover arbitrary code: "always" for these matches only the exact command line.
  if (RUNS_ARBITRARY.test(cmd.split(/\s+/)[0]?.replace(/^.*\//, "") ?? "")) return `${prefix}:exact:${cmd}`;
  // Program plus subcommand ("git status", "bun test"), so allowing one subcommand never covers "git push".
  const [prog, sub] = cmd.split(/\s+/);
  return `${prefix}:${prog ?? ""}${sub && /^[a-z][\w:-]*$/i.test(sub) ? ` ${sub}` : ""}`;
}

export const short = (s: string, n = 120) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
