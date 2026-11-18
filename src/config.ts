import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import type { Level } from "./guard/detectors";

export type TaskClass = "chat" | "code" | "review" | "long" | (string & {}); // plugins add more
export type Mode = "chat" | "agent";
type Tier = "fast" | "balanced" | "strong";

export interface Route {
  candidates: string[];
  mode: Mode;
  advisor: boolean;
  level: Level;
  ask: boolean; // always ask before sending on this route
}

export interface Account {
  id: string; // "claude@work"
  provider: string;
  name: string;
  env: Record<string, string>; // "" unsets the variable
  limits: Record<string, number>; // window ("5h", "7d") -> max requests, self-metered
  dirs: string[]; // agent-mode dirs that force this account
}

export interface GuardConfig {
  terms: string[];
  agentDirs: string[];
  askOn: string[]; // finding categories that trigger ask-first (prefix match, e.g. "DB" or "PRIVATE-KEY")
  askIfFindingsOver: number;
  approvalTimeoutSec: number;
  patterns: { category: string; regex: string; flags?: string }[]; // added by guard plugins
  ner: boolean; // local name/place/organisation detection (hib guard ner setup)
  nerIgnore: string[]; // words the NER should never treat as names
  nerBudgetSec: number; // time for name detection per request; what it doesn't reach is tokenised whole, and hib asks
}

export interface EventsConfig {
  enabled: boolean;
  dir: string; // event files only: a log collector mounts this directory alone
  maxMb: number;
  keep: number;
  heartbeatSec: number; // daemon.alive every this many seconds; 0 = off
  // How much of each identifying field to log. profile "local" (default) logs each whole, "siem" coarsens all five;
  // a setting given on its own overrides the profile.
  profile?: "local" | "siem";
  workspace?: "path" | "name" | "hash"; // the root path, its last folder name, or a keyed hash of the path
  account?: "name" | "hash"; // claude@work, or claude@<keyed hash of "work">
  netHost?: "full" | "domain"; // api.eu.example.com, or example.com (also cuts url to scheme://domain)
  command?: "full" | "program"; // the redacted command line, or only the program's name
  remote?: boolean; // false: auth.failure lines carry no peer address
  keyFile?: string; // the key for the hashes; it stays in hib's home, out of the events directory
  sessionScope?: boolean; // Linux: each agent CLI in a systemd user scope named after its session, for process telemetry
}

/**
 * A trusted read-only MCP server ([mcp.<name>]): the daemon is its only client and hands the agent its read-only tools
 * through hib's own MCP server, results guarded. Only entries with read_only = true are kept; others don't exist to hib.
 */
export interface McpUpstream {
  name: string; // [mcp.<name>]: the tools show up as mcp__hib__<name>__<tool>
  url: string; // streamable HTTP endpoint
  tokenFile?: string; // a bearer token: the whole file, or one KEY=VALUE line of it (tokenKey)
  tokenKey?: string;
  tokenEnv?: string; // or a variable in the daemon's environment
  sensitive: boolean; // offered in sensitive folders too
  tools: string[]; // optional globs that narrow the read-only tools further
}

export interface Config {
  home: string;
  port: number;
  switchAt: number;
  arenaRate: number;
  classifierModel: string;
  advisorModels: Record<string, string>; // provider -> model used when reviewing the other provider
  models: Record<string, Record<string, Tier>>; // provider -> model -> tier
  defaultAccount: Record<string, string>; // provider -> account name
  accounts: Account[];
  routes: Record<string, Route> & Record<"chat" | "code" | "review" | "long", Route>;
  guard: GuardConfig;
  events: EventsConfig;
  /** Acceptance tests only: the scripted agent (provider "script") and the folder its scripts are read from. */
  testing: { scriptDir?: string };
  mcp: McpUpstream[];
}

export const DEFAULT_TOML = `# hib config. Model ids: <provider>[@account]/<model>, e.g. claude@work/sonnet
port = 4141

[usage]
switchAt = 0.9          # move off an account at 90% of any quota window

[arena]
rate = 0.05             # chance a web/TUI request runs head-to-head

[classifier]
model = "claude/haiku"  # only consulted when the heuristics are unsure

[advisor]
claude = "claude/opus"          # reviews codex answers
codex = "codex/gpt-6-astra"     # reviews claude answers

[models.claude]
haiku = "fast"
sonnet = "balanced"
opus = "strong"

[models.codex]
"gpt-6-luna" = "fast"
"gpt-6.1-sol" = "balanced"
"gpt-6-astra" = "strong"

# Accounts: env is applied on top of a minimal environment; "" unsets a variable.
# Each CLAUDE_CONFIG_DIR / CODEX_HOME is a separate login and a separate quota.
[providers.claude]
default = "default"
[providers.claude.accounts.default]
env = { CLAUDE_CONFIG_DIR = "" }
# A second login, e.g. a work subscription:
# [providers.claude.accounts.work]
# env = { CLAUDE_CONFIG_DIR = "~/.claude-work" }
# limits = { "5h" = 200, "7d" = 2000 }   # optional self-metered request caps
# dirs = ["~/work"]                       # agent mode in these dirs always uses this account

[providers.codex]
default = "default"
[providers.codex.accounts.default]
env = { CODEX_HOME = "~/.codex" }

[routes.chat]
candidates = ["claude/haiku", "codex/gpt-6-luna"]
mode = "chat"
level = "paranoid"

[routes.code]
candidates = ["claude/sonnet", "codex/gpt-6.1-sol", "claude/opus"]
mode = "chat"
advisor = true
level = "standard"

[routes.review]
candidates = ["claude/opus", "codex/gpt-6-astra"]
mode = "chat"
level = "standard"

[routes.long]
candidates = ["claude/sonnet", "codex/gpt-6.1-sol"]
mode = "chat"
level = "standard"

[guard]
terms = []                      # extra sensitive words: company, clients, repo/org names, internal domains
agentDirs = []                  # dirs where agent mode may run
askOn = ["PRIVATE-KEY", "DB-URI", "AWS", "TERM"]
askIfFindingsOver = 10
approvalTimeoutSec = 300
ner = false                     # local name/place/company detection; run "hib guard ner setup" first
nerIgnore = []                  # words never treated as names (product or tech names)
nerBudgetSec = 120              # name detection time per request; free text it doesn't reach is tokenised whole

[events]
enabled = true                  # security events as JSON lines, for a log collector (SIB)
# dir = "~/.hib/events"         # holds event files only; never point it at ~/.hib itself
max_mb = 20                     # rotate events.jsonl at this size
keep = 5                        # rotated files kept: events.jsonl.1 … .5
heartbeat_sec = 300             # daemon.alive every 5 minutes, so a crash shows; 0 = off
# profile = "local"             # each field whole; "siem" coarsens all five below, for logs that leave this machine
# Or one at a time (overrides the profile):
# workspace = "path"            # "name": last folder only; "hash": keyed hash (same folder, same hash)
# account = "name"              # "hash": claude@<keyed hash>
# net_host = "full"             # "domain": registrable domain (Public Suffix List); url too
# command = "full"              # "program": a best-effort program label; loses the arguments detections use
# remote = true                 # false: no peer address on auth.failure
# session_scope = false         # Linux: run each agent CLI in a systemd user scope (hib-<session>-<n>.scope), so
#                               # Falco can tie its processes to the session by cgroup

# Trusted read-only MCP servers: hib's daemon calls them for the agent and guards every result. Only tools the server
# marks readOnlyHint are offered, without prompts. See the README, "Trusted read-only MCP servers".
# [mcp.oib]
# url = "http://127.0.0.1:3030/mcp"
# token_file = "~/oib/mcp/secrets/mcp.env"     # or token_env = "VAR"; never given to the agent
# token_key = "MCP_GRAFANA_SERVER_TOKEN"        # needed when the file has several KEY=VALUE lines
# read_only = true                              # required: without it hib ignores the entry
# sensitive = true                              # offer it in sensitive folders too (default false)
# tools = ["query_*", "search_*"]               # optional: narrows the read-only tools further
`;

function expandHome(p: string): string {
  return p.startsWith("~") ? join(homedir(), p.slice(1)) : p;
}

export function hibHome(): string {
  return expandHome(process.env.HIB_HOME ?? "~/.hib");
}

export function loadConfig(home = hibHome()): Config {
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const file = join(home, "config.toml");
  if (!existsSync(file)) {
    writeFileSync(file, DEFAULT_TOML);
    chmodSync(file, 0o600);
  }
  return parseConfig(Bun.TOML.parse(readFileSync(file, "utf8")) as any, home);
}

export function parseConfig(raw: any, home: string): Config {
  const accounts: Account[] = [];
  const defaultAccount: Record<string, string> = {};
  const scriptDir = typeof raw.testing?.script_dir === "string" && raw.testing.script_dir ? expandHome(raw.testing.script_dir) : undefined;
  for (const [provider, p] of Object.entries<any>(raw.providers ?? {})) {
    if (provider === "script") continue; // only [testing] script_dir makes the scripted agent, never a providers entry
    defaultAccount[provider] = p.default ?? "default";
    for (const [name, a] of Object.entries<any>(p.accounts ?? { default: {} })) {
      const env: Record<string, string> = {};
      for (const [k, v] of Object.entries<any>(a.env ?? {})) env[k] = v === "" ? "" : expandHome(String(v));
      accounts.push({
        id: `${provider}@${name}`,
        provider,
        name,
        env,
        limits: a.limits ?? {},
        dirs: (a.dirs ?? []).map(expandHome),
      });
    }
  }
  const route = (r: any): Route => ({
    candidates: r?.candidates ?? [],
    mode: r?.mode === "agent" ? "agent" : "chat",
    advisor: !!r?.advisor,
    level: r?.level ?? "standard",
    ask: !!r?.ask,
  });
  const g = raw.guard ?? {};
  const ev = raw.events ?? {};
  const eventsDir = resolve(expandHome(ev.dir ?? join(home, "events")));
  // The collector mounts this directory: if it were hib's home (or held it), the token, vault key and database would go too.
  const rel = relative(eventsDir, resolve(home));
  if (rel === "" || (!rel.startsWith("..") && !isAbsolute(rel))) throw new Error(`[events] dir ${eventsDir} must not be or contain hib's home (${home}): use a directory of its own`);
  const profile = oneOf("profile", ev.profile, ["local", "siem"] as const, "local");
  const siem = profile === "siem";
  return {
    home,
    port: raw.port ?? 4141,
    switchAt: raw.usage?.switchAt ?? 0.9,
    arenaRate: raw.arena?.rate ?? 0,
    classifierModel: raw.classifier?.model ?? "claude/haiku",
    advisorModels: Object.fromEntries(Object.entries<any>(raw.advisor ?? {}).filter(([k]) => k !== "script")),
    models: raw.models ?? {},
    defaultAccount,
    accounts: scriptDir ? [...accounts, { id: "script@default", provider: "script", name: "default", env: {}, limits: {}, dirs: [] }] : accounts,
    testing: { scriptDir },
    mcp: mcpServers(raw.mcp),
    routes: {
      chat: route(raw.routes?.chat),
      code: route(raw.routes?.code),
      review: route(raw.routes?.review),
      long: route(raw.routes?.long ?? raw.routes?.code),
    },
    guard: {
      terms: g.terms ?? [],
      agentDirs: (g.agentDirs ?? []).map(expandHome),
      askOn: g.askOn ?? [],
      askIfFindingsOver: g.askIfFindingsOver ?? 10,
      approvalTimeoutSec: g.approvalTimeoutSec ?? 300,
      patterns: [],
      ner: !!g.ner,
      nerIgnore: g.nerIgnore ?? [],
      nerBudgetSec: g.nerBudgetSec ?? 120,
    },
    events: {
      enabled: ev.enabled ?? true,
      dir: eventsDir,
      maxMb: Number(ev.max_mb ?? 20),
      keep: Number(ev.keep ?? 5),
      heartbeatSec: Number(ev.heartbeat_sec ?? 300),
      profile,
      workspace: oneOf("workspace", ev.workspace, ["path", "name", "hash"] as const, siem ? "hash" : "path"),
      account: oneOf("account", ev.account, ["name", "hash"] as const, siem ? "hash" : "name"),
      netHost: oneOf("net_host", ev.net_host, ["full", "domain"] as const, siem ? "domain" : "full"),
      command: oneOf("command", ev.command, ["full", "program"] as const, siem ? "program" : "full"),
      remote: typeof ev.remote === "boolean" ? ev.remote : ev.remote === undefined ? !siem : bad("remote", ev.remote, ["true", "false"]),
      keyFile: join(home, "events.key"),
      sessionScope: typeof ev.session_scope === "boolean" ? ev.session_scope : ev.session_scope === undefined ? false : bad("session_scope", ev.session_scope, ["true", "false"]),
    },
  };
}

/** [mcp.<name>] entries with read_only = true; a malformed one stops config loading. */
function mcpServers(raw: any): McpUpstream[] {
  const out: McpUpstream[] = [];
  for (const [name, m] of Object.entries<any>(raw ?? {})) {
    const fail = (why: string): never => {
      throw new Error(`[mcp.${name}] ${why}`);
    };
    if (m?.read_only !== true) continue;
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(name) || name.includes("__") || name === "hib") fail("the name must be 1-32 letters, digits, - or _, without __, and not hib");
    let url: URL;
    try {
      url = new URL(String(m.url ?? ""));
    } catch {
      return fail("url must be an http(s) URL");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") fail("url must be an http(s) URL");
    if (url.username || url.password) fail("put the credential in token_file or token_env, not in the url");
    if (m.token_file !== undefined && m.token_env !== undefined) fail("use token_file or token_env, not both");
    if (m.token_key !== undefined && m.token_file === undefined) fail("token_key needs token_file");
    for (const k of ["token_file", "token_key", "token_env"]) if (m[k] !== undefined && (typeof m[k] !== "string" || !m[k])) fail(`${k} must be a non-empty string`);
    if (m.sensitive !== undefined && typeof m.sensitive !== "boolean") fail("sensitive must be true or false");
    if (m.tools !== undefined && (!Array.isArray(m.tools) || !m.tools.every((t: unknown) => typeof t === "string" && t))) fail('tools must be a list of names or globs, like ["query_*"]');
    out.push({
      name,
      url: url.href,
      ...(m.token_file ? { tokenFile: expandHome(m.token_file) } : {}),
      ...(m.token_key ? { tokenKey: m.token_key } : {}),
      ...(m.token_env ? { tokenEnv: m.token_env } : {}),
      sensitive: m.sensitive === true,
      tools: m.tools ?? [],
    });
  }
  return out;
}

/** An [events] setting from its allowed values; unset gives the profile's default. */
function oneOf<T extends string>(key: string, v: unknown, allowed: readonly T[], dflt: T): T {
  if (v === undefined) return dflt;
  if (allowed.includes(v as T)) return v as T;
  return bad(key, v, allowed.map((a) => `"${a}"`));
}

function bad(key: string, v: unknown, allowed: string[]): never {
  throw new Error(`[events] ${key} = ${JSON.stringify(v)}: use ${allowed.join(", ")}`);
}

/** "claude@work/sonnet" | "claude/sonnet" -> parts; account falls back to the provider default. */
export function parseModelId(id: string, cfg: Config): { provider: string; account: string; model: string } | null {
  const m = /^([a-z0-9_-]+)(?:@([A-Za-z0-9_-]+))?\/(.+)$/.exec(id);
  if (!m) return null;
  const provider = m[1]!;
  const account = m[2] ?? cfg.defaultAccount[provider] ?? "default";
  return { provider, account, model: m[3]! };
}
