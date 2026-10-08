import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Level } from "./guard/detectors";

export type TaskClass = "chat" | "code" | "review" | "long" | (string & {}); // plugins add more
export type Mode = "chat" | "agent";
export type Tier = "fast" | "balanced" | "strong";

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
`;

export function expandHome(p: string): string {
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
  for (const [provider, p] of Object.entries<any>(raw.providers ?? {})) {
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
  return {
    home,
    port: raw.port ?? 4141,
    switchAt: raw.usage?.switchAt ?? 0.9,
    arenaRate: raw.arena?.rate ?? 0,
    classifierModel: raw.classifier?.model ?? "claude/haiku",
    advisorModels: raw.advisor ?? {},
    models: raw.models ?? {},
    defaultAccount,
    accounts,
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
    },
  };
}

/** "claude@work/sonnet" | "claude/sonnet" -> parts; account falls back to the provider default. */
export function parseModelId(id: string, cfg: Config): { provider: string; account: string; model: string } | null {
  const m = /^([a-z0-9_-]+)(?:@([A-Za-z0-9_-]+))?\/(.+)$/.exec(id);
  if (!m) return null;
  const provider = m[1]!;
  const account = m[2] ?? cfg.defaultAccount[provider] ?? "default";
  return { provider, account, model: m[3]! };
}
