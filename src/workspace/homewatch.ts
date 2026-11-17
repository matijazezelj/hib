import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, readlinkSync, statSync, type Stats } from "node:fs";
import { join } from "node:path";

/**
 * Files in your home folder that run code or steer an agent outside any workspace: shell startup files, user-level
 * agent config and instructions, autostart and user services, git's global config (core.hooksPath), ssh's config and
 * authorized_keys. An agent can change them with its own file tools, which process telemetry (Falco) can't attribute
 * to a path, so each turn snapshots them and reports what changed. Report only: you edit these yourself, and hib
 * can't tell your edit in another terminal from the agent's, so nothing is put back.
 */
export const HOME_WATCH = [
  ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
  ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout",
  ".config/fish/config.fish", ".config/fish/conf.d",
  ".gitconfig", ".config/git/config",
  ".ssh/config", ".ssh/authorized_keys", ".ssh/rc",
  ".config/autostart", ".config/systemd/user", ".config/environment.d",
];
/** Watched inside each Claude config dir (~/.claude, and every account's CLAUDE_CONFIG_DIR). */
export const CLAUDE_WATCH = ["settings.json", "settings.local.json", "CLAUDE.md", "hooks", "agents", "commands", "skills"];
/** Watched inside each Codex home (~/.codex, and every account's CODEX_HOME). */
export const CODEX_WATCH = ["config.toml", "AGENTS.md", "hooks"];

/**
 * Keys a CLI rewrites in its own settings when you switch model, theme and the like in any session (/model, /config,
 * /advisor). A change to a settings file that touches only these is reported as preferences only; anything else in
 * the file (hooks, permissions, env, statusLine, MCP servers, apiKeyHelper, sandbox, model_provider) runs code,
 * grants access or redirects traffic, and keeps the change critical.
 */
export const CLAUDE_PREFS = ["model", "advisorModel", "theme", "tui", "agentPushNotifEnabled"];
export const CODEX_PREFS = ["model", "model_reasoning_effort"];

const MAX_ENTRIES = 5_000;
const MAX_DEPTH = 4; // also what stops a symlink loop
const MAX_FILE = 1 << 20; // larger files are compared by size and mtime
const MAX_TOTAL = 32 << 20; // bytes hashed per snapshot; past it, files are compared by size and mtime
const OVERFLOW = "(more files than hib checks)";

/** A fingerprint per path: content hash and mode, symlink target, or size+mtime for what isn't read. */
export type HomeSnapshot = Map<string, string>;
export interface HomeChange {
  path: string; // "~/.bashrc": relative to home, so no user name
  change: "added" | "changed" | "removed";
  prefs_only?: true; // a CLI settings file where only preference keys (CLAUDE_PREFS, CODEX_PREFS) changed
}
export interface HomeWatch {
  home: string;
  claudeDirs?: string[]; // absolute; ~/.claude is always included
  codexDirs?: string[]; // absolute; ~/.codex is always included
}

/** Settings files whose preference keys are told apart, by absolute path, with the keys to ignore and the parser. */
function prefsFiles(w: HomeWatch): Map<string, { keys: string[]; parse: (s: string) => unknown }> {
  const m = new Map<string, { keys: string[]; parse: (s: string) => unknown }>();
  for (const d of new Set([join(w.home, ".claude"), ...(w.claudeDirs ?? [])]))
    for (const f of ["settings.json", "settings.local.json"]) m.set(join(d, f), { keys: CLAUDE_PREFS, parse: JSON.parse });
  for (const d of new Set([join(w.home, ".codex"), ...(w.codexDirs ?? [])])) m.set(join(d, "config.toml"), { keys: CODEX_PREFS, parse: Bun.TOML.parse });
  return m;
}

/** JSON with sorted keys, so a rewrite that only reorders gives the same text. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as any)[k])}`).join(",")}}`;
  return JSON.stringify(v) ?? "null";
}

/** Hash of a settings file without its preference keys; undefined if it isn't a top-level object that parses. */
function coreHash(data: Buffer, f: { keys: string[]; parse: (s: string) => unknown }): string | undefined {
  try {
    const v = f.parse(data.toString("utf8"));
    if (!v || typeof v !== "object" || Array.isArray(v)) return undefined;
    const rest = Object.fromEntries(Object.entries(v).filter(([k]) => !f.keys.includes(k)));
    return createHash("sha256").update(canonical(rest)).digest("hex");
  } catch {
    return undefined;
  }
}

/** Every watched path, absolute. */
function roots(w: HomeWatch): string[] {
  const claude = new Set([join(w.home, ".claude"), ...(w.claudeDirs ?? [])]);
  const codex = new Set([join(w.home, ".codex"), ...(w.codexDirs ?? [])]);
  return [
    ...HOME_WATCH.map((r) => join(w.home, r)),
    ...[...claude].flatMap((d) => CLAUDE_WATCH.map((r) => join(d, r))),
    ...[...codex].flatMap((d) => CODEX_WATCH.map((r) => join(d, r))),
  ];
}

/**
 * Nothing found here makes this throw or block: unreadable entries and fifos are recorded without being opened.
 * Symlinks are recorded by target and followed (a stow-managed ~/.zshrc is edited through its link), up to MAX_DEPTH.
 */
export function homeSnapshot(w: HomeWatch): HomeSnapshot {
  const snap: HomeSnapshot = new Map();
  const prefs = prefsFiles(w);
  let budget = MAX_TOTAL;
  const stat = (p: string, follow: boolean): Stats | "unreadable" | undefined => {
    try {
      return (follow ? statSync : lstatSync)(p, { throwIfNoEntry: false });
    } catch {
      return "unreadable"; // EACCES on a parent, ELOOP
    }
  };
  const walk = (p: string, depth: number, key: string, follow = false): void => {
    if (snap.size >= MAX_ENTRIES) return void snap.set(OVERFLOW, "overflow");
    const st = stat(p, follow);
    if (!st) return follow ? void snap.set(key, "dangling") : undefined;
    if (st === "unreadable") return void snap.set(key, "unreadable");
    if (st.isSymbolicLink()) {
      let target = "?";
      try {
        target = readlinkSync(p);
      } catch {}
      snap.set(key, `link:${target}`);
      return depth < MAX_DEPTH ? walk(p, depth + 1, `${key} ->`, true) : undefined;
    }
    if (st.isDirectory()) {
      if (depth >= MAX_DEPTH) return void snap.set(key, `dir:${st.mtimeMs}`);
      let names: string[];
      try {
        names = readdirSync(p);
      } catch {
        return void snap.set(key, `unreadable-dir:${st.mode}:${st.mtimeMs}`);
      }
      for (const n of names) walk(join(p, n), depth + 1, join(key, n));
      return;
    }
    // fifos, sockets and devices are never opened (a fifo would block)
    if (!st.isFile()) return void snap.set(key, `special:${st.mode}:${st.mtimeMs}`);
    if (st.size > MAX_FILE || st.size > budget) return void snap.set(key, `big:${st.size}:${st.mtimeMs}:${st.mode}`);
    try {
      const data = readFileSync(p);
      budget -= data.length;
      const f = prefs.get(p);
      const core = f && coreHash(data, f);
      snap.set(key, `file:${st.mode & 0o7777}:${createHash("sha256").update(data).digest("hex")}${core ? `|core:${st.mode & 0o7777}:${core}` : ""}`);
    } catch {
      snap.set(key, `unreadable:${st.mode}:${st.mtimeMs}`);
    }
  };
  for (const p of roots(w)) walk(p, 0, p);
  return snap;
}

/**
 * A watched path as reported: "~/..." under home, "[CLI home]/..." for a config dir elsewhere; never a user name.
 * Content reached through a symlink is marked "(link target)".
 */
export function homePath(w: HomeWatch, p: string): string {
  if (p === OVERFLOW) return p;
  const followed = / ->(?=\/|$)/.test(p);
  const raw = p.replace(/ ->(?=\/|$)/g, "");
  const tail = followed ? " (link target)" : "";
  if (raw.startsWith(w.home + "/")) return `~/${raw.slice(w.home.length + 1)}${tail}`;
  for (const d of [...(w.claudeDirs ?? []), ...(w.codexDirs ?? [])]) if (raw.startsWith(d + "/")) return `[CLI home]/${raw.slice(d.length + 1)}${tail}`;
  return `[outside home]${tail}`;
}

export function homeChanges(before: HomeSnapshot, w: HomeWatch): HomeChange[] {
  const after = homeSnapshot(w);
  const out: HomeChange[] = [];
  const seen = new Set<string>();
  const add = (p: string, change: HomeChange["change"], prefsOnly = false) => {
    const path = homePath(w, p);
    if (!seen.has(path)) out.push(prefsOnly ? { path, change, prefs_only: true } : { path, change }), seen.add(path);
  };
  // only a hashed file has a core part; a link fingerprint holds a target anyone can choose, "|core:" included
  const core = (f: string) => (f.startsWith("file:") ? f.split("|core:")[1] : undefined);
  for (const [p, f] of after) {
    const b = before.get(p);
    if (b === undefined) add(p, "added");
    else if (b !== f || p === OVERFLOW) add(p, "changed", !!core(f) && core(f) === core(b));
  }
  for (const p of before.keys()) if (!after.has(p)) add(p, "removed");
  return out;
}
