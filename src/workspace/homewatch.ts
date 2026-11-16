import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, readlinkSync } from "node:fs";
import { join } from "node:path";

/**
 * Files in your home folder that run code or steer an agent outside any workspace: shell startup files, user-level
 * agent config, autostart and user services, git's global config (core.hooksPath), ssh's config and authorized_keys.
 * An agent can change them with its own file tools, which process telemetry (Falco) can't attribute to a path, so
 * each turn snapshots them and reports what changed. Report only: you edit these yourself, and hib can't tell your
 * edit in another terminal from the agent's, so nothing is put back.
 */
export const HOME_WATCH = [
  ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
  ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout",
  ".config/fish/config.fish", ".config/fish/conf.d",
  ".claude/settings.json", ".claude/settings.local.json", ".claude/hooks", ".claude/agents", ".claude/commands", ".claude/skills",
  ".codex/config.toml", ".codex/hooks",
  ".gitconfig", ".config/git/config",
  ".ssh/config", ".ssh/authorized_keys", ".ssh/rc",
  ".config/autostart", ".config/systemd/user", ".config/environment.d",
];

const MAX_ENTRIES = 5_000;
const MAX_FILE = 1 << 20; // larger files are compared by size and mtime
const MAX_TOTAL = 32 << 20; // bytes hashed per snapshot; past it, files are compared by size and mtime
const OVERFLOW = "(more files than hib checks)";

/** A fingerprint per path: content hash and mode, symlink target, or size+mtime for what isn't read. */
export type HomeSnapshot = Map<string, string>;
export interface HomeChange {
  path: string; // "~/.bashrc": relative to home, so no user name
  change: "added" | "changed" | "removed";
}

export function homeSnapshot(home: string): HomeSnapshot {
  const snap: HomeSnapshot = new Map();
  let budget = MAX_TOTAL;
  const walk = (p: string, depth: number) => {
    if (snap.size >= MAX_ENTRIES) return void snap.set(OVERFLOW, "overflow");
    const st = lstatSync(p, { throwIfNoEntry: false });
    if (!st) return;
    if (st.isSymbolicLink()) return void snap.set(p, `link:${readlinkSync(p)}`);
    if (st.isDirectory()) {
      if (depth > 4) return void snap.set(p, `dir:${st.mtimeMs}`);
      let names: string[];
      try {
        names = readdirSync(p);
      } catch {
        return void snap.set(p, `unreadable-dir:${st.mode}:${st.mtimeMs}`);
      }
      for (const n of names) walk(join(p, n), depth + 1);
      return;
    }
    // fifos, sockets and devices are never opened (a fifo would block)
    if (!st.isFile()) return void snap.set(p, `special:${st.mode}:${st.mtimeMs}`);
    if (st.size > MAX_FILE || st.size > budget) return void snap.set(p, `big:${st.size}:${st.mtimeMs}:${st.mode}`);
    try {
      const data = readFileSync(p);
      budget -= data.length;
      snap.set(p, `file:${st.mode & 0o7777}:${createHash("sha256").update(data).digest("hex")}`);
    } catch {
      snap.set(p, `unreadable:${st.mode}:${st.mtimeMs}`);
    }
  };
  for (const rel of HOME_WATCH) walk(join(home, rel), 0);
  return snap;
}

export function homeChanges(before: HomeSnapshot, home: string): HomeChange[] {
  const after = homeSnapshot(home);
  const tilde = (p: string) => (p === OVERFLOW ? p : p.startsWith(home + "/") ? `~/${p.slice(home.length + 1)}` : p);
  const out: HomeChange[] = [];
  for (const [p, f] of after) {
    const b = before.get(p);
    if (b === undefined) out.push({ path: tilde(p), change: "added" });
    else if (b !== f || p === OVERFLOW) out.push({ path: tilde(p), change: "changed" });
  }
  for (const p of before.keys()) if (!after.has(p)) out.push({ path: tilde(p), change: "removed" });
  return out;
}
