import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, readlinkSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

/**
 * The files that steer code running outside any sandbox: git hooks and config (run by git), and tool config inside
 * the folder (.claude/ hooks and settings, .codex/, .mcp.json servers). hib approves edits to them by path, but a path
 * can be swapped for a symlink between the approval and the write, so each turn is also checked by content: a
 * snapshot before, a comparison after, and anything changed that you didn't approve is put back.
 */
type Entry =
  | { kind: "file"; mode: number; data: Buffer }
  | { kind: "link"; target: string }
  | { kind: "big"; size: number; mtime: number } // over the size budget: compared by size and mtime, can't be restored
  | { kind: "special"; type: string; mode: number; mtime: number } // fifo, socket, device, or unreadable: never read (a fifo would block)
  | { kind: "overflow" }; // more protected files than hib walks: always reported
export type Snapshot = Map<string, Entry>;
export interface ProtectedChange {
  path: string;
  change: "added" | "changed" | "removed";
}

const MAX_FILES = 20_000;
const MAX_FILE = 1 << 20; // larger files are compared by size and mtime only, and can't be restored
const MAX_TOTAL = 64 << 20; // content kept per snapshot; past it, files are compared by size and mtime

/** The repository's git dir and common dir; a worktree's .git is a file pointing at them. */
function gitDirs(root: string): string[] {
  const dotgit = join(root, ".git");
  const st = lstatSync(dotgit, { throwIfNoEntry: false });
  if (!st) return [];
  if (st.isDirectory()) return [dotgit];
  if (!st.isFile()) throw new Error(".git is neither a folder nor a file"); // never open a fifo
  const m = /^gitdir:\s*(.+)$/m.exec(readFileSync(dotgit, "utf8"));
  if (!m) return [];
  const gitdir = resolve(root, m[1]!.trim());
  const common = existsSync(join(gitdir, "commondir")) ? resolve(gitdir, readFileSync(join(gitdir, "commondir"), "utf8").trim()) : gitdir;
  return [...new Set([gitdir, common])];
}

const OVERFLOW = "(more protected files than hib checks)";

/**
 * Every protected entry under root (and the repo's git dirs), symlinks not followed. Nothing an agent can create makes
 * this throw or block: unreadable entries, fifos and sockets are recorded without being opened, and too many files is
 * itself a finding rather than a place to stop looking.
 */
export function snapshot(root: string): Snapshot {
  const snap: Snapshot = new Map();
  let budget = MAX_TOTAL;
  const special = (p: string, type: string, st: { mode: number; mtimeMs: number }) => snap.set(p, { kind: "special", type, mode: st.mode, mtime: st.mtimeMs });
  const walk = (p: string) => {
    if (snap.size >= MAX_FILES) return void snap.set(OVERFLOW, { kind: "overflow" });
    const st = lstatSync(p, { throwIfNoEntry: false });
    if (!st) return;
    if (st.isSymbolicLink()) return void snap.set(p, { kind: "link", target: readlinkSync(p) });
    if (st.isDirectory()) {
      let names: string[];
      try {
        names = readdirSync(p);
      } catch {
        return special(p, "unreadable directory", st);
      }
      for (const n of names) walk(join(p, n));
      return;
    }
    if (!st.isFile()) return special(p, st.isFIFO() ? "fifo" : st.isSocket() ? "socket" : "device", st);
    if (st.size > MAX_FILE || st.size > budget) return void snap.set(p, { kind: "big", size: st.size, mtime: st.mtimeMs });
    try {
      const data = readFileSync(p);
      budget -= data.length;
      snap.set(p, { kind: "file", mode: st.mode & 0o7777, data });
    } catch {
      special(p, "unreadable file", st);
    }
  };
  for (const n of [".claude", ".codex", ".hib", ".mcp.json"]) walk(join(root, n));
  let dirs: string[] = [];
  try {
    dirs = gitDirs(root);
  } catch {
    special(join(root, ".git"), "unreadable .git", { mode: 0, mtimeMs: 0 });
  }
  for (const g of dirs) {
    walk(join(g, "hooks"));
    for (const f of ["config", "config.worktree"]) walk(join(g, f));
  }
  return snap;
}

function same(a: Entry, b: Entry): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === "link") return a.target === (b as typeof a).target;
  if (a.kind === "big") return a.size === (b as typeof a).size && a.mtime === (b as typeof a).mtime;
  if (a.kind === "special") return a.type === (b as typeof a).type && a.mode === (b as typeof a).mode && a.mtime === (b as typeof a).mtime;
  if (a.kind === "overflow") return false;
  return a.mode === (b as typeof a).mode && a.data.equals((b as typeof a).data);
}

export function changes(before: Snapshot, root: string): ProtectedChange[] {
  const after = snapshot(root);
  const out: ProtectedChange[] = [];
  for (const [p, e] of after) {
    const b = before.get(p);
    if (!b) out.push({ path: p, change: "added" });
    else if (!same(b, e)) out.push({ path: p, change: "changed" });
  }
  for (const p of before.keys()) if (!after.has(p)) out.push({ path: p, change: "removed" });
  return out;
}

/** Puts changed files back as they were; returns the paths it couldn't restore (large files). */
export function revert(before: Snapshot, list: ProtectedChange[]): string[] {
  const failed: string[] = [];
  for (const { path } of list) {
    const b = before.get(path);
    if (path === OVERFLOW || b?.kind === "special" || b?.kind === "overflow") {
      failed.push(path); // can't be put back as it was: report it
      continue;
    }
    try {
      // Whatever is there now goes (a planted file, a fifo, or a symlink swapped in), without following links.
      const now = lstatSync(path, { throwIfNoEntry: false });
      if (now?.isDirectory()) chmodSync(path, 0o700); // an unreadable directory can't be emptied otherwise
      if (now) rmSync(path, { force: true, recursive: true });
      if (!b) continue;
      if (b.kind === "big") {
        failed.push(path);
        continue;
      }
      // A parent directory swapped for a symlink would send the restore elsewhere: make it a real directory again.
      const dir = dirname(path);
      if (lstatSync(dir, { throwIfNoEntry: false })?.isSymbolicLink()) rmSync(dir, { force: true });
      mkdirSync(dir, { recursive: true });
      if (b.kind === "link") symlinkSync(b.target, path);
      else {
        writeFileSync(path, b.data);
        chmodSync(path, b.mode);
      }
    } catch {
      failed.push(path);
    }
  }
  return failed;
}
