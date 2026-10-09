import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, readlinkSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

/**
 * The files that steer code running outside any sandbox: git hooks and config (run by git), and tool config inside
 * the folder (.claude/ hooks and settings, .codex/, .mcp.json servers). hib approves edits to them by path, but a path
 * can be swapped for a symlink between the approval and the write, so each turn is also checked by content: a
 * snapshot before, a comparison after, and anything changed that you didn't approve is put back.
 */
type Entry = { kind: "file"; mode: number; data: Buffer } | { kind: "link"; target: string } | { kind: "big"; size: number; mtime: number };
export type Snapshot = Map<string, Entry>;
export interface ProtectedChange {
  path: string;
  change: "added" | "changed" | "removed";
}

const MAX_FILES = 2000;
const MAX_FILE = 1 << 20; // larger files are compared by size and mtime only, and can't be restored

/** The repository's git dir and common dir; a worktree's .git is a file pointing at them. */
function gitDirs(root: string): string[] {
  const dotgit = join(root, ".git");
  const st = lstatSync(dotgit, { throwIfNoEntry: false });
  if (!st) return [];
  if (st.isDirectory()) return [dotgit];
  const m = /^gitdir:\s*(.+)$/m.exec(readFileSync(dotgit, "utf8"));
  if (!m) return [];
  const gitdir = resolve(root, m[1]!.trim());
  const common = existsSync(join(gitdir, "commondir")) ? resolve(gitdir, readFileSync(join(gitdir, "commondir"), "utf8").trim()) : gitdir;
  return [...new Set([gitdir, common])];
}

/** Every protected file under root (and the repo's git dirs), as absolute paths, symlinks not followed. */
function protectedFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (p: string) => {
    if (out.length >= MAX_FILES) return;
    const st = lstatSync(p, { throwIfNoEntry: false });
    if (!st) return;
    if (st.isDirectory()) for (const n of readdirSync(p)) walk(join(p, n));
    else out.push(p);
  };
  for (const n of [".claude", ".codex", ".hib", ".mcp.json"]) walk(join(root, n));
  for (const g of gitDirs(root)) {
    walk(join(g, "hooks"));
    for (const f of ["config", "config.worktree"]) walk(join(g, f));
  }
  return out;
}

export function snapshot(root: string): Snapshot {
  const snap: Snapshot = new Map();
  for (const p of protectedFiles(root)) {
    const st = lstatSync(p, { throwIfNoEntry: false });
    if (!st) continue;
    if (st.isSymbolicLink()) snap.set(p, { kind: "link", target: readlinkSync(p) });
    else if (st.size > MAX_FILE) snap.set(p, { kind: "big", size: st.size, mtime: st.mtimeMs });
    else snap.set(p, { kind: "file", mode: st.mode & 0o7777, data: readFileSync(p) });
  }
  return snap;
}

function same(a: Entry, b: Entry): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === "link") return a.target === (b as typeof a).target;
  if (a.kind === "big") return a.size === (b as typeof a).size && a.mtime === (b as typeof a).mtime;
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
    try {
      // Whatever is there now goes (a planted file, or a symlink swapped in), without following links.
      if (lstatSync(path, { throwIfNoEntry: false })) rmSync(path, { force: true, recursive: true });
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
