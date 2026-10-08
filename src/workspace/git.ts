import { rmSync } from "node:fs";
import { safePath } from "./fs";

async function git(root: string, ...args: string[]): Promise<{ out: string; err: string; code: number }> {
  const p = Bun.spawn(["git", ...args], { cwd: root, stdout: "pipe", stderr: "pipe" });
  const [out, err] = [await new Response(p.stdout).text(), await new Response(p.stderr).text()];
  return { out, err, code: await p.exited };
}

export interface FileStatus {
  path: string;
  index: string; // X of porcelain XY
  worktree: string; // Y
  untracked: boolean;
}

export async function status(root: string): Promise<{ branch: string; files: FileStatus[] } | null> {
  const r = await git(root, "status", "--porcelain=v1", "-z", "--branch", "--untracked-files=all");
  if (r.code !== 0) return null;
  const parts = r.out.split("\0").filter(Boolean);
  let branch = "";
  const files: FileStatus[] = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i]!;
    if (p.startsWith("## ")) {
      branch = p.slice(3);
      continue;
    }
    const [x, y, path] = [p[0]!, p[1]!, p.slice(3)];
    files.push({ path, index: x, worktree: y, untracked: x === "?" });
    if (x === "R" || x === "C") i++; // rename source follows
  }
  return { branch, files };
}

export async function diff(root: string, rel: string): Promise<string> {
  safePath(root, rel);
  const st = await status(root);
  const f = st?.files.find((x) => x.path === rel);
  if (f?.untracked) return (await git(root, "diff", "--no-index", "--", "/dev/null", rel)).out;
  return (await git(root, "diff", "HEAD", "--", rel)).out || (await git(root, "diff", "--", rel)).out;
}

export async function discard(root: string, rel: string): Promise<void> {
  const abs = safePath(root, rel);
  const st = await status(root);
  const f = st?.files.find((x) => x.path === rel);
  if (!f) return;
  if (f.untracked) rmSync(abs, { force: true });
  else {
    const r = await git(root, "restore", "--staged", "--worktree", "--source=HEAD", "--", rel);
    if (r.code !== 0) throw new Error(r.err.trim());
  }
}

export async function commit(root: string, message: string): Promise<string> {
  if (!message.trim()) throw new Error("empty commit message");
  let r = await git(root, "add", "-A");
  if (r.code !== 0) throw new Error(r.err.trim());
  r = await git(root, "commit", "-m", message);
  if (r.code !== 0) throw new Error((r.err || r.out).trim());
  return r.out.trim().split("\n")[0] ?? "";
}
