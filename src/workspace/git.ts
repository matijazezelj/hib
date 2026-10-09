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

async function must(root: string, ...args: string[]): Promise<string> {
  const r = await git(root, ...args);
  if (r.code !== 0) throw new Error((r.err || r.out).trim() || `git ${args[0]} failed`);
  return r.out.trim();
}

/** The repository's top-level folder and current commit; throws if `root` isn't the top of a repo with a commit. */
export async function head(root: string): Promise<{ top: string; sha: string; branch: string }> {
  const top = await must(root, "rev-parse", "--show-toplevel").catch(() => {
    throw new Error(`${root} is not a git repository`);
  });
  const sha = await must(root, "rev-parse", "--verify", "HEAD").catch(() => {
    throw new Error("this repository has no commits yet");
  });
  const branch = (await git(root, "symbolic-ref", "--short", "-q", "HEAD")).out.trim();
  return { top, sha, branch };
}

/** A new worktree at `path` on a new branch starting at `base`. */
export async function worktreeAdd(root: string, path: string, branch: string, base: string): Promise<void> {
  await must(root, "worktree", "add", "-b", branch, path, base);
}

/** Removes a worktree (even with uncommitted changes) and deletes its branch. */
export async function worktreeRemove(root: string, path: string, branch: string): Promise<void> {
  await git(root, "worktree", "remove", "--force", path);
  await git(root, "worktree", "prune");
  await git(root, "branch", "-D", branch);
}

/** Commits everything in a worktree if anything changed; returns whether it committed. */
export async function commitAll(root: string, message: string): Promise<boolean> {
  if (!(await status(root))?.files.length) return false;
  await commit(root, message);
  return true;
}

/** What a branch changed since it left `base`: commits, stat and diff. */
export async function branchChanges(root: string, base: string, branch: string): Promise<{ log: string; stat: string; diff: string }> {
  const range = `${base}..${branch}`;
  return {
    log: (await git(root, "log", "--oneline", range)).out.trim(),
    stat: (await git(root, "diff", "--stat", `${base}...${branch}`)).out.trimEnd(),
    diff: (await git(root, "diff", `${base}...${branch}`)).out,
  };
}

/** Merges a branch into whatever `root` has checked out; a conflicting merge is aborted and reported. */
export async function merge(root: string, branch: string, message: string): Promise<string> {
  const r = await git(root, "merge", "--no-ff", "-m", message, branch);
  if (r.code === 0) return r.out.trim().split("\n")[0] ?? "";
  await git(root, "merge", "--abort");
  throw new Error(`merge failed, nothing changed: ${(r.err || r.out).trim().split("\n").slice(0, 6).join("; ")}`);
}
