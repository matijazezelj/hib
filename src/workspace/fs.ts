import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

const SKIP = new Set([".git", "node_modules", "dist", "build", ".next", "target", ".venv", "venv", "__pycache__", ".turbo", ".cache"]);
const MAX_FILES = 20_000;
const MAX_READ = 1024 * 1024;

/** Resolves a workspace-relative path, refusing anything (including symlinks) that escapes the root. */
export function safePath(root: string, rel: string): string {
  const abs = resolve(realpathSync(root), rel.replace(/^\/+/, ""));
  if (!insideRoot(root, abs)) throw new Error("path outside workspace");
  return existsSync(abs) ? realpathSync(abs) : abs;
}

/** `p` (absolute or relative to root) with `..`, `.`, repeated slashes and symlinks resolved; the missing tail is kept as is. */
export function realTarget(root: string, p: string): string {
  const realRoot = realpathSync(root);
  let abs = isAbsolute(p) ? resolve(p) : resolve(realRoot, p);
  let rest = "";
  while (!existsSync(abs) && dirname(abs) !== abs) {
    rest = join(abs.slice(dirname(abs).length + 1), rest);
    abs = dirname(abs);
  }
  return join(realpathSync(abs), rest);
}

/** True if `p` (absolute or relative to root) lands inside root once symlinks are resolved. */
export function insideRoot(root: string, p: string): boolean {
  const realRoot = realpathSync(root);
  const real = realTarget(root, p);
  return real === realRoot || real.startsWith(realRoot + sep);
}

async function run(cmd: string[], cwd: string): Promise<{ out: string; code: number }> {
  const p = Bun.spawn(cmd, { cwd, stdout: "pipe", stderr: "pipe" });
  const out = await new Response(p.stdout).text();
  return { out, code: await p.exited };
}

async function isGitRepo(root: string): Promise<boolean> {
  return (await run(["git", "rev-parse", "--is-inside-work-tree"], root)).code === 0;
}

/** Workspace file list, honouring .gitignore when the folder is a git repo. */
export async function listFiles(root: string): Promise<string[]> {
  if (await isGitRepo(root)) {
    const { out } = await run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], root);
    return out.split("\0").filter(Boolean).slice(0, MAX_FILES).sort();
  }
  const out: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      if (out.length >= MAX_FILES) return;
      if (SKIP.has(n)) continue;
      const p = join(d, n);
      const st = statSync(p, { throwIfNoEntry: false });
      if (!st) continue;
      if (st.isDirectory()) walk(p);
      else out.push(relative(root, p));
    }
  };
  walk(root);
  return out.sort();
}

export function readFile(root: string, rel: string): { path: string; content?: string; binary?: boolean; tooLarge?: boolean; size: number } {
  const abs = safePath(root, rel);
  const st = statSync(abs);
  if (!st.isFile()) throw new Error("not a file");
  if (st.size > MAX_READ) return { path: rel, tooLarge: true, size: st.size };
  const buf = readFileSync(abs);
  if (buf.includes(0)) return { path: rel, binary: true, size: st.size };
  return { path: rel, content: buf.toString("utf8"), size: st.size };
}
