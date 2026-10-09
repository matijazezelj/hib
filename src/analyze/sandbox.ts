import { lstatSync, readlinkSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { Table } from "./table";

export interface RunResult {
  ok: boolean;
  result?: unknown;
  error?: string;
  sandbox: "macos-sandbox" | "linux-bwrap" | "process-only";
}

const RUNNER = join(import.meta.dir, "runner.ts");

/**
 * macOS Seatbelt profile: no network, no file writes, and no reads of anyone's home folder, temp folders or mounted
 * volumes, except hib itself (the runner and its modules) and bun. No starting other programs either, which also
 * rules out reaching outside through `open` (LaunchServices) or `osascript`, and no Apple Events. Later rules win,
 * so the allows carve hib and bun out of the denies.
 */
export function seatbelt(): string {
  const q = (p: string) => JSON.stringify(p);
  const bun = realpathSync(process.execPath);
  return [
    "(version 1)",
    "(allow default)",
    "(deny network*)",
    "(deny file-write*)",
    '(allow file-write* (literal "/dev/null"))',
    ...[homedir(), "/Users", "/Volumes", "/private/tmp", "/private/var/folders", "/private/var/root", "/Library/Keychains"].map((p) => `(deny file-read* (subpath ${q(p)}))`),
    // Resolving the runner's path needs stat on its folders; metadata says a file exists, never what's in it.
    "(allow file-read-metadata)",
    "(deny process-exec*)",
    `(allow process-exec* (literal ${q(bun)}))`,
    "(deny appleevent-send)",
    `(allow file-read* (subpath ${q(dirname(RUNNER))}))`,
    // Bun may live under $HOME (~/.bun when installed with the official script).
    `(allow file-read* (subpath ${q(dirname(bun))}))`,
  ].join("");
}

/** System folders bun needs to start: its shared libraries and the dynamic loader. Nothing with data in it. */
const LINUX_SYSTEM = ["/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin"];

/**
 * Linux: bubblewrap from an empty root. Only what the runner needs is mounted, read-only: the system libraries, the bun
 * binary's folder and the runner's own folder (`src/analyze`), plus a fresh /dev, /proc and an empty /tmp. No /etc,
 * /home, /run, /var, /srv, /opt or mounted volumes, so no host files and no socket files (ssh/gpg agents) to reach. Every
 * namespace is unshared (no network, own PIDs), and the data arrives on stdin.
 */
export function bwrapArgv(cmd: string[], pathKind: (p: string) => PathKind = linuxPathKind): string[] {
  const mounts: string[] = [];
  for (const p of LINUX_SYSTEM) {
    const k = pathKind(p);
    // Merged-/usr systems have /lib → usr/lib: recreate the link instead of binding the target twice.
    if (k?.link) mounts.push("--symlink", k.link, p);
    else if (k) mounts.push("--ro-bind", p, p);
  }
  const own = [...new Set([dirname(realpathSync(process.execPath)), dirname(RUNNER)])].filter((p) => !LINUX_SYSTEM.some((s) => p === s || p.startsWith(s + "/")));
  return [
    "bwrap", "--die-with-parent", "--new-session", "--unshare-all",
    ...mounts,
    ...own.flatMap((p) => ["--ro-bind", p, p]),
    "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
    "--chdir", "/", ...cmd,
  ];
}

type PathKind = { link?: string } | null; // null: missing; {}: a directory; {link}: a symlink to `link`

function linuxPathKind(p: string): PathKind {
  const st = lstatSync(p, { throwIfNoEntry: false });
  return st?.isSymbolicLink() ? { link: readlinkSync(p) } : st?.isDirectory() ? {} : null;
}

/** Runs model-written code against the table locally, isolated from the network and your files. */
export async function runAnalysis(code: string, table: Table, timeoutMs = 20_000, geo?: { data: string; helper: string }): Promise<RunResult> {
  const mac = process.platform === "darwin" && !!Bun.which("sandbox-exec");
  const cmd = [process.execPath, RUNNER];
  const bwrap = !mac && process.platform === "linux" && !!Bun.which("bwrap");
  // Model-written code never runs with only a JavaScript context between it and your files and network.
  if (!mac && !bwrap)
    return { ok: false, sandbox: "process-only", error: "no OS sandbox on this machine, so the code was not run. On Linux install bubblewrap (bwrap); Windows isn't supported." };
  const argv = mac ? ["sandbox-exec", "-p", seatbelt(), ...cmd] : bwrapArgv(cmd);
  const p = Bun.spawn(argv, {
    cwd: "/",
    env: { PATH: "/usr/bin:/bin", HOME: "/nonexistent", TMPDIR: "/nonexistent" },
    stdin: new Blob([JSON.stringify({ code, data: JSON.stringify(table.rows), timeoutMs, geo: geo?.data, geoHelper: geo?.helper })]),
    stdout: "pipe",
    stderr: "pipe",
  });
  const killer = setTimeout(() => p.kill(), timeoutMs + 10_000);
  const [out, err] = [await new Response(p.stdout).text(), await new Response(p.stderr).text()];
  clearTimeout(killer);
  await p.exited;
  const sandbox = mac ? "macos-sandbox" : bwrap ? "linux-bwrap" : "process-only";
  try {
    return { ...JSON.parse(out), sandbox };
  } catch {
    return { ok: false, error: (err || out || "analysis process failed").trim().split("\n").slice(-3).join(" ").slice(0, 500), sandbox };
  }
}
