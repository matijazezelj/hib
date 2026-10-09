import { realpathSync } from "node:fs";
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
const REPO = join(import.meta.dir, "..", "..");

/**
 * macOS Seatbelt profile: no network, no file writes, no reads under $HOME except hib itself
 * (the runner and its modules). Later rules win, so the allow carves hib out of the deny.
 */
function seatbelt(): string {
  const q = (p: string) => JSON.stringify(p);
  return [
    "(version 1)",
    "(allow default)",
    "(deny network*)",
    "(deny file-write*)",
    '(allow file-write* (literal "/dev/null"))',
    `(deny file-read* (subpath ${q(homedir())}))`,
    `(allow file-read* (subpath ${q(REPO)}))`,
    // Bun may live under $HOME (~/.bun when installed with the official script).
    `(allow file-read* (subpath ${q(dirname(realpathSync(process.execPath)))}))`,
  ].join("");
}

/**
 * Linux: bubblewrap with the filesystem read-only, $HOME replaced by an empty tmpfs (hib's own files and the bun binary
 * are bound back read-only), no network, and its own PID namespace. Same promises as the Seatbelt profile.
 */
export function bwrapArgv(cmd: string[], home = homedir()): string[] {
  const keep = [REPO, dirname(realpathSync(process.execPath))].filter((p) => p === home || p.startsWith(home + "/"));
  return [
    "bwrap", "--die-with-parent", "--unshare-net", "--unshare-pid", "--unshare-ipc",
    "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", home,
    ...keep.flatMap((p) => ["--ro-bind", p, p]),
    "--chdir", "/", ...cmd,
  ];
}

/** Runs model-written code against the table locally, isolated from the network and your files. */
export async function runAnalysis(code: string, table: Table, timeoutMs = 20_000, geo?: { data: string; helper: string }): Promise<RunResult> {
  const mac = process.platform === "darwin" && !!Bun.which("sandbox-exec");
  const cmd = [process.execPath, RUNNER];
  const bwrap = !mac && process.platform === "linux" && !!Bun.which("bwrap");
  const argv = mac ? ["sandbox-exec", "-p", seatbelt(), ...cmd] : bwrap ? bwrapArgv(cmd) : cmd;
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
