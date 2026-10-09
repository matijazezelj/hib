import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { hibHome, type Config } from "../config";
import type { Sandbox } from "./driver";

/**
 * Agent commands run in the CLI's own OS sandbox: Claude Code's (Seatbelt on macOS, bubblewrap on Linux) and Codex's
 * (Seatbelt / Landlock). Without one there is nothing to confine a script the agent writes and runs, so auto mode and
 * background tasks are off.
 */
export function sandboxAvailable(): boolean {
  if (process.platform === "darwin") return !!Bun.which("sandbox-exec");
  // Claude Code's Linux sandbox needs both; with failIfUnavailable a missing one would stop every session from starting.
  if (process.platform === "linux") return !!Bun.which("bwrap") && !!Bun.which("socat");
  return false;
}

/**
 * Paths no agent command may read, whatever is approved: hib's home (the daemon token, database, vault key), every
 * account's CLI login (the session's own included; commands never need it), and common credential stores.
 */
export function sandboxFor(cfg: Config): Sandbox | undefined {
  if (!sandboxAvailable()) return undefined;
  const home = homedir();
  const expand = (p: string) => p.replace(/^~(?=$|\/)/, home);
  // Codex runs its own binary from inside CODEX_HOME (packages/), so only its login file is hidden there.
  const codexHomes = [join(home, ".codex"), ...cfg.accounts.map((a) => a.env.CODEX_HOME).filter((p): p is string => !!p).map(expand)];
  const paths = [
    hibHome(),
    ...[".claude", ".claude.json", ".ssh", ".aws", ".gnupg", ".config/gh", ".netrc", ".git-credentials"].map((p) => join(home, p)),
    ...cfg.accounts.map((a) => a.env.CLAUDE_CONFIG_DIR).filter((p): p is string => !!p).map(expand),
    ...codexHomes.map((d) => join(d, "auth.json")),
  ];
  return { denyRead: [...new Set(paths)].filter((p) => existsSync(p)) };
}

/** Package registries a sandboxed command may reach in auto mode; any other host asks, even in auto mode. */
export const REGISTRIES = new Set([
  "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
  "crates.io", "index.crates.io", "static.crates.io", "proxy.golang.org", "sum.golang.org",
]);
