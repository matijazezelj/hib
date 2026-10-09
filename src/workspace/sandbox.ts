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
 * Credentials agents never read. `commands`: denied to every sandboxed command (and so to scripts the agent writes).
 * `tools`: denied to the CLI's own file tools too, which run outside the sandbox; that list adds what commands still
 * need to work (npm reads ~/.npmrc for its registry) and whole CLI homes (Codex runs its binary from CODEX_HOME).
 */
export function secretPaths(cfg: Config): { commands: string[]; tools: string[] } {
  const home = homedir();
  const expand = (p: string) => p.replace(/^~(?=$|\/)/, home);
  const codexHomes = [join(home, ".codex"), ...cfg.accounts.map((a) => a.env.CODEX_HOME).filter((p): p is string => !!p).map(expand)];
  const commands = [
    hibHome(),
    ...[
      ".claude", ".claude.json", ".ssh", ".aws", ".gnupg", ".config/gh", ".netrc", ".git-credentials",
      ".cargo/credentials", ".cargo/credentials.toml", ".pypirc", ".docker/config.json", ".kube", ".config/gcloud", ".azure",
    ].map((p) => join(home, p)),
    ...cfg.accounts.map((a) => a.env.CLAUDE_CONFIG_DIR).filter((p): p is string => !!p).map(expand),
    ...codexHomes.map((d) => join(d, "auth.json")),
  ];
  const tools = [...commands, ...codexHomes, join(home, ".npmrc"), join(home, ".yarnrc.yml"), join(home, ".gem/credentials")];
  return { commands: [...new Set(commands)], tools: [...new Set(tools)] };
}

/** The sandbox for agent commands: hib's home, every account's CLI login and common credential stores are unreadable. */
export function sandboxFor(cfg: Config): Sandbox | undefined {
  if (!sandboxAvailable()) return undefined;
  return { denyRead: secretPaths(cfg).commands.filter((p) => existsSync(p)) };
}

/** Package registries a sandboxed command may reach in auto mode; any other host asks, even in auto mode. */
export const REGISTRIES = new Set([
  "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
  "crates.io", "index.crates.io", "static.crates.io", "proxy.golang.org", "sum.golang.org",
]);
