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
  return sandboxProblem() === null;
}

let problem: string | null | undefined;

/**
 * Why agent commands can't be sandboxed here, or null when they can. The Linux check is a real probe, not just "are the
 * binaries installed": on Ubuntu 24.04+ (kernel.apparmor_restrict_unprivileged_userns=1) bubblewrap starts but Claude
 * Code's helper can't create its nested user namespace, so every Bash command would die with an apply-seccomp error.
 */
export function sandboxProblem(): string | null {
  if (problem !== undefined) return problem;
  if (process.platform === "darwin") return (problem = Bun.which("sandbox-exec") ? null : "sandbox-exec not found");
  if (process.platform !== "linux") return (problem = "no OS sandbox on this platform");
  // Claude Code's Linux sandbox needs both; with failIfUnavailable a missing one would stop every session from starting.
  if (!Bun.which("bwrap") || !Bun.which("socat")) return (problem = "bubblewrap and socat are not both installed");
  if (!Bun.which("unshare")) return (problem = null); // can't probe; trust the install
  const r = Bun.spawnSync(
    ["bwrap", "--unshare-user", "--unshare-pid", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "unshare", "--user", "--map-root-user", "true"],
    { stdout: "ignore", stderr: "ignore", timeout: 5000 },
  );
  return (problem = r.exitCode === 0 ? null : "this kernel blocks the nested user namespace the sandbox needs (Ubuntu: kernel.apparmor_restrict_unprivileged_userns=1)");
}

/** For tests: forget the cached probe result. */
export function resetSandboxProbe() {
  problem = undefined;
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
