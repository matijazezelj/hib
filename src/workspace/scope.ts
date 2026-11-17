/**
 * Each agent CLI in a systemd user scope of its own (Linux, `[events] session_scope = true`). Process telemetry
 * (Falco's container/cgroup fields) can then tie every process an agent starts to its hib session by cgroup, which,
 * unlike HIB_SESSION in the environment, survives `env -i`, `setsid`, bash reordering the environment and Falco
 * reading only the first 4 KB of it.
 *
 * `systemd-run --scope` moves itself into the new scope and then execs the command, so the CLI stays hib's child with
 * the same pipes. The user manager is reached through XDG_RUNTIME_DIR, which the CLI's minimal environment doesn't
 * carry; it's given to systemd-run only and removed again (with systemd's INVOCATION_ID) before the CLI starts.
 * Scopes aren't stopped when a session ends: what a command left running keeps running, as without a scope.
 */
export interface ScopeTool {
  systemdRun: string; // absolute
  env: string; // absolute path of env(1)
  runtimeDir: string; // XDG_RUNTIME_DIR, for systemd-run to find the user manager
}

export type ScopeProbe = { tool: ScopeTool } | { problem: string };

/** Whether this machine can put a process in a user scope: checked once, by starting `true` in one. */
export function probeScope(sys: { platform?: string; which?: (c: string) => string | null; runtimeDir?: string; run?: (argv: string[], env: Record<string, string>) => boolean } = {}): ScopeProbe {
  const platform = sys.platform ?? process.platform;
  if (platform !== "linux") return { problem: `systemd scopes are Linux only (this is ${platform})` };
  const which = sys.which ?? ((c: string) => Bun.which(c));
  const systemdRun = which("systemd-run");
  const env = which("env");
  if (!systemdRun || !env) return { problem: `${systemdRun ? "env" : "systemd-run"} not found` };
  const runtimeDir = "runtimeDir" in sys ? sys.runtimeDir : process.env.XDG_RUNTIME_DIR;
  if (!runtimeDir) return { problem: "XDG_RUNTIME_DIR isn't set, so there's no user systemd to reach" };
  const run =
    sys.run ??
    ((argv: string[], e: Record<string, string>) => {
      try {
        return Bun.spawnSync(argv, { env: e, stdout: "ignore", stderr: "ignore", timeout: 10_000 }).exitCode === 0;
      } catch {
        return false;
      }
    });
  const ok = run([systemdRun, "--user", "--scope", "--quiet", "--collect", `--unit=hib-probe-${process.pid}-${crypto.randomUUID().slice(0, 8)}`, "--", env, "true"], { PATH: "/usr/bin:/bin", XDG_RUNTIME_DIR: runtimeDir });
  return ok ? { tool: { systemdRun, env, runtimeDir } } : { problem: "systemd-run --user --scope failed (is a user systemd running?)" };
}

let cached: ScopeProbe | undefined;
/** The probe, run on first use and kept for the daemon's life. */
export function scopeProbe(): ScopeProbe {
  return (cached ??= probeScope());
}

/** A unit name for one CLI start: unique per start, since a resumed session can start a new CLI while the old scope lives on. */
export function scopeUnit(session: string): string {
  return `hib-${session.replace(/[^A-Za-z0-9_-]/g, "_")}-${crypto.randomUUID().slice(0, 8)}.scope`;
}

/** argv and env that start `argv` inside the scope `unit`; unchanged without a tool. */
export function inScope(argv: string[], env: Record<string, string>, scope?: { tool: ScopeTool; unit: string }): { argv: string[]; env: Record<string, string> } {
  if (!scope) return { argv, env };
  const own = "XDG_RUNTIME_DIR" in env; // the account set it: the CLI keeps it
  return {
    argv: [scope.tool.systemdRun, "--user", "--scope", "--quiet", "--collect", `--unit=${scope.unit}`, "--", scope.tool.env, "-u", "INVOCATION_ID", ...(own ? [] : ["-u", "XDG_RUNTIME_DIR"]), ...argv],
    env: own ? env : { ...env, XDG_RUNTIME_DIR: scope.tool.runtimeDir },
  };
}
