import { describe, expect, test } from "bun:test";
import { inScope, probeScope, scopeUnit } from "../src/workspace/scope";

const tool = { systemdRun: "/usr/bin/systemd-run", env: "/usr/bin/env", runtimeDir: "/run/user/1000" };

describe("inScope", () => {
  test("wraps the CLI in systemd-run --scope and strips what only systemd-run needs", () => {
    const { argv, env } = inScope(["claude", "-p"], { HIB_SESSION: "w_1", PATH: "/bin" }, { tool, unit: "hib-w_1-ab.scope" });
    expect(argv).toEqual(["/usr/bin/systemd-run", "--user", "--scope", "--quiet", "--collect", "--unit=hib-w_1-ab.scope", "--", "/usr/bin/env", "-u", "INVOCATION_ID", "-u", "XDG_RUNTIME_DIR", "claude", "-p"]);
    expect(Object.entries(env)).toEqual([["HIB_SESSION", "w_1"], ["PATH", "/bin"], ["XDG_RUNTIME_DIR", "/run/user/1000"]]);
  });

  test("an account's own XDG_RUNTIME_DIR is kept for the CLI; no scope leaves everything as it was", () => {
    const own = inScope(["codex"], { XDG_RUNTIME_DIR: "/mine" }, { tool, unit: "u.scope" });
    expect(own.argv).not.toContain("XDG_RUNTIME_DIR");
    expect(own.env).toEqual({ XDG_RUNTIME_DIR: "/mine" });
    const env = { PATH: "/bin" };
    expect(inScope(["codex"], env)).toEqual({ argv: ["codex"], env });
  });
});

test("scopeUnit: unique per start, safe characters only", () => {
  const a = scopeUnit("w_0123abcd");
  expect(a).toMatch(/^hib-w_0123abcd-[0-9a-f]{8}\.scope$/);
  expect(scopeUnit("w_0123abcd")).not.toBe(a);
  expect(scopeUnit("w/../x y")).toMatch(/^hib-w____x_y-[0-9a-f]{8}\.scope$/);
});

describe("probeScope", () => {
  const which = (c: string) => `/usr/bin/${c}`;
  test("not Linux, missing tools, no runtime dir, or a failing start: a reason, never a throw", () => {
    expect(probeScope({ platform: "darwin" })).toEqual({ problem: expect.stringContaining("Linux only") });
    expect(probeScope({ platform: "linux", which: () => null })).toEqual({ problem: "systemd-run not found" });
    expect(probeScope({ platform: "linux", which, runtimeDir: undefined })).toEqual({ problem: expect.stringContaining("XDG_RUNTIME_DIR") });
    expect(probeScope({ platform: "linux", which, runtimeDir: "/r", run: () => false })).toEqual({ problem: expect.stringContaining("failed") });
  });
  test("works: the tool, after starting `true` in a probe scope with only PATH and the runtime dir", () => {
    let seen: [string[], Record<string, string>] | undefined;
    const p = probeScope({ platform: "linux", which, runtimeDir: "/r", run: (a, e) => ((seen = [a, e]), true) });
    expect(p).toEqual({ tool: { systemdRun: "/usr/bin/systemd-run", env: "/usr/bin/env", runtimeDir: "/r" } });
    expect(seen![0].slice(-3)).toEqual(["--", "/usr/bin/env", "true"]);
    expect(seen![1]).toEqual({ PATH: "/usr/bin:/bin", XDG_RUNTIME_DIR: "/r" });
  });
});
