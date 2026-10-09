import { expect, test } from "bun:test";
import { bwrapArgv, runAnalysis } from "../src/analyze/sandbox";

test("bwrapArgv: read-only root, empty home, no network, own pid namespace", () => {
  const a = bwrapArgv(["/usr/bin/bun", "runner.ts"], "/home/u");
  expect(a[0]).toBe("bwrap");
  for (const f of ["--unshare-net", "--unshare-pid", "--die-with-parent"]) expect(a).toContain(f);
  expect(a.slice(a.indexOf("--ro-bind"), a.indexOf("--ro-bind") + 3)).toEqual(["--ro-bind", "/", "/"]);
  expect(a.slice(a.indexOf("--tmpfs"), a.indexOf("--tmpfs") + 2)).toEqual(["--tmpfs", "/home/u"]);
  expect(a.slice(-2)).toEqual(["/usr/bin/bun", "runner.ts"]);
});

test.skipIf(process.platform !== "linux" || !Bun.which("bwrap"))("analysis runs under bubblewrap on Linux", async () => {
  const r = await runAnalysis("function analyze(rows){ return rows.length }", { columns: [], rows: [{ a: 1 }, { a: 2 }] } as any);
  expect(r.sandbox).toBe("linux-bwrap");
  expect(r.ok).toBe(true);
  expect(r.result).toBe(2);
});
