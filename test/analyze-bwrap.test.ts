import { expect, test } from "bun:test";
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { bwrapArgv, runAnalysis } from "../src/analyze/sandbox";

const pairs = (a: string[], flag: string) => a.flatMap((x, i) => (x === flag ? [`${a[i + 1]} ${a[i + 2]}`] : []));

test("bwrapArgv starts from an empty root and mounts only system libraries, bun and the runner", () => {
  const kinds: Record<string, { link?: string } | null> = { "/usr": {}, "/lib": { link: "usr/lib" }, "/lib64": { link: "usr/lib64" }, "/lib32": null, "/bin": { link: "usr/bin" }, "/sbin": { link: "usr/sbin" } };
  const a = bwrapArgv(["/usr/bin/bun", "runner.ts"], (p) => kinds[p] ?? null);
  expect(a[0]).toBe("bwrap");
  for (const f of ["--unshare-all", "--die-with-parent", "--new-session"]) expect(a).toContain(f);
  const binds = pairs(a, "--ro-bind").map((b) => b.split(" ")[0]!);
  expect(binds).not.toContain("/"); // no host root, read-only or not
  for (const p of ["/etc", "/home", "/run", "/var", "/srv", "/opt", "/tmp", "/mnt", "/media", homedir()]) expect(binds).not.toContain(p);
  expect(binds).toContain("/usr");
  expect(pairs(a, "--symlink")).toContain("usr/lib /lib"); // merged /usr: links, not second binds
  expect(a.slice(a.indexOf("--tmpfs"), a.indexOf("--tmpfs") + 2)).toEqual(["--tmpfs", "/tmp"]); // empty, not the host's
  expect(a.slice(-2)).toEqual(["/usr/bin/bun", "runner.ts"]);
});

const linux = process.platform === "linux" && !!Bun.which("bwrap");

test.skipIf(!linux)("under bubblewrap the runner can't see host files, sockets or the network", async () => {
  // bun and the runner may live under $HOME (CI: ~/.bun/bin, ~/work/…), so bwrap creates their parent folders as empty
  // mount points. What matters is that nothing else is there: home lists only the way to those mounts, and of the repo
  // only src/analyze is visible.
  const repo = join(import.meta.dir, "..");
  const probe = `const fs = require("node:fs");
    const seen = ["/etc/passwd", "/etc/hostname", "/run/user", "/var", "/srv", "/opt", ${JSON.stringify(join(repo, "package.json"))}, ${JSON.stringify(join(repo, "src/workspace"))}].filter((p) => fs.existsSync(p));
    const home = fs.existsSync(${JSON.stringify(homedir())}) ? fs.readdirSync(${JSON.stringify(homedir())}) : [];
    const tmp = fs.readdirSync("/tmp");
    let net = "blocked"; try { await fetch("http://1.1.1.1", { signal: AbortSignal.timeout(2000) }); net = "open"; } catch {}
    console.log(JSON.stringify({ seen, home, tmp, net }));`;
  const p = Bun.spawn(bwrapArgv([process.execPath, "-e", probe]), { stdout: "pipe", stderr: "pipe", env: { PATH: "/usr/bin:/bin" } });
  const out = await new Response(p.stdout).text();
  expect(await p.exited, await new Response(p.stderr).text()).toBe(0);
  const r = JSON.parse(out);
  expect({ seen: r.seen, tmp: r.tmp, net: r.net }).toEqual({ seen: [], tmp: [], net: "blocked" });
  // Only first path segments that lead to a mount (e.g. ".bun", "work"); never dotfiles like .ssh or .bashrc.
  const leads = [dirname(realpathSync(process.execPath)), repo].filter((p) => p.startsWith(homedir() + "/")).map((p) => p.slice(homedir().length + 1).split("/")[0]);
  for (const n of r.home) expect(leads).toContain(n);
});

test.skipIf(!linux)("analysis runs under bubblewrap on Linux", async () => {
  const r = await runAnalysis("function analyze(rows){ return rows.length }", { columns: [], rows: [{ a: 1 }, { a: 2 }] } as any);
  expect(r.sandbox).toBe("linux-bwrap");
  expect(r.ok).toBe(true);
  expect(r.result).toBe(2);
});
