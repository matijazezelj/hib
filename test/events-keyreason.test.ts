import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig } from "../src/config";
import { EventLog, readKey } from "../src/events";
import { dataBlockEventReason, rawDataCommand } from "../src/workspace/datarules";

const tmp = () => mkdtempSync(join(tmpdir(), "hib-evk-"));
const read = (file: string) => (existsSync(file) ? readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const HEX = "0123456789abcdef".repeat(4);

describe("readKey", () => {
  test("a valid key file is read", () => {
    const f = join(tmp(), "events.key");
    writeFileSync(f, HEX + "\n", { mode: 0o600 });
    expect(readKey(f).toString("hex")).toBe(HEX);
  });

  test("a file over 65 bytes is refused", () => {
    const f = join(tmp(), "events.key");
    writeFileSync(f, HEX + "\n\n", { mode: 0o600 });
    expect(() => readKey(f)).toThrow(/not a 32-byte hex key/);
    writeFileSync(f, HEX + "0".repeat(1 << 20), { mode: 0o600 });
    expect(() => readKey(f)).toThrow(/not a 32-byte hex key/);
  });

  // A blocking open would freeze this process's event loop, so a test-level timeout couldn't fire: run readKey in a
  // child with a hard kill instead, so a regression fails rather than hangs.
  test(
    "a named pipe is refused without blocking",
    async () => {
      const f = join(tmp(), "events.key");
      expect(Bun.spawnSync(["mkfifo", "-m", "600", f]).success).toBe(true);
      const script = `import { readKey } from ${JSON.stringify(join(import.meta.dir, "../src/events.ts"))};
try { readKey(${JSON.stringify(f)}); console.log("READ"); } catch (e) { console.log("ERR " + e.message); }`;
      const child = Bun.spawn([process.execPath, "-e", script], { stdout: "pipe", stderr: "pipe", timeout: 4000, killSignal: "SIGKILL" });
      const out = await new Response(child.stdout).text();
      await child.exited;
      expect(child.signalCode).toBeNull();
      expect(out).toContain("not a regular file");
    },
    8000,
  );
});

describe("data.block reason", () => {
  const root = "/home/u/proj";
  const outside = "python3 /srv/acme/clients/payroll_2026/extract.py";
  const named = "head -5 salaries_q3";
  const files = new Set(["salaries_q3"]);

  test("rawDataCommand keeps the detail apart from the fixed reason", () => {
    expect(rawDataCommand(outside, root)).toEqual({
      reason: "it runs a script from outside this folder",
      detail: "/srv/acme/clients/payroll_2026/extract.py",
      text: "it runs a script from outside this folder (/srv/acme/clients/payroll_2026/extract.py)",
    });
    expect(rawDataCommand(named, root, files)).toEqual({ reason: "it reads a data file directly", detail: "salaries_q3", text: "it reads salaries_q3 directly" });
    expect(rawDataCommand("python3 -c 'print(1)'", root)).toEqual({ reason: "it runs inline code that could read data files", text: "it runs inline code that could read data files" });
  });

  const emitted = (ev: EventLog, cmd: string, dataFiles?: Set<string>) => {
    const block = rawDataCommand(cmd, root, dataFiles)!;
    ev.emit("data.block", { mode: "workspace" }, { command: ev.redact(cmd), reason: dataBlockEventReason(block, ev.cfg.command, (t) => ev.redact(t)) });
    return read(ev.file).at(-1);
  };

  test("profile siem: the event carries neither the path nor the file name", () => {
    const cfg = parseConfig({ events: { profile: "siem" } }, tmp()).events;
    const ev = new EventLog({ ...cfg, dir: join(tmp(), "events"), keyFile: undefined });
    for (const [cmd, df] of [[outside, undefined], [named, files]] as const) {
      const line = emitted(ev, cmd, df);
      const text = JSON.stringify(line);
      for (const leak of ["/srv/acme", "payroll_2026", "extract.py", "salaries_q3"]) expect(text).not.toContain(leak);
      expect(typeof line.reason).toBe("string");
    }
    expect(read(ev.file).map((l) => l.reason)).toEqual(["it runs a script from outside this folder", "it reads a data file directly"]);
  });

  test("command = full: the detail is kept, redacted", () => {
    const ev = new EventLog({ enabled: true, dir: join(tmp(), "events"), maxMb: 20, keep: 5, heartbeatSec: 0, command: "full" });
    const full = rawDataCommand(outside, root)!.text;
    const reason0 = emitted(ev, outside).reason;
    expect(reason0).toBe(ev.scrub(ev.redact(full))); // the full sentence, through redact (and emit's own scrub)
    expect(reason0).toStartWith("it runs a script from outside this folder (");
    const secret = "python3 /tmp/x.py --token ghp_" + "a".repeat(36);
    const block = { reason: "it runs a script from outside this folder" as const, detail: secret, text: `it runs a script from outside this folder (${secret})` };
    const reason = dataBlockEventReason(block, "full", (t) => ev.redact(t));
    expect(reason).not.toContain("ghp_" + "a".repeat(36));
  });
});
