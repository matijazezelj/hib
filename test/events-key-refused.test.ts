import { describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventLog, KeyRefused, readKey } from "../src/events";

const tmp = () => mkdtempSync(join(tmpdir(), "hib-kr-"));
const read = (file: string) => (existsSync(file) ? readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const HEX = "ab".repeat(32) + "\n";
const log = (keyFile: string) =>
  new EventLog({ enabled: true, dir: join(tmp(), "events"), maxMb: 20, keep: 5, heartbeatSec: 0, workspace: "hash", account: "hash", keyFile } as any);

describe("events.key_refused", () => {
  test("readKey gives a fixed reason code", () => {
    const d = tmp();
    const cases: [string, () => void, string][] = [
      ["open.key", () => { writeFileSync(join(d, "open.key"), HEX); chmodSync(join(d, "open.key"), 0o644); }, "mode"],
      ["short.key", () => writeFileSync(join(d, "short.key"), "abc\n", { mode: 0o600 }), "format"],
      ["link.key", () => { writeFileSync(join(d, "real.key"), HEX, { mode: 0o600 }); symlinkSync(join(d, "real.key"), join(d, "link.key")); }, "symlink"],
    ];
    for (const [name, make, reason] of cases) {
      make();
      let err: unknown;
      try { readKey(join(d, name)); } catch (e) { err = e; }
      expect(err).toBeInstanceOf(KeyRefused);
      expect((err as KeyRefused).reason).toBe(reason as any);
    }
  });

  test("one warning per run, with only the reason; hashed lines dropped, heartbeat-style lines kept", () => {
    const d = tmp();
    const keyFile = join(d, "home", "secret-user", "events.key");
    require("node:fs").mkdirSync(join(d, "home", "secret-user"), { recursive: true });
    writeFileSync(keyFile, HEX);
    chmodSync(keyFile, 0o644);
    const ev = log(keyFile);
    ev.checkKey();
    ev.emit("session.start", { mode: "workspace", workspace: "/w/payroll", account: "claude@ana" });
    ev.emit("session.start", { mode: "workspace", workspace: "/w/payroll" });
    ev.emit("daemon.alive", { mode: "daemon" }, { uptime_sec: 1 });
    const lines = read(ev.file);
    expect(lines.map((l) => l.event)).toEqual(["events.key_refused", "daemon.alive"]);
    expect(lines[0]).toMatchObject({ severity: "warning", reason: "mode", mode: "daemon" });
    expect(readFileSync(ev.file, "utf8")).not.toContain("secret-user");
  });

  test("checkKey makes the key when missing and reports nothing; skipped when nothing hashes", () => {
    const keyFile = join(tmp(), "events.key");
    const ev = log(keyFile);
    ev.checkKey();
    expect(existsSync(keyFile)).toBe(true);
    expect(read(ev.file)).toEqual([]);
    const nope = join(tmp(), "nope", "events.key");
    const off = new EventLog({ enabled: true, dir: join(tmp(), "events"), maxMb: 20, keep: 5, heartbeatSec: 0, keyFile: nope } as any);
    off.checkKey();
    expect(existsSync(nope)).toBe(false);
  });
});
