import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_TOML, parseConfig } from "../src/config";
import { EventLog, severityOf } from "../src/events";

const tmp = () => mkdtempSync(join(tmpdir(), "hib-ev-"));
const read = (file: string) => (existsSync(file) ? readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const log = (over: Partial<ConstructorParameters<typeof EventLog>[0]> = {}) => new EventLog({ enabled: true, dir: join(tmp(), "events"), maxMb: 20, keep: 5, ...over });

describe("event lines", () => {
  test("common fields on every line; absent optional fields are left out, never null", () => {
    const ev = log();
    ev.emit("session.start", { mode: "workspace", session_id: "s1", workspace: "/w", account: "claude@work", model: undefined, run_id: "" }, { agent: "claude", sensitive: false, gone: undefined });
    const [l] = read(ev.file);
    expect(l).toMatchObject({ schema: 1, source: "hib", event: "session.start", severity: "info", mode: "workspace", session_id: "s1", workspace: "/w", account: "claude@work", agent: "claude", sensitive: false });
    expect(l.ts).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    expect(typeof l.host).toBe("string");
    expect(typeof l.hib_version).toBe("string");
    for (const k of ["model", "run_id", "route", "gone"]) expect(k in l).toBe(false);
  });

  test("directory 0700, file 0600, one line per event", () => {
    const ev = log();
    ev.emit("daemon.start", { mode: "daemon" }, { bind: "127.0.0.1", port: 4141, sandbox: "available" });
    ev.emit("daemon.stop", { mode: "daemon" });
    expect(statSync(ev.cfg.dir).mode & 0o777).toBe(0o700);
    expect(statSync(ev.file).mode & 0o777).toBe(0o600);
    expect(readFileSync(ev.file, "utf8").split("\n")).toHaveLength(3); // two lines and the final "\n"
  });

  test("disabled: nothing is written, not even the directory", () => {
    const ev = log({ enabled: false });
    ev.emit("daemon.start", { mode: "daemon" });
    expect(existsSync(ev.cfg.dir)).toBe(false);
  });

  test("severity is fixed per type; decisions against the request are warnings", () => {
    expect(severityOf("protected.reverted", {})).toBe("critical");
    expect(severityOf("terminal.open", {})).toBe("warning");
    expect(severityOf("guard.decision", { action: "redacted" })).toBe("info");
    expect(severityOf("guard.decision", { action: "timeout" })).toBe("warning");
    expect(severityOf("tool.permission", { decision: "always" })).toBe("info");
    expect(severityOf("tool.permission", { decision: "deny" })).toBe("warning");
    expect(severityOf("sandbox.network", { decision: "deny" })).toBe("warning");
    expect(severityOf("something.new", {})).toBe("info");
  });
});

describe("what may go in", () => {
  test("user text is redacted and cut to 300 characters", () => {
    const ev = log();
    const out = ev.redact("mysql -u app -pS3cretPassw0rd -h 10.0.0.5 --email ana.kovac@acme.hr AKIAABCDEFGHIJKLMNOP");
    for (const v of ["S3cretPassw0rd", "10.0.0.5", "ana.kovac@acme.hr", "AKIAABCDEFGHIJKLMNOP"]) expect(out).not.toContain(v);
    expect(out).toContain("mysql -u app");
    expect(out).not.toContain("HIB"); // labels, not vault tokens: nothing in the log points into a vault
    const long = ev.redact("x".repeat(400));
    expect(long).toHaveLength(301);
    expect(long.endsWith("…")).toBe(true);
  });

  test("paths inside the workspace are relative; outside it they're redacted", () => {
    const ev = log();
    expect(ev.path("/w/app/src/a.ts", "/w/app")).toBe("src/a.ts");
    expect(ev.path("src/a.ts", "/w/app")).toBe("src/a.ts");
    expect(ev.path("/w/other/a.ts", "/w/app")).toBe("/w/other/a.ts");
  });
});

describe("rotation", () => {
  test("by size, keeping `keep` old files", () => {
    const ev = log({ maxMb: 600 / (1024 * 1024), keep: 2 });
    for (let i = 0; i < 20; i++) ev.emit("daemon.start", { mode: "daemon" }, { n: i });
    expect(existsSync(`${ev.file}.1`)).toBe(true);
    expect(existsSync(`${ev.file}.2`)).toBe(true);
    expect(existsSync(`${ev.file}.3`)).toBe(false);
    expect(statSync(ev.file).size).toBeLessThanOrEqual(600);
    // Newest in the live file, older ones shifted up, nothing out of order.
    const all = [...read(`${ev.file}.2`), ...read(`${ev.file}.1`), ...read(ev.file)].map((l) => l.n);
    expect(all).toEqual([...all].sort((a, b) => a - b));
    expect(all.at(-1)).toBe(19);
  });

  test("a restarted log appends and keeps counting the size already on disk", () => {
    const cfg = { enabled: true, dir: join(tmp(), "events"), maxMb: 400 / (1024 * 1024), keep: 1 };
    new EventLog(cfg).emit("daemon.start", { mode: "daemon" }, { pad: "x".repeat(250) });
    new EventLog(cfg).emit("daemon.start", { mode: "daemon" }, { pad: "y".repeat(250) });
    expect(read(join(cfg.dir, "events.jsonl.1"))[0].pad[0]).toBe("x");
    expect(read(join(cfg.dir, "events.jsonl"))[0].pad[0]).toBe("y");
  });
});

describe("auth failures", () => {
  test("one line per reason and peer per minute, the rest counted on the next line", () => {
    const ev = log();
    for (let i = 0; i < 5; i++) ev.authFailure("token", "/hib/info", "127.0.0.1");
    ev.authFailure("origin", "/hib/info", "127.0.0.1");
    ev.authFailure("token", "/hib/info", "10.9.9.9");
    const lines = read(ev.file);
    expect(lines.map((l) => [l.reason, l.remote, l.count])).toEqual([
      ["token", "127.0.0.1", 1],
      ["origin", "127.0.0.1", 1],
      ["token", "10.9.9.9", 1],
    ]);
    expect(lines[0]).toMatchObject({ event: "auth.failure", severity: "warning", mode: "daemon", path: "/hib/info" });
  });
});

describe("config", () => {
  test("defaults: on, $HIB_HOME/events, 20 MB, 5 kept", () => {
    const home = tmp();
    expect(parseConfig(Bun.TOML.parse(DEFAULT_TOML) as any, home).events).toEqual({ enabled: true, dir: join(home, "events"), maxMb: 20, keep: 5 });
  });

  test("keys as written in config.toml", () => {
    const home = tmp();
    const raw = { events: { enabled: false, dir: join(home, "..", "elsewhere"), max_mb: 5, keep: 2 } };
    expect(parseConfig(raw, home).events).toMatchObject({ enabled: false, maxMb: 5, keep: 2 });
  });

  test("the directory may not be hib's home or hold it: a collector would mount the token and vault key", () => {
    const home = join(tmp(), "hib");
    expect(() => parseConfig({ events: { dir: home } }, home)).toThrow(/must not be or contain/);
    expect(() => parseConfig({ events: { dir: join(home, "..") } }, home)).toThrow(/must not be or contain/);
  });
});
