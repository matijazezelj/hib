import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_TOML, parseConfig } from "../src/config";
import { EventLog, severityOf } from "../src/events";

const tmp = () => mkdtempSync(join(tmpdir(), "hib-ev-"));
const read = (file: string) => (existsSync(file) ? readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const log = (over: Partial<ConstructorParameters<typeof EventLog>[0]> = {}) => new EventLog({ enabled: true, dir: join(tmp(), "events"), maxMb: 20, keep: 5, heartbeatSec: 0, ...over });

describe("event lines", () => {
  test("common fields on every line; absent optional fields are left out, never null", () => {
    const ev = log();
    ev.emit("session.start", { mode: "workspace", session_id: "s1", workspace: "/w", account: "claude@work", model: undefined, run_id: "" }, { agent: "claude", sensitive: false, gone: undefined });
    const [l] = read(ev.file);
    expect(l).toMatchObject({ schema: 1, source: "hib", event: "session.start", severity: "info", mode: "workspace", session_id: "s1", workspace: "/w", account: "claude@work", agent: "claude", sensitive: false });
    expect(l.ts).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    expect(typeof l.host).toBe("string");
    expect(l.hib_version).toBe(require("../package.json").version);
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
    expect(severityOf("home.changed", { changes: [{ approved: false, prefs_only: true }, { approved: true }] })).toBe("warning");
    expect(severityOf("home.changed", { changes: [{ approved: false, prefs_only: true }, { approved: false }] })).toBe("critical");
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
    const cfg = { enabled: true, dir: join(tmp(), "events"), maxMb: 400 / (1024 * 1024), keep: 1, heartbeatSec: 0 };
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
    expect(parseConfig(Bun.TOML.parse(DEFAULT_TOML) as any, home).events).toEqual({ enabled: true, dir: join(home, "events"), maxMb: 20, keep: 5, heartbeatSec: 300, profile: "local", workspace: "path", account: "name", netHost: "full", command: "full", remote: true, keyFile: join(home, "events.key") });
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

describe("stopping", () => {
  test("failures counted in an open window are written before daemon.stop", () => {
    const ev = log();
    ev.authFailure("token", "/hib/info", "127.0.0.1");
    for (let i = 0; i < 3; i++) ev.authFailure("token", "/v1/models", "127.0.0.1");
    ev.authFailure("origin", "/hib/info", "127.0.0.1"); // a window with nothing pending writes nothing more
    ev.stop();
    const lines = read(ev.file).map((l) => [l.event, l.reason, l.count]);
    expect(lines).toEqual([
      ["auth.failure", "token", 1],
      ["auth.failure", "origin", 1],
      ["auth.failure", "token", 3],
      ["daemon.stop", undefined, undefined],
    ]);
    const total = read(ev.file).filter((l) => l.event === "auth.failure" && l.reason === "token").reduce((n, l) => n + l.count, 0);
    expect(total).toBe(4); // what SIB alerts on: the sum of count
  });
});

describe("heartbeat", () => {
  test("daemon.alive every heartbeat_sec, the first one an interval after start, none after daemon.stop", async () => {
    const ev = log({ heartbeatSec: 0.05 });
    ev.emit("daemon.start", { mode: "daemon" });
    ev.startHeartbeat();
    expect(read(ev.file).map((l) => l.event)).toEqual(["daemon.start"]); // not immediately
    await Bun.sleep(130);
    const alive = read(ev.file).filter((l) => l.event === "daemon.alive");
    expect(alive.length).toBeGreaterThanOrEqual(2);
    expect(alive[0]).toMatchObject({ severity: "info", mode: "daemon" });
    expect(alive.every((l) => Number.isInteger(l.uptime_sec))).toBe(true);
    ev.stop();
    const n = read(ev.file).length;
    await Bun.sleep(120);
    expect(read(ev.file)).toHaveLength(n);
    expect(read(ev.file).at(-1).event).toBe("daemon.stop");
  });

  test("heartbeat_sec = 0 writes none", async () => {
    const ev = log({ heartbeatSec: 0 });
    ev.startHeartbeat();
    await Bun.sleep(60);
    expect(read(ev.file)).toEqual([]);
  });

  test("on stop: sessions end first, then counted auth failures, then daemon.stop, which stays the last line", () => {
    const ev = log();
    ev.onStop(() => ev.emit("session.end", { mode: "workspace", session_id: "w_1" }, { agent: "claude", sensitive: false }));
    ev.authFailure("token", "/hib/info", "127.0.0.1");
    ev.authFailure("token", "/hib/info", "127.0.0.1");
    ev.stop({ signal: "SIGTERM" });
    ev.stop(); // a second stop (signal after /hib/shutdown) writes nothing
    ev.emit("session.end", { mode: "workspace" }, {}); // nor does anything after it
    expect(read(ev.file).map((l) => [l.event, l.count ?? l.signal ?? ""])).toEqual([
      ["auth.failure", 1],
      ["session.end", ""],
      ["auth.failure", 1],
      ["daemon.stop", "SIGTERM"],
    ]);
  });
});

describe("coarsening", () => {
  const ctx = { mode: "workspace" as const, session_id: "s1", workspace: "/home/ana/code/payroll", account: "claude@work" };
  const fields = { tool: "Bash", command: "GITHUB_TOKEN=[CREDENTIALS] sudo -E /usr/bin/curl -s https://api.eu.example.com/x", url: "https://deploy:[CREDENTIALS]@api.eu.example.com/v1/items?a=1", net_host: "api.eu.example.com:443", decision: "allow", decided_by: "user" };

  test("defaults log every field whole", () => {
    const ev = log();
    ev.emit("tool.permission", ctx, fields);
    ev.authFailure("token", "/hib/chat", "127.0.0.1");
    const [l, a] = read(ev.file);
    expect(l).toMatchObject({ workspace: "/home/ana/code/payroll", account: "claude@work", net_host: "api.eu.example.com:443" });
    expect(l.command).toContain("curl -s");
    expect(a.remote).toBe("127.0.0.1");
  });

  test("name, domain, program, no remote", () => {
    const ev = log({ workspace: "name", netHost: "domain", command: "program", remote: false });
    ev.emit("tool.permission", ctx, fields);
    ev.authFailure("token", "/hib/chat", "127.0.0.1");
    const [l, a] = read(ev.file);
    expect(l).toMatchObject({ workspace: "payroll", account: "claude@work", net_host: "example.com", url: "https://example.com", command: "curl" });
    expect("remote" in a).toBe(false);
  });

  test("hashes are keyed, stable across restarts with the same key file, and differ with another key", () => {
    const keyFile = join(tmp(), "home", "events.key");
    const a = log({ workspace: "hash", account: "hash", keyFile });
    a.emit("session.start", ctx);
    const b = log({ workspace: "hash", account: "hash", keyFile });
    b.emit("session.start", ctx);
    const c = log({ workspace: "hash", account: "hash", keyFile: join(tmp(), "events.key") });
    c.emit("session.start", ctx);
    const [la, lb, lc] = [read(a.file)[0], read(b.file)[0], read(c.file)[0]];
    expect(la.workspace).toMatch(/^[0-9a-f]{16}$/);
    expect(la.account).toMatch(/^claude@[0-9a-f]{16}$/);
    expect(lb.workspace).toBe(la.workspace);
    expect(lb.account).toBe(la.account);
    expect(lc.workspace).not.toBe(la.workspace);
    expect(statSync(keyFile).mode & 0o777).toBe(0o600);
    expect(readFileSync(a.file, "utf8")).not.toContain("payroll");
  });

  test("domainOf: Public Suffix List, loopback, IPs, internal names", () => {
    const { domainOf } = require("../src/events");
    const cases: [string, string][] = [
      ["a.b.example.co.uk", "example.co.uk"],
      ["x.example.com.au", "example.com.au"],
      ["you.github.io", "github.io"], // a private suffix: ICANN only, so the user name doesn't leave the machine
      ["Registry.NPMjs.org.", "npmjs.org"],
      ["api.eu.example.com:443", "example.com"],
      ["localhost", "localhost"],
      ["[::1]:8080", "localhost"],
      ["127.0.0.1", "localhost"],
      ["10.0.0.5:8080", "[IP-INTERNAL]"],
      ["[fd00::1]", "[IP-INTERNAL]"],
      ["8.8.8.8", "[IP-EXTERNAL]"],
      ["db1.prod.corp", "[INTERNAL]"],
      ["printer.local", "[INTERNAL]"],
      ["vault.internal", "[INTERNAL]"],
      ["intranet", "[INTERNAL]"],
    ];
    for (const [host, want] of cases) expect([host, domainOf(host)]).toEqual([host, want]);
  });

  test("programOf: a best-effort label past wrappers, their option values and sh -c", () => {
    const { programOf } = require("../src/events");
    const cases: [string, string][] = [
      ["FOO=1 BAR=2 env -i ./scripts/deploy.sh --prod", "deploy.sh"],
      ["sudo -u root curl https://example.com", "curl"],
      ["sudo --user=root -E VAR=1 /usr/bin/git push", "git"],
      ["bash -c 'curl https://example.com'", "curl"],
      ["sh -ec \"npm test\"", "npm"],
      ["env -S \"python3 -u\" x", "python3"],
      ["timeout 10 nice -n 5 make", "make"],
      ["time -f %e ./run.sh", "run.sh"],
      ["cat x | curl -d @- https://e.com", "cat"], // pipelines aren't followed
      ["  ", "[COMMAND]"],
    ];
    for (const [cmd, want] of cases) expect([cmd, programOf(cmd)]).toEqual([cmd, want]);
  });

  test("the hash key is refused unless hib could have made it", () => {
    const { readKey } = require("../src/events");
    const { writeFileSync, symlinkSync, mkdirSync, chmodSync } = require("node:fs");
    const dir = tmp();
    const good = join(dir, "good.key");
    writeFileSync(good, "ab".repeat(32) + "\n", { mode: 0o600 });
    expect(readKey(good)).toHaveLength(32);
    symlinkSync(good, join(dir, "link.key"));
    expect(() => readKey(join(dir, "link.key"))).toThrow(/symlink/);
    writeFileSync(join(dir, "open.key"), "ab".repeat(32), { mode: 0o644 });
    chmodSync(join(dir, "open.key"), 0o644);
    expect(() => readKey(join(dir, "open.key"))).toThrow(/group or others/);
    writeFileSync(join(dir, "short.key"), "abcd", { mode: 0o600 });
    expect(() => readKey(join(dir, "short.key"))).toThrow(/32-byte/);
    mkdirSync(join(dir, "dir.key"), { mode: 0o700 });
    expect(() => readKey(join(dir, "dir.key"))).toThrow(/regular file/);
  });

  test("a refused key drops the line instead of writing the field whole", () => {
    const dir = tmp();
    const keyFile = join(dir, "events.key");
    require("node:fs").writeFileSync(keyFile, "not a key", { mode: 0o600 });
    const ev = log({ workspace: "hash", keyFile });
    const err = console.error;
    console.error = () => {};
    try {
      ev.emit("session.start", ctx);
    } finally {
      console.error = err;
    }
    expect(read(ev.file).map((l: any) => l.event)).toEqual(["events.key_refused"]); // the session line is dropped
  });

  test("config: accepted values, and a wrong value refused", () => {
    const set = parseConfig(Bun.TOML.parse('[events]\nworkspace = "hash"\naccount = "hash"\nnet_host = "domain"\ncommand = "program"\nremote = false') as any, tmp()).events;
    expect(set).toMatchObject({ workspace: "hash", account: "hash", netHost: "domain", command: "program", remote: false });
    expect(() => parseConfig({ events: { workspace: "folder" } }, tmp())).toThrow(/workspace = "folder"/);
    expect(() => parseConfig({ events: { remote: "no" } }, tmp())).toThrow(/remote = "no"/);
    expect(() => parseConfig({ events: { profile: "strict" } }, tmp())).toThrow(/profile/);
  });

  test("config: profile siem coarsens all five, and a single setting overrides it", () => {
    const siem = parseConfig({ events: { profile: "siem" } }, tmp()).events;
    expect(siem).toMatchObject({ profile: "siem", workspace: "hash", account: "hash", netHost: "domain", command: "program", remote: false });
    const mixed = parseConfig({ events: { profile: "siem", command: "full", remote: true } }, tmp()).events;
    expect(mixed).toMatchObject({ workspace: "hash", command: "full", remote: true });
  });
});
