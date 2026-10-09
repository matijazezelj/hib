import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig } from "../src/config";
import { memoryDb } from "../src/db";
import { Engine } from "../src/engine";
import { Sealer } from "../src/guard/seal";
import { Registry } from "../src/providers/registry";
import { startServer } from "../src/server";

const TOKEN = "test-token";
let server: ReturnType<typeof startServer>, base: string, engine: Engine;

beforeAll(async () => {
  const home = mkdtempSync(join(tmpdir(), "hib-srv-"));
  const cfg = parseConfig(Bun.TOML.parse(`[models.claude]\nsonnet = "balanced"\n[providers.claude]\ndefault = "main"\n[providers.claude.accounts.main]\nenv = {}\n[routes.code]\ncandidates = []\n`) as any, home);
  engine = new Engine(cfg, memoryDb(), new Registry([]), await Sealer.open(home), { skills: new Map(), agents: new Map(), routes: [], guardTerms: [], guardPatterns: [], askOn: [], advisor: [], providers: [], warnings: [] });
  const port = 41000 + Math.floor(Math.random() * 2000);
  server = startServer(engine, { port, token: TOKEN, onShutdown: () => {} });
  base = `http://127.0.0.1:${port}`;
});
afterAll(() => server.stop(true));

describe("browser login", () => {
  const login = async () => ((await (await fetch(`${base}/hib/login`, { method: "POST", headers: { authorization: `Bearer ${TOKEN}` } })).json()) as any).code as string;
  const session = (code: string) => fetch(`${base}/hib/session`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code }) });

  test("a local process without the token gets nothing", async () => {
    expect((await fetch(`${base}/hib/login`, { method: "POST" })).status).toBe(401);
    expect((await session("guess")).status).toBe(401);
    expect((await fetch(`${base}/hib/info`)).status).toBe(401);
  });

  test("a code buys one browser session id, never the token, and only once", async () => {
    const code = await login();
    const r = await session(code);
    expect(r.status).toBe(200);
    expect(r.headers.get("set-cookie")).toBeNull(); // a cookie on 127.0.0.1 would reach every other local port
    const sid = ((await r.json()) as any).session as string;
    expect(sid).not.toContain(TOKEN);
    expect((await fetch(`${base}/hib/info`, { headers: { authorization: `Bearer ${sid}` } })).status).toBe(200);
    expect((await session(code)).status).toBe(401);
  });

  test("another site can't use it, and the old cookie no longer works", async () => {
    const sid = ((await (await session(await login())).json()) as any).session;
    expect((await fetch(`${base}/hib/info`, { headers: { authorization: `Bearer ${sid}`, origin: "https://evil.example" } })).status).toBe(401);
    expect((await fetch(`${base}/hib/info`, { headers: { cookie: `hib_token=${TOKEN}` } })).status).toBe(401);
  });
});

describe("browser sessions end and can be revoked", () => {
  const login = async () => ((await (await fetch(`${base}/hib/login`, { method: "POST", headers: { authorization: `Bearer ${TOKEN}` } })).json()) as any).code as string;
  const newSession = async () => ((await (await fetch(`${base}/hib/session`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code: await login() }) })).json()) as any).session as string;
  const info = (sid: string) => fetch(`${base}/hib/info`, { headers: { authorization: `Bearer ${sid}` } }).then((r) => r.status);
  const hash = (sid: string) => new Bun.CryptoHasher("sha256").update(sid).digest("hex");

  test("after 12 idle hours, and after 7 days however busy", async () => {
    const idle = await newSession();
    engine.db.run("UPDATE browser_sessions SET last_used = ? WHERE hash = ?", [Date.now() - 13 * 3600_000, hash(idle)]);
    expect(await info(idle)).toBe(401);
    const old = await newSession();
    engine.db.run("UPDATE browser_sessions SET created = ? WHERE hash = ?", [Date.now() - 8 * 24 * 3600_000, hash(old)]);
    expect(await info(old)).toBe(401);
  });

  test("sign-out ends this browser only; the token signs every browser out", async () => {
    const [a, b] = [await newSession(), await newSession()];
    await fetch(`${base}/hib/session`, { method: "DELETE", headers: { authorization: `Bearer ${a}` } });
    expect([await info(a), await info(b)]).toEqual([401, 200]);
    await fetch(`${base}/hib/session`, { method: "DELETE", headers: { authorization: `Bearer ${TOKEN}` } });
    expect(await info(b)).toBe(401);
  });

  test("the terminal opens with a one-time ticket for one folder, never a session in the URL", async () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "hib-term-")));
    const h = { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" };
    await fetch(`${base}/hib/workspaces`, { method: "POST", headers: h, body: JSON.stringify({ root: dir }) });
    const sid = await newSession();
    const root = encodeURIComponent(dir);
    const ws = (query: string) => fetch(`${base}/ws/terminal?root=${root}&${query}`, { headers: { upgrade: "websocket", connection: "Upgrade", "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==", "sec-websocket-version": "13" } }).then((r) => r.status);
    expect(await ws(`session=${sid}`)).toBe(401);
    const ticket = ((await (await fetch(`${base}/ws/terminal/ticket?root=${root}`, { method: "POST", headers: { authorization: `Bearer ${sid}` } })).json()) as any).ticket;
    expect(await ws(`ticket=${ticket}`)).toBe(101);
    expect(await ws(`ticket=${ticket}`)).toBe(401); // burnt
  });
});

describe("sensitive folders over HTTP", () => {
  test("forgetting one (which would drop its policy) is refused", async () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "hib-sens-")));
    const h = { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" };
    await fetch(`${base}/hib/workspaces`, { method: "POST", headers: h, body: JSON.stringify({ root: dir }) });
    engine.workspaces.setPolicy(dir, { sensitive: true, account: "claude@main" });
    expect((await fetch(`${base}/hib/workspaces?root=${encodeURIComponent(dir)}`, { method: "DELETE", headers: h })).status).toBe(403);
    expect(engine.workspaces.policy(dir)).not.toBeNull();
  });
});
