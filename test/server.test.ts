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
