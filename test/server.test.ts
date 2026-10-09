import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig } from "../src/config";
import { memoryDb } from "../src/db";
import { Engine } from "../src/engine";
import { Sealer } from "../src/guard/seal";
import { Registry } from "../src/providers/registry";
import { startServer } from "../src/server";

const TOKEN = "test-token";
let server: ReturnType<typeof startServer>, base: string;

beforeAll(async () => {
  const home = mkdtempSync(join(tmpdir(), "hib-srv-"));
  const cfg = parseConfig(Bun.TOML.parse(`[routes.code]\ncandidates = []\n`) as any, home);
  const engine = new Engine(cfg, memoryDb(), new Registry([]), await Sealer.open(home), { skills: new Map(), agents: new Map(), routes: [], guardTerms: [], guardPatterns: [], askOn: [], advisor: [], providers: [], warnings: [] });
  const port = 41000 + Math.floor(Math.random() * 2000);
  server = startServer(engine, { port, token: TOKEN, onShutdown: () => {} });
  base = `http://127.0.0.1:${port}`;
});
afterAll(() => server.stop(true));

describe("browser login", () => {
  test("a local process without the token gets no cookie", async () => {
    const r = await fetch(`${base}/hib/session`);
    expect(r.status).toBe(401);
    expect(r.headers.get("set-cookie")).toBeNull();
    expect((await fetch(`${base}/hib/login`, { method: "POST" })).status).toBe(401);
    expect((await fetch(`${base}/hib/session?code=guess`)).headers.get("set-cookie")).toBeNull();
  });

  test("a code minted with the token logs in exactly once", async () => {
    const { code } = (await (await fetch(`${base}/hib/login`, { method: "POST", headers: { authorization: `Bearer ${TOKEN}` } })).json()) as any;
    const first = await fetch(`${base}/hib/session?code=${code}`);
    expect(first.status).toBe(204);
    expect(first.headers.get("set-cookie")).toContain(`hib_token=${TOKEN}`);
    const again = await fetch(`${base}/hib/session?code=${code}`);
    expect(again.status).toBe(401);
    expect(again.headers.get("set-cookie")).toBeNull();
  });
});
