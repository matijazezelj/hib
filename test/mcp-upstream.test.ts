import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig, type McpUpstream } from "../src/config";
import { claudeLaunch } from "../src/workspace/claude-driver";
import { userMcpServers } from "../src/workspace/codex-driver";
import { cutResult, McpClient, readOnlyTools, readToken, resultText } from "../src/workspace/mcp-upstream";
import { fakeMcp, type FakeMcp } from "./helpers/fake-mcp";

const dir = () => mkdtempSync(join(tmpdir(), "hib-mcpu-"));
const up = (o: Partial<McpUpstream> = {}): McpUpstream => ({ name: "oib", url: "http://127.0.0.1:1/mcp", sensitive: false, tools: [], ...o });

describe("[mcp.<name>] config", () => {
  const parse = (mcp: unknown) => parseConfig({ mcp } as any, dir()).mcp;
  test("only read_only = true entries exist to hib; the rest is checked strictly", () => {
    expect(parse({ oib: { url: "http://127.0.0.1:3030/mcp", token_file: "~/x.env", token_key: "K", read_only: true, sensitive: true, tools: ["query_*"] } })).toEqual([
      { name: "oib", url: "http://127.0.0.1:3030/mcp", tokenFile: expect.stringMatching(/\/x\.env$/), tokenKey: "K", sensitive: true, tools: ["query_*"] },
    ]);
    expect(parse({ rw: { url: "http://x/mcp" }, rw2: { url: "http://x/mcp", read_only: false } })).toEqual([]);
    expect(() => parse({ a: { url: "ftp://x", read_only: true } })).toThrow("[mcp.a] url");
    expect(() => parse({ a: { url: "http://u:p@x/mcp", read_only: true } })).toThrow("not in the url");
    expect(() => parse({ hib: { url: "http://x/mcp", read_only: true } })).toThrow("not hib");
    expect(() => parse({ "a__b": { url: "http://x/mcp", read_only: true } })).toThrow("without __");
    expect(() => parse({ a: { url: "http://x/mcp", read_only: true, token_file: "f", token_env: "E" } })).toThrow("not both");
    expect(() => parse({ a: { url: "http://x/mcp", read_only: true, sensitive: "yes" } })).toThrow("sensitive");
    expect(parseConfig({} as any, dir()).mcp).toEqual([]);
  });
});

describe("token", () => {
  test("the file's only key, the key named, or the whole file; several keys without token_key is an error naming them", () => {
    const d = dir();
    const two = join(d, "mcp.env");
    writeFileSync(two, "# OIB\nGRAFANA_SERVICE_ACCOUNT_TOKEN=glsa_aaa\nexport MCP_GRAFANA_SERVER_TOKEN=\"mcp-bbb\"\n");
    expect(() => readToken(up({ tokenFile: two }))).toThrow("several keys (GRAFANA_SERVICE_ACCOUNT_TOKEN, MCP_GRAFANA_SERVER_TOKEN): set token_key");
    expect(readToken(up({ tokenFile: two, tokenKey: "MCP_GRAFANA_SERVER_TOKEN" }))).toBe("mcp-bbb");
    expect(() => readToken(up({ tokenFile: two, tokenKey: "NOPE" }))).toThrow("has no NOPE (it has GRAFANA_SERVICE_ACCOUNT_TOKEN, MCP_GRAFANA_SERVER_TOKEN)");
    const one = join(d, "one.env");
    writeFileSync(one, "TOKEN='only'\n");
    expect(readToken(up({ tokenFile: one }))).toBe("only");
    const raw = join(d, "raw");
    writeFileSync(raw, "plain-token\n");
    expect(readToken(up({ tokenFile: raw }))).toBe("plain-token");
    expect(() => readToken(up({ tokenFile: join(d, "missing") }))).toThrow("ENOENT");
    expect(readToken(up({ tokenEnv: "T" }), { T: "from-env" })).toBe("from-env");
    expect(() => readToken(up({ tokenEnv: "T" }), {})).toThrow("token_env T isn't set");
    expect(readToken(up())).toBeUndefined();
    // Errors never carry the token.
    try {
      readToken(up({ tokenFile: two, tokenKey: "NOPE" }));
    } catch (e: any) {
      expect(e.message).not.toContain("mcp-bbb");
      expect(e.message).not.toContain("glsa_aaa");
    }
  });
});

describe("which tools", () => {
  const tools = [
    { name: "query_logs", annotations: { readOnlyHint: true } },
    { name: "search_traces", annotations: { readOnlyHint: true } },
    { name: "update_dashboard", annotations: { readOnlyHint: false } },
    { name: "no_annotations" },
    { name: "bad.name", annotations: { readOnlyHint: true } },
  ];
  test("only readOnlyHint tools, narrowed by the globs, never widened", () => {
    expect(readOnlyTools(up(), tools).tools.map((t) => t.name)).toEqual(["query_logs", "search_traces"]);
    expect(readOnlyTools(up({ tools: ["query_*", "update_*", "no_*"] }), tools).tools.map((t) => t.name)).toEqual(["query_logs"]);
    expect(readOnlyTools(up(), tools).note).toContain("2 of its 5 tools aren't marked read-only");
    const none = readOnlyTools(up(), [{ name: "w" }, { name: "x", annotations: {} }]);
    expect(none.tools).toEqual([]);
    expect(none.note).toBe("none of its 2 tools is marked read-only (readOnlyHint), so none is offered");
    expect(readOnlyTools(up({ tools: ["zzz*"] }), tools).note).toContain("no read-only tool matches");
  });
  test("results: text only, the rest named and withheld; a cut never splits a value", () => {
    expect(resultText({ content: [{ type: "image", data: "x" }, { type: "text", text: "hi" }] })).toBe("[hib withheld a part of this result (image): only text is guarded]\nhi");
    expect(resultText({ content: [], structuredContent: { a: 1 } })).toBe('{"a":1}');
    expect(resultText({ content: [{ type: "text", text: "t" }], structuredContent: { secret: 1 } })).toBe("t");
    expect(cutResult("aaa 10.1.2.3 bbb", 10)).toEqual({ text: "aaa", cut: true });
    expect(cutResult("short", 10)).toEqual({ text: "short", cut: false });
  });
});

describe("client", () => {
  let f: FakeMcp | undefined;
  afterEach(() => f?.stop());
  test("JSON and SSE replies, bearer token; errors name the status, never the URL or token", async () => {
    f = fakeMcp();
    const c = new McpClient(up({ url: f.url }), () => f!.token);
    expect((await c.listTools()).map((t) => t.name)).toContain("read_logs");
    const r = await c.callTool("read_logs", { query: "q" });
    expect(resultText(r)).toContain("10.1.2.3");
    expect(f.auth.every((a) => a === `Bearer ${f!.token}`)).toBe(true);
    const bad = new McpClient(up({ url: f.url }), () => "wrong");
    const err = await bad.listTools().catch((e) => e.message);
    expect(err).toBe("HTTP 401 (check its token)");
    const down = await new McpClient(up({ url: "http://127.0.0.1:9/mcp?k=QUERYSECRET" }), () => "t").listTools().catch((e) => e.message);
    expect(down).toBe("can't be reached");
  });
});

describe("the user's own server of the same name is switched off", () => {
  test("Claude: denied; Codex: disabled only when its config defines it (Codex refuses an entry without a transport)", () => {
    const account = { id: "claude@x", provider: "claude", name: "x", env: {}, limits: {}, dirs: [] };
    const { args } = claudeLaunch({ cwd: "/w", model: "m", account, hideMcp: ["oib"] } as any);
    const settings = JSON.parse(args[args.indexOf("--settings") + 1]!);
    expect(settings.permissions.deny).toContain("mcp__oib");
    const home = dir(), cwd = dir();
    writeFileSync(join(home, "config.toml"), '[mcp_servers.oib]\nurl = "http://x"\n[mcp_servers.other]\ncommand = "x"\n');
    expect(userMcpServers(home, cwd).sort()).toEqual(["oib", "other"]);
    expect(userMcpServers(dir(), cwd)).toEqual([]);
  });
});

describe("hib's MCP server (the shim in the CLI)", () => {
  test("lists and calls trusted tools through the daemon with its key; the advisor only with its own key", async () => {
    const seen: any[] = [];
    const daemon = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(req) {
        const b: any = await req.json();
        seen.push({ path: new URL(req.url).pathname, key: req.headers.get("x-hib-mcp"), ...b });
        if (b.method === "tools/list") return Response.json({ result: { tools: [{ name: "oib__read_logs", inputSchema: { type: "object" } }] } });
        return Response.json({ result: { content: [{ type: "text", text: "guarded" }], isError: false } });
      },
    });
    const proc = Bun.spawn(["bun", new URL("../src/workspace/hib-mcp.ts", import.meta.url).pathname], {
      env: { ...process.env, HIB_URL: `http://127.0.0.1:${daemon.port}`, HIB_MCP_KEY: "k1", HIB_SESSION: "s1", HIB_ADVISOR_KEY: "" },
      stdin: "pipe",
      stdout: "pipe",
    });
    const send = (m: unknown) => (proc.stdin.write(JSON.stringify(m) + "\n"), proc.stdin.flush());
    send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "oib__read_logs", arguments: { query: "q" } } });
    send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "advisor", arguments: { question: "q" } } });
    const out: any[] = [];
    const reader = proc.stdout.getReader();
    let buf = "";
    while (out.length < 3) {
      const { value } = await reader.read();
      buf += new TextDecoder().decode(value);
      const lines = buf.split("\n");
      buf = lines.pop()!;
      out.push(...lines.filter(Boolean).map((l) => JSON.parse(l)));
    }
    proc.kill();
    daemon.stop(true);
    const by = (id: number) => out.find((m) => m.id === id).result;
    expect(by(1).tools.map((t: any) => t.name)).toEqual(["oib__read_logs"]); // no advisor without its key
    expect(by(2)).toEqual({ content: [{ type: "text", text: "guarded" }], isError: false });
    expect(by(3)).toEqual(by(2)); // "advisor" without its key is just a name: the daemon decides (and refuses it)
    // Requests run concurrently: order-free.
    expect(seen).toHaveLength(3);
    expect(seen).toContainEqual({ path: "/ws/mcp", key: "k1", sessionId: "s1", method: "tools/list", params: {} });
    expect(seen).toContainEqual({ path: "/ws/mcp", key: "k1", sessionId: "s1", method: "tools/call", params: { name: "oib__read_logs", arguments: { query: "q" } } });
    expect(seen).toContainEqual({ path: "/ws/mcp", key: "k1", sessionId: "s1", method: "tools/call", params: { name: "advisor", arguments: { question: "q" } } });
  });
});
