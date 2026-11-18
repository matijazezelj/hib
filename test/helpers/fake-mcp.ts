/**
 * A fake upstream MCP server (streamable HTTP) for hib's trusted-server tests: one read-only tool that echoes its
 * arguments inside a Loki-like result, one write tool, one read-only tool with an image part and a large one.
 * tools/call replies over SSE, the rest as JSON, so both reply shapes are exercised.
 */
export interface FakeMcp {
  url: string;
  token: string;
  calls: { name: string; args: any }[];
  auth: string[]; // Authorization headers seen
  reply: (args: any) => unknown; // read_logs' JSON result
  stop: () => void;
}

export function fakeMcp(token = "tok-SECRET-0123456789"): FakeMcp {
  const f: FakeMcp = {
    url: "",
    token,
    calls: [],
    auth: [],
    reply: (args) => ({ data: { result: [{ stream: { job: "app", user: "marko" }, values: [["1700000000", `query=${args.query}\t10.1.2.3\nlogin by ivana@acme-corp.hr`]] }] } }),
    stop: () => {},
  };
  const tools = [
    { name: "read_logs", description: "Query logs", inputSchema: { type: "object", properties: { query: { type: "string" } } }, annotations: { readOnlyHint: true } },
    { name: "delete_all", description: "Delete everything", inputSchema: { type: "object" }, annotations: { destructiveHint: true } },
    { name: "get_panel_image", description: "A panel as PNG", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } },
    { name: "big_logs", description: "Lots of logs", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } },
  ];
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      f.auth.push(req.headers.get("authorization") ?? "");
      if (req.headers.get("authorization") !== `Bearer ${f.token}`) return new Response("no", { status: 401 });
      const m: any = await req.json();
      if (m.id === undefined) return new Response(null, { status: 202 });
      const ok = (result: unknown, sse = false) => {
        const body = JSON.stringify({ jsonrpc: "2.0", id: m.id, result });
        return sse
          ? new Response(`event: message\ndata: ${body}\n\n`, { headers: { "content-type": "text/event-stream", "mcp-session-id": "s1" } })
          : new Response(body, { headers: { "content-type": "application/json", "mcp-session-id": "s1" } });
      };
      if (m.method === "initialize") return ok({ protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fake", version: "1" } });
      if (m.method === "tools/list") return ok({ tools });
      if (m.method === "tools/call") {
        f.calls.push({ name: m.params.name, args: m.params.arguments });
        if (m.params.name === "read_logs") {
          const out = f.reply(m.params.arguments);
          return ok({ content: [{ type: "text", text: typeof out === "string" ? out : JSON.stringify(out) }] }, true);
        }
        if (m.params.name === "get_panel_image") return ok({ content: [{ type: "image", data: "iVBORw0KGgo=", mimeType: "image/png" }, { type: "text", text: "panel for 10.9.8.7" }] }, true);
        if (m.params.name === "big_logs") return ok({ content: [{ type: "text", text: Array.from({ length: 5000 }, (_, i) => `line ${i} from 10.0.${i % 250}.1 ok`).join("\n") }] }, true);
        return ok({ content: [{ type: "text", text: "deleted" }] }, true);
      }
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "nope" } }), { headers: { "content-type": "application/json" } });
    },
  });
  f.url = `http://127.0.0.1:${server.port}/mcp?api_key=QUERYSECRET`;
  f.stop = () => server.stop(true);
  return f;
}
