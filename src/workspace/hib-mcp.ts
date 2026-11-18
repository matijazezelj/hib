#!/usr/bin/env bun
/**
 * hib's own MCP server (stdio), started by the agent CLI. It holds no credentials: each call goes to the hib daemon with
 * a per-session key that can do only that.
 * - `advisor` (HIB_ADVISOR_KEY): the daemon builds the context, guards it and asks a model from the other provider.
 * - Trusted read-only MCP servers (HIB_MCP_KEY): their read-only tools, as `<server>__<tool>`. The daemon checks each
 *   call against the tools it offered, calls the server with a token this process never sees, and returns the result
 *   after the guard.
 */
const { HIB_URL, HIB_ADVISOR_KEY, HIB_MCP_KEY, HIB_SESSION } = process.env;

const ADVISOR = {
  name: "advisor",
  description:
    "Consult a reviewer from a different AI provider. It sees the user's task, a summary of this session and the current git diff, " +
    "and replies with advice. Call it before substantive work (before writing code or committing to an approach), when stuck or " +
    "going in circles, and when you believe the task is done, before saying so. Give its advice serious weight; if you have " +
    "evidence it is wrong, say so and continue.",
  inputSchema: {
    type: "object",
    properties: { question: { type: "string", description: "What you want advice on: your plan, the problem you are stuck on, or what you did and want checked." } },
    required: ["question"],
  },
  // Claude Code defers MCP tool schemas by default; a deferred tool can get called with no arguments.
  _meta: { "anthropic/alwaysLoad": true },
};

function reply(id: unknown, result: unknown) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}
const text = (t: string, isError = false) => ({ content: [{ type: "text", text: t }], isError });

async function advise(question: string): Promise<{ text: string; isError?: boolean }> {
  try {
    const r = await fetch(`${HIB_URL}/ws/advise`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-hib-advisor": HIB_ADVISOR_KEY ?? "" },
      body: JSON.stringify({ sessionId: HIB_SESSION, question }),
    });
    const b: any = await r.json();
    return r.ok ? { text: b.advice } : { text: `advisor unavailable: ${b.error?.message ?? r.status}`, isError: true };
  } catch (e: any) {
    return { text: `advisor unavailable: ${e?.message ?? e}`, isError: true };
  }
}

/** The daemon's side of a trusted server: tools/list or tools/call. */
async function daemon(method: string, params: unknown): Promise<any> {
  const r = await fetch(`${HIB_URL}/ws/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-hib-mcp": HIB_MCP_KEY ?? "" },
    body: JSON.stringify({ sessionId: HIB_SESSION, method, params }),
  });
  const b: any = await r.json();
  if (!r.ok) throw new Error(b.error?.message ?? `HTTP ${r.status}`);
  return b.result;
}

async function handle(m: any) {
  if (m.id === undefined) return; // notifications
  switch (m.method) {
    case "initialize":
      return reply(m.id, { protocolVersion: m.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "hib", version: "1" } });
    case "ping":
      return reply(m.id, {});
    case "tools/list": {
      const tools: unknown[] = HIB_ADVISOR_KEY ? [ADVISOR] : [];
      if (HIB_MCP_KEY)
        try {
          tools.push(...(await daemon("tools/list", {})).tools);
        } catch {} // the daemon says why in the session's timeline
      return reply(m.id, { tools });
    }
    case "tools/call": {
      const name = String(m.params?.name ?? "");
      if (name === "advisor" && HIB_ADVISOR_KEY) {
        const question = String(m.params?.arguments?.question ?? "").trim();
        if (!question) return reply(m.id, text('Missing "question". Call advisor with {"question": "<your plan, problem or what you did>"}.', true));
        const r = await advise(question);
        return reply(m.id, text(r.text, !!r.isError));
      }
      if (!HIB_MCP_KEY) return reply(m.id, text(`unknown tool ${name}`, true));
      try {
        return reply(m.id, await daemon("tools/call", { name, arguments: m.params?.arguments ?? {} }));
      } catch (e: any) {
        return reply(m.id, text(`hib couldn't run ${name}: ${e?.message ?? e}`, true));
      }
    }
    default:
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: `method not found: ${m.method}` } }) + "\n");
  }
}

let buf = "";
for await (const chunk of process.stdin) {
  buf += Buffer.from(chunk).toString("utf8");
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    try {
      void handle(JSON.parse(line));
    } catch {}
  }
}
