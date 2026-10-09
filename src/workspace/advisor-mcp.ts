#!/usr/bin/env bun
/**
 * MCP server (stdio) that gives a workspace agent an `advisor` tool. It holds no credentials of its own:
 * each call goes to the hib daemon with a per-session key that can only ask the advisor, and the daemon
 * builds the context, runs it through the guard and asks a model from the other provider.
 */
const { HIB_URL, HIB_ADVISOR_KEY, HIB_SESSION } = process.env;

const TOOL = {
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

async function handle(m: any) {
  if (m.id === undefined) return; // notifications
  switch (m.method) {
    case "initialize":
      return reply(m.id, { protocolVersion: m.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "hib", version: "1" } });
    case "ping":
      return reply(m.id, {});
    case "tools/list":
      return reply(m.id, { tools: [TOOL] });
    case "tools/call": {
      if (m.params?.name !== "advisor") return reply(m.id, { content: [{ type: "text", text: `unknown tool ${m.params?.name}` }], isError: true });
      const question = String(m.params?.arguments?.question ?? "").trim();
      if (!question) return reply(m.id, { content: [{ type: "text", text: 'Missing "question". Call advisor with {"question": "<your plan, problem or what you did>"}.' }], isError: true });
      const r = await advise(question);
      return reply(m.id, { content: [{ type: "text", text: r.text }], isError: !!r.isError });
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
