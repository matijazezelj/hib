/**
 * `hib ask --workspace <dir>`: one workspace turn without a terminal UI, for scripts and acceptance tests. The turn runs
 * in the daemon like any other (same permissions, data rules, trusted MCP servers); anything that would ask you is
 * denied instead, and the caller learns what was.
 */
import type { HibClient } from "./client";

export interface AskResult {
  sessionId: string;
  answer: string; // the agent's text, real values restored, as you'd see it
  denied: string[]; // what would have asked you: tool calls, network hosts, guard approvals
  errors: string[];
}

/** Exit codes: 0 the turn finished, 3 it finished but something that would have asked you was denied, 1 an error. */
export const exitCode = (r: AskResult) => (r.errors.length ? 1 : r.denied.length ? 3 : 0);

export async function askWorkspace(
  client: HibClient,
  o: { root: string; text: string; model?: string; sessionId?: string; onEvent?: (e: any) => void },
): Promise<AskResult> {
  const root = (await client.post<{ root: string }>("/hib/workspaces", { root: o.root })).root;
  const q = `root=${encodeURIComponent(root)}`;
  // Manual mode: an unlisted command or edit asks, and is denied here, rather than running unasked.
  const started = await client.post<{ sessionId: string }>(`/ws/turn?${q}`, { sessionId: o.sessionId, model: o.model, text: o.text, auto: false });
  const r: AskResult = { sessionId: started.sessionId, answer: "", denied: [], errors: [] };
  const ac = new AbortController();
  try {
    for await (const e of client.stream(`/ws/sessions/${r.sessionId}/stream?${q}&after=0`, ac.signal)) {
      o.onEvent?.(e);
      if (e.type === "text") r.answer += e.delta;
      else if (e.type === "permission") {
        r.denied.push(e.call?.title ?? e.call?.name ?? "a tool call");
        await client.post(`/ws/permission?${q}`, { sessionId: r.sessionId, id: e.id, choice: "deny", message: "Denied: this turn runs unattended (hib ask --workspace), so nothing that needs approval runs." });
      } else if (e.type === "approval") {
        r.denied.push(`sending the prompt (${(e.reasons ?? []).join("; ")})`);
        await client.post(`/hib/approvals/${e.id}`, { approve: false });
      } else if (e.type === "error") r.errors.push(String(e.message));
      else if (e.type === "turn_end") break;
    }
  } finally {
    ac.abort();
  }
  return r;
}
