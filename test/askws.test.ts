import { expect, test } from "bun:test";
import { askWorkspace, exitCode } from "../src/askws";

/** A daemon client that replays one turn's events and records what was posted. */
function fakeClient(events: any[]) {
  const posted: { path: string; body: any }[] = [];
  const client: any = {
    async post(path: string, body: any) {
      posted.push({ path, body });
      if (path === "/hib/workspaces") return { root: "/real/root" };
      if (path.startsWith("/ws/turn")) return { sessionId: "w_1" };
      return { ok: true };
    },
    async *stream(path: string) {
      posted.push({ path, body: null });
      yield* events;
      yield { type: "text", delta: "after the end: never read" };
    },
  };
  return { client, posted };
}

test("one turn: the answer, the session id; prompts and guard approvals are denied and reported", async () => {
  const { client, posted } = fakeClient([
    { type: "ws_session", id: "w_1", model: "claude@default/sonnet" },
    { type: "text", delta: "Redis " },
    { type: "permission", id: "p1", call: { name: "Bash", title: "$ docker restart oib-redis" } },
    { type: "approval", id: "a1", reasons: ["2 secrets"] },
    { type: "text", delta: "was down." },
    { type: "turn_end" },
  ]);
  const r = await askWorkspace(client, { root: "./x", text: "why?", model: "claude@default/sonnet", sessionId: "w_0" });
  expect(r).toEqual({ sessionId: "w_1", answer: "Redis was down.", denied: ["$ docker restart oib-redis", "sending the prompt (2 secrets)"], errors: [] });
  expect(exitCode(r)).toBe(3);
  expect(posted[1]).toEqual({ path: "/ws/turn?root=%2Freal%2Froot", body: { sessionId: "w_0", model: "claude@default/sonnet", text: "why?", auto: false } });
  expect(posted).toContainEqual({ path: "/ws/permission?root=%2Freal%2Froot", body: expect.objectContaining({ sessionId: "w_1", id: "p1", choice: "deny" }) });
  expect(posted).toContainEqual({ path: "/hib/approvals/a1", body: { approve: false } });
  expect(posted.find((p) => p.path.includes("/stream"))!.path).toBe("/ws/sessions/w_1/stream?root=%2Freal%2Froot&after=0");
});

test("exit codes: 0 done, 3 something denied, 1 an error (which wins)", async () => {
  const ok = await askWorkspace(fakeClient([{ type: "text", delta: "fine" }, { type: "turn_end" }]).client, { root: ".", text: "q" });
  expect(exitCode(ok)).toBe(0);
  const bad = await askWorkspace(fakeClient([{ type: "permission", id: "p", call: { name: "Edit" } }, { type: "error", message: "claude@default is not logged in" }, { type: "turn_end" }]).client, { root: ".", text: "q" });
  expect(bad.errors).toEqual(["claude@default is not logged in"]);
  expect(exitCode(bad)).toBe(1);
});
