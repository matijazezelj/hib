import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { parseClaudeLine } from "../src/providers/claude-cli";
import { parseCodexLine, parseCodexRateLimits } from "../src/providers/codex-cli";
import { accountEnv, transcript } from "../src/providers/spawn";

const lines = (f: string) => readFileSync(new URL(`./fixtures/${f}`, import.meta.url), "utf8").trim().split("\n").map((l) => JSON.parse(l));

describe("claude stream-json (captured fixture)", () => {
  const events = lines("claude-stream.jsonl").flatMap(parseClaudeLine);
  test("text deltas reassemble the answer", () => {
    expect(events.filter((e) => e.type === "text").map((e: any) => e.delta).join("")).toBe("pong");
  });
  test("real quota windows are reported", () => {
    const q = events.filter((e) => e.type === "quota").map((e: any) => e.quota.window);
    expect(q).toEqual(["5h", "7d"]);
  });
  test("usage and no errors", () => {
    expect(events.some((e) => e.type === "usage")).toBe(true);
    expect(events.some((e) => e.type === "error" || e.type === "rate_limited")).toBe(false);
  });
  test("rejected status is a rate limit", () => {
    const ev = parseClaudeLine({ type: "rate_limit_event", rate_limit_info: { status: "rejected", resetsAt: 123, rateLimitType: "five_hour", unifiedWindows: { five_hour: { utilization: 1, resetsAt: 123 } } } });
    expect(ev.map((e) => e.type)).toEqual(["quota", "rate_limited"]);
  });
});

describe("codex exec --json (captured fixture)", () => {
  const events = lines("codex-stream.jsonl").flatMap(parseCodexLine);
  test("agent message", () => expect(events.find((e) => e.type === "text")).toEqual({ type: "text", delta: "pong" }));
  test("usage", () => expect(events.find((e) => e.type === "usage")).toMatchObject({ type: "usage", out: 5 }));
  test("rollout rate limits -> weekly window", () => {
    const q = parseCodexRateLimits(readFileSync(new URL("./fixtures/codex-rollout.jsonl", import.meta.url), "utf8"));
    expect(q).toEqual([{ window: "7d", usedPct: 0, resetsAt: 1791961865 }]);
  });
  test("usage limit error is a rate limit", () => {
    expect(parseCodexLine({ type: "turn.failed", error: { message: "You've hit your usage limit" } })[0]!.type).toBe("rate_limited");
  });
});

describe("account isolation", () => {
  const acct = (env: Record<string, string>) => ({ id: "x@y", provider: "x", name: "y", env, limits: {}, dirs: [] });
  test("unrelated env (other accounts' secrets) is not passed through", () => {
    process.env.ANTHROPIC_API_KEY = "leak";
    process.env.CLAUDE_CONFIG_DIR = "/other";
    const env = accountEnv(acct({}));
    expect(env.ANTHROPIC_API_KEY).toBeUndefined();
    expect(env.CLAUDE_CONFIG_DIR).toBeUndefined();
    expect(env.PATH).toBeDefined();
  });
  test("account env applied, empty string unsets", () => {
    expect(accountEnv(acct({ CLAUDE_CONFIG_DIR: "/work" })).CLAUDE_CONFIG_DIR).toBe("/work");
    expect(accountEnv(acct({ CLAUDE_CONFIG_DIR: "" })).CLAUDE_CONFIG_DIR).toBeUndefined();
  });
});

test("transcript carries history across models", () => {
  const t = transcript([
    { role: "system", content: "sys" },
    { role: "user", content: "q1" },
    { role: "assistant", content: "a1" },
    { role: "user", content: "q2" },
  ]);
  expect(t.system).toBe("sys");
  expect(t.prompt).toContain("<assistant>\na1\n</assistant>");
  expect(t.prompt.endsWith("q2")).toBe(true);
});

test("a CLI that goes silent is killed and reported as stalled", async () => {
  const { spawnLines } = await import("../src/providers/spawn");
  const p = spawnLines(["sh", "-c", "echo started; sleep 10"], { cwd: "/", env: { PATH: process.env.PATH! }, stdin: "", signal: new AbortController().signal, idleMs: 200 });
  const got: string[] = [];
  for await (const l of p.lines) got.push(l);
  expect(got).toEqual(["started"]);
  expect(p.stalled()).toBe(true);
});

test("codex web searches and other agent actions are visible, never dropped", async () => {
  const { describeOther } = await import("../src/workspace/codex-driver");
  expect(describeOther({ type: "webSearch", id: "w1", query: "AKIA example key", action: { type: "search", query: "aws example secret key", queries: null } }).title).toBe('web search "aws example secret key"');
  expect(describeOther({ type: "webSearch", id: "w2", query: "", action: { type: "openPage", url: "https://docs.aws.amazon.com/x" } })).toMatchObject({ kind: "web", title: "web open https://docs.aws.amazon.com/x" });
  expect(describeOther({ type: "collabAgentToolCall", id: "c1", tool: "spawn" })).toMatchObject({ kind: "other", title: "collabAgentToolCall spawn" });
});
