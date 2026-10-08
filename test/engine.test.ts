import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig } from "../src/config";
import { memoryDb } from "../src/db";
import { Engine, type HibEvent } from "../src/engine";
import { Sealer } from "../src/guard/seal";
import { Registry } from "../src/providers/registry";
import type { Provider, RunEvent, RunRequest } from "../src/providers/types";
import type { Plugins } from "../src/plugins";

const TOML = `
[usage]
switchAt = 0.9
[advisor]
alpha = "alpha/big"
beta = "beta/big"
[models.alpha]
fast = "fast"
big = "strong"
[models.beta]
fast = "fast"
big = "strong"
[providers.alpha]
default = "main"
[providers.alpha.accounts.main]
env = {}
[providers.alpha.accounts.work]
env = {}
[providers.beta]
default = "main"
[providers.beta.accounts.main]
env = {}
[routes.chat]
candidates = ["alpha/fast", "beta/fast"]
level = "standard"
[routes.code]
candidates = ["alpha/big"]
advisor = true
level = "standard"
[guard]
askOn = ["PRIVATE-KEY"]
askIfFindingsOver = 50
approvalTimeoutSec = 5
`;

type Script = (req: RunRequest) => RunEvent[];
const sent: { provider: string; account: string; model: string; messages: RunRequest["messages"] }[] = [];

function fake(id: string, script: { current: Script }): Provider {
  return {
    id,
    available: async () => true,
    async *run(req) {
      sent.push({ provider: id, account: req.account.name, model: req.model, messages: req.messages });
      for (const e of script.current(req)) yield e;
      yield { type: "done" };
    },
  };
}

const noPlugins = (): Plugins => ({ skills: new Map(), agents: new Map(), routes: [], guardTerms: [], guardPatterns: [], askOn: [], advisor: [], providers: [], warnings: [] });
const echo: Script = (req) => {
  const last = req.messages[req.messages.length - 1]!.content;
  return [{ type: "text", delta: `you said: ${last}` }];
};

let alpha: { current: Script }, beta: { current: Script }, engine: Engine;

async function run(input: Parameters<Engine["chat"]>[0]) {
  const events: HibEvent[] = [];
  for await (const e of engine.chat(input, new AbortController().signal)) events.push(e);
  return { events, text: events.filter((e) => e.type === "text").map((e: any) => e.delta).join(""), of: <T extends HibEvent["type"]>(t: T) => events.filter((e) => e.type === t) as Extract<HibEvent, { type: T }>[] };
}

beforeEach(async () => {
  sent.length = 0;
  alpha = { current: echo };
  beta = { current: echo };
  const home = mkdtempSync(join(tmpdir(), "hib-eng-"));
  const cfg = parseConfig(Bun.TOML.parse(TOML) as any, home);
  engine = new Engine(cfg, memoryDb(), new Registry([fake("alpha", alpha), fake("beta", beta)]), await Sealer.open(home), noPlugins());
  engine.learner.sample = (_c, _m, prior = 0) => prior; // deterministic: route order wins
});

describe("guard end to end", () => {
  test("provider only ever sees tokens; user gets real values back", async () => {
    alpha.current = (req) => {
      const tok = /\[HIB\w+-IP-EXTERNAL-NET1-1\]/.exec(req.messages.at(-1)!.content)![0];
      // split the token across chunks to exercise streaming restore
      return [{ type: "text", delta: `${tok.slice(0, 7)}` }, { type: "text", delta: `${tok.slice(7)} is suspicious` }];
    };
    const r = await run({ messages: [{ role: "user", content: "who is 8.8.4.4 talking to bob@acme.io?" }], model: "hib/chat" });
    const wire = JSON.stringify(sent);
    expect(wire).not.toContain("8.8.4.4");
    expect(wire).not.toContain("bob@acme.io");
    expect(r.text).toBe("8.8.4.4 is suspicious");
    expect(r.of("guard")[0]!.findings).toEqual({ "IP-EXTERNAL": 1, EMAIL: 1 });
  });

  test("ask-first: rejection sends nothing", async () => {
    const p = run({ messages: [{ role: "user", content: "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----" }], model: "hib/chat" });
    await Bun.sleep(20);
    const [a] = engine.pendingApprovals();
    expect(a!.redacted).toContain("PRIVATE-KEY");
    expect(a!.redacted).not.toContain("BEGIN RSA");
    engine.decideApproval(a!.id, false);
    const r = await p;
    expect(sent.length).toBe(0);
    expect(r.of("error")[0]!.message).toContain("rejected");
  });

  test("a rejected turn is never persisted (no conversation, no title leak)", async () => {
    const p = run({ persist: true, messages: [{ role: "user", content: "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----" }], model: "hib/chat" });
    await Bun.sleep(20);
    engine.decideApproval(engine.pendingApprovals()[0]!.id, false);
    const r = await p;
    expect(r.of("conversation")).toEqual([]);
    expect(engine.listConversations()).toEqual([]);
    expect(engine.db.query("SELECT COUNT(*) AS n FROM messages").get()).toEqual({ n: 0 });
  });

  test("rejecting in an existing conversation leaves its history clean", async () => {
    const id = (await run({ persist: true, messages: [{ role: "user", content: "hi" }], model: "hib/chat" })).of("conversation")[0]!.id;
    const p = run({ conversationId: id, messages: [{ role: "user", content: "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----" }], model: "hib/chat" });
    await Bun.sleep(20);
    engine.decideApproval(engine.pendingApprovals()[0]!.id, false);
    await p;
    expect(engine.getConversation(id).messages.map((m: any) => m.content)).toEqual(["hi", "you said: hi"]);
  });

  test("ask-first: approve with edits re-checks the edit", async () => {
    const p = run({ messages: [{ role: "user", content: "key -----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----" }], model: "hib/chat" });
    await Bun.sleep(20);
    const [a] = engine.pendingApprovals();
    engine.decideApproval(a!.id, true, "nevermind, ping 8.8.8.8");
    await p;
    expect(sent.length).toBe(1);
    expect(JSON.stringify(sent)).not.toContain("8.8.8.8");
  });
});

describe("routing and usage", () => {
  test("switches provider when an account is near its quota", async () => {
    engine.usage.recordQuota("alpha@main", { window: "5h", usedPct: 0.95, resetsAt: Math.floor(Date.now() / 1000) + 3600 });
    const r = await run({ messages: [{ role: "user", content: "hi" }], model: "hib/chat" });
    expect(r.of("meta")[0]!.model).toBe("beta@main/fast");
    expect(r.of("meta")[0]!.skipped[0]!.id).toBe("alpha@main/fast");
  });

  test("expired quota windows don't block", async () => {
    engine.usage.recordQuota("alpha@main", { window: "5h", usedPct: 1, resetsAt: Math.floor(Date.now() / 1000) - 10 });
    const r = await run({ messages: [{ role: "user", content: "hi" }], model: "hib/chat" });
    expect(r.of("meta")[0]!.model).toBe("alpha@main/fast");
  });

  test("rate limit mid-request fails over and cools the account down", async () => {
    alpha.current = () => [{ type: "rate_limited", message: "usage limit" }];
    const r = await run({ messages: [{ role: "user", content: "hi" }], model: "hib/chat" });
    expect(r.of("failover")[0]).toMatchObject({ from: "alpha@main/fast", to: "beta@main/fast" });
    expect(r.text).toBe("you said: hi");
    expect(engine.usage.of(engine.cfg.accounts[0]!).cooldownUntil).toBeGreaterThan(Date.now());
  });

  test("explicit account id is honoured (work vs personal never mixed implicitly)", async () => {
    await run({ messages: [{ role: "user", content: "hi" }], model: "alpha@work/fast" });
    expect(sent[0]).toMatchObject({ provider: "alpha", account: "work", model: "fast" });
  });

  test("code route is classified from content", async () => {
    const r = await run({ messages: [{ role: "user", content: "fix this bug:\n```ts\nconst x: number = 'a';\n```" }] });
    expect(r.of("meta")[0]!.cls).toBe("code");
  });
});

describe("advisor", () => {
  test("cross-provider critique triggers a revision", async () => {
    alpha.current = (req) => (req.messages.at(-1)!.content.includes("reviewer from a different") ? [{ type: "text", delta: "fixed answer" }] : [{ type: "text", delta: "first answer" }]);
    beta.current = () => [{ type: "text", delta: "1. off by one" }];
    const r = await run({ messages: [{ role: "user", content: "implement a function that sums" }], model: "hib/code" });
    expect(r.of("advisor")[0]).toMatchObject({ model: "beta@main/big", verdict: "issues" });
    expect(sent.map((s) => s.provider)).toEqual(["alpha", "beta", "alpha"]);
    expect(r.events.filter((e) => e.type === "text" && e.part === "revision").map((e: any) => e.delta).join("")).toBe("fixed answer");
  });

  test("OK verdict keeps the answer", async () => {
    beta.current = () => [{ type: "text", delta: "OK" }];
    const r = await run({ messages: [{ role: "user", content: "implement a function that sums" }], model: "hib/code" });
    expect(r.of("advisor")[0]!.verdict).toBe("ok");
    expect(sent.length).toBe(2);
  });
});

describe("conversations and resume", () => {
  test("resume on a different provider keeps history and the same tokens", async () => {
    const r1 = await run({ persist: true, messages: [{ role: "user", content: "server 10.1.1.7 is down" }], model: "alpha/fast" });
    const id = r1.of("conversation")[0]!.id;
    await run({ conversationId: id, messages: [{ role: "user", content: "is 10.1.1.7 internal?" }], model: "beta/fast" });
    const [first, second] = [sent[0]!, sent[1]!];
    expect(second.provider).toBe("beta");
    const tok1 = /\[HIB\w+-IP-INTERNAL-NET1-1\]/.exec(JSON.stringify(first.messages))![0];
    const transcript = JSON.stringify(second.messages);
    expect(transcript.split(tok1).length - 1).toBe(3); // user turn, echoed assistant turn and new turn share one token
    expect(transcript).not.toContain("10.1.1.7");
    const conv = engine.getConversation(id);
    expect(conv.messages.map((m: any) => m.role)).toEqual(["user", "assistant", "user", "assistant"]);
    expect(conv.messages[0].content).toBe("server 10.1.1.7 is down"); // originals stored locally
    expect(conv.last_model).toBe("beta@main/fast");
    const raw = engine.db.query("SELECT vault FROM conversations WHERE id = ?").get(id) as any;
    expect(raw.vault).not.toContain("10.1.1.7"); // vault sealed at rest
  });
});

describe("learning", () => {
  test("thumbs and retries move scores", async () => {
    const r = await run({ messages: [{ role: "user", content: "hello there" }], model: "hib/chat" });
    const runId = r.of("done")[0]!.runId;
    const before = engine.learner.get("chat", "alpha@main/fast");
    engine.feedback(runId, -1);
    const after = engine.learner.get("chat", "alpha@main/fast");
    expect(after.beta).toBeGreaterThan(before.beta);
    await run({ messages: [{ role: "user", content: "hello there" }], model: "hib/chat" }); // same prompt again = retry
    expect(engine.learner.get("chat", "alpha@main/fast").beta).toBeGreaterThan(after.beta);
  });

  test("arena runs two providers and the pick updates scores", async () => {
    const r = await run({ persist: true, messages: [{ role: "user", content: "hello" }], model: "hib/chat", arena: true });
    const a = r.of("arena")[0]!;
    expect(new Set([a.a.model, a.b.model])).toEqual(new Set(["alpha@main/fast", "beta@main/fast"]));
    engine.pickArena(a.id, "b");
    expect(engine.learner.get("chat", a.b.model).alpha).toBeGreaterThan(engine.learner.get("chat", a.a.model).alpha);
  });
});

describe("agent mode", () => {
  test("refused outside guard.agentDirs, nothing sent", async () => {
    const r = await run({ messages: [{ role: "user", content: "create a file" }], model: "alpha/big", mode: "agent", cwd: "/" });
    expect(r.of("error")[0]!.message).toContain("not in guard.agentDirs");
    expect(sent.length).toBe(0);
  });
  test("allowed dir keeps real paths; a secret file in it triggers ask-first", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const dir = mkdtempSync(join(tmpdir(), "hib-agent-"));
    engine.cfg.guard.agentDirs.push(dir);
    const r1 = await run({ messages: [{ role: "user", content: `edit ${dir}/x.ts and /Users/someone/y.ts` }], model: "alpha/big", mode: "agent", cwd: dir });
    expect(r1.of("guard")[0]!.action).toBe("redact");
    expect(JSON.stringify(sent[0]!.messages)).toContain("/Users/someone/y.ts");
    writeFileSync(join(dir, ".env"), "X=1");
    const p = run({ messages: [{ role: "user", content: "edit x.ts" }], model: "alpha/big", mode: "agent", cwd: dir });
    await Bun.sleep(20);
    const [a] = engine.pendingApprovals();
    expect(a!.reasons.join()).toContain(".env");
    engine.decideApproval(a!.id, false);
    await p;
  });
});

describe("sensitive workspaces (router)", () => {
  async function sensitiveDir() {
    const { mkdtempSync, realpathSync } = await import("node:fs");
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "hib-sens-")));
    engine.workspaces.register(dir);
    engine.workspaces.setPolicy(dir, { sensitive: true, account: "alpha@work" });
    return dir;
  }

  test("pinned account only: no failover, advisor or arena", async () => {
    const dir = await sensitiveDir();
    beta.current = () => [{ type: "text", delta: "1. issue" }];
    const r = await run({ messages: [{ role: "user", content: "implement a function that sums" }], model: "hib/code", cwd: dir, arena: true, persist: true });
    expect(r.of("meta")[0]!.model).toBe("alpha@work/big");
    expect(r.of("advisor")).toEqual([]);
    expect(r.of("arena")).toEqual([]);
    expect(new Set(sent.map((s) => `${s.provider}@${s.account}`))).toEqual(new Set(["alpha@work"]));
  });

  test("other accounts are refused before anything is sent", async () => {
    const dir = await sensitiveDir();
    const r = await run({ messages: [{ role: "user", content: "hi" }], model: "beta/fast", cwd: dir });
    expect(r.of("error")[0]!.message).toContain("pinned to alpha@work");
    expect(sent.length).toBe(0);
  });

  test("a rate-limited pinned account fails instead of spilling over", async () => {
    const dir = await sensitiveDir();
    alpha.current = () => [{ type: "rate_limited", message: "usage limit" }];
    const r = await run({ messages: [{ role: "user", content: "hi" }], model: "hib/chat", cwd: dir });
    expect(r.of("error").length).toBe(1);
    expect(sent.every((s) => s.provider === "alpha" && s.account === "work")).toBe(true);
  });
});

test("solo requests use exactly one model: no advisor, no failover", async () => {
  beta.current = () => [{ type: "text", delta: "1. issue" }];
  alpha.current = () => [{ type: "rate_limited", message: "usage limit" }];
  const r = await run({ messages: [{ role: "user", content: "implement a function that sums" }], model: "hib/code", solo: true });
  expect(r.of("advisor")).toEqual([]);
  expect(sent.every((s) => s.provider === "alpha")).toBe(true);
});

test("attached tables go out pseudonymised and the answer comes back with real values", async () => {
  const { loadTable } = await import("../src/analyze/table");
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const p = join(mkdtempSync(join(tmpdir(), "hib-att-")), "u.csv");
  writeFileSync(p, "username,email,department,salary\njsmith,john@acme.io,Finance,72000\nmkovac,marija@acme.io,IT,90000\n");
  alpha.current = (req) => {
    const tok = /\[HIB\w+-USERNAME-2\]/.exec(JSON.stringify(req.messages))![0];
    return [{ type: "text", delta: `top earner: ${tok}` }];
  };
  const r = await run({ messages: [{ role: "user", content: "who earns most?" }], model: "alpha/fast", attachments: [{ name: "u.csv", table: loadTable(p) }], persist: true });
  const wire = JSON.stringify(sent);
  for (const real of ["jsmith", "mkovac", "john@", "acme.io"]) expect(wire).not.toContain(real);
  expect(wire).toContain("Finance");
  expect(r.text).toBe("top earner: mkovac");
  const conv = engine.getConversation(r.of("conversation")[0]!.id);
  expect(conv.messages[0].content).toContain("[attached u.csv: 2 rows; pseudonymised: username, email]");
  expect(conv.messages[0].content).not.toContain("jsmith");
});

describe("tables and the sensitive pin", () => {
  async function csvIn(dir: string) {
    const { writeFileSync } = await import("node:fs");
    const p = join(dir, "u.csv");
    writeFileSync(p, "username,salary\njsmith,72000\n");
    return p;
  }
  test("a CSV from a sensitive folder can't be attached for another vendor", async () => {
    const { mkdtempSync, realpathSync } = await import("node:fs");
    const { loadTable } = await import("../src/analyze/table");
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "hib-sens-att-")));
    engine.workspaces.register(dir);
    engine.workspaces.setPolicy(dir, { sensitive: true, account: "alpha@work" });
    const p = await csvIn(dir);
    const r = await run({ messages: [{ role: "user", content: "summarise" }], model: "beta/fast", attachments: [{ name: "u.csv", path: p, table: loadTable(p) }] });
    expect(r.of("error")[0]!.message).toContain("pinned to alpha@work");
    expect(sent.length).toBe(0);
  });
  test("attachments never reach an advisor", async () => {
    const { mkdtempSync } = await import("node:fs");
    const { loadTable } = await import("../src/analyze/table");
    const p = await csvIn(mkdtempSync(join(tmpdir(), "hib-att2-")));
    beta.current = () => [{ type: "text", delta: "1. issue" }];
    const r = await run({ messages: [{ role: "user", content: "implement a function over this table" }], model: "hib/code", attachments: [{ name: "u.csv", path: p, table: loadTable(p) }] });
    expect(r.of("advisor")).toEqual([]);
    expect(sent.every((s) => s.provider === "alpha")).toBe(true);
  });
  test("analysis warns when a result carries identifying values back out", async () => {
    const { mkdtempSync } = await import("node:fs");
    const { Analyzer } = await import("../src/analyze");
    const p = await csvIn(mkdtempSync(join(tmpdir(), "hib-leak-")));
    alpha.current = () => [{ type: "text", delta: "```js\nfunction analyze(rows) { return rows.map((r) => ({ who: r.username })); }\n```\nlists users" }];
    const a = new Analyzer(engine);
    const plan = await a.plan({ path: p, question: "who?", model: "alpha/fast" });
    expect(JSON.stringify(sent)).not.toContain("jsmith");
    expect((await a.run(plan.id)).ok).toBe(true);
    expect(a.leaks(plan.id)).toEqual(["username"]);
  });
});
