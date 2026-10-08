import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig } from "../src/config";
import { memoryDb } from "../src/db";
import { Engine } from "../src/engine";
import { Sealer } from "../src/guard/seal";
import { Registry } from "../src/providers/registry";
import type { Provider } from "../src/providers/types";
import type { AgentDriver, AgentEvent, Decision, StartOptions } from "../src/workspace/driver";
import { Queue } from "../src/workspace/queue";
import { WorkspaceSessions, type WsEvent } from "../src/workspace/sessions";

const TOML = `
[models.alpha]
big = "strong"
[providers.alpha]
default = "main"
[providers.alpha.accounts.main]
env = {}
[routes.code]
candidates = ["alpha/big"]
[guard]
terms = ["ProjectFalcon"]
askOn = ["PRIVATE-KEY"]
askIfFindingsOver = 50
`;

type Script = (text: string, d: FakeDriver, q: Queue<AgentEvent>) => Promise<void>;

class FakeDriver implements AgentDriver {
  readonly provider = "alpha";
  started: StartOptions[] = [];
  decisions = new Map<string, Decision>();
  waiters = new Map<string, (d: Decision) => void>();
  dead = false;
  constructor(public script: { current: Script }) {}
  async start(o: StartOptions) {
    this.started.push(o);
  }
  turn(text: string) {
    const q = new Queue<AgentEvent>();
    q.push({ type: "session", nativeId: "native-1" });
    this.script.current(text, this, q).then(() => {
      q.push({ type: "turn_done" });
      q.end();
    });
    return q;
  }
  ask(id: string): Promise<Decision> {
    return new Promise((r) => this.waiters.set(id, r));
  }
  answer(id: string, d: Decision) {
    this.decisions.set(id, d);
    this.waiters.get(id)?.(d);
  }
  async interrupt() {}
  async close() {}
  get alive() {
    return !this.dead;
  }
}

let root: string, sessions: WorkspaceSessions, script: { current: Script }, drivers: FakeDriver[];

beforeEach(async () => {
  const home = mkdtempSync(join(tmpdir(), "hib-ses-"));
  root = realpathSync(mkdtempSync(join(tmpdir(), "hib-root-")));
  const cfg = parseConfig(Bun.TOML.parse(TOML) as any, home);
  cfg.guard.agentDirs.push(root);
  const alpha: Provider = { id: "alpha", available: async () => true, async *run() {} };
  const sealer = await Sealer.open(home);
  const engine = new Engine(cfg, memoryDb(), new Registry([alpha]), sealer, { skills: new Map(), agents: new Map(), routes: [], guardTerms: [], guardPatterns: [], askOn: [], advisor: [], providers: [], warnings: [] });
  script = { current: async () => {} };
  drivers = [];
  sessions = new WorkspaceSessions(engine, sealer, () => {
    const d = new FakeDriver(script);
    drivers.push(d);
    return d;
  });
});

/** Runs a turn, answering permissions with `choose` as they arrive. */
async function turn(text: string, sessionId?: string, choose: (e: Extract<WsEvent, { type: "permission" }>) => "allow" | "always" | "deny" | null = () => "allow") {
  const events: WsEvent[] = [];
  let sid = sessionId;
  for await (const e of sessions.send({ sessionId, root, model: "alpha/big", text }, new AbortController().signal)) {
    events.push(e);
    if (e.type === "ws_session") sid = e.id;
    if (e.type === "permission") {
      const c = choose(e);
      if (c) sessions.answer(sid!, e.id, c);
    }
  }
  return { events, sid: sid! };
}

describe("workspace sessions", () => {
  test("placeholders in an approved tool input are swapped back before the CLI runs it", async () => {
    let seen = "";
    script.current = async (text, d, q) => {
      seen = text;
      const tok = /\[HIB\w+-TERM-1\]/.exec(text)![0];
      q.push({ type: "permission", id: "p1", ruleKey: "edit", call: { id: "t1", name: "Write", kind: "edit", title: "Write a.txt", path: "a.txt" }, input: { file_path: `${root}/a.txt`, content: `name: ${tok}` } });
      await d.ask("p1");
    };
    await turn("rename ProjectFalcon in a.txt");
    expect(seen).not.toContain("ProjectFalcon");
    const d = drivers[0]!.decisions.get("p1")!;
    expect(d).toEqual({ behavior: "allow", updatedInput: { file_path: `${root}/a.txt`, content: "name: ProjectFalcon" } });
  });

  test("'always' covers edits inside the folder only", async () => {
    const edit = (id: string, path: string): AgentEvent => ({ type: "permission", id, ruleKey: "edit", call: { id, name: "Edit", kind: "edit", title: `Edit ${path}`, path, paths: [path] }, input: {} });
    const prompted: string[] = [];
    script.current = async (_t, d, q) => {
      q.push(edit("p1", "src/a.ts"));
      await d.ask("p1");
      q.push(edit("p2", "src/b.ts")); // inside: auto-allowed
      await d.ask("p2");
      q.push(edit("p3", "/Users/someone/.zshrc")); // outside: must prompt
      await d.ask("p3");
    };
    await turn("edit things", undefined, (e) => {
      prompted.push(e.id);
      return e.id === "p1" ? "always" : "deny";
    });
    expect(prompted).toEqual(["p1", "p3"]);
    expect(drivers[0]!.decisions.get("p2")!.behavior).toBe("allow");
    expect(drivers[0]!.decisions.get("p3")!.behavior).toBe("deny");
  });

  test("unanswered permissions are denied when the turn ends", async () => {
    script.current = async (_t, _d, q) => {
      q.push({ type: "permission", id: "p1", ruleKey: "Bash:rm", call: { id: "x", name: "Bash", kind: "command", title: "$ rm x" } });
    };
    await turn("go", undefined, () => null);
    expect(drivers[0]!.decisions.get("p1")!.behavior).toBe("deny");
  });

  test("a second turn on a busy session is refused", async () => {
    let release!: () => void;
    script.current = () => new Promise<void>((r) => (release = r));
    const first = sessions.send({ root, model: "alpha/big", text: "long" }, new AbortController().signal);
    let sid = "";
    for (;;) {
      const { value } = await first.next();
      if (value?.type === "ws_session") {
        sid = value.id;
        break;
      }
    }
    const second = await turn("again", sid);
    expect(second.events.at(-1)).toEqual({ type: "error", message: "this session is already running a turn" });
    const rest = (async () => {
      for await (const _ of first);
    })();
    while (!release) await Bun.sleep(5);
    release();
    await rest;
  });

  test("a dead CLI is reopened on its native session", async () => {
    const { sid } = await turn("hello");
    drivers[0]!.dead = true;
    const r = await turn("again", sid);
    expect(drivers.length).toBe(2);
    expect(drivers[1]!.started[0]!.resume).toBe("native-1");
    expect(r.events.find((e) => e.type === "ws_session")).toMatchObject({ resumed: true });
  });
});

describe("shared live sessions", () => {
  test("a client joining mid-turn catches up, and leaving never stops the turn", async () => {
    let release!: () => void;
    script.current = async (_t, _d, q) => {
      q.push({ type: "text", delta: "part one " });
      await new Promise<void>((r) => (release = r));
      q.push({ type: "text", delta: "part two" });
    };
    const started = sessions.startTurn({ root, model: "alpha/big", text: "go" });
    if ("error" in started) throw new Error(started.error);
    const id = started.sessionId;
    while (!release) await Bun.sleep(5);

    // a second client (e.g. the web) attaches while the CLI's turn is running
    const snap = sessions.snapshot(id);
    expect(snap.running).toBe(true);
    expect(snap.live.map((e) => e.type)).toContain("turn_start");
    const seen: string[] = [];
    const unsub = sessions.subscribe(id, snap.seq, (_s, e) => e.type === "text" && seen.push(e.delta));
    unsub(); // the client goes away
    const late: string[] = [];
    const unsub2 = sessions.subscribe(id, 0, (_s, e) => e.type === "text" && late.push(e.delta));
    release();
    while (sessions.snapshot(id).running) await Bun.sleep(5);
    unsub2();
    expect(seen).toEqual([]);
    expect(late).toEqual(["part one ", "part two"]); // replay from 0 plus live
    const after = sessions.snapshot(id);
    expect(after.events.map((e: any) => e.type)).toEqual(["user", "assistant"]);
    expect(after.events[1].text).toBe("part one part two");
  });
});

describe("workspace registry", () => {
  test("home and / are refused; real folders are canonicalized", async () => {
    const { eligible } = await import("../src/workspace/registry");
    const { homedir } = await import("node:os");
    expect(eligible(homedir()).ok).toBe(false);
    expect(eligible("/").ok).toBe(false);
    expect(eligible("/definitely/not/here").ok).toBe(false);
    expect(eligible(root)).toEqual({ ok: true, root });
  });
});
