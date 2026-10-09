import { beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
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
import { WorkspaceSessions } from "../src/workspace/sessions";
import { Tasks } from "../src/workspace/tasks";

const TOML = `
[models.alpha]
big = "strong"
[providers.alpha]
default = "main"
[providers.alpha.accounts.main]
env = {}
[routes.code]
candidates = ["alpha/big"]
`;

type Script = (text: string, d: FakeDriver, q: Queue<AgentEvent>) => Promise<void>;

class FakeDriver implements AgentDriver {
  readonly provider = "alpha";
  started: StartOptions[] = [];
  decisions = new Map<string, Decision>();
  waiters = new Map<string, (d: Decision) => void>();
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
    return true;
  }
}

const FAKE_SANDBOX = () => ({ denyRead: ["/fake/.hib"] });

const git = (cwd: string, ...args: string[]) => {
  const r = Bun.spawnSync(["git", ...args], { cwd, stdout: "pipe", stderr: "pipe" });
  if (!r.success) throw new Error(r.stderr.toString());
  return r.stdout.toString().trim();
};

let root: string, wtDir: string, engine: Engine, sessions: WorkspaceSessions, tasks: Tasks, script: { current: Script }, drivers: FakeDriver[], notes: [string, string][];

async function until(fn: () => boolean, what: string) {
  for (let i = 0; i < 200 && !fn(); i++) await Bun.sleep(10);
  if (!fn()) throw new Error(`timed out waiting for ${what}`);
}

beforeEach(async () => {
  const home = mkdtempSync(join(tmpdir(), "hib-task-"));
  root = realpathSync(mkdtempSync(join(tmpdir(), "hib-repo-")));
  wtDir = realpathSync(mkdtempSync(join(tmpdir(), "hib-wt-")));
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "user.email", "t@example.com");
  git(root, "config", "user.name", "Test");
  writeFileSync(join(root, "a.txt"), "one\n");
  git(root, "add", "-A");
  git(root, "commit", "-qm", "init");
  const cfg = parseConfig(Bun.TOML.parse(TOML) as any, home);
  const alpha: Provider = { id: "alpha", available: async () => true, async *run() {} };
  const sealer = await Sealer.open(home);
  engine = new Engine(cfg, memoryDb(), new Registry([alpha]), sealer, { skills: new Map(), agents: new Map(), routes: [], guardTerms: [], guardPatterns: [], askOn: [], advisor: [], providers: [], warnings: [] });
  engine.workspaces.register(root);
  script = { current: async () => {} };
  drivers = [];
  sessions = new WorkspaceSessions(
    engine,
    sealer,
    () => {
      const d = new FakeDriver(script);
      drivers.push(d);
      return d;
    },
    "",
    FAKE_SANDBOX,
  );
  notes = [];
  tasks = new Tasks(engine, sessions, { dir: wtDir, notify: (title, body) => notes.push([title, body]) });
});

describe("background tasks", () => {
  test("runs in its own worktree in auto mode, commits what it leaves, and merges back after review", async () => {
    script.current = async (_t, d, q) => {
      writeFileSync(join(d.started[0]!.cwd, "b.txt"), "from the task\n"); // stands in for the agent's edits
      q.push({ type: "permission", id: "p1", ruleKey: "Bash:bun test", call: { id: "c1", name: "Bash", kind: "command", title: "$ bun test", command: "bun test" }, input: {} });
      await d.ask("p1");
      q.push({ type: "text", delta: "Added b.txt." });
    };
    const t = await tasks.create({ root, prompt: "add b.txt" });
    expect(t.worktree.startsWith(wtDir)).toBe(true);
    expect(git(t.worktree, "rev-parse", "--abbrev-ref", "HEAD")).toBe(t.branch);
    await until(() => tasks.get(t.id).status === "done", "task done");

    const d = drivers[0]!;
    expect(d.started[0]!.cwd).toBe(t.worktree);
    expect(d.started[0]!.system).toContain("background task");
    expect(d.decisions.get("p1")!.behavior).toBe("allow"); // auto mode: no prompt
    expect(notes.map((n) => n[0])).toEqual(["hib task done"]);
    expect(existsSync(join(root, "b.txt"))).toBe(false); // the original folder is untouched until merge

    const r = await tasks.review(t.id.slice(2)); // id prefix works
    expect(r.summary).toBe("Added b.txt.");
    expect(r.log).toContain("hib task: add b.txt");
    expect(r.diff).toContain("+from the task");

    await tasks.merge(t.id);
    expect(readFileSync(join(root, "b.txt"), "utf8")).toBe("from the task\n");
    expect(existsSync(t.worktree)).toBe(false);
    expect(git(root, "branch", "--list", t.branch)).toBe("");
    expect(engine.workspaces.has(t.worktree)).toBe(false);
    expect(tasks.get(t.id).status).toBe("merged");
    expect(tasks.list()).toEqual([]);
  });

  test("a risky command waits for approval and notifies; answering lets it finish", async () => {
    script.current = async (_t, d, q) => {
      q.push({ type: "permission", id: "p1", ruleKey: "Bash:git push", call: { id: "c1", name: "Bash", kind: "command", title: "$ git push", command: "git push origin main" }, input: {} });
      await d.ask("p1");
    };
    const t = await tasks.create({ root, prompt: "ship it" });
    await until(() => tasks.get(t.id).status === "waiting", "waiting");
    expect(notes[0]![0]).toBe("hib task needs approval");
    expect(tasks.get(t.id).note).toContain("git push");
    expect(sessions.answer(t.session_id, "p1", "deny")).toBe(true);
    await until(() => tasks.get(t.id).status === "done", "task done");
    expect(drivers[0]!.decisions.get("p1")!.behavior).toBe("deny");
  });

  test("discard deletes the worktree and branch and leaves the folder alone", async () => {
    script.current = async (_t, d) => writeFileSync(join(d.started[0]!.cwd, "junk.txt"), "x");
    const t = await tasks.create({ root, prompt: "make junk" });
    await until(() => tasks.get(t.id).status === "done", "task done");
    await tasks.discard(t.id);
    expect(existsSync(t.worktree)).toBe(false);
    expect(git(root, "branch", "--list", t.branch)).toBe("");
    expect(existsSync(join(root, "junk.txt"))).toBe(false);
    expect(tasks.get(t.id).status).toBe("discarded");
  });

  test("refused in sensitive workspaces, outside git, and from inside a task", async () => {
    const plain = realpathSync(mkdtempSync(join(tmpdir(), "hib-plain-")));
    engine.workspaces.register(plain);
    await expect(tasks.create({ root: plain, prompt: "x" })).rejects.toThrow(/not a git repository/);

    script.current = async () => {};
    const t = await tasks.create({ root, prompt: "noop" });
    await until(() => tasks.get(t.id).status === "done", "task done");
    await expect(tasks.create({ root: t.worktree, prompt: "nested" })).rejects.toThrow(/itself a background task/);

    engine.workspaces.setPolicy(root, { sensitive: true, account: "alpha@main" });
    await expect(tasks.create({ root, prompt: "x" })).rejects.toThrow(/sensitive/);
    engine.workspaces.setPolicy(root, null);

    const unsandboxed = new Tasks(engine, new WorkspaceSessions(engine, await Sealer.open(mkdtempSync(join(tmpdir(), "hib-task3-"))), () => new FakeDriver(script), "", () => undefined), { dir: wtDir, notify: () => {} });
    await expect(unsandboxed.create({ root, prompt: "x" })).rejects.toThrow(/sandbox/);
  });

  test("a task that fails to start leaves no worktree or branch behind", async () => {
    sessions.startTurn = () => ({ error: "busy" });
    await expect(tasks.create({ root, prompt: "y" })).rejects.toThrow(/busy/);
    expect(git(root, "worktree", "list").split("\n").length).toBe(1);
    expect(git(root, "branch", "--list", "hib/*")).toBe("");
    expect(tasks.list({ all: true })[0]?.status).toBe("discarded");
  });

  test("a daemon restart marks running tasks interrupted and restores auto mode", async () => {
    script.current = (_t, d) => d.ask("never").then(() => {});
    const t = await tasks.create({ root, prompt: "long" });
    await until(() => sessions.running(t.session_id), "running");
    const sealer = await Sealer.open(mkdtempSync(join(tmpdir(), "hib-task2-")));
    const fresh = new WorkspaceSessions(engine, sealer, () => new FakeDriver(script), "", FAKE_SANDBOX);
    new Tasks(engine, fresh, { dir: wtDir, notify: () => {} });
    expect(tasks.get(t.id).status).toBe("interrupted");
    expect(fresh.snapshot(t.session_id).auto).toBe(true);
  });
});
