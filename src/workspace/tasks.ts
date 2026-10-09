import { mkdirSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import type { Engine } from "../engine";
import * as git from "./git";
import type { WorkspaceSessions, WsEvent } from "./sessions";

export type TaskStatus = "running" | "waiting" | "done" | "failed" | "interrupted" | "merged" | "discarded";

export interface Task {
  id: string;
  root: string; // the folder the task was started from; merges go back here
  worktree: string; // the task's own checkout, a registered workspace while the task is open
  branch: string;
  base: string; // commit the branch started from
  session_id: string;
  title: string;
  model: string;
  status: TaskStatus;
  note: string | null;
  created: number;
  updated: number;
}

export type Notify = (title: string, body: string) => void;

/** A macOS notification; nothing elsewhere. Text goes in as arguments, never into the script. */
export const macNotify: Notify = (title, body) => {
  if (process.platform !== "darwin") return;
  try {
    Bun.spawn(["osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", title, body], { stdout: "ignore", stderr: "ignore" });
  } catch {}
};

/**
 * Outside ~/.hib, the repo, and anything auto mode or the CLIs' deny rules treat as credentials (.hib, .claude, .codex),
 * so the agent can read and run commands in it like in any folder.
 */
export const defaultWorktreeDir = () => process.env.HIB_WORKTREES ?? join(homedir(), ".local", "share", "hib", "worktrees");

const OPEN: TaskStatus[] = ["running", "waiting", "done", "failed", "interrupted"];

const TASK_NOTE = (branch: string) =>
  `You are running as a background task in a separate git worktree (branch ${branch}); the user is not watching live and will review ` +
  "the branch later. Work autonomously and don't stop to ask questions: make reasonable choices and note them. Verify your work " +
  "(tests, typecheck) where the project has them. End with a short summary of what you changed, what you verified and anything left open. " +
  "hib commits whatever you leave uncommitted when you finish. Leave PROGRESS.md alone (other tasks may run in parallel and " +
  "would conflict on it); put what it should say in your summary instead.";

/**
 * Background tasks: one workspace session in its own git worktree, in auto mode, started from a folder and merged
 * back into it after review. Status follows the session's events; done and needs-approval raise a notification.
 */
export class Tasks {
  private watching = new Map<string, () => void>();
  private lastError = new Map<string, string>();

  constructor(
    private engine: Engine,
    private sessions: WorkspaceSessions,
    private opts: { dir: string; notify?: Notify } = { dir: defaultWorktreeDir() },
  ) {
    // A daemon restart drops running CLIs and in-memory auto mode: those tasks are interrupted, and every open task
    // gets auto mode and its note back so continuing it doesn't fall back to asking for everything.
    this.db.run(`UPDATE tasks SET status = 'interrupted', note = 'the daemon restarted while it ran; open it to continue', updated = ? WHERE status IN ('running', 'waiting')`, [Date.now()]);
    for (const t of this.list()) this.watch(t);
  }

  private get db() {
    return this.engine.db;
  }

  private row(id: string): Task | null {
    return (this.db.query("SELECT * FROM tasks WHERE id = ?").get(id) as Task | null) ?? null;
  }

  private set(id: string, status: TaskStatus, note?: string | null) {
    this.db.run("UPDATE tasks SET status = ?, note = COALESCE(?, note), updated = ? WHERE id = ?", [status, note ?? null, Date.now(), id]);
  }

  /** Open tasks (or all, newest first), optionally only those started from `root`. */
  list(opts: { root?: string; all?: boolean } = {}): Task[] {
    const where = [opts.all ? "" : `status IN (${OPEN.map(() => "?").join(",")})`, opts.root ? "root = ?" : ""].filter(Boolean);
    const args = [...(opts.all ? [] : OPEN), ...(opts.root ? [opts.root] : [])];
    return this.db.query(`SELECT * FROM tasks ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY created DESC LIMIT 200`).all(...args) as Task[];
  }

  /** A task by id or unique id prefix ("t_3f2a" or "3f2a"). */
  get(id: string): Task {
    const exact = this.row(id);
    if (exact) return exact;
    const prefix = id.startsWith("t_") ? id : `t_${id}`;
    const hits = this.db.query("SELECT * FROM tasks WHERE id LIKE ? ORDER BY created DESC").all(`${prefix}%`) as Task[];
    if (hits.length === 1) return hits[0]!;
    throw new Error(hits.length ? `${id} matches ${hits.length} tasks; use more of the id` : `no task ${id}`);
  }

  /** Worktrees of open tasks: registered so sessions can run there, but not folders the user opened. */
  worktrees(): Set<string> {
    return new Set(this.list().map((t) => t.worktree));
  }

  /** The task whose worktree this is, if any. */
  byWorktree(root: string): Task | null {
    return (this.db.query("SELECT * FROM tasks WHERE worktree = ? ORDER BY created DESC").get(root) as Task | null) ?? null;
  }

  async create(input: { root: string; prompt: string; model?: string }): Promise<Task & { dirty: number }> {
    const { root } = input;
    const prompt = input.prompt.trim();
    if (!prompt) throw new Error("describe the task");
    // A worktree lives outside the folder, so a sensitive folder's pin and read rules wouldn't follow it there.
    if (this.engine.workspaces.policyFor(root)) throw new Error("background tasks are off in sensitive workspaces");
    // Unattended auto mode is only acceptable when the agent's commands are confined.
    if (!this.sessions.sandboxed()) throw new Error("background tasks need an OS sandbox for agent commands (macOS, or Linux with bubblewrap and socat installed)");
    if (this.byWorktree(root)) throw new Error("this folder is itself a background task; start tasks from the original folder");
    const h = await git.head(root);
    if (realpathSync(h.top) !== root) throw new Error(`run tasks from the repository's top folder (${h.top})`);

    const id = `t_${crypto.randomUUID().replace(/-/g, "").slice(0, 8)}`;
    const branch = `hib/task-${id.slice(2)}`;
    mkdirSync(this.opts.dir, { recursive: true, mode: 0o700 });
    const path = join(this.opts.dir, `${basename(root)}-${id.slice(2)}`);
    await git.worktreeAdd(root, path, branch, h.sha);
    let worktree = path;
    let sessionId: string;
    let dirty: number;
    try {
      worktree = this.engine.workspaces.register(path);
      // Chosen for the original folder, so per-folder account pins (accounts.dirs) still apply.
      const model = input.model && input.model !== "hib/auto" ? input.model : await this.sessions.defaultModel(root);
      dirty = (await git.status(root))?.files.length ?? 0;
      const now = Date.now();
      const title = prompt.replace(/\s+/g, " ").slice(0, 80);
      this.db.run("INSERT INTO tasks(id, root, worktree, branch, base, session_id, title, model, status, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?)", [
        id, root, worktree, branch, h.sha, "", title, model, "running", now, now,
      ]);
      const started = this.sessions.startTurn({ root: worktree, model, text: prompt, auto: true, system: TASK_NOTE(branch) });
      if ("error" in started) throw new Error(started.error);
      sessionId = started.sessionId;
    } catch (e) {
      // Nothing half-made stays behind: no worktree, branch or registered folder.
      await git.worktreeRemove(root, path, branch);
      this.engine.workspaces.forget(worktree);
      if (this.row(id)) this.set(id, "discarded", String((e as any)?.message ?? e).slice(0, 300));
      throw e;
    }
    this.db.run("UPDATE tasks SET session_id = ? WHERE id = ?", [sessionId, id]);
    const t = this.row(id)!;
    this.watch(t);
    return { ...t, dirty };
  }

  /** Follows a task's session for the life of the daemon; status and notifications come from its events. */
  private watch(t: Task) {
    if (!t.session_id || this.watching.has(t.id)) return;
    this.sessions.setAuto(t.session_id, true);
    this.sessions.setNote(t.session_id, TASK_NOTE(t.branch));
    const unsub = this.sessions.subscribe(t.session_id, 0, (_seq, e) => void this.onEvent(t.id, e));
    this.watching.set(t.id, unsub);
  }

  /** Title and status only: notification bodies aren't clickable and truncate, so the hint is the command to run. */
  private notify(t: Task, what: string) {
    const id = t.id.slice(2);
    (this.opts.notify ?? macNotify)(`hib task ${what}`, `${t.title.slice(0, 60)}\n${what === "needs approval" ? `hib tasks open ${id}` : `hib tasks review ${id}`}`);
  }

  private async onEvent(id: string, e: WsEvent) {
    const t = this.row(id);
    if (!t || !OPEN.includes(t.status)) return;
    switch (e.type) {
      case "turn_start":
        this.lastError.delete(id);
        this.set(id, "running");
        break;
      case "permission":
      case "approval":
        if (t.status !== "waiting") {
          this.set(id, "waiting", e.type === "permission" ? `asks to run: ${e.call.title}` : "the guard wants approval before sending");
          this.notify(t, "needs approval");
        }
        break;
      case "permission_answer":
        if (!this.sessions.pending(t.session_id).length) this.set(id, "running");
        break;
      case "error":
        this.lastError.set(id, e.message);
        break;
      case "turn_end": {
        const err = this.lastError.get(id);
        let committed = false;
        try {
          committed = await git.commitAll(t.worktree, `hib task: ${t.title}`);
        } catch (x: any) {
          this.set(id, "failed", `couldn't commit the task's changes: ${String(x?.message ?? x).slice(0, 200)}`);
          return this.notify(t, "failed");
        }
        if (err) {
          this.set(id, "failed", err.slice(0, 300));
          this.notify(t, "failed");
        } else {
          this.set(id, "done", committed ? "changes committed on the task branch" : "finished");
          this.notify(t, "done");
        }
        break;
      }
    }
  }

  /** The branch's changes and the agent's last answer, for review before merging. */
  async review(id: string) {
    const t = this.get(id);
    const changes = OPEN.includes(t.status) ? await git.branchChanges(t.root, t.base, t.branch) : { log: "", stat: "", diff: "" };
    const uncommitted = OPEN.includes(t.status) ? ((await git.status(t.worktree))?.files.length ?? 0) : 0;
    const summary = [...this.sessions.history(t.session_id)].reverse().find((e) => e.type === "assistant")?.text ?? "";
    return { task: t, running: this.sessions.running(t.session_id), summary, uncommitted, ...changes };
  }

  /** Merges the task branch into what the original folder has checked out, then removes the worktree and branch. */
  async merge(id: string): Promise<{ task: Task; summary: string }> {
    const t = this.get(id);
    if (!OPEN.includes(t.status)) throw new Error(`task ${t.id} is ${t.status}`);
    if (this.sessions.running(t.session_id)) throw new Error(`task ${t.id} is still running; wait for it or discard it`);
    await git.commitAll(t.worktree, `hib task: ${t.title}`);
    const summary = (await git.branchChanges(t.root, t.base, t.branch)).log ? await git.merge(t.root, t.branch, `Merge hib task ${t.id}: ${t.title}`) : "nothing to merge";
    await this.remove(t, "merged");
    return { task: this.row(t.id)!, summary };
  }

  /** Stops the task if it runs, and deletes its worktree and branch. */
  async discard(id: string): Promise<Task> {
    const t = this.get(id);
    if (!OPEN.includes(t.status)) throw new Error(`task ${t.id} is ${t.status}`);
    await this.remove(t, "discarded");
    return this.row(t.id)!;
  }

  private async remove(t: Task, status: "merged" | "discarded") {
    this.watching.get(t.id)?.();
    this.watching.delete(t.id);
    if (t.session_id) await this.sessions.close(t.session_id);
    await git.worktreeRemove(t.root, t.worktree, t.branch);
    this.engine.workspaces.forget(t.worktree);
    this.set(t.id, status);
  }
}
