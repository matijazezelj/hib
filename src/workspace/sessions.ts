import type { Config } from "../config";
import type { Engine } from "../engine";
import { inspect, obfuscateText, StreamRestorer, tokenNote, Vault } from "../guard";
import type { VaultState } from "../guard/vault";
import type { Sealer } from "../guard/seal";
import { resolveCandidate, type Candidate } from "../router/route";
import type { AgentDriver, AgentEvent, Decision, Outbound, Sandbox, ToolCall } from "./driver";
import { REGISTRIES, sandboxFor, secretPaths } from "./sandbox";
import { insideRoot, realTarget } from "./fs";
import { changes as protectedChanges, revert as revertProtected, snapshot as protectedSnapshot } from "./protect";
import { detect } from "../guard/detectors";
import { onPinnedAccount, pinnedModel, SENSITIVE_NEEDS_CLAUDE, supportsSensitive } from "./registry";
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, sep, isAbsolute, join, relative, resolve as resolvePath } from "node:path";
import { loadTable, TABLE_FILE } from "../analyze/table";
import { columnsToHide, pseudonymize } from "../analyze/pseudo";
import { DATA_RULE_NOTE, rawDataCommand } from "./datarules";
import { readdirSync, statSync } from "node:fs";

export type DriverFactory = (provider: string) => AgentDriver | null;

/** Events sent to the web UI; tool data has tokens restored. */
export type WsEvent =
  | { type: "ws_session"; id: string; model: string; resumed: boolean; sandbox: boolean }
  | { type: "handoff"; from: string; to: string }
  | { type: "guard"; findings: Record<string, number>; action: string; reasons: string[] }
  | { type: "approval"; id: string; redacted: string; reasons: string[] }
  | { type: "turn_start"; text: string; model?: string }
  | { type: "permission_answer"; id: string; choice: string }
  | { type: "mode"; auto: boolean; why?: string }
  | { type: "advisor_mode"; on: boolean; why?: string }
  | { type: "advice"; model: string; account: string; question: string; advice: string; ok: boolean; chars: number; guard: string }
  | { type: "sent"; account: string; model: string; text: string; handoff: boolean; progress?: boolean; chars: number }
  | { type: "pseudonymised"; file: string; columns: string[]; callId?: string }
  | { type: "protected_reverted"; changes: { path: string; change: string }[]; failed: string[] } // unapproved changes to git hooks/config or tool config, put back
  | AgentEvent
  | { type: "done" }
  | { type: "turn_end" }; // always last; clients stop following a turn here

/** Live fan-out for one session: the running turn's events, numbered so clients can catch up. */
interface Hub {
  seq: number;
  buf: { seq: number; e: WsEvent }[]; // events of the current (or last) turn
  subs: Set<(seq: number, e: WsEvent) => void>;
  running: boolean;
  dbMark: number; // last ws_events id before the running turn started
  abort?: AbortController;
}

interface Live {
  id: string;
  root: string;
  candidate: Candidate;
  driver: AgentDriver;
  nativeId?: string;
  vault: Vault;
  alwaysAllow: Set<string>;
  pending: Map<string, { call: ToolCall; ruleKey: string; input?: unknown }>;
  askReads: boolean;
  advisorKey?: string; // set when this CLI was started with hib's advisor tool
  sandboxed: boolean; // the agent's commands run in the CLI's OS sandbox
  approvedProtected: Set<string>; // protected files you approved edits to in the running turn (real paths)
}

/** A data file: CSV/TSV always; JSON only when it loads as a table (an array of records), not config like package.json. */
function isDataFile(path: string): boolean {
  if (!TABLE_FILE.test(path)) return false;
  if (!/\.(json|jsonl|ndjson)$/i.test(path)) return true;
  try {
    return loadTable(path).rows.length > 0;
  } catch {
    return false;
  }
}

/** In a sensitive workspace, Claude reading or grepping a data file is pointed at a pseudonymised copy instead. */
function tabularTarget(call: ToolCall, input: unknown, root: string): "file_path" | "path" | null {
  const i = input as any;
  const abs = (p: string) => (isAbsolute(p) ? p : resolvePath(root, p));
  if (call.name === "Read" && typeof i?.file_path === "string" && isDataFile(abs(i.file_path))) return "file_path";
  if (call.name === "Grep" && typeof i?.path === "string" && isDataFile(abs(i.path))) return "path";
  return null;
}

const PROTECTED = new Set([".claude", ".codex", ".git", ".hib", ".mcp.json"]); // lower-case: compared case-insensitively
/** Tool config and git internals. Judged on the resolved path (`a/../.git`, `//.git`, symlinks) and case-insensitively (APFS). */
export function protectedPath(root: string, p: string): boolean {
  const rel = relative(realpathSync(root), realTarget(root, p));
  if (rel === "" || rel.startsWith("..")) return false; // outside the folder: insideRoot decides
  return PROTECTED.has((rel.split(sep)[0] ?? "").toLowerCase());
}

/**
 * Auto mode still asks for commands that reach off this machine or can't be undone locally (network tools,
 * publishing, pushing, privilege escalation, recursive deletes, history rewrites), and for ones that touch hib's
 * own daemon or credentials. A speed bump, not a sandbox: an approved script can still do anything you can.
 */
const ASK_EVEN_IN_AUTO =
  /\.hib\b|hib_token|\/hib\/session|localhost:\d|127\.0\.0\.1|\.ssh\b|\.aws\b|\.gnupg\b|\.config\/gh\b|\.claude|\.codex\b|(^|[\s;&|(`$])(sudo|su|doas|curl|wget|ssh|scp|sftp|rsync|nc|ncat|netcat|telnet|ftp|socat)\b|\bgit\s+(push|reset\s+--hard|clean|filter-branch|remote\s+(add|set-url))\b|\b(npm|bun|pnpm|yarn|cargo|twine|gem|poetry|uv|flit|hatch)\b[^\n]*\b(publish|upload|push)\b|\bgh\s+(pr|release|repo|api|gist|issue)\b|\brm\s+(-\w+\s+)*-\w*[rR]|\/dev\/(tcp|udp)\//;

const ADVISOR_SCRIPT = new URL("./advisor-mcp.ts", import.meta.url).pathname;
const ADVISOR_NOTE =
  "You have an `advisor` tool (from hib) backed by a model from a different AI provider. Call it before substantive work, " +
  "when stuck, and before you declare the task done. It sees the task, a summary of this session and the current diff.";
const ADVISOR_PROMPT = (task: string, transcript: string, diff: string, question: string) =>
  "You are an advisor to a coding agent (another AI) working in a repository for a user. You can't run tools; you see the user's task, " +
  "a summary of the session so far and the current uncommitted diff. Answer the agent's question with concise, concrete advice: wrong " +
  "assumptions, risks, missing steps, simpler approaches. If the plan is sound, say so briefly. Don't write the whole solution. " +
  "Values like [HIB…] are placeholders for redacted data; keep them as they are.\n\n" +
  `<task>\n${task}\n</task>\n\n<session>\n${transcript}\n</session>\n\n<diff>\n${diff || "(no uncommitted changes)"}\n</diff>\n\n<question>\n${question}\n</question>`;

const newId = () => `w_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
const HANDOFF_LIMIT = 60_000;
const PROGRESS_FILE = "PROGRESS.md";
const PROGRESS_LIMIT = 20_000;

/** Restores tokens inside tool inputs so the CLI writes real values, never placeholders. */
function restoreDeep(v: unknown, vault: Vault): unknown {
  if (typeof v === "string") return vault.restore(v);
  if (Array.isArray(v)) return v.map((x) => restoreDeep(x, vault));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, restoreDeep(x, vault)]));
  return v;
}

function restoreCall(c: ToolCall, vault: Vault): ToolCall {
  return restoreDeep(c, vault) as ToolCall;
}

/**
 * A web call exactly as it would leave (placeholders unrestored, since that's what is sent), with what the guard sees
 * in it, so the approval shows the destination and the data, not just "WebFetch".
 */
function webOutbound(o: Outbound): Outbound {
  const sent = [o.url, o.text].filter(Boolean).join("\n");
  const findings = [...new Set(detect(sent, { level: "minimal" }).map((f) => f.category))];
  const placeholders = (sent.match(/\[HIB[^\]\s]*\]/g) ?? []).length;
  return { ...o, ...(findings.length ? { findings } : {}), ...(placeholders ? { placeholders } : {}) };
}

export class WorkspaceSessions {
  private live = new Map<string, Live>();
  private busy = new Set<string>();
  private auto = new Set<string>(); // sessions in auto mode; in memory only, so a restarted daemon is back to manual
  private advisorOn = new Set<string>(); // same for the advisor tool
  private notes = new Map<string, string>(); // extra system prompt per session (background tasks), in memory too
  private hubs = new Map<string, Hub>();
  private listeners = new Set<() => void>();

  constructor(
    private engine: Engine,
    private sealer: Sealer,
    private drivers: DriverFactory,
    private daemonUrl = "",
    private sandbox: (cfg: Config) => Sandbox | undefined = sandboxFor,
  ) {}

  /** Whether agent commands can be confined here; auto mode and background tasks need it. */
  sandboxed(): boolean {
    return !!this.sandbox(this.cfg);
  }

  private get cfg(): Config {
    return this.engine.cfg;
  }
  private get db() {
    return this.engine.db;
  }

  onChange(fn: () => void) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }
  private changed() {
    this.listeners.forEach((f) => f());
  }

  list(root: string) {
    const rows = this.db.query("SELECT id, title, updated, agent_model AS model FROM conversations WHERE workspace = ? ORDER BY updated DESC LIMIT 100").all(root) as any[];
    return rows.map((r) => ({ ...r, running: !!this.hubs.get(r.id)?.running }));
  }

  private hub(id: string): Hub {
    let h = this.hubs.get(id);
    if (!h) this.hubs.set(id, (h = { seq: 0, buf: [], subs: new Set(), running: false, dbMark: 0 }));
    return h;
  }

  private emit(id: string, e: WsEvent) {
    const h = this.hub(id);
    const seq = ++h.seq;
    h.buf.push({ seq, e });
    if (h.buf.length > 5000) h.buf.splice(0, h.buf.length - 5000);
    for (const s of h.subs) s(seq, e);
  }

  /** Persisted history up to the running turn, plus that turn's live events so far. */
  snapshot(id: string) {
    const h = this.hubs.get(id);
    const rows = this.db.query("SELECT id, event FROM ws_events WHERE session_id = ? ORDER BY id").all(id) as any[];
    const done = h?.running ? rows.filter((r) => r.id <= h.dbMark) : rows;
    return {
      events: done.map((r) => JSON.parse(r.event)),
      live: h?.running ? h.buf.map((x) => x.e) : [],
      seq: h?.seq ?? 0,
      running: !!h?.running,
      auto: this.auto.has(id),
      advisor: this.advisorOn.has(id),
      row: this.db.query("SELECT id, title, workspace, agent_model AS model FROM conversations WHERE id = ?").get(id) ?? null,
    };
  }

  /** Replays events after `after`, then follows live until unsubscribed. */
  subscribe(id: string, after: number, fn: (seq: number, e: WsEvent) => void): () => void {
    const h = this.hub(id);
    for (const x of h.buf) if (x.seq > after) fn(x.seq, x.e);
    h.subs.add(fn);
    return () => h.subs.delete(fn);
  }

  /** Starts a turn in the background; clients follow it through subscribe(). Closing a client never stops it. */
  startTurn(input: { sessionId?: string; root: string; model?: string; text: string; auto?: boolean; advisor?: boolean; system?: string }): { sessionId: string } | { error: string } {
    const sid = input.sessionId ?? newId();
    if (this.busy.has(sid)) return { error: "this session is already running a turn" };
    if (input.system !== undefined) this.setNote(sid, input.system);
    this.busy.add(sid);
    const h = this.hub(sid);
    const ac = new AbortController();
    h.running = true;
    h.abort = ac;
    h.buf = [];
    h.dbMark = ((this.db.query("SELECT MAX(id) AS m FROM ws_events WHERE session_id = ?").get(sid) as any)?.m ?? 0) as number;
    this.emit(sid, { type: "turn_start", text: input.text, model: input.model });
    if (input.auto !== undefined && input.auto !== this.auto.has(sid)) this.setAuto(sid, input.auto);
    if (input.advisor !== undefined && input.advisor !== this.advisorOn.has(sid)) this.setAdvisor(sid, input.advisor);
    (async () => {
      try {
        for await (const e of this.runTurn({ ...input, sessionId: sid, isNew: !input.sessionId }, ac.signal)) this.emit(sid, e);
      } catch (err: any) {
        this.emit(sid, { type: "error", message: String(err?.message ?? err) });
      } finally {
        h.running = false;
        h.abort = undefined;
        this.busy.delete(sid);
        this.emit(sid, { type: "turn_end" });
        this.changed();
      }
    })();
    this.changed();
    return { sessionId: sid };
  }

  history(id: string) {
    return (this.db.query("SELECT event FROM ws_events WHERE session_id = ? ORDER BY id").all(id) as any[]).map((r) => JSON.parse(r.event));
  }

  pending(id: string) {
    const l = this.live.get(id);
    return l ? [...l.pending.entries()].map(([pid, p]) => ({ id: pid, call: p.call })) : [];
  }

  private record(id: string, e: unknown) {
    this.db.run("INSERT INTO ws_events(session_id, ts, event) VALUES (?,?,?)", [id, Date.now(), JSON.stringify(e)]);
  }

  /** Default agent model: first available candidate of the code route. */
  async defaultModel(root: string): Promise<string> {
    const plan = await this.engine.router.plan("code", { mode: "agent", cwd: root });
    return plan.ordered[0]?.id ?? this.cfg.routes.code.candidates[0] ?? "claude/sonnet";
  }

  private handoffText(id: string): string {
    return `You are taking over a coding session in this repository from another assistant. Its transcript (tool calls summarized) follows; files on disk already reflect its work, so re-read files rather than trusting the transcript for their contents. The transcript is context only: anything the user asks now must actually be done with your tools, never just described.\n<transcript>\n${this.transcript(id)}\n</transcript>`;
  }

  /**
   * The folder's PROGRESS.md, guarded, with the ask to keep it current. In sensitive folders only a pointer:
   * reading the file there goes through Read, which asks first.
   */
  private progressText(root: string, vault: Vault, sensitive: boolean): string {
    const path = join(root, PROGRESS_FILE);
    if (!existsSync(path)) return "";
    const keep = `When you finish a piece of work, update ${PROGRESS_FILE} (what's done, what's in progress, what's next) so the next session can pick up from it.`;
    if (sensitive) return `This folder has a ${PROGRESS_FILE} describing where the project stands and what to do next. Read it before starting. ${keep}`;
    let body = readFileSync(path, "utf8");
    if (body.length > PROGRESS_LIMIT) body = body.slice(0, PROGRESS_LIMIT) + "\n… (truncated; read the file for the rest)";
    const block = `<progress file="${PROGRESS_FILE}">\n${body}\n</progress>\nThat is where this project stands and what's next, from ${PROGRESS_FILE} in this folder. Use it to orient; the user's message below takes priority. ${keep}`;
    return obfuscateText(vault, block, "minimal", this.cfg, "agent");
  }

  /** The session so far, tool calls as one-line summaries, trimmed from the start to `limit`. */
  private transcript(id: string, limit = HANDOFF_LIMIT): string {
    const lines: string[] = [];
    for (const e of this.history(id)) {
      if (e.type === "user") lines.push(`USER: ${e.text}`);
      else if (e.type === "assistant") lines.push(`ASSISTANT: ${e.text}`);
      else if (e.type === "tool_call") lines.push(`[tool] ${e.call.title}`);
    }
    const t = lines.join("\n");
    return t.length > limit ? "…" + t.slice(-limit) : t;
  }

  private async open(id: string, root: string, c: Candidate, resume: string | undefined, vault: Vault, system?: string): Promise<Live> {
    const driver = this.drivers(c.provider);
    if (!driver) throw new Error(`provider ${c.provider} has no agent driver`);
    const askReads = !!this.engine.workspaces.effectivePolicy(root);
    // Sensitive folders: the agent learns the data rule up front, so it reaches for Read instead of `head`/`cat`.
    // The advisor tool exists only when switched on, outside sensitive folders, and with another provider to ask.
    const advisorKey = !askReads && this.advisorOn.has(id) && this.engine.router.advisorFor(c) ? crypto.randomUUID() : undefined;
    const sys = [system, this.notes.get(id), askReads ? DATA_RULE_NOTE : "", advisorKey ? ADVISOR_NOTE : ""].filter(Boolean).join("\n\n") || undefined;
    const mcp = advisorKey ? { name: "hib", command: process.execPath, args: [ADVISOR_SCRIPT], env: { HIB_URL: this.daemonUrl, HIB_ADVISOR_KEY: advisorKey, HIB_SESSION: id } } : undefined;
    const sandbox = this.sandbox(this.cfg);
    await driver.start({ cwd: root, model: c.model, account: c.account, resume, system: sys, askReads, mcp, sandbox, denyReads: secretPaths(this.cfg).tools });
    const l: Live = { id, root, candidate: c, driver, nativeId: resume, vault, alwaysAllow: new Set(), pending: new Map(), askReads, advisorKey, sandboxed: !!sandbox, approvedProtected: new Set() };
    this.live.set(id, l);
    return l;
  }

  /** Starts a turn and yields its events until it ends (used by tests and simple clients). */
  async *send(input: { sessionId?: string; root: string; model?: string; text: string; auto?: boolean; advisor?: boolean; system?: string }, _signal?: AbortSignal): AsyncGenerator<WsEvent> {
    const started = this.startTurn(input);
    if ("error" in started) return yield { type: "error", message: started.error };
    const q: WsEvent[] = [];
    let wake: (() => void) | undefined;
    const unsub = this.subscribe(started.sessionId, 0, (_s, e) => {
      q.push(e);
      wake?.();
    });
    try {
      for (;;) {
        while (q.length) {
          const e = q.shift()!;
          if (e.type === "turn_end") return;
          yield e;
        }
        await new Promise<void>((r) => (wake = r));
      }
    } finally {
      unsub();
    }
  }

  private async *runTurn(input: { sessionId: string; isNew: boolean; root: string; model?: string; text: string }, signal: AbortSignal): AsyncGenerator<WsEvent> {
    const { root } = input;
    const id = input.sessionId;
    let row = input.isNew ? null : (this.db.query("SELECT * FROM conversations WHERE id = ? AND workspace = ?").get(id, root) as any);
    if (!input.isNew && !row) return yield { type: "error", message: `no session ${id} in this workspace` };

    const policy = this.engine.workspaces.effectivePolicy(root);
    const chosen = input.model && input.model !== "hib/auto" ? input.model : undefined;
    let modelId = chosen ?? row?.agent_model ?? (policy ? pinnedModel(policy, this.cfg) : await this.defaultModel(root));
    if (policy && !supportsSensitive(policy.account)) return yield { type: "error", message: SENSITIVE_NEEDS_CLAUDE }; // a policy set before this rule
    if (policy && !onPinnedAccount(modelId, policy, this.cfg)) {
      // A sensitive folder only ever talks to its pinned account.
      if (chosen) return yield { type: "error", message: `this workspace is sensitive and pinned to ${policy.account}; ${chosen} is not allowed` };
      modelId = pinnedModel(policy, this.cfg);
    }
    const c = resolveCandidate(modelId, this.cfg);
    if (!c) return yield { type: "error", message: `unknown model ${modelId}` };
    if (!(await this.engine.registry.available(c.account))) return yield { type: "error", message: `${c.id} is not logged in` };

    const vault = row?.vault ? Vault.from(await this.sealer.unseal<VaultState>(row.vault)) : this.live.get(id)?.vault ?? new Vault();
    const route = { ...this.cfg.routes.code, mode: "agent" as const, level: "minimal" as const };

    // Guard: secrets and configured terms are tokenized; the folder pre-scan runs once per session.
    // In sensitive folders, names/places/companies in your prompt are tokenized too (local NER, if enabled).
    const ner = policy ? await this.engine.ner([input.text]) : undefined;
    const insp = inspect([{ role: "user", content: input.text }], route, this.cfg, { cwd: root, vault, skipScan: !!row, ner });
    yield { type: "guard", findings: insp.findings, action: insp.blocked ? "block" : insp.decision.action, reasons: insp.blocked ? [insp.blocked] : insp.decision.reasons };
    if (insp.blocked) return yield { type: "error", message: `blocked: ${insp.blocked}` };
    if (policy) {
      // Sensitive workspaces never send a secret, not even tokenized: the agent could still act on it.
      const secrets = [...new Set(detect(input.text, { level: "minimal" }).filter((f) => f.kind === "secret").map((f) => f.category))];
      if (secrets.length) return yield { type: "error", message: `blocked: this workspace is sensitive and your message contains ${secrets.join(", ")}. Remove it and send again.` };
    }
    let text = insp.messages[0]!.content;
    if (insp.decision.action === "ask") {
      const aid = `ap_${crypto.randomUUID().slice(0, 12)}`;
      yield { type: "approval", id: aid, redacted: text, reasons: insp.decision.reasons };
      const r = await this.engine.waitApproval({ id: aid, created: Date.now(), redacted: text, original: input.text, reasons: insp.decision.reasons, findings: insp.findings, model: c.id }, signal);
      if (!r.ok) return yield { type: "error", message: "not sent: approval rejected or timed out" };
      if (r.edited !== undefined) text = obfuscateText(vault, r.edited, "minimal", this.cfg, "agent");
    }

    // Session bookkeeping happens only after the guard let the turn through.
    if (!row) {
      this.db.run("INSERT INTO conversations(id, title, created, updated, workspace, agent_model) VALUES (?,?,?,?,?,?)", [id, input.text.replace(/\s+/g, " ").slice(0, 80), Date.now(), Date.now(), root, c.id]);
      row = { id, agent_model: c.id };
    }
    const sid = id;

    let l = this.live.get(sid);
    if (l && !!policy !== l.askReads) {
      // The folder's sensitivity changed since this CLI started; restart it on its native session with the right permissions.
      await l.driver.close();
      this.live.delete(sid);
      row.native_id = l.nativeId ?? row.native_id;
      l = undefined;
    }
    if (this.advisorOn.has(sid) && (policy || !this.engine.router.advisorFor(c))) {
      this.advisorOn.delete(sid);
      yield { type: "advisor_mode", on: false, why: policy ? "not available in sensitive folders" : `no model from another provider is available to advise ${c.id}` };
    }
    if (l && this.advisorOn.has(sid) !== !!l.advisorKey) {
      // The advisor was switched on or off: restart the CLI on its native session with or without the tool.
      await l.driver.close();
      this.live.delete(sid);
      row.native_id = l.nativeId ?? row.native_id;
      l = undefined;
    }
    if (l && !l.driver.alive) {
      // The CLI died (crash, stall, interrupt fallback); reopen it on the native session.
      this.live.delete(sid);
      row.native_id = l.nativeId ?? row.native_id;
      l = undefined;
    }
    let firstTurnPrefix = "";
    if (l && l.candidate.id !== c.id) {
      await l.driver.close();
      this.live.delete(sid);
      // Same CLI and login: keep the native session, only the model changes. Otherwise hand over.
      const sameCli = l.candidate.provider === c.provider && l.candidate.account.id === c.account.id;
      const from = l.candidate.id;
      l = await this.open(sid, root, c, sameCli ? l.nativeId : undefined, vault);
      if (!sameCli) {
        firstTurnPrefix = obfuscateText(vault, this.handoffText(sid), "minimal", this.cfg, "agent");
        yield { type: "handoff", from, to: c.id };
      }
    } else if (!l) {
      const prev = row.agent_model ? resolveCandidate(row.agent_model, this.cfg) : null;
      const sameCli = prev && prev.provider === c.provider && prev.account.id === c.account.id;
      l = await this.open(sid, root, c, sameCli ? row.native_id ?? undefined : undefined, vault);
      if (row.native_id && !sameCli) {
        firstTurnPrefix = obfuscateText(vault, this.handoffText(sid), "minimal", this.cfg, "agent");
        yield { type: "handoff", from: row.agent_model, to: c.id };
      }
    }
    yield { type: "ws_session", id: sid, model: c.id, resumed: !!l.nativeId, sandbox: l.sandboxed };
    this.db.run("UPDATE conversations SET agent_model = ?, updated = ?, vault = ? WHERE id = ?", [c.id, Date.now(), await this.sealer.seal(vault.state()), sid]);
    this.record(sid, { type: "user", text: input.text, model: c.id });

    // A fresh CLI context (new session or handoff) starts from the folder's PROGRESS.md; a resumed one already has it.
    const progress = l.nativeId ? "" : this.progressText(root, vault, !!policy);
    // Sensitive folders can hand the agent pseudonymised files later in the turn, so it always gets the note.
    const note = vault.size || policy ? `(${tokenNote(vault.tag)})\n\n` : "";
    const prompt = [firstTurnPrefix, progress, `${note}${text}`].filter(Boolean).join("\n\n");
    // Egress log: exactly what this turn sends, and to whom. The CLI's own reads show up as tool calls.
    const sentEv = { type: "sent" as const, account: c.account.id, model: c.id, text, handoff: !!firstTurnPrefix, progress: !!progress, chars: prompt.length };
    this.record(sid, sentEv);
    yield sentEv;
    if (Object.keys(insp.findings).length || insp.decision.reasons.length)
      this.record(sid, {
        type: "guard_decision",
        summary: `${Object.entries(insp.findings).map(([k, v]) => `${k}×${v}`).join(" ") || "no findings"} → ${insp.decision.action === "ask" ? "you approved sending the redacted text" : "redacted"}${insp.decision.reasons.length ? ` (${insp.decision.reasons.join("; ").slice(0, 160)})` : ""}`,
      });

    const runId = `r_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const started = Date.now();
    this.db.run("INSERT INTO runs(id, ts, conversation_id, class, model, account, mode, pipeline, status) VALUES (?,?,?,?,?,?,?,?,?)", [runId, started, sid, "code", c.id, c.account.id, "agent", "workspace", "running"]);
    // Data files in the folder (by name), so `cat clients.json` is caught even though .json isn't always data.
    let dataCache: Set<string> | undefined;
    const dataFiles = () => {
      if (dataCache) return dataCache;
      dataCache = new Set();
      const walk = (dir: string, depth: number) => {
        if (depth > 3) return;
        for (const n of readdirSync(dir)) {
          if (n.startsWith(".") || n === "node_modules") continue;
          const p = join(dir, n);
          const st = statSync(p, { throwIfNoEntry: false });
          if (st?.isDirectory()) walk(p, depth + 1);
          else if (st && isDataFile(p)) dataCache!.add(n);
        }
      };
      try {
        walk(root, 0);
      } catch {}
      return dataCache;
    };
    const restorer = new StreamRestorer(vault);
    let answer = "";
    let failure: string | undefined;
    let tokIn = 0, tokOut = 0;
    const onAbort = () => l!.driver.interrupt();
    signal.addEventListener("abort", onAbort, { once: true });
    // Git hooks/config and tool config, by content: whatever changes there this turn without your approval is put back.
    const guarded = protectedSnapshot(root);
    l.approvedProtected.clear();

    try {
      for await (const e of l.driver.turn(prompt)) {
        switch (e.type) {
          case "session":
            l.nativeId = e.nativeId;
            this.db.run("UPDATE conversations SET native_id = ? WHERE id = ?", [e.nativeId, sid]);
            break;
          case "text": {
            const out = restorer.push(e.delta);
            answer += out;
            if (out) yield { type: "text", delta: out };
            break;
          }
          case "tool_call": {
            const ev = { type: "tool_call" as const, call: restoreCall(e.call, vault) };
            this.record(sid, ev);
            yield ev;
            break;
          }
          case "tool_result": {
            const ev = { ...e, output: e.output ? vault.restore(e.output) : undefined };
            this.record(sid, ev);
            yield ev;
            break;
          }
          case "permission": {
            const call = restoreCall(e.call, vault);
            if (e.call.outbound) call.outbound = webOutbound(e.call.outbound);
            if (policy && call.kind === "command" && call.command) {
              // Raw reads of data through the shell are refused outright; the agent is told to use Read instead.
              const why = rawDataCommand(call.command, root, dataFiles());
              if (why) {
                const message = `Blocked by hib: this folder is sensitive and ${why}. Read data files with the Read tool instead (you get a pseudonymised copy).`;
                l.driver.answer(e.id, { behavior: "deny", message });
                const ev = { type: "tool_result" as const, id: call.id, ok: false, output: `denied: ${why}` };
                this.record(sid, { type: "data_block", command: call.command, why });
                this.record(sid, { type: "tool_call", call });
                this.record(sid, ev);
                yield { type: "tool_call", call };
                yield ev;
                break;
              }
            }
            if (policy && tabularTarget(call, e.input, root)) call.title += " (the agent gets a pseudonymised copy)";
            else if (policy && call.name === "Grep") call.title += " (may return raw rows from data files)";
            if ((l.advisorKey && call.name === "mcp__hib__advisor") || this.autoAllowed(l, e.ruleKey, call) || (this.auto.has(sid) && this.autoModeCovers(l, call))) {
              l.driver.answer(e.id, this.allowDecision(l, call, e.input));
              break;
            }
            l.pending.set(e.id, { call, ruleKey: e.ruleKey, input: e.input });
            this.changed();
            yield { type: "permission", id: e.id, call, ruleKey: e.ruleKey };
            break;
          }
          case "usage":
            [tokIn, tokOut] = [tokIn + e.in, tokOut + e.out];
            break;
          case "quota":
            this.engine.usage.recordQuota(c.account.id, e);
            break;
          case "rate_limited":
            this.engine.usage.cooldown(c.account.id, e.resetsAt ? e.resetsAt * 1000 : Date.now() + 15 * 60_000, e.message);
            failure = e.message;
            yield e;
            break;
          case "error":
            failure = e.message;
            yield { type: "error", message: vault.restore(e.message) };
            break;
          case "turn_done":
            break;
        }
      }
    } catch (err: any) {
      failure = String(err?.message ?? err);
      yield { type: "error", message: failure };
    } finally {
      signal.removeEventListener("abort", onAbort);
      for (const pid of l.pending.keys()) l.driver.answer(pid, { behavior: "deny", message: "turn ended" });
      l.pending.clear();
      this.changed();
    }
    let protectedEv: Extract<WsEvent, { type: "protected_reverted" }> | undefined;
    try {
      const unapproved = protectedChanges(guarded, root).filter((c) => !l!.approvedProtected.has(c.path));
      if (unapproved.length) {
        const failed = revertProtected(guarded, unapproved);
        protectedEv = { type: "protected_reverted", changes: unapproved.map((c) => ({ ...c, path: c.path.startsWith(root + "/") ? c.path.slice(root.length + 1) : c.path })), failed };
      }
    } catch (e: any) {
      // The check itself must never be what lets a change through: say so loudly instead.
      protectedEv = { type: "protected_reverted", changes: [], failed: [`the check failed (${String(e?.message ?? e).slice(0, 160)}); inspect .git/hooks, .git/config, .claude/, .codex/ and .mcp.json by hand`] };
    }
    if (protectedEv) {
      this.record(sid, protectedEv);
      yield protectedEv;
    }
    const tail = restorer.flush();
    answer += tail;
    if (tail) yield { type: "text", delta: tail };
    if (answer) this.record(sid, { type: "assistant", text: answer, model: c.id });
    this.db.run("UPDATE runs SET in_tok = ?, out_tok = ?, ms = ?, status = ? WHERE id = ?", [tokIn, tokOut, Date.now() - started, failure ? failure.slice(0, 200) : "ok", runId]);
    this.db.run("UPDATE conversations SET updated = ?, vault = ? WHERE id = ?", [Date.now(), await this.sealer.seal(vault.state()), sid]);
    yield { type: "done" };
  }

  /**
   * What left the machine in a session, turn by turn: the redacted prompt and the vendor account that got it,
   * plus every tool call the agent made (file reads and command output go to the same account).
   */
  egress(id: string) {
    const turns: { at?: number; account: string; model: string; prompt: string; handoff: boolean; guard?: string; actions: { kind: string; title: string; status: string }[] }[] = [];
    const byCall = new Map<string, { kind: string; title: string; status: string }>();
    for (const e of this.history(id)) {
      if (e.type === "sent") turns.push({ account: e.account, model: e.model, prompt: e.text, handoff: e.handoff, actions: [] });
      else if (e.type === "advice") turns.push({ account: e.account, model: e.model, prompt: `advisor (${e.chars} chars: task, session summary, diff): ${e.question}`, handoff: false, guard: e.guard, actions: [] });
      else if (e.type === "guard_decision" && turns.length) turns[turns.length - 1]!.guard = e.summary;
      else if (e.type === "pseudonymised" && turns.length)
        turns[turns.length - 1]!.actions.push({ kind: "read", title: `pseudonymised copy of ${e.file} (tokenized: ${e.columns.join(", ") || "none"})`, status: "done" });
      else if (e.type === "tool_call" && turns.length) {
        const known = byCall.get(e.call.id);
        if (known) {
          known.title = e.call.title; // a later event can carry more detail (e.g. the final search query)
          continue;
        }
        const a = { kind: e.call.kind, title: e.call.title, status: "requested" };
        byCall.set(e.call.id, a);
        turns[turns.length - 1]!.actions.push(a);
      } else if (e.type === "tool_result") {
        const a = byCall.get(e.id);
        if (a) a.status = e.ok ? "done" : /denied|declined/i.test(e.output ?? "") ? "denied" : "failed";
      }
    }
    return turns;
  }

  /**
   * What the CLI actually executes: placeholders restored, and in sensitive folders table reads redirected to a
   * pseudonymised copy. If that copy can't be made, the read is denied: it was approved on the promise of the copy.
   */
  private allowDecision(l: Live, call: ToolCall, input: unknown): Decision {
    if (call.kind === "edit") for (const p of call.paths ?? (call.path ? [call.path] : [])) if (protectedPath(l.root, p)) l.approvedProtected.add(realTarget(l.root, p));
    if (input === undefined) return { behavior: "allow" };
    // A web fetch or search leaves the machine: placeholders go out as placeholders, never as the real values.
    if (call.kind === "web" && call.host === undefined) return { behavior: "allow", updatedInput: input };
    const real = restoreDeep(input, l.vault) as any;
    const key = this.engine.workspaces.effectivePolicy(l.root) ? tabularTarget(call, real, l.root) : null;
    if (!key) return { behavior: "allow", updatedInput: real };
    const src = isAbsolute(real[key]) ? real[key] : resolvePath(l.root, real[key]);
    try {
      const table = loadTable(src);
      const cols = columnsToHide(table);
      const dir = join(tmpdir(), `hib-pseudo-${process.getuid?.() ?? "u"}`, l.id);
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      const copy = join(dir, basename(src));
      writeFileSync(copy, pseudonymize(table, cols, l.vault), { mode: 0o600 });
      const ev = { type: "pseudonymised" as const, file: real[key], columns: cols, callId: call.id };
      this.record(l.id, ev);
      this.emit(l.id, ev); // live viewers mark the tool card
      return { behavior: "allow", updatedInput: { ...real, [key]: copy } };
    } catch (e: any) {
      return { behavior: "deny", message: `hib couldn't make a pseudonymised copy of ${basename(src)} (${e?.message ?? e}), so the read was blocked.` };
    }
  }

  /**
   * "Always" rules never cover edits outside the workspace (like Claude Code's acceptEdits), nor tool
   * config inside it: writing .claude/ or .codex/ could widen the agent's own permissions, and .git/hooks runs on commit.
   */
  private autoAllowed(l: Live, ruleKey: string, call: ToolCall): boolean {
    if (!l.alwaysAllow.has(ruleKey)) return false;
    if (call.kind !== "edit") return true;
    const paths = call.paths ?? (call.path ? [call.path] : []);
    return paths.length > 0 && paths.every((p) => insideRoot(l.root, p) && !protectedPath(l.root, p));
  }

  /**
   * Auto mode: edits inside the folder and commands run without asking, except edits to tool config and
   * ASK_EVEN_IN_AUTO commands. Reads and searches run unasked (but ask in sensitive folders); web fetches and searches always ask. Commands are
   * sandboxed (no writes outside the folder, no reads of hib or credentials), and a command reaching a host
   * other than a package registry asks.
   */
  private autoModeCovers(l: Live, call: ToolCall): boolean {
    if (!l.sandboxed) return false;
    if (call.host !== undefined) return REGISTRIES.has(call.host);
    if (call.kind === "edit") {
      const paths = call.paths ?? (call.path ? [call.path] : []);
      return paths.length > 0 && paths.every((p) => insideRoot(l.root, p) && !protectedPath(l.root, p));
    }
    if (call.kind === "command") return !!call.command && !ASK_EVEN_IN_AUTO.test(call.command);
    // The CLI's file tools aren't sandboxed: reads outside the folder ask, even in auto mode.
    if (call.kind === "read" || call.kind === "search") return !l.askReads && (!call.path || insideRoot(l.root, call.path));
    // WebFetch / WebSearch send text (and anything a prompt-injected page asks for) off the machine: always ask.
    return false;
  }

  /** Switches a session between asking for every action (manual, the default) and auto mode; pending prompts it covers are approved. */
  setAuto(sessionId: string, on: boolean) {
    if (on && !this.sandboxed()) {
      this.auto.delete(sessionId);
      return this.emit(sessionId, { type: "mode", auto: false, why: "auto mode needs an OS sandbox for agent commands (macOS, or Linux with bubblewrap and socat installed)" });
    }
    if (on) this.auto.add(sessionId);
    else this.auto.delete(sessionId);
    this.emit(sessionId, { type: "mode", auto: on });
    const l = this.live.get(sessionId);
    if (on && l) for (const [id, p] of l.pending) if (this.autoModeCovers(l, p.call)) this.answer(sessionId, id, "allow");
  }

  /** A standing system note for a session's CLI, applied whenever it (re)starts. */
  setNote(sessionId: string, note: string) {
    if (note) this.notes.set(sessionId, note);
    else this.notes.delete(sessionId);
  }

  running(sessionId: string): boolean {
    return !!this.hubs.get(sessionId)?.running;
  }

  /** Stops a session's turn and its CLI; the history stays. */
  async close(sessionId: string) {
    await this.interrupt(sessionId);
    const l = this.live.get(sessionId);
    this.live.delete(sessionId);
    await l?.driver.close();
    this.auto.delete(sessionId);
    this.notes.delete(sessionId);
  }

  /** Switches the advisor tool for a session; it takes effect on the next message (the CLI restarts on its native session). */
  setAdvisor(sessionId: string, on: boolean) {
    if (on) this.advisorOn.add(sessionId);
    else this.advisorOn.delete(sessionId);
    this.emit(sessionId, { type: "advisor_mode", on });
  }

  /**
   * The agent's advisor tool call. Context (task, session summary, diff) goes through the guard with the session's
   * own vault, so placeholders match what the agent sees; the reply goes back with placeholders intact.
   */
  async advise(sessionId: string, key: string, question: string): Promise<string> {
    const l = this.live.get(sessionId);
    if (!l?.advisorKey || key.length !== l.advisorKey.length || !crypto.timingSafeEqual(Buffer.from(key), Buffer.from(l.advisorKey))) throw new Error("unauthorized");
    const adv = this.engine.router.advisorFor(l.candidate);
    if (!adv) throw new Error("no model from another provider is available right now");
    const history = this.history(sessionId);
    const task = history.filter((e) => e.type === "user").slice(-5).map((e) => e.text).join("\n---\n");
    const transcript = this.transcript(sessionId, 20_000);
    const git = Bun.spawnSync(["git", "-c", "core.fsmonitor=false", "diff", "--no-ext-diff", "--no-textconv", "HEAD"], { cwd: l.root, stdout: "pipe", stderr: "pipe" });
    let diff = git.success ? git.stdout.toString() : "";
    if (diff.length > 40_000) diff = diff.slice(0, 40_000) + "\n… (diff truncated)";
    const plain = ADVISOR_PROMPT(task, transcript, diff, question);
    const found = detect(plain, { level: "minimal" });
    const counts: Record<string, number> = {};
    for (const f of found) counts[f.category] = (counts[f.category] ?? 0) + 1;
    const guard = Object.entries(counts).map(([k, v]) => `${k}×${v}`).join(" ") || "nothing to redact";
    const outbound = [{ role: "user" as const, content: obfuscateText(l.vault, plain, "minimal", this.cfg, "agent") }];
    const r = await this.engine.consult(adv, l.vault, outbound, { cwd: l.root, guard, signal: AbortSignal.timeout(600_000) });
    const ev = { type: "advice" as const, model: adv.id, account: adv.account.id, question: l.vault.restore(question), advice: r.ok ? r.text : `advisor failed: ${r.why}`, ok: r.ok, chars: outbound[0]!.content.length, guard };
    this.record(sessionId, ev);
    this.emit(sessionId, ev);
    if (!r.ok) throw new Error(r.why ?? "advisor failed");
    return r.raw;
  }

  /** Allow once, allow this kind of call for the rest of the session, or deny. */
  answer(sessionId: string, permissionId: string, choice: "allow" | "always" | "deny", message?: string): boolean {
    const l = this.live.get(sessionId);
    const p = l?.pending.get(permissionId);
    if (!l || !p) return false;
    l.pending.delete(permissionId);
    if (choice === "always") l.alwaysAllow.add(p.ruleKey);
    // The CLI executes exactly what we return, so placeholders are swapped back to real values here.
    const d: Decision =
      choice === "deny"
        ? { behavior: "deny", message: message || "The user denied this action." }
        : this.allowDecision(l, p.call, p.input);
    l.driver.answer(permissionId, d);
    this.record(sessionId, { type: "permission_answer", id: permissionId, choice });
    this.emit(sessionId, { type: "permission_answer", id: permissionId, choice });
    this.changed();
    return true;
  }

  async interrupt(sessionId: string) {
    const h = this.hubs.get(sessionId);
    if (h?.abort) h.abort.abort(); // the running turn's abort handler interrupts the driver
    else await this.live.get(sessionId)?.driver.interrupt();
  }

  closeAll() {
    for (const l of this.live.values()) void l.driver.close();
    this.live.clear();
  }
}
