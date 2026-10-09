import type { Database } from "bun:sqlite";
import type { Config, Mode, TaskClass } from "./config";
import { inspect, machineTerms, obfuscateText, runNer, StreamRestorer, tokenNote, Vault, type NerResult } from "./guard";
import { NerModel, type Infer } from "./guard/ner";
import { stricterLevel, type Finding } from "./guard/detectors";
import { join } from "node:path";
import type { VaultState } from "./guard/vault";
import type { Sealer } from "./guard/seal";
import { Learner, SIGNALS } from "./learn";
import type { Registry } from "./providers/registry";
import { expandSkill, type Plugins } from "./plugins";
import type { Message, RunEvent } from "./providers/types";
import { CLASSIFY_PROMPT, classify, parseClassifierReply } from "./router/classify";
import { Router, resolveCandidate, type Candidate } from "./router/route";
import { Usage } from "./usage";
import { onPinnedAccount, pinnedModel, Workspaces } from "./workspace/registry";
import { columnsToHide, pseudonymizeWithSpans } from "./analyze/pseudo";
import { dirname } from "node:path";
import type { Table } from "./analyze/table";

export interface ChatInput {
  conversationId?: string; // continue a saved conversation
  persist?: boolean; // start a saved conversation (web/TUI); OpenAI clients are stateless
  messages: Message[]; // OpenAI: full history. Conversations: only the new user turn(s).
  model?: string; // "hib/auto" | "hib/chat" | "hib/code" | "hib/review" | explicit "claude@work/sonnet"
  mode?: Mode;
  cwd?: string;
  arena?: boolean; // force head-to-head
  allowArena?: boolean; // let arenaRate trigger one (only for UIs that can show it)
  solo?: boolean; // exactly one model: no advisor, arena or failover to another vendor
  attachments?: { name: string; path?: string; table: Table; hide?: string[]; keep?: string[] }[]; // tables sent pseudonymised by column
}

export type HibEvent =
  | { type: "conversation"; id: string }
  | { type: "meta"; runId: string; cls: TaskClass; why: string; model: string; mode: Mode; level: string; advisor: boolean; skipped: { id: string; why: string }[] }
  | { type: "guard"; findings: Record<string, number>; action: string; reasons: string[] }
  | { type: "approval"; id: string; redacted: string; reasons: string[] }
  | { type: "approved"; edited: boolean }
  | { type: "text"; delta: string; part: "primary" | "revision" }
  | { type: "tool"; name: string; detail?: string }
  | { type: "failover"; from: string; to?: string; why: string }
  | { type: "advisor"; model: string; verdict: "ok" | "issues"; critique: string }
  | { type: "arena"; id: string; a: { runId: string; model: string; text: string }; b: { runId: string; model: string; text: string } }
  | { type: "done"; runId: string; model: string }
  | { type: "error"; message: string };

interface Approval {
  id: string;
  created: number;
  redacted: string;
  original: string;
  reasons: string[];
  findings: Record<string, number>;
  model: string;
  resolve: (r: { ok: boolean; edited?: string }) => void;
}

const RETRY_WINDOW_MS = 10 * 60_000;

const ADVISOR_PROMPT = (answer: string, checklist: string[]) =>
  `You are reviewing another AI assistant's answer to the conversation above. Here is the answer:\n<answer>\n${answer}\n</answer>\n\n` +
  (checklist.length ? `Check in particular:\n${checklist.join("\n")}\n\n` : "") +
  `If it is correct and complete enough, reply with exactly: OK\nOtherwise reply with a short numbered list of concrete problems (bugs, wrong facts, missed requirements). No rewrite.`;
const REVISE_PROMPT = (critique: string) =>
  `A reviewer from a different AI provider found these problems with your previous answer:\n${critique}\n\nWrite a corrected, complete answer. Do not mention the review.`;

const newId = (p: string) => `${p}_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
const hash = (s: string) => new Bun.CryptoHasher("sha256").update(s).digest("hex").slice(0, 32);

interface RunCtx {
  c: Candidate;
  runId: string;
  outbound: Message[];
  cls: TaskClass;
  mode: Mode;
  cwd?: string;
  vault: Vault;
  signal: AbortSignal;
  conversationId?: string;
  promptHash: string;
  part: "primary" | "revision" | "advisor" | "arena";
  explicit?: boolean;
  guard?: string; // the guard's summary for this request, kept with the egress record
}

interface RunResult {
  raw: string; // as the model wrote it (tokens intact)
  text: string; // restored
  ok: boolean;
  why?: string;
}

export class Engine {
  readonly usage: Usage;
  readonly learner: Learner;
  readonly router: Router;
  readonly workspaces: Workspaces;
  readonly nerModel: NerModel;
  private nerCache = new Map<string, Finding[]>();
  private approvals = new Map<string, Approval>();
  private approvalListeners = new Set<() => void>();

  constructor(readonly cfg: Config, readonly db: Database, readonly registry: Registry, readonly sealer: Sealer, readonly plugins: Plugins) {
    this.usage = new Usage(db, cfg);
    this.learner = new Learner(db);
    this.router = new Router(cfg, registry, this.usage, this.learner);
    this.workspaces = new Workspaces(db, cfg);
    this.nerModel = new NerModel(join(cfg.home, "models"));
  }

  /** Local NER over texts, cached per text so long conversations aren't re-scanned every turn. Tests swap `nerInfer`. */
  nerInfer?: Infer;
  async ner(texts: string[]): Promise<NerResult> {
    if (!this.cfg.guard.ner) return { byText: new Map() };
    const todo = texts.filter((t) => !this.nerCache.has(t));
    const r = await runNer(todo, this.cfg, this.nerInfer ?? this.nerModel.infer);
    if (r.error) return r;
    for (const [t, f] of r.byText) {
      if (this.nerCache.size > 2000) this.nerCache.delete(this.nerCache.keys().next().value!);
      this.nerCache.set(t, f);
    }
    return { byText: new Map(texts.map((t) => [t, this.nerCache.get(t) ?? []])) };
  }

  /** Egress log for router requests: exactly what each model call sent (already redacted), and to whom. */
  private recordEgress(runId: string | null, part: string, c: Candidate, outbound: Message[], cwd: string | undefined, guard: string | undefined) {
    const text = outbound.map((m) => `<${m.role}>\n${m.content}`).join("\n\n");
    this.db.run("INSERT INTO egress(ts, run_id, part, cwd, model, account, guard, chars, text) VALUES (?,?,?,?,?,?,?,?,?)", [
      Date.now(), runId, part, cwd ?? null, c.id, c.account.id, guard ?? null, text.length, text.slice(0, 500_000),
    ]);
  }

  egressList(opts: { limit?: number; cwd?: string; run?: string } = {}) {
    const where = opts.run ? "WHERE run_id = ?" : opts.cwd ? "WHERE cwd = ?" : "";
    const args = opts.run ? [opts.run] : opts.cwd ? [opts.cwd] : [];
    return this.db
      .query(`SELECT id, ts, run_id, part, cwd, model, account, guard, chars, substr(text, CASE WHEN instr(text, '<user>') > 0 THEN instr(text, '<user>') ELSE 1 END, 400) AS head FROM egress ${where} ORDER BY id DESC LIMIT ?`)
      .all(...args, opts.limit ?? 20) as any[];
  }

  egressGet(id: number | "last") {
    return id === "last" ? this.db.query("SELECT * FROM egress ORDER BY id DESC LIMIT 1").get() : this.db.query("SELECT * FROM egress WHERE id = ?").get(id);
  }

  // ---------- conversations ----------

  listConversations(limit = 50) {
    return this.db.query("SELECT id, title, created, updated, last_model FROM conversations WHERE workspace IS NULL ORDER BY updated DESC LIMIT ?").all(limit) as any[];
  }

  getConversation(id: string) {
    const c = this.db.query("SELECT id, title, created, updated, last_model FROM conversations WHERE id = ? AND workspace IS NULL").get(id) as any;
    if (!c) return null;
    c.messages = this.db.query("SELECT role, content, model, run_id FROM messages WHERE conversation_id = ? ORDER BY id").all(id);
    return c;
  }

  deleteConversation(id: string) {
    this.db.run("DELETE FROM messages WHERE conversation_id = ?", [id]);
    this.db.run("DELETE FROM conversations WHERE id = ?", [id]);
  }

  private async loadVault(conversationId: string): Promise<Vault> {
    const r = this.db.query("SELECT vault FROM conversations WHERE id = ?").get(conversationId) as any;
    return r?.vault ? Vault.from(await this.sealer.unseal<VaultState>(r.vault)) : new Vault();
  }

  private async saveVault(conversationId: string, vault: Vault) {
    this.db.run("UPDATE conversations SET vault = ? WHERE id = ?", [await this.sealer.seal(vault.state()), conversationId]);
  }

  private addMessage(conversationId: string, m: Message, model?: string, runId?: string) {
    this.db.run("INSERT INTO messages(conversation_id, role, content, model, run_id, ts) VALUES (?,?,?,?,?,?)", [conversationId, m.role, m.content, model ?? null, runId ?? null, Date.now()]);
    this.db.run("UPDATE conversations SET updated = ?, last_model = COALESCE(?, last_model) WHERE id = ?", [Date.now(), model ?? null, conversationId]);
  }

  // ---------- approvals ----------

  pendingApprovals() {
    return [...this.approvals.values()].map(({ resolve, original, ...a }) => ({ ...a, original }));
  }

  onApprovalsChanged(fn: () => void) {
    this.approvalListeners.add(fn);
    return () => this.approvalListeners.delete(fn);
  }

  decideApproval(id: string, ok: boolean, edited?: string): boolean {
    const a = this.approvals.get(id);
    if (!a) return false;
    this.approvals.delete(id);
    a.resolve({ ok, edited });
    this.approvalListeners.forEach((f) => f());
    return true;
  }

  waitApproval(a: Omit<Approval, "resolve">, signal: AbortSignal): Promise<{ ok: boolean; edited?: string }> {
    return new Promise((resolve) => {
      const done = (r: { ok: boolean; edited?: string }) => {
        clearTimeout(timer);
        this.approvals.delete(a.id);
        this.approvalListeners.forEach((f) => f());
        resolve(r);
      };
      const timer = setTimeout(() => done({ ok: false }), this.cfg.guard.approvalTimeoutSec * 1000);
      signal.addEventListener("abort", () => done({ ok: false }), { once: true });
      this.approvals.set(a.id, { ...a, resolve: done });
      this.approvalListeners.forEach((f) => f());
    });
  }

  // ---------- feedback ----------

  feedback(runId: string, value: number) {
    const r = this.db.query("SELECT class, model FROM runs WHERE id = ?").get(runId) as any;
    if (!r) return false;
    this.db.run("INSERT INTO feedback(run_id, ts, kind, value) VALUES (?,?,?,?)", [runId, Date.now(), "thumbs", value]);
    this.learner.record(r.class, r.model, value > 0 ? SIGNALS.thumbsUp : SIGNALS.thumbsDown);
    return true;
  }

  pickArena(id: string, winner: "a" | "b") {
    const r = this.db.query("SELECT * FROM arena WHERE id = ?").get(id) as any;
    if (!r || r.winner) return false;
    this.db.run("UPDATE arena SET winner = ? WHERE id = ?", [winner, id]);
    const [w, l] = winner === "a" ? [r.run_a, r.run_b] : [r.run_b, r.run_a];
    const runW = this.db.query("SELECT model FROM runs WHERE id = ?").get(w) as any;
    const runL = this.db.query("SELECT model FROM runs WHERE id = ?").get(l) as any;
    if (runW) this.learner.record(r.class, runW.model, SIGNALS.arenaWin);
    if (runL) this.learner.record(r.class, runL.model, SIGNALS.arenaLoss);
    // The conversation keeps the winner's answer.
    if (winner === "b") this.db.run("UPDATE messages SET content = ?, model = ?, run_id = ? WHERE run_id = ?", [r.text_b, runW?.model, w, r.run_a]);
    return true;
  }

  // ---------- the pipeline ----------

  async *chat(input: ChatInput, signal: AbortSignal): AsyncGenerator<HibEvent> {
    input = { ...input, messages: [...input.messages] };
    // `/skill args` from any client expands to the skill's prompt and preferences.
    const lastIn = input.messages.length - 1;
    const skill = lastIn >= 0 && input.messages[lastIn]!.role === "user" ? expandSkill(input.messages[lastIn]!.content, this.plugins) : null;
    if (skill) {
      input.messages[lastIn] = { role: "user", content: skill.prompt };
      input.model ??= skill.skill.model;
      input.mode ??= skill.skill.mode;
    }
    const agentName = input.model?.startsWith("hib/agent/") ? input.model.slice("hib/agent/".length) : undefined;
    const agent = agentName ? this.plugins.agents.get(agentName) : undefined;
    if (agentName && !agent) return yield { type: "error", message: `no agent plugin "${agentName}"` };
    if (agent) {
      input.model = agent.model ?? (agent.route ? `hib/${agent.route}` : "hib/auto");
      input.mode ??= agent.mode;
    }

    let conversationId = input.conversationId;
    let history: Message[];
    let vault: Vault;
    const persistent = conversationId !== undefined || !!input.persist;

    if (conversationId) {
      const c = this.getConversation(conversationId);
      if (!c) return yield { type: "error", message: `no conversation ${conversationId}` };
      history = c.messages.map((m: any) => ({ role: m.role, content: m.content }));
      vault = await this.loadVault(conversationId);
    } else {
      history = [];
      vault = new Vault();
    }
    // Attached tables go out pseudonymised by column, with tokens from this conversation's vault so answers restore.
    const attached = (input.attachments ?? []).map((a) => {
      const cols = columnsToHide(a.table, a.hide, a.keep);
      const { csv, kept } = pseudonymizeWithSpans(a.table, cols, vault, a.keep ?? []);
      const head = `<table name="${a.name}" rows="${a.table.rows.length}">\n`;
      const keptNote = a.keep?.length ? `; kept readable: ${a.keep.join(", ")}` : "";
      return { note: `[attached ${a.name}: ${a.table.rows.length} rows; pseudonymised: ${cols.join(", ") || "none"}${keptNote}]`, text: `${head}${csv}</table>`, kept: kept.map(([s, e]) => [s + head.length, e + head.length] as [number, number]) };
    });
    if (attached.reduce((n, x) => n + x.text.length, 0) > 400_000)
      return yield { type: "error", message: "attached table is too large to send; use `hib analyze`, which sends only the schema" };
    // Kept columns are exempt from every detector: record their spans in the final message text.
    const exempt = new Map<string, [number, number][]>();
    const outgoingInput = attached.length
      ? input.messages.map((m, i) => {
          if (i !== lastIn || m.role !== "user") return m;
          let content = m.content;
          const spans: [number, number][] = [];
          for (const x of attached) {
            content += "\n\n";
            spans.push(...x.kept.map(([s, e]) => [s + content.length, e + content.length] as [number, number]));
            content += x.text;
          }
          exempt.set(content, spans);
          return { ...m, content };
        })
      : input.messages;
    const messages = [...history, ...outgoingInput];

    // classify
    // Work inside a sensitive workspace goes to its one pinned account: no classifier call, failover, advisor or arena.
    // An attached file from a sensitive folder pins the request just like working in it.
    const sensitive =
      (input.cwd ? this.workspaces.policyFor(input.cwd) : null) ??
      (input.attachments ?? []).map((a) => (a.path ? this.workspaces.policyFor(dirname(a.path)) : null)).find(Boolean) ??
      null;
    // Attached tables go to exactly one model: never to an advisor or arena opponent.
    if (input.attachments?.length) input.solo = true;
    if (sensitive && input.model && !input.model.startsWith("hib/") && !onPinnedAccount(input.model, sensitive.policy, this.cfg))
      return yield { type: "error", message: `${sensitive.root} is sensitive and pinned to ${sensitive.policy.account}; ${input.model} is not allowed` };
    const forced = input.model?.startsWith("hib/") && input.model !== "hib/auto" ? input.model.slice(4) : undefined;
    if (forced && !this.cfg.routes[forced]) return yield { type: "error", message: `no route "${forced}"` };
    let explicit = input.model && !forced && input.model !== "hib/auto" ? input.model : undefined;
    let { cls, confident, why } = classify(messages, input.mode ?? "chat", this.plugins.routes);
    if (forced) [cls, why] = [forced, `forced by ${input.model}`];
    else if (!confident && !explicit && !sensitive) {
      const llm = await this.classifyWithModel(messages, signal, await this.ner(messages.map((m) => m.content)));
      if (llm) [cls, why] = [llm, `${why}; classifier said ${llm}`];
    }

    if (sensitive) explicit ??= pinnedModel(sensitive.policy, this.cfg, cls);
    const plan = await this.router.plan(cls, { explicit, mode: input.mode, cwd: input.cwd });
    // An agent plugin can make the guard stricter, never looser; and the sensitive/solo rules apply after it, so no
    // plugin turns the advisor back on where it must stay off.
    if (agent) plan.route = { ...plan.route, level: stricterLevel(agent.level, plan.route.level), advisor: agent.advisor ?? plan.route.advisor };
    if (sensitive || input.solo) plan.route = { ...plan.route, advisor: false };
    if (input.solo) plan.ordered = plan.ordered.slice(0, 1);
    if (!plan.ordered.length) return yield { type: "error", message: `no usable model for ${cls}: ${plan.skipped.map((s) => `${s.id} (${s.why})`).join(", ")}` };

    // guard
    // Names, places and companies (local NER) are tokenized too, unless the route only covers secrets.
    const ner = plan.route.level === "minimal" ? undefined : await this.ner(messages.map((m) => m.content));
    const insp = inspect(messages, plan.route, this.cfg, { cwd: input.cwd, vault, ner, exempt });
    yield { type: "guard", findings: insp.findings, action: insp.blocked ? "block" : insp.decision.action, reasons: insp.blocked ? [insp.blocked] : insp.decision.reasons };
    if (insp.blocked) return yield { type: "error", message: `blocked: ${insp.blocked}` };
    let outbound = insp.messages;
    const lastUserIdx = outbound.map((m) => m.role).lastIndexOf("user");
    let edited: string | undefined; // what you approved, if you changed it: history keeps that, not what you removed

    if (insp.decision.action === "ask") {
      const id = newId("ap");
      yield { type: "approval", id, redacted: outbound[lastUserIdx]?.content ?? "", reasons: insp.decision.reasons };
      const r = await this.waitApproval(
        { id, created: Date.now(), redacted: outbound[lastUserIdx]?.content ?? "", original: messages[lastUserIdx]?.content ?? "", reasons: insp.decision.reasons, findings: insp.findings, model: plan.ordered[0]!.id },
        signal,
      );
      this.audit(id, plan, insp.findings, r.ok ? "approved" : "rejected", insp.decision.reasons, "user");
      if (!r.ok) return yield { type: "error", message: "not sent: approval rejected or timed out" };
      if (r.edited !== undefined && lastUserIdx >= 0) {
        // Edits are made to the redacted text; re-check them so nothing new slips out unredacted.
        const edNer = ner ? await this.ner([r.edited]) : undefined;
        if (edNer?.error) return yield { type: "error", message: `not sent: ${edNer.error}` };
        const again = obfuscateText(vault, r.edited, plan.route.level, this.cfg, plan.route.mode, edNer?.byText.get(r.edited));
        outbound = outbound.map((m, i) => (i === lastUserIdx ? { ...m, content: again } : m));
        edited = vault.restore(again);
      }
      yield { type: "approved", edited: r.edited !== undefined };
    }
    if (agent) outbound = [{ role: "system", content: obfuscateText(vault, agent.system, plan.route.level, this.cfg, plan.route.mode) }, ...outbound];
    if (vault.size) outbound = [{ role: "system", content: tokenNote(vault.tag) }, ...outbound];

    // Persist only once the guard let the turn through, so a rejected secret never lands in history.
    if (persistent) {
      if (!conversationId) {
        conversationId = newId("c");
        const first = input.messages.findIndex((m) => m.role === "user");
        const title = ((first === lastIn ? edited : undefined) ?? input.messages[first]?.content ?? "chat").replace(/\s+/g, " ").slice(0, 80);
        this.db.run("INSERT INTO conversations(id, title, created, updated) VALUES (?,?,?,?)", [conversationId, title, Date.now(), Date.now()]);
        yield { type: "conversation", id: conversationId };
      }
      // History keeps a note of attachments, not the tables themselves.
      for (const [i, m] of input.messages.entries()) {
        const content = i === lastIn && edited !== undefined ? edited : m.content;
        this.addMessage(conversationId, i === lastIn && attached.length ? { ...m, content: `${content}\n${attached.map((x) => x.note).join("\n")}` } : { ...m, content });
      }
    }

    const promptHash = hash(messages[lastUserIdx]?.content ?? "");
    this.noteRetry(promptHash);

    const guardSummary = `${Object.entries(insp.findings).map(([k, v]) => `${k}×${v}`).join(" ") || "no findings"} → ${insp.decision.action === "ask" ? "approved by you" : "redacted"}`;
    const base = { cls, mode: plan.route.mode, cwd: input.cwd, vault, signal, conversationId, promptHash, guard: guardSummary };
    const wantArena = !input.solo && !explicit && plan.ordered.length >= 2 && (input.arena || (input.allowArena && Math.random() < this.cfg.arenaRate));
    let finalText: string;
    let finalRun: string;
    let finalModel: string;

    if (wantArena) {
      const [a, b] = pickPair(plan.ordered);
      const ids = [newId("r"), newId("r")] as const;
      const [ra, rb] = await Promise.all([
        this.collect({ ...base, c: a, runId: ids[0], outbound, part: "arena" }),
        this.collect({ ...base, c: b, runId: ids[1], outbound, part: "arena" }),
      ]);
      const arenaId = newId("ar");
      this.db.run("INSERT INTO arena(id, ts, class, run_a, run_b, text_b) VALUES (?,?,?,?,?,?)", [arenaId, Date.now(), cls, ids[0], ids[1], rb.text]);
      yield { type: "meta", runId: ids[0], cls, why, model: `${a.id} vs ${b.id}`, mode: plan.route.mode, level: plan.route.level, advisor: false, skipped: plan.skipped };
      yield { type: "arena", id: arenaId, a: { runId: ids[0], model: a.id, text: ra.text }, b: { runId: ids[1], model: b.id, text: rb.text } };
      if (persistent) {
        // A is kept until a pick; pickArena swaps in B if it wins.
        this.addMessage(conversationId!, { role: "assistant", content: ra.text }, a.id, ids[0]);
        await this.saveVault(conversationId!, vault);
      }
      return yield { type: "done", runId: ids[0], model: a.id };
    }

    // primary, with failover down the ordered list
    let primary: Candidate | undefined;
    let res: RunResult | undefined;
    for (let i = 0; i < plan.ordered.length; i++) {
      const c = plan.ordered[i]!;
      const runId = newId("r");
      yield { type: "meta", runId, cls, why, model: c.id, mode: plan.route.mode, level: plan.route.level, advisor: plan.route.advisor, skipped: plan.skipped };
      this.audit(runId, plan, insp.findings, insp.decision.action === "ask" ? "approved" : "redacted", insp.decision.reasons, "policy", c);
      const gen = this.stream({ ...base, c, runId, outbound, part: "primary", explicit: explicit !== undefined });
      let r: IteratorResult<HibEvent, RunResult>;
      while (!(r = await gen.next()).done) yield r.value;
      res = r.value;
      if (res.ok || signal.aborted) {
        primary = c;
        finalRun = runId;
        break;
      }
      // Partial output was already streamed; don't splice another model's answer onto it.
      const next = res.raw ? undefined : plan.ordered[i + 1];
      yield { type: "failover", from: c.id, to: next?.id, why: res.why ?? "failed" };
      if (!next) break;
    }
    if (!primary || !res?.ok) return yield { type: "error", message: res?.why ?? "all candidates failed" };
    finalText = res.text;
    finalModel = primary.id;

    // advisor: a different provider critiques; the primary revises only if problems were found
    if (plan.route.advisor && !signal.aborted) {
      const adv = this.router.advisorFor(primary, input.cwd);
      if (adv) {
        const critiqueRun = newId("r");
        // The answer goes to a second vendor. In agent mode it can quote files the primary read itself, real secrets
        // included, so it passes the guard like any outbound text (same vault, so placeholders still line up).
        const guardedAnswer = obfuscateText(vault, res.raw, plan.route.level, this.cfg, plan.route.mode);
        const review = await this.collect({ ...base, mode: "chat", c: adv, runId: critiqueRun, outbound: [...outbound, { role: "user", content: ADVISOR_PROMPT(guardedAnswer, this.plugins.advisor.filter((a) => a.classes.includes(cls)).map((a) => a.text)) }], part: "advisor" });
        if (review.ok) {
          const ok = /^\s*OK\b/i.test(review.raw) && review.raw.trim().length < 20;
          yield { type: "advisor", model: adv.id, verdict: ok ? "ok" : "issues", critique: review.text };
          if (!ok) {
            this.learner.record(cls, primary.id, SIGNALS.advisorIssues);
            const revRun = newId("r");
            const gen = this.stream({
              ...base, c: primary, runId: revRun, part: "revision",
              outbound: [...outbound, { role: "assistant", content: res.raw }, { role: "user", content: REVISE_PROMPT(review.raw) }],
            });
            let r: IteratorResult<HibEvent, RunResult>;
            while (!(r = await gen.next()).done) yield r.value;
            if (r.value.ok) [finalText, finalRun] = [r.value.text, revRun];
          }
        }
      }
    }

    if (persistent) {
      this.addMessage(conversationId!, { role: "assistant", content: finalText }, finalModel, finalRun!);
      await this.saveVault(conversationId!, vault);
    }
    yield { type: "done", runId: finalRun!, model: finalModel };
  }

  private audit(runId: string, plan: { cls: string; route: any }, findings: Record<string, number>, action: string, reasons: string[], by: string, c?: Candidate) {
    this.db.run("INSERT INTO audit(run_id, ts, route, account, findings, action, reasons, decided_by) VALUES (?,?,?,?,?,?,?,?)", [
      runId, Date.now(), plan.cls, c?.account.id ?? null, JSON.stringify(findings), action, JSON.stringify(reasons), by,
    ]);
  }

  /** Same prompt again within a few minutes means the previous answer wasn't good enough. */
  private noteRetry(promptHash: string) {
    const prev = this.db.query("SELECT class, model FROM runs WHERE prompt_hash = ? AND ts > ? AND pipeline = 'primary' AND status = 'ok' ORDER BY ts DESC LIMIT 1").get(promptHash, Date.now() - RETRY_WINDOW_MS) as any;
    if (prev) this.learner.record(prev.class, prev.model, SIGNALS.retried);
  }

  private async *stream(x: RunCtx): AsyncGenerator<HibEvent, RunResult> {
    const { c, runId, outbound, cls, mode, cwd, vault, signal, conversationId, promptHash, part, explicit } = x;
    const started = Date.now();
    this.recordEgress(runId, part, c, outbound, x.cwd, x.guard);
    this.db.run("INSERT INTO runs(id, ts, conversation_id, class, model, account, mode, pipeline, status, prompt_hash, explicit) VALUES (?,?,?,?,?,?,?,?,?,?,?)", [
      runId, started, conversationId ?? null, cls, c.id, c.account.id, mode, part, "running", promptHash, explicit ? 1 : 0,
    ]);
    const provider = this.registry.get(c.provider)!;
    const restorer = new StreamRestorer(vault);
    let raw = "";
    let text = "";
    let failure: string | undefined;
    let tokIn = 0, tokOut = 0;
    const emit = part === "primary" || part === "revision";

    try {
      for await (const ev of provider.run({ model: c.model, account: c.account, messages: outbound, mode, cwd }, signal) as AsyncIterable<RunEvent>) {
        if (ev.type === "text") {
          raw += ev.delta;
          const out = restorer.push(ev.delta);
          text += out;
          if (emit && out) yield { type: "text", delta: out, part: part as "primary" | "revision" };
        } else if (ev.type === "tool") {
          if (emit) yield { type: "tool", name: ev.name, detail: ev.detail ? vault.restore(ev.detail) : undefined };
        } else if (ev.type === "usage") [tokIn, tokOut] = [tokIn + ev.in, tokOut + ev.out];
        else if (ev.type === "quota") this.usage.recordQuota(c.account.id, ev.quota);
        else if (ev.type === "rate_limited") {
          failure = ev.message ?? "rate limited";
          this.usage.cooldown(c.account.id, ev.resetsAt ? ev.resetsAt * 1000 : Date.now() + 15 * 60_000, failure);
        } else if (ev.type === "error") failure = ev.message;
      }
    } catch (e: any) {
      failure = String(e?.message ?? e);
    }
    const tail = restorer.flush();
    text += tail;
    if (emit && tail) yield { type: "text", delta: tail, part: part as "primary" | "revision" };
    if (signal.aborted) failure ??= "aborted";
    const ok = !failure && raw.length > 0;
    if (!ok) failure ??= "empty response";

    this.db.run("UPDATE runs SET in_tok = ?, out_tok = ?, ms = ?, status = ? WHERE id = ?", [tokIn, tokOut, Date.now() - started, ok ? "ok" : failure!.slice(0, 200), runId]);
    if (part === "primary" || part === "arena") this.learner.record(cls, c.id, ok ? SIGNALS.success : SIGNALS.error);
    return { raw, text, ok, why: failure ? vault.restore(failure) : undefined };
  }

  /**
   * One call outside the router, for the workspace advisor. `outbound` is already obfuscated with `vault`;
   * the call is metered, logged in the egress table and its reply returned with tokens intact.
   */
  async consult(c: Candidate, vault: Vault, outbound: Message[], opts: { cwd: string; guard: string; signal: AbortSignal }): Promise<RunResult> {
    const text = outbound.map((m) => m.content).join("\n");
    return this.collect({ c, runId: newId("run"), outbound, cls: "code", mode: "chat", cwd: opts.cwd, vault, signal: opts.signal, promptHash: hash(text), part: "advisor", guard: opts.guard });
  }

  private async collect(x: RunCtx): Promise<RunResult> {
    const gen = this.stream(x);
    let r: IteratorResult<HibEvent, RunResult>;
    while (!(r = await gen.next()).done);
    return r.value;
  }

  private async classifyWithModel(messages: Message[], signal: AbortSignal, ner: NerResult): Promise<TaskClass | null> {
    if (ner.error) return null; // can't redact names: classify from heuristics only, send nothing
    const c = resolveCandidate(this.cfg.classifierModel, this.cfg);
    const provider = c && this.registry.get(c.provider);
    if (!c || !provider || !(await this.registry.available(c.account)) || !this.usage.usable(c.account)) return null;
    const last = [...messages].reverse().find((m) => m.role === "user")?.content ?? "";
    // Classifier sees only a paranoid-redacted excerpt under a throwaway vault, with every rule the main guard has
    // (plugin patterns, this machine's user and host names). Redacted whole, then cut: a cut first could split a key.
    const excerpt = new Vault().obfuscate(last, { level: "paranoid", terms: this.cfg.guard.terms, patterns: this.cfg.guard.patterns, identities: machineTerms(), extra: ner.byText.get(last) ?? [] }).text.slice(0, 2000);
    let out = "";
    try {
      const msgs: Message[] = [{ role: "system", content: CLASSIFY_PROMPT }, { role: "user", content: excerpt }];
      this.recordEgress(null, "classifier", c, msgs, undefined, "paranoid excerpt of your message");
      for await (const ev of provider.run({ model: c.model, account: c.account, mode: "chat", messages: msgs }, signal)) {
        if (ev.type === "text") out += ev.delta;
        if (ev.type === "quota") this.usage.recordQuota(c.account.id, ev.quota);
      }
    } catch {
      return null;
    }
    return parseClassifierReply(out);
  }
}

/** Prefer two different providers for a head-to-head. */
function pickPair(ordered: Candidate[]): [Candidate, Candidate] {
  const a = ordered[0]!;
  const b = ordered.find((c) => c.provider !== a.provider) ?? ordered[1]!;
  return Math.random() < 0.5 ? [a, b] : [b, a];
}
