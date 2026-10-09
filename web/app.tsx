import { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { HibClient } from "../src/client";
import type { HibEvent } from "../src/engine";
import { WorkspaceApp } from "./workspace";
import { Markdown } from "./markdown";
import { Icon } from "./icons";

const api = new HibClient();

interface Turn {
  role: "user" | "assistant";
  content: string;
  revision?: string;
  model?: string;
  cls?: string;
  why?: string;
  runId?: string;
  guard?: { findings: Record<string, number>; action: string; reasons: string[] };
  advisor?: { model: string; verdict: string; critique: string };
  notes: string[];
  error?: string;
  arena?: Extract<HibEvent, { type: "arena" }> & { picked?: "a" | "b" };
  rated?: number;
  waiting?: boolean;
  approval?: boolean;
}

export const fmtTime = (ts: number) => new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

export function ago(ts: number): string {
  const s = (Date.now() - ts) / 1000;
  if (s < 60) return "now";
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return new Date(ts).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export function until(ts: number): string {
  const s = (ts - Date.now()) / 1000;
  if (s <= 60) return "soon";
  if (s < 3600) return `in ${Math.round(s / 60)}m`;
  if (s < 86400) return `in ${Math.round(s / 3600)}h`;
  return new Date(ts).toLocaleDateString(undefined, { weekday: "short", hour: "2-digit", minute: "2-digit" });
}

function dayLabel(ts: number): string {
  const d = new Date(ts), now = new Date();
  const days = Math.floor((new Date(now.toDateString()).getTime() - new Date(d.toDateString()).getTime()) / 86400000);
  return days === 0 ? "Today" : days === 1 ? "Yesterday" : days < 7 ? "This week" : "Earlier";
}

const shortModel = (m?: string) => (m ? m.replace(/@default\//, "/") : "");
const findingCount = (f?: Record<string, number>) => Object.values(f ?? {}).reduce((a, b) => a + b, 0);

const SUGGESTIONS = [
  { title: "Explain a concept", text: "Explain how TLS certificate pinning works and when it's worth it." },
  { title: "Review a snippet", text: "Review this function for bugs and edge cases:\n\n```ts\n\n```" },
  { title: "Draft a message", text: "Draft a short, friendly note to the team about tomorrow's deploy window." },
  { title: "Compare options", text: "Compare Postgres and SQLite for a small internal tool. Short table." },
];

function App() {
  const [info, setInfo] = useState<any>(null);
  const [loggedOut, setLoggedOut] = useState(false);
  useEffect(() => {
    // A link from hib carries a one-time login code; trade it for the cookie and drop it from the address bar.
    const url = new URL(location.href);
    const code = url.searchParams.get("login") ?? "";
    url.searchParams.delete("login");
    history.replaceState(null, "", url);
    fetch(`/hib/session?code=${encodeURIComponent(code)}`).then(async (r) => (r.ok ? setInfo(await api.get("/hib/info")) : setLoggedOut(true)));
  }, []);
  // /?ws=<folder> is a workspace; / lists workspaces; /?router is the multi-model chat.
  const params = new URLSearchParams(location.search);
  if (loggedOut)
    return (
      <div className="home">
        <h1>hib</h1>
        <p>This browser isn't logged in. Run <code>hib serve</code> (or <code>/web</code> in the terminal agent) and open the link it prints. Each link logs in once.</p>
      </div>
    );
  if (!info) return null;
  if (params.get("ws")) return <WorkspaceApp info={info} root={params.get("ws")!} />;
  if (!params.has("router") && info.workspaces?.length) return <Home info={info} />;
  return <Chat info={info} />;
}

// ---------- guard visibility ----------

/** "4 redacted" chip that opens: where the message went, what was replaced, and the exact text sent. */
function GuardChip({ turn }: { turn: Turn }) {
  const [open, setOpen] = useState(false);
  const [sent, setSent] = useState<string | null>(null);
  const n = findingCount(turn.guard?.findings);
  if (!turn.guard) return null;
  const tone = turn.guard.action === "ask" ? "warn" : "guard";
  const label = n ? `${n} redacted` : "nothing to redact";
  async function showSent() {
    if (!turn.runId) return;
    const rows = await api.get(`/hib/egress?run=${turn.runId}&limit=1`).catch(() => []);
    const full = rows[0] ? await api.get(`/hib/egress/${rows[0].id}`) : null;
    setSent(full?.text ?? "(not recorded)");
  }
  return (
    <>
      <button className={`chip ${tone}`} onClick={() => setOpen((o) => !o)} title="What left this machine">
        <Icon name="shield-check" size={12} /> {label} <Icon name={open ? "chevron-down" : "chevron-right"} size={11} />
      </button>
      {open && (
        <div className="guard-detail" style={{ flexBasis: "100%" }}>
          <div className="flow">
            <Icon name="lock" size={13} /> your message <Icon name="chevron-right" size={12} /> <b>guard</b> <Icon name="chevron-right" size={12} />
            <b>{shortModel(turn.model) || "model"}</b>
          </div>
          {n > 0 ? (
            <div className="row">
              <span className="muted">Replaced with placeholders before sending:</span>
              {Object.entries(turn.guard.findings).map(([k, v]) => (
                <span key={k} className="chip guard mono">{k} ×{v}</span>
              ))}
            </div>
          ) : (
            <div className="muted">The guard found nothing to replace in this message.</div>
          )}
          {turn.guard.reasons.length > 0 && <div className="muted">Held for approval: {turn.guard.reasons.join("; ")}</div>}
          <div className="row">
            {sent === null ? (
              <button className="mini" onClick={showSent} disabled={!turn.runId}><Icon name="eye" size={12} /> View exact text sent</button>
            ) : (
              <pre className="sent-text">{sent}</pre>
            )}
          </div>
        </div>
      )}
    </>
  );
}

// ---------- chat ----------

function Chat({ info }: { info: any }) {
  const [convs, setConvs] = useState<any[]>([]);
  const [convId, setConvId] = useState<string | undefined>();
  const [title, setTitle] = useState<string>("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [model, setModel] = useState("hib/auto");
  const [arena, setArena] = useState(false);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState("");
  const [approvals, setApprovals] = useState<any[]>([]);
  const [usage, setUsage] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const abort = useRef<AbortController | null>(null);
  const threadRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    refreshSide();
    const t = setInterval(async () => setApprovals(await api.get("/hib/approvals").catch(() => [])), 1000);
    const u = setInterval(refreshSide, 10_000);
    return () => (clearInterval(t), clearInterval(u));
  }, []);
  useEffect(() => {
    threadRef.current?.scrollTo({ top: threadRef.current.scrollHeight });
  }, [turns]);
  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(260, el.scrollHeight)}px`;
  }, [draft]);

  async function refreshSide() {
    setConvs(await api.get("/hib/conversations").catch(() => []));
    setUsage(await api.get("/hib/usage").catch(() => []));
    setStats(await api.get("/hib/stats").catch(() => null));
  }

  async function openConv(id: string) {
    const c = await api.get(`/hib/conversations/${id}`);
    setConvId(id);
    setTitle(c.title);
    setTurns(c.messages.map((m: any) => ({ role: m.role, content: m.content, model: m.model ?? undefined, runId: m.run_id ?? undefined, notes: [] })));
  }

  function newConv() {
    abort.current?.abort();
    setConvId(undefined);
    setTitle("");
    setTurns([]);
    inputRef.current?.focus();
  }

  async function send(text = draft) {
    const prompt = text.trim();
    if (!prompt || busy) return;
    setDraft("");
    setBusy(true);
    if (!convId) setTitle(prompt.replace(/\s+/g, " ").slice(0, 80));
    const ac = new AbortController();
    abort.current = ac;
    setTurns((t) => [...t, { role: "user", content: prompt, notes: [] }, { role: "assistant", content: "", notes: [], waiting: true }]);
    const patch = (fn: (t: Turn) => Turn) => setTurns((ts) => [...ts.slice(0, -1), fn(ts[ts.length - 1]!)]);
    try {
      for await (const e of api.chat({ conversationId: convId, messages: [{ role: "user", content: prompt }], model, arena }, ac.signal)) {
        switch (e.type) {
          case "conversation":
            setConvId(e.id);
            break;
          case "meta":
            patch((t) => ({ ...t, model: e.model, cls: e.cls, why: e.why, runId: e.runId, notes: e.skipped.length ? [...t.notes, `skipped ${e.skipped.map((s) => `${shortModel(s.id)} (${s.why})`).join(", ")}`] : t.notes }));
            break;
          case "guard":
            patch((t) => ({ ...t, guard: e }));
            break;
          case "approval":
            patch((t) => ({ ...t, approval: true }));
            break;
          case "approved":
            patch((t) => ({ ...t, approval: false, notes: [...t.notes, e.edited ? "sent with your edits" : "approved by you"] }));
            break;
          case "text":
            patch((t) => (e.part === "revision" ? { ...t, revision: (t.revision ?? "") + e.delta, waiting: false } : { ...t, content: t.content + e.delta, waiting: false }));
            break;
          case "tool":
            patch((t) => ({ ...t, notes: [...t.notes, `${e.name}${e.detail ? ` ${e.detail}` : ""}`] }));
            break;
          case "failover":
            patch((t) => ({ ...t, content: "", notes: [...t.notes, `${shortModel(e.from)} failed (${e.why})${e.to ? `, switched to ${shortModel(e.to)}` : ""}`] }));
            break;
          case "advisor":
            patch((t) => ({ ...t, advisor: e }));
            break;
          case "arena":
            patch((t) => ({ ...t, arena: e, waiting: false }));
            break;
          case "done":
            patch((t) => ({ ...t, runId: e.runId, waiting: false, approval: false }));
            break;
          case "error":
            patch((t) => ({ ...t, error: e.message, waiting: false, approval: false }));
            break;
        }
      }
    } catch (err: any) {
      if (!ac.signal.aborted) patch((t) => ({ ...t, error: String(err.message ?? err), waiting: false }));
    } finally {
      setBusy(false);
      setArena(false);
      refreshSide();
    }
  }

  async function rate(i: number, value: number) {
    const t = turns[i]!;
    if (!t.runId) return;
    await api.post("/hib/feedback", { runId: t.runId, value });
    setTurns((ts) => ts.map((x, j) => (j === i ? { ...x, rated: value } : x)));
  }

  async function pick(i: number, winner: "a" | "b") {
    const t = turns[i]!;
    if (!t.arena) return;
    await api.post(`/hib/arena/${t.arena.id}`, { winner });
    const w = t.arena[winner];
    setTurns((ts) => ts.map((x, j) => (j === i ? { ...x, content: w.text, model: w.model, runId: w.runId, arena: { ...t.arena!, picked: winner } } : x)));
  }

  const grouped = useMemo(() => {
    const out: [string, any[]][] = [];
    for (const c of convs.filter((c) => !query || c.title.toLowerCase().includes(query.toLowerCase()))) {
      const d = dayLabel(c.updated);
      const last = out[out.length - 1];
      if (last && last[0] === d) last[1].push(c);
      else out.push([d, [c]]);
    }
    return out;
  }, [convs, query]);

  const routes = (info.models as string[]).filter((m) => m.startsWith("hib/"));
  const models = (info.models as string[]).filter((m) => !m.startsWith("hib/"));

  return (
    <div className="chat">
      <aside className="chat-side">
        <div className="brand">
          <span className="brand-mark"><Icon name="shield" size={13} /></span> hib
          {info.workspaces?.length > 0 && <a href="/">Workspaces</a>}
        </div>
        <div className="side-actions">
          <button className="primary" onClick={newConv}><Icon name="plus" size={14} /> New chat</button>
          <div className="search">
            <Icon name="search" size={14} />
            <input placeholder="Search chats" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
        </div>
        <div className="conv-list">
          {grouped.length === 0 && <div className="empty" style={{ padding: "6px 9px" }}>No conversations yet.</div>}
          {grouped.map(([day, list]) => (
            <div key={day}>
              <div className="day">{day}</div>
              {list.map((c) => (
                <div key={c.id} className={`conv ${c.id === convId ? "active" : ""}`} onClick={() => openConv(c.id)} title={c.title}>
                  <div className="conv-title">{c.title}</div>
                  <small><span>{ago(c.updated)}</span>{c.last_model && <span>· {shortModel(c.last_model)}</span>}</small>
                </div>
              ))}
            </div>
          ))}
        </div>
      </aside>

      <main className="chat-main">
        <div className="chat-head">
          <span className="title">{title || "New chat"}</span>
          {busy && <span className="chip accent"><span className="thinking" style={{ padding: 0 }}><i /><i /><i /></span> working</span>}
          <span style={{ flex: 1 }} />
          {info?.skills?.length > 0 && <span className="chip" title={info.skills.map((s: any) => `/${s.name} — ${s.description ?? ""}`).join("\n")}><Icon name="wand" size={12} /> {info.skills.length} skills</span>}
        </div>

        <div className="thread" ref={threadRef}>
          {turns.length === 0 ? (
            <div className="empty-state">
              <div className="brand-mark"><Icon name="shield" size={22} /></div>
              <h1>What can I help with?</h1>
              <p>Names, keys, IPs and other sensitive values are swapped for placeholders on this machine before anything is sent, and restored in the answer.</p>
              <div className="suggestions">
                {SUGGESTIONS.map((s) => (
                  <div key={s.title} className="suggestion" onClick={() => (setDraft(s.text), inputRef.current?.focus())}>
                    <b>{s.title}</b>
                    {s.text.split("\n")[0]}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="thread-inner">
              {turns.map((t, i) =>
                t.role === "user" ? (
                  <div key={i} className="turn-user">{t.content}</div>
                ) : t.arena ? (
                  <div key={i} className="turn-ai">
                    <div className="turn-meta"><span className="chip accent"><Icon name="swords" size={12} /> arena: pick the better answer</span></div>
                    <div className="arena">
                      {(["a", "b"] as const).map((k) => (
                        <div key={k} className={`card ${t.arena!.picked === k ? "winner" : ""}`}>
                          <div className="turn-meta">
                            <span className="chip mono">{shortModel(t.arena![k].model)}</span>
                            <span className="spacer" />
                            {t.arena!.picked ? (t.arena!.picked === k ? <span className="chip ok"><Icon name="check" size={12} /> picked</span> : null) : <button className="mini" onClick={() => pick(i, k)}>This one</button>}
                          </div>
                          <Markdown text={t.arena![k].text} />
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div key={i} className="turn-ai">
                    <div className="turn-meta">
                      {t.cls && <span className="chip accent" title={t.why}><Icon name="route" size={12} /> {t.cls}</span>}
                      {t.model && <span className="chip mono">{shortModel(t.model)}</span>}
                      <GuardChip turn={t} />
                      {t.advisor && <span className={`chip ${t.advisor.verdict === "ok" ? "ok" : "warn"}`}><Icon name={t.advisor.verdict === "ok" ? "check" : "alert"} size={12} /> review by {shortModel(t.advisor.model)}: {t.advisor.verdict === "ok" ? "looks good" : "issues found"}</span>}
                      <span className="spacer" />
                      {t.runId && !t.waiting && (
                        <>
                          <button className={`ghost icon-btn ${t.rated === 1 ? "ok" : ""}`} onClick={() => rate(i, 1)} disabled={t.rated !== undefined} title="Good answer (teaches routing)"><Icon name="thumbs-up" size={14} /></button>
                          <button className={`ghost icon-btn ${t.rated === -1 ? "bad" : ""}`} onClick={() => rate(i, -1)} disabled={t.rated !== undefined} title="Bad answer (teaches routing)"><Icon name="thumbs-down" size={14} /></button>
                        </>
                      )}
                    </div>
                    {t.notes.map((n, j) => <div key={j} className="muted">{n}</div>)}
                    {t.approval && <div className="note warn">Waiting for your approval in the panel on the right…</div>}
                    {t.waiting && !t.content ? <span className="thinking"><i /><i /><i /></span> : <Markdown text={t.content} />}
                    {t.advisor && t.advisor.verdict === "issues" && (
                      <details><summary>What the reviewer found</summary><div className="md" style={{ padding: "0 12px" }}><Markdown text={t.advisor.critique} /></div></details>
                    )}
                    {t.revision && (
                      <div className="revised">
                        <div className="turn-meta" style={{ marginBottom: 6 }}><span className="chip ok"><Icon name="check" size={12} /> revised after review</span></div>
                        <Markdown text={t.revision} />
                      </div>
                    )}
                    {t.error && <div className="err">{t.error}</div>}
                  </div>
                ),
              )}
            </div>
          )}
        </div>

        <div className="composer-wrap">
          <div className="composer">
            <textarea
              ref={inputRef}
              value={draft}
              rows={1}
              placeholder={convId ? "Reply…" : "Ask anything…"}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  send();
                }
              }}
            />
            <div className="composer-bar">
              <select value={model} onChange={(e) => setModel(e.target.value)} title="Routing: hib/* picks a model for you; or choose one">
                <optgroup label="Automatic">
                  {routes.map((m) => <option key={m} value={m}>{m === "hib/auto" ? "Auto" : m.replace("hib/", "").replace("agent/", "agent: ")}</option>)}
                </optgroup>
                <optgroup label="Models">
                  {models.map((m) => <option key={m} value={m}>{shortModel(m)}</option>)}
                </optgroup>
              </select>
              <button className={`chip ${arena ? "accent" : ""}`} onClick={() => setArena((a) => !a)} title="Run the next message on two models and pick the better answer">
                <Icon name="swords" size={12} /> Arena{arena ? " on" : ""}
              </button>
              <span className="spacer" />
              {busy ? (
                <button className="send" onClick={() => abort.current?.abort()} title="Stop"><Icon name="stop" size={14} /></button>
              ) : (
                <button className="primary send" onClick={() => send()} disabled={!draft.trim()} title="Send (Enter)"><Icon name="arrow-up" size={16} /></button>
              )}
            </div>
          </div>
          <div className="composer-hint">
            <span><Icon name="shield-check" size={11} /> redacted locally before sending</span>
            <span><span className="kbd">Enter</span> send · <span className="kbd">Shift</span>+<span className="kbd">Enter</span> newline</span>
          </div>
        </div>
      </main>

      <aside className="chat-right">
        {approvals.length > 0 && (
          <>
            <div className="section-title"><Icon name="alert" size={12} /> Needs your approval</div>
            {approvals.map((a) => <ApprovalCard key={a.id} a={a} />)}
          </>
        )}
        <UsagePanel usage={usage} />
        <ScoresPanel scores={stats?.scores ?? []} />
        <AuditPanel audit={stats?.audit ?? []} />
        {info?.pluginWarnings?.length > 0 && (
          <>
            <div className="section-title">Plugins</div>
            {info.pluginWarnings.map((w: string, i: number) => <div key={i} className="note warn">{w}</div>)}
          </>
        )}
      </aside>
    </div>
  );
}

export function UsagePanel({ usage }: { usage: any[] }) {
  return (
    <>
      <div className="section-title"><Icon name="gauge" size={12} /> Usage</div>
      {usage.map((u) => (
        <div key={u.account} className="usage-card">
          <div className="head">
            {u.account}
            {u.cooldownUntil && <span className="chip bad">resting until {new Date(u.cooldownUntil).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}</span>}
          </div>
          {u.windows.length === 0 && <div className="muted" style={{ marginTop: 4 }}>No data yet</div>}
          {u.windows.map((w: any) => {
            const pct = Math.round(w.usedPct * 100);
            return (
              <div key={w.window + w.source} className="win">
                <div className="win-top">
                  <span><b>{pct}%</b> of {w.window} {w.source === "meter" ? "(estimated)" : ""}</span>
                  {w.resetsAt && <span>resets {until(w.resetsAt * 1000)}</span>}
                </div>
                <div className="meter"><div className={pct >= 90 ? "hot" : pct >= 70 ? "warm" : ""} style={{ width: `${Math.max(2, Math.min(100, pct))}%` }} /></div>
              </div>
            );
          })}
        </div>
      ))}
    </>
  );
}

function ScoresPanel({ scores }: { scores: any[] }) {
  const byClass = new Map<string, any[]>();
  for (const s of scores) byClass.set(s.class, [...(byClass.get(s.class) ?? []), s]);
  return (
    <>
      <div className="section-title" title="Learned from your ratings, retries, reviews and errors"><Icon name="chart" size={12} /> What works where</div>
      {scores.length === 0 && <div className="empty">Rate answers with 👍 / 👎 to teach routing.</div>}
      {[...byClass].map(([cls, list]) => (
        <div key={cls} className="score-group">
          <div className="cls">{cls}</div>
          {list.slice(0, 4).map((s) => (
            <div key={s.model} className="score-row">
              <span className="name">{shortModel(s.model)}</span>
              <div className="meter"><div style={{ width: `${Math.round(s.mean * 100)}%` }} /></div>
              <span className="val">{Math.round(s.mean * 100)}</span>
            </div>
          ))}
        </div>
      ))}
    </>
  );
}

function AuditPanel({ audit }: { audit: any[] }) {
  return (
    <>
      <div className="section-title"><Icon name="shield-check" size={12} /> Guard log</div>
      {audit.length === 0 && <div className="empty">Nothing sent yet.</div>}
      {audit.slice(0, 14).map((a: any, i: number) => {
        const f = Object.entries(JSON.parse(a.findings || "{}") as Record<string, number>);
        return (
          <div key={i} className="audit-row" title={a.reasons}>
            <span className="when">{ago(a.ts)}</span>
            <div className="what">
              <span className={`chip ${a.action === "redacted" ? "guard" : a.action === "rejected" ? "bad" : "warn"}`}>{a.action}</span>
              {f.length === 0 && <span className="muted">clean</span>}
              {f.slice(0, 4).map(([k, v]) => <span key={k} className="chip mono">{k} ×{v}</span>)}
              {f.length > 4 && <span className="muted">+{f.length - 4}</span>}
            </div>
          </div>
        );
      })}
    </>
  );
}

function Home({ info }: { info: any }) {
  return (
    <div className="home">
      <h1><span className="brand-mark"><Icon name="shield" size={13} /></span> hib</h1>
      <p>Your workspaces and chat. Everything sensitive is redacted on this machine before it reaches a model.</p>
      <div className="section-title">Workspaces</div>
      <div className="ws-cards">
        {info.workspaces.map((w: string) => (
          <a key={w} className="ws-card" href={`/?ws=${encodeURIComponent(w)}`}>
            <Icon name="folder" size={18} />
            <div className="grow">
              <div>{w.split("/").slice(-2).join("/")}</div>
              <small>{w}</small>
            </div>
            {info.policies?.[w] && <span className="sensitive-pill"><Icon name="lock" size={12} /> sensitive</span>}
            <Icon name="chevron-right" size={14} />
          </a>
        ))}
      </div>
      <div className="section-title">Chat</div>
      <div className="ws-cards">
      <a className="ws-card" href="/?router">
        <Icon name="sparkles" size={18} />
        <div className="grow">
          <div>Multi-model chat</div>
          <small>Routed across your Claude and Codex accounts, with arena and reviews</small>
        </div>
        <Icon name="chevron-right" size={14} />
      </a>
      </div>
      <p className="muted" style={{ marginTop: 20 }}>Run <code>hib</code> in a project folder to add it here.</p>
    </div>
  );
}

function ApprovalCard({ a }: { a: any }) {
  const [text, setText] = useState(a.redacted);
  return (
    <div className="approval">
      <div className="turn-meta"><span className="chip warn"><Icon name="alert" size={12} /> held by the guard</span><span className="chip mono">{shortModel(a.model)}</span></div>
      <div className="muted">{a.reasons.join("; ")}</div>
      <div className="muted">This exact text would be sent. Edit it to remove more:</div>
      <textarea value={text} onChange={(e) => setText(e.target.value)} />
      <details><summary style={{ padding: 0 }}>Original (stays here)</summary><div className="orig">{a.original}</div></details>
      <div style={{ display: "flex", gap: 6 }}>
        <button className="primary" onClick={() => api.post(`/hib/approvals/${a.id}`, { approve: true, edited: text !== a.redacted ? text : undefined })}><Icon name="send" size={13} /> Send</button>
        <button onClick={() => api.post(`/hib/approvals/${a.id}`, { approve: false })}>Don't send</button>
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
