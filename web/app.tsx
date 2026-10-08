import { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { HibClient } from "../src/client";
import type { HibEvent } from "../src/engine";
import { WorkspaceApp } from "./workspace";
import { Markdown } from "./markdown";

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
}

const fmtTime = (ts: number) => new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

function App() {
  const [ready, setReady] = useState(false);
  const [info, setInfo] = useState<any>(null);
  const [convs, setConvs] = useState<any[]>([]);
  const [convId, setConvId] = useState<string | undefined>();
  const [turns, setTurns] = useState<Turn[]>([]);
  const [model, setModel] = useState("hib/auto");
  const [mode, setMode] = useState<"chat" | "agent">("chat");
  const [cwd, setCwd] = useState("");
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [usage, setUsage] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const abort = useRef<AbortController | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/hib/session").then(async () => {
      setReady(true);
      setInfo(await api.get("/hib/info"));
      refreshSide();
    });
  }, []);

  useEffect(() => {
    if (!ready) return;
    const t = setInterval(async () => {
      setApprovals(await api.get("/hib/approvals").catch(() => []));
    }, 1000);
    const u = setInterval(refreshSide, 10_000);
    return () => (clearInterval(t), clearInterval(u));
  }, [ready]);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [turns]);

  async function refreshSide() {
    setConvs(await api.get("/hib/conversations").catch(() => []));
    setUsage(await api.get("/hib/usage").catch(() => []));
    setStats(await api.get("/hib/stats").catch(() => null));
  }

  async function openConv(id: string) {
    const c = await api.get(`/hib/conversations/${id}`);
    setConvId(id);
    setTurns(c.messages.map((m: any) => ({ role: m.role, content: m.content, model: m.model ?? undefined, runId: m.run_id ?? undefined, notes: [] })));
  }

  function newConv() {
    abort.current?.abort();
    setConvId(undefined);
    setTurns([]);
  }

  async function send(arena = false) {
    const prompt = draft.trim();
    if (!prompt || busy) return;
    setDraft("");
    setBusy(true);
    const ac = new AbortController();
    abort.current = ac;
    setTurns((t) => [...t, { role: "user", content: prompt, notes: [] }, { role: "assistant", content: "", notes: [], waiting: true }]);
    const patch = (fn: (t: Turn) => Turn) => setTurns((ts) => [...ts.slice(0, -1), fn(ts[ts.length - 1]!)]);
    try {
      for await (const e of api.chat({ conversationId: convId, messages: [{ role: "user", content: prompt }], model, mode, cwd: mode === "agent" ? cwd : undefined, arena }, ac.signal)) {
        switch (e.type) {
          case "conversation":
            setConvId(e.id);
            break;
          case "meta":
            patch((t) => ({ ...t, model: e.model, cls: e.cls, why: e.why, runId: e.runId, notes: e.skipped.length ? [...t.notes, `skipped: ${e.skipped.map((s) => `${s.id} (${s.why})`).join(", ")}`] : t.notes }));
            break;
          case "guard":
            patch((t) => ({ ...t, guard: e }));
            break;
          case "approval":
            patch((t) => ({ ...t, notes: [...t.notes, "waiting for your approval (right panel)…"] }));
            break;
          case "approved":
            patch((t) => ({ ...t, notes: [...t.notes, e.edited ? "approved with edits" : "approved"] }));
            break;
          case "text":
            patch((t) => (e.part === "revision" ? { ...t, revision: (t.revision ?? "") + e.delta, waiting: false } : { ...t, content: t.content + e.delta, waiting: false }));
            break;
          case "tool":
            patch((t) => ({ ...t, notes: [...t.notes, `tool: ${e.name}${e.detail ? ` ${e.detail}` : ""}`] }));
            break;
          case "failover":
            patch((t) => ({ ...t, content: "", notes: [...t.notes, `failover from ${e.from}${e.to ? ` → ${e.to}` : ""}: ${e.why}`] }));
            break;
          case "advisor":
            patch((t) => ({ ...t, advisor: e }));
            break;
          case "arena":
            patch((t) => ({ ...t, arena: e, waiting: false }));
            break;
          case "done":
            patch((t) => ({ ...t, runId: e.runId, waiting: false }));
            break;
          case "error":
            patch((t) => ({ ...t, error: e.message, waiting: false }));
            break;
        }
      }
    } catch (err: any) {
      if (!ac.signal.aborted) patch((t) => ({ ...t, error: String(err.message ?? err), waiting: false }));
    } finally {
      setBusy(false);
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

  // /?ws=<folder> is a workspace; / lists workspaces; /?router is the multi-model chat.
  const params = new URLSearchParams(location.search);
  if (!info) return null;
  if (params.get("ws")) return <WorkspaceApp info={info} root={params.get("ws")!} />;
  if (!params.has("router") && info.workspaces?.length) return <Home info={info} />;

  return (
    <div className="app">
      <aside className="side">
        <button className="primary" onClick={newConv} style={{ width: "100%" }}>New chat</button>
        <h2>Conversations</h2>
        {convs.map((c) => (
          <div key={c.id} className={`conv ${c.id === convId ? "active" : ""}`} onClick={() => openConv(c.id)} title={c.title}>
            {c.title}
            <small>{fmtTime(c.updated)} · {c.last_model ?? "—"}</small>
          </div>
        ))}
      </aside>

      <main className="main">
        <div className="bar">
          <select value={model} onChange={(e) => setModel(e.target.value)} title="Model: hib/* routes automatically; pick one to switch mid-conversation">
            {(info?.models ?? ["hib/auto"]).map((m: string) => <option key={m}>{m}</option>)}
          </select>
          <select value={mode} onChange={(e) => setMode(e.target.value as any)}>
            <option value="chat">chat (no tools)</option>
            <option value="agent">agent (works in a dir)</option>
          </select>
          {mode === "agent" && (
            <input list="agentdirs" placeholder="/path/to/repo (must be in guard.agentDirs)" value={cwd} onChange={(e) => setCwd(e.target.value)} style={{ minWidth: 280 }} />
          )}
          <datalist id="agentdirs">{(info?.agentDirs ?? []).map((d: string) => <option key={d} value={d} />)}</datalist>
          {busy && <button onClick={() => abort.current?.abort()}>Stop</button>}
          {info?.skills?.length > 0 && <span className="chip" title={info.skills.map((s: any) => `/${s.name} — ${s.description ?? ""}`).join("\n")}>{info.skills.length} skills</span>}
        </div>

        <div className="log" ref={logRef}>
          {turns.length === 0 && <div className="msg note">Ask anything. Sensitive values are replaced locally before anything leaves this machine. Type /skill to use a plugin skill.</div>}
          {turns.map((t, i) =>
            t.arena ? (
              <div key={i} className="arena">
                {(["a", "b"] as const).map((k) => (
                  <div key={k} className="msg">
                    <div className="meta">
                      <span className="chip">{t.arena![k].model}</span>
                      {t.arena!.picked ? (t.arena!.picked === k ? <span className="chip ok">winner</span> : null) : <button onClick={() => pick(i, k)}>This one is better</button>}
                    </div>
                    <Markdown text={t.arena![k].text} />
                  </div>
                ))}
              </div>
            ) : (
              <div key={i} className={`msg ${t.role}`}>
                {t.role === "assistant" && (
                  <div className="meta">
                    {t.cls && <span className="chip">{t.cls}</span>}
                    {t.model && <span className="chip" title={t.why}>{t.model}</span>}
                    {t.guard && Object.keys(t.guard.findings).length > 0 && (
                      <span className={`chip ${t.guard.action === "redact" ? "" : "warn"}`} title={t.guard.reasons.join("\n")}>
                        redacted {Object.entries(t.guard.findings).map(([k, v]) => `${k}×${v}`).join(" ")}
                      </span>
                    )}
                    {t.advisor && <span className={`chip ${t.advisor.verdict === "ok" ? "ok" : "warn"}`}>advisor {t.advisor.model}: {t.advisor.verdict}</span>}
                    {t.runId && !t.waiting && (
                      <span className="rate">
                        <button onClick={() => rate(i, 1)} disabled={t.rated !== undefined} title="good answer">{t.rated === 1 ? "▲" : "△"}</button>
                        <button onClick={() => rate(i, -1)} disabled={t.rated !== undefined} title="bad answer">{t.rated === -1 ? "▼" : "▽"}</button>
                      </span>
                    )}
                  </div>
                )}
                {t.notes.map((n, j) => <div key={j} className="note">{n}</div>)}
                {t.waiting && !t.content ? <span className="note">thinking…</span> : t.role === "assistant" ? <Markdown text={t.content} /> : t.content}
                {t.advisor && t.advisor.verdict === "issues" && (
                  <details className="note"><summary>Advisor critique</summary><Markdown text={t.advisor.critique} /></details>
                )}
                {t.revision && <div className="rev"><div className="meta"><span className="chip ok">revised</span></div><Markdown text={t.revision} /></div>}
                {t.error && <div className="note" style={{ color: "var(--bad)" }}>{t.error}</div>}
              </div>
            ),
          )}
        </div>

        <div className="compose">
          <textarea
            value={draft}
            placeholder="Message (Enter to send, Shift+Enter for newline)"
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                send();
              }
            }}
          />
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <button className="primary" onClick={() => send()} disabled={busy}>Send</button>
            <button onClick={() => send(true)} disabled={busy} title="Run two models head-to-head and pick the better answer">Arena</button>
          </div>
        </div>
      </main>

      <aside className="right">
        {approvals.length > 0 && <h2>Needs approval</h2>}
        {approvals.map((a) => <ApprovalCard key={a.id} a={a} />)}
        <h2>Usage</h2>
        {usage.map((u) => (
          <div key={u.account} className="usage-row">
            <b>{u.account}</b> {u.cooldownUntil && <span className="chip bad">cooling down until {fmtTime(u.cooldownUntil)}</span>}
            {u.windows.length === 0 && <div className="note">no data yet</div>}
            {u.windows.map((w: any) => (
              <div key={w.window + w.source}>
                {w.window} {Math.round(w.usedPct * 100)}% <small style={{ color: "var(--muted)" }}>{w.source}{w.resetsAt ? ` · resets ${fmtTime(w.resetsAt * 1000)}` : ""}</small>
                <div className="meter"><div className={w.usedPct >= 0.9 ? "hot" : ""} style={{ width: `${Math.min(100, w.usedPct * 100)}%` }} /></div>
              </div>
            ))}
          </div>
        ))}
        <h2>What works where</h2>
        <table>
          <thead><tr><th>class</th><th>model</th><th>score</th></tr></thead>
          <tbody>
            {(stats?.scores ?? []).map((s: any) => (
              <tr key={s.class + s.model}><td>{s.class}</td><td>{s.model}</td><td>{(s.mean * 100).toFixed(0)}</td></tr>
            ))}
          </tbody>
        </table>
        <h2>Recent guard decisions</h2>
        <table>
          <tbody>
            {(stats?.audit ?? []).slice(0, 15).map((a: any, i: number) => (
              <tr key={i} title={a.reasons}><td>{fmtTime(a.ts)}</td><td>{a.action}</td><td>{Object.entries(JSON.parse(a.findings || "{}")).map(([k, v]) => `${k}×${v}`).join(" ")}</td></tr>
            ))}
          </tbody>
        </table>
        {info?.pluginWarnings?.length > 0 && (
          <>
            <h2>Plugins</h2>
            {info.pluginWarnings.map((w: string, i: number) => <div key={i} className="note">{w}</div>)}
          </>
        )}
      </aside>
    </div>
  );
}

function Home({ info }: { info: any }) {
  return (
    <div style={{ maxWidth: 720, margin: "40px auto", padding: "0 16px" }}>
      <h1 style={{ fontSize: 20 }}>hib</h1>
      <h2 className="muted" style={{ textTransform: "uppercase", fontSize: 12 }}>Workspaces</h2>
      {info.workspaces.map((w: string) => (
        <a key={w} className="conv" style={{ display: "block", color: "inherit", textDecoration: "none" }} href={`/?ws=${encodeURIComponent(w)}`}>
          {w.split("/").slice(-2).join("/")}
          <small>{w}</small>
        </a>
      ))}
      <p className="note">Run <code>hib</code> or <code>hib serve</code> in a project folder to add it here.</p>
      <p>
        <a href="/?router">Multi-model chat →</a>
      </p>
    </div>
  );
}

function ApprovalCard({ a }: { a: any }) {
  const [text, setText] = useState(a.redacted);
  return (
    <div className="approval">
      <div className="meta"><span className="chip warn">{a.model}</span></div>
      <div className="note">{a.reasons.join("; ")}</div>
      <div className="note">This exact text will be sent (edit to remove more):</div>
      <textarea value={text} onChange={(e) => setText(e.target.value)} />
      <details><summary className="note">Original (stays local)</summary><div className="orig">{a.original}</div></details>
      <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
        <button className="primary" onClick={() => api.post(`/hib/approvals/${a.id}`, { approve: true, edited: text !== a.redacted ? text : undefined })}>Send</button>
        <button onClick={() => api.post(`/hib/approvals/${a.id}`, { approve: false })}>Reject</button>
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
