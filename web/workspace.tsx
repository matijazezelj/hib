import { useEffect, useMemo, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { HibClient } from "../src/client";
import { Markdown } from "./markdown";

const api = new HibClient();

type Item =
  | { kind: "user"; text: string; model?: string }
  | { kind: "assistant"; text: string }
  | { kind: "tool"; call: any; result?: { ok: boolean; output?: string }; permission?: { id: string; ruleKey: string; answered?: string } }
  | { kind: "note"; text: string; tone?: "warn" | "bad" | "ok" }
  | { kind: "approval"; id: string; redacted: string; reasons: string[]; original?: string };

/** Events stored server-side (and streamed live) folded into timeline items. */
function fold(items: Item[], e: any): Item[] {
  const last = items[items.length - 1];
  switch (e.type) {
    case "turn_start":
    case "user":
      return [...items, { kind: "user", text: e.text, model: e.model }];
    case "assistant":
      return last?.kind === "assistant" ? items : [...items, { kind: "assistant", text: e.text }];
    case "text":
      return last?.kind === "assistant" ? [...items.slice(0, -1), { ...last, text: last.text + e.delta }] : [...items, { kind: "assistant", text: e.delta }];
    case "tool_call": {
      const i = items.findIndex((x) => x.kind === "tool" && x.call.id === e.call.id);
      if (i >= 0) return items.map((x, j) => (j === i ? { ...(x as any), call: { ...e.call, ...(x as any).call, diff: (x as any).call.diff ?? e.call.diff } } : x));
      return [...items, { kind: "tool", call: e.call }];
    }
    case "tool_result":
      return items.map((x) => (x.kind === "tool" && x.call.id === e.id ? { ...x, result: { ok: e.ok, output: e.output } } : x));
    case "permission": {
      const i = items.findIndex((x) => x.kind === "tool" && x.call.id === e.call.id);
      const perm = { id: e.id, ruleKey: e.ruleKey };
      if (i >= 0) return items.map((x, j) => (j === i ? { ...(x as any), call: { ...(x as any).call, ...e.call }, permission: perm } : x));
      return [...items, { kind: "tool", call: e.call, permission: perm }];
    }
    case "permission_answer":
      return items.map((x) => (x.kind === "tool" && x.permission && x.permission.id === e.id ? { ...x, permission: { ...x.permission, answered: e.choice } } : x));
    case "sent":
      return [...items, { kind: "note", text: `→ sent to ${e.account}${e.handoff ? " (with handoff transcript)" : ""}` }];
    case "handoff":
      return [...items, { kind: "note", text: `handed over from ${e.from} to ${e.to} (new native session, transcript passed along)`, tone: "warn" }];
    case "guard":
      return Object.keys(e.findings).length ? [...items, { kind: "note", text: `guard ${e.action}: ${Object.entries(e.findings).map(([k, v]) => `${k}×${v}`).join(" ")}`, tone: e.action === "redact" ? undefined : "warn" }] : items;
    case "approval":
      return [...items, { kind: "approval", id: e.id, redacted: e.redacted, reasons: e.reasons }];
    case "rate_limited":
      return [...items, { kind: "note", text: `rate limited: ${e.message}`, tone: "bad" }];
    case "error":
      return [...items, { kind: "note", text: e.message, tone: "bad" }];
  }
  return items;
}

const denied = (output?: string) => !!output && /^(declined|denied)$|denied this action/i.test(output.trim());

// ---------- diff rendering ----------

function DiffView({ diff }: { diff: any }) {
  if (!diff) return null;
  let lines: { t: string; c: "add" | "del" | "ctx" | "hdr" }[] = [];
  if (diff.unified) {
    lines = String(diff.unified)
      .split("\n")
      .map((t) => ({ t, c: t.startsWith("+++") || t.startsWith("---") || t.startsWith("@@") || t.startsWith("diff ") ? "hdr" : t.startsWith("+") ? "add" : t.startsWith("-") ? "del" : "ctx" }));
  } else {
    if (diff.before) lines.push(...String(diff.before).split("\n").map((t) => ({ t: `-${t}`, c: "del" as const })));
    if (diff.after !== undefined) lines.push(...String(diff.after).split("\n").map((t) => ({ t: `+${t}`, c: "add" as const })));
  }
  const shown = lines.slice(0, 400);
  return (
    <pre className="diff">
      {shown.map((l, i) => <div key={i} className={l.c}>{l.t || " "}</div>)}
      {lines.length > shown.length && <div className="hdr">… {lines.length - shown.length} more lines</div>}
    </pre>
  );
}

// ---------- file tree ----------

interface Node { name: string; path: string; children?: Map<string, Node> }

function buildTree(paths: string[]): Node {
  const root: Node = { name: "", path: "", children: new Map() };
  for (const p of paths) {
    let n = root;
    const parts = p.split("/");
    parts.forEach((part, i) => {
      const leaf = i === parts.length - 1;
      if (!n.children!.has(part)) n.children!.set(part, { name: part, path: parts.slice(0, i + 1).join("/"), children: leaf ? undefined : new Map() });
      n = n.children!.get(part)!;
    });
  }
  return root;
}

function Tree({ node, depth, open, toggle, onFile, changed, active }: { node: Node; depth: number; open: Set<string>; toggle: (p: string) => void; onFile: (p: string) => void; changed: Map<string, string>; active?: string }) {
  const kids = [...(node.children?.values() ?? [])].sort((a, b) => (!!b.children === !!a.children ? a.name.localeCompare(b.name) : b.children ? 1 : -1));
  return (
    <>
      {kids.map((k) => (
        <div key={k.path}>
          <div className={`tree-row ${active === k.path ? "active" : ""}`} style={{ paddingLeft: 8 + depth * 12 }} onClick={() => (k.children ? toggle(k.path) : onFile(k.path))}>
            <span className="tree-icon">{k.children ? (open.has(k.path) ? "▾" : "▸") : ""}</span>
            <span className={changed.has(k.path) ? "changed" : ""}>{k.name}</span>
            {changed.has(k.path) && <span className="badge">{changed.get(k.path)}</span>}
          </div>
          {k.children && open.has(k.path) && <Tree node={k} depth={depth + 1} open={open} toggle={toggle} onFile={onFile} changed={changed} active={active} />}
        </div>
      ))}
    </>
  );
}

// ---------- terminal ----------

function TerminalPane({ root }: { root: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const term = new Terminal({ fontSize: 13, fontFamily: "ui-monospace, Menlo, monospace", cursorBlink: true, theme: { background: "#141413" } });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(ref.current!);
    fit.fit();
    const sock = new WebSocket(`ws://${location.host}/ws/terminal?root=${encodeURIComponent(root)}`);
    sock.binaryType = "arraybuffer";
    sock.onmessage = (m) => term.write(typeof m.data === "string" ? m.data : new Uint8Array(m.data));
    sock.onopen = () => sock.send(JSON.stringify({ resize: [term.cols, term.rows] }));
    sock.onclose = () => term.write("\r\n[terminal closed]\r\n");
    const d = term.onData((s) => sock.readyState === 1 && sock.send(s));
    const ro = new ResizeObserver(() => {
      fit.fit();
      if (sock.readyState === 1) sock.send(JSON.stringify({ resize: [term.cols, term.rows] }));
    });
    ro.observe(ref.current!);
    return () => {
      ro.disconnect();
      d.dispose();
      sock.close();
      term.dispose();
    };
  }, []);
  return <div className="terminal" ref={ref} />;
}

// ---------- main ----------

export function WorkspaceApp({ info, root }: { info: any; root: string }) {
  const q = `root=${encodeURIComponent(root)}`;
  const [tab, setTab] = useState<"files" | "changes" | "sessions" | "egress">("files");
  const [policy, setPolicy] = useState<{ account: string; model?: string } | null>(null);
  const [egress, setEgress] = useState<any[]>([]);
  const [files, setFiles] = useState<string[]>([]);
  const [gitState, setGit] = useState<any>(null);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [viewer, setViewer] = useState<{ path: string; content?: string; diff?: string; note?: string } | null>(null);
  const [sessions, setSessions] = useState<any[]>([]);
  const [sessionId, setSessionId] = useState<string | undefined>();
  const [items, setItems] = useState<Item[]>([]);
  const [model, setModel] = useState("hib/auto");
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [term, setTerm] = useState(false);
  const [commitMsg, setCommitMsg] = useState("");
  const [approvals, setApprovals] = useState<any[]>([]);
  const follow = useRef<AbortController | null>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const sidRef = useRef<string | undefined>(undefined);

  const agentModels = (info.models as string[]).filter((m) => /^(claude|codex)@/.test(m) && (!policy || m.startsWith(policy.account + "/")));
  const changed = useMemo(() => new Map<string, string>((gitState?.files ?? []).map((f: any) => [f.path, f.untracked ? "U" : (f.worktree.trim() || f.index).trim()])), [gitState]);
  const tree = useMemo(() => buildTree(files), [files]);

  async function refresh() {
    const t = await api.get(`/ws/tree?${q}`).catch(() => null);
    if (t) {
      setFiles(t.files);
      setGit(t.git);
      setPolicy(t.policy);
    }
    if (sidRef.current) setEgress(await api.get(`/ws/egress/${sidRef.current}?${q}`).catch(() => []));
    setSessions(await api.get(`/ws/sessions?${q}`).catch(() => []));
  }
  useEffect(() => {
    refresh();
    const s = new URLSearchParams(location.search).get("s");
    if (s) attach(s);
    const t = setInterval(async () => setApprovals(await api.get("/hib/approvals").catch(() => [])), 1000);
    return () => clearInterval(t);
  }, []);
  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [items]);

  async function openFile(path: string) {
    const f = await api.get(`/ws/file?${q}&path=${encodeURIComponent(path)}`).catch((e) => ({ note: String(e.message) }));
    setViewer({ path, content: f.content, note: f.binary ? "binary file" : f.tooLarge ? `too large (${f.size} bytes)` : f.note });
  }
  async function openDiff(path: string) {
    const d = await api.get(`/ws/git/diff?${q}&path=${encodeURIComponent(path)}`);
    setViewer({ path, diff: d.diff || "(no diff)" });
  }
  function setUrlSession(id?: string) {
    const u = new URL(location.href);
    if (id) u.searchParams.set("s", id);
    else u.searchParams.delete("s");
    history.replaceState(null, "", u);
  }

  /** History, then the live stream; turns started from the CLI show up here as they run. */
  async function attach(id: string, quiet = false) {
    follow.current?.abort();
    const ctl = new AbortController();
    follow.current = ctl;
    sidRef.current = id;
    setSessionId(id);
    setUrlSession(id);
    const snap = await api.get(`/ws/sessions/${id}?${q}`);
    if (!quiet) {
      let it: Item[] = [];
      for (const e of [...snap.events, ...snap.live]) it = fold(it, e);
      setItems(it);
    }
    if (snap.row?.model) setModel(snap.row.model);
    setBusy(snap.running);
    api.get(`/ws/egress/${id}?${q}`).then(setEgress).catch(() => setEgress([]));
    let after = quiet ? 0 : snap.seq;
    (async () => {
      while (!ctl.signal.aborted) {
        try {
          for await (const e of api.stream(`/ws/sessions/${id}/stream?${q}&after=${after}`, ctl.signal)) {
            after = e.seq;
            if (e.type === "turn_start") setBusy(true);
            if (e.type === "turn_end") {
              setBusy(false);
              refresh();
              continue;
            }
            if (e.type === "ws_session") {
              setModel(e.model);
              continue;
            }
            setItems((x) => fold(x, e));
            if (e.type === "tool_result") refresh();
          }
        } catch {
          if (ctl.signal.aborted) return;
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
    })();
  }

  function newSession() {
    follow.current?.abort();
    setSessionId(undefined);
    sidRef.current = undefined;
    setUrlSession();
    setItems([]);
    setBusy(false);
  }

  async function send() {
    const text = draft.trim();
    if (!text || busy) return;
    setDraft("");
    try {
      const r = await api.post(`/ws/turn?${q}`, { sessionId: sidRef.current, model, text });
      if (r.sessionId !== sidRef.current) {
        setItems([]);
        await attach(r.sessionId, true);
      }
    } catch (err: any) {
      setItems((x) => fold(x, { type: "error", message: String(err.message ?? err) }));
    }
  }

  async function answer(id: string, choice: "allow" | "always" | "deny") {
    await api.post(`/ws/permission?${q}`, { sessionId: sidRef.current, id, choice });
  }

  async function discard(path: string) {
    if (!confirm(`Discard all changes to ${path}?`)) return;
    await api.post(`/ws/git/discard?${q}`, { path });
    refresh();
    if (viewer?.path === path) setViewer(null);
  }
  async function commit() {
    try {
      const r = await api.post(`/ws/git/commit?${q}`, { message: commitMsg });
      setCommitMsg("");
      setItems((x) => [...x, { kind: "note", text: `committed: ${r.summary}`, tone: "ok" }]);
    } catch (e: any) {
      alert(e.message);
    }
    refresh();
  }

  const ruleLabel = (k: string) => k.replace(/^(Bash|command):exact:.*/, "this exact command").replace(/^(Bash|command):/, "").replace(/^edit$/, "edits in this folder");

  return (
    <div className={`ws ${viewer ? "with-viewer" : ""} ${term ? "with-term" : ""}`}>
      <header className="ws-head">
        <b>hib</b>
        <a className="muted" href="/" title={root}>{root.split("/").slice(-2).join("/")}</a>
        {gitState?.branch && <span className="chip">{gitState.branch.split("...")[0]}</span>}
        {policy && (
          <span className="chip warn" title="Only this account sees this folder. No handoff, failover, advisor, arena or browser terminal; secrets are blocked; every read asks.">
            sensitive → {policy.account}
          </span>
        )}
        <span style={{ flex: 1 }} />
        <select value={model} onChange={(e) => setModel(e.target.value)} title="Switching model mid-session hands the session over">
          <option value="hib/auto">{policy ? `auto (pinned to ${policy.account})` : "auto (code route)"}</option>
          {agentModels.map((m) => <option key={m}>{m}</option>)}
        </select>
        {!policy && <button onClick={() => setTerm((t) => !t)}>{term ? "Hide terminal" : "Terminal"}</button>}
      </header>

      <aside className="ws-side">
        <div className="tabs">
          {(["files", "changes", "sessions", "egress"] as const).map((t) => (
            <button key={t} className={tab === t ? "on" : ""} onClick={() => setTab(t)}>
              {t}{t === "changes" && changed.size ? ` (${changed.size})` : ""}
            </button>
          ))}
        </div>
        {tab === "files" && (
          <div className="tree">
            <Tree node={tree} depth={0} open={open} toggle={(p) => setOpen((s) => { const n = new Set(s); n.has(p) ? n.delete(p) : n.add(p); return n; })} onFile={openFile} changed={changed} active={viewer?.path} />
          </div>
        )}
        {tab === "changes" && (
          <div className="changes">
            {!gitState && <div className="note">not a git repository</div>}
            {gitState?.files.map((f: any) => (
              <div key={f.path} className="tree-row" onClick={() => openDiff(f.path)}>
                <span className="badge">{f.untracked ? "U" : (f.worktree.trim() || f.index).trim()}</span>
                <span style={{ flex: 1 }}>{f.path}</span>
                <button className="mini" onClick={(e) => (e.stopPropagation(), discard(f.path))} title="Discard changes">↺</button>
              </div>
            ))}
            {gitState && gitState.files.length > 0 && (
              <div className="commit">
                <textarea placeholder="Commit message" value={commitMsg} onChange={(e) => setCommitMsg(e.target.value)} />
                <button className="primary" disabled={!commitMsg.trim()} onClick={commit}>Commit all</button>
              </div>
            )}
            {gitState && gitState.files.length === 0 && <div className="note">working tree clean</div>}
          </div>
        )}
        {tab === "egress" && (
          <div className="egress">
            {!sessionId && <div className="note">Open a session to see what it sent, and where.</div>}
            {sessionId && egress.length === 0 && <div className="note">Nothing sent yet.</div>}
            {egress.map((t, i) => (
              <div key={i} className="egress-turn">
                <div><b>→ {t.account}</b> <span className="muted">{t.model.split("/").pop()}{t.handoff ? " · handoff" : ""}</span></div>
                <div className="muted" title={t.prompt}>{t.prompt.slice(0, 140)}</div>
                {t.guard && <div className="egress-guard">guard: {t.guard}</div>}
                {t.actions.map((a: any, j: number) => (
                  <div key={j} className={`egress-act ${a.status}`}>
                    <span className={`kind ${a.kind}`}>{a.kind}</span> {a.title}
                  </div>
                ))}
              </div>
            ))}
            <div className="note">File contents the agent reads and command output also go to that account.</div>
          </div>
        )}
        {tab === "sessions" && (
          <div>
            <button className="primary" style={{ width: "100%", marginBottom: 8 }} onClick={newSession}>New session</button>
            {sessions.map((s) => (
              <div key={s.id} className={`conv ${s.id === sessionId ? "active" : ""}`} onClick={() => attach(s.id)}>
                {s.running ? "● " : ""}{s.title}
                <small>{new Date(s.updated).toLocaleString()} · {s.model}</small>
              </div>
            ))}
          </div>
        )}
      </aside>

      <main className="ws-main">
        <div className="timeline" ref={logRef}>
          {items.length === 0 && (
            <div className="note">
              Ask the agent to work on this folder. Edits and commands wait for your OK here. Secrets in your prompt are caught by the guard;
              switch model at any time and the session is handed over.
            </div>
          )}
          {approvals.map((a) => (
            <div key={a.id} className="perm">
              <div><b>Guard:</b> {a.reasons.join("; ")}</div>
              <pre className="cmd">{a.redacted}</pre>
              <div className="perm-actions">
                <button className="primary" onClick={() => api.post(`/hib/approvals/${a.id}`, { approve: true })}>Send redacted</button>
                <button onClick={() => api.post(`/hib/approvals/${a.id}`, { approve: false })}>Don't send</button>
              </div>
            </div>
          ))}
          {items.map((it, i) => {
            if (it.kind === "user") return <div key={i} className="msg user">{it.text}</div>;
            if (it.kind === "assistant") return <div key={i} className="msg assistant"><Markdown text={it.text} /></div>;
            if (it.kind === "note") return <div key={i} className={`note ${it.tone ?? ""}`}>{it.text}</div>;
            if (it.kind === "approval") return null;
            const c = it.call;
            const pending = it.permission && !it.permission.answered && !it.result;
            return (
              <div key={i} className={`tool ${pending ? "pending" : ""} ${it.result && !it.result.ok ? "failed" : ""}`}>
                <div className="tool-head" onClick={() => c.path && openFile(c.path)}>
                  <span className={`kind ${c.kind}`}>{c.kind}</span>
                  <span className="tool-title">{c.title}</span>
                  {it.result && <span className={it.result.ok ? "ok" : "bad"}>{it.result.ok ? "✓" : denied(it.result.output) ? "denied" : "✗"}</span>}
                  {it.permission?.answered && !it.result && <span className="muted">{it.permission.answered}</span>}
                </div>
                {c.diff && <DiffView diff={c.diff} />}
                {c.command && c.kind === "command" && pending && <pre className="cmd">{c.command}</pre>}
                {pending && (
                  <div className="perm-actions">
                    <button className="primary" onClick={() => answer(it.permission!.id, "allow")}>Allow</button>
                    <button onClick={() => answer(it.permission!.id, "always")}>Always allow {ruleLabel(it.permission!.ruleKey)}</button>
                    <button onClick={() => answer(it.permission!.id, "deny")}>Deny</button>
                  </div>
                )}
                {it.result?.output && !denied(it.result.output) && c.kind !== "edit" && (
                  <details><summary className="muted">output</summary><pre className="out">{it.result.output}</pre></details>
                )}
              </div>
            );
          })}
          {busy && <div className="note">working…</div>}
        </div>
        <div className="compose">
          <textarea
            value={draft}
            placeholder={sessionId ? "Continue the session (Enter to send)" : "What should the agent do in this folder?"}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                send();
              }
            }}
          />
          {busy ? (
            <button onClick={() => api.post(`/ws/interrupt?${q}`, { sessionId: sidRef.current })}>Stop</button>
          ) : (
            <button className="primary" onClick={send}>Send</button>
          )}
        </div>
      </main>

      {viewer && (
        <section className="ws-viewer">
          <div className="viewer-head">
            <b>{viewer.path}</b>
            <span style={{ flex: 1 }} />
            {changed.has(viewer.path) && !viewer.diff && <button className="mini" onClick={() => openDiff(viewer.path)}>diff</button>}
            {viewer.diff && <button className="mini" onClick={() => openFile(viewer.path)}>file</button>}
            <button className="mini" onClick={() => setViewer(null)}>✕</button>
          </div>
          {viewer.note && <div className="note">{viewer.note}</div>}
          {viewer.diff !== undefined ? (
            <DiffView diff={{ unified: viewer.diff }} />
          ) : (
            <pre className="code">
              {(viewer.content ?? "").split("\n").map((l, i) => (
                <div key={i}><span className="ln">{i + 1}</span>{l || " "}</div>
              ))}
            </pre>
          )}
        </section>
      )}

      {term && !policy && (
        <section className="ws-term">
          <TerminalPane root={root} />
        </section>
      )}
    </div>
  );
}
