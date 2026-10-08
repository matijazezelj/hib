import { useEffect, useState } from "react";
import { HibClient } from "../src/client";
import { Markdown } from "./markdown";
import { Icon } from "./icons";

const api = new HibClient();

export const ANALYZABLE = /\.(csv|tsv|json|jsonl|ndjson)$/i;

const isRowList = (v: unknown): v is Record<string, unknown>[] => Array.isArray(v) && v.length > 0 && v.every((r) => r && typeof r === "object" && !Array.isArray(r));
const cell = (v: unknown) => (v === null || v === undefined ? "" : typeof v === "number" ? (Number.isInteger(v) ? v.toLocaleString() : v.toLocaleString(undefined, { maximumFractionDigits: 2 })) : typeof v === "object" ? JSON.stringify(v) : String(v));

/** Results: numbers as stat tiles, lists of rows as tables, nested objects as titled sections. */
function ResultView({ result, title }: { result: unknown; title?: string }): any {
  if (isRowList(result)) {
    const cols = [...new Set(result.flatMap((r) => Object.keys(r)))];
    return (
      <div>
        {title && <div className="sub-title">{title} <span className="muted">({result.length})</span></div>}
        <div className="md">
          <table>
            <thead><tr>{cols.map((c) => <th key={c}>{c}</th>)}</tr></thead>
            <tbody>{result.slice(0, 200).map((r, i) => <tr key={i}>{cols.map((c) => <td key={c}>{cell(r[c])}</td>)}</tr>)}</tbody>
          </table>
        </div>
      </div>
    );
  }
  if (result && typeof result === "object" && !Array.isArray(result)) {
    const entries = Object.entries(result as Record<string, unknown>);
    const scalars = entries.filter(([, v]) => v === null || typeof v !== "object");
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {title && <div className="sub-title">{title}</div>}
        {scalars.length > 0 && (
          <div className="result-scalars">
            {scalars.map(([k, v]) => <div key={k} className="stat"><div className="k" title={k}>{k.replace(/_/g, " ")}</div><div className="v">{cell(v)}</div></div>)}
          </div>
        )}
        {entries.filter(([, v]) => v !== null && typeof v === "object").map(([k, v]) => <ResultView key={k} result={v} title={k.replace(/_/g, " ")} />)}
      </div>
    );
  }
  return (
    <div>
      {title && <div className="sub-title">{title}</div>}
      <pre className="code-block">{JSON.stringify(result, null, 2)}</pre>
    </div>
  );
}

function Step({ n, title, state, children, aside }: { n: number; title: string; state: "done" | "active" | "todo"; children?: any; aside?: any }) {
  return (
    <div className={`step ${state}`}>
      <div className="step-num">{state === "done" ? <Icon name="check" size={12} /> : n}</div>
      <div className="step-body">
        <div className="step-title">{title} {aside}</div>
        {children}
      </div>
    </div>
  );
}

/**
 * "Send code, not data": the model sees only the profile, writes code, the code runs locally in a sandbox,
 * and the result is sent for interpretation only if you choose to, after seeing exactly what goes.
 */
export function AnalyzePanel({ root, path, models, onClose }: { root: string; path: string; models: string[]; onClose: () => void }) {
  const [profile, setProfile] = useState<any>(null);
  const [share, setShare] = useState<string[]>([]);
  const [question, setQuestion] = useState("");
  const [model, setModel] = useState(models[0] ?? "hib/code");
  const [plan, setPlan] = useState<any>(null);
  const [run, setRun] = useState<any>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [leaks, setLeaks] = useState<string[]>([]);
  const [answer, setAnswer] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showCode, setShowCode] = useState(true);
  const [editing, setEditing] = useState(true); // step 1 collapses to a summary once code is written

  useEffect(() => {
    api.post("/hib/analyze/profile", { root, path }).then(setProfile).catch((e) => setError(e.message));
  }, [root, path]);

  const step = async (label: string, fn: () => Promise<void>) => {
    setBusy(label);
    setError(null);
    try {
      await fn();
    } catch (e: any) {
      setError(String(e.message ?? e));
    } finally {
      setBusy(null);
    }
  };

  const writeCode = () =>
    step("Writing analysis code…", async () => {
      setRun(null);
      setPreview(null);
      setAnswer(null);
      setPlan(await api.post("/hib/analyze/plan", { root, path, question, model, share }));
      setShowCode(true);
      setEditing(false);
    });
  const runIt = () =>
    step("Running locally…", async () => {
      setRun(await api.post("/hib/analyze/run", { id: plan.id }));
      setShowCode(false);
    });
  const fix = () =>
    step("Asking for a fix (error message only)…", async () => {
      const f = await api.post("/hib/analyze/fix", { id: plan.id });
      setPlan({ ...plan, ...f });
      setRun(null);
      setShowCode(true);
    });
  const showPreview = () =>
    step("", async () => {
      const pv = await api.post("/hib/analyze/explain", { id: plan.id, preview: true });
      setPreview(pv.sent);
      setLeaks(pv.leaks ?? []);
    });
  const explain = () => step("Interpreting…", async () => setAnswer((await api.post("/hib/analyze/explain", { id: plan.id })).answer));

  const canShare = (c: any) => !c.identifying && c.type === "string" && c.distinct <= 50;
  const stage = answer ? 4 : run?.ok ? 3 : plan?.code ? 2 : 1;
  const short = (m?: string) => (m ? m.replace(/@default\//, "/") : "the model");

  return (
    <div className="analyze">
      <div className="viewer-head">
        <Icon name="table" size={15} /> <b>Analyze</b> <span className="muted">{path}</span>
        <span style={{ flex: 1 }} />
        <button className="ghost icon-btn" onClick={onClose} title="Close"><Icon name="x" size={14} /></button>
      </div>
      <div className="analyze-body">
        <div className="guard-detail">
          <div className="flow"><Icon name="shield-check" size={14} /> <b>Your data stays here.</b> The model sees column names, types and counts, writes code, and the code runs on this machine.</div>
        </div>

        <Step n={1} title="Ask a question" state={stage > 1 ? "done" : "active"} aside={profile && <span className="muted">{profile.rows.toLocaleString()} rows × {profile.columns.length} columns</span>}>
          {!editing && plan ? (
            <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
              <div style={{ flex: 1 }}>
                <div>{question}</div>
                <div className="muted">
                  {profile?.columns.filter((c: any) => c.identifying).length ?? 0} hidden · {share.length} shared · {short(model)}
                </div>
              </div>
              <button className="ghost mini" onClick={() => setEditing(true)}>Change</button>
            </div>
          ) : (
            <>
          {profile && (
            <div className="cols">
              {profile.columns.map((c: any) => (
                <div key={c.name} className="col">
                  <span>{c.name}</span>
                  <span className="type">{c.type}</span>
                  {c.identifying ? (
                    <span className="chip guard" title="Looks like it identifies someone: values are never shared"><Icon name="lock" size={11} /> hidden</span>
                  ) : canShare(c) ? (
                    <label title="Let the model see this column's distinct values, e.g. to filter by them">
                      <input type="checkbox" checked={share.includes(c.name)} onChange={(e) => setShare((s) => (e.target.checked ? [...s, c.name] : s.filter((x) => x !== c.name)))} /> share {c.distinct} values
                    </label>
                  ) : (
                    <span className="muted">schema only</span>
                  )}
                </div>
              ))}
            </div>
          )}
          <textarea placeholder="e.g. impossible travel: logins implying more than 900 km/h, with times and places" value={question} onChange={(e) => setQuestion(e.target.value)} />
          <div style={{ display: "flex", gap: 6 }}>
            <select value={model} onChange={(e) => setModel(e.target.value)} style={{ flex: 1, minWidth: 0 }}>
              {models.map((m) => <option key={m} value={m}>{short(m)}</option>)}
            </select>
            <button className="primary" disabled={!question.trim() || !!busy} onClick={writeCode}><Icon name="code" size={14} /> Write code</button>
          </div>
            </>
          )}
        </Step>

        {plan && (
          <Step n={2} title="Review the code" state={stage > 2 ? "done" : "active"} aside={<button className="ghost mini" onClick={() => setShowCode((s) => !s)}>{showCode ? "hide" : "show"}</button>}>
            {plan.code ? (
              <>
                {showCode && <pre className="code-block">{plan.code}</pre>}
                {plan.note && <div className="muted">{plan.note}</div>}
                <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <button className="primary" disabled={!!busy} onClick={runIt}><Icon name="play" size={13} /> Run locally</button>
                  <span className="muted">sandboxed: no network, no file access</span>
                </div>
                <details><summary style={{ padding: 0 }}>What was sent to {short(plan.model)}</summary><pre className="sent-text">{plan.sent}</pre></details>
              </>
            ) : (
              <div className="err">The model didn't return an analyze() function. Try rephrasing the question.</div>
            )}
          </Step>
        )}

        {run && (
          <Step n={3} title="Result" state={run.ok && stage > 3 ? "done" : "active"} aside={<span className="muted">{run.ms} ms · {run.sandbox === "macos-sandbox" ? "macOS sandbox" : "isolated process"}</span>}>
            {run.ok ? (
              <>
                <ResultView result={run.result} />
                {!preview && !answer && (
                  <div><button disabled={!!busy} onClick={showPreview}><Icon name="sparkles" size={13} /> Interpret with the model…</button></div>
                )}
              </>
            ) : (
              <>
                <div className="err">{run.error}</div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}><button disabled={!!busy} onClick={fix}><Icon name="wand" size={13} /> Ask for a fix</button> <span className="muted">sends this error message</span></div>
              </>
            )}
          </Step>
        )}

        {preview && (
          <Step n={4} title="Interpretation" state={answer ? "done" : "active"}>
            {!answer && (
              <div className="approval" style={{ marginBottom: 0 }}>
                <div className="muted">This exact text goes to {short(plan.model)} through the guard. The table stays here.</div>
                {leaks.length > 0 && (
                  <div><span className="chip guard"><Icon name="shield-check" size={11} /> {leaks.join(", ")} sent as placeholders, restored in the answer</span></div>
                )}
                <pre className="sent-text">{preview}</pre>
                <div style={{ display: "flex", gap: 6 }}>
                  <button className="primary" disabled={!!busy} onClick={explain}><Icon name="send" size={13} /> Send</button>
                  <button onClick={() => setPreview(null)}>Don't send</button>
                </div>
              </div>
            )}
            {answer && <div className="md"><Markdown text={answer} /></div>}
          </Step>
        )}

        {busy && <div className="note">{busy}</div>}
        {error && <div className="err">{error}</div>}
      </div>
    </div>
  );
}
