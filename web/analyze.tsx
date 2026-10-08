import { useEffect, useState } from "react";
import { HibClient } from "../src/client";
import { Markdown } from "./markdown";

const api = new HibClient();

export const ANALYZABLE = /\.(csv|tsv|json|jsonl|ndjson)$/i;

function ResultView({ result }: { result: unknown }) {
  if (Array.isArray(result) && result.length && result.every((r) => r && typeof r === "object" && !Array.isArray(r))) {
    const cols = [...new Set(result.flatMap((r: any) => Object.keys(r)))];
    return (
      <div className="md">
        <table>
          <thead>
            <tr>{cols.map((c) => <th key={c}>{c}</th>)}</tr>
          </thead>
          <tbody>
            {result.slice(0, 200).map((r: any, i) => (
              <tr key={i}>{cols.map((c) => <td key={c}>{r[c] === null || r[c] === undefined ? "" : typeof r[c] === "object" ? JSON.stringify(r[c]) : String(r[c])}</td>)}</tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  return <pre className="out">{JSON.stringify(result, null, 2)}</pre>;
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
    step("asking for analysis code…", async () => {
      setRun(null);
      setPreview(null);
      setAnswer(null);
      setPlan(await api.post("/hib/analyze/plan", { root, path, question, model, share }));
    });
  const runIt = () => step("running locally…", async () => setRun(await api.post("/hib/analyze/run", { id: plan.id })));
  const fix = () =>
    step("asking for a fix (error message only)…", async () => {
      const f = await api.post("/hib/analyze/fix", { id: plan.id });
      setPlan({ ...plan, ...f });
      setRun(null);
    });
  const showPreview = () =>
    step("", async () => {
      const pv = await api.post("/hib/analyze/explain", { id: plan.id, preview: true });
      setPreview(pv.sent);
      setLeaks(pv.leaks ?? []);
    });
  const explain = () => step("interpreting…", async () => setAnswer((await api.post("/hib/analyze/explain", { id: plan.id })).answer));

  const shareable = (profile?.columns ?? []).filter((c: any) => !c.identifying && c.type === "string" && c.distinct <= 50);

  return (
    <div className="analyze">
      <div className="viewer-head">
        <b>Analyze {path}</b>
        <span style={{ flex: 1 }} />
        <button className="mini" onClick={onClose}>✕</button>
      </div>
      <div className="analyze-body">
        {profile && (
          <div className="note">
            {profile.rows} rows × {profile.columns.length} columns. The model sees column names and types, counts and 3 synthetic rows; never your data.
            {profile.columns.some((c: any) => c.identifying) && <> Identifying, never shared: {profile.columns.filter((c: any) => c.identifying).map((c: any) => c.name).join(", ")}.</>}
          </div>
        )}
        {shareable.length > 0 && (
          <div className="share">
            <span className="muted">Share distinct values of (helps filters like "only Finance"):</span>
            {shareable.map((c: any) => (
              <label key={c.name}>
                <input type="checkbox" checked={share.includes(c.name)} onChange={(e) => setShare((s) => (e.target.checked ? [...s, c.name] : s.filter((x) => x !== c.name)))} /> {c.name} ({c.distinct})
              </label>
            ))}
          </div>
        )}
        <textarea placeholder="What do you want to know? e.g. average salary per department" value={question} onChange={(e) => setQuestion(e.target.value)} />
        <div className="perm-actions" style={{ padding: 0 }}>
          <select value={model} onChange={(e) => setModel(e.target.value)}>
            {models.map((m) => <option key={m}>{m}</option>)}
          </select>
          <button className="primary" disabled={!question.trim() || !!busy} onClick={writeCode}>Write analysis code</button>
        </div>
        {busy && <div className="note">{busy}</div>}
        {error && <div className="note bad">{error}</div>}

        {plan && (
          <>
            <details className="note"><summary>What was sent to {plan.model}</summary><pre className="out">{plan.sent}</pre></details>
            {plan.code ? (
              <>
                <pre className="code-block">{plan.code}</pre>
                {plan.note && <div className="muted">{plan.note}</div>}
                <div className="perm-actions" style={{ padding: 0 }}>
                  <button className="primary" disabled={!!busy} onClick={runIt}>Run locally (sandboxed)</button>
                </div>
              </>
            ) : (
              <div className="note bad">The model didn't return an analyze() function.</div>
            )}
          </>
        )}

        {run && (
          <>
            <div className="muted">ran in {run.ms} ms · {run.sandbox === "macos-sandbox" ? "macOS sandbox: no network, no file access" : "isolated process (no OS sandbox on this platform)"}</div>
            {run.ok ? (
              <>
                <ResultView result={run.result} />
                {!preview && !answer && <button onClick={showPreview}>Interpret with the model…</button>}
              </>
            ) : (
              <>
                <div className="note bad">{run.error}</div>
                <button disabled={!!busy} onClick={fix}>Ask for a fix (sends this error message)</button>
              </>
            )}
          </>
        )}

        {preview && !answer && (
          <div className="perm">
            <div>This exact text goes to {plan.model} (through the guard). The table stays here.</div>
            {leaks.length > 0 && <div className="note warn">⚠ The result contains real values from identifying columns: {leaks.join(", ")}.</div>}
            <pre className="out">{preview}</pre>
            <div className="perm-actions" style={{ padding: 0 }}>
              <button className="primary" disabled={!!busy} onClick={explain}>Send</button>
              <button onClick={() => setPreview(null)}>Don't send</button>
            </div>
          </div>
        )}
        {answer && <div className="msg assistant"><Markdown text={answer} /></div>}
      </div>
    </div>
  );
}
