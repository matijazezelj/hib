import { dirname, resolve } from "node:path";
import type { Engine } from "../engine";
import type { Message } from "../providers/types";
import { runAnalysis, type RunResult } from "./sandbox";
import { loadTable, profile, type Profile, type Table } from "./table";

/**
 * "Send code, not data": the model sees a profile of the table (names, types, counts, synthetic rows),
 * writes analyze(rows), and that code runs here in a sandbox. Results leave only via explain(), after preview.
 */

const SYSTEM = `You write JavaScript that analyses a table you cannot see.
You get the table's profile: column names, types, null and distinct counts, and a few SYNTHETIC rows that only show the shape (never real values; never hardcode anything from them).
Write exactly one function, \`function analyze(rows) { ... }\`, where rows is an array of objects keyed by column name. Values are numbers, booleans, strings (dates are ISO strings) or null.
Rules: plain synchronous JavaScript (ES2022); no imports, require, fetch, eval, Function, console or I/O; handle nulls; return a JSON-serializable result, preferably an array of flat objects (a table) or a small object of named numbers. Aggregate rather than returning raw rows unless asked; if rows are needed, return at most 50.
Answer with one \`\`\`js code block, then one short sentence describing what the result contains.`;

export interface Job {
  id: string;
  path: string;
  question: string;
  model?: string;
  table: Table;
  profile: Profile;
  code?: string;
  note?: string;
  usedModel?: string;
  last?: RunResult & { ms: number };
  created: number;
}

function extractCode(text: string): { code?: string; note: string } {
  const m = /```(?:js|javascript|ts|typescript)?\s*\n([\s\S]*?)```/i.exec(text);
  const code = m?.[1]?.trim();
  const note = text.replace(m?.[0] ?? "", "").trim().split("\n").filter(Boolean).slice(-1)[0] ?? "";
  return { code: code && /function\s+analyze\s*\(/.test(code) ? code : undefined, note };
}

function profileText(p: Profile): string {
  const cols = p.columns
    .map((c) => `- ${c.name}: ${c.type}, ${c.nulls} null, ${c.distinct} distinct${c.identifying ? ", identifying (values withheld)" : ""}${c.values ? `, values: ${JSON.stringify(c.values)}` : ""}`)
    .join("\n");
  return `Table: ${p.file}, ${p.rows} rows.\nColumns:\n${cols}\nSynthetic sample rows (shape only):\n${JSON.stringify(p.sample, null, 1)}`;
}

/** The result as it would be sent for interpretation: compact JSON, capped. */
export function resultText(result: unknown, max = 6000): string {
  const s = JSON.stringify(result, null, 1) ?? "null";
  return s.length > max ? s.slice(0, max) + `\n… (${s.length - max} more characters not sent)` : s;
}

export class Analyzer {
  private jobs = new Map<string, Job>();

  constructor(private engine: Engine) {}

  private async ask(messages: Message[], model: string | undefined, cwd: string): Promise<{ text: string; model?: string }> {
    let text = "";
    let used: string | undefined;
    let error: string | undefined;
    // solo: the table's profile and results go to the one model chosen, never to an advisor or arena opponent.
    for await (const e of this.engine.chat({ messages, model: model ?? "hib/code", cwd, solo: true }, new AbortController().signal)) {
      if (e.type === "text") text += e.delta;
      if (e.type === "meta") used = e.model;
      if (e.type === "error") error = e.message;
    }
    if (!text && error) throw new Error(error);
    return { text, model: used };
  }

  get(id: string): Job {
    const j = this.jobs.get(id);
    if (!j) throw new Error("unknown or expired analysis");
    return j;
  }

  profileOf(path: string, share: string[] = []): Profile {
    return profile(loadTable(path), path, share);
  }

  /** Builds the profile locally and asks the model for code. Nothing from the table but the profile is sent. */
  async plan(input: { path: string; question: string; model?: string; share?: string[] }) {
    const path = resolve(input.path);
    const table = loadTable(path);
    const prof = profile(table, path, input.share ?? []);
    const prompt = `${profileText(prof)}\n\nQuestion: ${input.question}`;
    const r = await this.ask([{ role: "system", content: SYSTEM }, { role: "user", content: prompt }], input.model, dirname(path));
    const { code, note } = extractCode(r.text);
    const id = `an_${crypto.randomUUID().slice(0, 12)}`;
    for (const [k, j] of this.jobs) if (Date.now() - j.created > 3600_000) this.jobs.delete(k);
    this.jobs.set(id, { id, path, question: input.question, model: input.model, table, profile: prof, code, note, usedModel: r.model, created: Date.now() });
    return { id, sent: prompt, profile: prof, code, note, model: r.model, raw: code ? undefined : r.text };
  }

  async run(id: string) {
    const j = this.get(id);
    if (!j.code) throw new Error("no code to run");
    const t0 = Date.now();
    j.last = { ...(await runAnalysis(j.code, j.table)), ms: Date.now() - t0 };
    return j.last;
  }

  /** Asks for corrected code. Only the error message is sent, never data. */
  async fix(id: string) {
    const j = this.get(id);
    if (!j.code || !j.last?.error) throw new Error("nothing to fix");
    const prompt = `${profileText(j.profile)}\n\nQuestion: ${j.question}\n\nYour previous code:\n\`\`\`js\n${j.code}\n\`\`\`\nIt failed with: ${j.last.error}\nWrite a corrected version.`;
    const r = await this.ask([{ role: "system", content: SYSTEM }, { role: "user", content: prompt }], j.model ?? j.usedModel, dirname(j.path));
    const { code, note } = extractCode(r.text);
    if (code) [j.code, j.note] = [code, note];
    return { id, sent: prompt, code: j.code, note: j.note, model: r.model };
  }

  explainPreview(id: string): string {
    const j = this.get(id);
    if (!j.last?.ok) throw new Error("run the analysis successfully first");
    return `Question: ${j.question}\n\nAnalysis code:\n\`\`\`js\n${j.code}\n\`\`\`\n\nResult:\n${resultText(j.last.result)}`;
  }

  /** Identifying columns whose real values appear in the result: the model wrote the code, so check before sending it back. */
  leaks(id: string): string[] {
    const j = this.get(id);
    const out = JSON.stringify(j.last?.result ?? null);
    return j.profile.columns
      .filter((c) => c.identifying)
      .map((c) => c.name)
      .filter((name) => j.table.rows.some((r) => typeof r[name] === "string" && (r[name] as string).length >= 3 && out.includes(JSON.stringify(r[name]).slice(1, -1))));
  }

  /** Sends the question, code and result (not the table) for interpretation. The guard still runs on it. */
  async explain(id: string) {
    const j = this.get(id);
    const content = this.explainPreview(id);
    const r = await this.ask(
      [
        { role: "system", content: "Interpret this analysis result for the user in plain language. Be concise, point out anything notable, and say if the result can't answer the question." },
        { role: "user", content },
      ],
      j.model ?? j.usedModel,
      dirname(j.path),
    );
    return { answer: r.text, model: r.model, sent: content };
  }
}
