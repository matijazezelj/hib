import { dirname, resolve } from "node:path";
import type { Engine } from "../engine";
import type { Message } from "../providers/types";
import { runAnalysis, type RunResult } from "./sandbox";
import { loadTables, profile, type Profile, type Table } from "./table";
import { GEO_DOC, GEO_HELPER, geoFile, geoInstalled } from "./geo";
import { Vault } from "../guard/vault";
import { categoryFor } from "./pseudo";
import { tokenNote } from "../guard";
import { readFileSync } from "node:fs";

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
  vault?: Vault; // tokens for identifying values echoed in the result, restored in the interpretation
  pinDir: string; // the folder whose sensitive policy (if any) decides which account may see this analysis
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
function cut(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + `\n… (${s.length - max} more characters not sent)` : s;
}

export class Analyzer {
  private jobs = new Map<string, Job>();

  constructor(private engine: Engine) {}

  /** The system prompt, mentioning the offline geo helper only when it's installed. */
  private system() {
    return geoInstalled(this.engine.cfg.home) ? `${SYSTEM}\n\n${GEO_DOC}` : SYSTEM;
  }

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
    return profile(loadTables([path]), path, share);
  }

  /** Builds the profile locally and asks the model for code. Nothing from the table but the profile is sent. */
  async plan(input: { path: string; paths?: string[]; question: string; model?: string; share?: string[] }) {
    const paths = (input.paths?.length ? input.paths : [input.path]).map((p) => resolve(p));
    const path = paths[0]!;
    const table = loadTables(paths);
    const prof = profile(table, paths.length > 1 ? `${paths.length} files (${paths.map((p) => p.split("/").pop()).join(", ")})` : path, input.share ?? []);
    const prompt = `${profileText(prof)}\n\nQuestion: ${input.question}`;
    // With several files, any one from a sensitive folder pins the whole analysis; two different pins can't both hold.
    const pinned = [...new Map(paths.map((p) => this.engine.workspaces.policyFor(dirname(p))).filter((x) => !!x).map((x) => [x!.policy.account, x!.root])).entries()];
    if (pinned.length > 1) throw new Error(`these files come from sensitive folders pinned to different accounts (${pinned.map(([a]) => a).join(", ")}); analyse them separately`);
    const pinDir = pinned[0]?.[1] ?? dirname(path);
    const r = await this.ask([{ role: "system", content: this.system() }, { role: "user", content: prompt }], input.model, pinDir);
    const { code, note } = extractCode(r.text);
    const id = `an_${crypto.randomUUID().slice(0, 12)}`;
    for (const [k, j] of this.jobs) if (Date.now() - j.created > 3600_000) this.jobs.delete(k);
    this.jobs.set(id, { id, path, question: input.question, model: input.model, table, profile: prof, code, note, usedModel: r.model, pinDir, created: Date.now() });
    return { id, sent: prompt, profile: prof, code, note, model: r.model, raw: code ? undefined : r.text };
  }

  async run(id: string) {
    const j = this.get(id);
    if (!j.code) throw new Error("no code to run");
    const t0 = Date.now();
    // The gazetteer (~1 MB) goes into the sandbox only when the code uses it.
    const home = this.engine.cfg.home;
    const geo = /\bgeo\./.test(j.code) && geoInstalled(home) ? { data: readFileSync(geoFile(home), "utf8"), helper: GEO_HELPER } : undefined;
    j.last = { ...(await runAnalysis(j.code, j.table, 30_000, geo)), ms: Date.now() - t0 };
    j.vault = undefined; // a new result gets a fresh preview
    if (!j.last.ok && /geo is not defined/.test(j.last.error ?? "")) j.last.error += " (run `hib geo setup` to install the offline gazetteer)";
    return j.last;
  }

  /** Asks for corrected code. Only the error message is sent, never data. */
  async fix(id: string) {
    const j = this.get(id);
    if (!j.code || !j.last?.error) throw new Error("nothing to fix");
    // Model-written code can put data in its error (`throw new Error(JSON.stringify(rows))`): identifying values become
    // tokens, and only the start of the message goes.
    j.vault ??= new Vault();
    const error = cut(this.tokenized(j, j.last.error), 1500);
    const prompt = `${profileText(j.profile)}\n\nQuestion: ${j.question}\n\nYour previous code:\n\`\`\`js\n${j.code}\n\`\`\`\nIt failed with: ${error}\nWrite a corrected version.`;
    const r = await this.ask([{ role: "system", content: this.system() }, { role: "user", content: prompt }], j.model ?? j.usedModel, j.pinDir);
    const { code, note } = extractCode(r.text);
    if (code) [j.code, j.note] = [code, note];
    return { id, sent: prompt, code: j.code, note: j.note, model: r.model };
  }

  /**
   * Values from identifying columns that appear in `text`, longest first: the model wrote the code, so its output may
   * echo IPs, user agents or names back. Numbers count too (an employee id), and so do the forms code derives most
   * often (lower case, an email's local part); matching ignores case. They are tokenized before anything is sent.
   */
  private identifyingValues(j: Job, text: string): [string, string][] {
    const hay = text.toLowerCase();
    const pairs = new Map<string, string>();
    for (const c of j.profile.columns.filter((c) => c.identifying))
      for (const r of j.table.rows) {
        const v = r[c.name];
        if (v === null || v === undefined || typeof v === "object") continue;
        const s = String(v);
        const forms = [s, ...(s.includes("@") ? [s.slice(0, s.indexOf("@"))] : [])];
        for (const f of forms) if (f.length >= 3 && hay.includes(JSON.stringify(f).slice(1, -1).toLowerCase())) pairs.set(f, c.name);
      }
    return [...pairs].sort((a, b) => b[0].length - a[0].length);
  }

  /** `text` with every identifying value it contains replaced by a stable token (case-insensitive). */
  private tokenized(j: Job, text: string): string {
    let out = text;
    for (const [value, col] of this.identifyingValues(j, text)) {
      const needle = JSON.stringify(value).slice(1, -1).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      out = out.replace(new RegExp(needle, "gi"), `[${j.vault!.token(categoryFor(col), value)}]`);
    }
    return out;
  }

  /** Exactly what interpretation sends: question, code and result, with identifying values as stable tokens. */
  explainPreview(id: string): string {
    const j = this.get(id);
    if (!j.last?.ok) throw new Error("run the analysis successfully first");
    j.vault ??= new Vault();
    // Tokenized whole, then cut: a cut first could leave a value's prefix behind, untokenized.
    const result = cut(this.tokenized(j, JSON.stringify(j.last.result, null, 1) ?? "null"), 6000);
    return `Question: ${j.question}\n\nAnalysis code:\n\`\`\`js\n${j.code}\n\`\`\`\n\nResult:\n${result}`;
  }

  /** Identifying columns whose values appear in the result (they are sent as tokens, never as values). */
  leaks(id: string): string[] {
    const j = this.get(id);
    return [...new Set(this.identifyingValues(j, JSON.stringify(j.last?.result ?? null)).map(([, col]) => col))];
  }

  /** Sends the question, code and result (not the table) for interpretation. The guard still runs on it. */
  async explain(id: string) {
    const j = this.get(id);
    const content = this.explainPreview(id);
    const r = await this.ask(
      [
        { role: "system", content: `Interpret this analysis result for the user in plain language. Be concise, point out anything notable, and say if the result can't answer the question.\n\n${tokenNote(j.vault!.tag)}` },
        { role: "user", content },
      ],
      j.model ?? j.usedModel,
      j.pinDir,
    );
    return { answer: j.vault!.restore(r.text), model: r.model, sent: content };
  }
}
