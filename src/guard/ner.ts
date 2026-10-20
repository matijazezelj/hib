// Local name/place/organisation detection: a multilingual NER model plus rules for what it misses.
// Runs only on prose (code is skipped), entirely on this machine; findings feed the guard's vault.
import type { Finding } from "./detectors";
import { encodedBlobs, encodedCategory, stringLiterals } from "./encoded";

export const NER_MODEL = "Xenova/bert-base-multilingual-cased-ner-hrl";
export const NER_REVISION = "263e82c06569c8c2ac46238a7ae5107598934234"; // pinned: a model update can't change what's detected
const MAX_PIECE = 1000; // the model reads ~512 tokens; longer prose segments are split at a space or separator
const MAX_RSS_GROWTH = 1024 * 1024 * 1024; // memory budget for one scan
const LABEL: Record<string, string> = { PER: "PERSON", ORG: "ORG", LOC: "PLACE" };

/** Tech names the model tends to call organisations or places; never sensitive on their own. */
const TECH = new Set(
  `redis postgres postgresql kafka mysql mariadb mongodb sqlite docker kubernetes k8s helm terraform ansible react vue svelte angular next nuxt django flask rails laravel spring node nodejs bun deno npm yarn pnpm github gitlab bitbucket jira confluence slack aws gcp azure linux macos windows ubuntu debian python typescript javascript java golang rust ruby php swift kotlin grafana prometheus loki tempo traefik nginx apache caddy envoy istio elastic elasticsearch kibana logstash sentry datadog vercel netlify cloudflare openai anthropic claude codex gemini chatgpt copilot trivy authentik victoriametrics us eu api
   smb sme enterprise public private b2b b2c saas paas iaas ceo cto cfo coo cio ciso vp hr it qa ops devops sre crm erp vpn sla kpi okr roi gdpr iso`.split(/\s+/),
);

const ORG_SUFFIX = /\b[\p{Lu}][\p{L}&'-]*(?:\s+[\p{Lu}][\p{L}&'-]*){0,4}\s+(?:d\.o\.o\.|j\.d\.o\.o\.|d\.d\.|a\.d\.|GmbH|AG|Ltd\.?|LLC|Inc\.?|plc|S\.A\.|S\.r\.l\.|B\.V\.)/gu;
const ADDRESS =
  /\b(?:(?:Ulica|Ul\.|Trg|Cesta|Put|Avenija|Obala|Bulevar)\s+(?:[\p{L}.]+\s+){0,4}\d+[a-z]?|\d+[a-z]?\s+(?:[\p{Lu}][\p{L}]+\s+){1,3}(?:Street|St\.|Road|Rd\.|Avenue|Ave\.|Lane|Boulevard|Blvd\.|Way|Drive|Straße|Strasse|Gasse))\b/gu;

export interface Segment {
  start: number;
  text: string;
}

/** Prose parts of a text: fenced code, inline code and code-looking lines are left out. */
export function proseSegments(text: string): Segment[] {
  const out: Segment[] = [];
  const blocked: [number, number][] = [];
  for (const m of text.matchAll(/```[\s\S]*?(```|$)|`[^`\n]*`/g)) blocked.push([m.index!, m.index! + m[0].length]);
  let pos = 0;
  for (const line of text.split("\n")) {
    const start = pos;
    pos += line.length + 1;
    if (!line.trim()) continue;
    // Judge the line without inline code or hib tokens. Only real code characters count: dots, commas and quotes
    // are everywhere in prose, abbreviations ("d.o.o.") and CSV rows, and must not make a data row look like code.
    const prose = line.replace(/`[^`\n]*`/g, " ").replace(/\[HIB[0-9a-f]{4}-[A-Z0-9-]+-\d+\]/g, " ");
    const codeChars = (prose.match(/[{}()[\];=<>$*\\|&^%~#]/g) ?? []).length / Math.max(1, prose.replace(/\s/g, "").length);
    const codey =
      codeChars > 0.08 ||
      /^\s*(import|export|const|let|var|function|def|class|func|return|SELECT|INSERT|UPDATE|DELETE|FROM|if|for|while)\b/.test(prose) ||
      /[{};]\s*$/.test(prose) ||
      /=>|::|:=|\w\(\w*\)|\w\.\w+\(/.test(prose);
    if (codey) continue;
    // Cut blocked (code) ranges out of the line.
    let s = start;
    const end = start + line.length;
    for (const [bs, be] of blocked.filter(([bs, be]) => bs < end && be > start).sort((a, b) => a[0] - b[0])) {
      if (bs > s) out.push({ start: s, text: text.slice(s, bs) });
      s = Math.max(s, be);
    }
    if (s < end) out.push({ start: s, text: text.slice(s, end) });
  }
  return out.filter((seg) => /\p{L}{2}/u.test(seg.text));
}

/** All-lowercase prose ("can you ask luka novak…"): the cased model needs a title-cased copy to see names. */
export function isLowerProse(text: string): boolean {
  const letters = text.replace(/\[HIB[0-9a-f]{4}-[A-Z0-9-]+-\d+\]/g, " ").replace(/[^\p{L}]/gu, "");
  return letters.length >= 10 && letters.replace(/[^\p{Lu}]/gu, "").length / letters.length < 0.03;
}

/**
 * Lowercase stretches inside a segment, judged per field/clause: a CSV row can carry "SMB" in one column and
 * "met luka novak in pula" in its notes; the notes still need the title-cased pass.
 */
function lowercasePieces(seg: Segment): Segment[] {
  const out: Segment[] = [];
  // Any clause with a few lowercase words: "met luka vuković at the Graz conference" has a capital, and a name.
  for (const m of seg.text.matchAll(/[^",;|\t()]+/g)) if ((m[0].match(/(?<![\p{L}\p{N}])\p{Ll}{2,}/gu) ?? []).length >= 2) out.push({ start: seg.start + m.index!, text: m[0] });
  return out;
}

export interface RawToken {
  entity: string; // B-PER, I-ORG, …
  word: string; // "Ivan", "##vač"
  score: number;
}

/** Joins B-/I- tokens and "##" word pieces into entities. */
export function mergeTokens(tokens: RawToken[]): { text: string; label: string; score: number }[] {
  const out: { pieces: string[]; label: string; scores: number[] }[] = [];
  for (const t of tokens) {
    const label = t.entity.slice(2);
    const last = out[out.length - 1];
    if (t.word.startsWith("##") && last) last.pieces[last.pieces.length - 1] += t.word.slice(2);
    else if (t.entity.startsWith("I-") && last && last.label === label) last.pieces.push(t.word);
    else out.push({ pieces: [t.word], label, scores: [] });
    out[out.length - 1]!.scores.push(t.score);
  }
  return out.map((e) => ({ text: e.pieces.join(" "), label: e.label, score: Math.min(...e.scores) }));
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Finds an entity's text in the segment from `from` on, tolerating spacing/punctuation differences. */
function locate(segment: string, entity: string, from: number, caseless: boolean): [number, number] | null {
  const parts = entity.split(/\s+/).filter(Boolean).map((p) => p.split(/(?=[.,'&-])|(?<=[.,'&-])/).map(esc).join("\\s*"));
  if (!parts.length) return null;
  const re = new RegExp(parts.join("[\\s.,'&-]*"), caseless ? "giu" : "gu");
  re.lastIndex = from;
  const m = re.exec(segment);
  return m ? [m.index, m.index + m[0].length] : null;
}

// Letters NFD doesn't take apart. One output character per input code unit, so offsets in the folded copy stay put.
const FOLD: Record<string, string> = { đ: "d", Đ: "d", ł: "l", Ł: "l", ø: "o", Ø: "o", ħ: "h", Ħ: "h", ı: "i" };

/** Lowercase with diacritics dropped (`Babić` -> `babic`), the same length as `s`. */
export function fold(s: string): string {
  let out = "";
  for (const c of s) {
    const f = FOLD[c] ?? c.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();
    out += f.length === c.length ? f : c.toLowerCase().length === c.length ? c.toLowerCase() : c;
  }
  return out;
}

const nameParts = (s: string) => fold(s).split(/[^\p{L}]+/u).filter(Boolean);
/** How a person's name is keyed in the vault: folded parts, space-joined. Single words have none. */
export function nameKey(value: string): string | undefined {
  const parts = nameParts(value);
  return parts.length >= 2 ? parts.join(" ") : undefined;
}

/**
 * Every written form of the full names found: any case, diacritics folded, the parts joined by a space, `_`, `-`,
 * `.`, `+`, `%20` or nothing (`IvanaBabic`), in prose and code alike. Only names of two or more parts, each at least 3
 * letters: a lone "dover" or "turner" is a word as often as a name.
 */
export function spreadNames(text: string, names: Iterable<string>): Finding[] {
  const keys = new Map<string, string[]>(); // letters only ("ivanababic") -> parts; a match maps back to its key that way
  for (const n of names) {
    const parts = nameParts(n);
    if (parts.length >= 2 && parts.every((p) => p.length >= 3)) keys.set(parts.join(""), parts);
  }
  if (!keys.size) return [];
  const re = new RegExp(
    [...keys.values()].sort((a, b) => b.join("").length - a.join("").length).map((ps) => ps.map(esc).join("(?:\\s+|[_.+-]|%20)?")).join("|"),
    "g",
  );
  const folded = fold(text);
  const isAlnum = (c: string | undefined) => !!c && /[\p{L}\p{N}]/u.test(c);
  const lower = (c: string | undefined) => !!c && /\p{Ll}/u.test(c);
  const upper = (c: string | undefined) => !!c && /\p{Lu}/u.test(c);
  const out: Finding[] = [];
  for (const m of folded.matchAll(re)) {
    const s = m.index!;
    const e = s + m[0].length;
    // Whole words, or a camelCase piece (getIvanaBabic, IvanaBabicRecord).
    const startOk = !isAlnum(text[s - 1]) || (lower(text[s - 1]) && upper(text[s]));
    const endOk = !isAlnum(text[e]) || (lower(text[e - 1]) && upper(text[e]));
    if (!startOk || !endOk) continue;
    const parts = keys.get(m[0].replace(/[^\p{L}]/gu, ""));
    if (parts) out.push({ start: s, end: e, value: text.slice(s, e), category: "PERSON", kind: "pii", key: parts.join(" ") });
  }
  return out;
}

// A file name, URL or path (`_3077649_-_ivana_babic_learner_-_….pdf`): words joined by _ or -, percent escapes, a scheme,
// or several path segments. The model reads such text as one unknown token, so it gets a readable copy.
const RUN = /[^\s"'`<>()[\]{},;|]{6,}/g;
const SLUGGY = /[\p{L}\p{N}](?:[_-]+|%[0-9A-Fa-f]{2}|\+)[\p{L}\p{N}]|:\/\/|\/[^/]*\p{L}{2}[^/]*\/[^/]*\p{L}{2}/u;
const MAX_RUN = MAX_PIECE; // longer runs aren't file names; base64 and the like

/**
 * A readable copy of a slug for the model: separators become spaces, percent escapes are decoded and each word is
 * title-cased. `from[i]`/`to[i]` are the run offsets character i of the copy came from.
 */
export function deslug(run: string): { text: string; from: number[]; to: number[] } {
  let text = "";
  const from: number[] = [];
  const to: number[] = [];
  const put = (s: string, a: number, b: number) => {
    for (const c of s) {
      text += c;
      for (let k = 0; k < c.length; k++) from.push(a), to.push(b);
    }
  };
  for (let i = 0; i < run.length; ) {
    const esc = /^(?:%[0-9A-Fa-f]{2})+/.exec(run.slice(i))?.[0];
    if (esc) {
      let decoded: string | null = null;
      try {
        decoded = decodeURIComponent(esc);
      } catch {}
      if (decoded !== null) {
        put(decoded.replace(/[^\p{L}\p{N}]/gu, " "), i, i + esc.length); // a decoded char maps to its whole escape
        i += esc.length;
        continue;
      }
    }
    const c = run[i]!;
    put(/[\p{L}\p{N}]/u.test(c) ? c : " ", i, i + 1);
    i++;
  }
  return { text: text.replace(/(?<![\p{L}\p{N}])\p{Ll}/gu, (c) => c.toUpperCase()), from, to };
}

/** Slug-like runs in `text`: what deslug() opens up. */
function slugRuns(text: string): { start: number; value: string }[] {
  const out: { start: number; value: string }[] = [];
  for (const m of text.matchAll(RUN)) {
    if (m[0].length > MAX_RUN || /HIB[0-9a-f]{4}-/.test(m[0]) || !SLUGGY.test(m[0])) continue;
    // Two words to hold a full name, not counting a file extension ("attachment-1.csv" is one).
    if ((m[0].replace(/\.[A-Za-z0-9]{1,5}$/, "").match(/\p{L}{3,}/gu) ?? []).length < 2) continue;
    out.push({ start: m.index!, value: m[0] });
  }
  return out;
}

export type Infer = (text: string) => Promise<RawToken[]>;

export interface NerOptions {
  minScore?: number;
  ignore?: string[]; // user-configured terms that are never findings
  deadline?: number; // Date.now() after which no more prose is scanned (shared across texts by runNer)
  cells?: [number, number][]; // free-text table cells: what gets tokenised whole if the budget runs out
  depth?: number; // internal: inside a decoded payload
}

export interface NerScan {
  findings: Finding[];
  scannedTo: number; // text.length when every segment was scanned; else where the budget ran out
  tokenised: number; // free-text cells or lines tokenised whole because they weren't scanned
}

/** Findings for one text: model entities in prose plus rule-based companies and addresses. */
export async function nerFindings(text: string, infer: Infer, opts: NerOptions = {}): Promise<Finding[]> {
  return (await nerScan(text, infer, opts)).findings;
}

/** Prose segments cut to what the model reads at once, at a space or separator where possible. */
function chunks(segs: Segment[]): Segment[] {
  const out: Segment[] = [];
  for (const seg of segs) {
    let s = 0;
    while (seg.text.length - s > MAX_PIECE) {
      const window = seg.text.slice(s, s + MAX_PIECE);
      const cut = Math.max(window.lastIndexOf(" "), window.lastIndexOf(","), window.lastIndexOf("\t"));
      const end = cut > MAX_PIECE / 2 ? s + cut + 1 : s + MAX_PIECE;
      out.push({ start: seg.start + s, text: seg.text.slice(s, end) });
      s = end;
    }
    out.push({ start: seg.start + s, text: seg.text.slice(s) });
  }
  return out.filter((c) => /\p{L}{2}/u.test(c.text));
}

const wordCount = (s: string) => s.trim().split(/\s+/).filter(Boolean).length;

/**
 * Name detection over any length of text, segment by segment, within a time and memory budget. What the budget doesn't
 * reach is never passed through: free-text cells (4+ words) there are tokenised whole, and so are free-text lines outside
 * the tables. `scannedTo` and `tokenised` say what happened, for the approval reason.
 */
export async function nerScan(text: string, model: Infer, opts: NerOptions = {}): Promise<NerScan> {
  const depth = opts.depth ?? 0;
  // Memory is measured from the first model call on, so loading the model (~500 MB) isn't charged to the scan.
  let rss0: number | undefined;
  const overBudget = () => (opts.deadline !== undefined && Date.now() > opts.deadline) || (rss0 !== undefined && process.memoryUsage().rss - rss0 > MAX_RSS_GROWTH);
  const infer: Infer = async (t) => {
    const r = await model(t);
    rss0 ??= process.memoryUsage().rss;
    return r;
  };
  const ignore = new Set([...TECH, ...(opts.ignore ?? []).map((s) => s.toLowerCase())]);
  const found: Finding[] = [];
  const isWord = (c: string | undefined) => !!c && /[\p{L}\p{N}]/u.test(c);
  const add = (start: number, end: number, category: string, key?: string) => {
    // Whole words only: the model sometimes tags a fragment ("SM" of "SMB"), which would leave "[ORG-1]B".
    while (start > 0 && isWord(text[start - 1]) && isWord(text[start])) start--;
    while (end < text.length && isWord(text[end]) && isWord(text[end - 1])) end++;
    const value = text.slice(start, end);
    if (value.length < 2 || ignore.has(value.toLowerCase()) || /^\[?HIB[0-9a-f]{4}-/.test(value)) return;
    key ??= category === "PERSON" ? nameKey(value) : undefined;
    found.push({ start, end, value, category, kind: "pii", ...(key ? { key } : {}) });
  };
  const personOf = (f: Finding) => (f.category === "PERSON" ? [f.key ?? f.value] : []);
  // Encoded payloads: names in a decoded script (its string literals too, since code lines aren't read as prose) hide
  // the whole blob. A payload the budget didn't reach goes whole as well: it wasn't read, so it can't be passed.
  const encoded: Finding[] = [];
  const decodedNames: string[] = []; // people named inside payloads: their other forms in the text are found too
  for (const b of depth < 2 ? encodedBlobs(text) : []) {
    const inner = overBudget() ? null : await nerScan(`${b.decoded}\n${stringLiterals(b.decoded)}`, infer, { ...opts, cells: undefined, depth: depth + 1 });
    if (inner && !inner.findings.length) continue;
    decodedNames.push(...(inner?.findings.flatMap(personOf) ?? []));
    const absorbed = [...new Set(inner?.findings.map((f) => f.category) ?? [])];
    encoded.push({ start: b.start, end: b.end, value: b.value, category: encodedCategory(b), kind: "pii", ...(absorbed.length ? { absorbed } : {}) });
  }
  const segs = proseSegments(text);
  let scannedTo = text.length;
  for (const seg of chunks(segs)) {
    if (overBudget()) {
      scannedTo = seg.start;
      break;
    }
    // Pass 1: the text as written. Pass 2: lowercase stretches title-cased, since the cased model needs capitals.
    const passes: [Segment, string, number, boolean][] = [[seg, seg.text, opts.minScore ?? 0.6, false]];
    for (const piece of lowercasePieces(seg)) passes.push([piece, piece.text.replace(/(?<![\p{L}\p{N}])\p{Ll}/gu, (c) => c.toUpperCase()), 0.9, true]);
    for (const [where, input, min, caseless] of passes) {
      let cursor = 0;
      for (const e of mergeTokens(await infer(input))) {
        if (e.score < min || !LABEL[e.label]) continue;
        const at = locate(where.text, e.text, cursor, caseless);
        if (!at) continue;
        cursor = at[1];
        // The title-cased pass exists for names typed in lowercase; anything capitalised was pass 1's call.
        if (caseless && /\p{Lu}/u.test(where.text.slice(at[0], at[1]))) continue;
        add(where.start + at[0], where.start + at[1], LABEL[e.label]!);
      }
    }
    for (const m of seg.text.matchAll(ORG_SUFFIX)) add(seg.start + m.index!, seg.start + m.index! + m[0].length, "ORG");
    for (const m of seg.text.matchAll(ADDRESS)) add(seg.start + m.index!, seg.start + m.index! + m[0].length, "ADDRESS");
  }
  // Pass 3: file names, URLs and slugs, anywhere (a URL line can look like code). Each distinct one goes to the model
  // as a readable, title-cased copy, several to a piece; what it finds maps back onto the exact span in the text.
  // `slugsTo`: runs ending past it weren't read this way (all of them if prose already ran out of budget).
  let slugsTo = 0;
  if (scannedTo === text.length) {
    slugsTo = text.length;
    const byCopy = new Map<string, { start: number; from: number[]; to: number[] }[]>();
    for (const r of slugRuns(text)) {
      const d = deslug(r.value);
      byCopy.set(d.text, [...(byCopy.get(d.text) ?? []), { start: r.start, from: d.from, to: d.to }]);
    }
    const copies = [...byCopy.keys()];
    for (let i = 0; i < copies.length; ) {
      if (overBudget()) {
        scannedTo = slugsTo = Math.min(...copies.slice(i).flatMap((c) => byCopy.get(c)!.map((r) => r.start)));
        break;
      }
      const batch: { at: number; copy: string }[] = [];
      let input = "";
      while (i < copies.length && (!batch.length || input.length + 1 + copies[i]!.length <= MAX_PIECE)) {
        if (batch.length) input += "\n";
        batch.push({ at: input.length, copy: copies[i]! });
        input += copies[i++]!;
      }
      let cursor = 0;
      for (const e of mergeTokens(await infer(input))) {
        if (e.score < 0.9 || !LABEL[e.label]) continue;
        const at = locate(input, e.text, cursor, true);
        if (!at) continue;
        cursor = at[1];
        const b = batch.findLast((x) => x.at <= at[0]);
        if (!b || at[1] > b.at + b.copy.length) continue; // spans two copies
        const key = e.label === "PER" ? nameKey(e.text) : undefined;
        for (const r of byCopy.get(b.copy)!) add(r.start + r.from[at[0] - b.at]!, r.start + r.to[at[1] - b.at - 1]!, LABEL[e.label]!, key);
      }
    }
  }
  // Spreading: a full name found anywhere (prose, a slug, a decoded payload) is found in all its forms across the whole
  // text, code included: `ivana_babic`, `IvanaBabic`, `"ivana babic"` get the token `Ivana Babić` got.
  found.push(...spreadNames(text, new Set([...found.flatMap(personOf), ...decodedNames])));
  // Consistency: once a value is found, every occurrence in the prose is a finding, so a single miss by the model
  // can't leave "Split" tokenized in one row and in clear text in the next. This covers the whole text, including any
  // part the budget didn't reach. One pass with every value, longest first.
  const values = new Map(found.filter((f) => f.value.length >= 3).map((f) => [f.value, f.category]));
  if (values.size) {
    const re = new RegExp(`(?<![\\p{L}\\p{N}])(?:${[...values.keys()].sort((a, b) => b.length - a.length).map(esc).join("|")})(?![\\p{L}\\p{N}])`, "gu");
    for (const seg of segs) for (const m of seg.text.matchAll(re)) add(seg.start + m.index!, seg.start + m.index! + m[0].length, values.get(m[0])!);
  }
  // Out of budget: what wasn't scanned is tokenised whole. Table cells with 4+ words, and lines of 4+ words outside the
  // tables; short cells (codes, numbers, single names) are left to the column rules and the regex guard.
  let tokenised = 0;
  if (scannedTo < text.length) {
    const whole = (s: number, e: number) => {
      found.push({ start: s, end: e, value: text.slice(s, e), category: "TEXT", kind: "pii" });
      tokenised++;
    };
    const cells = opts.cells ?? [];
    for (const [s, e] of cells) if (e > scannedTo) whole(s, e);
    const lo = cells.reduce((m, c) => Math.min(m, c[0]), Infinity);
    const hi = cells.reduce((m, c) => Math.max(m, c[1]), -Infinity);
    let pos = 0;
    for (const line of text.split("\n")) {
      const start = pos + (line.length - line.trimStart().length);
      const end = pos + line.trimEnd().length;
      pos += line.length + 1;
      if (end <= scannedTo || (start < hi && end > lo) || wordCount(line) < 4) continue;
      whole(start, end);
    }
    // File names, URLs and slugs it didn't reach go whole too: one "word" to the rules above, a full name to a reader.
    for (const r of slugRuns(text)) if (r.start + r.value.length > slugsTo) whole(r.start, r.start + r.value.length);
  }
  found.push(...encoded);
  // One finding per span; adjacent same-kind findings separated only by spaces merge ("Ericsson" "Nikola Tesla"
  // -> one ORG); longest first so "Acme d.o.o." wins over "Acme" (the guard resolves remaining overlaps).
  const unique = [...new Map(found.map((f) => [`${f.start}:${f.end}`, f])).values()].sort((a, b) => a.start - b.start || b.end - a.end);
  const merged: Finding[] = [];
  for (const f of unique) {
    const last = merged[merged.length - 1];
    // Withheld blobs and cells are one value each: two on a line keep two tokens.
    const whole = /-ENCODED$|^TEXT$/.test(f.category);
    if (last && !whole && last.category === f.category && f.start >= last.end && /^ +$/.test(text.slice(last.end, f.start))) {
      last.end = f.end;
      last.value = text.slice(last.start, last.end);
      if (last.category === "PERSON") last.key = nameKey(last.value);
    } else merged.push({ ...f });
  }
  return { findings: merged.sort((a, b) => b.end - b.start - (a.end - a.start)), scannedTo, tokenised };
}

/** Loads the pinned model on first use. Never downloads unless `allowDownload` (hib guard ner setup). */
export class NerModel {
  private pipe?: Promise<(text: string, o: object) => Promise<RawToken[]>>;
  constructor(private cacheDir: string) {}

  load(allowDownload = false) {
    this.pipe ??= (async () => {
      const { pipeline, env } = await import("@huggingface/transformers");
      env.cacheDir = this.cacheDir;
      env.allowRemoteModels = allowDownload;
      return (await pipeline("token-classification", NER_MODEL, { dtype: "q8", revision: NER_REVISION } as any)) as any;
    })();
    this.pipe.catch(() => (this.pipe = undefined)); // let a later call retry
    return this.pipe;
  }

  infer: Infer = async (text) => (await this.load())(text, { ignore_labels: ["O"] });
}
