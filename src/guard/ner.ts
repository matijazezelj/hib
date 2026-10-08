// Local name/place/organisation detection: a multilingual NER model plus rules for what it misses.
// Runs only on prose (code is skipped), entirely on this machine; findings feed the guard's vault.
import type { Finding } from "./detectors";

export const NER_MODEL = "Xenova/bert-base-multilingual-cased-ner-hrl";
export const NER_REVISION = "263e82c06569c8c2ac46238a7ae5107598934234"; // pinned: a model update can't change what's detected
const MAX_CHARS = 200_000;
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
export function lowercasePieces(seg: Segment): Segment[] {
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

export type Infer = (text: string) => Promise<RawToken[]>;

export interface NerOptions {
  minScore?: number;
  ignore?: string[]; // user-configured terms that are never findings
}

/** Findings for one text: model entities in prose plus rule-based companies and addresses. */
export async function nerFindings(text: string, infer: Infer, opts: NerOptions = {}): Promise<Finding[]> {
  if (text.length > MAX_CHARS) throw new Error(`text too large for name detection (${text.length} > ${MAX_CHARS} chars)`);
  const ignore = new Set([...TECH, ...(opts.ignore ?? []).map((s) => s.toLowerCase())]);
  const found: Finding[] = [];
  const isWord = (c: string | undefined) => !!c && /[\p{L}\p{N}]/u.test(c);
  const add = (start: number, end: number, category: string) => {
    // Whole words only: the model sometimes tags a fragment ("SM" of "SMB"), which would leave "[ORG-1]B".
    while (start > 0 && isWord(text[start - 1]) && isWord(text[start])) start--;
    while (end < text.length && isWord(text[end]) && isWord(text[end - 1])) end++;
    const value = text.slice(start, end);
    if (value.length < 2 || ignore.has(value.toLowerCase()) || /^\[?HIB[0-9a-f]{4}-/.test(value)) return;
    found.push({ start, end, value, category, kind: "pii" });
  };
  for (const seg of proseSegments(text)) {
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
  // Consistency: once a value is found, every occurrence in the prose is a finding, so a single miss by the model
  // can't leave "Split" tokenized in one row and in clear text in the next.
  const segs = proseSegments(text);
  for (const v of new Map(found.map((f) => [f.value, f.category])).entries()) {
    const [value, category] = v;
    if (value.length < 3) continue;
    const re = new RegExp(`(?<![\\p{L}\\p{N}])${esc(value)}(?![\\p{L}\\p{N}])`, "gu");
    for (const seg of segs) for (const m of seg.text.matchAll(re)) add(seg.start + m.index!, seg.start + m.index! + m[0].length, category);
  }
  // One finding per span; adjacent same-kind findings separated only by spaces merge ("Ericsson" "Nikola Tesla"
  // -> one ORG); longest first so "Acme d.o.o." wins over "Acme" (the guard resolves remaining overlaps).
  const unique = [...new Map(found.map((f) => [`${f.start}:${f.end}`, f])).values()].sort((a, b) => a.start - b.start || b.end - a.end);
  const merged: Finding[] = [];
  for (const f of unique) {
    const last = merged[merged.length - 1];
    if (last && last.category === f.category && f.start >= last.end && /^ +$/.test(text.slice(last.end, f.start))) {
      last.end = f.end;
      last.value = text.slice(last.start, last.end);
    } else merged.push({ ...f });
  }
  return merged.sort((a, b) => b.end - b.start - (a.end - a.start));
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
