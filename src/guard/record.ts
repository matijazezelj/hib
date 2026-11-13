// One log event at a time, for `hib pipe`: the table rules (src/analyze/table.ts) and pseudonymisation
// (src/analyze/pseudo.ts) applied per record, with no look at other rows, plus the regex guard on readable text.
// TODO: name detection (NER) is left out on purpose: ~80 ms per event is too slow for a log pipeline.
import { flatten, identifyingName, IDENTIFYING_VALUE, inferType, isFreeText, type Cell, type ColType } from "../analyze/table";
import { knownKey, replaceKnown, replaceKnownEncoded, tokenFor } from "../analyze/pseudo";
import { isPrivateIp, type DetectOptions, type Finding, type Level } from "./detectors";
import { machineTerms } from "./index";
import { Vault } from "./vault";

export interface RecordPolicy {
  level: Level; // "standard" by default
  hide: string[]; // dotted field names always tokenised whole
  keep: string[]; // dotted field names left readable (still regex-guarded)
  terms: string[]; // cfg.guard.terms
  patterns: { category: string; regex: string; flags?: string }[]; // cfg.guard.patterns
}

export const defaultPolicy = (p: Partial<RecordPolicy> = {}): RecordPolicy => ({ level: "standard", hide: [], keep: [], terms: [], patterns: [], ...p });

/** State that lives across records: the vault plus the values already hidden, so they're replaced inside later free text too. */
export class GuardState {
  /** Normalised hidden value -> its token, oldest first (a Map keeps insertion order; a value seen again moves to the end). */
  private known = new Map<string, string>();
  private maxWords = 1;
  // This machine's username and hostname, as obfuscateText adds them in chat mode. Looked up once, not per event.
  private readonly identities = machineTerms();

  constructor(
    readonly vault: Vault = new Vault(),
    readonly maxKnown = 100_000,
  ) {
    // A vault loaded from an earlier run: its values are hidden again wherever they turn up in free text, from the first
    // event on, not only after a field brings them up again. Newest last, so the bound keeps the most recent.
    for (const [value, core] of vault.state().entries.slice(-maxKnown)) {
      const k = knownKey(value);
      if (!k) continue;
      this.known.set(k.key, `[${core}]`);
      if (k.words > this.maxWords) this.maxWords = k.words;
    }
  }

  /** Tokenises a hidden value and remembers it for later free text. */
  hide(field: string, value: string): string {
    // An IPv4 value is tokenised as an IP whatever the field is called, so it keeps its NETn (/24) group and matches the
    // token the regex guard gives the same address in free text.
    const ip = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value);
    const token = ip ? `[${this.vault.token(isPrivateIp(value) ? "IP-INTERNAL" : "IP-EXTERNAL", value)}]` : tokenFor(this.vault, field, value);
    const k = knownKey(value);
    if (k && this.maxKnown > 0) {
      this.known.delete(k.key);
      this.known.set(k.key, token);
      if (k.words > this.maxWords) this.maxWords = k.words;
      // maxWords isn't lowered when long values are dropped: it only bounds how far the lookup tries, never what matches.
      while (this.known.size > this.maxKnown) this.known.delete(this.known.keys().next().value!);
    }
    return token;
  }

  /** Readable text: hidden values written into it get their tokens, then the regex guard runs. */
  guardText(text: string, policy: RecordPolicy): { text: string; findings: Finding[] } {
    if (this.known.size) {
      text = replaceKnown(text, this.known, this.maxWords);
      text = replaceKnownEncoded(text, this.known, this.maxWords, this.vault);
    }
    const opts: DetectOptions = { level: policy.level, terms: policy.terms, identities: this.identities, patterns: policy.patterns };
    return this.vault.obfuscate(text, opts);
  }

  get knownCount() {
    return this.known.size;
  }
}

/** A finding as reported to callers: where and what kind, never the value it hid (callers log and serialise these). */
export type GuardFinding = Omit<Finding, "value" | "key"> & { field?: string };

const report = (f: Finding, field?: string): GuardFinding => {
  const { value: _value, key: _key, ...rest } = f;
  return field === undefined ? rest : { ...rest, field };
};

export interface GuardedRecord {
  record: Record<string, Cell>; // flattened (dotted keys), every identifying value replaced by a [HIB…] token
  hidden: string[]; // fields tokenised whole in this record
  findings: GuardFinding[]; // regex-guard findings inside readable fields; offsets are within `field`
}

/** The type the table code would give a column holding only this value. */
function cellType(v: Exclude<Cell, null>): ColType {
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  if (typeof v === "boolean") return "boolean";
  return inferType([v.trim()]);
}

/** Hidden whole by default: identifying by name, or a lone email / IP / phone / internal FQDN (not free text naming one). */
function identifying(field: string, v: Exclude<Cell, null>): boolean {
  const type = cellType(v);
  if (type === "boolean") return false; // a yes/no flag identifies no one
  if (identifyingName(field, type)) return true;
  // Free text naming an address stays readable (the regex guard replaces the address inside it). A phone number written
  // with spaces ("+385 91 234 5678") has four "words" but no letters: that's a value, not text.
  return type === "string" && typeof v === "string" && IDENTIFYING_VALUE.test(v) && !(isFreeText(v) && /\p{L}/u.test(v));
}

export function guardRecord(record: unknown, state: GuardState, policy: RecordPolicy): GuardedRecord {
  const flat = flatten(record);
  const hide = new Set(policy.hide);
  const keep = new Set(policy.keep);
  const out: Record<string, Cell> = {};
  const hidden: string[] = [];
  const findings: GuardFinding[] = [];
  const readable: string[] = [];
  // Hidden fields first, so a hidden value written into a readable field of this same record gets its token there.
  for (const [field, v] of Object.entries(flat)) {
    out[field] = v;
    if (v === null || v === "") continue;
    if (!keep.has(field) && (hide.has(field) || identifying(field, v))) {
      out[field] = state.hide(field, String(v));
      hidden.push(field);
    } else if (typeof v === "string") readable.push(field);
  }
  // Each field on its own, so no detector matches across two fields. Field names are schema and stay as they are.
  for (const field of readable) {
    const r = state.guardText(out[field] as string, policy);
    out[field] = r.text;
    for (const f of r.findings) findings.push(report(f, field));
  }
  return { record: out, hidden, findings };
}

export function guardLine(line: string, state: GuardState, policy: RecordPolicy): { text: string; findings: GuardFinding[] } {
  const r = state.guardText(line, policy);
  return { text: r.text, findings: r.findings.map((f) => report(f)) };
}
