import { encodedBlobs, encodedCategory } from "../guard/encoded";
import type { Vault } from "../guard/vault";
import { identifyingBy, type Table } from "./table";

const EMAIL = /^([^@\s]+)@([^@\s]+\.[^@\s]+)$/;

/** Token category from a column name: "full_name" -> "FULL-NAME". Tokens only allow A-Z, 0-9 and "-". */
export function categoryFor(column: string): string {
  return column.toUpperCase().replace(/[^A-Z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "COL";
}

function csvCell(v: unknown): string {
  if (v === null || v === undefined) return "";
  const s = String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/**
 * Columns to pseudonymise whole by default: the identifying ones, plus `hide`, minus `keep`. Free text that only
 * contains identifiers stays readable here; the identifiers inside it are replaced cell by cell.
 */
export function columnsToHide(table: Table, hide: string[] = [], keep: string[] = []): string[] {
  return table.columns.filter((c) => {
    if (keep.includes(c)) return false;
    if (hide.includes(c)) return true;
    const by = identifyingBy(c, table.rows);
    return by === "name" || by === "value";
  });
}

/**
 * The table as CSV with each value in `columns` replaced by a stable token from the conversation's vault,
 * so the same person is the same token everywhere and answers can be restored. Emails keep their shape:
 * the name and the domain become separate tokens, so grouping by domain still works.
 */
export function pseudonymize(table: Table, columns: string[], vault: Vault, guard?: (text: string) => string): string {
  return pseudonymizeWithSpans(table, columns, vault, [], guard).csv;
}

/**
 * Same, also returning where the cells of `keep` columns sit in the CSV, so the guard can leave them exactly as
 * they are: `--keep country,city` means readable, not re-tokenized by name detection or other detectors.
 * `guard` runs on each column name and each readable text cell on its own, so no detector can match across a cell
 * boundary and swallow the next cell.
 */
export function pseudonymizeWithSpans(
  table: Table,
  columns: string[],
  vault: Vault,
  keep: string[],
  guard: (text: string) => string = (t) => t,
): { csv: string; kept: [number, number][]; text: [number, number][] } {
  const kept: [number, number][] = [];
  const text: [number, number][] = []; // readable free-text cells (4+ words): tokenised whole if name detection can't reach them
  const keepSet = new Set(keep);
  let csv = "";
  const line = (cells: string[], keepFlags: boolean[]) => {
    cells.forEach((c, i) => {
      if (i) csv += ",";
      if (keepFlags[i] && c) kept.push([csv.length, csv.length + c.length]);
      else if (c.trim().split(/\s+/).length >= 4) text.push([csv.length, csv.length + c.length]);
      csv += c;
    });
    csv += "\n";
  };
  const hidden = new Set(columns);
  const tok = (col: string, v: string) => {
    const m = EMAIL.exec(v);
    if (m) return `[${vault.token(categoryFor(col), m[1]!)}]@[${vault.token("DOMAIN", m[2]!)}]`;
    return `[${vault.token(categoryFor(col), v)}]`;
  };
  // Tokenize the hidden columns first, so a hidden value written into another cell ("follow up with josip müller")
  // gets the same token there instead of going out readable.
  const known = new Map<string, string>();
  let maxWords = 1;
  for (const r of table.rows)
    for (const c of columns) {
      const v = r[c];
      if (v === null || v === undefined || v === "") continue;
      const t = tok(c, String(v));
      const key = norm(String(v));
      if (key.length < 3 || known.has(key)) continue;
      const n = pieces(key).length;
      if (n > MAX_PIECES) continue;
      known.set(key, t);
      maxWords = Math.max(maxWords, n);
    }
  line(table.columns.map((c) => csvCell(guard(c))), table.columns.map(() => false));
  const flags = table.columns.map((c) => keepSet.has(c));
  for (const r of table.rows)
    line(
      table.columns.map((c) => {
        const v = r[c];
        if (v === null || v === undefined || v === "") return csvCell(v);
        if (hidden.has(c)) return csvCell(tok(c, String(v)));
        return csvCell(typeof v === "string" && !keepSet.has(c) ? guard(replaceKnownEncoded(replaceKnown(v, known, maxWords), known, maxWords, vault)) : v);
      }),
      flags,
    );
  return { csv, kept, text };
}

/** An encoded blob (`python3 -c <base64>`) that decodes to text naming a hidden value goes out as one token. */
function replaceKnownEncoded(text: string, known: Map<string, string>, maxWords: number, vault: Vault): string {
  if (!known.size) return text;
  let out = "";
  let pos = 0;
  for (const b of encodedBlobs(text)) {
    if (replaceKnown(b.decoded, known, maxWords) === b.decoded) continue;
    out += text.slice(pos, b.start) + `[${vault.token(encodedCategory(b), b.value)}]`;
    pos = b.end;
  }
  return out + text.slice(pos);
}

const norm = (s: string) => s.trim().replace(/\s+/g, " ").toLowerCase();
// Words for matching: split on spaces and on the separators logs put around names (CORP\jdoe, C:\Users\jdoe, jdoe@host,
// user=jdoe), but not on dots or dashes, so "a.kovac" and "WS-ZG-0142" stay whole and only match whole.
const PIECE = /[^\s\\/:=,;()"'<>|@[\]{}]+/g;
const pieces = (s: string) => [...s.matchAll(PIECE)].map((m) => ({ start: m.index!, end: m.index! + m[0].length }));
const MAX_PIECES = 8;

/** Replaces whole-word occurrences of known values (any case, any spacing) with their tokens. Longest match wins. */
function replaceKnown(text: string, known: Map<string, string>, maxWords: number): string {
  if (!known.size) return text;
  const words = pieces(text);
  let out = "";
  let pos = 0;
  for (let i = 0; i < words.length; i++) {
    for (let k = Math.min(maxWords, words.length - i); k >= 1; k--) {
      const raw = text.slice(words[i]!.start, words[i + k - 1]!.end);
      // Try the span as written, then without sentence punctuation ("Horvat." or "jdoe!").
      let hit = known.get(norm(raw));
      const start = words[i]!.start;
      let end = words[i + k - 1]!.end;
      if (!hit) {
        const trail = raw.match(/[.!?«»“”]+$/)?.[0].length ?? 0;
        if (trail) {
          hit = known.get(norm(raw.slice(0, raw.length - trail)));
          end -= trail;
        }
      }
      if (!hit) continue;
      out += text.slice(pos, start) + hit;
      pos = end;
      i += k - 1;
      break;
    }
  }
  return out + text.slice(pos);
}
