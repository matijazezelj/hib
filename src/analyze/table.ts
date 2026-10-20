import { readFileSync, statSync } from "node:fs";
import { basename, extname } from "node:path";

export type Cell = string | number | boolean | null;
type ColType = "integer" | "number" | "boolean" | "date" | "string";

export interface Table {
  columns: string[];
  rows: Record<string, Cell>[];
}

interface ColumnProfile {
  name: string;
  type: ColType;
  nulls: number;
  distinct: number;
  identifying: boolean; // looks like it identifies a person or system: never shown, even when sharing
  values?: string[]; // real distinct values, only for columns the user chose to share
}

export interface Profile {
  file: string;
  rows: number;
  columns: ColumnProfile[];
  sample: Record<string, Cell>[]; // synthetic rows with the right shape, never real data
}

const MAX_BYTES = 50 * 1024 * 1024;
/** Several files as one table: columns are unioned and `source_file` says where each row came from. */
export function loadTables(paths: string[]): Table {
  if (paths.length === 1) return loadTable(paths[0]!);
  const tables = paths.map((p) => ({ name: basename(p), t: loadTable(p) }));
  const columns = ["source_file", ...new Set(tables.flatMap((x) => x.t.columns))];
  const rows = tables.flatMap((x) => x.t.rows.map((r) => Object.fromEntries(columns.map((c) => [c, c === "source_file" ? x.name : (r[c] ?? null)]))));
  return { columns, rows };
}

export const TABLE_FILE = /\.(csv|tsv|json|jsonl|ndjson|log)$/i;

/** RFC 4180-style CSV: quoted fields, doubled quotes, newlines inside quotes. */
export function parseDelimited(text: string, delim: string): string[][] {
  const out: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else quoted = false;
      } else field += c;
    } else if (c === '"' && field === "") quoted = true;
    else if (c === delim) {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      field = "";
      if (row.length > 1 || row[0] !== "") out.push(row);
      row = [];
    } else field += c;
  }
  if (field !== "" || row.length) {
    row.push(field);
    out.push(row);
  }
  return out;
}

function sniffDelimiter(firstLine: string): string {
  const counts = [",", "\t", ";", "|"].map((d) => [d, firstLine.split(d).length - 1] as const);
  return counts.sort((a, b) => b[1] - a[1])[0]![1] > 0 ? counts[0]![0] : ",";
}

const NUM = /^-?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/;
const INT = /^-?\d+$/;
const DATE = /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$/;
const BOOL = /^(true|false)$/i;

function inferType(values: string[]): ColType {
  const v = values.filter((x) => x !== "");
  if (!v.length) return "string";
  if (v.some((x) => /^-?0\d/.test(x))) return "string"; // leading zeros (ids, zip codes) must survive
  if (v.every((x) => INT.test(x))) return "integer";
  if (v.every((x) => NUM.test(x))) return "number";
  if (v.every((x) => BOOL.test(x))) return "boolean";
  if (v.every((x) => DATE.test(x))) return "date";
  return "string";
}

function convert(x: string, t: ColType): Cell {
  if (x === "") return null;
  if (t === "integer" || t === "number") return Number(x);
  if (t === "boolean") return /^true$/i.test(x);
  return x;
}

export function loadTable(path: string): Table {
  // Any other file would have its first line sent as "column names".
  if (!TABLE_FILE.test(path)) throw new Error(`${basename(path)} is not a CSV, TSV, JSON, JSONL or JSON-lines .log file`);
  if (statSync(path).size > MAX_BYTES) throw new Error(`${basename(path)} is larger than 50 MB`);
  const text = readFileSync(path, "utf8").replace(/^﻿/, "");
  const ext = extname(path).toLowerCase();
  if (ext === ".json" || ext === ".jsonl" || ext === ".ndjson" || ext === ".log") {
    let records: any;
    if (ext === ".json") records = JSON.parse(text);
    else
      records = text.split("\n").filter((l) => l.trim()).map((l, i) => {
        try {
          return JSON.parse(l);
        } catch {
          throw new Error(`${basename(path)} line ${i + 1} isn't JSON (hib reads ${ext} files as one JSON object per line)`);
        }
      });
    // An Elasticsearch / OpenSearch search response: the events are hits.hits[]._source.
    if (!Array.isArray(records) && Array.isArray(records?.hits?.hits)) records = records.hits.hits.map((h: any) => h?._source ?? h);
    // Any other object: the records inside it ({"rows": [...]}, or {"1.2.3.4": {...}, ...} keyed by id).
    if (!Array.isArray(records)) records = recordsIn(records) as any;
    if (!records) throw new Error("JSON holds no list of records (an array of objects, or an object of objects)");
    // Nested objects become dotted columns (user.name, source.ip), so each field is judged and hidden on its own.
    const flat = (records as unknown[]).map((r) => flatten(r));
    const columns = [...new Set(flat.flatMap((r) => Object.keys(r)))];
    const rows = flat.map((r) => Object.fromEntries(columns.map((c) => [c, r[c] ?? null])));
    return { columns, rows };
  }
  const delim = ext === ".tsv" ? "\t" : sniffDelimiter(text.split("\n", 1)[0] ?? "");
  const grid = parseDelimited(text, delim);
  if (!grid.length) throw new Error("empty file");
  const header = grid[0]!.map((h, i) => h.trim() || `column_${i + 1}`);
  const body = grid.slice(1);
  const types = header.map((_, i) => inferType(body.map((r) => (r[i] ?? "").trim())));
  const rows = body.map((r) => Object.fromEntries(header.map((h, i) => [h, convert((r[i] ?? "").trim(), types[i]!)])));
  if (!rows.some((r) => Object.values(r).some(jsonObjectIn))) return { columns: header, rows };
  // A CSV export of JSON events (a full_log column): its JSON cells become dotted columns too.
  const flat = rows.map((r) => flatten(r));
  const columns = [...new Set(flat.flatMap((r) => Object.keys(r)))];
  return { columns, rows: flat.map((r) => Object.fromEntries(columns.map((c) => [c, r[c] ?? null]))) };
}

const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** The largest set of records anywhere in a JSON value: an array of objects, or an object whose values are all objects. */
function recordsIn(value: unknown, depth = 0): Record<string, unknown>[] | null {
  if (depth > 4) return null;
  let best: Record<string, unknown>[] | null = null;
  const consider = (r: Record<string, unknown>[] | null) => {
    if (r && r.length > (best?.length ?? 0)) best = r;
  };
  if (Array.isArray(value)) {
    if (value.length && value.every(isRecord)) consider(value);
    for (const v of value.slice(0, 50)) consider(recordsIn(v, depth + 1));
  } else if (isRecord(value)) {
    const entries = Object.entries(value);
    if (entries.length >= 2 && entries.every(([, v]) => isRecord(v))) consider(entries.map(([k, v]) => ({ _key: k, ...(v as object) })));
    for (const [, v] of entries) consider(recordsIn(v, depth + 1));
  }
  return best;
}

/** A string cell holding a JSON object (Wazuh's full_log), parsed; anything else is null. */
function jsonObjectIn(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "string" || value.length > MAX_JSON_CELL) return null;
  const s = value.trim();
  if (!s.startsWith("{") || !s.endsWith("}")) return null;
  try {
    const v = JSON.parse(s);
    return isRecord(v) ? v : null;
  } catch {
    return null;
  }
}
const MAX_JSON_CELL = 1024 * 1024;

function flatten(value: any, prefix = "", out: Record<string, Cell> = {}, depth = 0): Record<string, Cell> {
  // JSON stored in a string is flattened like nested JSON (full_log.callerIp), so each field is judged on its own
  // instead of the whole document as one value. The original column goes away; its fields replace it.
  const inner = depth < 3 ? jsonObjectIn(value) : null;
  if (inner && Object.keys(inner).length) return flatten(inner, prefix, out, depth + 1);
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value)) flatten(v, prefix ? `${prefix}.${k}` : k, out, depth);
    return out;
  }
  const key = prefix || "value";
  // A one-element list of scalars (ECS host.ip: ["10.0.0.5"]) is that scalar; anything else stays JSON in one cell.
  if (Array.isArray(value)) out[key] = value.length === 1 && (value[0] === null || typeof value[0] !== "object") ? value[0] : JSON.stringify(value);
  else out[key] = value ?? null;
  return out;
}

// Hard identifiers name a person whatever the column holds, numbers and dates too (an OIB is 11 digits, a birth date is
// a date). Soft words identify string columns, and number or date columns only when they look like an id (user_id).
const HARD_NAME = /e-?mail|mail|phone|mobile|tel|address|addr|street|zip|postal|ssn|oib|jmbg|iban|account|card|passport|birth|dob|token|password|secret|mac_?addr|uuid|guid/i;
const SOFT_NAME = /user|login|name|(?<![a-z])ip(?:v[46])?(?![a-z])|ip_?addr|host|device|person|employee|customer|client|owner/i;
const CAMEL_IP = /[a-z]I[pP](?![a-z])/; // callerIp, sourceIP
const ID_LIKE = /id$/i;
// Segments that name a thing, not a person: methodName, service_name, program_name. displayName and full_name aren't here.
const THING_NAME = /^(?:method|service|log|event|program|process|app|application|resource|rule|policy|operation|action|task|job|command|module|function|class|type|metric|decoder|index|table|field|queue|topic|product|plugin|integration|protocol|alert|signature|feature|setting|template|workflow|step|stage)[_-]?name$/i;
// Descriptors of a person-ish word that aren't the person: user_type, loginCount, account_status.
// Case matters for camelCase: "account" ends in "count" but isn't a count.
const DESCRIPTOR = /[_-](?:type|kind|version|count|status|TYPE|KIND|VERSION|COUNT|STATUS)$|[a-z](?:Type|Kind|Version|Count|Status)$/;
// A client's software, not a customer: client_id (an OAuth app), client_type, clientOsVersion.
const CLIENT_META = /^client[_-]?(?:id|type|os|version|app|platform|software|lib|agent|build|locale|lang)/i;
const IDENTIFYING_VALUE = /@[\w-]+\.\w|^\d{1,3}(\.\d{1,3}){3}$|^\+?\d[\d\s()-]{7,}$/;

/** The part of a column path its name is judged by: no trailing ".name", no thing names or descriptors. */
function judgedName(column: string): string {
  const segs = column.split(".");
  // user.name and host.name identify, process.name doesn't: a trailing ".name" is judged by its parent.
  if (segs.length > 1 && /^name$/i.test(segs[segs.length - 1]!)) segs.pop();
  return segs.map((s) => (THING_NAME.test(s) || DESCRIPTOR.test(s) || CLIENT_META.test(s) ? "" : s)).join(".");
}

/** Identifying by name alone: hard identifiers always, soft words for strings, and for numbers and dates only as ids. */
function identifyingName(column: string, type: ColType): boolean {
  const judged = judgedName(column);
  if (HARD_NAME.test(judged)) return true;
  if (!SOFT_NAME.test(judged) && !CAMEL_IP.test(judged)) return false;
  return type === "string" || ID_LIKE.test(column.split(".").pop()!);
}

function columnType(rows: Record<string, Cell>[], col: string): ColType {
  const v = rows.map((r) => r[col]).find((x) => x !== null && x !== undefined);
  if (typeof v === "number") return rows.every((r) => r[col] === null || Number.isInteger(r[col])) ? "integer" : "number";
  if (typeof v === "boolean") return "boolean";
  return inferType(rows.map((r) => (r[col] === null || r[col] === undefined ? "" : String(r[col]))));
}

/** Identifying columns: by name, or because their values look like emails, IPs or phone numbers. */
export function isIdentifying(name: string, rows: Record<string, Cell>[]): boolean {
  return identifyingBy(name, rows) !== null;
}

/**
 * Why a column identifies people or systems: its name, its values, or "text" when it's free text (log lines,
 * descriptions) that merely contains an email here and there. Text is pseudonymised identifier by identifier, not as
 * whole cells, so the model can still read what each row says.
 */
export function identifyingBy(name: string, rows: Record<string, Cell>[]): "name" | "value" | "text" | null {
  const type = columnType(rows, name);
  if (type === "boolean") return null; // a yes/no flag ("known_abuser") identifies no one
  if (identifyingName(name, type)) return "name";
  if (type !== "string") return null; // numbers and ISO dates aren't emails, IPs or phones
  const sample = rows.slice(0, 200).map((r) => r[name]).filter((x): x is string => typeof x === "string" && x !== "");
  if (!sample.length || sample.filter((x) => IDENTIFYING_VALUE.test(x)).length / sample.length <= 0.3) return null;
  return sample.filter((x) => x.trim().split(/\s+/).length >= 4).length / sample.length >= 0.5 ? "text" : "value";
}

function synthetic(col: ColumnProfile, i: number): Cell {
  switch (col.type) {
    case "integer":
      return (i + 1) * 10;
    case "number":
      return (i + 1) * 10.5;
    case "boolean":
      return i % 2 === 0;
    case "date":
      return `2024-01-0${i + 1}`;
    default:
      if (col.values?.length) return col.values[i % col.values.length]!;
      if (/mail/i.test(col.name)) return `user${i + 1}@example.com`;
      return `${col.name}_${String.fromCharCode(97 + i)}`;
  }
}

/** Everything the model may see about a table. Real values appear only for columns in `share`, never identifying ones. */
export function profile(table: Table, file: string, share: string[] = []): Profile {
  const columns: ColumnProfile[] = table.columns.map((name) => {
    const vals = table.rows.map((r) => r[name]);
    const nonNull = vals.filter((v) => v !== null && v !== undefined);
    const distinctSet = new Set(nonNull.map(String));
    const identifying = isIdentifying(name, table.rows);
    const p: ColumnProfile = { name, type: columnType(table.rows, name), nulls: vals.length - nonNull.length, distinct: distinctSet.size, identifying };
    if (share.includes(name) && !identifying && distinctSet.size <= 50) p.values = [...distinctSet].sort();
    return p;
  });
  const sample = [0, 1, 2].map((i) => Object.fromEntries(columns.map((c) => [c.name, synthetic(c, i)])));
  return { file: basename(file), rows: table.rows.length, columns, sample };
}
