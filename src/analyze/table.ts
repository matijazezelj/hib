import { readFileSync, statSync } from "node:fs";
import { basename, extname } from "node:path";

export type Cell = string | number | boolean | null;
export type ColType = "integer" | "number" | "boolean" | "date" | "string";

export interface Table {
  columns: string[];
  rows: Record<string, Cell>[];
}

export interface ColumnProfile {
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
export const TABLE_FILE = /\.(csv|tsv|json|jsonl|ndjson)$/i;

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
  if (!TABLE_FILE.test(path)) throw new Error(`${basename(path)} is not a CSV, TSV, JSON or JSONL file`);
  if (statSync(path).size > MAX_BYTES) throw new Error(`${basename(path)} is larger than 50 MB`);
  const text = readFileSync(path, "utf8").replace(/^﻿/, "");
  const ext = extname(path).toLowerCase();
  if (ext === ".json" || ext === ".jsonl" || ext === ".ndjson") {
    const records: any[] = ext === ".json" ? JSON.parse(text) : text.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
    if (!Array.isArray(records)) throw new Error("JSON must be an array of objects");
    const columns = [...new Set(records.flatMap((r) => Object.keys(r ?? {})))];
    const rows = records.map((r) => Object.fromEntries(columns.map((c) => [c, typeof r?.[c] === "object" && r?.[c] !== null ? JSON.stringify(r[c]) : (r?.[c] ?? null)])));
    return { columns, rows };
  }
  const delim = ext === ".tsv" ? "\t" : sniffDelimiter(text.split("\n", 1)[0] ?? "");
  const grid = parseDelimited(text, delim);
  if (!grid.length) throw new Error("empty file");
  const header = grid[0]!.map((h, i) => h.trim() || `column_${i + 1}`);
  const body = grid.slice(1);
  const types = header.map((_, i) => inferType(body.map((r) => (r[i] ?? "").trim())));
  const rows = body.map((r) => Object.fromEntries(header.map((h, i) => [h, convert((r[i] ?? "").trim(), types[i]!)])));
  return { columns: header, rows };
}

const IDENTIFYING_NAME = /user|login|name|e-?mail|mail|phone|mobile|tel|\bip\b|ip_?addr|address|addr|street|zip|postal|ssn|oib|jmbg|iban|account|card|passport|birth|dob|token|password|secret|host|device|mac_?addr|uuid|guid|person|employee|customer|client|owner/i;
const IDENTIFYING_VALUE = /@[\w-]+\.\w|^\d{1,3}(\.\d{1,3}){3}$|^\+?\d[\d\s()-]{7,}$/;

export function columnType(rows: Record<string, Cell>[], col: string): ColType {
  const v = rows.map((r) => r[col]).find((x) => x !== null && x !== undefined);
  if (typeof v === "number") return rows.every((r) => r[col] === null || Number.isInteger(r[col])) ? "integer" : "number";
  if (typeof v === "boolean") return "boolean";
  return inferType(rows.map((r) => (r[col] === null || r[col] === undefined ? "" : String(r[col]))));
}

/** Identifying columns: by name, or because their values look like emails, IPs or phone numbers. */
export function isIdentifying(name: string, rows: Record<string, Cell>[]): boolean {
  if (IDENTIFYING_NAME.test(name)) return true;
  if (columnType(rows, name) !== "string") return false; // numbers and ISO dates aren't emails, IPs or phones
  const sample = rows.slice(0, 200).map((r) => r[name]).filter((x): x is string => typeof x === "string");
  return sample.length > 0 && sample.filter((x) => IDENTIFYING_VALUE.test(x)).length / sample.length > 0.3;
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
