import type { Vault } from "../guard/vault";
import { isIdentifying, type Table } from "./table";

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

/** Columns to pseudonymise by default: the identifying ones, plus `hide`, minus `keep`. */
export function columnsToHide(table: Table, hide: string[] = [], keep: string[] = []): string[] {
  return table.columns.filter((c) => !keep.includes(c) && (hide.includes(c) || isIdentifying(c, table.rows)));
}

/**
 * The table as CSV with each value in `columns` replaced by a stable token from the conversation's vault,
 * so the same person is the same token everywhere and answers can be restored. Emails keep their shape:
 * the name and the domain become separate tokens, so grouping by domain still works.
 */
export function pseudonymize(table: Table, columns: string[], vault: Vault): string {
  const hidden = new Set(columns);
  const tok = (col: string, v: string) => {
    const m = EMAIL.exec(v);
    if (m) return `[${vault.token(categoryFor(col), m[1]!)}]@[${vault.token("DOMAIN", m[2]!)}]`;
    return `[${vault.token(categoryFor(col), v)}]`;
  };
  const lines = [table.columns.map(csvCell).join(",")];
  for (const r of table.rows)
    lines.push(table.columns.map((c) => (hidden.has(c) && r[c] !== null && r[c] !== undefined && r[c] !== "" ? csvCell(tok(c, String(r[c]))) : csvCell(r[c]))).join(","));
  return lines.join("\n") + "\n";
}
