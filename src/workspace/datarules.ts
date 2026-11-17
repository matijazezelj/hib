import { isAbsolute, resolve } from "node:path";

/**
 * Sensitive workspaces: shell commands that would read data files raw. Data goes to the agent only through the
 * Read tool, which hands it a pseudonymised copy. Returns why a command is blocked, or null.
 */
// JSON is data only when it's a table (passed in via dataFiles); package.json and friends stay readable.
const DATA_EXT = /\.(csv|tsv|jsonl|ndjson|log|xlsx?|parquet|sqlite3?)\b/i;
const DATA_GLOB = /\*[^\s]*\.(csv|tsv|jsonl|ndjson|log|xlsx?|parquet)\b/i;
// Programs that only list or count files, never print their contents.
const METADATA_ONLY = new Set(["ls", "find", "stat", "file", "du", "wc", "tree"]);
const INTERPRETERS = /(^|[\s;&|(])(python3?|node|bun|deno|ruby|perl|php|Rscript|julia|duckdb|sqlite3|jq|mlr|xsv|qsv|csvlook|csvcut|csvgrep|awk|gawk)\b/;
const INLINE_CODE = /(^|[\s;&|(])(python3?|node|bun|deno|ruby|perl|php|Rscript)\s+(-[a-zA-Z]*[ce]\b|-\s|<<)/;
const HEREDOC_INTO_INTERPRETER = /(python3?|node|bun|deno|ruby|perl|php|Rscript|duckdb|sqlite3)\s*<</;

export const DATA_RULE_NOTE =
  "This folder is marked sensitive. Read data files (CSV, TSV, JSON, logs…) only with the Read tool: you will receive a pseudonymised copy " +
  "in which people, accounts, IPs and similar values are placeholders like [HIB…-USER-3]. A JSON file that isn't a list arrives as the largest list of records inside it. Shell commands that read data files, inline scripts " +
  "(python -c, node -e, heredocs) and scripts written outside this folder are blocked. To compute something over a data file, read it with Read and reason over it, " +
  "or write a script inside this folder that the user can review. " +
  "Each shell command runs on its own in a subshell: cd and export don't carry over to the next command, so use absolute paths or repeat them. " +
  "Its output reaches you after hib's guard, with the same kind of placeholders, and ends with [exit N].";

/**
 * Why a command was blocked. `reason` is fixed text that never holds anything from the command; `detail` is the file
 * name or script path that set it off, if any; `text` is the full sentence for the agent and the user.
 */
export interface DataBlock {
  reason: "it reads a data file directly" | "it runs inline code that could read data files" | "it runs a script from outside this folder";
  detail?: string;
  text: string;
}

export function rawDataCommand(command: string, root: string, dataFiles: Set<string> = new Set()): DataBlock | null {
  const cmd = command.trim();
  const programs = cmd.split(/\s*(?:&&|\|\||[;|])\s*/).map((part) => part.trim().split(/\s+/)[0] ?? "");
  if (programs.every((p) => METADATA_ONLY.has(p)) && !/-exec|-execdir|-ok\b|-delete/.test(cmd)) return null;
  if (DATA_EXT.test(cmd) || DATA_GLOB.test(cmd)) return { reason: "it reads a data file directly", text: "it reads a data file directly" };
  for (const name of dataFiles) if (name.length > 2 && cmd.includes(name)) return { reason: "it reads a data file directly", detail: name, text: `it reads ${name} directly` };
  if (INLINE_CODE.test(cmd) || HEREDOC_INTO_INTERPRETER.test(cmd)) return { reason: "it runs inline code that could read data files", text: "it runs inline code that could read data files" };
  if (INTERPRETERS.test(cmd)) {
    // An interpreter running a script from outside the folder (e.g. /tmp/x.py) can read anything here unseen.
    for (const m of cmd.matchAll(/(?:^|\s)((?:\/|~\/|\.\.\/)[^\s;&|'"]+\.(?:py|js|mjs|ts|rb|pl|php|r|jl|sql|jq|awk))\b/gi)) {
      const p = m[1]!.startsWith("~/") ? m[1]! : isAbsolute(m[1]!) ? m[1]! : resolve(root, m[1]!);
      if (p.startsWith("~/") || !(p === root || p.startsWith(root + "/")))
        return { reason: "it runs a script from outside this folder", detail: m[1]!, text: `it runs a script from outside this folder (${m[1]})` };
    }
  }
  return null;
}

/**
 * The data.block event's reason. With [events] command = "program" (the siem default) only the fixed reason, since the
 * detail is a file name or path the command field was coarsened to hide; otherwise the full text. Redacted either way.
 */
export function dataBlockEventReason(block: DataBlock, command: "full" | "program" | undefined, redact: (text: string) => string): string {
  return redact(command === "program" ? block.reason : block.text);
}
