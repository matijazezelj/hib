import { isAbsolute, resolve } from "node:path";

/**
 * Sensitive workspaces: shell commands that would read data files raw. Data goes to the agent only through the
 * Read tool, which hands it a pseudonymised copy. Returns why a command is blocked, or null.
 */
// JSON is data only when it's a table (passed in via dataFiles); package.json and friends stay readable.
const DATA_EXT = /\.(csv|tsv|jsonl|ndjson|xlsx?|parquet|sqlite3?)\b/i;
const DATA_GLOB = /\*[^\s]*\.(csv|tsv|jsonl|ndjson|xlsx?|parquet)\b/i;
// Programs that only list or count files, never print their contents.
const METADATA_ONLY = new Set(["ls", "find", "stat", "file", "du", "wc", "tree"]);
const INTERPRETERS = /(^|[\s;&|(])(python3?|node|bun|deno|ruby|perl|php|Rscript|julia|duckdb|sqlite3|jq|mlr|xsv|qsv|csvlook|csvcut|csvgrep|awk|gawk)\b/;
const INLINE_CODE = /(^|[\s;&|(])(python3?|node|bun|deno|ruby|perl|php|Rscript)\s+(-[a-zA-Z]*[ce]\b|-\s|<<)/;
const HEREDOC_INTO_INTERPRETER = /(python3?|node|bun|deno|ruby|perl|php|Rscript|duckdb|sqlite3)\s*<</;

export const DATA_RULE_NOTE =
  "This folder is marked sensitive. Read data files (CSV, TSV, JSON…) only with the Read tool: you will receive a pseudonymised copy " +
  "in which people, accounts, IPs and similar values are placeholders like [HIB…-USER-3]. Shell commands that read data files, inline scripts " +
  "(python -c, node -e, heredocs) and scripts written outside this folder are blocked. To compute something over a data file, read it with Read and reason over it, " +
  "or write a script inside this folder that the user can review.";

export function rawDataCommand(command: string, root: string, dataFiles: Set<string> = new Set()): string | null {
  const cmd = command.trim();
  const programs = cmd.split(/\s*(?:&&|\|\||[;|])\s*/).map((part) => part.trim().split(/\s+/)[0] ?? "");
  if (programs.every((p) => METADATA_ONLY.has(p)) && !/-exec|-execdir|-ok\b|-delete/.test(cmd)) return null;
  if (DATA_EXT.test(cmd) || DATA_GLOB.test(cmd)) return "it reads a data file directly";
  for (const name of dataFiles) if (name.length > 2 && cmd.includes(name)) return `it reads ${name} directly`;
  if (INLINE_CODE.test(cmd) || HEREDOC_INTO_INTERPRETER.test(cmd)) return "it runs inline code that could read data files";
  if (INTERPRETERS.test(cmd)) {
    // An interpreter running a script from outside the folder (e.g. /tmp/x.py) can read anything here unseen.
    for (const m of cmd.matchAll(/(?:^|\s)((?:\/|~\/|\.\.\/)[^\s;&|'"]+\.(?:py|js|mjs|ts|rb|pl|php|r|jl|sql|jq|awk))\b/gi)) {
      const p = m[1]!.startsWith("~/") ? m[1]! : isAbsolute(m[1]!) ? m[1]! : resolve(root, m[1]!);
      if (p.startsWith("~/") || !(p === root || p.startsWith(root + "/"))) return `it runs a script from outside this folder (${m[1]})`;
    }
  }
  return null;
}
