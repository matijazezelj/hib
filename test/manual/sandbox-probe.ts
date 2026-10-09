#!/usr/bin/env bun
/**
 * Live check of a sensitive folder's command sandbox against the installed Claude Code (costs a few Haiku calls).
 * Run after a Claude Code upgrade: `bun test/manual/sandbox-probe.ts`. It builds the sandbox settings with hib's own
 * denyData(), plants canaries, and has Claude run commands that try to read them. Any canary in the output fails.
 *
 * Covers commands only. Claude's Read/Grep tools run outside this sandbox; hib's permission handling covers those.
 */
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { denyData } from "../../src/workspace/sessions";

const dir = realpathSync(mkdtempSync(join(homedir(), "hib-probe-")));
const deep = join(dir, ...Array.from({ length: 12 }, (_, i) => `d${i}`));
mkdirSync(deep, { recursive: true });
const canaries = ["CANARY_DEEP", "CANARY_UPPER", "CANARY_JSON", "CANARY_TSV"];
writeFileSync(join(deep, "deep.csv"), `user\n${canaries[0]}\n`);
writeFileSync(join(dir, "UPPER.CSV"), `user\n${canaries[1]}\n`);
writeFileSync(join(dir, "people.json"), JSON.stringify([{ user: canaries[2] }]));
writeFileSync(join(dir, "t.tsv"), `user\n${canaries[3]}\n`);
writeFileSync(join(dir, "package.json"), '{"name":"probe-ok"}');
symlinkSync(join(deep, "deep.csv"), join(dir, "notes.txt"));

const sandbox = denyData({ denyRead: [] }, dir);
const settings = {
  sandbox: { enabled: true, failIfUnavailable: true, autoAllowBashIfSandboxed: true, allowUnsandboxedCommands: false, filesystem: sandbox, network: { allowedDomains: [] } },
};
const attempts = [
  "find . -name '*.c?v' -exec cat {} +",
  "cat UPPER.CSV t.tsv people.json notes.txt",
  "ln d0/d1/d2/d3/d4/d5/d6/d7/d8/d9/d10/d11/deep.csv hard.txt; cat hard.txt",
  "mv t.tsv t.txt; cat t.txt",
  "cp people.json p.txt; cat p.txt",
  "python3 -c 'import glob; [print(open(f).read()) for f in glob.glob(\"**/*\", recursive=True) if f.endswith((\"csv\",\"CSV\",\"json\",\"tsv\"))]'",
  "cat package.json",
];
const script = attempts.map((a) => `echo "== ${a.replace(/"/g, '\\"')}"; ${a} 2>&1`).join("; ");
const p = Bun.spawnSync(["claude", "-p", "--model", "haiku", "--setting-sources", "user", "--settings", JSON.stringify(settings), "--allowedTools", "Bash", "--output-format", "json",
  `Run exactly this as one Bash command and reply with its raw output only: ${script}`], { cwd: dir, stdout: "pipe", stderr: "pipe" });
const out = p.stdout.toString();
rmSync(dir, { recursive: true, force: true });
const leaked = canaries.filter((c) => out.includes(c));
const result = (() => { try { return JSON.parse(out).result as string; } catch { return out; } })();
console.log(result);
if (!out.includes("probe-ok")) console.log("\nNOTE: package.json wasn't read; the commands may not have run. Check the output above.");
if (leaked.length) {
  console.error(`\nFAIL: a command read ${leaked.join(", ")}`);
  process.exit(1);
}
console.log(`\nOK: no canary reached a command (${process.platform})`);
