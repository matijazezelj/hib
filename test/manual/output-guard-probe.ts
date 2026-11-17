/**
 * Re-run after a Claude Code upgrade: does hib's command-output guard still hold with this version?
 *
 *   bun test/manual/output-guard-probe.ts [model]     (default: haiku; uses your Claude login, a few cents)
 *
 * It starts Claude Code through hib's own ClaudeDriver as a sensitive session does (sandbox, capture folder, the output
 * hook registered over the control channel, every command wrapped) and has it run commands that print a marker held only
 * in a file: plain, failing (exit 3), killed (kill -9 of its shell), one that tries to close hib's subshell with `)`, one
 * from a subagent, and Read/Grep of a file left in the capture folder. The "guard" here swaps the marker for [GUARDED].
 * It checks that the session starts (Claude Code confirmed the hook), that the marker never reaches the model (tool
 * results, its answer) or Claude's transcript, and that the guarded form does.
 * Relies on the stream-json control protocol, which isn't a documented interface: this is what tells you it changed.
 * Checked on Linux (bubblewrap); on macOS it also tells you whether the capture folder works under Seatbelt.
 */
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { ClaudeDriver } from "../../src/workspace/claude-driver";

const model = process.argv[2] ?? "haiku";
const MARK = `PROBE-${crypto.randomUUID().slice(0, 8)}`;
const ws = realpathSync(mkdtempSync(join(tmpdir(), "hib-ogp-ws-")));
const cap = join(realpathSync(mkdtempSync(join(tmpdir(), "hib-ogp-cap-"))), "s");
mkdirSync(cap, { mode: 0o700 });
writeFileSync(join(ws, "marker.txt"), `the code is ${MARK}\n`);
writeFileSync(join(cap, "planted"), `the code is ${MARK}\n`); // as a killed command would leave it
Bun.spawnSync(["git", "init", "-q"], { cwd: ws });

const failures: string[] = [];
let outputs = 0, guarded = 0, nativeId = "";
const d = new ClaudeDriver();
const account = { id: "claude@probe", provider: "claude", name: "probe", env: {}, limits: {}, dirs: [] };
try {
  await d.start({ cwd: ws, model, account, askReads: true, sandbox: { denyRead: [] }, captureDir: cap } as any);
} catch (e: any) {
  console.log(`FAIL\n- the session didn't start: ${e?.message ?? e}`);
  process.exit(1);
}
const prompt =
  "Run these Bash commands, one tool call each, in order, and quote each output exactly: 1) cat marker.txt   2) cat marker.txt; exit 3   3) cat marker.txt; kill -9 $$   " +
  "4) this exact three-line command:\ntrue )\ncat marker.txt; exit 3\n( true\n   " +
  `5) use the Read tool on ${join(cap, "planted")} and the Grep tool for "code" in ${cap}   6) use the Agent tool (general-purpose subagent) to run \`cat marker.txt\` with Bash and report what it printed.`;
const timer = setTimeout(() => (failures.push("timed out after 6 minutes"), d.close()), 360_000);
for await (const e of d.turn(prompt)) {
  const seen = JSON.stringify(e);
  if (e.type === "session") nativeId = e.nativeId;
  if (e.type === "permission") d.answer(e.id, { behavior: "allow" });
  else if (e.type === "output") {
    outputs++;
    d.answerOutput(e.id, e.text.replaceAll(MARK, "[GUARDED]"));
  } else if (seen.includes(MARK)) failures.push(`raw marker reached the model in a ${e.type} event: ${seen.slice(0, 200)}`);
  if (e.type !== "output" && seen.includes("[GUARDED]")) guarded++;
}
clearTimeout(timer);
await d.close();

if (outputs < 4) failures.push(`only ${outputs} guarded outputs (expected at least 4: plain, exit 3, the ")" command, subagent)`);
if (!guarded) failures.push("the guarded output never reached the model");
const dir = join(process.env.CLAUDE_CONFIG_DIR ?? join(homedir(), ".claude"), "projects");
for (const p of existsSync(dir) ? readdirSync(dir) : [])
  for (const f of readdirSync(join(dir, p), { recursive: true }) as string[])
    if (nativeId && String(f).includes(nativeId) && String(f).endsWith(".jsonl") && readFileSync(join(dir, p, String(f)), "utf8").includes(MARK))
      failures.push(`raw marker in the transcript ${join(p, String(f))}`);
rmSync(ws, { recursive: true, force: true });
rmSync(join(cap, ".."), { recursive: true, force: true });

console.log(failures.length ? `FAIL\n- ${failures.join("\n- ")}` : `ok: the session started, ${outputs} outputs guarded, the marker never reached the model or the transcript`);
process.exit(failures.length ? 1 : 0);
