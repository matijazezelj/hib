#!/usr/bin/env bun
import { parseArgs } from "node:util";
import { hibHome } from "./config";
import * as plugins from "./plugins";
import { bold, BoldStream } from "./tui/bold";

const HELP = `hib — harness in a box

  hib                         terminal coding agent for this folder (shared with the web UI)
  hib --resume [id]           resume a session in this folder (picker if no id)
  hib serve                   open this folder in the web workspace; runs the daemon in the
                              foreground if none is running (web UI + OpenAI-compatible API)
  hib chat [--resume [id]]    multi-model router chat in the terminal
  hib daemon status|stop      the shared background daemon (logs: ~/.hib/daemon.log)
  hib workspace list|forget [dir]   folders agents may work in
  hib workspace sensitive --account claude@work [--model m] [dir]
                              pin a folder to one account: no handoff/failover/advisor/arena,
                              no browser terminal, secrets blocked, every read needs approval
  hib workspace normal [dir]  lift that
  hib workspace egress [session]    what left the machine in a session (default: latest here)
  hib guard ner setup|status|off    local name/place/company detection (one-time ~180 MB model download)
  hib geo setup                     offline gazetteer for hib analyze (GeoNames cities/countries, ~3 MB download)
  hib egress [last|id] [--here]     what router requests (ask, chat, analyze, API) sent, and to whom
  hib ask "prompt" [-m model] one-shot answer on stdout
  hib ask -f data.csv "question" [--hide col,col] [--keep col,col]
                              attach a table pseudonymised by column (identifying columns become
                              stable tokens; the answer comes back with real values)
  hib analyze <file> "question" [-m model] [--share col,col] [-y]
                              analyse a CSV/TSV/JSON locally: the model sees only the schema and
                              writes code; you approve it; it runs here in a sandbox
  hib conversations           list saved conversations
  hib usage                   quota per account
  hib stats                   learned scores per task class
  hib plugin install <git-url | https://…/x.md | path>
  hib plugin list | trust <name> | update <name> | remove <name>

Models: hib/auto, hib/chat, hib/code, hib/review, hib/agent/<name>, or <provider>[@account]/<model>.
Config: ~/.hib/config.toml   API token: ~/.hib/token`;

const argv = process.argv.slice(2);
const { values, positionals } = parseArgs({
  args: argv,
  allowPositionals: true,
  strict: false,
  options: {
    port: { type: "string" },
    model: { type: "string", short: "m" },
    resume: { type: "boolean", short: "r" },
    account: { type: "string" },
    share: { type: "string" },
    here: { type: "boolean" },
    file: { type: "string", short: "f" },
    hide: { type: "string" },
    keep: { type: "string" },
    yes: { type: "boolean", short: "y" },
    "show-sent": { type: "boolean" },
    help: { type: "boolean", short: "h" },
  },
});
const [cmd, ...rest] = positionals;

async function main() {
  if (values.help || cmd === "help") return console.log(HELP);
  if (values.resume && cmd !== "chat") {
    // `hib --resume [id]`: a workspace session in this folder
    return agent(cmd ?? true);
  }

  switch (cmd) {
    case "serve": {
      const b = await import("./boot");
      const { eligible } = await import("./workspace/registry");
      const here = eligible(process.cwd());
      const { client, url } = b.daemonClient();
      const running = await b.daemonUp(client);
      if (!running) {
        const s = await b.serve(values.port ? Number(values.port) : undefined);
        console.log(`hib daemon listening on ${s.url}`);
        console.log(`  OpenAI API:  ${s.url}/v1  (api key: contents of ${s.home}/token)`);
        for (const w of s.engine.plugins.warnings) console.log(`  plugin: ${w}`);
      }
      if (here.ok) {
        const root = await b.registerWorkspace(client, here.root);
        console.log(`  workspace:   ${b.workspaceUrl(url, root)}`);
      } else console.log(`  ${here.why}; open ${url}/ for router chat`);
      if (running && here.ok) console.log(`(daemon already running at ${url}; this folder is now available there)`);
      return;
    }
    case "daemon": {
      const b = await import("./boot");
      const sub = rest[0] ?? "status";
      if (sub === "run") {
        const s = await b.serve(values.port ? Number(values.port) : undefined);
        console.log(`[${new Date().toISOString()}] hib daemon listening on ${s.url}`);
        return;
      }
      const { client, url } = b.daemonClient();
      const up = await b.daemonUp(client);
      if (sub === "status") {
        if (!up) return console.log("daemon not running");
        console.log(`daemon running at ${url}`);
        for (const w of await client.get("/hib/workspaces")) console.log(`  ${w.root}`);
      } else if (sub === "stop") {
        if (!up) return console.log("daemon not running");
        await client.post("/hib/shutdown", {});
        // Wait until it's really gone, so an immediate `hib` starts a fresh daemon instead of finding this one.
        for (let i = 0; i < 50 && (await b.daemonUp(client)); i++) await Bun.sleep(100);
        console.log("daemon stopped");
      } else if (sub === "start") {
        const d = await b.ensureDaemon();
        console.log(d.started ? `daemon started at ${d.url}` : `daemon already running at ${d.url}`);
      } else throw new Error(`unknown daemon command ${sub}`);
      return;
    }
    case "workspace": {
      const b = await import("./boot");
      const { client } = await b.ensureDaemon();
      const sub = rest[0] ?? "list";
      const dir = rest[1] ?? process.cwd();
      if (sub === "forget") {
        await client.del(`/hib/workspaces?root=${encodeURIComponent(dir)}`);
        console.log("forgotten");
      } else if (sub === "sensitive") {
        if (!values.account) {
          const info = await client.get("/hib/info");
          const accounts = [...new Set((info.models as string[]).filter((m) => /^(claude|codex)@/.test(m)).map((m) => m.split("/")[0]))];
          throw new Error(`choose the one account this folder may use: --account ${accounts.join(" | ")}`);
        }
        const root = await b.registerWorkspace(client, dir);
        await client.post("/hib/workspaces/policy", { root, policy: { account: values.account, model: values.model } });
        console.log(`${root} is sensitive: only ${values.account} sees it; no handoff, failover, advisor, arena or browser terminal; secrets blocked; every read asks.`);
        if (String(values.account).startsWith("codex@"))
          console.log("note: Codex runs read-only commands like cat/ls/grep without asking, so reads can't be gated there. Prefer a Claude account for sensitive folders.");
      } else if (sub === "normal") {
        // Written straight to the database: the HTTP API refuses to lift a policy.
        const { openDb } = await import("./db");
        const { loadConfig } = await import("./config");
        const { Workspaces } = await import("./workspace/registry");
        const root = new Workspaces(openDb(hibHome()), loadConfig()).setPolicy(dir, null);
        console.log(`${root} is a normal workspace again (running sessions switch on their next turn)`);
      } else if (sub === "egress") {
        const { eligible } = await import("./workspace/registry");
        const here = eligible(process.cwd());
        if (!here.ok) throw new Error(here.why);
        const q = `root=${encodeURIComponent(here.root)}`;
        const id = rest[1] ?? (await client.get(`/ws/sessions?${q}`))[0]?.id;
        if (!id) throw new Error("no agent sessions in this folder. For hib ask / hib chat / analyze, use: hib egress (or hib egress --here)");
        for (const t of await client.get(`/ws/egress/${id}?${q}`)) {
          console.log(`\n→ ${t.account} (${t.model})${t.handoff ? " + handoff transcript" : ""}`);
          console.log(`  prompt: ${t.prompt.replace(/\s+/g, " ").slice(0, 200)}`);
          if (t.guard) console.log(`  guard:  ${t.guard}`);
          for (const a of t.actions) console.log(`  ${a.status.padEnd(9)} ${a.kind.padEnd(7)} ${a.title}`);
        }
      } else
        for (const w of await client.get("/hib/workspaces"))
          console.log(`${new Date(w.added).toLocaleDateString()}  ${w.root}${w.policy ? `  [sensitive → ${w.policy.account}]` : ""}`);
      return;
    }
    case "chat": {
      const { runTui } = await import("./tui/App");
      return runTui({ resume: values.resume ? (rest[0] ?? true) : undefined, model: values.model as string | undefined });
    }
    case "ask": {
      const { connect } = await import("./boot");
      const prompt = rest.join(" ") || (await Bun.stdin.text());
      const { client } = await connect();
      let failed = false;
      let revising = false;
      const tty = !!process.stdout.isTTY;
      const bolder = new BoldStream();
      const { resolve } = await import("node:path");
      const list = (v: unknown) => (v ? String(v).split(",").map((s) => s.trim()) : []);
      const attachments = values.file ? [{ path: resolve(String(values.file)), hide: list(values.hide), keep: list(values.keep) }] : undefined;
      // cwd: a sensitive folder's pin applies to asks from inside it, and `hib egress --here` can find them.
      for await (const e of client.chat({ messages: [{ role: "user", content: prompt }], model: values.model, attachments, cwd: process.cwd() })) {
        if (e.type === "meta") console.error(`[${e.cls} → ${e.model}]`);
        if (e.type === "guard" && Object.keys(e.findings).length) console.error(`[guard: ${e.action} ${JSON.stringify(e.findings)}]`);
        if (e.type === "approval") {
          // Answer the guard here when there's a terminal; otherwise the web UI or TUI can.
          if (!process.stdin.isTTY) {
            console.error(`[waiting for approval in the web UI or TUI: ${e.reasons.join("; ")}]`);
            continue;
          }
          const shown = e.redacted.length > 1500 ? `${e.redacted.slice(0, 1500)}\n… (${e.redacted.length - 1500} more characters)` : e.redacted;
          console.error(`\n\x1b[33mguard: ${e.reasons.join("; ")}\x1b[0m\nThis is exactly what would be sent:\n\x1b[2m${shown}\x1b[0m\n`);
          const ok = await confirm("Send it?");
          await client.post(`/hib/approvals/${e.id}`, { approve: ok });
        }
        if (e.type === "advisor") console.error(`\n[advisor ${e.model}: ${e.verdict}]`);
        if (e.type === "text") {
          if (e.part === "revision" && !revising) {
            revising = true;
            process.stdout.write("\n\n--- revised after review ---\n\n");
          }
          process.stdout.write(tty ? bolder.feed(e.delta) : e.delta);
        }
        if (e.type === "error") {
          console.error(`\nerror: ${e.message}`);
          failed = true;
        }
      }
      process.stdout.write((tty ? bolder.flush() : "") + "\n");
      process.exitCode = failed ? 1 : 0;
      return;
    }
    case "conversations":
    case "usage":
    case "stats": {
      const { connect } = await import("./boot");
      const { client } = await connect();
      if (cmd === "conversations") for (const c of await client.get("/hib/conversations")) console.log(`${c.id}  ${new Date(c.updated).toLocaleString()}  ${c.last_model ?? "-"}  ${c.title}`);
      if (cmd === "usage")
        for (const u of await client.get("/hib/usage"))
          console.log(`${u.account.padEnd(20)} ${u.windows.map((w: any) => `${w.window} ${Math.round(w.usedPct * 100)}%`).join("  ") || "no data"}${u.cooldownUntil ? `  cooling down until ${new Date(u.cooldownUntil).toLocaleTimeString()}` : ""}`);
      if (cmd === "stats") for (const s of (await client.get("/hib/stats")).scores) console.log(`${s.class.padEnd(8)} ${s.model.padEnd(28)} ${(s.mean * 100).toFixed(0).padStart(3)}  (α ${s.alpha.toFixed(1)} β ${s.beta.toFixed(1)})`);
      return;
    }
    case "plugin":
      return pluginCmd(rest);
    case "egress":
      return egressCmd(rest[0]);
    case "geo": {
      if (rest[0] !== "setup") throw new Error("usage: hib geo setup");
      const { setupGeo } = await import("./analyze/geo");
      console.log("downloading GeoNames cities (pop. > 15k) and country info…");
      const g = await setupGeo(hibHome());
      console.log(`installed: ${g.cities.length} cities, ${g.countries.length} countries. hib analyze can now use geo.locate / geo.km / geo.kmh.`);
      return;
    }
    case "guard":
      if (rest[0] !== "ner") throw new Error("usage: hib guard ner setup|status|off");
      return nerCmd(rest[1] ?? "status");
    case "analyze":
    case "analyse":
    {
      // Leading arguments that are table files (a shell glob like investigation-*.csv expands to several) are
      // the input; everything after is the question.
      const { existsSync } = await import("node:fs");
      const { TABLE_FILE } = await import("./analyze/table");
      const files: string[] = [];
      while (files.length < rest.length && TABLE_FILE.test(rest[files.length]!) && existsSync(rest[files.length]!)) files.push(rest[files.length]!);
      return analyzeCmd(files, rest.slice(files.length).join(" "));
    }
    case undefined:
      return agent();
    default:
      console.error(`unknown command ${cmd}\n\n${HELP}`);
      process.exitCode = 2;
  }
}

/** `hib` in a folder: the terminal agent; elsewhere (home, /) the router chat. */
async function agent(resume?: string | true) {
  const { eligible } = await import("./workspace/registry");
  const here = eligible(process.cwd());
  if (!here.ok) {
    console.log(`${here.why}. Opening router chat instead (hib chat).`);
    const { runTui } = await import("./tui/App");
    return runTui({ model: values.model as string | undefined });
  }
  const { runAgent } = await import("./tui/Agent");
  return runAgent({ dir: here.root, resume, model: values.model as string | undefined });
}

/** Sets `ner = …` in the [guard] section of config.toml, adding the line if an older config lacks it. */
function setNerFlag(on: boolean) {
  const { readFileSync, writeFileSync } = require("node:fs") as typeof import("node:fs");
  const file = `${hibHome()}/config.toml`;
  let s = readFileSync(file, "utf8");
  if (/^ner\s*=.*$/m.test(s)) s = s.replace(/^ner\s*=.*$/m, `ner = ${on}                     # local name/place/company detection`);
  else if (/^\[guard\]\s*$/m.test(s)) s = s.replace(/^\[guard\]\s*$/m, `[guard]\nner = ${on}                     # local name/place/company detection`);
  else s += `\n[guard]\nner = ${on}\n`;
  writeFileSync(file, s);
}

async function nerCmd(sub: string) {
  const { join } = await import("node:path");
  const { NerModel, nerFindings, NER_MODEL, NER_REVISION } = await import("./guard/ner");
  const { loadConfig } = await import("./config");
  const model = new NerModel(join(hibHome(), "models"));
  if (sub === "off") {
    setNerFlag(false);
    return console.log("name detection off. Restart the daemon: hib daemon stop");
  }
  if (sub === "status") {
    const on = loadConfig().guard.ner;
    const ok = await model.load(false).then(() => true, () => false);
    return console.log(`name detection: ${on ? "on" : "off"}; model ${ok ? "installed" : "not installed"} (${NER_MODEL}@${NER_REVISION.slice(0, 8)})`);
  }
  if (sub !== "setup") throw new Error("usage: hib guard ner setup|status|off");
  console.log(`downloading ${NER_MODEL} @ ${NER_REVISION.slice(0, 8)} into ${join(hibHome(), "models")} (once, ~300 MB)…`);
  const t0 = Date.now();
  await model.load(true);
  const sample = "Ask Marija Horvat from Podravka d.d. whether Ivan Kovačević is still in Zagreb; the build uses Redis and Postgres.";
  const found = await nerFindings(sample, model.infer);
  console.log(`self-test (${Date.now() - t0} ms): ${found.map((f) => `${f.category}:${f.value}`).join(", ")}`);
  if (!found.some((f) => f.value === "Marija Horvat") || found.some((f) => /Redis|Postgres/.test(f.value))) throw new Error("self-test failed; leaving name detection off");
  setNerFlag(true);
  console.log("name detection on. Restart the daemon to use it: hib daemon stop");
}

async function egressCmd(which?: string) {
  const { ensureDaemon } = await import("./boot");
  const { client } = await ensureDaemon();
  const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
  if (which) {
    const r = await client.get(`/hib/egress/${which}`);
    console.log(`#${r.id}  ${new Date(r.ts).toLocaleString()}  → ${r.model} (${r.part})  ${r.chars} chars${r.guard ? `\nguard: ${r.guard}` : ""}\n`);
    console.log(r.text);
    return;
  }
  const { realpathSync } = await import("node:fs");
  const rows = await client.get(`/hib/egress?limit=30${values.here ? `&cwd=${encodeURIComponent(realpathSync(process.cwd()))}` : ""}`);
  if (!rows.length) return console.log("nothing sent yet" + (values.here ? " from this folder" : ""));
  for (const r of rows) {
    const user = /<user>\n([\s\S]*)/.exec(r.head)?.[1] ?? r.head;
    console.log(`#${String(r.id).padEnd(5)} ${new Date(r.ts).toLocaleTimeString()}  → ${r.model.padEnd(28)} ${r.part.padEnd(10)} ${String(r.chars).padStart(7)} chars  ${dim(user.replace(/\s+/g, " ").slice(0, 70))}`);
    if (r.guard) console.log(dim(`        guard: ${r.guard}`));
  }
  console.log(dim(`\nfull text of one: hib egress <id>   ·   latest: hib egress last`));
}

/** y/N question. A fresh readline per question: returning out of `for await (… of console)` closes stdin for good. */
async function confirm(q: string): Promise<boolean> {
  if (values.yes) return true;
  if (!process.stdin.isTTY) return false;
  const { createInterface } = await import("node:readline");
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await new Promise<string>((resolve) => {
      rl.question(`${q} [y/N] `, resolve);
      rl.once("close", () => resolve(""));
    });
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

const isRowList = (v: unknown): v is Record<string, unknown>[] => Array.isArray(v) && v.length > 0 && v.every((r) => r && typeof r === "object" && !Array.isArray(r));

/** Readable output: tables for lists of rows, "key  value" lines for summaries, sections for nested objects. */
function printResult(result: unknown, depth = 0) {
  if (result && typeof result === "object" && !Array.isArray(result) && !isRowList(result)) {
    const entries = Object.entries(result as Record<string, unknown>);
    const scalars = entries.filter(([, v]) => v === null || typeof v !== "object");
    const w = Math.max(0, ...scalars.map(([k]) => k.length));
    for (const [k, v] of scalars) console.log(`${"  ".repeat(depth)}${k.padEnd(w)}  ${v}`);
    for (const [k, v] of entries.filter(([, v]) => v !== null && typeof v === "object")) {
      console.log(`\n${"  ".repeat(depth)}\x1b[1m${k}\x1b[0m${Array.isArray(v) ? ` (${v.length})` : ""}`);
      printResult(v, depth + 1);
    }
    return;
  }
  if (isRowList(result)) {
    const cols = [...new Set(result.flatMap((r) => Object.keys(r)))];
    const cell = (v: unknown) => (v === null || v === undefined ? "" : typeof v === "number" ? (Number.isInteger(v) ? String(v) : v.toFixed(2)) : typeof v === "object" ? JSON.stringify(v) : String(v));
    const rows = result.slice(0, 100).map((r: any) => cols.map((c) => cell(r[c])));
    const w = cols.map((c, i) => Math.min(40, Math.max(c.length, ...rows.map((r) => r[i]!.length))));
    const line = (xs: string[]) => xs.map((x, i) => (x.length > w[i]! ? x.slice(0, w[i]! - 1) + "…" : x.padEnd(w[i]!))).join("  ");
    console.log(line(cols));
    console.log(w.map((n) => "─".repeat(n)).join("  "));
    for (const r of rows) console.log(line(r));
    if (result.length > 100) console.log(`… ${result.length - 100} more rows`);
  } else console.log(JSON.stringify(result, null, 2));
}

async function analyzeCmd(files: string[], question: string) {
  if (!files.length || !question) throw new Error('usage: hib analyze <file.csv|tsv|json|jsonl>… "question" [-m model] [--share col,col] [-y]');
  const { resolve } = await import("node:path");
  const { ensureDaemon } = await import("./boot");
  const { client } = await ensureDaemon();
  const path = resolve(files[0]!);
  const paths = files.map((f) => resolve(f));
  if (paths.length > 1) console.log(`\x1b[2mcombining ${paths.length} files into one table (column source_file): ${files.join(", ")}\x1b[0m`);
  const share = values.share ? String(values.share).split(",").map((s) => s.trim()) : [];
  if (values.keep || values.hide)
    console.log(`\x1b[2mnote: analyze never sends rows, so --keep/--hide don't apply. Use --share col to give the model a column's distinct values, or hib ask -f to send rows.\x1b[0m`);
  const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;

  console.log(dim("profiling locally and asking for analysis code…"));
  let plan = await client.post("/hib/analyze/plan", { path, paths, question, model: values.model, share });
  const withheld = plan.profile.columns.filter((c: any) => c.identifying).map((c: any) => c.name);
  const shared = plan.profile.columns.filter((c: any) => c.values).map((c: any) => c.name);
  console.log(`\nSent to ${plan.model ?? "model"}: the schema of ${plan.profile.rows} rows × ${plan.profile.columns.length} columns and 3 synthetic rows. No real values${shared.length ? ` except the distinct values of: ${shared.join(", ")}` : ""}.`);
  if (withheld.length) console.log(dim(`identifying columns (never shared): ${withheld.join(", ")}`));
  if (!plan.code) throw new Error(`the model didn't return an analyze() function:\n${plan.raw ?? ""}`);

  for (let attempt = 0; ; attempt++) {
    console.log(`\n${dim("── code to run locally ──")}\n${plan.code}\n${dim("──")}${plan.note ? `\n${dim(plan.note)}` : ""}`);
    if (!(await confirm("Run this locally (sandboxed: no network, no file access)?"))) return console.log("not run");
    const r = await client.post("/hib/analyze/run", { id: plan.id });
    console.log(dim(`\nran in ${r.ms} ms · ${r.sandbox === "macos-sandbox" ? "macOS sandbox" : "isolated process (no OS sandbox on this platform)"}\n`));
    if (r.ok) {
      printResult(r.result);
      break;
    }
    console.log(`\x1b[31m${r.error}\x1b[0m`);
    if (attempt >= 2 || !(await confirm("Ask the model to fix it? (sends the error message above)"))) return;
    plan = { ...plan, ...(await client.post("/hib/analyze/fix", { id: plan.id })) };
  }

  const pv = await client.post("/hib/analyze/explain", { id: plan.id, preview: true });
  const preview = pv.sent as string;
  if (pv.leaks?.length) console.log(`\n\x1b[33mThe result contains values from identifying columns (${pv.leaks.join(", ")}); they go out as tokens and come back restored.\x1b[0m`);
  console.log(dim(`\nTo interpret this, hib would send the question, the code and the result (${preview.length} characters, through the guard). The table itself stays here. Exact text: rerun with --show-sent.`));
  if (values["show-sent"]) console.log(`\n${preview}\n`);
  if (!(await confirm("Send the result for interpretation?"))) return;
  const ex = await client.post("/hib/analyze/explain", { id: plan.id });
  console.log(`\n${process.stdout.isTTY ? bold(ex.answer) : ex.answer}`);
}

async function pluginCmd([sub, arg]: string[]) {
  const home = hibHome();
  switch (sub) {
    case "install": {
      if (!arg) throw new Error("usage: hib plugin install <source>");
      const r = await plugins.install(home, arg);
      console.log(`installed ${r.name}${r.sha ? ` @ ${r.sha.slice(0, 12)}` : ""}`);
      if (r.code.length) {
        console.log(`\nThis plugin contains code that would run with your permissions:\n${r.code.map((f) => `  ${f}`).join("\n")}`);
        console.log(`Review it in ${plugins.pluginsDir(home)}/${r.name}, then run: hib plugin trust ${r.name}`);
      }
      break;
    }
    case "trust": {
      const r = plugins.trust(home, arg!);
      console.log(`trusted ${arg} @ ${r.sha?.slice(0, 12)}; code files: ${r.code.join(", ") || "none"}`);
      break;
    }
    case "update": {
      const r = await plugins.update(home, arg!);
      if (r.from === r.to) console.log(`${arg} is up to date`);
      else console.log(`${arg}: ${r.from?.slice(0, 12)} → ${r.to?.slice(0, 12)}`);
      if (r.codeDiff) console.log(`\nCode changed — review before trusting again:\n\n${r.codeDiff}`);
      if (r.untrusted) console.log(`\ncode is NOT loaded until: hib plugin trust ${arg}`);
      break;
    }
    case "remove":
      plugins.remove(home, arg!);
      console.log(`removed ${arg}`);
      break;
    case "list":
    case undefined:
      for (const p of plugins.list(home)) console.log(`${p.name.padEnd(24)} ${String(p.sha ?? "").padEnd(12)} md:${p.md} code:${p.code}${p.code ? (p.trusted ? " (trusted)" : " (NOT trusted)") : ""}  ${p.source}`);
      break;
    default:
      throw new Error(`unknown plugin command ${sub}`);
  }
}

main().catch((e) => {
  console.error(`hib: ${e.message ?? e}`);
  process.exit(1);
});
