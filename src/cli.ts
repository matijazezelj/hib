#!/usr/bin/env bun
import { parseArgs } from "node:util";
import { hibHome } from "./config";
import * as plugins from "./plugins";

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
    file: { type: "string", short: "f" },
    hide: { type: "string" },
    keep: { type: "string" },
    yes: { type: "boolean", short: "y" },
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
        if (!id) throw new Error("no sessions in this folder");
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
      const { resolve } = await import("node:path");
      const list = (v: unknown) => (v ? String(v).split(",").map((s) => s.trim()) : []);
      const attachments = values.file ? [{ path: resolve(String(values.file)), hide: list(values.hide), keep: list(values.keep) }] : undefined;
      for await (const e of client.chat({ messages: [{ role: "user", content: prompt }], model: values.model, attachments })) {
        if (e.type === "meta") console.error(`[${e.cls} → ${e.model}]`);
        if (e.type === "guard" && Object.keys(e.findings).length) console.error(`[guard: ${e.action} ${JSON.stringify(e.findings)}]`);
        if (e.type === "approval") console.error(`[waiting for approval in the web UI or TUI: ${e.reasons.join("; ")}]`);
        if (e.type === "advisor") console.error(`\n[advisor ${e.model}: ${e.verdict}]`);
        if (e.type === "text") {
          if (e.part === "revision" && !revising) {
            revising = true;
            process.stdout.write("\n\n--- revised after review ---\n\n");
          }
          process.stdout.write(e.delta);
        }
        if (e.type === "error") {
          console.error(`\nerror: ${e.message}`);
          failed = true;
        }
      }
      process.stdout.write("\n");
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
    case "analyze":
    case "analyse":
      return analyzeCmd(rest[0], rest.slice(1).join(" "));
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

async function confirm(q: string): Promise<boolean> {
  if (values.yes) return true;
  if (!process.stdin.isTTY) return false;
  process.stdout.write(`${q} [y/N] `);
  for await (const line of console) return /^y(es)?$/i.test(line.trim());
  return false;
}

/** Arrays of flat objects print as an aligned table; anything else as JSON. */
function printResult(result: unknown) {
  if (Array.isArray(result) && result.length && result.every((r) => r && typeof r === "object" && !Array.isArray(r))) {
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

async function analyzeCmd(file: string | undefined, question: string) {
  if (!file || !question) throw new Error('usage: hib analyze <file.csv|tsv|json|jsonl> "question" [-m model] [--share col,col] [-y]');
  const { resolve } = await import("node:path");
  const { ensureDaemon } = await import("./boot");
  const { client } = await ensureDaemon();
  const path = resolve(file);
  const share = values.share ? String(values.share).split(",").map((s) => s.trim()) : [];
  const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;

  console.log(dim("profiling locally and asking for analysis code…"));
  let plan = await client.post("/hib/analyze/plan", { path, question, model: values.model, share });
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
  if (pv.leaks?.length) console.log(`\x1b[33m\n⚠ the result contains real values from identifying columns: ${pv.leaks.join(", ")}\x1b[0m`);
  console.log(dim(`\nTo interpret this, hib would send the question, the code and the result above (${preview.length} characters, through the guard). The table itself stays here.`));
  if (!(await confirm("Send the result for interpretation?"))) return;
  const ex = await client.post("/hib/analyze/explain", { id: plan.id });
  console.log(`\n${ex.answer}`);
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
