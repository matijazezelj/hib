#!/usr/bin/env bun
/**
 * Guard benchmark on synthetic data: `bun test/manual/bench.ts [rows] [--ner]`.
 * Generates a customer CSV and an ECS-style SIEM JSONL with planted values, times each guard stage, and counts the
 * planted values still readable afterwards. Name detection runs on a 500-row sample with --ner (needs `hib guard ner setup`).
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { columnsToHide, pseudonymize } from "../../src/analyze/pseudo";
import { loadTable, profile } from "../../src/analyze/table";
import { loadConfig } from "../../src/config";
import { obfuscateText, Vault } from "../../src/guard";
import { NerModel, nerFindings } from "../../src/guard/ner";

const N = Number(process.argv.find((a) => /^\d+$/.test(a)) ?? 10000);
const withNer = process.argv.includes("--ner");
const dir = mkdtempSync(join(tmpdir(), "hib-bench-"));
let seed = 42;
const rnd = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32);
const pick = <T>(a: T[]) => a[Math.floor(rnd() * a.length)]!;
const int = (n: number) => Math.floor(rnd() * n);

type Planted = Map<string, Set<string>>;
const plant = (p: Planted, kind: string, v: string) => (p.set(kind, (p.get(kind) ?? new Set()).add(v)), v);

function customers(): { text: string; planted: Planted } {
  const planted: Planted = new Map();
  const first = ["Ana", "Marko", "Ivana", "Luka", "Petra", "Tomislav", "Maja", "Dario", "Elena", "Nikola", "Sara", "Filip"];
  const last = ["Horvat", "Kovačević", "Babić", "Marić", "Novak", "Jurić", "Knežević", "Smith", "Müller", "Rossi"];
  const rows = ["customer_id,full_name,email,phone,city,ip_address,signup_date,plan,monthly_spend,notes"];
  for (let i = 0; i < N; i++) {
    const name = plant(planted, "name", `${pick(first)} ${pick(last)}`);
    const email = plant(planted, "email", `${name.toLowerCase().normalize("NFD").replace(/[^\x00-\x7f]/g, "").replace(" ", ".")}@example.com`);
    const note = pick([`Called ${name} about the renewal`, `follow up with ${name.toLowerCase()} next week`, "no notes"]);
    rows.push([`C${String(i + 1).padStart(6, "0")}`, name, email, plant(planted, "phone", `+385 9${int(10)} ${String(int(1e7)).padStart(7, "0")}`),
      pick(["Zagreb", "Split", "Rijeka", "Vienna"]), plant(planted, "IP", `10.${int(4)}.${int(255)}.${int(255)}`), "2025-03-01", pick(["free", "pro"]), (rnd() * 500).toFixed(2), `"${note}"`].join(","));
  }
  return { text: rows.join("\n") + "\n", planted };
}

function siem(): { text: string; planted: Planted } {
  const planted: Planted = new Map();
  const users = ["jdoe", "a.kovac", "mhorvat", "svc_backup", "ivana.babic", "tnovak"];
  const people = ["Ivana Babić", "Marko Horvat", "John Doe"];
  const lines: string[] = [];
  for (let i = 0; i < N; i++) {
    const u = plant(planted, "username", pick(users));
    const h = plant(planted, "hostname", pick(["WS-ZG-0142", "WS-ST-0007", "dc01.corp.acme.local", "LAPTOP-8KQ2M1"]));
    const person = plant(planted, "name only in message", pick(people));
    const ext = plant(planted, "public IP", pick(["185.220.101.34", "45.155.205.99"]));
    lines.push(JSON.stringify({
      "@timestamp": new Date(Date.UTC(2026, 9, 1) + i * 37_000).toISOString(),
      event: { category: pick(["authentication", "process", "network"]), outcome: pick(["success", "failure"]) },
      host: { name: h, ip: [plant(planted, "internal IP", `10.20.${int(8)}.${int(250) + 2}`)] },
      user: { name: u, domain: "CORP", id: plant(planted, "Windows SID", `S-1-5-21-3623811015-3361044348-30300820-${1000 + users.indexOf(u)}`), email: plant(planted, "email", `${u}@acme-corp.com`) },
      source: { ip: ext, port: 40000 + (i % 2000) },
      process: {
        command_line: pick([
          `net use \\\\fs02\\share /user:CORP\\${u} ${plant(planted, "password in command", `Hunter2!${i % 3}`)}`,
          `C:\\Users\\${u}\\AppData\\Local\\Temp\\upd.exe /silent`,
          "powershell -nop -w hidden",
          // sudo-style `python3 -c <base64>`: the script names a third party the model could decode and quote
          `/bin/python3 -c ${plant(planted, "encoded payload", Buffer.from(`print("lookup ${pick(["ana.kovac", "m.horvat", "jroe"])}@partner-corp.com for ${person}")`).toString("base64"))}`,
        ]),
      },
      url: { full: `https://portal.acme-corp.com/reset?token=${plant(planted, "URL token", `tok_${(1e9 + i).toString(36)}`)}` },
      message: `CORP\\${u} logon from ${ext} to ${h} (${person})`,
    }));
  }
  return { text: lines.join("\n") + "\n", planted };
}

const mb = () => process.memoryUsage().rss / 1e6;
async function stage<T>(label: string, fn: () => T | Promise<T>): Promise<T> {
  Bun.gc(true);
  const before = mb();
  const s = performance.now();
  const v = await fn();
  console.log(`  ${label.padEnd(40)} ${(performance.now() - s).toFixed(0).padStart(6)} ms   +${(mb() - before).toFixed(0)} MB`);
  return v;
}

const cfg = loadConfig();
try {
  for (const [file, gen] of [["customers.csv", customers], ["siem.jsonl", siem]] as const) {
    const { text, planted } = gen();
    const path = join(dir, file);
    writeFileSync(path, text);
    console.log(`\n${file}: ${N.toLocaleString()} rows, ${(text.length / 1e6).toFixed(1)} MB`);
    const table = await stage("load and parse", () => loadTable(path));
    const cols = await stage("pick identifying columns", () => columnsToHide(table));
    const vault = new Vault();
    await stage("pseudonymise by column", () => pseudonymize(table, cols, new Vault()));
    await stage("profile (all hib analyze sends)", () => profile(table, path));
    const out = await stage("... plus the regex guard on each text cell", () => pseudonymize(table, cols, vault, (t) => obfuscateText(vault, t, "standard", cfg)));
    console.log(`  hidden columns: ${cols.join(", ")}; output ${(out.length / 1e6).toFixed(1)}M chars`);
    for (const [kind, values] of planted) {
      const checked = [...values].slice(0, 500); // each check scans the whole output
      const left = checked.filter((v) => out.includes(v) || out.includes(JSON.stringify(v).slice(1, -1)));
      console.log(`  ${left.length ? "READABLE" : "hidden  "} ${kind.padEnd(20)} ${left.length}/${checked.length}${left.length ? `  e.g. ${left[0]}` : ""}`);
    }
    if (withNer && file.endsWith(".csv")) {
      const model = new NerModel(join(cfg.home, "models"));
      await stage("name model load", () => model.load());
      const sample = out.split("\n").slice(0, 501).join("\n");
      const s = performance.now();
      await stage("name detection, 500 rows", () => nerFindings(sample, model.infer));
      console.log(`  ≈ ${((performance.now() - s) / 500).toFixed(0)} ms a row`);
    }
  }
  console.log(`\npeak RSS ${(process.resourceUsage().maxRSS / 1024).toFixed(0)} MB (${process.platform}, bun ${Bun.version})`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
