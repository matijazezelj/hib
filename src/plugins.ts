import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import type { Config, Mode, Route } from "./config";
import type { Level } from "./guard/detectors";
import type { Provider } from "./providers/types";

export interface Skill { name: string; description?: string; template: string; model?: string; mode?: Mode; plugin: string }
export interface Agent { name: string; description?: string; system: string; model?: string; route?: string; mode?: Mode; level?: Level; advisor?: boolean; plugin: string }
export interface RoutePlugin { name: string; route: Route; keywords: string[]; plugin: string }
export interface GuardPattern { category: string; regex: string; flags?: string }
export interface AdvisorChecklist { classes: string[]; text: string; plugin: string }

export interface Plugins {
  skills: Map<string, Skill>;
  agents: Map<string, Agent>;
  routes: RoutePlugin[];
  guardTerms: string[];
  guardPatterns: GuardPattern[];
  askOn: string[];
  advisor: AdvisorChecklist[];
  providers: Provider[];
  warnings: string[];
}

interface LockEntry {
  source: string;
  sha?: string; // pinned commit for git sources
  trustedSha?: string; // code runs only while this equals sha
  installed: number;
}
type Lock = Record<string, LockEntry>;

const CODE_FILE = /\.provider\.(ts|js)$/;

export const pluginsDir = (home: string) => join(home, "plugins");
const lockFile = (home: string) => join(home, "plugins.json");

export function readLock(home: string): Lock {
  try {
    return JSON.parse(readFileSync(lockFile(home), "utf8"));
  } catch {
    return {};
  }
}
function writeLock(home: string, lock: Lock) {
  writeFileSync(lockFile(home), JSON.stringify(lock, null, 2), { mode: 0o600 });
}

export function parseFrontmatter(text: string): { meta: Record<string, any>; body: string } {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  if (!m) return { meta: {}, body: text };
  return { meta: (Bun.YAML.parse(m[1]!) as any) ?? {}, body: m[2]!.trim() };
}

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    if (n === ".git" || n === "node_modules") continue;
    const p = join(dir, n);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

const isMd = (p: string) => p.endsWith(".md") && !/^(readme|license|changelog|contributing)\.md$/i.test(basename(p));

export function codeFiles(dir: string): string[] {
  return walk(dir).filter((p) => CODE_FILE.test(p)).map((p) => relative(dir, p));
}

function addMd(file: string, plugin: string, acc: Plugins) {
  const { meta, body } = parseFrontmatter(readFileSync(file, "utf8"));
  const name = String(meta.name ?? basename(file, ".md"));
  switch (meta.kind) {
    case "skill":
      acc.skills.set(name, { name, description: meta.description, template: body, model: meta.model, mode: meta.mode, plugin });
      break;
    case "agent":
      acc.agents.set(name, { name, description: meta.description, system: body, model: meta.model, route: meta.route, mode: meta.mode, level: meta.level, advisor: meta.advisor, plugin });
      break;
    case "route":
      acc.routes.push({
        name,
        plugin,
        keywords: meta.keywords ?? [],
        route: { candidates: meta.candidates ?? [], mode: meta.mode === "agent" ? "agent" : "chat", advisor: !!meta.advisor, level: meta.level ?? "standard", ask: !!meta.ask },
      });
      break;
    case "guard":
      acc.guardTerms.push(...(meta.terms ?? []));
      acc.askOn.push(...(meta.askOn ?? []));
      for (const p of meta.patterns ?? []) {
        try {
          new RegExp(p.regex, p.flags ?? "g");
          acc.guardPatterns.push({ category: String(p.category).toUpperCase(), regex: p.regex, flags: p.flags });
        } catch {
          acc.warnings.push(`${plugin}: bad regex ${p.regex}`);
        }
      }
      break;
    case "advisor":
      acc.advisor.push({ classes: meta.classes ?? ["code"], text: body, plugin });
      break;
    default:
      if (meta.kind) acc.warnings.push(`${plugin}: unknown kind "${meta.kind}" in ${basename(file)}`);
  }
}

export async function loadPlugins(home: string): Promise<Plugins> {
  const acc: Plugins = { skills: new Map(), agents: new Map(), routes: [], guardTerms: [], guardPatterns: [], askOn: [], advisor: [], providers: [], warnings: [] };
  const dir = pluginsDir(home);
  if (!existsSync(dir)) return acc;
  const lock = readLock(home);
  for (const name of readdirSync(dir)) {
    const root = join(dir, name);
    if (!statSync(root).isDirectory()) continue;
    for (const f of walk(root).filter(isMd)) {
      try {
        addMd(f, name, acc);
      } catch (e: any) {
        acc.warnings.push(`${name}: ${basename(f)}: ${e.message}`);
      }
    }
    const code = codeFiles(root);
    if (!code.length) continue;
    const entry = lock[name];
    if (!entry?.trustedSha || entry.trustedSha !== entry.sha) {
      acc.warnings.push(`${name}: ${code.length} code file(s) not loaded; run \`hib plugin trust ${name}\` after reviewing`);
      continue;
    }
    for (const f of code) {
      const mod = await import(join(root, f));
      if (mod.default?.id && typeof mod.default.run === "function") acc.providers.push(mod.default);
      else acc.warnings.push(`${name}: ${f} has no default Provider export`);
    }
  }
  return acc;
}

/** Merge plugin routes and guard rules into config. Guard additions only ever tighten. */
export function applyPlugins(cfg: Config, p: Plugins): Config {
  const routes = { ...cfg.routes };
  for (const r of p.routes) routes[r.name] ??= r.route;
  return {
    ...cfg,
    routes,
    guard: {
      ...cfg.guard,
      terms: [...cfg.guard.terms, ...p.guardTerms],
      askOn: [...cfg.guard.askOn, ...p.askOn],
      patterns: [...cfg.guard.patterns, ...p.guardPatterns],
    },
  };
}

/** `/name args` -> expanded prompt, or null if not a skill. */
export function expandSkill(input: string, p: Plugins): { skill: Skill; prompt: string } | null {
  const m = /^\/([\w-]+)(?:\s+([\s\S]*))?$/.exec(input.trim());
  const skill = m && p.skills.get(m[1]!);
  if (!skill) return null;
  const args = m![2] ?? "";
  const prompt = skill.template.includes("{{args}}") ? skill.template.replaceAll("{{args}}", args) : `${skill.template}\n\n${args}`.trim();
  return { skill, prompt };
}

// ---------- install / update / trust ----------

async function sh(cmd: string[], cwd?: string): Promise<string> {
  const p = Bun.spawn(cmd, { cwd, stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = [await new Response(p.stdout).text(), await new Response(p.stderr).text(), await p.exited];
  if (code !== 0) throw new Error(`${cmd.join(" ")}: ${err.trim() || out.trim()}`);
  return out.trim();
}

const isGit = (s: string) => /^(git:\/\/|file:\/\/|git@|ssh:\/\/|https?:\/\/.*\.git$|https:\/\/(github|gitlab|codeberg)\.\w+\/[^/]+\/[^/]+\/?$)/.test(s);

export function nameFor(source: string): string {
  return basename(source.replace(/\/$/, "")).replace(/\.git$/, "").replace(/\.md$/, "").replace(/[^\w.-]/g, "-");
}

export async function install(home: string, source: string, name = nameFor(source)): Promise<{ name: string; code: string[]; sha?: string }> {
  const dir = join(pluginsDir(home), name);
  if (existsSync(dir)) throw new Error(`plugin ${name} already installed; use update or remove`);
  mkdirSync(pluginsDir(home), { recursive: true });
  let sha: string | undefined;
  if (isGit(source)) {
    await sh(["git", "clone", "--depth", "1", "--quiet", source, dir]);
    sha = await sh(["git", "rev-parse", "HEAD"], dir);
  } else if (/^https?:\/\//.test(source)) {
    const r = await fetch(source);
    if (!r.ok) throw new Error(`fetch ${source}: ${r.status}`);
    mkdirSync(dir);
    writeFileSync(join(dir, `${name}.md`), await r.text());
    sha = new Bun.CryptoHasher("sha256").update(readFileSync(join(dir, `${name}.md`))).digest("hex");
  } else {
    const src = resolve(source);
    mkdirSync(dir);
    if (statSync(src).isDirectory()) cpSync(src, dir, { recursive: true, filter: (p) => !p.includes("/.git/") && !p.includes("/node_modules/") });
    else cpSync(src, join(dir, basename(src)));
    sha = "local";
  }
  const lock = readLock(home);
  lock[name] = { source, sha, installed: Date.now() };
  writeLock(home, lock);
  return { name, code: codeFiles(dir), sha };
}

export function trust(home: string, name: string): { code: string[]; sha?: string } {
  const lock = readLock(home);
  const e = lock[name];
  if (!e) throw new Error(`no plugin ${name}`);
  e.trustedSha = e.sha;
  writeLock(home, lock);
  return { code: codeFiles(join(pluginsDir(home), name)), sha: e.sha };
}

/** Fetches the newest commit; if code files changed, trust is dropped and the diff returned for review. */
export async function update(home: string, name: string): Promise<{ from?: string; to?: string; codeDiff: string; untrusted: boolean }> {
  const lock = readLock(home);
  const e = lock[name];
  if (!e) throw new Error(`no plugin ${name}`);
  const dir = join(pluginsDir(home), name);
  if (!isGit(e.source)) {
    rmSync(dir, { recursive: true, force: true });
    delete lock[name];
    writeLock(home, lock);
    const r = await install(home, e.source, name);
    return { from: e.sha, to: r.sha, codeDiff: "", untrusted: r.code.length > 0 };
  }
  await sh(["git", "fetch", "--depth", "1", "--quiet", "origin"], dir);
  const to = await sh(["git", "rev-parse", "FETCH_HEAD"], dir);
  if (to === e.sha) return { from: e.sha, to, codeDiff: "", untrusted: false };
  await sh(["git", "fetch", "--quiet", "--deepen", "50", "origin"], dir).catch(() => {});
  const codeDiff = await sh(["git", "diff", `${e.sha}..${to}`, "--", "*.provider.ts", "*.provider.js"], dir).catch(() => "(diff unavailable: history too shallow, review the files)");
  await sh(["git", "checkout", "--quiet", to], dir);
  const from = e.sha;
  const hadTrust = e.trustedSha === e.sha;
  e.sha = to;
  if (hadTrust && !codeDiff) e.trustedSha = to; // only markdown changed
  writeLock(home, lock);
  return { from, to, codeDiff, untrusted: codeFiles(dir).length > 0 && e.trustedSha !== to };
}

export function remove(home: string, name: string) {
  rmSync(join(pluginsDir(home), name), { recursive: true, force: true });
  const lock = readLock(home);
  delete lock[name];
  writeLock(home, lock);
}

export function list(home: string) {
  const lock = readLock(home);
  return Object.entries(lock).map(([name, e]) => {
    const dir = join(pluginsDir(home), name);
    const exists = existsSync(dir);
    const code = exists ? codeFiles(dir) : [];
    const md = exists ? walk(dir).filter(isMd).length : 0;
    return { name, source: e.source, sha: e.sha?.slice(0, 12), md, code: code.length, trusted: !!e.trustedSha && e.trustedSha === e.sha };
  });
}
