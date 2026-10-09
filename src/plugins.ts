import { cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, readlinkSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import type { Config, Mode, Route } from "./config";
import { stricterLevel, type Level } from "./guard/detectors";
import type { Provider } from "./providers/types";

export interface Skill { name: string; description?: string; template: string; model?: string; mode?: Mode; plugin: string }
interface Agent { name: string; description?: string; system: string; model?: string; route?: string; mode?: Mode; level?: Level; advisor?: boolean; plugin: string }
interface RoutePlugin { name: string; route: Route; keywords: string[]; plugin: string }
interface GuardPattern { category: string; regex: string; flags?: string }
interface AdvisorChecklist { classes: string[]; text: string; plugin: string }

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
  trustedSha?: string; // the commit you trusted
  trustedHash?: string; // fingerprint of the files you trusted; code and routes load only while the files on disk still match
  installed: number;
}
type Lock = Record<string, LockEntry>;

const CODE_FILE = /\.provider\.(ts|js)$/;

export const pluginsDir = (home: string) => join(home, "plugins");
const lockFile = (home: string) => join(home, "plugins.json");

function readLock(home: string): Lock {
  try {
    return JSON.parse(readFileSync(lockFile(home), "utf8"));
  } catch {
    return {};
  }
}
function writeLock(home: string, lock: Lock) {
  writeFileSync(lockFile(home), JSON.stringify(lock, null, 2), { mode: 0o600 });
}

function parseFrontmatter(text: string): { meta: Record<string, any>; body: string } {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  if (!m) return { meta: {}, body: text };
  return { meta: (Bun.YAML.parse(m[1]!) as any) ?? {}, body: m[2]!.trim() };
}

/**
 * Files in a plugin, symlinks included as entries but never followed (a link to `.` or `/` can't loop or wander).
 * Dependencies are skipped when looking for the plugin's own files, but counted for trust (`deps`).
 */
function walk(dir: string, out: string[] = [], deps = false): string[] {
  for (const n of readdirSync(dir)) {
    if (n === ".git" || (n === "node_modules" && !deps)) continue;
    const p = join(dir, n);
    const st = lstatSync(p);
    if (st.isDirectory()) walk(p, out, deps);
    else out.push(p);
  }
  return out;
}

/**
 * What trust is tied to: every file in the plugin (helpers a provider imports, node_modules, route files), by path and
 * content, symlinks by their target. Checked again before anything trusted loads, so an edited file on disk, or an
 * update that changed any of them, needs a fresh `hib plugin trust`.
 */
export function fingerprint(dir: string): string {
  const h = new Bun.CryptoHasher("sha256");
  for (const p of walk(dir, [], true).sort()) {
    const st = lstatSync(p);
    h.update(relative(dir, p)).update("\0");
    h.update(st.isSymbolicLink() ? `link:${readlinkSync(p)}` : st.isFile() ? readFileSync(p) : `special:${st.mode}`).update("\0");
  }
  return h.digest("hex");
}

const trusted = (e: LockEntry | undefined, dir: string) => !!e?.trustedHash && e.trustedSha === e.sha && e.trustedHash === fingerprint(dir);

const isMd = (p: string) => p.endsWith(".md") && !/^(readme|license|changelog|contributing)\.md$/i.test(basename(p));

function codeFiles(dir: string): string[] {
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
        // A route decides which account sees your prompts, so it's never looser than the default guard level.
        route: { candidates: meta.candidates ?? [], mode: meta.mode === "agent" ? "agent" : "chat", advisor: !!meta.advisor, level: stricterLevel(meta.level, "standard"), ask: !!meta.ask },
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
    if (!lstatSync(root).isDirectory()) continue;
    const isTrusted = trusted(lock[name], root);
    const routesBefore = acc.routes.length;
    for (const f of walk(root).filter(isMd)) {
      try {
        addMd(f, name, acc);
      } catch (e: any) {
        acc.warnings.push(`${name}: ${basename(f)}: ${e.message}`);
      }
    }
    // Routes send your prompts to the accounts they name: like code, they apply only once you've trusted the plugin.
    if (!isTrusted && acc.routes.length > routesBefore) {
      acc.routes.splice(routesBefore);
      acc.warnings.push(`${name}: route(s) not applied; they choose which account sees your prompts. Review, then \`hib plugin trust ${name}\``);
    }
    const code = codeFiles(root);
    if (!code.length) continue;
    if (!isTrusted) {
      acc.warnings.push(`${name}: ${code.length} code file(s) not loaded; ${lock[name]?.trustedSha && !lock[name]?.trustedHash ? "trust predates file fingerprints, so trust it again" : "its files changed since you trusted it, or it was never trusted"}. Review, then \`hib plugin trust ${name}\``);
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

function nameFor(source: string): string {
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
  e.trustedHash = fingerprint(join(pluginsDir(home), name));
  writeLock(home, lock);
  return { code: codeFiles(join(pluginsDir(home), name)), sha: e.sha };
}

/** Fetches the newest commit; if anything besides markdown docs changed, trust is dropped and the diff returned for review. */
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
  // Everything except markdown that isn't trust-gated: a provider's helpers, configs, and route files all count.
  // Each changed .md is judged by its new content (a deleted one counts as a doc).
  const changed = (await sh(["git", "diff", "--name-only", `${e.sha}..${to}`], dir).catch(() => "")).split("\n").filter(Boolean);
  const docs: string[] = [];
  for (const f of changed.filter((f) => f.endsWith(".md"))) {
    const next = await sh(["git", "show", `${to}:${f}`], dir).catch(() => null);
    let route = false;
    try {
      route = next !== null && parseFrontmatter(next).meta.kind === "route";
    } catch {
      route = true; // unparseable frontmatter: review it
    }
    if (!route) docs.push(f);
  }
  const codeDiff = await sh(["git", "diff", `${e.sha}..${to}`, "--", ".", ...docs.map((f) => `:(exclude)${f}`)], dir).catch(() => "(diff unavailable: history too shallow, review the files)");
  const hadTrust = trusted(e, dir);
  await sh(["git", "checkout", "--quiet", to], dir);
  const from = e.sha;
  e.sha = to;
  if (hadTrust && !codeDiff) [e.trustedSha, e.trustedHash] = [to, fingerprint(dir)]; // only markdown docs changed
  else delete e.trustedHash;
  writeLock(home, lock);
  return { from, to, codeDiff, untrusted: codeFiles(dir).length > 0 && !trusted(e, dir) };
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
    return { name, source: e.source, sha: e.sha?.slice(0, 12), md, code: code.length, trusted: exists && trusted(e, dir) };
  });
}
