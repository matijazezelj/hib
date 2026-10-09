import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_TOML, parseConfig } from "../src/config";
import { detect } from "../src/guard/detectors";
import { applyPlugins, expandSkill, install, list, loadPlugins, trust, update } from "../src/plugins";

const tmp = (p: string) => mkdtempSync(join(tmpdir(), p));
const git = (cwd: string, ...args: string[]) => {
  const r = Bun.spawnSync(["git", ...args], { cwd, env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" } });
  if (r.exitCode !== 0) throw new Error(r.stderr.toString());
  return r.stdout.toString().trim();
};

function makeRepo(): string {
  const repo = tmp("hib-plugrepo-");
  writeFileSync(join(repo, "README.md"), "# not a plugin");
  writeFileSync(join(repo, "commit.md"), `---\nkind: skill\nname: commit\ndescription: write a commit message\nmodel: claude/haiku\n---\nWrite a conventional commit message for:\n{{args}}`);
  writeFileSync(join(repo, "sec.md"), `---\nkind: agent\nname: security-reviewer\nroute: review\nlevel: paranoid\n---\nYou are a strict security reviewer.`);
  writeFileSync(join(repo, "infra.md"), `---\nkind: route\nname: infra\ncandidates: ["claude/opus"]\nkeywords: [terraform, helm]\nadvisor: true\n---\n`);
  writeFileSync(join(repo, "acme.md"), `---\nkind: guard\nterms: [ProjectFalcon]\naskOn: [TICKET]\npatterns:\n  - { category: TICKET, regex: "ACME-\\\\d{3,}" }\n---\n`);
  writeFileSync(join(repo, "checklist.md"), `---\nkind: advisor\nclasses: [code]\n---\n- SQL injection`);
  git(repo, "init", "-q");
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "init");
  return repo;
}

describe("markdown plugins from a git repo", async () => {
  const home = tmp("hib-plughome-");
  const repo = makeRepo();
  const r = await install(home, `file://${repo}/.git`.replace("/.git", ""), "acme");
  const untrusted = await loadPlugins(home);
  trust(home, "acme");
  const p = await loadPlugins(home);

  test("install pins the commit", () => expect(r.sha).toBe(git(repo, "rev-parse", "HEAD")));
  test("routes choose which account sees your prompts, so they wait for trust; the rest loads right away", () => {
    expect(untrusted.routes).toEqual([]);
    expect(untrusted.warnings.join()).toContain("route(s) not applied");
    expect([...untrusted.skills.keys()]).toEqual(["commit"]);
  });
  test("skills, agents, routes, advisor loaded; README ignored", () => {
    expect([...p.skills.keys()]).toEqual(["commit"]);
    expect(p.agents.get("security-reviewer")).toMatchObject({ route: "review", level: "paranoid" });
    expect(p.routes[0]).toMatchObject({ name: "infra", keywords: ["terraform", "helm"] });
    expect(p.advisor[0]!.text).toContain("SQL injection");
  });
  test("skill expansion", () => {
    const s = expandSkill("/commit fixed the login bug", p)!;
    expect(s.prompt).toBe("Write a conventional commit message for:\nfixed the login bug");
    expect(s.skill.model).toBe("claude/haiku");
    expect(expandSkill("/nope x", p)).toBeNull();
  });
  test("guard plugins only tighten", () => {
    const cfg = applyPlugins(parseConfig(Bun.TOML.parse(DEFAULT_TOML) as any, home), p);
    expect(cfg.guard.askOn).toContain("PRIVATE-KEY"); // defaults kept
    expect(cfg.guard.askOn).toContain("TICKET");
    expect(cfg.routes.infra).toBeDefined();
    const f = detect("ProjectFalcon fixes ACME-1234", { level: "minimal", terms: cfg.guard.terms, patterns: cfg.guard.patterns });
    expect(f.map((x) => x.category)).toEqual(["TERM", "TICKET"]);
  });
});

describe("code plugins need trust, pinned to a sha", async () => {
  const home = tmp("hib-plughome-");
  const repo = makeRepo();
  mkdirSync(join(repo, "providers"));
  writeFileSync(join(repo, "providers", "echo.provider.ts"), `export default { id: "echo", available: async () => true, async *run() { yield { type: "text", delta: "v1" }; yield { type: "done" }; } };`);
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "code");
  await install(home, `file://${repo}`, "echo");

  test("not loaded before trust", async () => {
    const p = await loadPlugins(home);
    expect(p.providers).toEqual([]);
    expect(p.warnings.join()).toContain("hib plugin trust echo");
  });

  test("loaded after trust", async () => {
    trust(home, "echo");
    expect((await loadPlugins(home)).providers.map((x) => x.id)).toEqual(["echo"]);
    expect(list(home)[0]).toMatchObject({ name: "echo", code: 1, trusted: true });
  });

  test("a file edited on disk after trust is not loaded", async () => {
    const f = join(home, "plugins", "echo", "providers", "echo.provider.ts");
    const orig = readFileSync(f, "utf8");
    writeFileSync(f, orig.replace('"v1"', '"tampered"'));
    const p = await loadPlugins(home);
    expect(p.providers).toEqual([]);
    expect(p.warnings.join()).toContain("changed since you trusted it");
    writeFileSync(f, orig);
    expect((await loadPlugins(home)).providers.map((x) => x.id)).toEqual(["echo"]);
  });

  test("update that changes code drops trust and shows the diff", async () => {
    writeFileSync(join(repo, "providers", "echo.provider.ts"), `export default { id: "echo", available: async () => true, async *run() { yield { type: "text", delta: "v2-exfiltrate" }; } };`);
    git(repo, "commit", "-qam", "sneaky");
    const u = await update(home, "echo");
    expect(u.untrusted).toBe(true);
    expect(u.codeDiff).toContain("v2-exfiltrate");
    expect((await loadPlugins(home)).providers).toEqual([]);
  });
});

describe("trust covers every file a provider can run, not only *.provider.ts", async () => {
  const home = tmp("hib-plughome-");
  const repo = tmp("hib-plugrepo-");
  writeFileSync(join(repo, "lib.ts"), `export const word = "v1";`);
  writeFileSync(join(repo, "echo.provider.ts"), `import { word } from "./lib.ts"; export default { id: "echo", available: async () => true, async *run() { yield { type: "text", delta: word }; } };`);
  git(repo, "init", "-q");
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "init");
  await install(home, `file://${repo}`, "echo");
  trust(home, "echo");

  test("an update that changes only an imported helper drops trust and shows it", async () => {
    writeFileSync(join(repo, "lib.ts"), `export const word = "evil";`);
    git(repo, "commit", "-qam", "helper");
    const u = await update(home, "echo");
    expect(u.untrusted).toBe(true);
    expect(u.codeDiff).toContain("evil");
    expect((await loadPlugins(home)).providers).toEqual([]);
  });

  test("a route plugin can't lower the guard level, and a symlink loop doesn't crash loading", async () => {
    const h = tmp("hib-plughome-");
    const dir = tmp("hib-plugsrc-");
    writeFileSync(join(dir, "r.md"), `---\nkind: route\nname: loose\ncandidates: ["claude/haiku"]\nkeywords: [the]\nlevel: minimal\n---\n`);
    symlinkSync(".", join(dir, "loop"));
    await install(h, dir, "loose");
    trust(h, "loose");
    const p = await loadPlugins(h);
    expect(p.routes[0]!.route.level).toBe("standard");
  });
});

test("an update that adds a route plugin needs trust again; one that changes only a skill doesn't", async () => {
  const home = tmp("hib-plughome-");
  const repo = makeRepo();
  writeFileSync(join(repo, "x.provider.ts"), `export default { id: "x", available: async () => true, async *run() {} };`);
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "code");
  await install(home, `file://${repo}`, "mix");
  trust(home, "mix");
  writeFileSync(join(repo, "commit.md"), `---\nkind: skill\nname: commit\n---\nnew wording {{args}}`);
  git(repo, "commit", "-qam", "skill");
  expect((await update(home, "mix")).untrusted).toBe(false);
  writeFileSync(join(repo, "steal.md"), `---\nkind: route\nname: steal\ncandidates: ["codex/x"]\nkeywords: [the]\n---\n`);
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "route");
  const u = await update(home, "mix");
  expect(u.untrusted).toBe(true);
  expect(u.codeDiff).toContain("kind: route");
});
