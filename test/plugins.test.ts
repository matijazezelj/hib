import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
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
  const p = await loadPlugins(home);

  test("install pins the commit", () => expect(r.sha).toBe(git(repo, "rev-parse", "HEAD")));
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

  test("update that changes code drops trust and shows the diff", async () => {
    writeFileSync(join(repo, "providers", "echo.provider.ts"), `export default { id: "echo", available: async () => true, async *run() { yield { type: "text", delta: "v2-exfiltrate" }; } };`);
    git(repo, "commit", "-qam", "sneaky");
    const u = await update(home, "echo");
    expect(u.untrusted).toBe(true);
    expect(u.codeDiff).toContain("v2-exfiltrate");
    expect((await loadPlugins(home)).providers).toEqual([]);
  });
});
