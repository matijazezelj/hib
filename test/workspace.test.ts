import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { listFiles, readFile, safePath } from "../src/workspace/fs";
import * as git from "../src/workspace/git";

const g = (cwd: string, ...args: string[]) =>
  Bun.spawnSync(["git", ...args], { cwd, env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" } });

function repo() {
  const root = mkdtempSync(join(tmpdir(), "hib-ws-"));
  writeFileSync(join(root, "a.ts"), "export const a = 1;\n");
  writeFileSync(join(root, ".gitignore"), "secret.log\n");
  writeFileSync(join(root, "secret.log"), "x");
  mkdirSync(join(root, "src"));
  writeFileSync(join(root, "src", "b.ts"), "b\n");
  g(root, "init", "-q");
  // commit() runs plain git; CI runners have no global author identity.
  g(root, "config", "user.name", "t");
  g(root, "config", "user.email", "t@t");
  g(root, "add", ".");
  g(root, "commit", "-qm", "init");
  return root;
}

describe("workspace jail", () => {
  test("rejects traversal and symlink escapes", () => {
    const root = repo();
    expect(() => safePath(root, "../../etc/passwd")).toThrow("outside workspace");
    symlinkSync("/etc", join(root, "etc-link"));
    expect(() => readFile(root, "etc-link/hosts")).toThrow("outside workspace");
    expect(readFile(root, "src/b.ts").content).toBe("b\n");
  });
  test("file list honours .gitignore", async () => {
    const root = repo();
    writeFileSync(join(root, "new.ts"), "n");
    const files = await listFiles(root);
    expect(files).toContain("new.ts");
    expect(files).toContain("src/b.ts");
    expect(files).not.toContain("secret.log");
  });
});

describe("git panel", () => {
  test("status, diff, discard, commit", async () => {
    const root = repo();
    writeFileSync(join(root, "a.ts"), "export const a = 2;\n");
    writeFileSync(join(root, "c.ts"), "new file\n");
    const st = (await git.status(root))!;
    expect(st.files.map((f) => [f.path, f.untracked])).toEqual([["a.ts", false], ["c.ts", true]]);
    expect(await git.diff(root, "a.ts")).toContain("+export const a = 2;");
    expect(await git.diff(root, "c.ts")).toContain("+new file");
    await git.discard(root, "a.ts");
    await git.discard(root, "c.ts");
    expect(existsSync(join(root, "c.ts"))).toBe(false);
    expect((await git.status(root))!.files).toEqual([]);
    writeFileSync(join(root, "d.ts"), "d\n");
    expect(await git.commit(root, "add d")).toContain("add d");
    await expect(git.discard(root, "../x")).rejects.toThrow("outside workspace");
  });
});

test("always-allow keys never let compound commands ride on a simple one", async () => {
  const { commandRuleKey } = await import("../src/workspace/driver");
  expect(commandRuleKey("Bash", "git status")).toBe("Bash:git status");
  expect(commandRuleKey("Bash", "git log --oneline")).toBe("Bash:git log");
  expect(commandRuleKey("Bash", "git push --force")).toBe("Bash:git push");
  expect(commandRuleKey("Bash", "ls -la")).toBe("Bash:ls");
  for (const c of ["cat a; rm -rf b", "cat a && rm b", "cat a | sh", "echo $(rm x)", "cat a > b", "ls `rm x`", "cat a\nrm b"])
    expect(commandRuleKey("Bash", c)).toBe(`Bash:exact:${c}`);
});

test("always-allow for interpreters and wrappers covers only the exact command line", async () => {
  const { commandRuleKey } = await import("../src/workspace/driver");
  for (const c of ["python x.py", "python3 -c 'import os'", "/usr/bin/python3.12 y.py", "node a.js", "bash run.sh", "env sh", "xargs rm", "find . -delete", "awk 'BEGIN{system(\"id\")}'", "sudo ls"])
    expect(commandRuleKey("Bash", c)).toBe(`Bash:exact:${c.trim()}`);
  expect(commandRuleKey("Bash", "python x.py")).not.toBe(commandRuleKey("Bash", "python -c 'x'"));
});

describe("codex approvals", () => {
  const { CodexDriver } = require("../src/workspace/codex-driver") as typeof import("../src/workspace/codex-driver");
  const { Queue } = require("../src/workspace/queue") as typeof import("../src/workspace/queue");
  const request = (params: Record<string, unknown>) => {
    const d = new CodexDriver() as any;
    const q = new Queue<any>();
    d.q = q;
    d.onServerRequest({ id: 7, method: "item/commandExecution/requestApproval", params: { itemId: "i1", command: "curl https://example.com", ...params } });
    q.end();
    return (q as any).items[0];
  };

  test("a plain command is a command", () => {
    expect(request({}).call.kind).toBe("command");
  });

  test("a request to leave the sandbox is never a plain command, so auto mode and 'always' can't approve it", () => {
    const e = request({ reason: "May I run the requested curl command outside the sandbox?" });
    expect(e.call.kind).toBe("other");
    expect(e.call.title).toContain("beyond the sandbox");
    expect(e.ruleKey).toStartWith("command:exact:widen:");
  });
});

describe("sensitive policy reaches every folder an agent could open", () => {
  test("subfolders inherit it, parents are held to it, and two different pins can't be mixed", async () => {
    const { Workspaces } = await import("../src/workspace/registry");
    const { memoryDb } = await import("../src/db");
    const { parseConfig } = await import("../src/config");
    const { realpathSync } = await import("node:fs");
    const cfg = parseConfig(Bun.TOML.parse(`[models.claude]\nsonnet = "balanced"\n[providers.claude]\ndefault = "main"\n[providers.claude.accounts.main]\nenv = {}\n[providers.claude.accounts.work]\nenv = {}\n`) as any, tmpdir());
    const ws = new Workspaces(memoryDb(), cfg);
    const top = realpathSync(mkdtempSync(join(tmpdir(), "hib-pol-")));
    for (const d of ["client/api", "other"]) mkdirSync(join(top, d), { recursive: true });
    for (const d of ["", "client", "client/api", "other"]) ws.register(join(top, d));
    ws.setPolicy(join(top, "client"), { sensitive: true, account: "claude@work" });
    expect(ws.policy(join(top, "client/api"))).toBeNull(); // the exact-match lookup misses it…
    expect(ws.effectivePolicy(join(top, "client/api"))?.account).toBe("claude@work"); // …the effective one doesn't
    expect(ws.effectivePolicy(top)?.account).toBe("claude@work"); // a parent can read the sensitive child
    expect(ws.effectivePolicy(join(top, "other"))).toBeNull();
    ws.setPolicy(join(top, "other"), { sensitive: true, account: "claude@main" });
    expect(() => ws.effectivePolicy(top)).toThrow(/different accounts/);
  });
});

test("a sensitive folder can't be pinned to Codex (it runs cat/grep without asking)", async () => {
  const { Workspaces } = await import("../src/workspace/registry");
  const { memoryDb } = await import("../src/db");
  const { parseConfig } = await import("../src/config");
  const cfg = parseConfig(Bun.TOML.parse(`[models.codex]\nm = "fast"\n[providers.codex]\ndefault = "main"\n[providers.codex.accounts.main]\nenv = {}\n`) as any, tmpdir());
  const ws = new Workspaces(memoryDb(), cfg);
  const dir = ws.register(mkdtempSync(join(tmpdir(), "hib-cx-")));
  expect(() => ws.setPolicy(dir, { sensitive: true, account: "codex@main" })).toThrow(/Claude account/);
});
