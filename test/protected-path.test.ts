import { afterAll, beforeAll, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { protectedPath } from "../src/workspace/sessions";

let root: string;
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "hib-protected-"));
  for (const d of ["src", ".git/hooks", ".claude", ".codex"]) mkdirSync(join(root, d), { recursive: true });
  symlinkSync(join(root, ".git"), join(root, "src", "gitlink"));
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

test("tool config and git internals are protected however the path is spelled", () => {
  for (const p of [
    ".git/hooks/pre-commit", ".git/config", ".claude/settings.json", ".codex/config.toml", ".mcp.json",
    `${root}/.git/hooks/pre-commit`, "src/../.git/hooks/pre-commit", `${root}/src/../.claude/settings.json`,
    "./.git/hooks/x", `${root}/./.git/hooks/x`, `${root}//.git/hooks/x`, "src/gitlink/hooks/pre-commit",
    ".GIT/hooks/pre-commit", ".Claude/settings.json",
  ]) expect([p, protectedPath(root, p)]).toEqual([p, true]);
});

test("ordinary files, and paths that only mention a protected name, are not protected", () => {
  for (const p of ["src/a.ts", "src/.git-notes.md", "docs/.claude-notes.md", `${root}/src/../src/b.ts`, ".gitignore", ".github/workflows/ci.yml"])
    expect([p, protectedPath(root, p)]).toEqual([p, false]);
});
