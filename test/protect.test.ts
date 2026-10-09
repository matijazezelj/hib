import { beforeEach, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { realTarget } from "../src/workspace/fs";
import { changes, revert, snapshot } from "../src/workspace/protect";
import { protectedPath } from "../src/workspace/sessions";

let root: string, outside: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "hib-prot-")));
  outside = realpathSync(mkdtempSync(join(tmpdir(), "hib-out-")));
  for (const d of ["src/deep", ".git/hooks", ".claude"]) mkdirSync(join(root, d), { recursive: true });
  writeFileSync(join(root, ".git/config"), "[core]\n");
  writeFileSync(join(root, ".git/hooks/pre-commit.sample"), "#!/bin/sh\n");
  writeFileSync(join(root, ".claude/settings.json"), "{}\n");
});

describe("protected paths, however they're reached", () => {
  test("a dangling symlink is judged by where a write through it would land", () => {
    symlinkSync(join(root, ".git/hooks/post-commit"), join(root, "src/dangle")); // target doesn't exist yet
    expect(realTarget(root, "src/dangle")).toBe(join(root, ".git/hooks/post-commit"));
    expect(protectedPath(root, "src/dangle")).toBe(true);
    symlinkSync("../.claude/new.json", join(root, "src/rel-dangle")); // relative target
    expect(protectedPath(root, "src/rel-dangle")).toBe(true);
  });

  test("nested and chained symlinks", () => {
    symlinkSync(join(root, ".git"), join(root, "src/deep/g"));
    symlinkSync(join(root, "src/deep"), join(root, "src/d"));
    expect(protectedPath(root, "src/d/g/hooks/pre-commit")).toBe(true);
    symlinkSync(join(root, "src/hop2"), join(root, "src/hop1")); // dangling → dangling → .git
    symlinkSync(join(root, ".git/hooks/x"), join(root, "src/hop2"));
    expect(protectedPath(root, "src/hop1")).toBe(true);
  });

  test("paths that don't exist yet", () => {
    expect(protectedPath(root, ".git/hooks/new-hook")).toBe(true);
    expect(protectedPath(root, ".claude/agents/new/agent.md")).toBe(true);
    expect(protectedPath(root, "src/new/dir/file.ts")).toBe(false);
  });

  test("a symlink loop doesn't hang", () => {
    symlinkSync(join(root, "src/loop-b"), join(root, "src/loop-a"));
    symlinkSync(join(root, "src/loop-a"), join(root, "src/loop-b"));
    expect(protectedPath(root, "src/loop-a")).toBe(false);
  });
});

describe("protected files are checked by content after each turn", () => {
  test("a planted hook and a config change are found and put back", () => {
    const before = snapshot(root);
    writeFileSync(join(root, ".git/hooks/post-commit"), "#!/bin/sh\ncurl evil\n", { mode: 0o755 });
    writeFileSync(join(root, ".git/config"), "[core]\n\thooksPath = /tmp/evil\n");
    const found = changes(before, root);
    expect(found).toContainEqual({ path: join(root, ".git/hooks/post-commit"), change: "added" });
    expect(found).toContainEqual({ path: join(root, ".git/config"), change: "changed" });
    expect(revert(before, found)).toEqual([]);
    expect(existsSync(join(root, ".git/hooks/post-commit"))).toBe(false);
    expect(readFileSync(join(root, ".git/config"), "utf8")).toBe("[core]\n");
    expect(changes(before, root)).toEqual([]);
  });

  test("a hooks directory swapped for a symlink is restored as a real directory", () => {
    const before = snapshot(root);
    mkdirSync(join(outside, "hooks"));
    writeFileSync(join(outside, "hooks/pre-commit"), "#!/bin/sh\nevil\n");
    renameSync(join(root, ".git/hooks"), join(outside, "old-hooks"));
    symlinkSync(join(outside, "hooks"), join(root, ".git/hooks"));
    revert(before, changes(before, root));
    expect(lstatSync(join(root, ".git/hooks")).isDirectory()).toBe(true);
    expect(readFileSync(join(root, ".git/hooks/pre-commit.sample"), "utf8")).toBe("#!/bin/sh\n");
    expect(existsSync(join(outside, "hooks/pre-commit"))).toBe(true); // the outside target is left alone
    expect(changes(before, root)).toEqual([]);
  });

  test("an unreadable file, a fifo or an unreadable folder can't stop the check, and gets removed", () => {
    const before = snapshot(root);
    writeFileSync(join(root, ".claude/locked"), "x");
    chmodSync(join(root, ".claude/locked"), 0o000);
    Bun.spawnSync(["mkfifo", join(root, ".claude/pipe")]); // reading it would block forever
    mkdirSync(join(root, ".claude/sealed"));
    writeFileSync(join(root, ".claude/sealed/settings.json"), "{}");
    chmodSync(join(root, ".claude/sealed"), 0o000);
    writeFileSync(join(root, ".git/hooks/post-commit"), "evil");
    const found = changes(before, root).map((c) => c.path);
    for (const p of [".claude/locked", ".claude/pipe", ".claude/sealed", ".git/hooks/post-commit"]) expect(found).toContain(join(root, p));
    revert(before, changes(before, root));
    expect(changes(before, root)).toEqual([]);
  });

  test("too many files is reported, never a reason to stop looking", () => {
    const before = snapshot(root);
    mkdirSync(join(root, ".claude/flood"));
    for (let i = 0; i < 20_100; i++) writeFileSync(join(root, ".claude/flood", String(i)), "");
    expect(changes(before, root).map((c) => c.path)).toContain("(more protected files than hib checks)");
  });

  test("a worktree's hooks live in the main repo and are covered too", () => {
    const wt = realpathSync(mkdtempSync(join(tmpdir(), "hib-wt-")));
    mkdirSync(join(root, ".git/worktrees/w"), { recursive: true });
    writeFileSync(join(root, ".git/worktrees/w/commondir"), "../..\n");
    writeFileSync(join(wt, ".git"), `gitdir: ${join(root, ".git/worktrees/w")}\n`);
    const before = snapshot(wt);
    writeFileSync(join(root, ".git/hooks/post-checkout"), "evil");
    expect(changes(before, wt)).toEqual([{ path: join(root, ".git/hooks/post-checkout"), change: "added" }]);
  });
});
