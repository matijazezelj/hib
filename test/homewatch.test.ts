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
    const before = homeSnapshot(h);
    writeFileSync(join(h, ".config/systemd/user/miner.service"), "[Service]");
    chmodSync(join(h, ".bashrc"), 0o755);
    rmSync(join(h, ".profile"));
    rmSync(join(h, ".gitconfig"));
    symlinkSync("/tmp/x", join(h, ".gitconfig"));
    writeFileSync(join(h, "other"), "x");
    expect(homeChanges(before, h).sort((a, b) => a.path.localeCompare(b.path))).toEqual([
      { path: "~/.bashrc", change: "changed" },
      { path: "~/.config/systemd/user/miner.service", change: "added" },
      { path: "~/.gitconfig", change: "changed" },
      { path: "~/.profile", change: "removed" },
    ]);
  });

  test("a fifo is recorded without being opened", () => {
    const h = home();
    Bun.spawnSync(["mkfifo", join(h, ".zshrc")]);
    const before = homeSnapshot(h); // would hang if it opened the fifo
    expect(homeChanges(before, h)).toEqual([]);
  });
});
