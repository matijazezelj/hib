/**
 * Preloaded for every `bun test` run (bunfig.toml): all of a run's temporary folders go in one folder of its own under
 * the system temp dir, removed when the run ends. Tests call tmpdir() as before; without this, each run left a few
 * thousand folders behind and a tmpfs /tmp ran out of inodes.
 */
import { chmodSync, lstatSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { afterAll } from "bun:test";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "hib-test-"));
process.env.TMPDIR = dir; // os.tmpdir() reads it on every call, and child processes inherit it

/** Tests make unreadable folders on purpose: open them up so they can be removed. */
function openUp(p: string) {
  try {
    const st = lstatSync(p);
    if (!st.isDirectory()) return;
    chmodSync(p, 0o700);
    for (const n of readdirSync(p)) openUp(join(p, n));
  } catch {}
}

function cleanUp() {
  openUp(dir);
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {}
}
afterAll(cleanUp); // in a preload: after every test file has run
process.on("exit", cleanUp); // and if the run stops early
