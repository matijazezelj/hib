import type { Database } from "bun:sqlite";
import { realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import type { Config } from "../config";

/**
 * Folders the user has opened hib in. Registering a folder is consent for agents to work in it,
 * so registered roots are also agent dirs. `hib workspace forget` withdraws that.
 */
export function eligible(dir: string): { ok: true; root: string } | { ok: false; why: string } {
  let root: string;
  try {
    root = realpathSync(dir);
  } catch {
    return { ok: false, why: `${dir} does not exist` };
  }
  if (!statSync(root).isDirectory()) return { ok: false, why: `${root} is not a directory` };
  if (root === "/" || root === realpathSync(homedir())) return { ok: false, why: `${root} is too broad for a workspace; cd into a project folder` };
  return { ok: true, root };
}

export class Workspaces {
  constructor(private db: Database, private cfg: Config) {
    for (const r of this.list()) if (!cfg.guard.agentDirs.includes(r.root)) cfg.guard.agentDirs.push(r.root);
  }

  list(): { root: string; added: number }[] {
    return this.db.query("SELECT root, added FROM workspaces ORDER BY added DESC").all() as any[];
  }

  has(root: string): boolean {
    return !!this.db.query("SELECT 1 FROM workspaces WHERE root = ?").get(root);
  }

  /** Resolves a client-supplied root to a registered workspace, or null. */
  resolve(dir: string | null | undefined): string | null {
    if (!dir) return null;
    try {
      const real = realpathSync(dir);
      return this.has(real) ? real : null;
    } catch {
      return null;
    }
  }

  register(dir: string): string {
    const e = eligible(dir);
    if (!e.ok) throw new Error(e.why);
    this.db.run("INSERT OR IGNORE INTO workspaces(root, added) VALUES (?, ?)", [e.root, Date.now()]);
    if (!this.cfg.guard.agentDirs.includes(e.root)) this.cfg.guard.agentDirs.push(e.root);
    return e.root;
  }

  forget(dir: string) {
    const root = this.resolve(dir) ?? dir;
    this.db.run("DELETE FROM workspaces WHERE root = ?", [root]);
    const i = this.cfg.guard.agentDirs.indexOf(root);
    if (i >= 0) this.cfg.guard.agentDirs.splice(i, 1);
  }
}
