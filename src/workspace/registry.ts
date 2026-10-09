import type { Database } from "bun:sqlite";
import { realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import type { Config } from "../config";

/**
 * A sensitive workspace sends its contents to exactly one vendor account. It allows no handoff,
 * failover, advisor or arena, has no browser terminal, blocks secrets in prompts, and asks before every read.
 */
export interface Policy {
  sensitive: true;
  account: string; // "claude@work": the only provider@account allowed to see this folder
  model?: string; // default model on that account
}

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

  list(): { root: string; added: number; policy: Policy | null }[] {
    return (this.db.query("SELECT root, added, policy FROM workspaces ORDER BY added DESC").all() as any[]).map((r) => ({ ...r, policy: r.policy ? JSON.parse(r.policy) : null }));
  }

  policy(root: string): Policy | null {
    const r = this.db.query("SELECT policy FROM workspaces WHERE root = ?").get(root) as any;
    return r?.policy ? JSON.parse(r.policy) : null;
  }

  /** Policy of the registered workspace containing `dir` (the innermost one), if any. */
  policyFor(dir: string): { root: string; policy: Policy } | null {
    let real: string;
    try {
      real = realpathSync(dir);
    } catch {
      return null;
    }
    const hits = this.list().filter((w) => w.policy && (real === w.root || real.startsWith(w.root + "/")));
    hits.sort((a, b) => b.root.length - a.root.length);
    return hits[0] ? { root: hits[0].root, policy: hits[0].policy! } : null;
  }

  /**
   * The policy that governs agents working in `root`. A sensitive folder's rules follow it into every subfolder, and
   * a folder that contains a sensitive one is held to its rules too (an agent there can read the child). Two sensitive
   * folders pinned to different accounts can't both be satisfied, so that's an error.
   */
  effectivePolicy(root: string): Policy | null {
    const up = this.policyFor(root)?.policy;
    const down = this.list().filter((w) => w.policy && w.root.startsWith(root + "/")).map((w) => w.policy!);
    const all = [...(up ? [up] : []), ...down];
    const accounts = new Set(all.map((p) => p.account));
    if (accounts.size > 1) throw new Error(`${root} spans sensitive folders pinned to different accounts (${[...accounts].join(", ")}); open hib in one of them instead`);
    return all[0] ?? null;
  }

  setPolicy(dir: string, policy: Policy | null) {
    const root = this.resolve(dir);
    if (!root) throw new Error(`${dir} is not a registered workspace; run hib there first`);
    if (policy) {
      if (!/^[a-z0-9_-]+@[A-Za-z0-9_-]+$/.test(policy.account) || !this.cfg.accounts.some((a) => a.id === policy.account))
        throw new Error(`unknown account ${policy.account}; known: ${this.cfg.accounts.map((a) => a.id).join(", ")}`);
      if (!supportsSensitive(policy.account)) throw new Error(SENSITIVE_NEEDS_CLAUDE);
      if (policy.model && !policy.model.startsWith(policy.account + "/")) throw new Error(`model must be on ${policy.account}, e.g. ${policy.account}/sonnet`);
    }
    this.db.run("UPDATE workspaces SET policy = ? WHERE root = ?", [policy ? JSON.stringify(policy) : null, root]);
    return root;
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

/**
 * Only Claude can keep a sensitive folder's promises: every read asks (Codex runs cat/head/grep without asking) and
 * data files are swapped for pseudonymised copies (that hooks Claude's Read tool, which Codex doesn't have).
 */
export const supportsSensitive = (account: string) => !account.startsWith("codex@");
export const SENSITIVE_NEEDS_CLAUDE = "sensitive folders need a Claude account: Codex runs read commands like cat and grep without asking, so reads can't be gated or pseudonymised there";

/** True if a model id ("claude@work/sonnet", "claude/sonnet") runs on the pinned account. */
export function onPinnedAccount(modelId: string, policy: Policy, cfg: Config): boolean {
  const m = /^([a-z0-9_-]+)(?:@([A-Za-z0-9_-]+))?\/(.+)$/.exec(modelId);
  if (!m) return false;
  const account = m[2] ?? cfg.defaultAccount[m[1]!] ?? "default";
  return `${m[1]}@${account}` === policy.account;
}

/** The model a sensitive workspace uses when none is chosen: its policy model, else the route's choice moved onto the pinned account. */
export function pinnedModel(policy: Policy, cfg: Config, cls = "code"): string {
  if (policy.model) return policy.model;
  const provider = policy.account.split("@")[0]!;
  const fromRoute = (cfg.routes[cls] ?? cfg.routes.code).candidates.map((c) => /^([a-z0-9_-]+)(?:@[^/]+)?\/(.+)$/.exec(c)).find((m) => m?.[1] === provider)?.[2];
  return `${policy.account}/${fromRoute ?? Object.keys(cfg.models[provider] ?? {})[0] ?? "default"}`;
}
