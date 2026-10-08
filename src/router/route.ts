import { resolve } from "node:path";
import { parseModelId, type Account, type Config, type Route, type TaskClass, type Tier } from "../config";
import type { Learner } from "../learn";
import type { Registry } from "../providers/registry";
import type { Usage } from "../usage";

export interface Candidate {
  id: string; // canonical "claude@default/sonnet"
  provider: string;
  account: Account;
  model: string;
}

export interface Plan {
  cls: TaskClass;
  route: Route;
  ordered: Candidate[]; // best first; the rest are failover
  skipped: { id: string; why: string }[];
}

export function resolveCandidate(id: string, cfg: Config): Candidate | null {
  const p = parseModelId(id, cfg);
  if (!p) return null;
  const account = cfg.accounts.find((a) => a.provider === p.provider && a.name === p.account);
  if (!account) return null;
  return { id: `${p.provider}@${p.account}/${p.model}`, provider: p.provider, account, model: p.model };
}

export function tierOf(c: Candidate, cfg: Config): Tier | undefined {
  return cfg.models[c.provider]?.[c.model];
}

/** In agent mode, a dir pinned to an account forces that account (e.g. work repos -> work login). */
function pinnedAccount(cfg: Config, provider: string, cwd?: string): Account | undefined {
  if (!cwd) return;
  const d = resolve(cwd);
  return cfg.accounts.find((a) => a.provider === provider && a.dirs.some((x) => d === x || d.startsWith(x + "/")));
}

export class Router {
  constructor(private cfg: Config, private registry: Registry, private usage: Usage, private learner: Learner) {}

  async plan(cls: TaskClass, opts: { explicit?: string; mode?: "chat" | "agent"; cwd?: string } = {}): Promise<Plan> {
    const base = this.cfg.routes[cls] ?? this.cfg.routes.chat;
    const route: Route = { ...base, mode: opts.mode ?? base.mode };
    const ids = opts.explicit ? [opts.explicit] : route.candidates;
    const skipped: Plan["skipped"] = [];
    const usable: Candidate[] = [];

    for (const id of ids) {
      let c = resolveCandidate(id, this.cfg);
      if (!c) {
        skipped.push({ id, why: "unknown model or account" });
        continue;
      }
      const pinned = route.mode === "agent" ? pinnedAccount(this.cfg, c.provider, opts.cwd) : undefined;
      if (pinned && pinned !== c.account) c = { ...c, account: pinned, id: `${c.provider}@${pinned.name}/${c.model}` };
      if (!this.registry.get(c.provider)) skipped.push({ id: c.id, why: "provider not installed" });
      else if (!(await this.registry.available(c.account))) skipped.push({ id: c.id, why: "not logged in" });
      else if (!this.usage.usable(c.account)) skipped.push({ id: c.id, why: `usage ≥ ${Math.round(this.cfg.switchAt * 100)}% or cooling down` });
      else if (!usable.some((u) => u.id === c!.id)) usable.push(c);
    }

    // An explicit pick that is over quota still runs; the user asked for it.
    if (opts.explicit && !usable.length) {
      const c = resolveCandidate(opts.explicit, this.cfg);
      if (c && this.registry.get(c.provider)) usable.push(c);
    }

    const scored = usable.map((c, i) => ({ c, s: opts.explicit ? 1 : this.learner.sample(cls, c.id, i === 0 ? 2 : 0) }));
    scored.sort((a, b) => b.s - a.s);
    return { cls, route, ordered: scored.map((x) => x.c), skipped };
  }

  /** Strongest model of a different provider than `primary`, for advisor/critique. */
  advisorFor(primary: Candidate): Candidate | null {
    for (const [provider, id] of Object.entries(this.cfg.advisorModels)) {
      if (provider === primary.provider) continue;
      const c = resolveCandidate(id, this.cfg);
      if (c && this.registry.get(c.provider) && this.usage.usable(c.account)) return c;
    }
    return null;
  }
}
