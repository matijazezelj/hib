import type { Database } from "bun:sqlite";
import type { Account, Config } from "./config";
import type { Quota } from "./providers/types";

const WINDOW_MS: Record<string, number> = { "1h": 3600e3, "5h": 5 * 3600e3, "1d": 86400e3, "7d": 7 * 86400e3 };

export interface AccountUsage {
  account: string;
  windows: { window: string; usedPct: number; resetsAt?: number; source: "cli" | "meter" }[];
  cooldownUntil?: number;
  maxPct: number;
}

export class Usage {
  constructor(private db: Database, private cfg: Config) {}

  recordQuota(account: string, q: Quota) {
    this.db.run("INSERT OR REPLACE INTO quota(account, window, used_pct, resets_at, ts) VALUES (?,?,?,?,?)", [account, q.window, q.usedPct, q.resetsAt ?? null, Date.now()]);
  }

  cooldown(account: string, until: number, reason: string) {
    this.db.run("INSERT OR REPLACE INTO cooldown(account, until, reason) VALUES (?,?,?)", [account, until, reason]);
  }

  of(account: Account): AccountUsage {
    const now = Date.now();
    const windows: AccountUsage["windows"] = [];
    for (const r of this.db.query("SELECT window, used_pct, resets_at FROM quota WHERE account = ?").all(account.id) as any[]) {
      if (r.resets_at && r.resets_at * 1000 < now) continue; // window rolled over since we last heard
      windows.push({ window: r.window, usedPct: r.used_pct, resetsAt: r.resets_at ?? undefined, source: "cli" });
    }
    for (const [w, limit] of Object.entries(account.limits)) {
      const ms = WINDOW_MS[w];
      if (!ms || !limit) continue;
      const { n } = this.db.query("SELECT COUNT(*) AS n FROM runs WHERE account = ? AND ts > ?").get(account.id, now - ms) as any;
      windows.push({ window: w, usedPct: n / limit, source: "meter" });
    }
    const cd = this.db.query("SELECT until FROM cooldown WHERE account = ?").get(account.id) as any;
    const cooldownUntil = cd && cd.until > now ? cd.until : undefined;
    return { account: account.id, windows, cooldownUntil, maxPct: Math.max(0, ...windows.map((w) => w.usedPct)) };
  }

  usable(account: Account): boolean {
    const u = this.of(account);
    return !u.cooldownUntil && u.maxPct < this.cfg.switchAt;
  }

  all(): AccountUsage[] {
    return this.cfg.accounts.map((a) => this.of(a));
  }
}
