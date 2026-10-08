import type { Account } from "../config";
import type { Provider } from "./types";
import { claudeCli } from "./claude-cli";
import { codexCli } from "./codex-cli";

export class Registry {
  private providers = new Map<string, Provider>();
  private availability = new Map<string, { ok: boolean; at: number }>();

  constructor(builtins: Provider[] = [claudeCli, codexCli]) {
    for (const p of builtins) this.providers.set(p.id, p);
  }

  add(p: Provider) {
    this.providers.set(p.id, p);
  }

  get(id: string): Provider | undefined {
    return this.providers.get(id);
  }

  ids(): string[] {
    return [...this.providers.keys()];
  }


  /** Cached for a minute so routing does not shell out on every request. */
  async available(account: Account): Promise<boolean> {
    const hit = this.availability.get(account.id);
    if (hit && Date.now() - hit.at < 60_000) return hit.ok;
    const p = this.providers.get(account.provider);
    const ok = p ? await p.available(account).catch(() => false) : false;
    this.availability.set(account.id, { ok, at: Date.now() });
    return ok;
  }

  markUnavailable(account: Account) {
    this.availability.set(account.id, { ok: false, at: Date.now() });
  }
}
