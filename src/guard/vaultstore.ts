import type { Database } from "bun:sqlite";
import { openDb } from "../db";
import { Sealer } from "./seal";
import { Vault, type VaultState } from "./vault";

const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/i;

function checkName(name: string): string {
  if (typeof name !== "string" || !NAME.test(name)) throw new Error(`invalid vault name: ${JSON.stringify(name)}`);
  return name;
}

/**
 * Named, persistent vaults for `hib pipe`: the token map is sealed (AES-GCM, key in <home>/vault.key) in the
 * pipe_vaults table, so tokens stay stable across runs and `hib pipe restore` can map them back.
 * TODO: vault TTL / rotation (out of scope for now).
 */
export class VaultStore {
  private constructor(
    private db: Database,
    private sealer: Sealer,
  ) {}

  static async open(home: string, db?: Database): Promise<VaultStore> {
    return new VaultStore(db ?? openDb(home), await Sealer.open(home));
  }

  /** The named vault, or a fresh empty one when there is none yet. */
  async load(name: string): Promise<Vault> {
    checkName(name);
    const row = this.db.query("SELECT vault FROM pipe_vaults WHERE name = ?").get(name) as { vault: string | null } | null;
    if (!row?.vault) return new Vault();
    return Vault.from(await this.sealer.unseal<VaultState>(row.vault));
  }

  async save(name: string, vault: Vault): Promise<void> {
    checkName(name);
    const sealed = await this.sealer.seal(vault.state());
    this.db
      .query(
        `INSERT INTO pipe_vaults (name, vault, size, updated) VALUES (?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET vault = excluded.vault, size = excluded.size, updated = excluded.updated`,
      )
      .run(name, sealed, vault.size, Date.now());
  }

  list(): { name: string; size: number; updated: number }[] {
    return this.db.query("SELECT name, size, updated FROM pipe_vaults ORDER BY name").all() as {
      name: string;
      size: number;
      updated: number;
    }[];
  }

  delete(name: string): boolean {
    checkName(name);
    return this.db.query("DELETE FROM pipe_vaults WHERE name = ?").run(name).changes > 0;
  }
}
