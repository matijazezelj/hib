import { afterEach, beforeEach, expect, test } from "bun:test";
import type { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "../src/db";
import { Vault } from "../src/guard/vault";
import { VaultStore } from "../src/guard/vaultstore";

let home: string;
let dbs: Database[];

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "hib-vaultstore-"));
  dbs = [];
});
afterEach(() => {
  for (const db of dbs) db.close();
  rmSync(home, { recursive: true, force: true });
});

function db() {
  const d = openDb(home);
  dbs.push(d);
  return d;
}

test("round trip keeps tokens stable in a fresh store on the same home", async () => {
  const store = await VaultStore.open(home, db());
  const v = await store.load("prod");
  const t1 = v.token("EMAIL", "jdoe@example.com");
  const t2 = v.token("IP-ADDR", "10.1.2.3");
  await store.save("prod", v);

  const fresh = await VaultStore.open(home, db());
  const back = await fresh.load("prod");
  expect(back.tag).toBe(v.tag);
  expect(back.token("EMAIL", "jdoe@example.com")).toBe(t1);
  expect(back.token("IP-ADDR", "10.1.2.3")).toBe(t2);
  expect(back.lookup(t1)).toBe("jdoe@example.com");
  // counters survive: a new value gets the next number, not a reused one
  expect(back.token("EMAIL", "other@example.com")).not.toBe(t1);
  expect(back.restore(`[${t1}] from [${t2}]`)).toBe("jdoe@example.com from 10.1.2.3");
});

test("store opened without a db uses openDb(home)", async () => {
  const a = await VaultStore.open(home);
  const v = new Vault();
  const t = v.token("USER", "jdoe");
  await a.save("x", v);
  const b = await VaultStore.open(home);
  expect((await b.load("x")).token("USER", "jdoe")).toBe(t);
});

test("the stored blob is sealed", async () => {
  const d = db();
  const store = await VaultStore.open(home, d);
  const v = new Vault();
  v.token("EMAIL", "secret.person@example.com");
  await store.save("s", v);
  const row = d.query("SELECT vault FROM pipe_vaults WHERE name = 's'").get() as { vault: string };
  expect(row.vault).toBeString();
  expect(row.vault).not.toContain("secret.person");
  expect(row.vault).not.toContain(`HIB${v.tag}`);
  expect(row.vault).toMatch(/^[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/);
});

test("list and delete", async () => {
  const store = await VaultStore.open(home, db());
  expect(store.list()).toEqual([]);
  const a = new Vault();
  a.token("EMAIL", "a@example.com");
  a.token("EMAIL", "b@example.com");
  const before = Date.now();
  await store.save("beta", a);
  await store.save("alpha", new Vault());
  const l = store.list();
  expect(l.map((r) => r.name)).toEqual(["alpha", "beta"]);
  expect(l.find((r) => r.name === "beta")!.size).toBe(2);
  expect(l.find((r) => r.name === "alpha")!.size).toBe(0);
  expect(l[0]!.updated).toBeGreaterThanOrEqual(before);

  // upsert, not a second row
  a.token("EMAIL", "c@example.com");
  await store.save("beta", a);
  expect(store.list().find((r) => r.name === "beta")!.size).toBe(3);
  expect(store.list()).toHaveLength(2);

  expect(store.delete("beta")).toBe(true);
  expect(store.delete("beta")).toBe(false);
  expect(store.list().map((r) => r.name)).toEqual(["alpha"]);
  expect((await store.load("beta")).size).toBe(0);
});

test("invalid names are rejected", async () => {
  const store = await VaultStore.open(home, db());
  for (const bad of ["", "-x", ".x", "a b", "a/b", "../x", "x".repeat(65), "naïve", "a;drop"]) {
    await expect(store.load(bad)).rejects.toThrow(/invalid vault name/);
    await expect(store.save(bad, new Vault())).rejects.toThrow(/invalid vault name/);
    expect(() => store.delete(bad)).toThrow(/invalid vault name/);
  }
  for (const good of ["default", "A.b_c-1", "x".repeat(64)]) await store.save(good, new Vault());
  expect(store.list()).toHaveLength(3);
});

test("a missing name gives a fresh empty vault", async () => {
  const store = await VaultStore.open(home, db());
  const v = await store.load("nothing-here");
  expect(v).toBeInstanceOf(Vault);
  expect(v.size).toBe(0);
  expect(store.list()).toEqual([]);
});
