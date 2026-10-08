import { openSync } from "node:fs";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { loadConfig, hibHome } from "./config";
import { openDb } from "./db";
import { Engine } from "./engine";
import { Sealer } from "./guard/seal";
import { applyPlugins, loadPlugins } from "./plugins";
import { Registry } from "./providers/registry";
import { apiToken, startServer } from "./server";
import { HibClient } from "./client";

export async function boot(home = hibHome()) {
  process.umask(0o077); // db, wal, scratch dirs: owner-only
  const plugins = await loadPlugins(home);
  const cfg = applyPlugins(loadConfig(home), plugins);
  const registry = new Registry();
  for (const p of plugins.providers) registry.add(p);
  const engine = new Engine(cfg, openDb(home), registry, await Sealer.open(home), plugins);
  return { cfg, engine, home, token: apiToken(home) };
}

/** Runs the daemon in this process. */
export async function serve(port?: number) {
  const b = await boot();
  const server = startServer(b.engine, { port: port ?? b.cfg.port, token: b.token });
  return { ...b, server, url: `http://127.0.0.1:${server.port}` };
}

export function daemonClient(): { client: HibClient; url: string } {
  const home = hibHome();
  const url = `http://127.0.0.1:${loadConfig(home).port}`;
  return { client: new HibClient(url, apiToken(home)), url };
}

export async function daemonUp(client: HibClient): Promise<boolean> {
  try {
    await client.get("/hib/info");
    return true;
  } catch {
    return false;
  }
}

/** The shared daemon, started in the background (detached, logging to ~/.hib/daemon.log) if none answers. */
export async function ensureDaemon(): Promise<{ client: HibClient; url: string; started: boolean }> {
  const { client, url } = daemonClient();
  if (await daemonUp(client)) return { client, url, started: false };
  const log = openSync(join(hibHome(), "daemon.log"), "a", 0o600);
  const child = spawn(process.execPath, [join(import.meta.dir, "cli.ts"), "daemon", "run"], { detached: true, stdio: ["ignore", log, log], env: process.env });
  child.unref();
  for (let i = 0; i < 100; i++) {
    await Bun.sleep(100);
    if (await daemonUp(client)) return { client, url, started: true };
  }
  throw new Error(`daemon did not start; see ${join(hibHome(), "daemon.log")}`);
}

/** Registers a folder with the daemon; returns its canonical root. */
export async function registerWorkspace(client: HibClient, dir: string): Promise<string> {
  return (await client.post<{ root: string }>("/hib/workspaces", { root: dir })).root;
}

export function workspaceUrl(url: string, root: string, sessionId?: string): string {
  return `${url}/?ws=${encodeURIComponent(root)}${sessionId ? `&s=${sessionId}` : ""}`;
}

/** Back-compat for router clients (`hib chat`, `hib ask`): the shared daemon. */
export async function connect(): Promise<{ client: HibClient; url: string; embedded: boolean }> {
  const d = await ensureDaemon();
  return { client: d.client, url: d.url, embedded: false };
}
