import { appendFileSync, chmodSync, existsSync, mkdirSync, renameSync, rmSync, statSync } from "node:fs";
import { hostname } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import { detect } from "./guard/detectors";
import { machineTerms } from "./guard";
import type { EventsConfig } from "./config";

/**
 * Security events as JSON lines, for a log collector (SIB) to ship and alert on. Contract: sib/docs/hib-events-spec.md,
 * schema 1. The directory holds event files only, so a collector can mount it alone, never ~/.hib with the token,
 * vault key and database next to it. Never logged: prompts, model or tool output, file contents, diffs, tokens, vault
 * values. Fields that can carry user text go through the redactor and are cut to 300 characters.
 */

export const SCHEMA = 1;
const TEXT_MAX = 300;
const AUTH_WINDOW_MS = 60_000;

export type { EventsConfig };

export type Mode = "router" | "workspace" | "daemon";
export type Severity = "info" | "warning" | "critical";

/** Fields every event may carry; optional ones are left out when unknown, never null. */
export interface Context {
  mode: Mode;
  session_id?: string;
  run_id?: string;
  workspace?: string;
  account?: string;
  model?: string;
  route?: string;
}

const FIXED: Record<string, Severity> = {
  "daemon.start": "info",
  "daemon.stop": "info",
  "auth.failure": "warning",
  "approval.pending": "info",
  "data.block": "warning",
  "sandbox.unavailable": "warning",
  "protected.reverted": "critical",
  "terminal.open": "warning",
  "session.start": "info",
  "session.end": "info",
};

/** Fixed per type; the three types with a decision are a warning when it went against the request. */
export function severityOf(event: string, f: Record<string, unknown>): Severity {
  if (event === "guard.decision") return f.action === "rejected" || f.action === "timeout" ? "warning" : "info";
  if (event === "tool.permission" || event === "sandbox.network") return f.decision === "deny" ? "warning" : "info";
  return FIXED[event] ?? "info";
}

function version(): string {
  try {
    const pkg = require("../package.json") as { version?: string };
    if (pkg.version) return pkg.version;
  } catch {}
  const git = Bun.spawnSync(["git", "-C", import.meta.dir, "rev-parse", "--short", "HEAD"], { stdout: "pipe", stderr: "ignore" });
  return git.success ? `0.0.0+${git.stdout.toString().trim()}` : "0.0.0";
}

export class EventLog {
  readonly file: string;
  private size = -1;
  private readonly host = hostname();
  private readonly version = version();
  private readonly identities = machineTerms();
  private auth = new Map<string, { last: number; suppressed: number; timer?: ReturnType<typeof setTimeout> }>();

  constructor(
    readonly cfg: EventsConfig,
    private guard: { terms: string[]; patterns: { category: string; regex: string; flags?: string }[] } = { terms: [], patterns: [] },
    private now: () => Date = () => new Date(),
  ) {
    this.file = join(cfg.dir, "events.jsonl");
  }

  /** User-controlled text, made safe to log: secrets and identifiers become [CATEGORY], then it's cut to 300 chars. */
  redact(text: string): string {
    const found = detect(text, { level: "standard", terms: this.guard.terms, patterns: this.guard.patterns, identities: this.identities });
    let out = "";
    let pos = 0;
    for (const f of found) {
      out += text.slice(pos, f.start) + `[${f.category}]`;
      pos = f.end;
    }
    out += text.slice(pos);
    return out.length > TEXT_MAX ? out.slice(0, TEXT_MAX) + "…" : out;
  }

  /** A path inside the workspace, relative to it; outside it, redacted like any other text. */
  path(p: string, workspace?: string): string {
    if (workspace && isAbsolute(p)) {
      const rel = relative(workspace, p);
      if (rel && !rel.startsWith("..") && !isAbsolute(rel)) return rel;
    }
    return workspace && !isAbsolute(p) ? p : this.redact(p);
  }

  emit(event: string, ctx: Context, fields: Record<string, unknown> = {}): void {
    if (!this.cfg.enabled) return;
    const line: Record<string, unknown> = {
      ts: this.now().toISOString(),
      schema: SCHEMA,
      source: "hib",
      host: this.host,
      hib_version: this.version,
      event,
      severity: severityOf(event, fields),
      mode: ctx.mode,
    };
    for (const k of ["session_id", "run_id", "workspace", "account", "model", "route"] as const) if (ctx[k] !== undefined && ctx[k] !== "") line[k] = ctx[k];
    for (const [k, v] of Object.entries(fields)) if (v !== undefined && v !== null) line[k] = v;
    try {
      this.write(JSON.stringify(line) + "\n");
    } catch (e: any) {
      // The event log must never take a request down with it.
      console.error(`hib: could not write ${this.file}: ${e?.message ?? e}`);
    }
  }

  /** A rejected request. One line per reason and remote per 60 s; failures in between are counted on the next line. */
  authFailure(reason: "token" | "host" | "origin", path: string, remote: string | undefined): void {
    const key = `${reason}|${remote ?? ""}`;
    const t = Date.now();
    const s = this.auth.get(key);
    if (s && t - s.last < AUTH_WINDOW_MS) {
      s.suppressed++;
      // Flush the count when the window closes, so a burst that stops is still reported in full.
      s.timer ??= setTimeout(() => {
        const cur = this.auth.get(key);
        if (!cur?.suppressed) return;
        this.emit("auth.failure", { mode: "daemon" }, { reason, path: this.redact(path), ...(remote ? { remote } : {}), count: cur.suppressed });
        this.auth.set(key, { last: Date.now(), suppressed: 0 });
      }, AUTH_WINDOW_MS - (t - s.last));
      (s.timer as any).unref?.();
      return;
    }
    this.auth.set(key, { last: t, suppressed: 0 });
    this.emit("auth.failure", { mode: "daemon" }, { reason, path: this.redact(path), ...(remote ? { remote } : {}), count: 1 + (s?.suppressed ?? 0) });
  }

  private write(line: string) {
    if (this.size < 0) {
      mkdirSync(this.cfg.dir, { recursive: true, mode: 0o700 });
      chmodSync(this.cfg.dir, 0o700);
      this.size = existsSync(this.file) ? statSync(this.file).size : 0;
    }
    const bytes = Buffer.byteLength(line);
    if (this.size > 0 && this.size + bytes > this.cfg.maxMb * 1024 * 1024) this.rotate();
    const fresh = this.size === 0 && !existsSync(this.file);
    appendFileSync(this.file, line, { mode: 0o600 }); // one write per event; nothing buffered in the process
    if (fresh) chmodSync(this.file, 0o600);
    this.size += bytes;
  }

  /** events.jsonl -> .1, .1 -> .2 … up to `keep`; the oldest goes. */
  private rotate() {
    const keep = Math.max(0, Math.floor(this.cfg.keep));
    if (keep === 0) rmSync(this.file, { force: true });
    else {
      rmSync(`${this.file}.${keep}`, { force: true });
      for (let i = keep - 1; i >= 1; i--) if (existsSync(`${this.file}.${i}`)) renameSync(`${this.file}.${i}`, `${this.file}.${i + 1}`);
      renameSync(this.file, `${this.file}.1`);
    }
    this.size = 0;
  }
}

/** For code paths without a configured log (tests, one-off commands). */
export const noEvents = () => new EventLog({ enabled: false, dir: "", maxMb: 20, keep: 5 });
