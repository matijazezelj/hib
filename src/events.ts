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
const SCAN_MAX = 8192; // text past this can't reach the 300 characters that are kept, so it isn't scanned

/**
 * Fields hib writes itself (ids, enums, numbers, the workspace root): never redacted. Every other string field, at any
 * depth, can carry user or agent text and is scrubbed for secrets when the line is written, whatever the caller did.
 */
const OWN_FIELDS = new Set([
  "ts", "schema", "source", "host", "hib_version", "event", "severity", "mode", "session_id", "run_id", "workspace", "account", "model", "route",
  "bind", "port", "sandbox", "remote", "decision", "decided_by", "action", "kind", "agent", "sensitive", "count", "uptime_sec", "timeout_sec", "signal", "change", "findings",
]);

/** Lone surrogates become U+FFFD (every line stays valid UTF-8); zero-width and bidi controls go; look-alike forms fold (NFKC). */
export function sanitize(text: string): string {
  return text.toWellFormed().replace(/\p{Cf}/gu, "").normalize("NFKC");
}

type Span = { start: number; end: number; category: string };

/**
 * Secrets the guard's detectors don't look for in a log line, or can't see because of their shape. Over-redacting is
 * fine here: these lines are metadata for alerts, and an opaque id lost to [OPAQUE] costs nothing.
 */
const EXTRA: { category: string; re: RegExp; group?: number; secret?: (v: string) => boolean }[] = [
  { category: "CREDENTIALS", re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s@/]+)@/gi, group: 1 }, // https://user:PASS@host
  { category: "CREDENTIALS", re: /(?:^|[\s"'])(?:-u|--user)[\s=]+["']?[^\s:"']+:([^\s"']+)/g, group: 1 }, // curl -u user:PASS
  // Authorization: <scheme> <value>, Cookie, X-Api-Key and the like: everything after the colon, up to a quote or line end.
  { category: "AUTH-HEADER", re: /\b(?:authorization|proxy-authorization|cookie|set-cookie|x-[a-z0-9-]*(?:key|token|secret|auth|signature)[a-z0-9-]*)\s*:\s*([^"'\n]+)/gi, group: 1 },
  { category: "URL-ENCODED", re: /(?:%[0-9a-f]{2}){4,}/gi }, // a percent-encoded run hides whatever it spells
];

/**
 * Opaque runs with no known shape: a key one character short of its pattern, raw hex, base64 or hex encodings,
 * look-alike letters. Letters and digits mixed (16+), long and mixed-case (24+), or long with a digit (32+: a hex
 * encoding can be digits only). A run touching a line break counts from 8: half of a key split across lines.
 */
const RUN = /[\p{L}\p{N}_+=-]{8,}/gu;
function opaque(v: string, atBreak: boolean): boolean {
  const letter = /\p{L}/u.test(v);
  const digit = /\p{N}/u.test(v);
  if (v.length >= (atBreak ? 8 : 16) && letter && digit) return true;
  if (v.length >= 24 && /\p{Lu}/u.test(v) && /\p{Ll}/u.test(v)) return true;
  return v.length >= 32 && digit;
}

function extraSpans(text: string): Span[] {
  const out: Span[] = [];
  for (const m of text.matchAll(RUN)) {
    const atBreak = /[\r\n\\]/.test(text[m.index! - 1] ?? "") || /[\r\n\\]/.test(text[m.index! + m[0].length] ?? "");
    if (opaque(m[0], atBreak)) out.push({ start: m.index!, end: m.index! + m[0].length, category: "OPAQUE" });
  }
  for (const x of EXTRA)
    for (const m of text.matchAll(x.re)) {
      const v = m[x.group ?? 0];
      if (!v || (x.secret && !x.secret(v))) continue;
      const start = m.index! + (x.group ? m[0].lastIndexOf(v) : 0);
      out.push({ start, end: start + v.length, category: x.category });
    }
  return out;
}

/** Spans replaced by [CATEGORY]; overlapping ones merge into one, labelled by the first. */
function replaceSpans(text: string, spans: Span[]): string {
  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  let out = "";
  let pos = 0;
  for (const s of spans) {
    if (s.end <= pos) continue;
    if (s.start < pos) {
      pos = s.end; // overlaps the previous replacement: extend it
      continue;
    }
    out += text.slice(pos, s.start) + `[${s.category}]`;
    pos = s.end;
  }
  return out + text.slice(pos);
}

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
  private heartbeat?: ReturnType<typeof setInterval>;
  private stopHooks: (() => void)[] = [];
  private stopped = false;
  private auth = new Map<string, { last: number; suppressed: number; path: string; remote?: string; timer?: ReturnType<typeof setTimeout> }>();

  constructor(
    readonly cfg: EventsConfig,
    private guard: { terms: string[]; patterns: { category: string; regex: string; flags?: string }[] } = { terms: [], patterns: [] },
    private now: () => Date = () => new Date(),
  ) {
    this.file = join(cfg.dir, "events.jsonl");
  }

  /**
   * User-controlled text, made safe to log (command, url, reasons): secrets and identifiers (the guard at `standard`,
   * plus the event log's own patterns) become [CATEGORY], then it's cut to 300 chars.
   */
  redact(text: string): string {
    return this.clean(text, "standard");
  }

  /** Secrets only, for fields that should stay readable otherwise (a host name, a tool name, a relative path). */
  scrub(text: string): string {
    return this.clean(text, "minimal");
  }

  private clean(raw: string, level: "minimal" | "standard"): string {
    const text = sanitize(raw.length > SCAN_MAX ? raw.slice(0, SCAN_MAX) : raw);
    const found: Span[] = detect(text, { level, terms: this.guard.terms, patterns: this.guard.patterns, identities: level === "minimal" ? [] : this.identities });
    const out = replaceSpans(text, [...found, ...extraSpans(text)]);
    return out.length > TEXT_MAX ? out.slice(0, TEXT_MAX) + "…" : out;
  }

  /** A path inside the workspace, relative to it; outside it, redacted like any other text. Either way, no secrets. */
  path(p: string, workspace?: string): string {
    if (workspace && isAbsolute(p)) {
      const rel = relative(workspace, p);
      if (rel && !rel.startsWith("..") && !isAbsolute(rel)) return this.scrub(rel);
    }
    return workspace && !isAbsolute(p) ? this.scrub(p) : this.redact(p);
  }

  /** Every string a caller passed, at any depth, scrubbed unless hib wrote it itself (OWN_FIELDS). */
  private safe(value: unknown, key: string): unknown {
    if (typeof value === "string") return OWN_FIELDS.has(key) ? value.toWellFormed() : this.scrub(value);
    if (Array.isArray(value)) return value.map((v) => this.safe(v, key));
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, this.safe(v, k)]));
    return value;
  }

  emit(event: string, ctx: Context, fields: Record<string, unknown> = {}): void {
    if (!this.cfg.enabled || this.stopped) return; // daemon.stop stays the last line
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
    for (const k of ["session_id", "run_id", "workspace", "account", "model", "route"] as const) if (ctx[k] !== undefined && ctx[k] !== "") line[k] = ctx[k]!.toWellFormed();
    for (const [k, v] of Object.entries(fields)) if (v !== undefined && v !== null) line[k] = this.safe(v, k);
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
      s.timer ??= setTimeout(() => this.flushAuth(key), AUTH_WINDOW_MS - (t - s.last));
      (s.timer as any).unref?.();
      return;
    }
    this.auth.set(key, { last: t, suppressed: 0, path, remote });
    this.emit("auth.failure", { mode: "daemon" }, { reason, path: this.redact(path), ...(remote ? { remote } : {}), count: 1 });
  }

  /** Writes the failures counted but not yet logged: one window (`key`), or all of them. */
  flushAuth(key?: string): void {
    for (const [k, s] of key ? [[key, this.auth.get(key)] as const] : [...this.auth]) {
      if (!s) continue;
      clearTimeout(s.timer);
      s.timer = undefined;
      if (!s.suppressed) continue;
      const reason = k.slice(0, k.indexOf("|"));
      this.emit("auth.failure", { mode: "daemon" }, { reason, path: this.redact(s.path), ...(s.remote ? { remote: s.remote } : {}), count: s.suppressed });
      this.auth.set(k, { last: Date.now(), suppressed: 0, path: s.path, remote: s.remote });
    }
  }

  /**
   * daemon.alive every `heartbeatSec` (0: off), the first one a full interval after daemon.start. A collector that saw
   * heartbeats, then none and no daemon.stop, knows the daemon died (a crash or SIGKILL writes nothing).
   */
  startHeartbeat(): void {
    if (!this.cfg.enabled || !(this.cfg.heartbeatSec > 0) || this.heartbeat) return;
    const started = Date.now();
    this.heartbeat = setInterval(() => this.emit("daemon.alive", { mode: "daemon" }, { uptime_sec: Math.round((Date.now() - started) / 1000) }), this.cfg.heartbeatSec * 1000);
    (this.heartbeat as any).unref?.(); // the server keeps the daemon alive, not the heartbeat
  }

  /** Work that writes its own last events (agent sessions ending) and must run before daemon.stop. */
  onStop(fn: () => void): void {
    this.stopHooks.push(fn);
  }

  /**
   * A clean stop, once: sessions end, counted auth failures are written (a burst that ends with a restart isn't lost),
   * then daemon.stop, the last line. Anything emitted after it is dropped.
   */
  stop(fields: Record<string, unknown> = {}): void {
    if (this.stopped) return;
    clearInterval(this.heartbeat);
    for (const fn of this.stopHooks) {
      try {
        fn();
      } catch {}
    }
    this.flushAuth();
    this.emit("daemon.stop", { mode: "daemon" }, fields);
    this.stopped = true;
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
export const noEvents = () => new EventLog({ enabled: false, dir: "", maxMb: 20, keep: 5, heartbeatSec: 0 });
