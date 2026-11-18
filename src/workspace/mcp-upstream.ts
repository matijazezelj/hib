/**
 * The daemon's side of a trusted read-only MCP server ([mcp.<name>] in config.toml): its bearer token, a minimal
 * streamable-HTTP client, and which of its tools an agent may see. The agent never talks to the server: hib's own MCP
 * server (hib-mcp.ts) relays to the daemon, which calls this with the token the agent never sees.
 */
import { readFileSync, statSync } from "node:fs";
import type { McpUpstream } from "../config";

export interface UpstreamTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: { readOnlyHint?: boolean; [k: string]: unknown };
}

/**
 * The server's bearer token. From token_env, or token_file: the file's only KEY=VALUE line, the line token_key names,
 * or the whole file when it has no KEY=VALUE lines. Several keys and no token_key is an error that names them: hib
 * never guesses which credential to send. Messages never carry the token itself.
 */
export function readToken(u: McpUpstream, env: Record<string, string | undefined> = process.env): string | undefined {
  if (u.tokenEnv) {
    const v = env[u.tokenEnv]?.trim();
    if (!v) throw new Error(`token_env ${u.tokenEnv} isn't set in the daemon's environment`);
    return v;
  }
  if (!u.tokenFile) return undefined;
  let text: string;
  try {
    if (statSync(u.tokenFile).size > 64 * 1024) throw new Error("larger than 64 KB");
    text = readFileSync(u.tokenFile, "utf8");
  } catch (e: any) {
    throw new Error(`can't read token_file ${u.tokenFile} (${e?.code ?? e?.message ?? e})`);
  }
  const pairs: [string, string][] = [];
  const other: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(t);
    if (m) pairs.push([m[1]!, unquote(m[2]!.trim())]);
    else other.push(t);
  }
  const keys = pairs.map(([k]) => k).join(", ");
  if (u.tokenKey) {
    const hit = pairs.find(([k]) => k === u.tokenKey);
    if (!hit?.[1]) throw new Error(`token_file ${u.tokenFile} has no ${u.tokenKey}${keys ? ` (it has ${keys})` : ""}`);
    return hit[1];
  }
  if (pairs.length > 1) throw new Error(`token_file ${u.tokenFile} has several keys (${keys}): set token_key to the one to send`);
  if (pairs.length === 1) {
    if (!pairs[0]![1]) throw new Error(`token_file ${u.tokenFile}: ${pairs[0]![0]} is empty`);
    return pairs[0]![1];
  }
  if (other.length !== 1) throw new Error(`token_file ${u.tokenFile} should hold the token on one line, or KEY=VALUE lines with token_key`);
  return other[0];
}

function unquote(v: string): string {
  return (v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")) ? v.slice(1, -1) : v;
}

/** Tool names an agent can be given: Claude Code and Codex both want [A-Za-z0-9_-], 64 at most with the prefix. */
export const exposedName = (server: string, tool: string) => `${server}__${tool}`;
const NAME_OK = /^[A-Za-z0-9_-]+$/;

function glob(g: string): RegExp {
  return new RegExp(`^${g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`);
}

/**
 * The tools an agent may call: those the server marks readOnlyHint (nothing else, whatever the config says), narrowed
 * by the config's globs, with names both CLIs accept. `note` says why some or all were left out.
 */
export function readOnlyTools(u: McpUpstream, tools: UpstreamTool[]): { tools: UpstreamTool[]; note?: string } {
  const globs = u.tools.map(glob);
  const ro = tools.filter((t) => t?.annotations?.readOnlyHint === true);
  const picked = ro.filter((t) => !globs.length || globs.some((g) => g.test(t.name)));
  const ok = picked.filter((t) => NAME_OK.test(t.name) && `mcp__hib__${exposedName(u.name, t.name)}`.length <= 64);
  const notes: string[] = [];
  if (!ro.length) notes.push(`none of its ${tools.length} tools is marked read-only (readOnlyHint), so none is offered`);
  else if (ro.length < tools.length) notes.push(`${tools.length - ro.length} of its ${tools.length} tools aren't marked read-only and aren't offered`);
  if (ro.length && !picked.length) notes.push("no read-only tool matches its tools = [...] list");
  if (ok.length < picked.length) notes.push(`${picked.length - ok.length} tools have names an agent CLI can't take and aren't offered`);
  return { tools: ok, ...(notes.length ? { note: notes.join("; ") } : {}) };
}

export interface CallResult {
  content?: { type: string; text?: string; [k: string]: unknown }[];
  structuredContent?: unknown;
  isError?: boolean;
}

/**
 * A minimal MCP client over streamable HTTP: JSON or SSE replies, the Mcp-Session-Id header, one re-initialise when
 * the server forgets the session. Errors name the server and the HTTP status, never the URL (its query string could
 * carry a credential) or the token.
 */
export class McpClient {
  private sid?: string;
  private ready?: Promise<void>;
  private nextId = 1;

  constructor(
    readonly upstream: McpUpstream,
    private token: () => string | undefined = () => readToken(upstream),
    private fetchImpl: typeof fetch = fetch,
  ) {}

  private async post(body: unknown, timeoutMs: number): Promise<{ status: number; msg?: any }> {
    const token = this.token();
    const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json, text/event-stream" };
    if (token) headers.authorization = `Bearer ${token}`;
    if (this.sid) headers["mcp-session-id"] = this.sid;
    let r: Response;
    try {
      r = await this.fetchImpl(this.upstream.url, { method: "POST", headers, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs), redirect: "error" });
    } catch (e: any) {
      throw new Error(e?.name === "TimeoutError" ? `no answer in ${timeoutMs / 1000} s` : "can't be reached");
    }
    const sid = r.headers.get("mcp-session-id");
    if (sid) this.sid = sid;
    const id = (body as any).id;
    if (id === undefined || r.status === 202) return { status: r.status };
    const text = await r.text();
    if (!r.ok) return { status: r.status };
    const msgs: any[] = [];
    if ((r.headers.get("content-type") ?? "").includes("text/event-stream")) {
      for (const ev of text.split(/\r?\n\r?\n/)) {
        const data = ev.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
        if (data) msgs.push(...[JSON.parse(data)].flat());
      }
    } else if (text.trim()) msgs.push(...[JSON.parse(text)].flat());
    return { status: r.status, msg: msgs.find((m) => m?.id === id) };
  }

  private async rpc(method: string, params: unknown, timeoutMs: number, retry = true): Promise<any> {
    if (method !== "initialize") await this.init();
    const r = await this.post({ jsonrpc: "2.0", id: this.nextId++, method, params }, timeoutMs);
    if (r.status === 404 && this.sid && retry && method !== "initialize") {
      // The server dropped our session (restarted): start a new one, once.
      this.sid = undefined;
      this.ready = undefined;
      return this.rpc(method, params, timeoutMs, false);
    }
    if (r.status < 200 || r.status >= 300) throw new Error(`HTTP ${r.status}${r.status === 401 || r.status === 403 ? " (check its token)" : ""}`);
    if (!r.msg) throw new Error("no reply");
    if (r.msg.error) throw new Error(`error ${r.msg.error.code ?? ""}: ${String(r.msg.error.message ?? "").slice(0, 300)}`);
    return r.msg.result;
  }

  init(): Promise<void> {
    this.ready ??= (async () => {
      await this.rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "hib", version: "1" } }, 5_000);
      await this.post({ jsonrpc: "2.0", method: "notifications/initialized" }, 5_000);
    })().catch((e) => {
      this.ready = undefined;
      throw e;
    });
    return this.ready;
  }

  async listTools(timeoutMs = 5_000): Promise<UpstreamTool[]> {
    const out: UpstreamTool[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 20; page++) {
      const r = await this.rpc("tools/list", cursor ? { cursor } : {}, timeoutMs);
      out.push(...(Array.isArray(r?.tools) ? r.tools : []));
      cursor = typeof r?.nextCursor === "string" && r.nextCursor ? r.nextCursor : undefined;
      if (!cursor) break;
    }
    return out;
  }

  callTool(name: string, args: unknown, timeoutMs = 120_000): Promise<CallResult> {
    return this.rpc("tools/call", { name, arguments: args ?? {} }, timeoutMs);
  }
}

/** A result's text for the guard: text parts as they are, anything else named and withheld. */
export function resultText(r: CallResult): string {
  const parts: string[] = [];
  for (const c of Array.isArray(r?.content) ? r.content : []) {
    if (c?.type === "text" && typeof c.text === "string") parts.push(c.text);
    else parts.push(`[hib withheld a part of this result (${String(c?.type ?? "").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 20) || "not text"}): only text is guarded]`);
  }
  // Structured output only when there's no text: servers send the same data both ways, and both would go through the guard.
  if (!parts.length && r?.structuredContent !== undefined) parts.push(JSON.stringify(r.structuredContent));
  return parts.join("\n");
}

/**
 * Cut to `max` characters at a boundary a value is unlikely to span (a newline, space or comma), so a cut never leaves
 * half an address or key for the guard to miss.
 */
export function cutResult(text: string, max: number): { text: string; cut: boolean } {
  if (text.length <= max) return { text, cut: false };
  const at = Math.max(text.lastIndexOf("\n", max), text.lastIndexOf(" ", max), text.lastIndexOf(",", max));
  return { text: text.slice(0, at > 0 ? at : max), cut: true };
}
