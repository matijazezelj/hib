import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Engine, HibEvent, ChatInput } from "./engine";
import type { Message } from "./providers/types";
import index from "../web/index.html";
import { listFiles, readFile } from "./workspace/fs";
import * as git from "./workspace/git";
import { terminalSocket, type TermData } from "./workspace/terminal";
import { WorkspaceSessions } from "./workspace/sessions";
import { Analyzer } from "./analyze";
import { loadTable } from "./analyze/table";
import { basename } from "node:path";
import { safePath } from "./workspace/fs";
import { ClaudeDriver } from "./workspace/claude-driver";
import { CodexDriver } from "./workspace/codex-driver";

export function apiToken(home: string): string {
  const file = join(home, "token");
  if (!existsSync(file)) {
    writeFileSync(file, Buffer.from(crypto.getRandomValues(new Uint8Array(24))).toString("base64url"), { mode: 0o600 });
    chmodSync(file, 0o600);
  }
  return readFileSync(file, "utf8").trim();
}

const json = (data: unknown, status = 200) => Response.json(data, { status });
const sse = (body: ReadableStream) => new Response(body, { headers: { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" } });

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.map((p: any) => (typeof p === "string" ? p : p?.type === "text" ? p.text : "")).join("");
  return "";
}

function toMessages(raw: any[]): Message[] {
  return (raw ?? [])
    .map((m) => ({ role: m.role === "developer" ? "system" : m.role, content: textOf(m.content) }))
    .filter((m): m is Message => ["system", "user", "assistant"].includes(m.role) && m.content.length > 0);
}

/** Feeds engine events into an SSE stream, ending it on completion or client disconnect. */
function eventStream(engine: Engine, input: ChatInput, map: (e: HibEvent) => string[] | null, onEnd?: () => string[]): ReadableStream {
  const ac = new AbortController();
  const enc = new TextEncoder();
  return new ReadableStream({
    async start(ctrl) {
      const send = (s: string) => {
        try {
          ctrl.enqueue(enc.encode(s));
        } catch {}
      };
      const ping = setInterval(() => send(": ping\n\n"), 15_000);
      try {
        for await (const e of engine.chat(input, ac.signal)) for (const line of map(e) ?? []) send(`data: ${line}\n\n`);
      } catch (e: any) {
        send(`data: ${JSON.stringify({ type: "error", message: String(e?.message ?? e) })}\n\n`);
      } finally {
        clearInterval(ping);
        for (const line of onEnd?.() ?? []) send(`data: ${line}\n\n`);
        try {
          ctrl.close();
        } catch {}
      }
    },
    cancel() {
      ac.abort();
    },
  });
}

function openaiChunk(id: string, model: string, delta: Record<string, unknown>, finish: string | null = null) {
  return JSON.stringify({ id, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model, choices: [{ index: 0, delta, finish_reason: finish }] });
}

export function startServer(engine: Engine, opts: { port: number; token: string; onShutdown?: () => void }) {
  const { port, token } = opts;
  const workspaces = engine.workspaces;
  const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  const origins = new Set([`http://127.0.0.1:${port}`, `http://localhost:${port}`]);

  /**
   * Defends against browsers: the Host check stops DNS rebinding and the Origin check plus SameSite cookie stop other sites.
   * Local processes are trusted: any of them can call /hib/session, just as they can read ~/.hib/token.
   */
  function authorized(req: Request): boolean {
    if (!hosts.has(req.headers.get("host") ?? "")) return false;
    const origin = req.headers.get("origin");
    if (origin && !origins.has(origin)) return false;
    const bearer = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
    const cookie = /(?:^|;\s*)hib_token=([^;]+)/.exec(req.headers.get("cookie") ?? "")?.[1];
    return bearer === token || cookie === token;
  }

  const guarded = (fn: (req: Request & { params: Record<string, string> }) => Response | Promise<Response>) => async (req: any) => {
    if (!authorized(req)) return json({ error: { message: "unauthorized" } }, 401);
    try {
      return await fn(req);
    } catch (e: any) {
      return json({ error: { message: String(e?.message ?? e) } }, 400);
    }
  };
  const q = (req: Request, k: string) => new URL(req.url).searchParams.get(k) ?? "";
  // Every /ws call names its folder with ?root=; only registered folders are served.
  const ws = (fn: (root: string, req: Request & { params: Record<string, string> }) => Response | Promise<Response>) =>
    guarded((req) => {
      const root = workspaces.resolve(q(req, "root"));
      return root ? fn(root, req) : json({ error: { message: "unknown workspace; run hib in that folder first" } }, 404);
    });
  const sessions = new WorkspaceSessions(engine, engine.sealer, (p) => (p === "claude" ? new ClaudeDriver() : p === "codex" ? new CodexDriver() : null));
  const analyzer = new Analyzer(engine);
  // Files for analysis: a path inside a registered workspace (web), or an absolute path from the local CLI.
  const analysisPath = (b: any) => {
    if (b.root) {
      const root = workspaces.resolve(b.root);
      if (!root) throw new Error("unknown workspace");
      return safePath(root, String(b.path ?? ""));
    }
    if (!String(b.path ?? "").startsWith("/")) throw new Error("path must be absolute");
    return String(b.path);
  };
  const sessionIn = (root: string, id: string) => {
    const snap = sessions.snapshot(id);
    return snap.row && (snap.row as any).workspace !== root ? null : snap;
  };
  process.once("exit", () => sessions.closeAll());



  const modelList = () => {
    const ids = ["hib/auto", ...Object.keys(engine.cfg.routes).map((r) => `hib/${r}`), ...[...engine.plugins.agents.keys()].map((a) => `hib/agent/${a}`)];
    for (const a of engine.cfg.accounts) for (const m of Object.keys(engine.cfg.models[a.provider] ?? {})) ids.push(`${a.provider}@${a.name}/${m}`);
    return ids;
  };

  return Bun.serve<TermData, any>({
    hostname: "127.0.0.1",
    port,
    idleTimeout: 255,
    websocket: terminalSocket,
    routes: {
      "/ws/tree": ws(async (root) => json({ root, files: await listFiles(root), git: await git.status(root), policy: workspaces.policy(root) })),
      "/ws/egress/:id": ws((root, req) => (sessionIn(root, req.params.id!) ? json(sessions.egress(req.params.id!)) : json({ error: { message: "not found" } }, 404))),
      "/ws/file": ws((root, req) => json(readFile(root, q(req, "path")))),
      "/ws/git/status": ws(async (root) => json(await git.status(root))),
      "/ws/git/diff": ws(async (root, req) => json({ diff: await git.diff(root, q(req, "path")) })),
      "/ws/git/discard": { POST: ws(async (root, req) => (await git.discard(root, ((await req.json()) as any).path), json({ ok: true }))) },
      "/ws/git/commit": { POST: ws(async (root, req) => json({ ok: true, summary: await git.commit(root, ((await req.json()) as any).message ?? "") })) },
      "/ws/turn": {
        POST: ws(async (root, req) => {
          const b: any = await req.json();
          if (b.sessionId && !sessionIn(root, b.sessionId)) return json({ error: { message: "session not in this workspace" } }, 404);
          const r = sessions.startTurn({ sessionId: b.sessionId || undefined, root, model: b.model || undefined, text: String(b.text ?? "") });
          return "error" in r ? json({ error: { message: r.error } }, 409) : json(r);
        }),
      },
      "/ws/sessions": ws((root) => json(sessions.list(root))),
      "/ws/sessions/:id": ws((root, req) => {
        const snap = sessionIn(root, req.params.id!);
        return snap ? json(snap) : json({ error: { message: "not found" } }, 404);
      }),
      // Live events for a session: replays everything after ?after=seq, then follows until the client leaves.
      "/ws/sessions/:id/stream": ws((root, req) => {
        const id = req.params.id!;
        if (!sessionIn(root, id)) return json({ error: { message: "not found" } }, 404);
        const after = Number(q(req, "after") || 0);
        const enc = new TextEncoder();
        let unsub = () => {};
        let ping: Timer | undefined;
        return sse(
          new ReadableStream({
            start(ctrl) {
              const send = (s: string) => {
                try {
                  ctrl.enqueue(enc.encode(s));
                } catch {
                  unsub();
                }
              };
              unsub = sessions.subscribe(id, after, (seq, e) => send(`id: ${seq}\ndata: ${JSON.stringify({ seq, ...e })}\n\n`));
              ping = setInterval(() => send(": ping\n\n"), 15_000);
            },
            cancel() {
              unsub();
              clearInterval(ping);
            },
          }),
        );
      }),
      "/ws/permission": {
        POST: ws(async (root, req) => {
          const b: any = await req.json();
          if (!sessionIn(root, b.sessionId)) return json({ error: { message: "not found" } }, 404);
          return json({ ok: sessions.answer(b.sessionId, b.id, b.choice, b.message) });
        }),
      },
      "/ws/interrupt": {
        POST: ws(async (root, req) => {
          const id = ((await req.json()) as any).sessionId;
          if (!sessionIn(root, id)) return json({ error: { message: "not found" } }, 404);
          await sessions.interrupt(id);
          return json({ ok: true });
        }),
      },
      "/ws/terminal": (req: Request, server: any) => {
        if (!authorized(req)) return new Response("unauthorized", { status: 401 });
        const root = workspaces.resolve(q(req, "root"));
        if (!root) return new Response("unknown workspace", { status: 404 });
        if (workspaces.policy(root)) return new Response("the browser terminal is off in sensitive workspaces", { status: 403 });
        return server.upgrade(req, { data: { kind: "terminal", cwd: root } }) ? undefined : new Response("upgrade failed", { status: 400 });
      },
      "/hib/workspaces": {
        GET: guarded(() => json(workspaces.list())),
        POST: guarded(async (req) => json({ root: workspaces.register(String(((await req.json()) as any).root ?? "")) })),
        DELETE: guarded((req) => (workspaces.forget(q(req, "root")), json({ ok: true }))),
      },
      "/hib/workspaces/policy": {
        POST: guarded(async (req) => {
          const b: any = await req.json();
          // Tightening works over HTTP; lifting a policy only from the CLI, so a token alone can't switch it off.
          if (!b.policy) return json({ error: { message: "lift a sensitive policy with `hib workspace normal` in that folder" } }, 403);
          const p = { sensitive: true as const, account: String(b.policy.account ?? ""), ...(b.policy.model ? { model: String(b.policy.model) } : {}) };
          return json({ root: workspaces.setPolicy(String(b.root ?? ""), p) });
        }),
      },
      "/hib/analyze/profile": {
        POST: guarded(async (req) => {
          const b: any = await req.json();
          return json(analyzer.profileOf(analysisPath(b), b.share ?? []));
        }),
      },
      "/hib/analyze/plan": {
        POST: guarded(async (req) => {
          const b: any = await req.json();
          const paths = Array.isArray(b.paths) && b.paths.length ? b.paths.map((p: string) => analysisPath({ ...b, path: p })) : [analysisPath(b)];
          return json(await analyzer.plan({ path: paths[0], paths, question: String(b.question ?? ""), model: b.model || undefined, share: b.share ?? [] }));
        }),
      },
      "/hib/analyze/run": { POST: guarded(async (req) => json(await analyzer.run(((await req.json()) as any).id))) },
      "/hib/analyze/fix": { POST: guarded(async (req) => json(await analyzer.fix(((await req.json()) as any).id))) },
      "/hib/analyze/explain": {
        POST: guarded(async (req) => {
          const b: any = await req.json();
          return json(b.preview ? { sent: analyzer.explainPreview(b.id), leaks: analyzer.leaks(b.id) } : await analyzer.explain(b.id));
        }),
      },
      "/hib/egress": guarded((req) => json(engine.egressList({ limit: Number(q(req, "limit") || 20), cwd: q(req, "cwd") || undefined, run: q(req, "run") || undefined }))),
      "/hib/egress/:id": guarded((req) => {
        const row = engine.egressGet(req.params.id === "last" ? "last" : Number(req.params.id));
        return row ? json(row) : json({ error: { message: "not found" } }, 404);
      }),
      "/hib/shutdown": {
        POST: guarded(() => {
          setTimeout(() => {
            sessions.closeAll();
            opts.onShutdown ? opts.onShutdown() : process.exit(0);
          }, 50);
          return json({ ok: true });
        }),
      },

      "/": index,
      "/favicon.ico": new Response(null, { status: 204 }),
      // Sets the session cookie for the web UI. SameSite=Strict means other sites can never send it.
      "/hib/session": (req) => {
        if (!hosts.has(req.headers.get("host") ?? "")) return new Response("bad host", { status: 400 });
        return new Response(null, { status: 204, headers: { "set-cookie": `hib_token=${token}; HttpOnly; SameSite=Strict; Path=/` } });
      },

      "/v1/models": guarded(() => json({ object: "list", data: modelList().map((id) => ({ id, object: "model", owned_by: "hib" })) })),

      "/v1/chat/completions": {
        POST: guarded(async (req) => {
          const body: any = await req.json();
          const input: ChatInput = { messages: toMessages(body.messages), model: body.model ?? "hib/auto" };
          const id = `chatcmpl-${crypto.randomUUID()}`;
          let model = input.model!;
          let revising = false;

          if (body.stream) {
            let first = true;
            return sse(
              eventStream(
                engine, input,
                (e) => {
                  const out: string[] = [];
                  if (e.type === "meta") model = e.model;
                  if (first && (e.type === "text" || e.type === "error")) {
                    out.push(openaiChunk(id, model, { role: "assistant", content: "" }));
                    first = false;
                  }
                  if (e.type === "text") {
                    if (e.part === "revision" && !revising) {
                      revising = true;
                      out.push(openaiChunk(id, model, { content: "\n\n---\n_Revised after cross-provider review:_\n\n" }));
                    }
                    out.push(openaiChunk(id, model, { content: e.delta }));
                  }
                  if (e.type === "error") out.push(openaiChunk(id, model, { content: `[hib: ${e.message}]` }));
                  return out;
                },
                () => [openaiChunk(id, model, {}, "stop"), "[DONE]"],
              ),
            );
          }

          let text = "";
          let error: string | undefined;
          for await (const e of engine.chat(input, req.signal)) {
            if (e.type === "meta") model = e.model;
            if (e.type === "text") {
              if (e.part === "revision" && !revising) {
                revising = true;
                text = ""; // non-streaming clients get only the final answer
              }
              text += e.delta;
            }
            if (e.type === "error") error = e.message;
          }
          if (error && !text) return json({ error: { message: error, type: "hib_error" } }, 502);
          return json({ id, object: "chat.completion", created: Math.floor(Date.now() / 1000), model, choices: [{ index: 0, message: { role: "assistant", content: text }, finish_reason: "stop" }] });
        }),
      },

      "/hib/chat": {
        POST: guarded(async (req) => {
          const b: any = await req.json();
          const input: ChatInput = {
            conversationId: b.conversationId || undefined,
            persist: true,
            messages: toMessages(b.messages ?? [{ role: "user", content: b.prompt }]),
            model: b.model || undefined,
            mode: b.mode || undefined,
            cwd: b.cwd || undefined,
            arena: !!b.arena,
            allowArena: !b.attachments?.length,
            attachments: (b.attachments ?? []).map((a: any) => {
              const path = analysisPath(a);
              return { name: basename(path), path, table: loadTable(path), hide: a.hide ?? [], keep: a.keep ?? [] };
            }),
          };
          return sse(eventStream(engine, input, (e) => [JSON.stringify(e)]));
        }),
      },

      "/hib/conversations": guarded(() => json(engine.listConversations())),
      "/hib/conversations/:id": {
        GET: guarded((req) => {
          const c = engine.getConversation(req.params.id!);
          return c ? json(c) : json({ error: "not found" }, 404);
        }),
        DELETE: guarded((req) => {
          engine.deleteConversation(req.params.id!);
          return json({ ok: true });
        }),
      },

      "/hib/approvals": guarded(() => json(engine.pendingApprovals())),
      "/hib/approvals/:id": {
        POST: guarded(async (req) => {
          const b: any = await req.json();
          return json({ ok: engine.decideApproval(req.params.id!, !!b.approve, typeof b.edited === "string" ? b.edited : undefined) });
        }),
      },

      "/hib/feedback": {
        POST: guarded(async (req) => {
          const b: any = await req.json();
          return json({ ok: engine.feedback(b.runId, Number(b.value)) });
        }),
      },
      "/hib/arena/:id": {
        POST: guarded(async (req) => {
          const b: any = await req.json();
          return json({ ok: engine.pickArena(req.params.id!, b.winner === "b" ? "b" : "a") });
        }),
      },

      "/hib/usage": guarded(() => json(engine.usage.all())),
      "/hib/stats": guarded(() =>
        json({
          scores: engine.learner.table(),
          runs: engine.db.query("SELECT id, ts, class, model, account, pipeline, in_tok, out_tok, ms, status FROM runs ORDER BY ts DESC LIMIT 50").all(),
          audit: engine.db.query("SELECT run_id, ts, route, account, findings, action, reasons, decided_by FROM audit ORDER BY ts DESC LIMIT 50").all(),
        }),
      ),
      "/hib/info": guarded(() =>
        json({
          models: modelList(),
          routes: engine.cfg.routes,
          accounts: engine.cfg.accounts.map((a) => ({ id: a.id, env: a.env, limits: a.limits, dirs: a.dirs })),
          skills: [...engine.plugins.skills.values()].map(({ name, description, plugin }) => ({ name, description, plugin })),
          agents: [...engine.plugins.agents.values()].map(({ name, description, plugin }) => ({ name, description, plugin })),
          pluginWarnings: engine.plugins.warnings,
          agentDirs: engine.cfg.guard.agentDirs,
          workspaces: workspaces.list().map((w) => w.root),
          policies: Object.fromEntries(workspaces.list().map((w) => [w.root, w.policy])),
        }),
      ),
    },
    fetch() {
      return new Response("not found", { status: 404 });
    },
  });
}
