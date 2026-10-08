import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { hibHome } from "../config";
import type { Account } from "../config";
import type { Provider, RunEvent, RunRequest } from "./types";
import { accountEnv, looksRateLimited, parseJson, spawnLines, transcript } from "./spawn";

const WINDOWS: Record<string, string> = { five_hour: "5h", seven_day: "7d", seven_day_opus: "7d-opus", seven_day_sonnet: "7d-sonnet" };

/** Maps one stream-json line from `claude -p --output-format stream-json` to hib events. */
export function parseClaudeLine(o: any): RunEvent[] {
  if (!o) return [];
  if (o.type === "stream_event") {
    const e = o.event;
    if (e?.type === "content_block_delta" && e.delta?.type === "text_delta") return [{ type: "text", delta: e.delta.text }];
    if (e?.type === "content_block_start" && e.content_block?.type === "tool_use") return [{ type: "tool", name: e.content_block.name }];
    return [];
  }
  if (o.type === "rate_limit_event") {
    const info = o.rate_limit_info ?? {};
    const out: RunEvent[] = [];
    for (const [k, w] of Object.entries<any>(info.unifiedWindows ?? {}))
      out.push({ type: "quota", quota: { window: WINDOWS[k] ?? k, usedPct: Number(w.utilization ?? 0), resetsAt: w.resetsAt } });
    if (info.status && info.status !== "allowed" && info.status !== "allowed_warning")
      out.push({ type: "rate_limited", resetsAt: info.resetsAt, message: `claude ${info.rateLimitType ?? ""} limit: ${info.status}` });
    return out;
  }
  if (o.type === "result") {
    const out: RunEvent[] = [{ type: "usage", in: (o.usage?.input_tokens ?? 0) + (o.usage?.cache_read_input_tokens ?? 0) + (o.usage?.cache_creation_input_tokens ?? 0), out: o.usage?.output_tokens ?? 0 }];
    if (o.is_error || o.subtype !== "success") {
      const msg = String(o.result ?? o.subtype ?? "claude error");
      out.push(looksRateLimited(msg) ? { type: "rate_limited", message: msg } : { type: "error", message: msg });
    }
    return out;
  }
  return [];
}

export const claudeCli: Provider = {
  id: "claude",

  async available(account: Account) {
    if (!Bun.which("claude")) return false;
    const p = Bun.spawn(["claude", "auth", "status"], { env: accountEnv(account), stdout: "pipe", stderr: "pipe" });
    const out = await new Response(p.stdout).text();
    await p.exited;
    return /"loggedIn":\s*true/.test(out);
  },

  async *run(req: RunRequest, signal: AbortSignal) {
    const { system, prompt } = transcript(req.messages);
    const args = [
      "claude", "-p",
      "--output-format", "stream-json", "--verbose", "--include-partial-messages",
      "--model", req.model,
      "--no-session-persistence",
      "--strict-mcp-config",
    ];
    let cwd: string;
    let scratch: string | undefined;
    if (req.mode === "agent") {
      cwd = req.cwd!;
      args.push("--permission-mode", "acceptEdits");
      if (system) args.push("--append-system-prompt", system);
    } else {
      mkdirSync(join(hibHome(), "scratch"), { recursive: true });
      cwd = scratch = mkdtempSync(join(hibHome(), "scratch", "claude-"));
      args.push("--tools", "", "--system-prompt", system || "You are a helpful assistant.");
    }

    const p = spawnLines(args, { cwd, env: accountEnv(req.account), stdin: prompt, signal, idleMs: req.mode === "agent" ? 600_000 : 120_000 });
    let sawResult = false;
    try {
      for await (const line of p.lines) {
        const o = parseJson(line);
        if (o?.type === "result") sawResult = true;
        yield* parseClaudeLine(o);
      }
      const code = await p.exited;
      if (!sawResult && !signal.aborted) {
        const err = p.stalled() ? "claude stalled (no output), killed" : (await p.stderr).trim() || `claude exited with ${code}`;
        yield looksRateLimited(err) ? ({ type: "rate_limited", message: err } as const) : ({ type: "error", message: err } as const);
      }
    } finally {
      if (scratch) rmSync(scratch, { recursive: true, force: true });
    }
    yield { type: "done" };
  },
};
