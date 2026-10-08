import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { hibHome } from "../config";
import type { Account } from "../config";
import type { Provider, Quota, RunEvent, RunRequest } from "./types";
import { accountEnv, looksRateLimited, parseJson, spawnLines, transcript } from "./spawn";

// Everything that lets the model touch the machine; turned off for chat mode.
const CHAT_DISABLED = [
  "shell_tool", "unified_exec", "browser_use", "computer_use", "apps", "plugins",
  "multi_agent", "image_generation", "view_image", "shell_snapshot", "skill_search", "tool_suggest",
];

export function parseCodexLine(o: any): RunEvent[] {
  if (!o) return [];
  switch (o.type) {
    case "item.completed": {
      const it = o.item ?? {};
      if (it.type === "agent_message" && it.text) return [{ type: "text", delta: it.text }];
      if (it.type === "command_execution") return [{ type: "tool", name: "shell", detail: it.command }];
      if (it.type === "file_change") return [{ type: "tool", name: "edit", detail: (it.changes ?? []).map((c: any) => c.path).join(", ") }];
      return [];
    }
    case "turn.completed":
      return [{ type: "usage", in: o.usage?.input_tokens ?? 0, out: (o.usage?.output_tokens ?? 0) + (o.usage?.reasoning_output_tokens ?? 0) }];
    case "turn.failed":
    case "error": {
      const msg = String(o.error?.message ?? o.message ?? "codex error");
      return [looksRateLimited(msg) ? { type: "rate_limited", message: msg } : { type: "error", message: msg }];
    }
  }
  return [];
}

function windowLabel(minutes: number): string {
  return minutes % 1440 === 0 ? `${minutes / 1440}d` : minutes % 60 === 0 ? `${minutes / 60}h` : `${minutes}m`;
}

/** Codex only reports quota in its session rollout file, so read the latest `rate_limits` from there. */
export function parseCodexRateLimits(rollout: string): Quota[] {
  let last: any;
  for (const line of rollout.split("\n")) {
    if (!line.includes('"rate_limits"')) continue;
    const o = parseJson(line);
    const rl = o?.payload?.rate_limits ?? o?.rate_limits ?? o?.payload?.info?.rate_limits;
    if (rl) last = rl;
  }
  if (!last) return [];
  return [last.primary, last.secondary]
    .filter(Boolean)
    .map((w: any) => ({ window: windowLabel(w.window_minutes), usedPct: Number(w.used_percent ?? 0) / 100, resetsAt: w.resets_at }));
}

function findRollout(codexHome: string, threadId: string): string | undefined {
  const root = join(codexHome, "sessions");
  const now = new Date();
  // Rollouts live in sessions/YYYY/MM/DD; check today and yesterday (UTC/local drift).
  for (const d of [now, new Date(now.getTime() - 86400_000)]) {
    const dir = join(root, String(d.getFullYear()), String(d.getMonth() + 1).padStart(2, "0"), String(d.getDate()).padStart(2, "0"));
    try {
      const f = readdirSync(dir).find((n) => n.includes(threadId));
      if (f) return join(dir, f);
    } catch {}
  }
}

export const codexCli: Provider = {
  id: "codex",

  async available(account: Account) {
    if (!Bun.which("codex")) return false;
    const p = Bun.spawn(["codex", "login", "status"], { env: accountEnv(account), stdout: "pipe", stderr: "pipe" });
    const out = (await new Response(p.stdout).text()) + (await new Response(p.stderr).text());
    await p.exited;
    return /logged in/i.test(out) && !/not logged in/i.test(out);
  },

  async *run(req: RunRequest, signal: AbortSignal) {
    const env = accountEnv(req.account);
    const { system, prompt } = transcript(req.messages);
    const args = ["codex", "exec", "--json", "--skip-git-repo-check", "-m", req.model];
    let scratch: string | undefined;
    if (req.mode === "agent") {
      args.push("--sandbox", "workspace-write", "-C", req.cwd!);
    } else {
      mkdirSync(join(hibHome(), "scratch"), { recursive: true });
      scratch = mkdtempSync(join(hibHome(), "scratch", "codex-"));
      args.push("--sandbox", "read-only", "-C", scratch);
      for (const f of CHAT_DISABLED) args.push("--disable", f);
    }
    args.push("-");

    const p = spawnLines(args, { cwd: scratch ?? req.cwd!, env, stdin: system ? `${system}\n\n${prompt}` : prompt, signal, idleMs: req.mode === "agent" ? 600_000 : 120_000 });
    let threadId: string | undefined;
    let sawTurn = false;
    try {
      for await (const line of p.lines) {
        const o = parseJson(line);
        if (o?.type === "thread.started") threadId = o.thread_id;
        if (o?.type === "turn.completed" || o?.type === "turn.failed") sawTurn = true;
        yield* parseCodexLine(o);
      }
      const code = await p.exited;
      if (!sawTurn && !signal.aborted) {
        const err = p.stalled() ? "codex stalled (no output), killed" : (await p.stderr).trim().split("\n").slice(-5).join("\n") || `codex exited with ${code}`;
        yield looksRateLimited(err) ? ({ type: "rate_limited", message: err } as const) : ({ type: "error", message: err } as const);
      }
      if (threadId) {
        const codexHome = env.CODEX_HOME ?? join(homedir(), ".codex");
        const file = findRollout(codexHome, threadId);
        if (file && statSync(file).size < 50_000_000) for (const quota of parseCodexRateLimits(readFileSync(file, "utf8"))) yield { type: "quota", quota };
        // hib runs are one-shot; remove them from the user's codex history through codex itself.
        await Bun.spawn(["codex", "delete", "--force", threadId], { env, stdout: "ignore", stderr: "ignore" }).exited;
      }
    } finally {
      if (scratch) rmSync(scratch, { recursive: true, force: true });
    }
    yield { type: "done" };
  },
};
