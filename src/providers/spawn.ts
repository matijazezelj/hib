import type { Account } from "../config";

const PASSTHROUGH = ["PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "TMPDIR", "TZ", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"];

/** A minimal environment plus the account's overrides, so one account's credentials never leak into another. */
export function accountEnv(account: Account): Record<string, string> {
  const env: Record<string, string> = {};
  for (const k of PASSTHROUGH) if (process.env[k]) env[k] = process.env[k]!;
  for (const [k, v] of Object.entries(process.env)) if (k.startsWith("LC_") && v) env[k] = v;
  for (const [k, v] of Object.entries(account.env)) {
    if (v === "") delete env[k];
    else env[k] = v;
  }
  return env;
}

export interface Spawned {
  lines: AsyncIterable<string>;
  stalled: () => boolean;
  stderr: Promise<string>;
  exited: Promise<number>;
}

/** CLIs occasionally hang after start-up; `idleMs` without any output kills the process so routing can fail over. */
export function spawnLines(cmd: string[], opts: { cwd: string; env: Record<string, string>; stdin: string; signal: AbortSignal; idleMs: number }): Spawned {
  const proc = Bun.spawn(cmd, { cwd: opts.cwd, env: opts.env, stdin: new Blob([opts.stdin]), stdout: "pipe", stderr: "pipe" });
  let stalled = false;
  let timer: Timer | undefined;
  // Children of the CLI can keep stdout open after it is killed, so stop reading as well.
  const reader = proc.stdout.getReader();
  const stop = () => {
    proc.kill();
    reader.cancel().catch(() => {});
  };
  const arm = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      stalled = true;
      stop();
    }, opts.idleMs);
  };
  arm();
  proc.exited.finally(() => clearTimeout(timer));
  opts.signal.addEventListener("abort", stop, { once: true });
  proc.exited.finally(() => opts.signal.removeEventListener("abort", stop));

  async function* lines() {
    const decoder = new TextDecoder();
    let buf = "";
    for (;;) {
      const { done, value } = await reader.read().catch(() => ({ done: true, value: undefined }));
      if (done) break;
      arm();
      buf += decoder.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (line) yield line;
      }
    }
    clearTimeout(timer);
    if (buf.trim()) yield buf.trim();
  }
  return { lines: lines(), stalled: () => stalled, stderr: new Response(proc.stderr).text(), exited: proc.exited };
}

export function parseJson(line: string): any | null {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

const RATE_LIMIT = /rate.?limit|usage.?limit|quota|too many requests|429|hit your limit|limit reached/i;
export const looksRateLimited = (s: string) => RATE_LIMIT.test(s);

/** Flattens a conversation into one prompt; CLIs run one-shot so history is replayed as a transcript. */
export function transcript(messages: { role: string; content: string }[]): { system: string; prompt: string } {
  const system = messages.filter((m) => m.role === "system").map((m) => m.content).join("\n\n");
  const turns = messages.filter((m) => m.role !== "system");
  if (turns.length === 1) return { system, prompt: turns[0]!.content };
  const history = turns
    .slice(0, -1)
    .map((m) => `<${m.role}>\n${m.content}\n</${m.role}>`)
    .join("\n");
  const last = turns[turns.length - 1]!;
  return {
    system,
    prompt: `Conversation so far (possibly with other assistants):\n<history>\n${history}\n</history>\n\nContinue the conversation. Reply to this latest ${last.role} message:\n${last.content}`,
  };
}
