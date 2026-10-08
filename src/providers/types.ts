import type { Account, Mode } from "../config";

export interface Message {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface RunRequest {
  model: string; // provider-local model name, e.g. "sonnet"
  account: Account;
  messages: Message[]; // already obfuscated
  mode: Mode;
  cwd?: string; // agent mode working dir
}

export interface Quota {
  window: string; // "5h", "7d", ...
  usedPct: number; // 0..1
  resetsAt?: number; // unix seconds
}

export type RunEvent =
  | { type: "text"; delta: string }
  | { type: "tool"; name: string; detail?: string }
  | { type: "usage"; in: number; out: number }
  | { type: "quota"; quota: Quota }
  | { type: "rate_limited"; resetsAt?: number; message?: string }
  | { type: "error"; message: string }
  | { type: "done" };

export interface Provider {
  id: string;
  /** Whether this account's CLI is installed and logged in. */
  available(account: Account): Promise<boolean>;
  run(req: RunRequest, signal: AbortSignal): AsyncIterable<RunEvent>;
}
