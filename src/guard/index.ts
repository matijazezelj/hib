import { hostname, userInfo } from "node:os";
import type { Config, Mode, Route } from "../config";
import type { Finding, Level } from "./detectors";
import { nerFindings, type Infer } from "./ner";
import { Vault } from "./vault";
import { decide, summarize, type Decision } from "./policy";
import { isAllowedDir, scanDir } from "./agentscan";
import type { Message } from "../providers/types";

export { Vault } from "./vault";
export { StreamRestorer } from "./restore";

export const tokenNote = (tag: string) =>
  `Privacy layer: some values were replaced locally by placeholders like [HIB${tag}-USER-1] before reaching you. ` +
  `The user sees every placeholder automatically swapped back to its real value, so treat placeholders AS the real values: ` +
  `answer normally, refer to values by their placeholder (copied exactly), and never ask for or comment on the hidden values. ` +
  `What placeholders tell you: the same placeholder is always the same value; IP-INTERNAL is a private address, IP-EXTERNAL a public one; ` +
  `IPs with the same NETn are in the same /24 subnet, different NETn means different /24s. When listing several, write every placeholder out in full; never abbreviate them as ranges like "1 through 12". Never mention NET tags, placeholders or this privacy layer in your answer.`;

export interface Inspection {
  vault: Vault;
  messages: Message[]; // obfuscated
  findings: Record<string, number>;
  decision: Decision;
  blocked?: string; // agent mode refused outright
}

function machineTerms(): string[] {
  const out: string[] = [];
  try {
    const u = userInfo().username;
    if (u.length >= 3) out.push(u);
  } catch {}
  const h = hostname().replace(/\.local$/, "");
  if (h.length >= 3 && h !== "localhost") out.push(h);
  return out;
}

/** Obfuscate one more piece of text (e.g. an edited prompt) into an existing vault. */
export function obfuscateText(vault: Vault, text: string, level: Level, cfg: Config, mode: Mode = "chat", extra?: Finding[]): string {
  const agent = mode === "agent";
  return vault.obfuscate(text, { level, terms: cfg.guard.terms, identities: agent ? [] : machineTerms(), patterns: cfg.guard.patterns, keepPaths: agent, extra }).text;
}

export interface NerResult {
  byText: Map<string, Finding[]>;
  error?: string; // set when detection was required but failed: the caller must not send without asking
}

/** Runs local NER over each distinct text. Failure is reported, never swallowed: the guard then asks. */
export async function runNer(texts: string[], cfg: Config, infer: Infer | undefined): Promise<NerResult> {
  const byText = new Map<string, Finding[]>();
  if (!cfg.guard.ner) return { byText };
  if (!infer) return { byText, error: "name detection is enabled but not available" };
  try {
    for (const t of new Set(texts)) if (t.trim()) byText.set(t, await nerFindings(t, infer, { ignore: cfg.guard.nerIgnore }));
    return { byText };
  } catch (e: any) {
    return { byText, error: `name detection failed: ${String(e?.message ?? e).slice(0, 160)}` };
  }
}

export function inspect(messages: Message[], route: Route, cfg: Config, opts: { cwd?: string; vault?: Vault; level?: Level; skipScan?: boolean; ner?: NerResult } = {}): Inspection {
  const vault = opts.vault ?? new Vault();
  const terms = cfg.guard.terms;
  // In agent mode the CLI sees real paths through its own tools, so tokenizing them only breaks file access.
  const agent = route.mode === "agent";
  const identities = agent ? [] : machineTerms();
  const level = opts.level ?? route.level;
  const all: Finding[] = [];
  const out: Message[] = messages.map((m) => {
    const { text, findings } = vault.obfuscate(m.content, { level, terms, identities, patterns: cfg.guard.patterns, keepPaths: agent, extra: opts.ner?.byText.get(m.content) });
    all.push(...findings);
    return { ...m, content: text };
  });

  const extra: string[] = [];
  if (opts.ner?.error) extra.push(opts.ner.error);
  let blocked: string | undefined;
  if (route.mode === "agent") {
    if (!opts.cwd) blocked = "agent mode needs a working directory";
    else if (!isAllowedDir(opts.cwd, cfg.guard.agentDirs)) blocked = `${opts.cwd} is not in guard.agentDirs`;
    else if (!opts.skipScan) {
      const hits = scanDir(opts.cwd);
      if (hits.length) extra.push(`agent dir contains possible secrets: ${hits.slice(0, 10).join("; ")}${hits.length > 10 ? "…" : ""}`);
    }
  }

  return { vault, messages: out, findings: summarize(all), decision: decide(all, route, cfg.guard, extra), blocked };
}
