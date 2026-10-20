import { hostname, userInfo } from "node:os";
import type { Config, Mode, Route } from "../config";
import type { Finding, Level } from "./detectors";
import { nerScan, type Infer } from "./ner";
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
  `IPs with the same NETn are in the same /24 subnet, different NETn means different /24s. A BASE64-, HEX- or URL-ENCODED placeholder is an encoded payload (e.g. a script passed to a command) withheld whole; TEXT is a free-text value withheld whole. When listing several, write every placeholder out in full; never abbreviate them as ranges like "1 through 12". Never mention NET tags, placeholders or this privacy layer in your answer.`;

export interface Inspection {
  vault: Vault;
  messages: Message[]; // obfuscated
  findings: Record<string, number>;
  decision: Decision;
  blocked?: string; // agent mode refused outright
}

export function machineTerms(): string[] {
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
  partial?: Map<string, string>; // texts the budget didn't fully cover -> what was done instead; the guard asks
}

/**
 * Runs local NER over each distinct text, all of them within one time budget (`guard.nerBudgetSec`). Failure is
 * reported, never swallowed: the guard then asks. `cells` are the free-text table cells in a text, tokenised whole if
 * the budget runs out before them.
 */
export async function runNer(texts: string[], cfg: Config, infer: Infer | undefined, cells?: Map<string, [number, number][]>): Promise<NerResult> {
  const byText = new Map<string, Finding[]>();
  if (!cfg.guard.ner) return { byText };
  if (!infer) return { byText, error: "name detection is enabled but not available" };
  const deadline = Date.now() + cfg.guard.nerBudgetSec * 1000;
  const partial = new Map<string, string>();
  try {
    for (const t of new Set(texts)) {
      if (!t.trim()) continue;
      const r = await nerScan(t, infer, { ignore: cfg.guard.nerIgnore, deadline, cells: cells?.get(t) });
      byText.set(t, r.findings);
      if (r.scannedTo < t.length)
        partial.set(
          t,
          `name detection ran out of budget after ${r.scannedTo.toLocaleString("en")} of ${t.length.toLocaleString("en")} characters; ` +
            `the ${r.tokenised} free-text ${r.tokenised === 1 ? "cell or line it didn't reach was" : "cells or lines it didn't reach were"} tokenised whole`,
        );
    }
    return partial.size ? { byText, partial } : { byText };
  } catch (e: any) {
    return { byText, error: `name detection failed: ${String(e?.message ?? e).slice(0, 160)}` };
  }
}

export function inspect(messages: Message[], route: Route, cfg: Config, opts: { cwd?: string; vault?: Vault; level?: Level; skipScan?: boolean; ner?: NerResult; exempt?: Map<string, [number, number][]> } = {}): Inspection {
  const vault = opts.vault ?? new Vault();
  const terms = cfg.guard.terms;
  // In agent mode the CLI sees real paths through its own tools, so tokenizing them only breaks file access.
  const agent = route.mode === "agent";
  const identities = agent ? [] : machineTerms();
  const level = opts.level ?? route.level;
  const all: Finding[] = [];
  const out: Message[] = messages.map((m) => {
    const { text, findings } = vault.obfuscate(m.content, { level, terms, identities, patterns: cfg.guard.patterns, keepPaths: agent, extra: opts.ner?.byText.get(m.content), exempt: opts.exempt?.get(m.content) });
    all.push(...findings);
    return { ...m, content: text };
  });

  const extra: string[] = [];
  if (opts.ner?.error) extra.push(opts.ner.error);
  extra.push(...new Set(opts.ner?.partial?.values()));
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
