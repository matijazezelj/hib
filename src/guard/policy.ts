import type { GuardConfig, Route } from "../config";
import type { Finding } from "./detectors";

const NER_CATEGORIES = new Set(["PERSON", "ORG", "PLACE", "ADDRESS"]);

type Action = "redact" | "ask";

export interface Decision {
  action: Action;
  reasons: string[];
}

export function decide(findings: Finding[], route: Route, g: GuardConfig, extraReasons: string[] = []): Decision {
  const reasons = [...extraReasons];
  if (route.ask) reasons.push("route requires approval");
  // A merged finding carries the categories it absorbed (a term inside an email address), and those still count.
  const hit = new Set(findings.flatMap((f) => [f.category, ...(f.absorbed ?? [])]).filter((c) => g.askOn.some((p) => c.startsWith(p))));
  if (hit.size) reasons.push(`sensitive: ${[...hit].join(", ")}`);
  // The count rule catches an accidental big paste of secrets/infra details. Names, places and companies from local
  // NER are already tokenized, and a table full of them is expected, so they don't count toward it.
  const counted = findings.filter((f) => !NER_CATEGORIES.has(f.category)).length;
  if (counted > g.askIfFindingsOver) reasons.push(`${counted} findings > ${g.askIfFindingsOver}`);
  return { action: reasons.length ? "ask" : "redact", reasons };
}

export function summarize(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) out[f.category] = (out[f.category] ?? 0) + 1;
  return out;
}
