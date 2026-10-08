import type { GuardConfig, Route } from "../config";
import type { Finding } from "./detectors";

export type Action = "redact" | "ask";

export interface Decision {
  action: Action;
  reasons: string[];
}

export function decide(findings: Finding[], route: Route, g: GuardConfig, extraReasons: string[] = []): Decision {
  const reasons = [...extraReasons];
  if (route.ask) reasons.push("route requires approval");
  const hit = new Set(findings.filter((f) => g.askOn.some((p) => f.category.startsWith(p))).map((f) => f.category));
  if (hit.size) reasons.push(`sensitive: ${[...hit].join(", ")}`);
  if (findings.length > g.askIfFindingsOver) reasons.push(`${findings.length} findings > ${g.askIfFindingsOver}`);
  return { action: reasons.length ? "ask" : "redact", reasons };
}

export function summarize(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) out[f.category] = (out[f.category] ?? 0) + 1;
  return out;
}
