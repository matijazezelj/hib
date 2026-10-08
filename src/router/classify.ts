import type { TaskClass } from "../config";
import type { Message } from "../providers/types";

export interface Classification {
  cls: TaskClass;
  confident: boolean;
  why: string;
}

const CODE_SIGNS: [RegExp, number, string][] = [
  [/```/, 3, "code fence"],
  [/\b(?:at \S+ \(\S+:\d+:\d+\)|Traceback \(most recent call last\)|File "[^"]+", line \d+|panic:|Exception in thread)/, 3, "stack trace"],
  [/\b[\w./-]+\.(?:ts|tsx|js|jsx|py|go|rs|java|kt|swift|rb|php|c|cc|cpp|h|hpp|cs|sql|sh|yaml|yml|toml|json|tf|vue|svelte)\b/, 2, "file path"],
  [/\b(?:implement|refactor|debug|fix(?:es|ing)?|compile|stack ?trace|unit tests?|function|method|class|regex|endpoint|migration|bug|lint|typescript|python|golang|rust|dockerfile|kubernetes|sql query|api)\b/i, 1, "code vocabulary"],
  [/[{};]\s*$|^\s*(?:import|from|def|func|fn|const|let|var|class|public|private|SELECT|CREATE)\b/m, 2, "code syntax"],
  [/\$ [a-z]+ |\bnpm |\bbun |\bgit |\bdocker |\bkubectl /, 1, "shell"],
];
const REVIEW = /\b(?:review|critique|audit|assess|second opinion|what(?:'s| is) wrong with|find (?:the )?(?:bugs|issues))\b/i;
const LONG_CHARS = 40_000;

/** Heuristics only; `confident: false` means the caller may ask a cheap model. */
export function classify(messages: Message[], mode: "chat" | "agent" = "chat", custom: { name: string; keywords: string[] }[] = []): Classification {
  const last = [...messages].reverse().find((m) => m.role === "user")?.content ?? "";
  const total = messages.reduce((n, m) => n + m.content.length, 0);
  if (mode === "agent") return { cls: "code", confident: true, why: "agent mode" };
  for (const r of custom) {
    const hit = r.keywords.find((k) => new RegExp(`\\b${k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i").test(last));
    if (hit) return { cls: r.name, confident: true, why: `keyword "${hit}"` };
  }
  if (total > LONG_CHARS) return { cls: "long", confident: true, why: `${total} chars` };

  let score = 0;
  const why: string[] = [];
  for (const [re, w, label] of CODE_SIGNS)
    if (re.test(last)) {
      score += w;
      why.push(label);
    }
  const review = REVIEW.test(last);
  if (review && score >= 2) return { cls: "review", confident: true, why: ["review request", ...why].join(", ") };
  if (score >= 3) return { cls: "code", confident: true, why: why.join(", ") };
  if (score === 0 && !review) return { cls: "chat", confident: last.length < 2000, why: "no code signals" };
  return { cls: review ? "review" : score >= 2 ? "code" : "chat", confident: false, why: why.join(", ") || "review words" };
}

export const CLASSIFY_PROMPT = `Classify the user's request into exactly one word:
chat - conversation, questions, writing, explanations not about specific code
code - writing, fixing, explaining or running code
review - critiquing or auditing existing code or text
Reply with only the word.`;

export function parseClassifierReply(s: string): TaskClass | null {
  const m = /\b(chat|code|review)\b/i.exec(s);
  return m ? (m[1]!.toLowerCase() as TaskClass) : null;
}
