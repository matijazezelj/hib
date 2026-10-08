import type { Infer, RawToken } from "../../src/guard/ner";

/** Stand-in for the model: tags known entities (case-sensitive, like the cased BERT) in order of appearance. */
const KNOWN: [string, string][] = [
  ["Marija Horvat", "PER"], ["Ivan Kovačević", "PER"], ["Luka Novak", "PER"], ["Zagreb", "LOC"], ["Pula", "LOC"],
  ["Infobip", "ORG"], ["Redis", "ORG"], ["Acme", "ORG"],
];
export const fakeInfer: Infer = async (text) => {
  const hits: { at: number; name: string; label: string }[] = [];
  for (const [name, label] of KNOWN) for (const m of text.matchAll(new RegExp(name, "g"))) hits.push({ at: m.index!, name, label });
  hits.sort((a, b) => a.at - b.at);
  const out: RawToken[] = [];
  for (const h of hits) h.name.split(" ").forEach((w, i) => out.push({ entity: `${i ? "I" : "B"}-${h.label}`, word: w, score: 0.99 }));
  return out;
};
