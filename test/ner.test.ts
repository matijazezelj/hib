import { describe, expect, test } from "bun:test";
import { isLowerProse, mergeTokens, nerFindings, proseSegments } from "../src/guard/ner";
import { fakeInfer } from "./helpers/fake-ner";

describe("NER helpers", () => {
  test("word pieces and I- tags merge into entities", () => {
    expect(mergeTokens([
      { entity: "B-PER", word: "Ivan", score: 0.99 }, { entity: "I-PER", word: "Ko", score: 0.98 }, { entity: "I-PER", word: "##vač", score: 0.97 }, { entity: "I-PER", word: "##ević", score: 0.96 },
      { entity: "B-LOC", word: "Zagreb", score: 0.9 },
    ])).toEqual([{ text: "Ivan Kovačević", label: "PER", score: 0.96 }, { text: "Zagreb", label: "LOC", score: 0.9 }]);
  });
  test("code is never scanned: fences, inline code and code-looking lines", () => {
    const text = "Please ask Marija Horvat.\n```ts\nconst marija = new Horvat();\n```\nrun `Ivan.deploy()` then\nimport { Zagreb } from './city';\nthanks";
    const segs = proseSegments(text).map((s) => s.text);
    expect(segs).toEqual(["Please ask Marija Horvat.", "run ", " then", "thanks"]);
    for (const s of proseSegments(text)) expect(text.slice(s.start, s.start + s.text.length)).toBe(s.text);
  });
  test("lowercase prose detection", () => {
    expect(isLowerProse("can you check why luka novak can't log in from pula")).toBe(true);
    expect(isLowerProse("Can you check why Luka Novak can't log in")).toBe(false);
  });
});

describe("nerFindings", () => {
  test("exact offsets, categories, and rules for companies and addresses", async () => {
    const text = "Marija Horvat from Acme d.o.o. moved to Zagreb, Trg bana Josipa Jelačića 3.";
    const f = await nerFindings(text, fakeInfer);
    for (const x of f) expect(text.slice(x.start, x.end)).toBe(x.value);
    const got = Object.fromEntries(f.map((x) => [x.value, x.category]));
    expect(got["Marija Horvat"]).toBe("PERSON");
    expect(got["Zagreb"]).toBe("PLACE");
    expect(got["Acme d.o.o."]).toBe("ORG");
    expect(got["Trg bana Josipa Jelačića 3"]).toBe("ADDRESS");
  });
  test("tech names and configured terms are ignored", async () => {
    const f = await nerFindings("Move Redis next to Infobip's cluster", fakeInfer, { ignore: ["infobip"] });
    expect(f).toEqual([]);
  });
  test("lowercase chat: a title-cased pass finds names, mapped back to the real text", async () => {
    const text = "can you check why luka novak can't log in from pula this week";
    const f = await nerFindings(text, fakeInfer);
    expect(f.map((x) => x.value).sort()).toEqual(["luka novak", "pula"]);
  });
  test("names inside code are left alone", async () => {
    expect(await nerFindings("```\nconst who = 'Marija Horvat';\n```", fakeInfer)).toEqual([]);
  });
  test("oversized input is refused, not partially scanned", async () => {
    await expect(nerFindings("Marija Horvat ".repeat(20_000), fakeInfer)).rejects.toThrow("too large");
  });
});

describe("data rows", () => {
  test("CSV rows with abbreviations, quotes and hib tokens are scanned, not mistaken for code", () => {
    const row = `[HIB449b-CLIENT-ID-2],[HIB449b-FULL-NAME-2],Podravka d.d.,Ljubljana,SMB,80000,true,"Escalated to Ivan Grgić, account manager at Podravka d.d.."`;
    expect(proseSegments(row).length).toBe(1);
  });
  test("still skips real code lines", () => {
    for (const code of ["user, err := s.store.FindUser(r.Context(), r.FormValue(\"email\"))", "items.map((i) => i.price)", "if (x) { y = 1 }", "SELECT id FROM users WHERE city = 'Zagreb'"])
      expect(proseSegments(code)).toEqual([]);
  });
  test("a value found once is tokenized everywhere in the prose", async () => {
    const text = "Marija Horvat moved to Zagreb.\nlater: zagreb office? Zagreb, again; Marija Horvat";
    const values = (await nerFindings(text, async (t) => (t.includes("Marija Horvat moved") ? [{ entity: "B-PER", word: "Marija", score: 0.99 }, { entity: "I-PER", word: "Horvat", score: 0.99 }, { entity: "B-LOC", word: "Zagreb", score: 0.99 }] : []))).map((f) => text.slice(f.start, f.end));
    expect(values.filter((v) => v === "Zagreb").length).toBe(2);
    expect(values.filter((v) => v === "Marija Horvat").length).toBe(2);
  });
});
