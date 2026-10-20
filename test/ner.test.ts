import { describe, expect, test } from "bun:test";
import { isLowerProse, mergeTokens, nerFindings, nerScan, proseSegments } from "../src/guard/ner";
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
  test("input over 200,000 characters is scanned in chunks, a name deep inside included", async () => {
    const text = `${"routine status line with nothing in it\n".repeat(6000)}ticket #3077649 - Petra Learner - new contact form\n${"ok ".repeat(2000)}`;
    expect(text.length).toBeGreaterThan(200_000);
    const r = await nerScan(text, fakeInfer);
    expect(r.scannedTo).toBe(text.length);
    expect(r.findings.map((f) => f.value)).toEqual(["Petra Learner"]);
  });
  test("a long line is cut at spaces into pieces the model can read", async () => {
    const seen: number[] = [];
    const text = `${"word ".repeat(1000)}Marija Horvat`;
    const f = await nerFindings(text, async (t) => (seen.push(t.length), fakeInfer(t)));
    expect(Math.max(...seen)).toBeLessThanOrEqual(1000);
    expect(f.map((x) => text.slice(x.start, x.end))).toEqual(["Marija Horvat"]);
  });
  test("out of budget: free-text cells it didn't reach are tokenised whole, short cells and lines outside are judged apart", async () => {
    const head = "summarise:\n<table>\n";
    const rows = ["id,notes", "1,called the customer back about it", "2,ok", "3,Petra Learner asked for a refund today"];
    const text = `${head}${rows.join("\n")}\n</table>\nplease list everyone who asked for refunds`;
    const cells: [number, number][] = [];
    for (const cell of ["called the customer back about it", "Petra Learner asked for a refund today"]) cells.push([text.indexOf(cell), text.indexOf(cell) + cell.length]);
    const r = await nerScan(text, fakeInfer, { deadline: Date.now() - 1, cells });
    expect(r.scannedTo).toBe(0);
    const whole = r.findings.filter((f) => f.category === "TEXT").map((f) => f.value).sort();
    expect(whole).toEqual(["Petra Learner asked for a refund today", "called the customer back about it", "please list everyone who asked for refunds"]);
    expect(r.tokenised).toBe(3);
  });
  test("encoded payloads: a name in a decoded script hides the whole blob; out of budget, any blob goes whole", async () => {
    const blob = Buffer.from('import os\nprint("lookup Ivo Ivić")').toString("base64");
    const text = `sudo: COMMAND=/bin/python3 -c ${blob}`;
    const [f] = await nerFindings(text, fakeInfer);
    expect(f).toMatchObject({ value: blob, category: "BASE64-ENCODED" });
    expect(f!.absorbed).toEqual(["PERSON"]);
    expect(await nerFindings(`run ${Buffer.from("echo nightly backup completed").toString("base64")}`, fakeInfer)).toEqual([]);
    // the blob alone is one word, not a free-text line: only the blob rule covers it
    expect((await nerScan(blob, fakeInfer, { deadline: Date.now() - 1 })).findings.map((x) => [x.value, x.category])).toEqual([[blob, "BASE64-ENCODED"]]);
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

describe("data rows (regressions from a real CSV)", () => {
  const row = `[HIB4be5-CLIENT-ID-9],[HIB4be5-FULL-NAME-9],[HIB4be5-ORG-4],SMB,616000,false,"met luka novak at the [HIB4be5-PLACE-1] conference, follow up in march"`;
  test("lowercase notes inside a mixed-case row still get the title-cased pass", async () => {
    const values = (await nerFindings(row, fakeInfer)).map((f) => f.value);
    expect(values).toContain("luka novak");
  });
  test("a model fragment expands to the whole word (no '[ORG-1]B')", async () => {
    const f = await nerFindings("segment SMXB is new", async () => [{ entity: "B-ORG", word: "SM", score: 0.99 }]);
    expect(f.map((x) => x.value)).toEqual(["SMXB"]);
  });
  test("adjacent pieces of one company merge into one finding", async () => {
    const f = await nerFindings("works at Ericsson Nikola Tesla now", async () => [
      { entity: "B-ORG", word: "Ericsson", score: 0.99 }, { entity: "B-ORG", word: "Nikola", score: 0.99 }, { entity: "I-ORG", word: "Tesla", score: 0.99 },
    ]);
    expect(f.map((x) => x.value)).toEqual(["Ericsson Nikola Tesla"]);
  });
});

test("a lowercase name next to a capitalised city in the same clause is still found", async () => {
  const text = `false,"met luka novak at the Zagreb conference, follow up in march"`;
  const values = (await nerFindings(text, fakeInfer)).map((f) => f.value);
  expect(values).toContain("luka novak");
  expect(values).toContain("Zagreb");
  // the title-cased pass never adds capitalised words of its own
  expect(values).not.toContain("Met");
});
