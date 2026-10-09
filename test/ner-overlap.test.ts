import { expect, test } from "bun:test";
import { detect } from "../src/guard/detectors";

test("a name found by NER inside an email address does not displace the email finding", () => {
  const text = "Her email is ana.kovac@zelenival.example today";
  const start = text.indexOf("ana.kovac");
  const extra = [{ category: "PERSON", kind: "pii", start, end: start + "ana.kovac".length, value: "ana.kovac" }] as any;
  const found = detect(text, { level: "standard", extra });
  expect(found.map((f) => f.category)).toEqual(["EMAIL"]);
  expect(found[0]!.value).toBe("ana.kovac@zelenival.example");
});

test("NER findings outside other matches are still kept", () => {
  const text = "Ana Kovac wrote to bob@corp.example";
  const extra = [{ category: "PERSON", kind: "pii", start: 0, end: 9, value: "Ana Kovac" }] as any;
  expect(detect(text, { level: "standard", extra }).map((f) => f.category)).toEqual(["PERSON", "EMAIL"]);
});
