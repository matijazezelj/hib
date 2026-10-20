import { describe, expect, test } from "bun:test";
import { detect } from "../src/guard/detectors";
import { encodedBlobs, stringLiterals } from "../src/guard/encoded";
import { Vault } from "../src/guard/vault";

const SCRIPT = 'print("lookup jane.roe@example.org and Ivo Ivić")';
const ENCODINGS: [string, string][] = [
  ["base64", Buffer.from(SCRIPT).toString("base64")],
  ["base64url", Buffer.from(SCRIPT).toString("base64url")],
  ["hex", Buffer.from(SCRIPT).toString("hex")],
  ["percent", encodeURIComponent(SCRIPT)],
];

describe("encoded payloads", () => {
  for (const [name, blob] of ENCODINGS)
    test(`${name}: a blob that decodes to text with an address goes out as one placeholder`, () => {
      const v = new Vault("ab12");
      const text = `sudo: jdoe : COMMAND=/bin/python3 -c ${blob}`;
      const out = v.obfuscate(text, { level: "standard" }).text;
      expect(out).not.toContain(blob);
      expect(out).toMatch(/COMMAND=\/bin\/python3 -c \[HIBab12-(BASE64|HEX|URL)-ENCODED-1\]$/);
      // same value, same token
      expect(v.obfuscate(`again ${blob}`, { level: "standard" }).text).toBe(`again ${out.slice(out.lastIndexOf("["))}`);
    });

  test("blobs that aren't text (hashes, random bytes) and harmless text stay as they are", () => {
    const sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const random = Buffer.from(Array.from({ length: 48 }, (_, i) => (i * 97 + 13) % 256)).toString("base64");
    const harmless = Buffer.from("echo deployment finished successfully").toString("base64");
    for (const t of [`sha256 ${sha}`, `blob ${random}`, `cmd ${harmless}`, "q=hello%20world", "google.login.LoginService.loginSuccess internationalizationLocalization"])
      expect(detect(t, { level: "standard" })).toEqual([]);
    expect(encodedBlobs(`cmd ${harmless}`).map((b) => b.decoded)).toEqual(["echo deployment finished successfully"]);
  });

  test("secrets inside a blob keep their category for ask-first rules; nested encodings are opened too", () => {
    const key = Buffer.from("export AWS_KEY=AKIAIOSFODNN7EXAMPLE").toString("base64");
    const [f] = detect(`run ${key}`, { level: "minimal" });
    expect(f).toMatchObject({ category: "BASE64-ENCODED", kind: "secret" });
    expect(f!.absorbed).toContain("AWS-KEY");
    const twice = Buffer.from(`echo ${Buffer.from("mail ana.kovac@acme-corp.io").toString("base64")} | base64 -d`).toString("base64");
    expect(detect(twice, { level: "standard" }).map((f) => f.category)).toEqual(["BASE64-ENCODED"]);
  });

  test("line-wrapped base64 is one blob", () => {
    const long = Buffer.from(`${"lorem ipsum dolor sit amet ".repeat(4)}contact ana.kovac@acme-corp.io`).toString("base64");
    const wrapped = long.match(/.{1,60}/g)!.join("\n");
    const out = new Vault("ab12").obfuscate(`payload:\n${wrapped}\nend`, { level: "standard" }).text;
    expect(out).toBe("payload:\n[HIBab12-BASE64-ENCODED-1]\nend");
  });

  test("string literals of decoded code are pulled out for name detection", () => {
    expect(stringLiterals(`import os\nos.system('ls')\nprint("lookup Ivo Ivić")`)).toBe("ls\nlookup Ivo Ivić");
  });
});
