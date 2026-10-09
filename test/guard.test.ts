import { describe, expect, test } from "bun:test";
import { detect, isPrivateIp } from "../src/guard/detectors";
import { Vault } from "../src/guard/vault";
import { StreamRestorer } from "../src/guard/restore";
import { decide } from "../src/guard/policy";
import { Sealer } from "../src/guard/seal";
import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig, DEFAULT_TOML } from "../src/config";

const cfg = parseConfig(Bun.TOML.parse(DEFAULT_TOML) as any, "/tmp/hib-test");
const cats = (text: string, level: "minimal" | "standard" | "paranoid" = "standard") => detect(text, { level }).map((f) => f.category);

describe("secrets (ported from sib)", () => {
  const cases: [string, string][] = [
    ["key AKIAIOSFODNN7EXAMPLE here", "AWS-KEY"],
    ["ghp_" + "a".repeat(36), "GITHUB-TOKEN"],
    ["glpat-" + "x".repeat(20), "GITLAB-TOKEN"],
    ["xoxb-1234567890-1234567890-" + "a".repeat(24), "SLACK-TOKEN"],
    ["AIza" + "b".repeat(35), "GOOGLE-API"],
    ["sk_live_" + "c".repeat(24), "STRIPE-SECRET"],
    ["npm_" + "d".repeat(36), "NPM-TOKEN"],
    ["postgres://admin:hunter22@db.prod.acme.io:5432/app", "DB-URI"],
    ["mongodb+srv://u:p4ss@cluster0.mongodb.net", "DB-URI"],
    ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123", "JWT"],
    ["Authorization: Bearer abcdef0123456789abcdef", "BEARER-TOKEN"],
    ['password = "correct-horse-battery"', "SECRET"],
    ["API_KEY=f00ba5f00ba5f00ba5", "SECRET"],
    ["sk-ant-api03-" + "z".repeat(30), "ANTHROPIC-KEY"],
    ["-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "PRIVATE-KEY"],
  ];
  for (const [text, cat] of cases) test(cat + ": " + text.slice(0, 30), () => expect(cats(text, "minimal")).toContain(cat));

  test("minimal level leaves IPs and emails alone", () => {
    expect(cats("10.0.0.1 bob@acme.io", "minimal")).toEqual([]);
  });
});

describe("standard level", () => {
  test("ips keep internal/external distinction", () => {
    expect(cats("from 10.1.2.3 to 8.8.8.8")).toEqual(["IP-INTERNAL", "IP-EXTERNAL"]);
    expect(isPrivateIp("172.16.5.4")).toBe(true);
    expect(isPrivateIp("172.32.0.1")).toBe(false);
  });
  test("loopback stays visible", () => expect(cats("listen 127.0.0.1:4141")).toEqual([]));
  test("emails", () => expect(cats("ping jane.doe@acme.io")).toEqual(["EMAIL"]));
  test("home dir usernames", () => {
    const f = detect("open /Users/jane/work/x.ts and /home/bob/.bashrc", { level: "standard" });
    expect(f.map((x) => x.value)).toEqual(["jane", "bob"]);
  });
  test("system users stay visible", () => expect(cats("user=root and by user www-data")).toEqual([]));
  test("user= is tokenized", () => expect(cats("user=jsmith")).toEqual(["USER"]));
  test("prose 'User wants' is not a username (sib false positive)", () => expect(cats("User wants a fix")).toEqual([]));
  test("configured terms", () => {
    expect(detect("deploy AcmeCorp billing", { level: "standard", terms: ["acmecorp"] }).map((f) => f.category)).toEqual(["TERM"]);
  });
});

describe("code survives (false-positive fixtures)", () => {
  const code = `
import { useState } from "react";
const userId = "3f2b9c1e-8a7d-4e6f-9b1c-2d3e4f5a6b7c"; // uuid in code
export function computeTotalPriceWithDiscountAndTax(items) { return items.map((i) => i.price).reduce(add, 0); }
const commit = "9fceb02d0ae598e95dc970b74767f19372d61af8";
console.log(config.database.connectionPoolSize, path.join(__dirname, "index.ts"));
const v = "1.2.3"; obj.method(); fs.readFileSync("file.ts");
class AbstractSingletonProxyFactoryBean {}
`;
  test("standard level leaves identifiers, uuids, shas, filenames", () => {
    expect(detect(code, { level: "standard" })).toEqual([]);
  });
  test("paranoid hostnames do not eat obj.method / file.ts", () => {
    const f = detect(code, { level: "paranoid" }).map((x) => x.value);
    for (const v of ["obj.method", "file.ts", "path.join", "index.ts", "i.price"]) expect(f).not.toContain(v);
  });
  test("paranoid catches real hostnames", () => {
    expect(cats("ssh to build01.corp and api.acme.io", "paranoid")).toEqual(["HOST", "HOST"]);
  });
});

describe("vault", () => {
  test("round trip with consistent tokens", () => {
    const v = new Vault("ab12");
    const src = "server 10.0.0.5 and 10.0.0.5 owned by jane@acme.io key AKIAIOSFODNN7EXAMPLE";
    const { text } = v.obfuscate(src, { level: "standard" });
    expect(text).toBe("server [HIBab12-IP-INTERNAL-NET1-1] and [HIBab12-IP-INTERNAL-NET1-1] owned by [HIBab12-EMAIL-1] key [HIBab12-AWS-KEY-1]");
    expect(v.restore(text)).toBe(src);
  });
  test("restores tokens even without brackets", () => {
    const v = new Vault("ab12");
    v.obfuscate("mail jane@acme.io", { level: "standard" });
    expect(v.restore("send to HIBab12-EMAIL-1 now")).toBe("send to jane@acme.io now");
  });
  test("unknown or foreign tokens are left alone", () => {
    const v = new Vault("ab12");
    expect(v.restore("[HIBffff-EMAIL-1] [HIBab12-EMAIL-9]")).toBe("[HIBffff-EMAIL-1] [HIBab12-EMAIL-9]");
  });
  test("random tags are 4 hex chars and vary", () => {
    const tags = new Set(Array.from({ length: 20 }, () => new Vault().tag));
    for (const t of tags) expect(t).toMatch(/^[0-9a-f]{4}$/);
    expect(tags.size).toBeGreaterThan(1);
  });
});

test("nothing inside an existing hib token is detected again", () => {
  const text = "row: [HIBab12-EMAIL-1]@[HIBab12-DOMAIN-1], ticket PAY-1234";
  const f = detect(text, { level: "paranoid", patterns: [{ category: "TICKET", regex: "\\b[A-Z]{2,6}-\\d{2,6}\\b" }] });
  expect(f.map((x) => x.value)).toEqual(["PAY-1234"]);
});

describe("conversation-scoped vault", () => {
  test("ips in the same /24 share a NET group", () => {
    const v = new Vault("ab12");
    const { text } = v.obfuscate("10.0.1.5 10.0.1.9 10.0.2.5 8.8.8.8", { level: "standard" });
    expect(text).toBe("[HIBab12-IP-INTERNAL-NET1-1] [HIBab12-IP-INTERNAL-NET1-2] [HIBab12-IP-INTERNAL-NET2-1] [HIBab12-IP-EXTERNAL-NET3-1]");
  });
  test("state round trip keeps tokens stable across turns", () => {
    const a = new Vault();
    const t1 = a.obfuscate("from 1.2.3.4 by user=jsmith", { level: "standard" }).text;
    const b = Vault.from(JSON.parse(JSON.stringify(a.state())));
    const t2 = b.obfuscate("again 1.2.3.4 and 5.6.7.8, user=jsmith", { level: "standard" }).text;
    expect(t2).toContain(t1.match(/\[[^\]]*IP[^\]]*\]/)![0]);
    expect(t2).toContain(`[HIB${a.tag}-USER-1]`);
    expect(t2).toContain(`[HIB${a.tag}-IP-EXTERNAL-NET2-1]`);
    expect(b.restore(t2)).toBe("again 1.2.3.4 and 5.6.7.8, user=jsmith");
  });
  test("sealer encrypts at rest with a 0600 key", async () => {
    const home = mkdtempSync(join(tmpdir(), "hib-seal-"));
    const s = await Sealer.open(home);
    const blob = await s.seal({ secret: "1.2.3.4" });
    expect(blob).not.toContain("1.2.3.4");
    expect(await (await Sealer.open(home)).unseal<{ secret: string }>(blob)).toEqual({ secret: "1.2.3.4" });
    expect(statSync(join(home, "vault.key")).mode & 0o777).toBe(0o600);
  });
});

describe("streaming restore", () => {
  const v = new Vault("ab12");
  const { text } = v.obfuscate("ssh jane@acme.io at 10.0.0.5 using AKIAIOSFODNN7EXAMPLE", { level: "standard" });
  const original = "ssh jane@acme.io at 10.0.0.5 using AKIAIOSFODNN7EXAMPLE";
  for (const size of [1, 2, 3, 5, 7, 13]) {
    test(`chunk size ${size}`, () => {
      const r = new StreamRestorer(v);
      let out = "";
      for (let i = 0; i < text.length; i += size) out += r.push(text.slice(i, i + size));
      out += r.flush();
      expect(out).toBe(original);
    });
  }
  test("plain brackets and H are not held forever", () => {
    const r = new StreamRestorer(v);
    expect(r.push("array[0] Hello ") + r.push("world") + r.flush()).toBe("array[0] Hello world");
  });
});

describe("policy", () => {
  test("redact by default", () => {
    expect(decide(detect("mail jane@acme.io", { level: "standard" }), cfg.routes.chat, cfg.guard).action).toBe("redact");
  });
  test("ask on private key / db uri", () => {
    const d = decide(detect("postgres://a:b@h/db", { level: "standard" }), cfg.routes.chat, cfg.guard);
    expect(d.action).toBe("ask");
    expect(d.reasons.join()).toContain("DB-URI");
  });
  test("names/places/companies from NER don't count toward the findings limit", () => {
    const ner = Array.from({ length: 50 }, (_, i) => ({ start: i, end: i + 1, value: "x", category: i % 2 ? "PERSON" : "PLACE", kind: "pii" as const }));
    expect(decide(ner, cfg.routes.chat, cfg.guard).action).toBe("redact");
    const ips = Array.from({ length: 11 }, (_, i) => ({ start: i, end: i + 1, value: "x", category: "IP-INTERNAL", kind: "infra" as const }));
    expect(decide(ips, cfg.routes.chat, cfg.guard).reasons.join()).toContain("11 findings > 10");
  });
  test("route-level ask", () => {
    expect(decide([], { ...cfg.routes.chat, ask: true }, cfg.guard).action).toBe("ask");
  });
});

describe("overlapping findings never leave part of a match in the clear", () => {
  const sent = (text: string, opts: any) => new Vault("t0").obfuscate(text, { level: "standard", ...opts }).text;
  const cases: [string, string, any, string][] = [
    ["a term inside an email domain", "mail dana.horvat@northwind-logistics.io now", { terms: ["Northwind"] }, "dana.horvat"],
    ["your username starting an email", "mail jdoe.backup@gmail.com now", { identities: ["jdoe"] }, "gmail.com"],
    ["a plugin pattern inside an email", "mail ops-team@acme-corp.io now", { patterns: [{ category: "TEAM", regex: "ops-team" }] }, "acme-corp"],
  ];
  for (const [name, text, opts, leak] of cases)
    test(name, () => {
      const out = sent(text, opts);
      expect(out).not.toContain(leak);
      expect(out).toMatch(/^mail \[HIBt0-EMAIL-1\] now$/);
    });

  test("partial overlaps merge into one span; the round trip is exact", () => {
    const text = "ref ab-12345-cd done";
    const v = new Vault("t0");
    const r = v.obfuscate(text, { level: "minimal", patterns: [{ category: "A", regex: "ab-12345" }, { category: "B", regex: "345-cd" }] });
    expect(r.text).toBe("ref [HIBt0-A-1] done");
    expect(r.findings[0]!.absorbed).toEqual(["B"]);
    expect(v.restore(r.text)).toBe(text);
  });

  test("paranoid: a home path is hidden whole, labelled as a path", () => {
    expect(sent("see /Users/jdoe/src/app.ts", { level: "paranoid" })).toBe("see [HIBt0-PATH-1]");
  });

  test("a secret keeps its label when it absorbs something wider", () => {
    const f = detect("url postgres://app:s3cretpass@db.acme.io/main end", { level: "paranoid" });
    expect(f.map((x) => x.category)).toEqual(["DB-URI"]);
  });

  test("ask rules still fire for a category that was absorbed", () => {
    const g = { ...cfg.guard, askOn: ["TERM"] };
    const f = detect("mail dana@northwind.io", { level: "standard", terms: ["Northwind"] });
    expect(f.map((x) => x.category)).toEqual(["EMAIL"]);
    expect(decide(f, cfg.routes.chat, g).action).toBe("ask");
  });
});
