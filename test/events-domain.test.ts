import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { domainOf, EventLog, urlDomain } from "../src/events";

const tmp = () => mkdtempSync(join(tmpdir(), "hib-evd-"));
const read = (file: string) => (existsSync(file) ? readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const log = (over: Partial<ConstructorParameters<typeof EventLog>[0]> = {}) => new EventLog({ enabled: true, dir: join(tmp(), "events"), maxMb: 20, keep: 5, heartbeatSec: 0, ...over });

const check = (fn: (s: string) => string, cases: [string, string][]) => {
  for (const [input, want] of cases) expect([input, fn(input)]).toEqual([input, want]);
};

describe("domainOf", () => {
  test("IP addresses are classed by value, whatever form they are written in", () => {
    check(domainOf, [
      ["169.254.169.254", "[IP-INTERNAL]"], // cloud metadata, link-local
      ["100.64.0.1", "[IP-INTERNAL]"], // carrier-grade NAT
      ["100.127.255.254", "[IP-INTERNAL]"],
      ["100.128.0.1", "[IP-EXTERNAL]"], // just past 100.64/10
      ["0.0.0.0", "[IP-INTERNAL]"],
      ["0.0.0.0:8080", "[IP-INTERNAL]"],
      ["224.0.0.251", "[IP-INTERNAL]"],
      ["255.255.255.255", "[IP-INTERNAL]"],
      ["198.18.0.1", "[IP-INTERNAL]"],
      ["127.1", "localhost"],
      ["0x7f000001", "localhost"],
      ["2130706433", "localhost"],
      ["127.0.0.53", "localhost"],
      ["10.0.0.5", "[IP-INTERNAL]"],
      ["8.8.8.8", "[IP-EXTERNAL]"],
      ["::ffff:10.0.0.1", "[IP-INTERNAL]"],
      ["[::ffff:10.0.0.1]:443", "[IP-INTERNAL]"],
      ["::ffff:7f00:1", "localhost"],
      ["::ffff:8.8.8.8", "[IP-EXTERNAL]"],
      ["::ffff:169.254.169.254", "[IP-INTERNAL]"],
      ["64:ff9b::8.8.8.8", "[IP-EXTERNAL]"],
      ["64:ff9b::10.0.0.1", "[IP-INTERNAL]"],
      ["fe80::1%eth0", "[IP-INTERNAL]"],
      ["[fe80::1%eth0]:22", "[IP-INTERNAL]"],
      ["fe80::1", "[IP-INTERNAL]"],
      ["fd12:3456::1", "[IP-INTERNAL]"],
      ["ff02::1", "[IP-INTERNAL]"],
      ["::", "[IP-INTERNAL]"],
      ["[::]", "[IP-INTERNAL]"],
      ["::1", "localhost"],
      ["0:0:0:0:0:0:0:1", "localhost"],
      ["2001:4860:4860::8888", "[IP-EXTERNAL]"],
      ["[2001:4860:4860::8888]:53", "[IP-EXTERNAL]"],
    ]);
  });

  test("names under .arpa or a private suffix don't keep the labels that name a network or tenant", () => {
    check(domainOf, [
      ["router.home.arpa", "[INTERNAL]"],
      ["home.arpa", "[INTERNAL]"],
      ["1.0.0.10.in-addr.arpa", "[INTERNAL]"],
      ["acme-payroll.s3.amazonaws.com", "amazonaws.com"],
      ["tok3n-secret.ngrok.io", "ngrok.io"],
      ["you.github.io", "github.io"],
      ["myapp.herokuapp.com", "herokuapp.com"],
      ["a.b.example.co.uk", "example.co.uk"],
      ["db.dev.localhost", "localhost"],
    ]);
  });

  test("IDN comes out as punycode, the same for either spelling", () => {
    check(domainOf, [
      ["münchen.de", "xn--mnchen-3ya.de"],
      ["xn--mnchen-3ya.de", "xn--mnchen-3ya.de"],
      ["www.MÜNCHEN.de:443", "xn--mnchen-3ya.de"],
    ]);
  });

  test("placeholders the scrubber left give their category, port dropped", () => {
    check(domainOf, [
      ["[IP-INTERNAL]", "[IP-INTERNAL]"],
      ["[IP-INTERNAL]:8443", "[IP-INTERNAL]"],
      ["[HOST-1]", "[HOST]"],
      ["[ACME-PAYROLL-2026]", "[INTERNAL]"], // not a scrubber category: a name
      ["[HIBab12-IP-INTERNAL-NET1-1]", "[IP-INTERNAL]"],
      ["[HIBab12-IP-INTERNAL-NET1-1]:22", "[IP-INTERNAL]"],
    ]);
  });

  test("fails closed: what doesn't parse is [HOST], never the input", () => {
    const bad = ["", "secret project", "evil.com/path", "user@corp-db", "a\\b", "[not-a-placeholder]", "[ip-internal]", "host:notaport", "[zz::1]", "1:2:3", "corp.123", "%zz"];
    for (const h of bad) expect([h, domainOf(h)]).toEqual([h, "[HOST]"]);
  });
});

describe("urlDomain", () => {
  test("the host is the one new URL connects to", () => {
    check(urlDomain, [
      ["https://evil.com\\@good.com/", "https://evil.com"],
      ["https://user:pw@api.eu.example.com/x?y=1", "https://example.com"],
      ["https://a@b@evil.example.org/", "https://example.org"],
      ["HTTPS://WWW.Example.COM", "https://example.com"],
      ["http://127.1/", "http://localhost"],
      ["http://0x7f000001:8080/", "http://localhost"],
      ["http://169.254.169.254/latest/meta-data/", "http://[IP-INTERNAL]"],
      ["http://[::ffff:7f00:1]/", "http://localhost"],
      ["http://[fe80::1%25eth0]/", "http://[IP-INTERNAL]"],
      ["https://münchen.de/", "https://xn--mnchen-3ya.de"],
      ["https://acme-payroll.s3.amazonaws.com/bucket", "https://amazonaws.com"],
      ["https://router.home.arpa/", "https://[INTERNAL]"],
      ["ssh://git@github.com/org/repo", "ssh://github.com"],
      ["git://xn--mnchen-3ya.de/x", "git://xn--mnchen-3ya.de"],
    ]);
  });

  test("a placeholder host passes through, before new URL could throw on it", () => {
    check(urlDomain, [
      ["https://[IP-INTERNAL]/", "https://[IP-INTERNAL]"],
      ["https://[IP-INTERNAL]", "https://[IP-INTERNAL]"],
      ["https://[IP-INTERNAL]:8443/x?y#z", "https://[IP-INTERNAL]"],
      ["https://deploy:[CREDENTIALS]@[IP-INTERNAL]/v1", "https://[IP-INTERNAL]"],
      ["https://[HIBab12-IP-INTERNAL-NET1-1]:8080/x", "https://[IP-INTERNAL]"],
      ["https://deploy:[CREDENTIALS]@api.eu.example.com/v1", "https://example.com"],
    ]);
  });

  test("fails closed: what isn't a URL with a host is [URL], never the input", () => {
    const bad = ["", "not a url", "example.com/path", "mailto:secret@corp.example", "file:///etc/passwd", "https://[IP-INTERNAL].corp/", "https://[zz::1]/", "https://secret project/", "https://corp.123/"];
    for (const u of bad) expect([u, urlDomain(u)]).toEqual([u, "[URL]"]);
  });
});

describe("coarsening with net_host = domain", () => {
  test("net_host and url agree for the same request, raw or already redacted", () => {
    const pairs: [string, string, string][] = [
      ["[IP-INTERNAL]:443", "https://[IP-INTERNAL]/v1", "[IP-INTERNAL]"],
      ["10.0.0.1:443", "https://10.0.0.1/v1", "[IP-INTERNAL]"],
      ["169.254.169.254", "http://169.254.169.254/latest", "[IP-INTERNAL]"],
      ["münchen.de", "https://xn--mnchen-3ya.de/", "xn--mnchen-3ya.de"],
      ["acme-payroll.s3.amazonaws.com", "https://acme-payroll.s3.amazonaws.com/k", "amazonaws.com"],
    ];
    const ev = log({ netHost: "domain" });
    for (const [net_host, url] of pairs) ev.emit("sandbox.network", { mode: "workspace", session_id: "s1" }, { net_host, url });
    const lines = read(ev.file);
    pairs.forEach(([, , want], i) => {
      expect(lines[i].net_host).toBe(want);
      expect(lines[i].url).toBe(`${pairs[i]![1].split(":")[0]}://${want}`);
    });
    const text = readFileSync(ev.file, "utf8");
    for (const leak of ["acme-payroll", "münchen", "169.254", "10.0.0.1", "latest"]) expect(text).not.toContain(leak);
  });

  test("without net_host = domain, private-suffix hosts are left whole", () => {
    const ev = log();
    ev.emit("sandbox.network", { mode: "workspace", session_id: "s1" }, { net_host: "you.github.io" });
    expect(read(ev.file)[0].net_host).toBe("you.github.io");
  });
});
