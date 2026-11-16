import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig } from "../src/config";
import { EventLog } from "../src/events";
import { dataBlockEventReason, rawDataCommand } from "../src/workspace/datarules";

// The review's repro inputs, through the real emit() path with profile = "siem": nothing identifying may reach the file.
describe("profile siem, end to end", () => {
  const home = mkdtempSync(join(tmpdir(), "hib-siem-"));
  const cfg = { ...parseConfig({ events: { profile: "siem" } }, home).events, heartbeatSec: 0 };
  const ev = new EventLog(cfg);
  const ctx = { mode: "workspace" as const, session_id: "s1", workspace: "/srv/acme-corp/clients/payroll_2026", account: "claude@ana.kovac" };
  const lines = () => readFileSync(ev.file, "utf8").trim().split("\n").map((l) => JSON.parse(l));

  const cases: { command: string; net_host: string; url: string; program: string; domain: string; url_out: string }[] = [
    { command: 'DB_PASSWORD="correct horse battery" psql -h db', net_host: "acme-payroll.s3.amazonaws.com", url: "https://acme-payroll.s3.amazonaws.com/x", program: "psql", domain: "amazonaws.com", url_out: "https://amazonaws.com" },
    { command: 'A="$(cat /etc/passwd)" curl https://x', net_host: "evil.com", url: "https://evil.com\\@good.com/", program: "[COMMAND]", domain: "evil.com", url_out: "https://evil.com" },
    { command: "sudo -R /root curl x", net_host: "router.home.arpa", url: "http://router.home.arpa/", program: "curl", domain: "[INTERNAL]", url_out: "http://[INTERNAL]" },
    { command: 'env -S"FOO=1 wget" y', net_host: "169.254.169.254", url: "http://169.254.169.254/latest/meta-data", program: "wget", domain: "[IP-INTERNAL]", url_out: "http://[IP-INTERNAL]" },
    { command: "curl x", net_host: "[::ffff:10.0.0.1]:8080", url: "https://[IP-INTERNAL]/", program: "curl", domain: "[IP-INTERNAL]", url_out: "https://[IP-INTERNAL]" },
    { command: "curl x", net_host: "münchen.de", url: "https://xn--mnchen-3ya.de/", program: "curl", domain: "xn--mnchen-3ya.de", url_out: "https://xn--mnchen-3ya.de" },
    { command: "curl x", net_host: "tok3n-secret.ngrok.io", url: "https://tok3n-secret.ngrok.io/", program: "curl", domain: "ngrok.io", url_out: "https://ngrok.io" },
  ];

  test("command, net_host and url are coarsened; workspace and account hashed", () => {
    for (const c of cases) ev.emit("tool.permission", ctx, { kind: "command", command: c.command, net_host: c.net_host, url: c.url });
    const got = lines();
    expect(got).toHaveLength(cases.length);
    cases.forEach((c, i) => {
      expect({ command: got[i].command, net_host: got[i].net_host, url: got[i].url }).toEqual({ command: c.program, net_host: c.domain, url: c.url_out });
      expect(got[i].workspace).toMatch(/^[0-9a-f]{16}$/);
      expect(got[i].account).toMatch(/^claude@[0-9a-f]{16}$/);
    });
  });

  test("data.block carries only the fixed reason", () => {
    const block = rawDataCommand("python3 /srv/acme-corp/clients/payroll_2026/extract.py", "/w")!;
    ev.emit("data.block", ctx, { command: ev.redact("python3 /srv/acme-corp/clients/payroll_2026/extract.py"), reason: dataBlockEventReason(block, ev.cfg.command, (t) => ev.redact(t)) });
    const l = lines().at(-1);
    expect(l).toMatchObject({ command: "python3", reason: "it runs a script from outside this folder" });
  });

  test("nothing identifying anywhere in the file", () => {
    const text = readFileSync(ev.file, "utf8");
    for (const s of ["horse", "battery", "passwd", "/root", "good.com", "router", "acme", "payroll", "tok3n", "ana.kovac", "10.0.0.1", "169.254", "extract.py"]) expect(text).not.toContain(s);
  });
});
