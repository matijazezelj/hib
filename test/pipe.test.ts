import { describe, expect, test } from "bun:test";
import { defaultPolicy, GuardState } from "../src/guard/record";
import { Vault } from "../src/guard/vault";
import { REDACTED_JSON, REDACTED_TEXT, runPipe, runRestore, type PipeOptions } from "../src/pipe";

const enc = new TextEncoder();

/** A byte stream delivered in the given pieces (strings or raw byte arrays). */
function stream(...pieces: (string | Uint8Array)[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(c) {
      for (const p of pieces) c.enqueue(typeof p === "string" ? enc.encode(p) : p);
      c.close();
    },
  });
}

/** The same bytes cut at the given byte offsets. */
function cut(text: string, at: number[]): Uint8Array[] {
  const b = enc.encode(text);
  const bounds = [0, ...at, b.length];
  return bounds.slice(1).map((end, i) => b.slice(bounds[i], end));
}

const opts = (o: Partial<PipeOptions> = {}): PipeOptions => ({ format: "auto", onError: "redact", saveEvery: 1000, ...o });

async function pipe(input: ReadableStream<Uint8Array>, o: Partial<PipeOptions> = {}, state = new GuardState(new Vault("ab12")), save?: () => Promise<void>) {
  let out = "";
  const stats = await runPipe(input, (s) => void (out += s), state, defaultPolicy(), opts(o), save);
  return { out, stats, state };
}

async function restore(input: ReadableStream<Uint8Array>, vault: Vault) {
  let out = "";
  await runRestore(input, async (s) => void (out += s), vault);
  return out;
}

const ecs = {
  "@timestamp": "2026-11-13T08:00:00Z",
  event: { action: "login", outcome: "failure" },
  source: { ip: "10.1.2.3", port: 51234 },
  user: { name: "jdoe", email: "jane.doe@corp.example" },
  host: { hostname: "web-01.corp.internal" },
  message: "login failed for jane.doe@corp.example from 10.1.2.3",
};

describe("runPipe — independent of the guard", () => {
  test("ndjson: a bad line is dropped, redacted or fails, and never appears in the output", async () => {
    const bad = "password=hunter2 not json at all";
    const input = () => stream(`${bad}\n\n${bad}\n`);

    const drop = await pipe(input(), { format: "ndjson", onError: "drop" });
    expect(drop.out).toBe("\n"); // the blank line passes through, both bad lines are gone
    expect(drop.stats).toMatchObject({ lines: 3, dropped: 2, redacted: 0, records: 0, text: 0 });

    const red = await pipe(input(), { format: "ndjson", onError: "redact" });
    expect(red.out).toBe(`${REDACTED_JSON}\n\n${REDACTED_JSON}\n`);
    expect(red.stats).toMatchObject({ lines: 3, redacted: 2, dropped: 0 });

    let saves = 0;
    let written = "";
    const err = await runPipe(input(), (s) => void (written += s), new GuardState(new Vault("ab12")), defaultPolicy(), opts({ format: "ndjson", onError: "fail" }), async () => void saves++).catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(String(err.message)).not.toContain("hunter2");
    expect(String(err.message)).toContain("line 1");
    expect(saves).toBe(1); // saved before rethrowing
    for (const s of [drop.out, red.out, written]) expect(s).not.toContain("hunter2");
  });

  test("save is called every saveEvery lines and once at the end", async () => {
    let saves = 0;
    const lines = Array.from({ length: 7 }, (_, i) => `bad ${i}`).join("\n") + "\n";
    const r = await pipe(stream(lines), { format: "ndjson", onError: "drop", saveEvery: 3 }, undefined, async () => void saves++);
    expect(r.stats.lines).toBe(7);
    expect(saves).toBe(3); // after lines 3 and 6, then at the end
  });

  test("blank lines pass through, CRLF endings become LF", async () => {
    const r = await pipe(stream("\n\r\n  \n"), { format: "ndjson", onError: "fail" });
    expect(r.out).toBe("\n\n  \n");
    expect(r.stats.lines).toBe(3);
  });

  test("a guard that throws is fail-closed (vault whose token() throws)", async () => {
    const vault = new Vault("dead");
    vault.token = () => {
      throw new Error("boom: jane.doe@corp.example");
    };
    const line = JSON.stringify({ user: { email: "jane.doe@corp.example" }, message: "hi" });
    const red = await pipe(stream(`${line}\n`), { onError: "redact" }, new GuardState(vault));
    expect(red.out).toBe(`${REDACTED_JSON}\n`);
    const drop = await pipe(stream(`${line}\n`), { onError: "drop" }, new GuardState(vault));
    expect(drop.out).toBe("");
    const text = await pipe(stream("mail jane.doe@corp.example now\n"), { format: "text", onError: "redact" }, new GuardState(vault));
    expect(text.out).toBe(`${REDACTED_TEXT}\n`);
    const err = await pipe(stream(`${line}\n`), { onError: "fail" }, new GuardState(vault)).catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(String(err.message)).not.toContain("jane.doe");
  });
});

describe("runPipe — with guardRecord / guardLine", () => {
  test("one output line per input line, in order; mixed JSON and text in auto mode", async () => {
    const input = [JSON.stringify(ecs), "plain text from 10.9.8.7", "", JSON.stringify({ n: 1 }), "[1,2,3]", "{not json"].join("\n") + "\n";
    const { out, stats } = await pipe(stream(input));
    const lines = out.split("\n");
    expect(lines.length).toBe(7);
    expect(lines[6]).toBe("");
    expect(JSON.parse(lines[0]!)["event.action"]).toBe("login");
    expect(lines[1]).toStartWith("plain text from ");
    expect(lines[1]).not.toContain("10.9.8.7");
    expect(lines[2]).toBe("");
    expect(JSON.parse(lines[3]!)).toEqual({ n: 1 });
    expect(lines[4]).toBe("[1,2,3]"); // not an object: guarded as text
    expect(lines[5]).toBe("{not json");
    expect(stats).toMatchObject({ lines: 6, records: 2, text: 3, dropped: 0, redacted: 0 });
    expect(out).not.toContain("jane.doe@corp.example");
    expect(out).not.toContain("10.1.2.3");
  });

  test("the last line needs no trailing newline", async () => {
    const { out } = await pipe(stream("a\nb"), { format: "text" });
    expect(out).toBe("a\nb\n");
  });

  test("chunk boundaries inside a line and inside a multi-byte UTF-8 character change nothing", async () => {
    const text = `${JSON.stringify({ ...ecs, note: "Kovačević – 日本 ✓" })}\nčćžšđ from 10.1.2.3 and jane.doe@corp.example\n`;
    const whole = await pipe(stream(text));
    const bytes = enc.encode(text);
    const c = bytes.indexOf(0xc4); // first byte of a 2-byte "č"
    const j = bytes.indexOf(0xe6); // first byte of a 3-byte "日"
    for (const at of [[c + 1], [j + 1, j + 2], [5, c + 1, j + 2, bytes.length - 3], Array.from({ length: bytes.length - 1 }, (_, i) => i + 1)]) {
      const chunked = await pipe(stream(...cut(text, at)));
      expect(chunked.out).toBe(whole.out);
    }
    expect(whole.out).toContain("Kovačević – 日本 ✓");
    expect(whole.out).not.toContain("�");
  });

  test("pipe -> restore round trip on an ECS-like event", async () => {
    const vault = new Vault("ab12");
    const state = new GuardState(vault);
    const { out } = await pipe(stream(JSON.stringify(ecs) + "\n"), {}, state);
    expect(out).not.toContain("jane.doe@corp.example");
    expect(out).not.toContain("10.1.2.3");
    expect(out).toContain("[HIBab12-");
    const guarded = JSON.parse(out);
    expect(guarded["event.outcome"]).toBe("failure");
    expect(guarded["@timestamp"]).toBe(ecs["@timestamp"]);

    const back = JSON.parse(await restore(stream(...cut(out, [7, 20, 33, 60])), vault));
    expect(back["user.email"]).toBe("jane.doe@corp.example");
    expect(back["source.ip"]).toBe("10.1.2.3");
    expect(back["user.name"]).toBe("jdoe");
    expect(back.message).toBe(ecs.message);
    expect(back["event.action"]).toBe("login");
  });

  test("the same value gets the same token across runs sharing a vault", async () => {
    const state = new GuardState(new Vault("ab12"));
    const a = await pipe(stream(JSON.stringify(ecs) + "\n"), {}, state);
    const b = await pipe(stream(JSON.stringify(ecs) + "\n"), {}, new GuardState(Vault.from(state.vault.state())));
    expect(b.out).toBe(a.out);
  });
});

describe("runRestore", () => {
  test("restores tokens split across chunks at every position", async () => {
    const vault = new Vault("ab12");
    const t1 = vault.token("EMAIL", "jane.doe@corp.example");
    const t2 = vault.token("IP-INTERNAL", "10.1.2.3");
    const text = `ask [${t1}] about ${t2} — 日本 [${t1}]\n`;
    const want = "ask jane.doe@corp.example about 10.1.2.3 — 日本 jane.doe@corp.example\n";
    expect(await restore(stream(text), vault)).toBe(want);
    const n = enc.encode(text).length;
    for (let i = 1; i < n; i++) expect(await restore(stream(...cut(text, [i])), vault)).toBe(want);
    expect(await restore(stream(...cut(text, Array.from({ length: n - 1 }, (_, i) => i + 1))), vault)).toBe(want);
  });

  test("unknown tokens and plain text pass through", async () => {
    const vault = new Vault("ab12");
    expect(await restore(stream("no tokens here [HIBab12-EMAIL-9] [HIB"), vault)).toBe("no tokens here [HIBab12-EMAIL-9] [HIB");
  });
});
