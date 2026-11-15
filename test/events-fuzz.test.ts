import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventLog } from "../src/events";

/**
 * Tries to get a secret into events.jsonl through every field built from user or agent text, the way the hooks build
 * them (command/url/reasons through redact(), paths through path(), the rest as given). A line fails if it isn't valid
 * JSON, or if any 12-character piece of the secret shows up in it: as written, or after undoing zero-width characters,
 * homoglyphs, URL, base64 or hex encoding.
 */

// Real formats the guard knows, near-misses just outside its patterns, and secrets with no known shape at all.
const SECRETS = [
  "AKIAQ3EGRJ7N5XKW2PLM", // AWS
  "ghp_R8x2Lq9VtZ4mWn7Kc3Jp6Hs1Fd5Ga0Yb2EuQ", // GitHub, 36 after the prefix
  "ghp_R8x2Lq9VtZ4mWn7Kc3Jp6Hs1Fd5Ga0Yb2Eu", // near-miss: 35
  "sk-ant-api03-Zr7Kq2Xw9Lm4Vn8Bt3Hy6Jc1Pd5Fs0Ga",
  "sk-proj-Wq8Er2Ty6Ui0Op4As7Df1Gh5Jk9Lz3Xc",
  ["xox", "b-2847561930-7364829105-Kq7Wn2Lx9Vm4Bz8Ht3Rp6J"].join(""), // made up; assembled so push protection sees no token
  ["gl", "pat-Xy7Kq2Lm9Wn4Vb8Zt3Hr"].join(""), // made up, likewise
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqZG9lIn0.Qm7Kq2Xw9Lm4Vn8Bt3Hy6Jc1Pd5Fs0Ga",
  "d41d8cd98f00b204e9800998ecf8427e1a2b3c4d", // 40 hex, no prefix
  "Hunter2-Correct-Horse-Battery-77",
  "AKIAQ3EGRJ7N5XKW2PL", // near-miss: one short
  "q8Zr2Lm9Wx4Vn7Bt3Hy6Jc1Pd5Fs0GaKe", // opaque, high entropy
];

const b64 = (s: string) => Buffer.from(s).toString("base64");
const hex = (s: string) => Buffer.from(s).toString("hex");
const pct = (s: string) => [...Buffer.from(s)].map((b) => "%" + b.toString(16).padStart(2, "0")).join("");
const zw = (s: string) => [...s].map((c, i) => (i % 3 === 2 ? c + "​" : c)).join("");
const fullwidth = (s: string) => [...s].map((c) => (/[A-Za-z0-9]/.test(c) ? String.fromCharCode(c.charCodeAt(0) + 0xfee0) : c)).join("");
const CYRILLIC: Record<string, string> = { a: "а", e: "е", o: "о", p: "р", c: "с", x: "х", y: "у", A: "А", B: "В", E: "Е", K: "К", M: "М", H: "Н", O: "О", P: "Р", C: "С", T: "Т", X: "Х" };
const cyr = (s: string) => [...s].map((c) => CYRILLIC[c] ?? c).join("");
const half = (s: string) => Math.floor(s.length / 2);

// Each takes a secret and returns the text an agent or a request might carry.
const CONTEXTS: Record<string, (s: string) => string> = {
  bare: (s) => s,
  bearer: (s) => `curl -H "Authorization: Bearer ${s}" https://api.example.com/v1`,
  "authorization token": (s) => `curl -H 'Authorization: token ${s}' https://api.github.com/user`,
  "x-api-key header": (s) => `curl -H "X-Api-Key: ${s}" https://api.example.com`,
  "curl -u": (s) => `curl -u admin:${s} https://ci.example.com/api`,
  "url userinfo": (s) => `git clone https://deploy:${s}@git.example.com/team/app.git`,
  "url query": (s) => `https://api.example.com/v1/items?access_token=${s}&page=2`,
  "env assignment, plain name": (s) => `export FOO=${s} && ./deploy.sh`,
  "env assignment, secret name": (s) => `GITHUB_TOKEN=${s} gh pr list`,
  "--password=": (s) => `./tool --password=${s} --verbose`,
  "--api-key ": (s) => `./tool --api-key ${s}`,
  "json": (s) => JSON.stringify({ api_key: s, user: "x" }),
  "json escaped twice": (s) => JSON.stringify(JSON.stringify({ token: s })),
  "single quoted": (s) => `echo '${s}' | pbcopy`,
  base64: (s) => `echo ${b64(s)} | base64 -d`,
  "base64 of assignment": (s) => `echo ${b64(`token=${s}`)} | base64 -d | sh`,
  hex: (s) => `printf ${hex(s)} | xxd -r -p`,
  "percent-encoded": (s) => `curl https://hooks.example.com/x?k=${pct(s)}`,
  "zero-width inside": (s) => `curl -H "Authorization: Bearer ${zw(s)}"`,
  "fullwidth homoglyphs": (s) => `export TOKEN=${fullwidth(s)}`,
  "cyrillic homoglyphs": (s) => `echo ${cyr(s)}`,
  "split across lines": (s) => `echo ${s.slice(0, half(s))}\n${s.slice(half(s))}`,
  "at the 300-char boundary": (s) => `${"x".repeat(290)} ${s}`,
  "huge input": (s) => `${"lorem ipsum ".repeat(20_000)}${s}`,
  "lone surrogates": (s) => `\ud800${s}\udfff`,
};

/** Every reading of a written line a person or a parser could recover the secret from. */
function readings(line: string): string[] {
  const out = new Set<string>([line]);
  const plain = line.replace(/[​-‏⁠-⁤﻿]/g, "").normalize("NFKC");
  out.add(plain);
  const latin = Object.fromEntries(Object.entries(CYRILLIC).map(([l, c]) => [c, l]));
  out.add([...plain].map((c) => latin[c] ?? c).join(""));
  try {
    out.add(decodeURIComponent(plain));
  } catch {}
  for (const m of plain.matchAll(/[A-Za-z0-9+/=]{16,}/g)) out.add(Buffer.from(m[0], "base64").toString("latin1"));
  for (const m of plain.matchAll(/(?:[0-9a-f]{2}){8,}/gi)) out.add(Buffer.from(m[0], "hex").toString("latin1"));
  return [...out];
}

/** A 12-character piece of the secret anywhere in any reading of the line. */
function leak(line: string, secret: string): string | null {
  const views = readings(line);
  for (let i = 0; i + 12 <= secret.length; i++) {
    const piece = secret.slice(i, i + 12);
    if (views.some((v) => v.includes(piece))) return piece;
  }
  return null;
}

function writeAll(input: string) {
  const ev = new EventLog({ enabled: true, dir: join(mkdtempSync(join(tmpdir(), "hib-fuzz-")), "events"), maxMb: 20, keep: 5, heartbeatSec: 0 });
  const ws = "/w/app";
  const ctx = { mode: "workspace" as const, session_id: "w_1", workspace: ws };
  // As the hooks write them (sessions.ts toolFields, data.block, protected.reverted, guard reasons, auth path).
  ev.emit("tool.permission", ctx, { tool: input, command: ev.redact(input), path: ev.path(`${ws}/${input}`, ws), url: ev.redact(input), net_host: input, decision: "deny", decided_by: "user" });
  ev.emit("data.block", ctx, { command: ev.redact(input), reason: input });
  ev.emit("protected.reverted", ctx, { changes: [{ path: ev.path(`${ws}/.git/hooks/${input}`, ws), change: "added" }], failed: [input] });
  ev.emit("guard.decision", ctx, { action: "rejected", decided_by: "policy", findings: { X: 1 }, reasons: [ev.redact(input)] });
  ev.authFailure("token", `/hib/${input}`, "127.0.0.1");
  return readFileSync(ev.file, "utf8").split("\n").filter(Boolean);
}

describe("event log redaction under fuzzing", () => {
  for (const [name, ctxFn] of Object.entries(CONTEXTS))
    test(name, () => {
      const failures: string[] = [];
      for (const secret of SECRETS) {
        for (const line of writeAll(ctxFn(secret))) {
          let parsed: any;
          try {
            parsed = JSON.parse(line);
          } catch {
            failures.push(`${secret.slice(0, 12)}…: not valid JSON`);
            continue;
          }
          if (/[\ud800-\udfff]/.test(line) && !line.isWellFormed()) failures.push(`${secret.slice(0, 12)}…: lone surrogate in ${parsed.event}`);
          const piece = leak(line, secret);
          if (piece) failures.push(`${secret.slice(0, 12)}… leaked "${piece}" in ${parsed.event}: ${line.slice(0, 220)}`);
        }
      }
      expect(failures).toEqual([]);
    });

  test("random printable noise around secrets never breaks a line", () => {
    let seed = 7;
    const rnd = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32);
    for (let i = 0; i < 300; i++) {
      const noise = Array.from({ length: Math.floor(rnd() * 80) }, () => String.fromCharCode(32 + Math.floor(rnd() * 95))).join("");
      const secret = SECRETS[Math.floor(rnd() * SECRETS.length)]!;
      const ctxFn = Object.values(CONTEXTS)[Math.floor(rnd() * Object.keys(CONTEXTS).length)]!;
      for (const line of writeAll(noise + ctxFn(secret) + noise)) {
        expect(() => JSON.parse(line)).not.toThrow();
        expect(leak(line, secret)).toBeNull();
      }
    }
  });
});
