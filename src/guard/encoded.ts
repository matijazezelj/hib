// Encoded payloads: base64, hex and percent-encoded runs that decode to readable text. Sudo and process logs record
// `python3 -c <base64 script>`; the model decodes such a blob as easily as it reads plain text, so the guard has to
// look inside. A blob whose decoded text has any finding goes out as one placeholder, never in part.
import { gunzipSync, inflateSync } from "node:zlib";

export type Encoding = "BASE64" | "HEX" | "URL";

export interface Blob {
  start: number;
  end: number;
  value: string;
  decoded: string;
  encoding: Encoding;
}

const MAX_BLOB = 1_000_000; // longer runs aren't decoded (a payload that size isn't a command-line script)
// One run of 20+ characters, or MIME-style lines of 40+ wrapped at fixed width (the last line can be short).
const BASE64 = /(?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{40,}\r?\n)+[A-Za-z0-9+/]{2,}={0,2}|[A-Za-z0-9+/_-]{20,}={0,2})/g;
const HEX = /(?<![0-9A-Za-z])(?:[0-9a-fA-F]{2}){8,}(?![0-9A-Za-z])/g;
const PCT = /[A-Za-z0-9._~!*'()+%-]+/g; // URL-safe runs; only those holding a %XX escape are decoded

const utf8 = new TextDecoder("utf-8", { fatal: true });

/** Decoded bytes as text, or null if they aren't valid UTF-8 that is mostly printable (hashes, keys, binary). */
function asText(bytes: Uint8Array): string | null {
  let s: string;
  try {
    s = utf8.decode(bytes);
  } catch {
    return null;
  }
  const chars = [...s];
  if (chars.length < 6) return null;
  const printable = chars.filter((c) => /[\p{L}\p{N}\p{P}\p{S}\p{Zs}\t\n\r]/u.test(c)).length;
  return printable / chars.length >= 0.9 && (s.match(/\p{L}/gu) ?? []).length >= 4 ? s : null;
}

const MAX_INFLATED = 1_000_000;

/**
 * Bytes as text, opening gzip and zlib streams first (`echo … | gzip | base64`). Inflating is capped at 10× the input
 * and 1 MB: a stream that would grow past that stays closed, like any other binary.
 */
function bytesAsText(bytes: Uint8Array): string | null {
  const gzip = bytes[0] === 0x1f && bytes[1] === 0x8b;
  const zlib = bytes[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(bytes[1]!) && ((bytes[0] << 8) | bytes[1]!) % 31 === 0;
  if (!gzip && !zlib) return asText(bytes);
  try {
    const opts = { maxOutputLength: Math.min(10 * bytes.length, MAX_INFLATED) };
    return asText(new Uint8Array(gzip ? gunzipSync(bytes, opts) : inflateSync(bytes, opts)));
  } catch {
    return null;
  }
}

function base64(run: string): string | null {
  const s = run.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (s.length % 4 === 1) return null; // not a whole number of bytes
  return bytesAsText(Uint8Array.from(Buffer.from(s, "base64")));
}

/**
 * A run that doesn't decode whole may be a blob glued to a path (`/tmp/<base64>`, `/upload/<base64>/x`): base64 has
 * "/" in its alphabet, so the regex takes the path along. Pieces cut at slashes are tried, longest first.
 */
function base64Within(run: string): { start: number; end: number; decoded: string } | null {
  const cuts = [...run.matchAll(/\//g)].map((m) => m.index!).slice(0, 8);
  if (!cuts.length || run.includes("\n")) return null;
  const starts = [0, ...cuts.map((c) => c + 1)];
  const ends = [run.length, ...cuts];
  const spans = starts.flatMap((s) => ends.filter((e) => e - s >= 20).map((e) => [s, e] as const)).sort((a, b) => b[1] - b[0] - (a[1] - a[0]));
  for (const [s, e] of spans) {
    const decoded = base64(run.slice(s, e));
    if (decoded) return { start: s, end: e, decoded };
  }
  return null;
}

/** Encoded runs in `text` that decode to readable text, in order, not overlapping. */
export function encodedBlobs(text: string): Blob[] {
  const out: Blob[] = [];
  const taken = (s: number, e: number) => out.some((b) => s < b.end && b.start < e);
  for (const m of text.matchAll(HEX)) {
    if (m[0].length > MAX_BLOB) continue;
    const decoded = bytesAsText(Uint8Array.from(Buffer.from(m[0], "hex")));
    if (decoded) out.push({ start: m.index!, end: m.index! + m[0].length, value: m[0], decoded, encoding: "HEX" });
  }
  for (const m of text.matchAll(BASE64)) {
    // A run of hex digits is hex or nothing: as base64 it would decode to noise.
    if (m[0].length > MAX_BLOB || /^[0-9a-fA-F]+$/.test(m[0]) || taken(m.index!, m.index! + m[0].length)) continue;
    const decoded = base64(m[0]);
    if (decoded) out.push({ start: m.index!, end: m.index! + m[0].length, value: m[0], decoded, encoding: "BASE64" });
    else {
      const part = base64Within(m[0]);
      if (part) out.push({ start: m.index! + part.start, end: m.index! + part.end, value: m[0].slice(part.start, part.end), decoded: part.decoded, encoding: "BASE64" });
    }
  }
  for (const m of text.matchAll(PCT)) {
    if (m[0].length < 6 || m[0].length > MAX_BLOB || !/%[0-9A-Fa-f]{2}/.test(m[0]) || taken(m.index!, m.index! + m[0].length)) continue;
    let decoded: string;
    try {
      decoded = decodeURIComponent(m[0].replace(/\+/g, " "));
    } catch {
      continue;
    }
    if (decoded !== m[0]) out.push({ start: m.index!, end: m.index! + m[0].length, value: m[0], decoded, encoding: "URL" });
  }
  return out.sort((a, b) => a.start - b.start);
}

/** Token category for a blob with findings inside: BASE64-ENCODED, HEX-ENCODED, URL-ENCODED. */
export const encodedCategory = (b: Blob) => `${b.encoding}-ENCODED`;

/**
 * Quoted string literals in decoded code, one per line: name detection skips code-looking lines, and a script's
 * names and addresses sit in its strings (`print("lookup Ivo Ivić")`).
 */
export function stringLiterals(code: string): string {
  return [...code.matchAll(/"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'/g)].map((m) => m[1] ?? m[2] ?? "").filter((s) => /\p{L}{2}/u.test(s)).join("\n");
}
