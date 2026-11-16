import { createHmac, randomBytes } from "node:crypto";
import { appendFileSync, chmodSync, closeSync, constants as fsConstants, existsSync, fstatSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { basename, dirname, isAbsolute, join, relative } from "node:path";
import { parse as parseHost } from "tldts";
import { detect, isPrivateIp } from "./guard/detectors";
import { machineTerms } from "./guard";
import type { EventsConfig } from "./config";

/**
 * Security events as JSON lines, for a log collector (SIB) to ship and alert on. Contract: sib/docs/hib-events-spec.md,
 * schema 1. The directory holds event files only, so a collector can mount it alone, never ~/.hib with the token,
 * vault key and database next to it. Never logged: prompts, model or tool output, file contents, diffs, tokens, vault
 * values. Fields that can carry user text go through the redactor and are cut to 300 characters.
 */

export const SCHEMA = 1;
const TEXT_MAX = 300;
const AUTH_WINDOW_MS = 60_000;
const SCAN_MAX = 8192; // text past this can't reach the 300 characters that are kept, so it isn't scanned

/**
 * Fields hib writes itself (ids, enums, numbers, the workspace root): never redacted. Every other string field, at any
 * depth, can carry user or agent text and is scrubbed for secrets when the line is written, whatever the caller did.
 */
const OWN_FIELDS = new Set([
  "ts", "schema", "source", "host", "hib_version", "event", "severity", "mode", "session_id", "run_id", "workspace", "account", "model", "route",
  "bind", "port", "sandbox", "remote", "decision", "decided_by", "action", "kind", "agent", "sensitive", "count", "uptime_sec", "timeout_sec", "signal", "change", "findings",
]);

/** Lone surrogates become U+FFFD (every line stays valid UTF-8); zero-width and bidi controls go; look-alike forms fold (NFKC). */
export function sanitize(text: string): string {
  return text.toWellFormed().replace(/\p{Cf}/gu, "").normalize("NFKC");
}

type Span = { start: number; end: number; category: string };

/**
 * Secrets the guard's detectors don't look for in a log line, or can't see because of their shape. Over-redacting is
 * fine here: these lines are metadata for alerts, and an opaque id lost to [OPAQUE] costs nothing.
 */
const EXTRA: { category: string; re: RegExp; group?: number; secret?: (v: string) => boolean }[] = [
  { category: "CREDENTIALS", re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s@/]+)@/gi, group: 1 }, // https://user:PASS@host
  { category: "CREDENTIALS", re: /(?:^|[\s"'])(?:-u|--user)[\s=]+["']?[^\s:"']+:([^\s"']+)/g, group: 1 }, // curl -u user:PASS
  // Authorization: <scheme> <value>, Cookie, X-Api-Key and the like: everything after the colon, up to a quote or line end.
  { category: "AUTH-HEADER", re: /\b(?:authorization|proxy-authorization|cookie|set-cookie|x-[a-z0-9-]*(?:key|token|secret|auth|signature)[a-z0-9-]*)\s*:\s*([^"'\n]+)/gi, group: 1 },
  { category: "URL-ENCODED", re: /(?:%[0-9a-f]{2}){4,}/gi }, // a percent-encoded run hides whatever it spells
];

/**
 * Opaque runs with no known shape: a key one character short of its pattern, raw hex, base64 or hex encodings,
 * look-alike letters. Letters and digits mixed (16+), long and mixed-case (24+), or long with a digit (32+: a hex
 * encoding can be digits only). A run touching a line break counts from 8: half of a key split across lines.
 */
const RUN = /[\p{L}\p{N}_+=-]{8,}/gu;
function opaque(v: string, atBreak: boolean): boolean {
  const letter = /\p{L}/u.test(v);
  const digit = /\p{N}/u.test(v);
  if (v.length >= (atBreak ? 8 : 16) && letter && digit) return true;
  if (v.length >= 24 && /\p{Lu}/u.test(v) && /\p{Ll}/u.test(v)) return true;
  return v.length >= 32 && digit;
}

function extraSpans(text: string): Span[] {
  const out: Span[] = [];
  for (const m of text.matchAll(RUN)) {
    const atBreak = /[\r\n\\]/.test(text[m.index! - 1] ?? "") || /[\r\n\\]/.test(text[m.index! + m[0].length] ?? "");
    if (opaque(m[0], atBreak)) out.push({ start: m.index!, end: m.index! + m[0].length, category: "OPAQUE" });
  }
  for (const x of EXTRA)
    for (const m of text.matchAll(x.re)) {
      const v = m[x.group ?? 0];
      if (!v || (x.secret && !x.secret(v))) continue;
      const start = m.index! + (x.group ? m[0].lastIndexOf(v) : 0);
      out.push({ start, end: start + v.length, category: x.category });
    }
  return out;
}

/** Spans replaced by [CATEGORY]; overlapping ones merge into one, labelled by the first. */
function replaceSpans(text: string, spans: Span[]): string {
  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  let out = "";
  let pos = 0;
  for (const s of spans) {
    if (s.end <= pos) continue;
    if (s.start < pos) {
      pos = s.end; // overlaps the previous replacement: extend it
      continue;
    }
    out += text.slice(pos, s.start) + `[${s.category}]`;
    pos = s.end;
  }
  return out + text.slice(pos);
}

/** Loopback names (loopback addresses are found by their value, see ipv4Class and ipv6Class). */
const LOOPBACK = /^(?:localhost|.*\.localhost)$/;

/** A placeholder the scrubber already put where a host was: [IP-INTERNAL], [HIBab12-IP-INTERNAL-NET1-1]. */
const PLACEHOLDER = String.raw`\[(?:HIB[0-9a-f]{4}-)?[A-Z][A-Z0-9-]*\]`;
const PLACEHOLDER_HOST = new RegExp(String.raw`^(${PLACEHOLDER})(?::\d*)?$`);
/** scheme://[userinfo@]PLACEHOLDER[:port] up to the end of the authority (\ ends it too, as in new URL). */
const PLACEHOLDER_URL = new RegExp(String.raw`^([A-Za-z][A-Za-z0-9+.-]*):\/\/(?:[^\s\/?#\\]*@)?(${PLACEHOLDER})(?::\d*)?(?:[\/?#\\]|$)`);

/**
 * A placeholder reduced to its category, so only what the scrubber writes passes: [HIBab12-IP-INTERNAL-NET1-1] and
 * [IP-INTERNAL] both give [IP-INTERNAL]. Other bracketed text ([ACME-PAYROLL]) is a name, not a placeholder: [INTERNAL].
 */
const CATEGORIES = ["IP-INTERNAL", "IP-EXTERNAL", "INTERNAL", "HOST", "IP", "EMAIL", "USER", "PATH", "CONTAINER", "PERSON", "TERM", "TEXT", "HIGH-ENTROPY", "CREDENTIALS"];
function placeholderClass(p: string): string {
  const core = p.slice(1, -1).replace(/^HIB[0-9a-f]{4}-/, "");
  const cat = CATEGORIES.find((c) => core === c || core.startsWith(c + "-"));
  return cat ? `[${cat}]` : "[INTERNAL]";
}

/** What a host that can't be parsed becomes; never the input text. */
const BAD_HOST = "[HOST]";
const BAD_URL = "[URL]";

/** IPv4 ranges that are internal on top of isPrivateIp's (10/8, 172.16/12, 192.168/16, 127/8): [first, prefix bits]. */
const INTERNAL_V4: [number, number][] = [
  [0x00000000, 8], // 0.0.0.0/8, "this network", 0.0.0.0 included
  [0x64400000, 10], // 100.64.0.0/10, carrier-grade NAT
  [0xa9fe0000, 16], // 169.254.0.0/16, link-local (cloud metadata at 169.254.169.254)
  [0xc0000000, 24], // 192.0.0.0/24, IETF protocol assignments
  [0xc6120000, 15], // 198.18.0.0/15, benchmarking
  [0xe0000000, 4], // 224.0.0.0/4, multicast
  [0xf0000000, 4], // 240.0.0.0/4, reserved, 255.255.255.255 included
];

/** A dotted-quad IPv4 address (as new URL writes it) classed: localhost, [IP-INTERNAL] or [IP-EXTERNAL]. */
function ipv4Class(ip: string): string {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !(Number.isInteger(n) && n >= 0 && n <= 255))) return BAD_HOST;
  if (p[0] === 127) return "localhost";
  const n = ((p[0]! << 24) >>> 0) + (p[1]! << 16) + (p[2]! << 8) + p[3]!;
  const inRange = INTERNAL_V4.some(([base, bits]) => (n >>> (32 - bits)) === (base >>> (32 - bits)));
  return inRange || isPrivateIp(ip) ? "[IP-INTERNAL]" : "[IP-EXTERNAL]";
}

/** An IPv6 address without brackets or zone (as new URL writes it) as its eight 16-bit groups, or null. */
function ipv6Groups(s: string): number[] | null {
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const groups = (x: string) => (x === "" ? [] : x.split(":").map((g) => (/^[0-9a-f]{1,4}$/i.test(g) ? parseInt(g, 16) : NaN)));
  const head = groups(halves[0]!);
  const tail = halves.length === 2 ? groups(halves[1]!) : [];
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 1 : fill !== 0) return null;
  const all = [...head, ...new Array<number>(halves.length === 2 ? fill : 0).fill(0), ...tail];
  return all.every((n) => Number.isInteger(n)) ? all : null;
}

/** An IPv6 address classed; IPv4 inside it (mapped, compatible, NAT64) is classed as IPv4. */
function ipv6Class(s: string): string {
  const g = ipv6Groups(s);
  if (!g) return BAD_HOST;
  const [a, b, c, d, e, f, hi, lo] = g as [number, number, number, number, number, number, number, number];
  const zero5 = a === 0 && b === 0 && c === 0 && d === 0 && e === 0;
  if (zero5 && f === 0 && hi === 0 && lo === 1) return "localhost"; // ::1
  if (zero5 && f === 0 && hi === 0 && lo === 0) return "[IP-INTERNAL]"; // ::, unspecified
  const v4 = `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  if (zero5 && (f === 0xffff || f === 0)) return ipv4Class(v4); // ::ffff:0:0/96 mapped, ::/96 compatible
  if (a === 0x64 && b === 0xff9b && c === 0 && d === 0 && e === 0 && f === 0) return ipv4Class(v4); // 64:ff9b::/96 NAT64
  if (a === 0x64 && b === 0xff9b && c === 1) return "[IP-INTERNAL]"; // 64:ff9b:1::/48, local-use NAT64
  const internal =
    (a & 0xffc0) === 0xfe80 || // fe80::/10 link-local
    (a & 0xffc0) === 0xfec0 || // fec0::/10 site-local
    (a & 0xfe00) === 0xfc00 || // fc00::/7 unique local
    (a & 0xff00) === 0xff00; // ff00::/8 multicast
  return internal ? "[IP-INTERNAL]" : "[IP-EXTERNAL]";
}

/**
 * A host, host:port, [IPv6]:port or bare IPv6 (zone id allowed) as new URL normalises it: lower case, punycode,
 * IPv4 in dotted-quad (127.1 and 0x7f000001 are 127.0.0.1), IPv6 compressed in brackets. Null if it doesn't parse
 * or has anything a host can't (path, query, userinfo, whitespace).
 */
function canonicalHost(raw: string): string | null {
  if (!raw || /[\s\/\\?#@]/.test(raw)) return null;
  let h = raw;
  const bracketed = /^\[([^\]]*)\](:\d*)?$/.exec(h);
  if (bracketed) h = `[${bracketed[1]!.replace(/%.*$/, "")}]`; // the port goes, and an IPv6 zone id (fe80::1%eth0)
  else if ((h.match(/:/g) ?? []).length >= 2) h = `[${h.replace(/%.*$/, "")}]`; // bare IPv6; one colon is host:port
  try {
    return new URL(`http://${h}`).hostname || null;
  } catch {
    return null;
  }
}

/** A hostname from canonicalHost reduced to a domain or a fixed label. */
function hostClass(hostname: string | null): string {
  if (!hostname) return BAD_HOST;
  const h = hostname.replace(/\.$/, "");
  if (h.startsWith("[") && h.endsWith("]")) return ipv6Class(h.slice(1, -1));
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return ipv4Class(h);
  if (LOOPBACK.test(h)) return "localhost";
  if (h === "arpa" || h.endsWith(".arpa")) return "[INTERNAL]"; // home.arpa, in-addr.arpa, ip6.arpa: they name the network
  const p = parseHost(h, { allowPrivateDomains: false });
  return p.domain && p.isIcann ? p.domain : "[INTERNAL]";
}

/**
 * The registrable domain under an ICANN public suffix (tldts, private suffixes left out so a tenant label doesn't
 * survive: acme-payroll.s3.amazonaws.com and you.github.io become amazonaws.com and github.io; x.example.com.au
 * becomes example.com.au). IDN comes out as punycode. Loopback is "localhost"; an IP address (in any form new URL
 * accepts) becomes [IP-INTERNAL] or [IP-EXTERNAL]; a name under no ICANN suffix (.corp, .local, .internal, .arpa, a
 * single label) becomes [INTERNAL], since its last labels would still name the network. A port goes. A placeholder
 * the scrubber left gives its category ([IP-INTERNAL]); anything that doesn't parse is [HOST].
 */
export function domainOf(host: string): string {
  const h = host.trim();
  const placeholder = PLACEHOLDER_HOST.exec(h);
  if (placeholder) return placeholderClass(placeholder[1]!);
  return hostClass(canonicalHost(h));
}

/**
 * A URL cut to scheme://domain, the host as new URL reads it (https://evil.com\@good.com/ goes to evil.com) and
 * classed as domainOf does, so net_host and url agree. A placeholder host is kept; anything else that isn't a URL
 * with a host becomes [URL].
 */
export function urlDomain(url: string): string {
  const u = url.trim();
  const placeholder = PLACEHOLDER_URL.exec(u);
  if (placeholder) return `${placeholder[1]!.toLowerCase()}://${placeholderClass(placeholder[2]!)}`;
  let parsed: URL;
  try {
    // An IPv6 zone id ([fe80::1%25eth0]) makes new URL throw; it says nothing about where the request goes.
    parsed = new URL(u.replace(/^([^\/?#]*\/\/[^\/?#\\]*\[[0-9A-Fa-f:.]+)%[^\]\/?#]*\]/, "$1]"));
  } catch {
    return BAD_URL;
  }
  // Re-read as an http host: non-special schemes (ssh://, git://) leave the host as typed, not normalised.
  const domain = hostClass(canonicalHost(parsed.hostname));
  return domain === BAD_HOST ? BAD_URL : `${parsed.protocol.replace(/:$/, "")}://${domain}`;
}

/**
 * Wrappers that run another program, with the options that take a value (so the value isn't read as the program).
 * An extra entry only skips one word too many; a missing one logs the value, so when in doubt an option is listed.
 */
const WRAPPERS: Record<string, Set<string>> = {
  // sudo(8) -C -D -g -h -p -R -T -U -u; -a -c (BSD auth, login class) and -r -t (SELinux) exist only in some builds
  sudo: new Set([
    "-a", "-c", "-C", "-D", "-g", "-h", "-p", "-R", "-r", "-T", "-t", "-U", "-u",
    "--auth-type", "--login-class", "--close-from", "--chdir", "--group", "--host", "--prompt", "--chroot", "--role",
    "--command-timeout", "--type", "--other-user", "--user",
  ]),
  doas: new Set(["-a", "-u", "-C"]),
  env: new Set(["-a", "-u", "-C", "-P", "-S", "--argv0", "--unset", "--chdir", "--split-string"]),
  nice: new Set(["-n", "--adjustment"]),
  exec: new Set(["-a"]),
  time: new Set(["-f", "-o", "--format", "--output"]),
  nohup: new Set(),
  command: new Set(),
  timeout: new Set(["-s", "-k", "--signal", "--kill-after"]), // its first operand is the duration
};
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"]);

/** A shell word with its quotes removed; `live` if it holds a command substitution or a `$'...'` string. */
type ShellWord = { text: string; live: boolean };

/**
 * Splits a command line into words the way a POSIX shell would quote them: single quotes literal, double quotes and
 * backslash escapes honoured; unquoted `; | & ( )` end a word. `$(...)` and backticks are kept as text and mark the
 * word live. Returns null for anything it can't balance (open quote, open `$(`, trailing backslash).
 */
function shellWords(s: string): ShellWord[] | null {
  const words: ShellWord[] = [];
  let text = "";
  let live = false;
  let inWord = false;
  const end = () => {
    if (inWord) words.push({ text, live });
    text = "";
    live = false;
    inWord = false;
  };
  /** From s[j] just past "$(", returns the index just past the matching ")", or -1. Quotes inside are skipped whole. */
  const closeParen = (j: number): number => {
    let d = 1;
    while (j < s.length) {
      const ch = s[j]!;
      if (ch === "\\") j += 2;
      else if (ch === "'") {
        const k = s.indexOf("'", j + 1);
        if (k < 0) return -1;
        j = k + 1;
      } else if (ch === '"') {
        j++;
        while (j < s.length && s[j] !== '"') j += s[j] === "\\" ? 2 : 1;
        if (j >= s.length) return -1;
        j++;
      } else if (ch === "`") {
        const k = closeTick(j + 1);
        if (k < 0) return -1;
        j = k;
      } else {
        if (ch === "(") d++;
        else if (ch === ")" && --d === 0) return j + 1;
        j++;
      }
    }
    return -1;
  };
  /** From s[j] just past "`", returns the index just past the closing backtick, or -1. */
  const closeTick = (j: number): number => {
    while (j < s.length) {
      if (s[j] === "\\") j += 2;
      else if (s[j] === "`") return j + 1;
      else j++;
    }
    return -1;
  };
  /** A substitution starting at s[j] ("$(" or "`"): appends it to the word, returns the index past it, or -1. */
  const subst = (j: number): number => {
    const k = s[j] === "`" ? closeTick(j + 1) : closeParen(j + 2);
    if (k < 0) return -1;
    text += s.slice(j, k);
    live = true;
    return k;
  };
  let i = 0;
  while (i < s.length) {
    const ch = s[i]!;
    if (/\s/.test(ch)) {
      end();
      i++;
    } else if (";|&()".includes(ch)) {
      if (ch === "(" && inWord) return null; // A=(s1 s2): an array assignment, or a function definition
      end();
      i++;
    } else if (ch === "\\") {
      if (i + 1 >= s.length) return null;
      if (s[i + 1] !== "\n") {
        text += s[i + 1]!;
        inWord = true;
      }
      i += 2;
    } else if (ch === "'") {
      const k = s.indexOf("'", i + 1);
      if (k < 0) return null;
      text += s.slice(i + 1, k);
      inWord = true;
      i = k + 1;
    } else if (ch === "$" && s[i + 1] === "'") {
      // $'...' can spell any byte with escapes: kept as text, marked live so it is never taken as the program
      let j = i + 2;
      while (j < s.length && s[j] !== "'") j += s[j] === "\\" ? 2 : 1;
      if (j >= s.length) return null;
      text += s.slice(i + 2, j);
      live = inWord = true;
      i = j + 1;
    } else if ((ch === "$" && s[i + 1] === "(") || ch === "`") {
      inWord = true;
      i = subst(i);
      if (i < 0) return null;
    } else if (ch === '"') {
      inWord = true;
      i++;
      for (;;) {
        if (i >= s.length) return null;
        const c = s[i]!;
        if (c === '"') {
          i++;
          break;
        }
        if (c === "\\") {
          if (i + 1 >= s.length) return null;
          const n = s[i + 1]!;
          if (n !== "\n") text += "$`\"\\".includes(n) ? n : c + n;
          i += 2;
        } else if ((c === "$" && s[i + 1] === "(") || c === "`") {
          i = subst(i);
          if (i < 0) return null;
        } else {
          text += c;
          i++;
        }
      }
    } else {
      text += ch;
      inWord = true;
      i++;
    }
  }
  end();
  return words;
}

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * A best-effort label for what a command line runs, not an authoritative identity. Splits the line into shell words
 * (quotes and escapes honoured, nothing expanded), skips VAR=value assignments and the WRAPPERS with their options;
 * `bash -c '<cmd>'` and `env -S` give the program inside. Pipelines, `;`, `&&`, subshells and aliases are not
 * followed: `a | b` is labelled `a`. Fails closed to [COMMAND]: on quotes it can't balance, on a command substitution
 * or `$'...'` at or before the program word, and on a label that holds whitespace, `=` or `$` (so a quoted secret
 * or an unexpanded variable is never the label). Process telemetry (Falco, auditd) remains the source of truth for
 * what actually ran.
 */
export function programOf(command: string, depth = 0): string {
  const words = shellWords(command);
  if (!words) return "[COMMAND]";
  /** Recurse on the text of one word (bash -c, env -S), unless a word before it is live; the inner parse judges its own. */
  const inner = (text: string, upto: number): string =>
    depth < 3 && !words.slice(0, upto).some((x) => x.live) ? programOf(text, depth + 1) : "[COMMAND]";
  let i = 0;
  while (i < words.length && ASSIGNMENT.test(words[i]!.text)) i++;
  while (i < words.length) {
    const w = basename(words[i]!.text);
    const opts = Object.hasOwn(WRAPPERS, w) ? WRAPPERS[w] : undefined; // not "constructor" etc. from the prototype
    if (opts) {
      i++;
      while (i < words.length && words[i]!.text.startsWith("-")) {
        const o = words[i]!.text;
        if (o === "--") {
          i++;
          break;
        }
        // the option's value: "-u root" / "--user root" -> the next word, "-uroot" / "--user=root" -> attached,
        // grouped short options "-Eu root" / "-Euroot" -> the first letter that takes a value
        let name = o;
        let value: string | undefined;
        let next = false;
        if (o.startsWith("--")) {
          const eq = o.indexOf("=");
          if (eq > 0) [name, value] = [o.slice(0, eq), o.slice(eq + 1)];
          else next = opts.has(o);
        } else {
          for (let k = 1; k < o.length; k++) {
            if (!opts.has(`-${o[k]}`)) continue;
            name = `-${o[k]}`;
            if (k + 1 < o.length) value = o.slice(k + 1);
            else next = true;
            break;
          }
        }
        if (w === "env" && (name === "-S" || name === "--split-string")) {
          if (value !== undefined) return inner(value, i);
          if (next && i + 1 < words.length) return inner(words[i + 1]!.text, i + 1);
          return "[COMMAND]";
        }
        i += next ? 2 : 1;
      }
      if (w === "env" || w === "sudo" || w === "doas") while (i < words.length && ASSIGNMENT.test(words[i]!.text)) i++;
      if (w === "timeout") i++; // the duration
      continue;
    }
    if (SHELLS.has(w) && depth < 3) {
      const c = words.findIndex((x, j) => j > i && /^-[a-z]*c[a-z]*$/.test(x.text));
      if (c > 0 && c + 1 < words.length) return inner(words[c + 1]!.text, c + 1);
    }
    if (words.slice(0, i + 1).some((x) => x.live)) return "[COMMAND]";
    if (/[<>]/.test(words[i]!.text)) return "[COMMAND]"; // <file cmd, 2>log cmd: the file is no label
    return w && !/[\s=$]/.test(w) ? w : "[COMMAND]";
  }
  return "[COMMAND]";
}

/**
 * The hash key, refused unless it is what hib made: a regular file (not a symlink: opened with O_NOFOLLOW), owned by
 * this user, no access for group or others, holding exactly 32 bytes as hex. Someone who could swap it could make the
 * hashes of every folder known to them. Opened with O_NONBLOCK so a named pipe put there fails the regular-file check
 * instead of blocking the open (and the daemon with it); nothing is read before the checks pass, and never more than
 * the 65 bytes a key file can hold.
 */
/** Why the key was refused, as a fixed code: the events.key_refused event carries only this, never the path. */
export type KeyRefusal = "symlink" | "not_regular" | "not_owner" | "mode" | "format" | "unreadable";
export class KeyRefused extends Error {
  constructor(readonly file: string, readonly reason: KeyRefusal, detail: string) {
    super(`${file}: ${detail}`);
  }
}

export function readKey(file: string): Buffer {
  let fd: number;
  try {
    fd = openSync(file, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0));
  } catch (e: any) {
    if (e?.code === "ELOOP") throw new KeyRefused(file, "symlink", "is a symlink");
    throw new KeyRefused(file, "unreadable", e?.message ?? String(e));
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new KeyRefused(file, "not_regular", "not a regular file");
    if (process.getuid && st.uid !== process.getuid()) throw new KeyRefused(file, "not_owner", "not owned by this user");
    if (st.mode & 0o077) throw new KeyRefused(file, "mode", "group or others can access it (chmod 600)");
    if (st.size > 65) throw new KeyRefused(file, "format", "not a 32-byte hex key");
    const text = readFileSync(fd, "utf8"); // grown since the fstat: the length check below still refuses it
    if (text.length > 65 || !/^[0-9a-f]{64}\n?$/.test(text)) throw new KeyRefused(file, "format", "not a 32-byte hex key");
    return Buffer.from(text.trim(), "hex");
  } finally {
    closeSync(fd);
  }
}

export type { EventsConfig };

export type Mode = "router" | "workspace" | "daemon";
export type Severity = "info" | "warning" | "critical";

/** Fields every event may carry; optional ones are left out when unknown, never null. */
export interface Context {
  mode: Mode;
  session_id?: string;
  run_id?: string;
  workspace?: string;
  account?: string;
  model?: string;
  route?: string;
}

const FIXED: Record<string, Severity> = {
  "daemon.start": "info",
  "daemon.stop": "info",
  "auth.failure": "warning",
  "approval.pending": "info",
  "data.block": "warning",
  "events.key_refused": "warning",
  "sandbox.unavailable": "warning",
  "protected.reverted": "critical",
  "terminal.open": "warning",
  "session.start": "info",
  "session.end": "info",
};

/** Fixed per type; the three types with a decision are a warning when it went against the request. */
export function severityOf(event: string, f: Record<string, unknown>): Severity {
  if (event === "guard.decision") return f.action === "rejected" || f.action === "timeout" ? "warning" : "info";
  if (event === "tool.permission" || event === "sandbox.network") return f.decision === "deny" ? "warning" : "info";
  return FIXED[event] ?? "info";
}

function version(): string {
  try {
    const pkg = require("../package.json") as { version?: string };
    if (pkg.version) return pkg.version;
  } catch {}
  const git = Bun.spawnSync(["git", "-C", import.meta.dir, "rev-parse", "--short", "HEAD"], { stdout: "pipe", stderr: "ignore" });
  return git.success ? `0.0.0+${git.stdout.toString().trim()}` : "0.0.0";
}

export class EventLog {
  readonly file: string;
  private size = -1;
  private readonly host = hostname();
  private readonly version = version();
  private readonly identities = machineTerms();
  private heartbeat?: ReturnType<typeof setInterval>;
  private stopHooks: (() => void)[] = [];
  private stopped = false;
  private key?: Buffer;
  private auth = new Map<string, { last: number; suppressed: number; path: string; remote?: string; timer?: ReturnType<typeof setTimeout> }>();

  constructor(
    readonly cfg: EventsConfig,
    private guard: { terms: string[]; patterns: { category: string; regex: string; flags?: string }[] } = { terms: [], patterns: [] },
    private now: () => Date = () => new Date(),
  ) {
    this.file = join(cfg.dir, "events.jsonl");
  }

  /**
   * User-controlled text, made safe to log (command, url, reasons): secrets and identifiers (the guard at `standard`,
   * plus the event log's own patterns) become [CATEGORY], then it's cut to 300 chars.
   */
  redact(text: string): string {
    return this.clean(text, "standard");
  }

  /** Secrets only, for fields that should stay readable otherwise (a host name, a tool name, a relative path). */
  scrub(text: string): string {
    return this.clean(text, "minimal");
  }

  private clean(raw: string, level: "minimal" | "standard"): string {
    const text = sanitize(raw.length > SCAN_MAX ? raw.slice(0, SCAN_MAX) : raw);
    const found: Span[] = detect(text, { level, terms: this.guard.terms, patterns: this.guard.patterns, identities: level === "minimal" ? [] : this.identities });
    const out = replaceSpans(text, [...found, ...extraSpans(text)]);
    return out.length > TEXT_MAX ? out.slice(0, TEXT_MAX) + "…" : out;
  }

  /** A path inside the workspace, relative to it; outside it, redacted like any other text. Either way, no secrets. */
  path(p: string, workspace?: string): string {
    if (workspace && isAbsolute(p)) {
      const rel = relative(workspace, p);
      if (rel && !rel.startsWith("..") && !isAbsolute(rel)) return this.scrub(rel);
    }
    return workspace && !isAbsolute(p) ? this.scrub(p) : this.redact(p);
  }

  /**
   * A keyed hash (HMAC-SHA256, 16 hex): the same value gives the same hash on this machine, so events still correlate,
   * but a known path can't be hashed by anyone without the key to check a guess. The key is made on first use, 0600,
   * in hib's home, never next to the events.
   */
  hash(value: string): string {
    if (!this.key) {
      const file = this.cfg.keyFile;
      if (!file) this.key = randomBytes(32); // no home to keep it in (tests): hashes hold for this process only
      else {
        if (!existsSync(file)) {
          mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
          try {
            writeFileSync(file, randomBytes(32).toString("hex") + "\n", { mode: 0o600, flag: "wx" });
          } catch (e: any) {
            if (e?.code !== "EEXIST") throw e; // another process made it first: use theirs
          }
        }
        try {
          this.key = readKey(file);
        } catch (e) {
          this.keyRefused(e);
          throw e;
        }
      }
    }
    return createHmac("sha256", this.key).update(value).digest("hex").slice(0, 16);
  }

  /**
   * The lines that need a hash are dropped while the key is refused, and nothing else in the log would show it: say so
   * once per run, in a line that has nothing to hash. Only the fixed reason, never the path.
   */
  private refusalReported = false;
  private keyRefused(e: unknown): void {
    if (this.refusalReported) return;
    this.refusalReported = true;
    this.emit("events.key_refused", { mode: "daemon" }, { reason: e instanceof KeyRefused ? e.reason : "unreadable" });
  }

  /** At daemon start: when a setting hashes, load (or make) the key now, so a refused key shows before the first session. */
  checkKey(): void {
    if (this.cfg.workspace !== "hash" && this.cfg.account !== "hash") return;
    try {
      this.hash("");
    } catch (e: any) {
      console.error(`hib: events: hash key refused: ${e?.message ?? e}`);
    }
  }

  /** The [events] coarsening settings applied to the context and to the fields they name. */
  private coarsen(ctx: Context, fields: Record<string, unknown>): [Context, Record<string, unknown>] {
    const c = this.cfg;
    ctx = { ...ctx };
    if (ctx.workspace && c.workspace === "name") ctx.workspace = basename(ctx.workspace) || ctx.workspace;
    if (ctx.workspace && c.workspace === "hash") ctx.workspace = this.hash(ctx.workspace);
    if (ctx.account && c.account === "hash") {
      const at = ctx.account.indexOf("@");
      ctx.account = at > 0 ? `${ctx.account.slice(0, at)}@${this.hash(ctx.account.slice(at + 1))}` : this.hash(ctx.account);
    }
    fields = { ...fields };
    if (c.netHost === "domain") {
      if (typeof fields.net_host === "string") fields.net_host = domainOf(fields.net_host);
      if (typeof fields.url === "string") fields.url = urlDomain(fields.url);
    }
    if (c.command === "program" && typeof fields.command === "string") fields.command = programOf(fields.command);
    if (c.remote === false) delete fields.remote;
    return [ctx, fields];
  }

  /** Every string a caller passed, at any depth, scrubbed unless hib wrote it itself (OWN_FIELDS). */
  private safe(value: unknown, key: string): unknown {
    if (typeof value === "string") return OWN_FIELDS.has(key) ? value.toWellFormed() : this.scrub(value);
    if (Array.isArray(value)) return value.map((v) => this.safe(v, key));
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, this.safe(v, k)]));
    return value;
  }

  emit(event: string, ctx: Context, fields: Record<string, unknown> = {}): void {
    if (!this.cfg.enabled || this.stopped) return; // daemon.stop stays the last line
    try {
      [ctx, fields] = this.coarsen(ctx, fields);
    } catch (e: any) {
      // No key for the hashes (unreadable file): drop the line rather than write the field whole, and don't throw.
      console.error(`hib: event ${event} not written: ${e?.message ?? e}`);
      return;
    }
    const line: Record<string, unknown> = {
      ts: this.now().toISOString(),
      schema: SCHEMA,
      source: "hib",
      host: this.host,
      hib_version: this.version,
      event,
      severity: severityOf(event, fields),
      mode: ctx.mode,
    };
    for (const k of ["session_id", "run_id", "workspace", "account", "model", "route"] as const) if (ctx[k] !== undefined && ctx[k] !== "") line[k] = ctx[k]!.toWellFormed();
    for (const [k, v] of Object.entries(fields)) if (v !== undefined && v !== null) line[k] = this.safe(v, k);
    try {
      this.write(JSON.stringify(line) + "\n");
    } catch (e: any) {
      // The event log must never take a request down with it.
      console.error(`hib: could not write ${this.file}: ${e?.message ?? e}`);
    }
  }

  /** A rejected request. One line per reason and remote per 60 s; failures in between are counted on the next line. */
  authFailure(reason: "token" | "host" | "origin", path: string, remote: string | undefined): void {
    const key = `${reason}|${remote ?? ""}`;
    const t = Date.now();
    const s = this.auth.get(key);
    if (s && t - s.last < AUTH_WINDOW_MS) {
      s.suppressed++;
      // Flush the count when the window closes, so a burst that stops is still reported in full.
      s.timer ??= setTimeout(() => this.flushAuth(key), AUTH_WINDOW_MS - (t - s.last));
      (s.timer as any).unref?.();
      return;
    }
    this.auth.set(key, { last: t, suppressed: 0, path, remote });
    this.emit("auth.failure", { mode: "daemon" }, { reason, path: this.redact(path), ...(remote ? { remote } : {}), count: 1 });
  }

  /** Writes the failures counted but not yet logged: one window (`key`), or all of them. */
  flushAuth(key?: string): void {
    for (const [k, s] of key ? [[key, this.auth.get(key)] as const] : [...this.auth]) {
      if (!s) continue;
      clearTimeout(s.timer);
      s.timer = undefined;
      if (!s.suppressed) continue;
      const reason = k.slice(0, k.indexOf("|"));
      this.emit("auth.failure", { mode: "daemon" }, { reason, path: this.redact(s.path), ...(s.remote ? { remote: s.remote } : {}), count: s.suppressed });
      this.auth.set(k, { last: Date.now(), suppressed: 0, path: s.path, remote: s.remote });
    }
  }

  /**
   * daemon.alive every `heartbeatSec` (0: off), the first one a full interval after daemon.start. A collector that saw
   * heartbeats, then none and no daemon.stop, knows the daemon died (a crash or SIGKILL writes nothing).
   */
  startHeartbeat(): void {
    if (!this.cfg.enabled || !(this.cfg.heartbeatSec > 0) || this.heartbeat) return;
    const started = Date.now();
    this.heartbeat = setInterval(() => this.emit("daemon.alive", { mode: "daemon" }, { uptime_sec: Math.round((Date.now() - started) / 1000) }), this.cfg.heartbeatSec * 1000);
    (this.heartbeat as any).unref?.(); // the server keeps the daemon alive, not the heartbeat
  }

  /** Work that writes its own last events (agent sessions ending) and must run before daemon.stop. */
  onStop(fn: () => void): void {
    this.stopHooks.push(fn);
  }

  /**
   * A clean stop, once: sessions end, counted auth failures are written (a burst that ends with a restart isn't lost),
   * then daemon.stop, the last line. Anything emitted after it is dropped.
   */
  stop(fields: Record<string, unknown> = {}): void {
    if (this.stopped) return;
    clearInterval(this.heartbeat);
    for (const fn of this.stopHooks) {
      try {
        fn();
      } catch {}
    }
    this.flushAuth();
    this.emit("daemon.stop", { mode: "daemon" }, fields);
    this.stopped = true;
  }

  private write(line: string) {
    if (this.size < 0) {
      mkdirSync(this.cfg.dir, { recursive: true, mode: 0o700 });
      chmodSync(this.cfg.dir, 0o700);
      this.size = existsSync(this.file) ? statSync(this.file).size : 0;
    }
    const bytes = Buffer.byteLength(line);
    if (this.size > 0 && this.size + bytes > this.cfg.maxMb * 1024 * 1024) this.rotate();
    const fresh = this.size === 0 && !existsSync(this.file);
    appendFileSync(this.file, line, { mode: 0o600 }); // one write per event; nothing buffered in the process
    if (fresh) chmodSync(this.file, 0o600);
    this.size += bytes;
  }

  /** events.jsonl -> .1, .1 -> .2 … up to `keep`; the oldest goes. */
  private rotate() {
    const keep = Math.max(0, Math.floor(this.cfg.keep));
    if (keep === 0) rmSync(this.file, { force: true });
    else {
      rmSync(`${this.file}.${keep}`, { force: true });
      for (let i = keep - 1; i >= 1; i--) if (existsSync(`${this.file}.${i}`)) renameSync(`${this.file}.${i}`, `${this.file}.${i + 1}`);
      renameSync(this.file, `${this.file}.1`);
    }
    this.size = 0;
  }
}

/** For code paths without a configured log (tests, one-off commands). */
export const noEvents = () => new EventLog({ enabled: false, dir: "", maxMb: 20, keep: 5, heartbeatSec: 0 });
