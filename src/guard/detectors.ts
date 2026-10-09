// Ported from ../sib/analysis/obfuscator.py (TruffleHog-derived patterns), adapted for code-heavy prompts.

export type Level = "minimal" | "standard" | "paranoid";
type Kind = "secret" | "pii" | "infra" | "term";

export interface Finding {
  start: number;
  end: number;
  value: string;
  category: string; // token label, e.g. AWS-KEY, IP-INTERNAL, USER
  kind: Kind;
}

interface Detector {
  category: string;
  kind: Kind;
  re: RegExp;
  group?: number; // capture group holding the sensitive part (default: whole match)
  keep?: (value: string) => boolean; // return true to leave the value visible
  label?: (value: string) => string; // per-value category override
  path?: boolean; // filesystem-path detector, skipped with keepPaths
}

const secret = (category: string, re: RegExp, group?: number): Detector => ({ category, kind: "secret", re, group });

// Most specific first; overlaps resolve to the earliest detector.
const SECRETS: Detector[] = [
  secret("PRIVATE-KEY", /-----BEGIN[A-Z ]*PRIVATE KEY( BLOCK)?-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY( BLOCK)?-----/g),
  secret("PRIVATE-KEY", /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/g),
  secret("AWS-KEY", /\b(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}\b/g),
  secret("AWS-SESSION", /\b(?:FwoGZXIvYXdzE|IQoJb3JpZ2lu)[A-Za-z0-9/+=]+/g),
  secret("AWS-MWS", /\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g),
  secret("GCP-SERVICE-ACCOUNT", /\b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b/g),
  secret("GOOGLE-API", /\bAIza[0-9A-Za-z\-_]{35}\b/g),
  secret("GOOGLE-OAUTH", /\b[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com\b/g),
  secret("GOOGLE-SECRET", /\bGOCSPX-[A-Za-z0-9\-_]{28}\b/gi),
  secret("AZURE-STORAGE", /\b[A-Za-z0-9+/]{86}==/g),
  secret("AZURE-SAS", /\bsig=[A-Za-z0-9%]+&se=[0-9]+&[A-Za-z0-9&=%]+/g),
  secret("GITHUB-TOKEN", /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/g),
  secret("GITHUB-TOKEN", /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g),
  secret("GITLAB-TOKEN", /\bglpat-[A-Za-z0-9\-_]{20,}/g),
  secret("GITLAB-PIPELINE", /\bglptt-[A-Za-z0-9]{40}\b/g),
  secret("GITLAB-RUNNER", /\bGR1348941[A-Za-z0-9\-_]{20,}/g),
  secret("SLACK-TOKEN", /\bxox[bpas]-[0-9A-Za-z-]{20,}/g),
  secret("SLACK-APP", /\bxapp-[0-9]-[A-Z0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{64}\b/g),
  secret("SLACK-WEBHOOK", /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/g),
  secret("DISCORD-BOT", /\b(?:MTA|MTE|MTI|OT|Nj|Nz|OD)[A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b/g),
  secret("DISCORD-WEBHOOK", /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g),
  secret("TELEGRAM-BOT", /\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b/g),
  secret("STRIPE-SECRET", /\b(?:sk|rk)_(?:test|live)_[A-Za-z0-9]{24,}\b/g),
  secret("STRIPE-KEY", /\bpk_(?:test|live)_[A-Za-z0-9]{24,}\b/g),
  secret("TWILIO-KEY", /\bSK[a-f0-9]{32}\b/g),
  secret("TWILIO-SID", /\bAC[a-f0-9]{32}\b/g),
  secret("SENDGRID-KEY", /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/g),
  secret("MAILCHIMP-KEY", /\b[a-f0-9]{32}-us[0-9]{1,2}\b/g),
  secret("MAILGUN-KEY", /\bkey-[A-Za-z0-9]{32}\b/g),
  secret("NPM-TOKEN", /\bnpm_[A-Za-z0-9]{36}\b/g),
  secret("PYPI-TOKEN", /\bpypi-[A-Za-z0-9\-_]{50,}/g),
  secret("NUGET-KEY", /\boy2[a-z0-9]{43}\b/g),
  secret("DO-TOKEN", /\bdo[por]_v1_[a-f0-9]{64}\b/g),
  secret("CLOUDFLARE-CA", /\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b/g),
  secret("ANTHROPIC-KEY", /\bsk-ant-[A-Za-z0-9\-_]{20,}/g),
  secret("OPENAI-KEY", /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9\-_]{32,}/g),
  secret("SENTRY-DSN", /https:\/\/[a-f0-9]{32}@[a-z0-9.]+\.ingest\.(?:[a-z]+\.)?sentry\.io\/[0-9]+/g),
  secret("DB-URI", /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^\s:/@]+:[^\s@]+@[^\s/"'`]+(?:\/[^\s"'`]*)?/g),
  secret("JWT", /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_.+/-]*/g),
  secret("BASIC-AUTH", /\bBasic\s+([A-Za-z0-9+/]{8,}={0,2})/g, 1),
  secret("BEARER-TOKEN", /\bBearer\s+([A-Za-z0-9\-_.~+/]{16,}=*)/g, 1),
  // Assignments like `password: "..."`, `API_KEY=...`. Replaces sib's context-free cloudflare/pagerduty/heroku
  // patterns, which matched ordinary identifiers and UUIDs.
  secret(
    "SECRET",
    /(?:password|passwd|pwd|secret|secret[_-]?key|api[_-]?key|apikey|access[_-]?key|auth[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key|encryption[_-]?key|client[_-]?secret|token)["']?\s*[=:]\s*["']?([^\s"'`,;]{8,})/gi,
    1,
  ),
  secret("SSH-PUBLIC-KEY", /\bssh-(?:rsa|dss|ed25519|ecdsa)\s+[A-Za-z0-9+/]{40,}={0,2}/g),
];

const PRIVATE_RANGES: [number, number][] = [
  [0x0a000000, 0x0affffff],
  [0xac100000, 0xac1fffff],
  [0xc0a80000, 0xc0a8ffff],
  [0x7f000000, 0x7fffffff],
];

export function isPrivateIp(ip: string): boolean {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !(n >= 0 && n <= 255))) return false;
  const n = ((p[0]! << 24) >>> 0) + (p[1]! << 16) + (p[2]! << 8) + p[3]!;
  return PRIVATE_RANGES.some(([a, b]) => n >= a && n <= b);
}

const SYSTEM_USERS = new Set(["root", "nobody", "daemon", "www-data", "nginx", "postgres", "mysql", "redis", "node", "ubuntu", "admin"]);
const LOCAL_IPS = new Set(["127.0.0.1", "0.0.0.0", "255.255.255.255"]);

const STANDARD: Detector[] = [
  {
    category: "IP",
    kind: "infra",
    re: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    keep: (v) => LOCAL_IPS.has(v),
    label: (v) => (isPrivateIp(v) ? "IP-INTERNAL" : "IP-EXTERNAL"),
  },
  { category: "IP-EXTERNAL", kind: "infra", re: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g },
  { category: "EMAIL", kind: "pii", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, keep: (v) => /@(example\.(com|org)|users\.noreply\.github\.com)$/i.test(v) || v.startsWith("noreply@") },
  { category: "USER", kind: "pii", path: true, re: /\/(?:Users|home)\/([A-Za-z0-9._-]+)/g, group: 1, keep: (v) => v === "Shared" || SYSTEM_USERS.has(v) },
  { category: "USER", kind: "pii", re: /\b(?:user|username|login|uid)=["']?([A-Za-z0-9._-]+)/gi, group: 1, keep: (v) => SYSTEM_USERS.has(v.toLowerCase()) },
  { category: "USER", kind: "pii", re: /\bby user ([A-Za-z0-9._-]+)/gi, group: 1, keep: (v) => SYSTEM_USERS.has(v.toLowerCase()) },
];

// Hostnames are limited to known TLDs so `obj.method`, `file.ts` and version numbers survive.
const TLDS = "com|net|org|io|dev|app|ai|co|cloud|tech|xyz|me|info|biz|us|uk|de|eu|hr|si|rs|at|ch|fr|nl|internal|local|lan|corp|intra|intranet|private|home|localdomain";
const PARANOID: Detector[] = [
  {
    category: "HOST",
    kind: "infra",
    re: new RegExp(`\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+(?:${TLDS})\\b(?![.(\\w])`, "gi"),
    keep: (v) => /^(localhost|example\.(com|org|net))$/i.test(v),
  },
  { category: "CONTAINER", kind: "infra", re: /\b[a-f0-9]{64}\b|\b[a-f0-9]{12}\b/g },
  { category: "PATH", kind: "pii", path: true, re: /(?:~|\/(?:Users|home|var|opt|srv|mnt|Volumes))\/[\w.@/-]+/g },
];

function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function highEntropy(text: string): Finding[] {
  const out: Finding[] = [];
  for (const m of text.matchAll(/[A-Za-z0-9+/=_-]{24,}/g)) {
    const v = m[0];
    const mixed = /[a-z]/.test(v) && /[A-Z]/.test(v) && /[0-9]/.test(v);
    if (mixed && entropy(v) > 4.5) out.push({ start: m.index!, end: m.index! + v.length, value: v, category: "HIGH-ENTROPY", kind: "secret" });
  }
  return out;
}

function escapeRe(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function run(text: string, d: Detector): Finding[] {
  const out: Finding[] = [];
  d.re.lastIndex = 0;
  for (const m of text.matchAll(d.re)) {
    const g = d.group ?? 0;
    const value = m[g];
    if (!value) continue;
    if (d.keep?.(value)) continue;
    const start = m.index! + (g ? m[0].indexOf(value) : 0);
    out.push({ start, end: start + value.length, value, category: d.label?.(value) ?? d.category, kind: d.kind });
  }
  return out;
}

export interface DetectOptions {
  level: Level;
  terms?: string[]; // user-configured sensitive words: company, clients, repos, internal domains
  identities?: string[]; // this machine's username/hostname, tokenized as USER outside of paths too
  patterns?: { category: string; regex: string; flags?: string }[]; // from guard plugins; applied at every level
  keepPaths?: boolean; // agent mode: the CLI must open real paths, and its tool output reveals them anyway
  extra?: Finding[]; // precomputed findings for this exact text (local NER)
  exempt?: [number, number][]; // spans to leave exactly as they are (e.g. table columns the user chose to keep)
}

/** Non-overlapping findings, earlier detectors (secrets, then terms) winning ties. */
export function detect(text: string, opts: DetectOptions): Finding[] {
  const raw: Finding[] = [];
  for (const d of SECRETS) raw.push(...run(text, d));
  for (const t of opts.terms ?? []) {
    if (!t.trim()) continue;
    raw.push(...run(text, { category: "TERM", kind: "term", re: new RegExp(`(?<![\\w])${escapeRe(t)}(?![\\w])`, "gi") }));
  }
  for (const p of opts.patterns ?? []) {
    const flags = (p.flags ?? "").includes("g") ? p.flags! : (p.flags ?? "") + "g";
    raw.push(...run(text, { category: p.category, kind: "term", re: new RegExp(p.regex, flags) }));
  }
  if (opts.level !== "minimal")
    for (const t of opts.identities ?? [])
      raw.push(...run(text, { category: "USER", kind: "pii", re: new RegExp(`(?<![\\w])${escapeRe(t)}(?![\\w])`, "gi") }));
  const use = (d: Detector) => !(opts.keepPaths && d.path);
  if (opts.level !== "minimal") for (const d of STANDARD.filter(use)) raw.push(...run(text, d));
  if (opts.level === "paranoid") {
    for (const d of PARANOID.filter(use)) raw.push(...run(text, d));
    raw.push(...highEntropy(text));
  }
  // Local NER goes last: on an overlap the first finding wins, and a name found inside an email address or a path must
  // not displace the structured match (it would leave the rest of the address in the clear).
  raw.push(...(opts.extra ?? []));

  // Existing hib placeholders (e.g. from a pseudonymised table) are already safe; nothing inside them is a finding.
  const tokens = [...text.matchAll(/\[?HIB[0-9a-f]{4}-[A-Z0-9-]+?-\d+\]?/g)].map((m) => [m.index!, m.index! + m[0].length] as const);
  const taken: Finding[] = [];
  for (const f of raw) {
    if (tokens.some(([s, e]) => f.start < e && s < f.end)) continue;
    if (opts.exempt?.some(([s, e]) => f.start < e && s < f.end)) continue;
    if (taken.some((t) => f.start < t.end && t.start < f.end)) continue;
    taken.push(f);
  }
  return taken.sort((a, b) => a.start - b.start);
}

const LEVEL_ORDER: Level[] = ["minimal", "standard", "paranoid"];
/** The stricter of two guard levels; plugins may raise a route's level, never lower it. */
export function stricterLevel(a: Level | undefined, b: Level): Level {
  return a && LEVEL_ORDER.indexOf(a) > LEVEL_ORDER.indexOf(b) ? a : b;
}
