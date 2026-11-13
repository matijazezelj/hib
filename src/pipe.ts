import { guardLine, guardRecord, type GuardState, type RecordPolicy } from "./guard/record";
import { StreamRestorer } from "./guard/restore";
import type { Vault } from "./guard/vault";

// TODO (not in scope yet): name detection (NER, ~80 ms/event), HTTP ingest, syslog/grok parsing, vault TTL/rotation.

export interface PipeOptions {
  format: "auto" | "ndjson" | "text";
  onError: "drop" | "redact" | "fail";
  saveEvery: number;
}

export interface PipeStats {
  lines: number; // input lines, blank ones included
  records: number; // JSON lines guarded field by field
  text: number; // lines guarded as plain text
  dropped: number;
  redacted: number;
  tokens: number; // tokens in the vault at the end
  ms: number;
}

export const REDACTED_JSON = '{"hib_redacted":true}';
export const REDACTED_TEXT = "[HIB-REDACTED-LINE]";

const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** Splits a byte stream into lines, decoding UTF-8 across chunk boundaries. The last line needs no trailing "\n". */
async function* lines(input: ReadableStream<Uint8Array>): AsyncGenerator<string[]> {
  const decoder = new TextDecoder("utf-8", { fatal: false });
  let tail = "";
  // TODO: a single line with no newline is buffered whole; a cap (fail closed past N MB) would bound memory.
  for await (const chunk of input) {
    const text = tail + decoder.decode(chunk, { stream: true });
    const parts = text.split("\n");
    tail = parts.pop()!;
    if (parts.length) yield parts;
  }
  const last = tail + decoder.decode();
  if (last) yield [last];
}

/**
 * The filter: one line in, one guarded line out (or none, when a line that can't be guarded is dropped), in order.
 * The original text of a line that fails is never written anywhere, error messages included.
 */
export async function runPipe(
  input: ReadableStream<Uint8Array>,
  write: (s: string) => void | Promise<void>,
  state: GuardState,
  policy: RecordPolicy,
  opts: PipeOptions,
  save?: () => Promise<void>,
): Promise<PipeStats> {
  const t0 = performance.now();
  const stats: PipeStats = { lines: 0, records: 0, text: 0, dropped: 0, redacted: 0, tokens: 0, ms: 0 };
  const every = Math.max(1, Math.floor(opts.saveEvery) || 1);
  let out = "";
  const flush = async () => {
    if (!out) return;
    const s = out;
    out = "";
    await write(s);
  };

  /** The guarded line, or null to drop it. Throws only with onError "fail". */
  const guard = (raw: string): string | null => {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (!line.trim()) return line;
    let json = false;
    try {
      if (opts.format !== "text") {
        const first = line.trimStart()[0];
        let parsed: unknown;
        let ok = false;
        if (opts.format === "ndjson" || first === "{") {
          try {
            parsed = JSON.parse(line);
            ok = true;
          } catch {
            if (opts.format === "ndjson") {
              json = true;
              throw new Error("not JSON");
            }
          }
        }
        if (ok && (opts.format === "ndjson" || isObject(parsed))) {
          json = true;
          const r = guardRecord(parsed, state, policy);
          stats.records++;
          return JSON.stringify(r.record);
        }
      }
      const r = guardLine(line, state, policy);
      stats.text++;
      return r.text;
    } catch (e) {
      if (opts.onError === "fail") {
        // Only the error's name/kind: messages (a JSON parse error, a guard error) can quote the line itself.
        const why = e instanceof Error && e.message === "not JSON" ? "not JSON" : e instanceof Error ? e.name : "error";
        throw new Error(`line ${stats.lines} could not be guarded (${why})`);
      }
      if (opts.onError === "drop") {
        stats.dropped++;
        return null;
      }
      stats.redacted++;
      return json || opts.format === "ndjson" ? REDACTED_JSON : REDACTED_TEXT;
    }
  };

  try {
    for await (const batch of lines(input)) {
      for (const raw of batch) {
        stats.lines++;
        const g = guard(raw);
        if (g !== null) out += g + "\n";
        if (save && stats.lines % every === 0) {
          // Tokens written since the last save can't be restored if the process dies before this one; saveEvery bounds that.
          await flush();
          await save();
        }
      }
      await flush();
    }
  } catch (e) {
    await flush().catch(() => {});
    if (save) await save();
    throw e;
  }
  await flush();
  if (save) await save();
  stats.tokens = state.vault.size;
  stats.ms = Math.round(performance.now() - t0);
  return stats;
}

/** Tokens back to real values, written through as the input arrives; a token split across chunks is held until complete. */
export async function runRestore(input: ReadableStream<Uint8Array>, write: (s: string) => void | Promise<void>, vault: Vault): Promise<void> {
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const restorer = new StreamRestorer(vault);
  for await (const chunk of input) {
    const s = restorer.push(decoder.decode(chunk, { stream: true }));
    if (s) await write(s);
  }
  const s = restorer.push(decoder.decode()) + restorer.flush();
  if (s) await write(s);
}

export function formatStats(s: PipeStats, vault: string): string {
  const rate = s.ms > 0 ? Math.round((s.lines / s.ms) * 1000) : s.lines;
  return `hib pipe: ${s.lines} lines (${s.records} JSON, ${s.text} text), ${s.redacted} redacted, ${s.dropped} dropped; vault ${vault}: ${s.tokens} tokens; ${s.ms} ms (${rate}/s)`;
}
