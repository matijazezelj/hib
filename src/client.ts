// Small HTTP client for the hib daemon, shared by the web UI, the TUI and `hib ask`.
import type { HibEvent } from "./engine";

async function fail(path: string, r: Response): Promise<never> {
  const body: any = await r.json().catch(() => null);
  throw new Error(body?.error?.message ?? `${path}: ${r.status}`);
}

async function* sseLines(r: Response): AsyncGenerator<any> {
  const reader = r.body!.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const block = buf.slice(0, i);
      buf = buf.slice(i + 2);
      for (const line of block.split("\n")) if (line.startsWith("data: ")) yield JSON.parse(line.slice(6));
    }
  }
}

export const BROWSER_SESSION = "hib_session";

export class HibClient {
  constructor(private base = "", private token?: string) {}

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "content-type": "application/json" };
    // In the browser: the session id from the login link. localStorage is per origin (port included), unlike cookies,
    // which 127.0.0.1 shares with every other local port.
    const token = this.token ?? (typeof localStorage !== "undefined" ? localStorage.getItem(BROWSER_SESSION) : null);
    if (token) h.authorization = `Bearer ${token}`;
    return h;
  }

  async get<T = any>(path: string): Promise<T> {
    const r = await fetch(this.base + path, { headers: this.headers(), credentials: "same-origin" });
    if (!r.ok) await fail(path, r);
    return r.json() as Promise<T>;
  }

  async post<T = any>(path: string, body: unknown, method = "POST"): Promise<T> {
    const r = await fetch(this.base + path, { method, headers: this.headers(), body: JSON.stringify(body), credentials: "same-origin" });
    if (!r.ok) await fail(path, r);
    return r.json() as Promise<T>;
  }

  del(path: string) {
    return this.post(path, {}, "DELETE");
  }

  async *chat(body: Record<string, unknown>, signal?: AbortSignal): AsyncGenerator<HibEvent> {
    const r = await fetch(this.base + "/hib/chat", { method: "POST", headers: this.headers(), body: JSON.stringify(body), signal, credentials: "same-origin" });
    if (!r.ok || !r.body) await fail("chat", r);
    yield* sseLines(r);
  }

  /** Follows a server-sent event stream (e.g. a workspace session) until aborted. */
  async *stream(path: string, signal?: AbortSignal): AsyncGenerator<any> {
    const r = await fetch(this.base + path, { headers: this.headers(), signal, credentials: "same-origin" });
    if (!r.ok || !r.body) await fail(path, r);
    yield* sseLines(r);
  }
}
