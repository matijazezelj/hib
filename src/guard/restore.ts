import type { Vault } from "./vault";

/**
 * Streaming de-obfuscation: holds back a chunk tail that could be the start of a token
 * split across chunks, and releases it once complete or proven not to be a token.
 */
export class StreamRestorer {
  private pending = "";
  constructor(private vault: Vault) {}

  push(chunk: string): string {
    const text = this.pending + chunk;
    const cut = this.holdFrom(text);
    this.pending = text.slice(cut);
    return this.vault.restore(text.slice(0, cut));
  }

  flush(): string {
    const out = this.vault.restore(this.pending);
    this.pending = "";
    return out;
  }

  private holdFrom(text: string): number {
    const prefix = `HIB${this.vault.tag}-`;
    const window = Math.max(0, text.length - 64);
    for (let i = window; i < text.length; i++) {
      const c = text[i];
      if (c !== "[" && c !== "H") continue;
      const rest = text.slice(i);
      const body = rest.startsWith("[") ? rest.slice(1) : rest;
      if (rest.includes("]")) continue;
      if (prefix.startsWith(body) || new RegExp(`^${prefix}[A-Z0-9-]*$`).test(body)) return i;
    }
    return text.length;
  }
}
