import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** AES-256-GCM for vault state at rest. The key lives in <home>/vault.key (0600) and never leaves the machine. */
export class Sealer {
  private constructor(private key: CryptoKey) {}

  static async open(home: string): Promise<Sealer> {
    const file = join(home, "vault.key");
    if (!existsSync(file)) {
      writeFileSync(file, Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64"), { mode: 0o600 });
      chmodSync(file, 0o600);
    }
    const raw = Buffer.from(readFileSync(file, "utf8").trim(), "base64");
    return new Sealer(await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]));
  }

  async seal(data: unknown): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, this.key, new TextEncoder().encode(JSON.stringify(data)));
    return `${Buffer.from(iv).toString("base64")}.${Buffer.from(ct).toString("base64")}`;
  }

  async unseal<T>(blob: string): Promise<T> {
    const [iv, ct] = blob.split(".");
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(iv!, "base64") }, this.key, Buffer.from(ct!, "base64"));
    return JSON.parse(new TextDecoder().decode(pt));
  }
}
