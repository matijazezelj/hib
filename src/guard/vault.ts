import { detect, type DetectOptions, type Finding } from "./detectors";

export interface VaultState {
  tag: string;
  entries: [string, string][]; // value -> token core
  counters: [string, number][];
  nets: [string, number][];
  aliases?: [string, string][]; // name key -> token core
}

/**
 * Reversible map between sensitive values and placeholder tokens, stable for one conversation.
 * The random tag keeps tokens from colliding with literal text. IPv4 tokens carry a NETn group so
 * the model can still tell which addresses share a /24.
 */
export class Vault {
  readonly tag: string;
  private toToken = new Map<string, string>();
  private toValue = new Map<string, string>();
  private counters = new Map<string, number>();
  private nets = new Map<string, number>();
  private aliases = new Map<string, string>();

  constructor(tag = crypto.getRandomValues(new Uint8Array(2)).reduce((s, b) => s + b.toString(16).padStart(2, "0"), "")) {
    this.tag = tag;
  }

  static from(state: VaultState): Vault {
    const v = new Vault(state.tag);
    for (const [value, core] of state.entries) {
      v.toToken.set(value, core);
      if (!v.toValue.has(core)) v.toValue.set(core, value); // the first form a token was made for; later forms are aliases
    }
    v.counters = new Map(state.counters);
    v.nets = new Map(state.nets);
    v.aliases = new Map(state.aliases ?? []);
    return v;
  }

  state(): VaultState {
    return { tag: this.tag, entries: [...this.toToken], counters: [...this.counters], nets: [...this.nets], aliases: [...this.aliases] };
  }

  /**
   * The token for a value. With a name `key`, every form of one name (`Ivana Babić`, `ivana_babic`, `IvanaBabic`) gets
   * the token the first form got; restoring it gives that first form back.
   */
  token(category: string, value: string, key?: string): string {
    const existing = this.toToken.get(value);
    if (existing) return existing;
    const alias = key ? this.aliases.get(key) : undefined;
    if (alias) {
      this.toToken.set(value, alias);
      return alias;
    }
    if (category.startsWith("IP-") && /^\d+\.\d+\.\d+\.\d+$/.test(value)) {
      const net = value.split(".").slice(0, 3).join(".");
      if (!this.nets.has(net)) this.nets.set(net, this.nets.size + 1);
      category = `${category}-NET${this.nets.get(net)}`;
    }
    const n = (this.counters.get(category) ?? 0) + 1;
    this.counters.set(category, n);
    const core = `HIB${this.tag}-${category}-${n}`;
    this.toToken.set(value, core);
    this.toValue.set(core, value);
    if (key) this.aliases.set(key, core);
    return core;
  }

  /** `text` with each finding's span replaced by its token. Findings must not overlap and be sorted by start. */
  replace(text: string, findings: Finding[]): string {
    let out = "";
    let pos = 0;
    for (const f of findings) {
      out += text.slice(pos, f.start) + `[${this.token(f.category, f.value, f.key)}]`;
      pos = f.end;
    }
    return out + text.slice(pos);
  }

  lookup(core: string): string | undefined {
    return this.toValue.get(core);
  }

  get size() {
    return this.toValue.size;
  }

  obfuscate(text: string, opts: DetectOptions): { text: string; findings: Finding[] } {
    const findings = detect(text, opts);
    return { text: this.replace(text, findings), findings };
  }

  /** Matches tokens with or without brackets, since models sometimes drop them. */
  tokenPattern(): RegExp {
    return new RegExp(`\\[?(HIB${this.tag}-[A-Z0-9-]+?-\\d+)\\]?`, "g");
  }

  restore(text: string): string {
    return text.replace(this.tokenPattern(), (m, core: string) => this.lookup(core) ?? m);
  }
}
