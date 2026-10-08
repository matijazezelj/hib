import type { Database } from "bun:sqlite";

// Weights for feedback signals; positive moves alpha, negative moves beta.
export const SIGNALS = {
  thumbsUp: 1,
  thumbsDown: -1,
  arenaWin: 1,
  arenaLoss: -1,
  advisorIssues: -0.5,
  retried: -0.5,
  error: -0.25,
  success: 0, // plain success says nothing about quality; usage alone shouldn't raise a score
} as const;

const DECAY = 0.995; // older evidence fades so routing keeps adapting

export class Learner {
  constructor(private db: Database) {}

  get(cls: string, model: string): { alpha: number; beta: number } {
    const r = this.db.query("SELECT alpha, beta FROM scores WHERE class = ? AND model = ?").get(cls, model) as any;
    return r ? { alpha: r.alpha, beta: r.beta } : { alpha: 1, beta: 1 };
  }

  record(cls: string, model: string, weight: number) {
    let { alpha, beta } = this.get(cls, model);
    alpha = 1 + (alpha - 1) * DECAY;
    beta = 1 + (beta - 1) * DECAY;
    if (weight >= 0) alpha += weight;
    else beta -= weight;
    this.db.run("INSERT OR REPLACE INTO scores(class, model, alpha, beta, updated) VALUES (?,?,?,?,?)", [cls, model, alpha, beta, Date.now()]);
  }

  /** Thompson sample; `prior` favours the route's preferred order before evidence accumulates. */
  sample(cls: string, model: string, prior = 0, rand = Math.random): number {
    const { alpha, beta } = this.get(cls, model);
    return sampleBeta(alpha + prior, beta, rand);
  }

  table(): { class: string; model: string; alpha: number; beta: number; mean: number }[] {
    return (this.db.query("SELECT class, model, alpha, beta FROM scores ORDER BY class, alpha / (alpha + beta) DESC").all() as any[]).map((r) => ({
      ...r,
      mean: r.alpha / (r.alpha + r.beta),
    }));
  }
}

function sampleGamma(k: number, rand: () => number): number {
  if (k < 1) return sampleGamma(k + 1, rand) * Math.pow(rand(), 1 / k);
  // Marsaglia–Tsang
  const d = k - 1 / 3;
  const c = 1 / Math.sqrt(9 * d);
  for (;;) {
    let x: number, v: number;
    do {
      const u1 = rand() || 1e-12;
      const u2 = rand();
      x = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
      v = 1 + c * x;
    } while (v <= 0);
    v = v * v * v;
    const u = rand();
    if (u < 1 - 0.0331 * x ** 4 || Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v;
  }
}

function sampleBeta(a: number, b: number, rand = Math.random): number {
  const x = sampleGamma(a, rand);
  return x / (x + sampleGamma(b, rand));
}
