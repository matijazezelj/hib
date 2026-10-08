// Runs one model-written analyze(rows) function. Started by sandbox.ts in its own process; reads
// {code, data} from stdin and prints {ok, result} or {ok:false, error} as JSON on stdout.
import vm from "node:vm";

const input = JSON.parse(await Bun.stdin.text()) as { code: string; data: string; timeoutMs: number; geo?: string; geoHelper?: string };

// A null-prototype global has no path back to this realm's Function/process, and code generation
// from strings (eval, new Function) is off inside the context.
const context = vm.createContext(Object.create(null), { codeGeneration: { strings: false, wasm: false } });
try {
  // The data enters as a string literal compiled inside the context, so every object belongs to that realm.
  vm.runInContext(`"use strict"; const rows = JSON.parse(${JSON.stringify(input.data)});`, context, { timeout: input.timeoutMs });
  // Optional offline gazetteer: data and helper are compiled inside the context like the rows.
  if (input.geo && input.geoHelper) vm.runInContext(`"use strict"; const GEO = JSON.parse(${JSON.stringify(input.geo)});\n${input.geoHelper}\nglobalThis.geo = geo;`, context, { timeout: input.timeoutMs });
  const noImports = { importModuleDynamically: () => Promise.reject(new Error("imports are not allowed")) } as any;
  const out = vm.runInContext(
    `"use strict";\n${input.code}\n;(() => { const r = analyze(rows); if (r && typeof r.then === "function") throw new Error("analyze must return its result synchronously"); return JSON.stringify(r, (k, v) => (typeof v === "bigint" ? Number(v) : v)); })();`,
    context,
    { timeout: input.timeoutMs, ...noImports },
  );
  process.stdout.write(JSON.stringify({ ok: true, result: out === undefined ? null : JSON.parse(out) }));
} catch (e: any) {
  process.stdout.write(JSON.stringify({ ok: false, error: `${e?.name ?? "Error"}: ${String(e?.message ?? e).slice(0, 500)}` }));
}
