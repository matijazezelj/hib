import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { detect } from "./detectors";

const SECRET_FILES = /(^|\/)(\.env(\..*)?|.*\.pem|.*\.key|id_rsa|id_ed25519|id_ecdsa|\.npmrc|\.pypirc|\.netrc|credentials(\.json)?|.*\.p12|.*\.pfx|\.git-credentials)$/;
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "target", ".venv", "venv", "__pycache__"]);
const MAX_FILES = 5000;
const MAX_BYTES = 512 * 1024;

export function isAllowedDir(dir: string, allowed: string[]): boolean {
  const d = resolve(dir);
  return allowed.some((a) => d === resolve(a) || d.startsWith(resolve(a) + "/"));
}

/** Files an agent could read that look like they hold secrets. Paths are relative to dir. */
export function scanDir(dir: string): string[] {
  const hits: string[] = [];
  let seen = 0;
  const walk = (d: string) => {
    for (const name of readdirSync(d)) {
      if (seen++ > MAX_FILES) return;
      const p = join(d, name);
      let st;
      try {
        st = statSync(p);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name)) walk(p);
        continue;
      }
      const rel = relative(dir, p);
      if (SECRET_FILES.test(rel) && !/\.(example|sample|template)$/.test(rel)) {
        hits.push(rel);
        continue;
      }
      if (st.size > MAX_BYTES) continue;
      const text = readFileSync(p, "utf8");
      if (text.includes("\0")) continue;
      const found = detect(text, { level: "minimal" });
      if (found.length) hits.push(`${rel} (${[...new Set(found.map((f) => f.category))].join(", ")})`);
    }
  };
  walk(resolve(dir));
  return hits;
}
