import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadTable, parseDelimited, profile } from "../src/analyze/table";
import { runAnalysis } from "../src/analyze/sandbox";

const CSV = `username,full_name,email,department,phone,last_login_ip,salary,active,joined
jsmith,John Smith,john.smith@acme.io,Finance,+385 91 234 5678,10.0.4.17,72000,true,2023-04-10
mkovac,Marija Kovac,marija.kovac@acme.io,Engineering,+385 98 765 4321,10.0.4.22,81000,true,2016-04-19
"admin, root",Root Admin,admin@acme.io,IT,+385 1 555 0101,203.0.113.9,90000,false,2020-01-01
`;

function file(name: string, content: string) {
  const p = join(mkdtempSync(join(tmpdir(), "hib-an-")), name);
  writeFileSync(p, content);
  return p;
}

describe("table loading", () => {
  test("csv with quotes and types", () => {
    const t = loadTable(file("users.csv", CSV));
    expect(t.columns.length).toBe(9);
    expect(t.rows[2]!.username).toBe("admin, root");
    expect(t.rows[0]!.salary).toBe(72000);
    expect(t.rows[2]!.active).toBe(false);
  });
  test("quoted newlines and doubled quotes", () => {
    expect(parseDelimited('a,b\n"x\ny","say ""hi"""\n', ",")).toEqual([["a", "b"], ["x\ny", 'say "hi"']]);
  });
  test("tsv, json and jsonl", () => {
    expect(loadTable(file("a.tsv", "x\ty\n1\t2\n")).rows).toEqual([{ x: 1, y: 2 }]);
    expect(loadTable(file("a.json", '[{"x":1},{"x":2,"y":"z"}]')).rows).toEqual([{ x: 1, y: null }, { x: 2, y: "z" }]);
    expect(loadTable(file("a.jsonl", '{"x":1}\n{"x":2}\n')).rows.length).toBe(2);
  });
  test("ids with leading zeros stay strings", () => {
    expect(loadTable(file("z.csv", "zip\n01000\n10000\n")).rows[0]!.zip).toBe("01000");
  });
});

describe("profile: what the model may see", () => {
  const t = loadTable(file("users.csv", CSV));
  const p = profile(t, "/secret/path/users.csv", ["department", "email"]);
  const wire = JSON.stringify(p);
  test("no real identifying value ever appears", () => {
    for (const v of ["jsmith", "John Smith", "john.smith@acme.io", "+385 91 234 5678", "10.0.4.17", "72000", "/secret/path"]) expect(wire).not.toContain(v);
  });
  test("identifying columns are flagged, by name or by content", () => {
    expect(p.columns.filter((c) => c.identifying).map((c) => c.name)).toEqual(["username", "full_name", "email", "phone", "last_login_ip"]);
  });
  test("shared values only for non-identifying columns", () => {
    expect(p.columns.find((c) => c.name === "department")!.values).toEqual(["Engineering", "Finance", "IT"]);
    expect(p.columns.find((c) => c.name === "email")!.values).toBeUndefined();
  });
  test("types, counts and synthetic sample", () => {
    expect(p.rows).toBe(3);
    expect(p.columns.find((c) => c.name === "salary")).toMatchObject({ type: "integer", nulls: 0, distinct: 3 });
    expect(p.sample.length).toBe(3);
    expect(p.sample[0]!.email).toBe("user1@example.com");
  });
});

describe("sandboxed run", () => {
  const t = loadTable(file("users.csv", CSV));
  test("a normal analysis works", async () => {
    const r = await runAnalysis(
      `function analyze(rows) { const by = {}; for (const r of rows) by[r.department] = (by[r.department] ?? 0) + r.salary; return Object.entries(by).map(([department, total]) => ({ department, total })); }`,
      t,
    );
    expect(r.ok).toBe(true);
    expect(r.result).toEqual([{ department: "Finance", total: 72000 }, { department: "Engineering", total: 81000 }, { department: "IT", total: 90000 }]);
  });

  const escapes: [string, string][] = [
    ["global constructor", `function analyze(){ return this.constructor.constructor("return process")().env }`],
    ["rows constructor", `function analyze(rows){ return rows.constructor.constructor("return process")().pid }`],
    ["eval", `function analyze(){ return eval("1+1") }`],
    ["Function", `function analyze(){ return Function("return 1")() }`],
    ["fetch", `function analyze(){ return typeof fetch === "function" ? fetch("https://example.com") : "nofetch" }`],
    ["require", `function analyze(){ return require("fs").readFileSync("/etc/hosts", "utf8") }`],
    ["Bun", `function analyze(){ return Bun.file("/etc/hosts").size }`],
    ["process", `function analyze(){ return process.env }`],
    ["dynamic import", `function analyze(){ return import("node:fs") }`],
  ];
  for (const [name, code] of escapes)
    test(`blocks ${name}`, async () => {
      const r = await runAnalysis(code, t);
      if (name === "fetch") expect(r.result).toBe("nofetch");
      else expect(r.ok).toBe(false);
    });

  test("infinite loops time out", async () => {
    const r = await runAnalysis(`function analyze(){ for(;;){} }`, t, 500);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/timed out|timeout/i);
  });
});

describe("pseudonymise by column", async () => {
  const { pseudonymize, columnsToHide, categoryFor } = await import("../src/analyze/pseudo");
  const { Vault } = await import("../src/guard/vault");
  const t = loadTable(file("users.csv", CSV));

  test("identifying columns become stable tokens; the rest stays readable", () => {
    const v = new Vault("ab12");
    const cols = columnsToHide(t);
    expect(cols).toEqual(["username", "full_name", "email", "phone", "last_login_ip"]);
    const csv = pseudonymize(t, cols, v);
    for (const real of ["jsmith", "John Smith", "john.smith", "acme.io", "+385 91 234 5678", "10.0.4.17"]) expect(csv).not.toContain(real);
    expect(csv).toContain("Finance");
    expect(csv).toContain("72000");
    expect(csv.split("\n")[1]).toStartWith("[HIBab12-USERNAME-1],[HIBab12-FULL-NAME-1],[HIBab12-EMAIL-1]@[HIBab12-DOMAIN-1]");
  });
  test("emails share a domain token, so grouping by domain still works", () => {
    const v = new Vault("ab12");
    const csv = pseudonymize(t, ["email"], v);
    expect(csv.match(/@\[HIBab12-DOMAIN-1\]/g)!.length).toBe(3);
    expect(v.restore("[HIBab12-EMAIL-2]@[HIBab12-DOMAIN-1]")).toBe("marija.kovac@acme.io");
  });
  test("hide and keep override the defaults; categories are token-safe", () => {
    expect(columnsToHide(t, ["salary"], ["phone"])).toEqual(["username", "full_name", "email", "last_login_ip", "salary"]);
    expect(categoryFor("Full Name (legal)")).toBe("FULL-NAME-LEGAL");
  });
});

test("only table files are loaded, so a random file's first line is never sent as column names", () => {
  expect(() => loadTable(file("notes.txt", "secret plans\nmore"))).toThrow("not a CSV");
  expect(() => loadTable(file("id_rsa", "-----BEGIN"))).toThrow("not a CSV");
});

describe("offline geo helper", async () => {
  const { buildGeo, GEO_HELPER } = await import("../src/analyze/geo");
  // GeoNames format: geonameid, name, asciiname, alternatenames, lat, lon, fclass, fcode, cc, cc2, a1, a2, a3, a4, population, …
  const row = (name: string, lat: number, lon: number, cc: string, pop: number) => [1, name, name.normalize("NFD").replace(/[̀-ͯ]/g, ""), "", lat, lon, "P", "PPLC", cc, "", "", "", "", "", pop, "", "", "", ""].join("\t");
  const cities = [row("Zagreb", 45.815, 15.9819, "HR", 790017), row("Split", 43.5089, 16.4392, "HR", 160577), row("Tokyo", 35.6895, 139.6917, "JP", 8336599), row("Osaka", 34.6937, 135.5022, "JP", 2592413)].join("\n");
  const countries = "#ISO\tISO3\tISO-Numeric\tfips\tCountry\tCapital\tArea\tPopulation\tContinent\nHR\tHRV\t191\tHR\tCroatia\tZagreb\t56542\t4071000\tEU\nJP\tJPN\t392\tJA\tJapan\tTokyo\t377835\t127288000\tAS\n";
  const geo = buildGeo(cities, countries);

  test("parses cities and countries", () => {
    expect(geo.cities.length).toBe(4);
    expect(geo.countries.map((c) => c.name)).toEqual(["Croatia", "Japan"]);
  });

  test("impossible travel is computable locally from country/city columns", async () => {
    const t = loadTable(file("logins.csv", "user,time,country,city\njsmith,2026-10-08T22:00:00Z,Croatia,Zagreb\njsmith,2026-10-08T23:00:00Z,JP,Tōkyō\nmkovac,2026-10-08T08:00:00Z,HR,Zagreb\nmkovac,2026-10-08T12:00:00Z,Croatia,Split\n"));
    const code = `function analyze(rows) {
      const by = {}; for (const r of rows) (by[r.user] ??= []).push(r);
      const out = [];
      for (const [user, list] of Object.entries(by)) {
        list.sort((a, b) => Date.parse(a.time) - Date.parse(b.time));
        for (let i = 1; i < list.length; i++) {
          const a = geo.locate(list[i - 1].city, list[i - 1].country), b = geo.locate(list[i].city, list[i].country);
          const speed = geo.kmh(a, b, list[i - 1].time, list[i].time);
          if (speed > 900) out.push({ user, from: list[i - 1].city, to: list[i].city, km: Math.round(geo.km(a, b)), kmh: Math.round(speed) });
        }
      }
      return out;
    }`;
    const r = await runAnalysis(code, t, 20_000, { data: JSON.stringify(geo), helper: GEO_HELPER });
    expect(r.ok).toBe(true);
    expect(r.result).toHaveLength(1);
    expect((r.result as any)[0]).toMatchObject({ user: "jsmith", from: "Zagreb", to: "Tōkyō" });
    expect((r.result as any)[0].km).toBeGreaterThan(9000);
  });

  test("lookups: ISO2, ISO3, names, accents, unknowns", async () => {
    const t = loadTable(file("x.csv", "a\n1\n"));
    const r = await runAnalysis(`function analyze() { return [geo.country("HRV")?.name, geo.country("japan")?.iso2, geo.city("tokyo")?.country, geo.locate("Nowhere", "JP")?.name, geo.locate("Nowhere", "Atlantis")]; }`, t, 20_000, { data: JSON.stringify(geo), helper: GEO_HELPER });
    expect(r.result).toEqual(["Croatia", "JP", "JP", "Japan", null]);
  });
});

test("boolean flags are never identifying, even when the name matches (known_abuser)", () => {
  const t = loadTable(file("f.csv", "user,known_abuser,is_vpn\njsmith,true,false\n"));
  expect(profile(t, "f.csv").columns.filter((c) => c.identifying).map((c) => c.name)).toEqual(["user"]);
});

test("several files combine into one table with a source_file column", async () => {
  const { loadTables } = await import("../src/analyze/table");
  const a = file("investigation-1.csv", "time,ip\n2026-01-01T00:00:00Z,1.2.3.4\n");
  const b = file("investigation-2.csv", "time,ip,city\n2026-01-01T01:00:00Z,5.6.7.8,Tokyo\n");
  const t = loadTables([a, b]);
  expect(t.columns).toEqual(["source_file", "time", "ip", "city"]);
  expect(t.rows).toEqual([
    { source_file: "investigation-1.csv", time: "2026-01-01T00:00:00Z", ip: "1.2.3.4", city: null },
    { source_file: "investigation-2.csv", time: "2026-01-01T01:00:00Z", ip: "5.6.7.8", city: "Tokyo" },
  ]);
});
