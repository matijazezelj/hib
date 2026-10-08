// Local gazetteer for analyses: country and city coordinates from GeoNames (CC-BY 4.0), so code running in the
// sandbox can reason about distance (e.g. impossible travel) without any lookup leaving the machine.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const CITIES_URL = "https://download.geonames.org/export/dump/cities15000.zip";
const COUNTRIES_URL = "https://download.geonames.org/export/dump/countryInfo.txt";

export interface GeoData {
  source: string;
  built: number;
  countries: { iso2: string; iso3: string; name: string; continent: string; capital: string; lat: number; lon: number }[];
  cities: [name: string, ascii: string, country: string, lat: number, lon: number, population: number][];
}

export const geoFile = (home: string) => join(home, "geo", "geo.json");
export const geoInstalled = (home: string) => existsSync(geoFile(home));

export function loadGeo(home: string): GeoData | null {
  return geoInstalled(home) ? JSON.parse(readFileSync(geoFile(home), "utf8")) : null;
}

/** Parses GeoNames' cities15000.txt and countryInfo.txt into the compact form the sandbox gets. */
export function buildGeo(citiesTsv: string, countryInfo: string): GeoData {
  const cities: GeoData["cities"] = [];
  for (const line of citiesTsv.split("\n")) {
    const f = line.split("\t");
    if (f.length < 15) continue;
    const lat = Number(f[4]), lon = Number(f[5]), pop = Number(f[14]) || 0;
    if (!Number.isFinite(lat) || !Number.isFinite(lon) || !/^[A-Z]{2}$/.test(f[8]!)) continue;
    cities.push([f[1]!, f[2]!, f[8]!, Math.round(lat * 1e4) / 1e4, Math.round(lon * 1e4) / 1e4, pop]);
  }
  // Country position: population-weighted centre of its cities (good enough for travel distances), else capital.
  const sums = new Map<string, { w: number; lat: number; lon: number }>();
  for (const [, , cc, lat, lon, pop] of cities) {
    const s = sums.get(cc) ?? { w: 0, lat: 0, lon: 0 };
    const w = Math.max(pop, 1);
    sums.set(cc, { w: s.w + w, lat: s.lat + lat * w, lon: s.lon + lon * w });
  }
  const countries: GeoData["countries"] = [];
  for (const line of countryInfo.split("\n")) {
    if (line.startsWith("#") || !line.trim()) continue;
    const f = line.split("\t");
    if (!/^[A-Z]{2}$/.test(f[0] ?? "")) continue;
    const s = sums.get(f[0]!);
    const cap = cities.filter((c) => c[2] === f[0] && c[0] === f[5]).sort((a, b) => b[5] - a[5])[0];
    const lat = s ? s.lat / s.w : cap?.[3];
    const lon = s ? s.lon / s.w : cap?.[4];
    if (lat === undefined || lon === undefined) continue;
    countries.push({ iso2: f[0]!, iso3: f[1]!, name: f[4]!, capital: f[5] ?? "", continent: f[8] ?? "", lat: Math.round(lat * 1e3) / 1e3, lon: Math.round(lon * 1e3) / 1e3 });
  }
  return { source: "GeoNames cities15000 + countryInfo (CC-BY 4.0)", built: Date.now(), countries, cities };
}

/** Downloads and builds the gazetteer into <home>/geo/geo.json. */
export async function setupGeo(home: string): Promise<GeoData> {
  const dir = join(home, "geo");
  mkdirSync(dir, { recursive: true });
  const zip = join(dir, "cities15000.zip");
  const r = await fetch(CITIES_URL);
  if (!r.ok) throw new Error(`download failed: ${CITIES_URL} ${r.status}`);
  writeFileSync(zip, new Uint8Array(await r.arrayBuffer()));
  const unzip = Bun.spawnSync(["unzip", "-p", zip, "cities15000.txt"]);
  if (unzip.exitCode !== 0) throw new Error(`unzip failed: ${unzip.stderr.toString().slice(0, 200)}`);
  const ci = await fetch(COUNTRIES_URL);
  if (!ci.ok) throw new Error(`download failed: ${COUNTRIES_URL} ${ci.status}`);
  const geo = buildGeo(unzip.stdout.toString(), await ci.text());
  if (geo.cities.length < 20_000 || geo.countries.length < 200) throw new Error(`unexpected data: ${geo.cities.length} cities, ${geo.countries.length} countries`);
  writeFileSync(geoFile(home), JSON.stringify(geo));
  return geo;
}

/**
 * The `geo` helper as source compiled inside the sandbox context (no imports, no I/O). Lookups are accent- and
 * case-insensitive; a city is chosen within the given country when one is passed, else the most populous match.
 */
export const GEO_HELPER = `
const geo = (() => {
  const norm = (s) => String(s ?? "").normalize("NFD").replace(/[\\u0300-\\u036f]/g, "").toLowerCase().trim();
  const byCode = {}, byName = {}, cityIdx = {};
  for (const c of GEO.countries) { byCode[c.iso2] = c; byCode[c.iso3] = c; byName[norm(c.name)] = c; }
  for (const [name, ascii, cc, lat, lon, pop] of GEO.cities)
    for (const k of new Set([norm(name), norm(ascii)])) (cityIdx[k] ??= []).push({ name, country: cc, lat, lon, population: pop });
  const country = (x) => (x == null ? null : byCode[String(x).trim().toUpperCase()] ?? byName[norm(x)] ?? null);
  const city = (name, inCountry) => {
    const list = cityIdx[norm(name)];
    if (!list) return null;
    const c = inCountry ? country(inCountry) : null;
    const pick = c ? list.filter((e) => e.country === c.iso2) : list;
    return [...(pick.length ? pick : list)].sort((a, b) => b.population - a.population)[0] ?? null;
  };
  const locate = (cityName, countryName) => (cityName ? city(cityName, countryName) : null) ?? country(countryName);
  const km = (a, b) => {
    if (!a || !b) return null;
    const r = Math.PI / 180, dLat = (b.lat - a.lat) * r, dLon = (b.lon - a.lon) * r;
    const h = Math.sin(dLat / 2) ** 2 + Math.cos(a.lat * r) * Math.cos(b.lat * r) * Math.sin(dLon / 2) ** 2;
    return 2 * 6371 * Math.asin(Math.min(1, Math.sqrt(h)));
  };
  const kmh = (a, b, timeA, timeB) => {
    const d = km(a, b), hours = Math.abs(Date.parse(timeB) - Date.parse(timeA)) / 3.6e6;
    return d === null || !Number.isFinite(hours) ? null : hours === 0 ? (d > 0 ? Infinity : 0) : d / hours;
  };
  return Object.freeze({ country, city, locate, km, kmh });
})();`;

export const GEO_DOC = `A local \`geo\` helper is available (offline gazetteer):
- geo.locate(city, country) -> {lat, lon, ...} for the city (within that country), else the country's centre, else null
- geo.country(nameOrIsoCode) -> {iso2, iso3, name, continent, capital, lat, lon} or null; geo.city(name, country?) -> {name, country, lat, lon, population} or null
- geo.km(a, b) -> great-circle distance in km between two located points (null if either is null)
- geo.kmh(a, b, timeA, timeB) -> implied travel speed in km/h between two located points at two ISO timestamps
Commercial flights cruise at about 900 km/h; logins implying more than that are physically impossible for one person.`;
