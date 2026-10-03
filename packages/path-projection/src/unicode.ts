import {
  CASE_FOLDING,
  CCC,
  DECOMPOSITIONS,
  PRIMARY_COMPOSITES,
  UNICODE_VERSION,
} from "./generated/unicode-16.0.0.js";

// §16.2: NFC and full case folding from pinned Unicode tables (ADR-013). Never the runtime:
// no normalization or case mapping of the host JavaScript engine, no ICU.

export const UNICODE_TABLES_VERSION: string = UNICODE_VERSION;

export interface UnicodeTables {
  readonly ccc: ReadonlyMap<number, number>;
  /** Full (recursive) canonical decompositions, Hangul excluded. */
  readonly decomposition: ReadonlyMap<number, readonly number[]>;
  /** (first << 21 | second) → primary composite. */
  readonly composition: ReadonlyMap<number, number>;
  readonly folding: ReadonlyMap<number, readonly number[]>;
}

export interface EncodedTables {
  readonly CCC: string;
  readonly DECOMPOSITIONS: string;
  readonly PRIMARY_COMPOSITES: string;
  readonly CASE_FOLDING: string;
}

const records = (s: string) => (s === "" ? [] : s.split(";"));
const b36 = (s: string) => Number.parseInt(s, 36);

function decodeMappings(s: string): Map<number, number[]> {
  const out = new Map<number, number[]>();
  let cp = 0;
  for (const r of records(s)) {
    const [delta, values] = r.split(":") as [string, string];
    cp += b36(delta);
    out.set(cp, values.split(",").map(b36));
  }
  return out;
}

/** Decodes the generated strings (format documented in scripts/ucd.mjs). */
export function decodeTables(t: EncodedTables): UnicodeTables {
  const ccc = new Map<number, number>();
  let start = 0;
  for (const r of records(t.CCC)) {
    const [delta, len, cls] = r.split(":").map(b36) as [number, number, number];
    start += delta;
    for (let i = 0; i < len; i++) ccc.set(start + i, cls);
  }

  const single = decodeMappings(t.DECOMPOSITIONS);
  const full = (cp: number): number[] => {
    const d = single.get(cp);
    return d === undefined ? [cp] : d.flatMap(full);
  };
  const decomposition = new Map<number, number[]>();
  for (const cp of single.keys()) decomposition.set(cp, full(cp));

  const composition = new Map<number, number>();
  let composite = 0;
  for (const r of records(t.PRIMARY_COMPOSITES)) {
    composite += b36(r);
    const [first, second] = single.get(composite) as [number, number];
    composition.set(first * 0x200000 + second, composite);
  }

  return { ccc, decomposition, composition, folding: decodeMappings(t.CASE_FOLDING) };
}

export const TABLES: UnicodeTables = decodeTables({ CCC, DECOMPOSITIONS, PRIMARY_COMPOSITES, CASE_FOLDING });

// Hangul syllables are decomposed and composed algorithmically (Unicode §3.12).
const S_BASE = 0xac00;
const L_BASE = 0x1100;
const V_BASE = 0x1161;
const T_BASE = 0x11a7;
const L_COUNT = 19;
const V_COUNT = 21;
const T_COUNT = 28;
const N_COUNT = V_COUNT * T_COUNT;
const S_COUNT = L_COUNT * N_COUNT;

const codePoints = (s: string): number[] => Array.from(s, (ch) => ch.codePointAt(0)!);
const fromCodePoints = (cps: readonly number[]): string => {
  let out = "";
  for (let i = 0; i < cps.length; i += 4096) out += String.fromCodePoint(...cps.slice(i, i + 4096));
  return out;
};

function decomposeInto(out: number[], cp: number, t: UnicodeTables): void {
  const s = cp - S_BASE;
  if (s >= 0 && s < S_COUNT) {
    out.push(L_BASE + Math.floor(s / N_COUNT), V_BASE + Math.floor((s % N_COUNT) / T_COUNT));
    if (s % T_COUNT !== 0) out.push(T_BASE + (s % T_COUNT));
    return;
  }
  const d = t.decomposition.get(cp);
  if (d === undefined) out.push(cp);
  else out.push(...d);
}

/** Canonical ordering: stable sort of each run of non-starters by combining class. */
function canonicalOrder(cps: number[], t: UnicodeTables): number[] {
  for (let i = 1; i < cps.length; i++) {
    const c = t.ccc.get(cps[i]!) ?? 0;
    if (c === 0) continue;
    let j = i;
    while (j > 0) {
      const prev = t.ccc.get(cps[j - 1]!) ?? 0;
      if (prev <= c) break;
      [cps[j - 1], cps[j]] = [cps[j]!, cps[j - 1]!];
      j--;
    }
  }
  return cps;
}

function nfdCodePoints(s: string, t: UnicodeTables): number[] {
  const out: number[] = [];
  for (const cp of codePoints(s)) decomposeInto(out, cp, t);
  return canonicalOrder(out, t);
}

function composePair(a: number, b: number, t: UnicodeTables): number | undefined {
  const l = a - L_BASE;
  const v = b - V_BASE;
  if (l >= 0 && l < L_COUNT && v >= 0 && v < V_COUNT) return S_BASE + (l * V_COUNT + v) * T_COUNT;
  const s = a - S_BASE;
  const tt = b - T_BASE;
  if (s >= 0 && s < S_COUNT && s % T_COUNT === 0 && tt > 0 && tt < T_COUNT) return a + tt;
  return t.composition.get(a * 0x200000 + b);
}

export function toNFD(s: string, t: UnicodeTables = TABLES): string {
  return fromCodePoints(nfdCodePoints(s, t));
}

export function toNFC(s: string, t: UnicodeTables = TABLES): string {
  const out: number[] = [];
  let starter = -1;
  let lastCcc = 0;
  for (const cp of nfdCodePoints(s, t)) {
    const c = t.ccc.get(cp) ?? 0;
    // Not blocked: adjacent to the starter, or every character in between has a lower class.
    if (starter >= 0 && (out.length - 1 === starter || (lastCcc !== 0 && lastCcc < c))) {
      const composed = composePair(out[starter]!, cp, t);
      if (composed !== undefined) {
        out[starter] = composed;
        continue;
      }
    }
    if (c === 0) starter = out.length;
    lastCcc = c;
    out.push(cp);
  }
  return fromCodePoints(out);
}

/** Full case folding, statuses C + F of CaseFolding.txt; locale-independent (no T). */
export function caseFoldFull(s: string, t: UnicodeTables = TABLES): string {
  const out: number[] = [];
  for (const cp of codePoints(s)) {
    const f = t.folding.get(cp);
    if (f === undefined) out.push(cp);
    else out.push(...f);
  }
  return fromCodePoints(out);
}
