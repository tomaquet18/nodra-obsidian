import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { encodeTables } from "../scripts/ucd.mjs";
import { type UnicodeTables, caseFoldFull, decodeTables, TABLES, toNFC, toNFD } from "../src/unicode.js";

const UCD = join(import.meta.dirname, "..", "ucd", "16.0.0");
const cps = (field: string) => String.fromCodePoint(...field.split(" ").map((h) => Number.parseInt(h, 16)));
const hexOf = (s: string) => Array.from(s, (c) => c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")).join(" ");

interface NormalizationCase {
  part: string;
  c: [string, string, string, string, string];
}

function readNormalizationTest(): NormalizationCase[] {
  const out: NormalizationCase[] = [];
  let part = "";
  for (const raw of readFileSync(join(UCD, "NormalizationTest.txt"), "utf8").split("\n")) {
    const line = raw.replace(/#.*/, "").trim();
    if (line === "") continue;
    if (line.startsWith("@")) {
      part = line;
      continue;
    }
    const f = line.split(";").slice(0, 5).map(cps) as NormalizationCase["c"];
    out.push({ part, c: f });
  }
  return out;
}

const CASES = readNormalizationTest();

/** NormalizationTest.txt invariants for NFC and NFD. Returns the failing lines. */
function conformanceFailures(t: UnicodeTables): string[] {
  const failures: string[] = [];
  for (const { part, c } of CASES) {
    const [c1, c2, c3, c4, c5] = c;
    const nfcOk = [c1, c2, c3].every((x) => toNFC(x, t) === c2) && [c4, c5].every((x) => toNFC(x, t) === c4);
    const nfdOk = [c1, c2, c3].every((x) => toNFD(x, t) === c3) && [c4, c5].every((x) => toNFD(x, t) === c5);
    if (!nfcOk || !nfdOk) failures.push(`${part} ${hexOf(c1)} (nfc ${nfcOk}, nfd ${nfdOk})`);
  }
  return failures;
}

describe("NormalizationTest.txt (Unicode 16.0.0), NFC and NFD", () => {
  it("parses every part (Part0-Part5)", () => {
    const parts = new Map<string, number>();
    for (const { part } of CASES) parts.set(part, (parts.get(part) ?? 0) + 1);
    expect([...parts.keys()]).toEqual(["@Part0", "@Part1", "@Part2", "@Part3", "@Part4", "@Part5"]);
    expect(CASES.length).toBeGreaterThan(19000);
  });

  it("every line of every part holds: c2 == NFC(c1..c3), c4 == NFC(c4, c5), c3 == NFD(c1..c3), c5 == NFD(c4, c5)", () => {
    expect(conformanceFailures(TABLES)).toEqual([]);
  });

  it("Part 1 complement: every code point not listed in Part 1 is its own NFC and NFD", () => {
    const listed = new Set(CASES.filter((x) => x.part === "@Part1").map((x) => x.c[0].codePointAt(0)!));
    const failures: number[] = [];
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (listed.has(cp) || (cp >= 0xd800 && cp <= 0xdfff)) continue;
      const s = String.fromCodePoint(cp);
      if (toNFC(s) !== s || toNFD(s) !== s) failures.push(cp);
    }
    expect(failures).toEqual([]);
  }, 60_000);

  it("evidence: a composer that ignores composition exclusions fails the suite", () => {
    const broken = decodeTables(encodeTables(UCD, { applyExclusions: false }));
    expect(conformanceFailures(broken).length).toBeGreaterThan(50); // 96 lines at 16.0.0
  });

  it("evidence: a normalizer without canonical ordering fails the suite", () => {
    const noCcc: UnicodeTables = { ...TABLES, ccc: new Map() };
    expect(conformanceFailures(noCcc).length).toBeGreaterThan(100);
  });
});

describe("CaseFolding.txt (Unicode 16.0.0), statuses C + F, no T", () => {
  const lines = readFileSync(join(UCD, "CaseFolding.txt"), "utf8")
    .split("\n")
    .map((l) => l.replace(/#.*/, "").trim())
    .filter((l) => l !== "")
    .map((l) => l.split(";").map((s) => s.trim()) as [string, string, string]);

  it("every C and F line folds exactly as listed", () => {
    const cf = lines.filter(([, status]) => status === "C" || status === "F");
    expect(cf.length).toBeGreaterThan(1400);
    const failures = cf.filter(([code, , mapping]) => caseFoldFull(cps(code)) !== cps(mapping)).map(([code]) => code);
    expect(failures).toEqual([]);
  });

  it("S lines are superseded by F (full folding)", () => {
    const s = lines.filter(([, status]) => status === "S");
    for (const [code] of s) {
      const f = lines.find(([c, status]) => c === code && status === "F");
      expect(f).toBeDefined();
      expect(caseFoldFull(cps(code))).toBe(cps(f![2]));
    }
  });

  it("T lines (Turkic) are not applied", () => {
    const t = lines.filter(([, status]) => status === "T");
    expect(t.map(([code]) => code)).toEqual(["0049", "0130"]);
    expect(caseFoldFull("I")).toBe("i");
    expect(caseFoldFull(String.fromCodePoint(0x130))).toBe(String.fromCodePoint(0x69, 0x307)); // F, not T
  });

  it("named cases: sharp s, capital sharp s, final sigma", () => {
    expect(caseFoldFull(String.fromCodePoint(0xdf))).toBe("ss");
    expect(caseFoldFull(String.fromCodePoint(0x1e9e))).toBe("ss");
    expect(caseFoldFull(String.fromCodePoint(0x3c2))).toBe(String.fromCodePoint(0x3c3));
    expect(caseFoldFull(String.fromCodePoint(0x3a3))).toBe(String.fromCodePoint(0x3c3));
  });

  it("code points without a C or F line fold to themselves", () => {
    const mapped = new Set(lines.filter(([, s]) => s === "C" || s === "F").map(([c]) => Number.parseInt(c, 16)));
    for (let cp = 0; cp <= 0x10ffff; cp += 1) {
      if (mapped.has(cp) || (cp >= 0xd800 && cp <= 0xdfff)) continue;
      const s = String.fromCodePoint(cp);
      if (caseFoldFull(s) !== s) throw new Error(`unexpected fold for U+${cp.toString(16)}`);
    }
  }, 60_000);

  it("evidence: the old runtime approximation (upper then lower) fails the C + F lines", () => {
    const cf = lines.filter(([, status]) => status === "C" || status === "F");
    const approx = (s: string) => s.toUpperCase().toLowerCase();
    expect(cf.filter(([code, , mapping]) => approx(cps(code)) !== cps(mapping)).length).toBeGreaterThan(50);
  });
});
