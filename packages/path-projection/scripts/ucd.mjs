// Builds the pinned Unicode tables of §16.2 from the vendored UCD files (Node only; never imported by src).
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

export const UNICODE_VERSION = "16.0.0";
export const SOURCE_FILES = ["UnicodeData.txt", "CompositionExclusions.txt", "CaseFolding.txt"];

const hex = (s) => Number.parseInt(s, 16);
const b36 = (n) => n.toString(36);
const dataLines = (text) =>
  text
    .split("\n")
    .map((l) => l.replace(/#.*/, "").trim())
    .filter((l) => l !== "");

/**
 * Parses the UCD files. `applyExclusions: false` exists only so tests can prove that the
 * conformance suite detects a composer that ignores composition exclusions.
 */
export function parseUcd(dir, { applyExclusions = true } = {}) {
  const read = (f) => readFileSync(join(dir, f), "utf8");

  const ccc = new Map();
  const decomp = new Map(); // canonical decompositions only (no <tag> compatibility mappings)
  for (const line of dataLines(read("UnicodeData.txt"))) {
    const f = line.split(";");
    const cp = hex(f[0]);
    const cls = Number(f[3]);
    if (cls !== 0) ccc.set(cp, cls);
    if (f[5] !== "" && !f[5].startsWith("<")) decomp.set(cp, f[5].split(" ").map(hex));
  }

  // Full_Composition_Exclusion = listed exclusions + singletons + non-starter decompositions (UAX #15).
  const excluded = new Set(dataLines(read("CompositionExclusions.txt")).map((l) => hex(l.split(/\s/)[0])));
  const primaryComposites = [];
  for (const [cp, d] of decomp) {
    const fullExclusion =
      excluded.has(cp) || d.length === 1 || (ccc.get(cp) ?? 0) !== 0 || (ccc.get(d[0]) ?? 0) !== 0;
    if (d.length === 2 && (!applyExclusions || !fullExclusion)) primaryComposites.push(cp);
  }

  const fold = new Map();
  for (const line of dataLines(read("CaseFolding.txt"))) {
    const [code, status, mapping] = line.split(";").map((s) => s.trim());
    if (status === "C" || status === "F") fold.set(hex(code), mapping.split(" ").map(hex));
  }

  return { ccc, decomp, primaryComposites: primaryComposites.sort((a, b) => a - b), fold };
}

// Compact encodings: records sorted by code point, keys delta-encoded, numbers in base 36.
function encodeRuns(map) {
  const cps = [...map.keys()].sort((a, b) => a - b);
  const out = [];
  let prev = 0;
  for (let i = 0; i < cps.length; ) {
    let j = i;
    while (j + 1 < cps.length && cps[j + 1] === cps[j] + 1 && map.get(cps[j + 1]) === map.get(cps[i])) j++;
    out.push(`${b36(cps[i] - prev)}:${b36(j - i + 1)}:${b36(map.get(cps[i]))}`);
    prev = cps[i];
    i = j + 1;
  }
  return out.join(";");
}

function encodeMappings(map) {
  let prev = 0;
  return [...map.keys()]
    .sort((a, b) => a - b)
    .map((cp) => {
      const rec = `${b36(cp - prev)}:${map.get(cp).map(b36).join(",")}`;
      prev = cp;
      return rec;
    })
    .join(";");
}

function encodeList(cps) {
  let prev = 0;
  return cps
    .map((cp) => {
      const rec = b36(cp - prev);
      prev = cp;
      return rec;
    })
    .join(";");
}

export function sha256(dir, file) {
  return createHash("sha256").update(readFileSync(join(dir, file))).digest("hex");
}

/** The four encoded table strings (same format as the generated module). */
export function encodeTables(dir, options) {
  const t = parseUcd(dir, options);
  return {
    CCC: encodeRuns(t.ccc),
    DECOMPOSITIONS: encodeMappings(t.decomp),
    PRIMARY_COMPOSITES: encodeList(t.primaryComposites),
    CASE_FOLDING: encodeMappings(t.fold),
  };
}

/** Returns the full text of src/generated/unicode-16.0.0.ts (deterministic). */
export function generateModule(dir, options) {
  const t = encodeTables(dir, options);
  const hashes = SOURCE_FILES.map((f) => `//   ${f} sha256 ${sha256(dir, f)}`).join("\n");
  return `// GENERATED — do not edit. Run \`pnpm gen:unicode\` (scripts/gen-unicode.mjs).
// Unicode ${UNICODE_VERSION} tables for §16.2 (NFC + full case folding C+F), from ucd/${UNICODE_VERSION}/:
${hashes}
// Encoding: records separated by ";", code points delta-encoded in base 36 (see src/unicode.ts).

export const UNICODE_VERSION = "${UNICODE_VERSION}";

/** Canonical combining classes ≠ 0: "delta:runLength:class". */
export const CCC = "${t.CCC}";

/** Canonical decomposition mappings (one level; Hangul is algorithmic): "delta:cp,cp". */
export const DECOMPOSITIONS = "${t.DECOMPOSITIONS}";

/** Primary composites (composition exclusions applied): "delta". Pairs come from DECOMPOSITIONS. */
export const PRIMARY_COMPOSITES = "${t.PRIMARY_COMPOSITES}";

/** CaseFolding.txt statuses C and F (no T): "delta:cp,cp,...". */
export const CASE_FOLDING = "${t.CASE_FOLDING}";
`;
}
