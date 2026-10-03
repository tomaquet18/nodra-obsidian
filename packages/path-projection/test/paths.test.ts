import { describe, expect, it } from "vitest";
import {
  MAX_LOGICAL_PATH_BYTES,
  canonicalizePath,
  comparisonKey,
  conflictSuffix,
  fitSegment,
  objectLabel,
  sanitizeSegment,
  splitExtension,
  utf8Length,
} from "../src/paths.js";

const NFC_CAFE = "café.md";
const NFD_CAFE = "café.md";

describe("§16.2 canonicalizePath", () => {
  it("normalizes to NFC", () => {
    expect(NFD_CAFE).not.toBe(NFC_CAFE);
    expect(canonicalizePath(NFD_CAFE)).toEqual({ ok: true, path: NFC_CAFE });
  });
  it("converts backslash to / and drops trailing slash, empty and '.' segments", () => {
    expect(canonicalizePath("a\\b//./c.md/")).toEqual({ ok: true, path: "a/b/c.md" });
  });
  it("rejects '..' segments and empty paths", () => {
    expect(canonicalizePath("a/../b.md")).toEqual({ ok: false, reason: "DOT_DOT_SEGMENT" });
    expect(canonicalizePath("/./")).toEqual({ ok: false, reason: "EMPTY" });
  });
  it("rejects logical paths over 4096 UTF-8 bytes", () => {
    expect(canonicalizePath("a".repeat(MAX_LOGICAL_PATH_BYTES)).ok).toBe(true);
    expect(canonicalizePath("é".repeat(2049))).toEqual({ ok: false, reason: "TOO_LONG" });
  });
});

describe("§16.2 comparison key (NFC + full case fold)", () => {
  it("case-only differences collide", () => {
    expect(comparisonKey("Notes/Daily.md")).toBe(comparisonKey("notes/DAILY.md"));
  });
  it("Unicode-equivalent (NFC vs NFD) paths collide", () => {
    expect(comparisonKey(NFC_CAFE)).toBe(comparisonKey(NFD_CAFE));
  });
  it("full folding: sharp s ~ SS, final sigma, ligature fi", () => {
    expect(comparisonKey("straße")).toBe(comparisonKey("STRASSE"));
    expect(comparisonKey("ΟΔΟΣ")).toBe(comparisonKey("οδος"));
    expect(comparisonKey("ﬁle")).toBe(comparisonKey("FILE"));
  });
  // Behavior changes vs the old runtime approximation (upper then lower), found by an
  // exhaustive comparison over all code points (see NOTES.md, item 1).
  it("capital sharp s (U+1E9E) collides with sharp s and SS (C+F); the old approximation missed it", () => {
    const capitalSharpS = String.fromCodePoint(0x1e9e);
    expect(comparisonKey(`${capitalSharpS}.md`)).toBe(comparisonKey("ss.md"));
    expect(comparisonKey(`${capitalSharpS}.md`)).toBe(comparisonKey(`${String.fromCodePoint(0xdf)}.md`));
  });
  it("dotless i (U+0131) does not collide with i or I (no T folding); the old approximation merged them", () => {
    const dotless = String.fromCodePoint(0x131);
    expect(comparisonKey(`${dotless}.md`)).not.toBe(comparisonKey("i.md"));
    expect(comparisonKey("I.md")).toBe(comparisonKey("i.md"));
  });
  it("Cherokee folds to the uppercase block (keys differ from the old approximation, classes do not)", () => {
    expect(comparisonKey(String.fromCodePoint(0xab70))).toBe(String.fromCodePoint(0x13a0));
    expect(comparisonKey(String.fromCodePoint(0x13a0))).toBe(String.fromCodePoint(0x13a0));
  });
  it("different names do not collide", () => {
    expect(comparisonKey("a.md")).not.toBe(comparisonKey("b.md"));
  });
});

describe("§16.2 portable sanitization", () => {
  it.each([
    ["what?.md", "what_.md"],
    ['a<b>c:d"e|f*g.md', "a_b_c_d_e_f_g.md"],
    ["back\\slash.md", "back_slash.md"],
    ["tab\there\u0000.md", "tab_here_.md"],
    ["notes.", "notes._"],
    ["notes ", "notes _"],
    ["CON.md", "_CON.md"],
    ["con", "_con"],
    ["Lpt9.txt", "_Lpt9.txt"],
    ["COM1.tar.gz", "_COM1.tar.gz"],
    ["COM0.md", "COM0.md"],
    ["CONSOLE.md", "CONSOLE.md"],
    ["plain.md", "plain.md"],
  ])("%j → %j", (input, output) => {
    expect(sanitizeSegment(input)).toBe(output);
  });
});

describe("§16.3 segment length, label and suffix", () => {
  it("label is the last 8 characters of the object id, never the first", () => {
    expect(objectLabel("0190a1b2-0000-7000-8000-00003fa9c21b")).toBe("3fa9c21b");
  });
  it("suffix goes before the extension", () => {
    const [base, ext] = splitExtension("daily.md");
    expect(fitSegment(base, conflictSuffix("3fa9c21b"), ext)).toBe("daily (Nodra conflict 3fa9c21b).md");
  });
  it("multibyte names are truncated by whole characters to ≤ 255 bytes, keeping suffix and extension", () => {
    const seg = fitSegment("日本".repeat(100), conflictSuffix("3fa9c21b"), ".md");
    expect(utf8Length(seg)).toBeLessThanOrEqual(255);
    expect(seg.endsWith(" (Nodra conflict 3fa9c21b).md")).toBe(true);
    expect(seg.startsWith("日本日本")).toBe(true);
  });
  it("never splits a surrogate pair", () => {
    const emoji = "\u{1F600}";
    const seg = fitSegment(emoji.repeat(100), "", ".md");
    expect(utf8Length(seg)).toBeLessThanOrEqual(255);
    expect(seg).toBe(`${emoji.repeat(63)}.md`);
  });
  it("a truncation ending in '.' or space is sanitized again", () => {
    expect(fitSegment(`${"a".repeat(254)}. x`, "", "")).toBe(`${"a".repeat(254)}_`);
  });
  it("an extension too long to keep becomes part of the base", () => {
    const seg = fitSegment("n", conflictSuffix("3fa9c21b"), `.${"x".repeat(250)}`);
    expect(utf8Length(seg)).toBeLessThanOrEqual(255);
    expect(seg.endsWith(conflictSuffix("3fa9c21b"))).toBe(true);
  });
});
