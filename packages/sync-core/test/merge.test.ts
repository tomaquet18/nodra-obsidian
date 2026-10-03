import fc from "fast-check";
import { diff3Merge } from "node-diff3";
import { describe, expect, it } from "vitest";
import { merge3 } from "../src/merge.js";

const lines = (s: string) => s.split("\n");
const BASE = "a\nb\nc\nd\ne";

// Pins what node-diff3 3.2.1 actually does, line by line. If an upgrade changes any of
// these, the conflict criterion changed and must be reviewed before accepting it.
describe("node-diff3 pinned conflict criterion (diff3Merge, line-based)", () => {
  const conflicts = (local: string, base: string, remote: string) =>
    diff3Merge(lines(local), lines(base), lines(remote), { excludeFalseConflicts: true }).some((r) => r.conflict);

  it("overlapping edits (same line changed differently) → conflict", () => {
    expect(conflicts("a\nX\nc\nd\ne", BASE, "a\nY\nc\nd\ne")).toBe(true);
  });
  it("adjacent edits (touching lines b and c) → conflict", () => {
    expect(conflicts("a\nX\nc\nd\ne", BASE, "a\nb\nY\nd\ne")).toBe(true);
  });
  it("edits separated by one unchanged line → clean", () => {
    expect(conflicts("a\nX\nc\nd\ne", BASE, "a\nb\nc\nY\ne")).toBe(false);
  });
  it("deletion next to an insertion → conflict (both orders of the neighbouring line)", () => {
    expect(conflicts("a\nc\nd\ne", BASE, "a\nb\nNEW\nc\nd\ne")).toBe(true); // delete b, insert after b
    expect(conflicts("a\nb\nd\ne", BASE, "a\nb\nNEW\nc\nd\ne")).toBe(true); // delete c, insert before c
  });
  it("both sides delete adjacent lines → conflict", () => {
    expect(conflicts("a\nc\nd\ne", BASE, "a\nb\nd\ne")).toBe(true);
  });
  it("different insertions at the same point → conflict", () => {
    expect(conflicts("a\nX\nb\nc\nd\ne", BASE, "a\nY\nb\nc\nd\ne")).toBe(true);
  });
  it("identical edits on both sides → clean (false conflict excluded)", () => {
    expect(conflicts("a\nX\nc\nd\ne", BASE, "a\nX\nc\nd\ne")).toBe(false);
    expect(conflicts("a\nc\nd\ne", BASE, "a\nc\nd\ne")).toBe(false);
  });
  it("one-sided edit → clean", () => {
    expect(conflicts("a\nX\nc\nd\ne", BASE, BASE)).toBe(false);
    expect(conflicts(BASE, BASE, "a\nX\nc\nd\ne")).toBe(false);
  });
  it("empty base, different content on both sides → conflict", () => {
    expect(conflicts("x", "", "y")).toBe(true);
  });
  it("empty base, same content on both sides → clean", () => {
    expect(conflicts("x", "", "x")).toBe(false);
  });
  it("all empty → clean", () => {
    expect(conflicts("", "", "")).toBe(false);
  });
  it("one side empties the file, the other edits it → conflict", () => {
    expect(conflicts("", BASE, "a\nX\nc\nd\ne")).toBe(true);
  });

  // Question 415: two replicas editing different lines of the same note. Only lines that are not
  // adjacent merge; adjacency at the start, at the end and around the final newline is a conflict.
  it("first and last lines → clean; first and second, or the last two → conflict", () => {
    expect(conflicts("X\nb\nc\nd\ne", BASE, "a\nb\nc\nd\nY")).toBe(false);
    expect(conflicts("X\nb\nc\nd\ne", BASE, "a\nY\nc\nd\ne")).toBe(true);
    expect(conflicts("a\nb\nc\nX\ne", BASE, "a\nb\nc\nd\nY")).toBe(true);
  });
  it("appending a line after the last one, while the other side edits the last line → conflict", () => {
    expect(conflicts("a\nb\nc\nd\ne\nf", BASE, "a\nb\nc\nd\nY")).toBe(true);
    expect(conflicts("a\nb\nc\nd\ne\nf", BASE, "X\nb\nc\nd\ne")).toBe(false); // far from the append → clean
    expect(conflicts("z\na\nb\nc\nd\ne", BASE, "X\nb\nc\nd\ne")).toBe(true); // prepend next to an edit of the first line
  });
  it("inserting a line between two lines, while the other side edits the line above → conflict", () => {
    expect(conflicts("a\nb\nNEW\nc\nd\ne", BASE, "a\nX\nc\nd\ne")).toBe(true);
  });
  it("a final newline added or removed is a change of the (empty) last line: adjacent to an edit of the last line", () => {
    expect(conflicts(BASE, `${BASE}\n`, "X\nb\nc\nd\ne\n")).toBe(false); // removed, the other side edits the first line
    expect(conflicts(BASE, `${BASE}\n`, "a\nb\nc\nd\nY\n")).toBe(true); // removed, the other side edits the last line
    expect(conflicts(`${BASE}\n`, BASE, "a\nb\nc\nd\nY")).toBe(true); // added, the other side edits the last line
  });
  it("paragraphs separated by a blank line → clean", () => {
    expect(conflicts("P1\n\np2", "p1\n\np2", "p1\n\nP2")).toBe(false);
  });
  it("CRLF on both sides behaves like LF; one side rewritten to LF changes every line → conflict", () => {
    const crlf = "a\r\nb\r\nc\r\nd\r\ne\r\n";
    expect(conflicts("X\r\nb\r\nc\r\nd\r\ne\r\n", crlf, "a\r\nb\r\nc\r\nd\r\nY\r\n")).toBe(false);
    expect(conflicts("X\r\nb\r\nc\r\nd\r\ne\r\n", crlf, "a\nb\nc\nd\nY\n")).toBe(true);
  });
});

describe("merge3 policy (§17, §12.2 rule 4)", () => {
  it("resolves non-overlapping edits keeping both", () => {
    expect(merge3(BASE, "a\nX\nc\nd\ne", "a\nb\nc\nY\ne")).toEqual({ kind: "resolved", text: "a\nX\nc\nY\ne" });
  });
  it("overlapping hunks → conflict, never a text with markers", () => {
    expect(merge3(BASE, "a\nX\nc\nd\ne", "a\nY\nc\nd\ne")).toEqual({ kind: "conflict" });
  });
  it("adjacent edits → conflict (conservative, pinned library behavior)", () => {
    expect(merge3(BASE, "a\nX\nc\nd\ne", "a\nb\nY\nd\ne")).toEqual({ kind: "conflict" });
  });
  it("deletion next to insertion → conflict", () => {
    expect(merge3(BASE, "a\nc\nd\ne", "a\nb\nNEW\nc\nd\ne")).toEqual({ kind: "conflict" });
  });
  it("identical edits → resolved to that edit", () => {
    expect(merge3(BASE, "a\nX\nc\nd\ne", "a\nX\nc\nd\ne")).toEqual({ kind: "resolved", text: "a\nX\nc\nd\ne" });
  });
  it("empty files", () => {
    expect(merge3("", "", "")).toEqual({ kind: "resolved", text: "" });
    expect(merge3("", "x", "")).toEqual({ kind: "resolved", text: "x" });
    expect(merge3("", "x", "y")).toEqual({ kind: "conflict" });
  });
  it("different, non-adjacent lines of the same note → both kept (Q415)", () => {
    const note = "# Title\n\nline 3\nline 4\nline 5\n";
    expect(merge3(note, "# Title!\n\nline 3\nline 4\nline 5\n", "# Title\n\nline 3\nline 4\nline 5 edited\n")).toEqual({
      kind: "resolved",
      text: "# Title!\n\nline 3\nline 4\nline 5 edited\n",
    });
    expect(merge3(note, "# Title\n\nline 3\nline 4\nline 5 edited\n", "# Title!\n\nline 3\nline 4\nline 5\n")).toEqual({
      kind: "resolved",
      text: "# Title!\n\nline 3\nline 4\nline 5 edited\n",
    });
  });
  it("consecutive lines → conflict (the pinned criterion, stricter than §17.1's 'mismo tramo'; Q415)", () => {
    expect(merge3("l1\nl2\nl3\n", "l1 edited\nl2\nl3\n", "l1\nl2 edited\nl3\n")).toEqual({ kind: "conflict" });
  });
  it("preserves trailing newlines and CRLF bytes exactly", () => {
    expect(merge3("a\r\nb\r\n", "a\r\nb\r\n", "a\r\nB\r\n")).toEqual({ kind: "resolved", text: "a\r\nB\r\n" });
    expect(merge3("a\n", "a\n", "a")).toEqual({ kind: "resolved", text: "a" });
  });
});

// Small alphabets so the generator produces identical lines, empty files and overlaps.
const text = fc.array(fc.constantFrom("a", "b", "c", "", "x"), { maxLength: 6 }).map((ls) => ls.join("\n"));

/** Algebraic laws every correct merge policy must satisfy. */
function mergeLaws(merge: typeof merge3) {
  return fc.property(text, text, text, (base, local, remote) => {
    // One-sided changes are taken as-is (no silent data loss, no invented content).
    expect(merge(base, local, base)).toEqual({ kind: "resolved", text: local });
    expect(merge(base, base, remote)).toEqual({ kind: "resolved", text: remote });
    // Identical changes resolve to that change.
    expect(merge(base, local, local)).toEqual({ kind: "resolved", text: local });
    // Conflict status does not depend on which side is local.
    expect(merge(base, local, remote).kind).toBe(merge(base, remote, local).kind);
    const r = merge(base, local, remote);
    if (r.kind === "resolved") expect(r.text).not.toMatch(/^(<<<<<<<|=======|>>>>>>>)/m);
  });
}

describe("merge3 properties", () => {
  it("satisfies the merge laws", () => {
    fc.assert(mergeLaws(merge3), { numRuns: 2000 });
  });

  it("evidence: the laws detect a merge that drops the local side", () => {
    const loseLocal: typeof merge3 = (base, _local, remote) => merge3(base, base, remote);
    expect(() => fc.assert(mergeLaws(loseLocal), { numRuns: 2000 })).toThrow();
  });

  it("evidence: the laws detect a merge that emits conflict markers", () => {
    const markers: typeof merge3 = (base, local, remote) => {
      const r = merge3(base, local, remote);
      return r.kind === "conflict" ? { kind: "resolved", text: `<<<<<<<\n${local}\n=======\n${remote}\n>>>>>>>` } : r;
    };
    expect(() => fc.assert(mergeLaws(markers), { numRuns: 2000 })).toThrow();
  });
});
