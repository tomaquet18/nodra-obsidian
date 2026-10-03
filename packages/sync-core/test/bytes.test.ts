import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { bytesEqual, bytesStartWith } from "../src/bytes.js";
import { isMergeablePath } from "../src/merge.js";

// Content is bytes (types.ts `Content`); these comparisons replace string equality everywhere.

const b = (...xs: number[]) => Uint8Array.from(xs);

describe("byte comparisons", () => {
  it("equality is by value, never by reference", () => {
    expect(bytesEqual(b(0, 255), b(0, 255))).toBe(true);
    expect(bytesEqual(b(0, 255), b(0, 254))).toBe(false);
    expect(bytesEqual(b(), b())).toBe(true);
    expect(bytesEqual(b(1), b(1, 0))).toBe(false);
  });

  it("prefix: the empty content and the whole content are prefixes; a longer or different one is not", () => {
    expect(bytesStartWith(b(1, 2, 3), b())).toBe(true);
    expect(bytesStartWith(b(1, 2, 3), b(1, 2))).toBe(true);
    expect(bytesStartWith(b(1, 2, 3), b(1, 2, 3))).toBe(true);
    expect(bytesStartWith(b(1, 2), b(1, 2, 3))).toBe(false);
    expect(bytesStartWith(b(1, 2, 3), b(2))).toBe(false);
  });

  it("properties: equality agrees with element-wise comparison; every slice from 0 is a prefix", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 20 }), fc.uint8Array({ maxLength: 20 }), fc.nat(20), (x, y, n) => {
        expect(bytesEqual(x, y)).toBe(x.join() === y.join());
        expect(bytesStartWith(x, x.subarray(0, n))).toBe(true);
        expect(bytesStartWith(x, y)).toBe(y.length <= x.length && x.subarray(0, y.length).join() === y.join());
      }),
    );
  });
});

describe("isMergeablePath (§17 'ambas ramas son texto')", () => {
  it("Markdown only, case-insensitive; attachments and other text formats are binary", () => {
    for (const p of ["a.md", "d/B.MD", "x.Md", "nodra-recuperado-00ff.md"]) expect(isMergeablePath(p), p).toBe(true);
    for (const p of ["img.png", "doc.pdf", "a.canvas", "a.txt", "md", "a.md.png", "nodra-tmp-0123abcd", "a.markdown"]) expect(isMergeablePath(p), p).toBe(false);
  });
});
