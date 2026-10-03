import { describe, expect, it } from "vitest";
import { CONTEXT_VERSION, NCE_DOMAINS, NceError, context, decode, encode } from "../src/index.js";
import type { NceErrorCode, NceValue } from "../src/index.js";
import { parse } from "../src/nce.js";
import { fromHex, fromJson, toHex, vectors } from "./support.js";

function errorCode(f: () => unknown): NceErrorCode | "NO_ERROR" | "OTHER_ERROR" {
  try {
    f();
    return "NO_ERROR";
  } catch (e) {
    return e instanceof NceError ? e.code : "OTHER_ERROR";
  }
}

describe("positive vectors (vectors/nce.json)", () => {
  it.each(vectors.positive)("$name", ({ value, hex }) => {
    const v = fromJson(value);
    expect(toHex(encode(v))).toBe(hex);
    const decoded = decode(fromHex(hex));
    expect(decoded).toEqual(v);
    expect(toHex(encode(decoded))).toBe(hex);
  });
});

describe("negative vectors (vectors/nce.json)", () => {
  it.each(vectors.negative)("$name → $error", ({ hex, error }) => {
    expect(errorCode(() => decode(fromHex(hex)))).toBe(error);
    // The specific checks catch it; the final re-encoding comparison is only a safety net.
    expect(errorCode(() => parse(fromHex(hex)))).toBe(error);
  });

  it("covers every decode error code except the safety net", () => {
    const codes = new Set(vectors.negative.map((n) => n.error));
    const expected: NceErrorCode[] = [
      "MALFORMED", "TRAILING_BYTES", "NON_MINIMAL", "INDEFINITE_LENGTH", "FORBIDDEN_TYPE", "INVALID_UTF8",
      "NOT_NFC", "KEY_NOT_UINT", "KEY_OUT_OF_RANGE", "UNSORTED_KEYS", "DUPLICATE_KEY",
    ];
    expect([...codes].sort()).toEqual([...expected].sort());
  });
});

describe("context vectors (§23.3)", () => {
  it.each(vectors.contexts)("$name", ({ domain, fields, hex }) => {
    const bytes = context(domain, ...fields.map(fromJson));
    expect(toHex(bytes)).toBe(hex);
    expect(decode(bytes)).toEqual([domain, CONTEXT_VERSION, ...fields.map(fromJson)]);
  });

  it("lists the 23 crypto_version 1 domains, the 2 of crypto_version 2 and ADR-022's, all distinct", () => {
    expect(NCE_DOMAINS.length).toBe(26);
    expect(new Set(NCE_DOMAINS).size).toBe(26);
    // §23.3 spells the ADR-022 domain so; the signed bytes of every request, veto and cancel depend on it.
    expect(NCE_DOMAINS).toContain("nodra/recovery-request");
    // §23.3 names the two ADR-021 domains exactly so; the Context bytes depend on the spelling.
    expect(NCE_DOMAINS).toContain("nodra/escrow");
    expect(NCE_DOMAINS).toContain("nodra/escrow-rewrap");
  });

  it("separates domains: same fields, different domain → different bytes", () => {
    const blob = fromHex("0190f1a2b3c47d5e8f60718293a4b5c8");
    expect(toHex(context("nodra/hkdf/content", blob))).not.toBe(toHex(context("nodra/hkdf/manifest", blob)));
  });
});

describe("encode rejects values outside NCE", () => {
  const cases: [string, unknown, NceErrorCode][] = [
    ["float", 1.5, "INVALID_VALUE"],
    ["NaN", Number.NaN, "INVALID_VALUE"],
    ["Infinity", Number.POSITIVE_INFINITY, "INVALID_VALUE"],
    ["negative zero", -0, "INVALID_VALUE"],
    ["unsafe number", 2 ** 53, "INVALID_VALUE"],
    ["undefined", undefined, "INVALID_VALUE"],
    ["plain object", { 1: 2 }, "INVALID_VALUE"],
    ["Set", new Set([1]), "INVALID_VALUE"],
    ["Int8Array", new Int8Array(2), "INVALID_VALUE"],
    ["DataView", new DataView(new ArrayBuffer(2)), "INVALID_VALUE"],
    ["function", () => 1, "INVALID_VALUE"],
    ["symbol", Symbol("x"), "INVALID_VALUE"],
    ["bigint 2^64", 2n ** 64n, "INT_OUT_OF_RANGE"],
    ["bigint -2^64-1", -(2n ** 64n) - 1n, "INT_OUT_OF_RANGE"],
    ["non-NFC text", "é", "NOT_NFC"],
    ["non-NFC text nested in a map", new Map([[1, ["Å"]]]), "NOT_NFC"],
    ["lone high surrogate", "a\uD800", "INVALID_UTF8"],
    ["lone low surrogate", "\uDC00b", "INVALID_UTF8"],
    ["text map key", new Map([["a", 1]]), "KEY_NOT_UINT"],
    ["negative map key", new Map([[-1, 1]]), "KEY_NOT_UINT"],
    ["float map key", new Map([[1.5, 1]]), "KEY_NOT_UINT"],
    ["bigint map key", new Map([[1n, 1]]), "KEY_NOT_UINT"],
    ["unsafe map key", new Map([[2 ** 53, 1]]), "KEY_NOT_UINT"],
    ["undefined inside an array", [1, undefined], "INVALID_VALUE"],
  ];
  it.each(cases)("%s", (_name, value, code) => {
    expect(errorCode(() => encode(value as NceValue))).toBe(code);
  });

  it("circular structure", () => {
    const a: NceValue[] = [];
    a.push(a);
    expect(errorCode(() => encode(a))).toBe("INVALID_VALUE");
  });

  it("the same array twice (not circular) is fine", () => {
    const shared = [1];
    expect(toHex(encode([shared, shared]))).toBe("82810181" + "01");
  });

  it("a Uint8Array subclass encodes like a Uint8Array; decode copies the bytes", () => {
    const input = fromHex("4401020304");
    expect(toHex(encode(Buffer.from([1, 2, 3, 4])))).toBe("4401020304");
    const decoded = decode(input) as Uint8Array;
    input[1] = 9;
    expect(toHex(decoded)).toBe("01020304");
  });

  it("bug (envelope-set vector): decoded bytes of a longer input are plain Uint8Arrays, not views into it", () => {
    // cborg returned Node Buffers sharing memory with the input once the input was long enough.
    const input = encode([new Uint8Array(200).fill(7), new Uint8Array(16).fill(1)]);
    const decoded = decode(input) as Uint8Array[];
    input.fill(0);
    for (const b of decoded) expect(b.constructor).toBe(Uint8Array);
    expect(decoded[0]!.every((x) => x === 7)).toBe(true);
    expect(decoded[1]!.every((x) => x === 1)).toBe(true);
  });
});
