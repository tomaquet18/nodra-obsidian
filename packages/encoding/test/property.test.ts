import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { toNFC } from "@nodra/path-projection";
import { NceError, decode, encode } from "../src/index.js";
import type { NceValue } from "../src/index.js";
import { parse } from "../src/nce.js";
import { canonicalInt, fromHex, vectors } from "./support.js";

const RUNS = 2000;

const boundaryInts = [0, 23, 24, 255, 256, 65535, 65536, 2 ** 32 - 1, 2 ** 32, Number.MAX_SAFE_INTEGER]
  .flatMap((n) => [BigInt(n), -BigInt(n) - 1n])
  .concat([2n ** 53n, -(2n ** 53n) - 1n, 2n ** 64n - 1n, -(2n ** 64n)]);

const int = fc.oneof(
  fc.integer(),
  fc.maxSafeInteger(),
  fc.bigInt({ min: -(2n ** 64n), max: 2n ** 64n - 1n }).map(canonicalInt),
  fc.constantFrom(...boundaryInts).map(canonicalInt),
);

// Uncomfortable text too: combining marks, Hangul jamo, a leading BOM, NUL, astral characters.
const text = fc
  .oneof(
    fc.string({ unit: "grapheme" }),
    fc.string({ unit: "binary" }),
    fc.constantFrom("é", "한", "﻿", "\u0000", "Å", "\u{1F600}", "a".repeat(24)),
  )
  .map((s) => toNFC(s));

const key = fc.oneof(fc.nat(30), fc.constantFrom(23, 24, 255, 256, 65535, 65536, 2 ** 32, Number.MAX_SAFE_INTEGER));

const { value } = fc.letrec<{ value: NceValue }>((tie) => ({
  value: fc.oneof(
    { depthSize: "small", withCrossShrink: true },
    int,
    fc.uint8Array({ maxLength: 40 }),
    text,
    fc.boolean(),
    fc.constant(null),
    fc.array(tie("value"), { maxLength: 5 }),
    fc.uniqueArray(fc.tuple(key, tie("value")), { selector: ([k]) => k, maxLength: 5 }).map((es) => new Map(es)),
  ),
}));

/** The same value with every map's insertion order permuted (rotation by `shift`, then reversal). */
function reorder(v: NceValue, shift: number): NceValue {
  if (Array.isArray(v)) return v.map((x) => reorder(x, shift));
  if (!(v instanceof Map)) return v;
  const entries = [...v].map(([k, x]) => [k, reorder(x, shift)] as const);
  const s = entries.length === 0 ? 0 : shift % entries.length;
  return new Map([...entries.slice(s), ...entries.slice(0, s)].reverse());
}

type Mutation = { kind: "set" | "insert" | "delete" | "truncate"; at: number; byte: number };
const mutation = fc.record({
  kind: fc.constantFrom("set", "insert", "delete", "truncate"),
  at: fc.nat(),
  byte: fc.oneof(fc.integer({ min: 0, max: 255 }), fc.constantFrom(0x18, 0x19, 0x1f, 0x5f, 0x7f, 0x9f, 0xbf, 0xf7, 0xf9, 0xff, 0xc0)),
}) as fc.Arbitrary<Mutation>;

function mutate(bytes: Uint8Array, ms: Mutation[]): Uint8Array {
  let b = Array.from(bytes);
  for (const m of ms) {
    const at = b.length === 0 ? 0 : m.at % (b.length + 1);
    if (m.kind === "set" && at < b.length) b[at] = m.byte;
    else if (m.kind === "insert") b.splice(at, 0, m.byte);
    else if (m.kind === "delete") b.splice(at, 1);
    else if (m.kind === "truncate") b = b.slice(0, at);
  }
  return Uint8Array.from(b);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** Strictness (§23.2): the parser either rejects the input or returns a value that re-encodes to it. */
function strict(decodeFn: (b: Uint8Array) => NceValue, input: Uint8Array): boolean {
  let v: NceValue;
  try {
    v = decodeFn(input);
  } catch (e) {
    if (e instanceof NceError) return true;
    throw e;
  }
  return sameBytes(encode(v), input);
}

/** A map encoding with its entries written in reverse order (unsorted keys), built from NCE pieces. */
const unsortedMapBytes = fc
  .uniqueArray(fc.tuple(key, value), { selector: ([k]) => k, minLength: 2, maxLength: 5 })
  .map((es) => {
    const pieces = [...es].sort(([a], [b]) => a - b).map(([k, v]) => [...encode(k), ...encode(v)]);
    const whole = encode(new Map(es));
    const header = whole.slice(0, whole.length - pieces.reduce((n, p) => n + p.length, 0));
    return Uint8Array.from([...header, ...pieces.reverse().flat()]);
  });

describe("NCE properties (fast-check)", () => {
  it("round-trip: decode(encode(v)) equals v", () => {
    fc.assert(fc.property(value, (v) => void expect(decode(encode(v))).toEqual(v)), { numRuns: RUNS });
  });

  it("determinism: the bytes do not depend on map insertion order", () => {
    fc.assert(
      fc.property(value, fc.nat(10), (v, shift) => sameBytes(encode(reorder(v, shift)), encode(v))),
      { numRuns: RUNS },
    );
  });

  it("strictness under byte mutations, with the specific checks alone (no re-encoding safety net)", () => {
    fc.assert(
      fc.property(value, fc.array(mutation, { minLength: 1, maxLength: 3 }), (v, ms) => strict(parse, mutate(encode(v), ms))),
      { numRuns: RUNS * 5 },
    );
  });

  it("strictness under byte mutations, full decoder", () => {
    fc.assert(
      fc.property(value, fc.array(mutation, { minLength: 1, maxLength: 3 }), (v, ms) => strict(decode, mutate(encode(v), ms))),
      { numRuns: RUNS },
    );
  });

  it("maps with unsorted keys are rejected as UNSORTED_KEYS", () => {
    fc.assert(
      fc.property(unsortedMapBytes, (b) => {
        expect(() => parse(b)).toThrow(expect.objectContaining({ code: "UNSORTED_KEYS" }));
      }),
      { numRuns: RUNS },
    );
  });
});

describe("broken variant: a decoder that accepts unsorted keys", () => {
  const lenient = (b: Uint8Array) => parse(b, false);

  it("fails the strictness property", () => {
    expect(() => fc.assert(fc.property(unsortedMapBytes, (b) => strict(lenient, b)), { numRuns: 200 })).toThrow(
      /Property failed/,
    );
  });

  it("accepts every UNSORTED_KEYS negative vector", () => {
    const unsorted = vectors.negative.filter((n) => n.error === "UNSORTED_KEYS");
    expect(unsorted.length).toBeGreaterThan(0);
    for (const n of unsorted) expect(() => lenient(fromHex(n.hex))).not.toThrow();
  });
});
