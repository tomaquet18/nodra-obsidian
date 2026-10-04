// NCE — Nodra Canonical Encoding (§23.2): deterministic CBOR (RFC 8949 §4.2.1) restricted to
// uint/negint, byte strings, NFC text, definite arrays, maps with uint keys, true/false/null.
// cborg does the CBOR work; this file only adds the NCE restrictions.
import { Tokenizer, Type, decodeFirst, encode as cborEncode } from "cborg";
import type { DecodeOptions } from "cborg";
import type { DecodeTokenizer } from "cborg/interface";
import { toNFC } from "@nodra/path-projection";

/** Integers: `number` when safe, `bigint` otherwise (decode always returns this canonical form). */
export type NceInt = number | bigint;
export type NceMap = ReadonlyMap<number, NceValue>;
export type NceArray = readonly NceValue[];
export type NceValue = NceInt | Uint8Array | string | boolean | null | NceArray | NceMap;

export type NceKind = "int" | "bytes" | "text" | "bool" | "null" | "array" | "map";

export type NceErrorCode =
  | "MALFORMED" // not well-formed CBOR (truncated, reserved additional info, empty input)
  | "TRAILING_BYTES"
  | "NON_MINIMAL" // integer or length not in its shortest form
  | "INDEFINITE_LENGTH"
  | "FORBIDDEN_TYPE" // float, tag, undefined, simple value other than false/true/null
  | "INVALID_UTF8"
  | "NOT_NFC"
  | "KEY_NOT_UINT"
  | "KEY_OUT_OF_RANGE" // uint key above Number.MAX_SAFE_INTEGER (NOTES Q160)
  | "UNSORTED_KEYS"
  | "DUPLICATE_KEY"
  | "NON_CANONICAL" // safety net: parsed, but re-encoding differs
  | "INVALID_VALUE" // encode: not an NCE value
  | "INT_OUT_OF_RANGE"; // encode: integer outside [-2^64, 2^64-1]

export class NceError extends Error {
  readonly code: NceErrorCode;
  constructor(code: NceErrorCode, detail: string) {
    super(`NCE ${code}: ${detail}`);
    this.name = "NceError";
    this.code = code;
  }
}

const UINT64_MAX = 2n ** 64n - 1n;
const NEGINT64_MIN = -(2n ** 64n);
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Classifies a JS value as an NCE kind, or returns undefined if it is not one. Shallow. */
export function kindOf(v: unknown): NceKind | undefined {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return "bool";
    case "string":
      return "text";
    case "bigint":
      return v >= NEGINT64_MIN && v <= UINT64_MAX ? "int" : undefined;
    case "number":
      return Number.isSafeInteger(v) && !Object.is(v, -0) ? "int" : undefined;
    case "object":
      if (v instanceof Uint8Array) return "bytes";
      if (Array.isArray(v)) return "array";
      if (v instanceof Map) return "map";
      return undefined;
    default:
      return undefined;
  }
}

function isUintKey(k: unknown): k is number {
  return typeof k === "number" && Number.isSafeInteger(k) && k >= 0 && !Object.is(k, -0);
}

function checkText(s: string): void {
  if (LONE_SURROGATE.test(s)) throw new NceError("INVALID_UTF8", "text contains a lone surrogate");
  // Pinned Unicode tables (ADR-013): the verdict must not depend on the runtime's Unicode version.
  if (toNFC(s) !== s) throw new NceError("NOT_NFC", "text is not in NFC");
}

function assertEncodable(v: unknown, ancestors: Set<object>): void {
  const kind = kindOf(v);
  if (kind === undefined) {
    if (typeof v === "bigint") throw new NceError("INT_OUT_OF_RANGE", `integer ${v} outside [-2^64, 2^64-1]`);
    const shown = typeof v === "number" ? String(Object.is(v, -0) ? "-0" : v) : typeof v;
    throw new NceError("INVALID_VALUE", `not an NCE value (${shown})`);
  }
  if (kind === "text") checkText(v as string);
  if (kind !== "array" && kind !== "map") return;
  const container = v as NceArray | NceMap;
  if (ancestors.has(container)) throw new NceError("INVALID_VALUE", "circular structure");
  ancestors.add(container);
  if (kind === "array") {
    for (const item of container as NceArray) assertEncodable(item, ancestors);
  } else {
    for (const [k, item] of container as NceMap) {
      if (!isUintKey(k)) throw new NceError("KEY_NOT_UINT", `map key ${String(k)} is not a safe uint`);
      assertEncodable(item, ancestors);
    }
  }
  ancestors.delete(container);
}

/** Encodes an NCE value. Throws NceError if the value is outside the NCE subset. */
export function encode(value: NceValue): Uint8Array {
  assertEncodable(value, new Set());
  // cborg's default encode options are RFC 8949 §4.2.1: shortest forms, bytewise-sorted map keys.
  return cborEncode(value);
}

// cborg options; the tokenizer below rejects everything these would otherwise let through.
const CBORG_OPTIONS: DecodeOptions = {
  strict: true,
  useMaps: true,
  rejectDuplicateMapKeys: true,
  allowIndefinite: false,
  allowUndefined: false,
  allowInfinity: false,
  allowNaN: false,
  allowBigInt: true,
  retainStringBytes: true,
  tags: [],
};

// fatal: invalid UTF-8 throws instead of becoming U+FFFD. ignoreBOM: keep a leading U+FEFF.
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function checkInitialByte(b: number): void {
  const major = b >>> 5;
  const minor = b & 31;
  if (major === 6) throw new NceError("FORBIDDEN_TYPE", "tag");
  if (major === 7) {
    if (minor >= 20 && minor <= 22) return;
    if (minor >= 25 && minor <= 27) throw new NceError("FORBIDDEN_TYPE", "float");
    if (minor === 31) throw new NceError("INDEFINITE_LENGTH", "break");
    if (minor >= 28) throw new NceError("MALFORMED", `reserved initial byte 0x${b.toString(16)}`);
    throw new NceError("FORBIDDEN_TYPE", "simple value");
  }
  if (minor === 31) throw new NceError("INDEFINITE_LENGTH", `major type ${major}`);
  if (minor >= 28) throw new NceError("MALFORMED", `reserved initial byte 0x${b.toString(16)}`);
}

/** cborg's tokenizer, with every token's initial byte and every text string checked first. */
function nceTokenizer(data: Uint8Array): DecodeTokenizer {
  const inner = new Tokenizer(data, CBORG_OPTIONS);
  return {
    done: () => inner.done(),
    pos: () => inner.pos(),
    next: () => {
      const initial = data[inner.pos()];
      if (initial === undefined) throw new NceError("MALFORMED", "unexpected end of input");
      checkInitialByte(initial);
      const token = inner.next();
      if (token.type === Type.string) {
        // cborg shares one pre-built token for the empty string (0x60) and retains no bytes for it.
        const raw = token.byteValue ?? (initial === 0x60 ? new Uint8Array(0) : undefined);
        if (raw === undefined) throw new NceError("MALFORMED", "text bytes not retained");
        let text: string;
        try {
          text = utf8.decode(raw);
        } catch {
          throw new NceError("INVALID_UTF8", "text is not valid UTF-8");
        }
        checkText(text);
        token.value = text;
      }
      return token;
    },
  };
}

function fromCborgError(e: unknown): NceError {
  if (e instanceof NceError) return e;
  const message = e instanceof Error ? e.message : String(e);
  if (message.includes("more bytes than necessary")) return new NceError("NON_MINIMAL", message);
  if (message.includes("repeat map key")) return new NceError("DUPLICATE_KEY", message);
  return new NceError("MALFORMED", message);
}

// Checks map keys and rebuilds the value: cborg returns Node Buffers (views into the input) for
// some byte strings, so bytes are copied into plain Uint8Arrays that do not alias the input.
function finish(v: unknown, checkKeyOrder: boolean): NceValue {
  if (v instanceof Uint8Array) return new Uint8Array(v);
  if (Array.isArray(v)) return v.map((item) => finish(item, checkKeyOrder));
  if (!(v instanceof Map)) return v as NceValue;
  const out = new Map<number, NceValue>();
  let previous = -1;
  for (const [k, item] of v) {
    if (typeof k === "bigint" && k >= 0n) throw new NceError("KEY_OUT_OF_RANGE", `map key ${k}`);
    if (!isUintKey(k)) throw new NceError("KEY_NOT_UINT", "map key is not a uint");
    // Uint keys: bytewise order of the encoded key equals numeric order.
    if (checkKeyOrder && k <= previous) throw new NceError("UNSORTED_KEYS", `key ${k} after ${previous}`);
    previous = k;
    out.set(k, finish(item, checkKeyOrder));
  }
  return out;
}

/**
 * Parses with every specific NCE check but without the final re-encoding comparison.
 * Exported for tests only (strictness proof); production code uses `decode`.
 * `checkKeyOrder = false` exists only to prove the tests catch a lenient decoder.
 */
export function parse(bytes: Uint8Array, checkKeyOrder = true): NceValue {
  let value: unknown;
  let rest: Uint8Array;
  try {
    [value, rest] = decodeFirst(bytes, { ...CBORG_OPTIONS, tokenizer: nceTokenizer(bytes) }) as [unknown, Uint8Array];
  } catch (e) {
    throw fromCborgError(e);
  }
  if (rest.length > 0) throw new NceError("TRAILING_BYTES", `${rest.length} bytes after the value`);
  return finish(value, checkKeyOrder);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Decodes NCE bytes. Rejects (NceError) any input that does not re-encode to exactly the same bytes. */
export function decode(bytes: Uint8Array): NceValue {
  const value = parse(bytes);
  if (!sameBytes(encode(value), bytes)) throw new NceError("NON_CANONICAL", "re-encoding differs from input");
  return value;
}
