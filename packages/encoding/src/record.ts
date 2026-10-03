// Table-driven NCE record codecs (§23.4): a schema names each field, its frozen uint key and its
// exact type. NCE (§23.2) already guarantees canonical bytes, unique ascending map keys and NFC
// text; this layer adds the schema-level rules of §23.4 that the codec alone cannot know:
// fixed byte lengths, uint ranges, SCREAMING_SNAKE_CASE enum values, role collections ordered by
// code, and "a field that does not apply is omitted, never null".
import { decode as nceDecode, encode as nceEncode } from "./nce.js";
import type { NceValue } from "./nce.js";

export type RecordErrorCode =
  | "NOT_A_MAP" // the value (or a nested record) is not an NCE map
  | "UNKNOWN_KEY" // a map key outside the frozen key table
  | "UNKNOWN_FIELD" // encode: an object property outside the frozen key table
  | "MISSING_FIELD" // a required field is absent
  | "WRONG_TYPE"
  | "WRONG_LENGTH" // bytes(16) / bytes(32) / bytes(64) violated
  | "NULL_NOT_ALLOWED" // null where §23.4 requires omission or a value
  | "INVALID_ENUM"
  | "UNKNOWN_ROLE" // role code outside the frozen set of the collection
  | "UNSORTED_ROLES" // role pairs not in strictly increasing code order
  | "BAD_ROLE_PAIR" // a role element that is not [uint code, value]
  | "INT_NOT_SAFE"; // uint above Number.MAX_SAFE_INTEGER (NOTES Q173)

export class RecordError extends Error {
  readonly code: RecordErrorCode;
  readonly path: string;
  constructor(code: RecordErrorCode, path: string, detail: string) {
    super(`record ${code} at ${path}: ${detail}`);
    this.name = "RecordError";
    this.code = code;
    this.path = path;
  }
}

export type FieldKind = "bytes" | "uint" | "text" | "enum" | "bool" | "nullable" | "array" | "record" | "roles";

/**
 * One field type. `decode` and `encode` apply exactly the same checks in both directions, so a
 * value that encodes is a value that decodes back. The extra properties are introspection used by
 * the vector loader and the fast-check arbitraries; they are never read by production code.
 */
export interface Field<T> {
  readonly kind: FieldKind;
  readonly decode: (v: NceValue, at: string) => T;
  readonly encode: (t: T, at: string) => NceValue;
  readonly byteLength?: number;
  readonly enumValues?: readonly string[];
  readonly inner?: AnyField;
  readonly schema?: AnyRecordSchema;
  readonly roleCodes?: readonly number[];
}

// `any` is the erasure used where a field's own type is irrelevant (introspection, nesting).
export type AnyField = Field<any>;

/** A schema with its field types erased, for code that walks any record (vectors, arbitraries). */
export interface AnyRecordSchema {
  readonly name: string;
  readonly fields: { readonly [name: string]: AnyEntry };
  readonly order: readonly string[];
}

function notNull(v: NceValue, at: string): void {
  if (v === null) throw new RecordError("NULL_NOT_ALLOWED", at, "null where §23.4 requires a value or omission");
}

/** `bytes(n)` of §23.2 when `length` is given (ids 16, hashes 32, signatures 64); variable otherwise. */
export function bytes(length?: number): Field<Uint8Array> {
  const check = (v: unknown, at: string): Uint8Array => {
    notNull(v as NceValue, at);
    if (!(v instanceof Uint8Array)) throw new RecordError("WRONG_TYPE", at, "expected a byte string");
    if (length !== undefined && v.length !== length)
      throw new RecordError("WRONG_LENGTH", at, `expected ${length} bytes, got ${v.length}`);
    return v;
  };
  return length === undefined
    ? { kind: "bytes", decode: check, encode: check }
    : { kind: "bytes", byteLength: length, decode: check, encode: check };
}

/** Unsigned integer. Rejects bigint: every §23.4 uint field fits in a JS safe integer (Q173). */
export const uint: Field<number> = {
  kind: "uint",
  decode: checkUint,
  encode: checkUint,
};

function checkUint(v: unknown, at: string): number {
  notNull(v as NceValue, at);
  if (typeof v === "bigint") throw new RecordError("INT_NOT_SAFE", at, `uint ${v} above Number.MAX_SAFE_INTEGER`);
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0 || Object.is(v, -0))
    throw new RecordError("WRONG_TYPE", at, "expected a non-negative safe integer");
  return v;
}

/** Text (NFC and valid UTF-8 are already guaranteed by NCE). */
export const text: Field<string> = {
  kind: "text",
  decode: checkText,
  encode: checkText,
};

function checkText(v: unknown, at: string): string {
  notNull(v as NceValue, at);
  if (typeof v !== "string") throw new RecordError("WRONG_TYPE", at, "expected text");
  return v;
}

/** Enumeration: text in `SCREAMING_SNAKE_CASE`, as a value and never as a map key (§23.2). */
export function enumOf<const V extends readonly string[]>(values: V): Field<V[number]> {
  const check = (v: unknown, at: string): V[number] => {
    const s = checkText(v, at);
    if (!values.includes(s)) throw new RecordError("INVALID_ENUM", at, `${JSON.stringify(s)} is not one of ${values.join("|")}`);
    return s;
  };
  return { kind: "enum", enumValues: values, decode: check, encode: check };
}

export const bool: Field<boolean> = {
  kind: "bool",
  decode: checkBool,
  encode: checkBool,
};

function checkBool(v: unknown, at: string): boolean {
  notNull(v as NceValue, at);
  if (typeof v !== "boolean") throw new RecordError("WRONG_TYPE", at, "expected a boolean");
  return v;
}

/** A field that is present but may carry `null` (for example `parent_revision_id` of §8). */
export function nullable<T>(field: Field<T>): Field<T | null> {
  return {
    kind: "nullable",
    inner: field,
    decode: (v, at) => (v === null ? null : field.decode(v, at)),
    encode: (t, at) => (t === null ? null : field.encode(t, at)),
  };
}

export function arrayOf<T>(field: Field<T>): Field<readonly T[]> {
  return {
    kind: "array",
    inner: field,
    decode: (v, at) => {
      notNull(v, at);
      if (!Array.isArray(v)) throw new RecordError("WRONG_TYPE", at, "expected an array");
      return v.map((item, i) => field.decode(item, `${at}[${i}]`));
    },
    encode: (t, at) => {
      if (!Array.isArray(t)) throw new RecordError("WRONG_TYPE", at, "expected an array");
      return (t as readonly T[]).map((item, i) => field.encode(item, `${at}[${i}]`));
    },
  };
}

/** One entry of a "collection with a role" (§23.2): a `[code, value]` pair. */
export interface RolePair<C extends number, T> {
  readonly code: C;
  readonly value: T;
}

/**
 * `array de pares [código uint, valor] ordenado por código` (§23.2), with the frozen code set of
 * the structure (for example the four signer roles of §28.2). Codes must be strictly increasing,
 * which also rules out duplicates.
 */
export function roles<const C extends readonly number[], T>(
  codes: C,
  field: Field<T>,
): Field<readonly RolePair<C[number], T>[]> {
  const checkCode = (code: number, at: string): C[number] => {
    if (!codes.includes(code)) throw new RecordError("UNKNOWN_ROLE", at, `role code ${code} is not one of ${codes.join(",")}`);
    return code;
  };
  return {
    kind: "roles",
    roleCodes: codes,
    inner: field,
    decode: (v, at) => {
      notNull(v, at);
      if (!Array.isArray(v)) throw new RecordError("WRONG_TYPE", at, "expected an array of [code, value] pairs");
      let previous = -1;
      return v.map((pair, i) => {
        const where = `${at}[${i}]`;
        if (!Array.isArray(pair) || pair.length !== 2)
          throw new RecordError("BAD_ROLE_PAIR", where, "expected an array of exactly two elements");
        const code = checkCode(checkUint(pair[0], `${where}.code`), `${where}.code`);
        if (code <= previous) throw new RecordError("UNSORTED_ROLES", where, `code ${code} after ${previous}`);
        previous = code;
        return { code, value: field.decode(pair[1] as NceValue, `${where}.value`) };
      });
    },
    encode: (t, at) => {
      if (!Array.isArray(t)) throw new RecordError("WRONG_TYPE", at, "expected an array of role pairs");
      let previous = -1;
      return (t as readonly RolePair<C[number], T>[]).map((pair, i) => {
        const where = `${at}[${i}]`;
        const code = checkCode(checkUint(pair?.code, `${where}.code`), `${where}.code`);
        if (code <= previous) throw new RecordError("UNSORTED_ROLES", where, `code ${code} after ${previous}`);
        previous = code;
        return [code, field.encode(pair.value, `${where}.value`)] as NceValue;
      });
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------------------------

export interface Entry<T, Opt extends boolean> {
  readonly key: number;
  readonly field: Field<T>;
  readonly optional: Opt;
}

/** A field that must always be present. */
export function req<T>(key: number, field: Field<T>): Entry<T, false> {
  return { key, field, optional: false };
}

/** A field that is omitted when it does not apply — never sent as `null` (§23.4). */
export function opt<T>(key: number, field: Field<T>): Entry<T, true> {
  return { key, field, optional: true };
}

// `any` is the variance placeholder that lets `RecordOf` infer each field's type.
export type AnyEntry = Entry<any, boolean>;
export type Schema = { readonly [name: string]: AnyEntry };

type FieldType<E> = E extends Entry<infer T, boolean> ? T : never;
type Flatten<T> = { [K in keyof T]: T[K] } & {};

/** The TypeScript shape of a schema: required fields, plus optional ones that may be omitted. */
export type RecordOf<S extends Schema> = Flatten<
  { -readonly [K in keyof S as S[K]["optional"] extends true ? never : K]: FieldType<S[K]> } & {
    -readonly [K in keyof S as S[K]["optional"] extends true ? K : never]?: FieldType<S[K]>;
  }
>;

export interface RecordSchema<S extends Schema> {
  readonly name: string;
  readonly fields: S;
  /** Field names in ascending key order. */
  readonly order: readonly (keyof S & string)[];
}

/** Freezes a key table (§23.4). Throws at module load if two fields share a key. */
export function schema<const S extends Schema>(name: string, fields: S): RecordSchema<S> {
  const order = (Object.keys(fields) as (keyof S & string)[]).sort((a, b) => fields[a]!.key - fields[b]!.key);
  const seen = new Set<number>();
  for (const field of order) {
    const key = fields[field]!.key;
    if (!Number.isSafeInteger(key) || key < 0) throw new Error(`${name}.${field}: key ${key} is not a uint`);
    if (seen.has(key)) throw new Error(`${name}: duplicate key ${key}`);
    seen.add(key);
  }
  return { name, fields, order };
}

/** A whole record as one nested field, for `profile`, `descriptor`, `expected`… */
export function record<S extends Schema>(inner: RecordSchema<S>): Field<RecordOf<S>> {
  return {
    kind: "record",
    schema: inner as unknown as AnyRecordSchema,
    decode: (v, at) => fromNce(inner, v, at),
    encode: (t, at) => toNce(inner, t, at),
  };
}

/** The NCE map of a record. Optional fields whose value is `undefined` are omitted (§23.4). */
export function toNce<S extends Schema>(s: RecordSchema<S>, value: RecordOf<S>, at = s.name): Map<number, NceValue> {
  if (value === null || typeof value !== "object") throw new RecordError("WRONG_TYPE", at, "expected an object");
  const out = new Map<number, NceValue>();
  for (const name of s.order) {
    const entry = s.fields[name]!;
    const raw = (value as Record<string, unknown>)[name];
    if (raw === undefined) {
      if (entry.optional) continue;
      throw new RecordError("MISSING_FIELD", `${at}.${name}`, `key ${entry.key} is required`);
    }
    out.set(entry.key, entry.field.encode(raw, `${at}.${name}`));
  }
  // The encode-side twin of UNKNOWN_KEY: a property the table does not name would be silently
  // dropped, and the caller would sign bytes that do not say what it thinks they say.
  for (const name of Object.keys(value as Record<string, unknown>))
    if (!(name in s.fields)) throw new RecordError("UNKNOWN_FIELD", at, `${name} is not in the ${s.name} key table`);
  return out;
}

/** Decodes an NCE map into a record. Rejects unknown keys, missing required fields and bad types. */
export function fromNce<S extends Schema>(s: RecordSchema<S>, v: NceValue, at = s.name): RecordOf<S> {
  if (v === null) throw new RecordError("NULL_NOT_ALLOWED", at, "null where a record is required");
  if (!(v instanceof Map)) throw new RecordError("NOT_A_MAP", at, "expected an NCE map");
  const out: Record<string, unknown> = {};
  const known = new Set<number>();
  for (const name of s.order) {
    const entry = s.fields[name]!;
    known.add(entry.key);
    if (!v.has(entry.key)) {
      if (entry.optional) continue;
      throw new RecordError("MISSING_FIELD", `${at}.${name}`, `key ${entry.key} is required`);
    }
    out[name] = entry.field.decode(v.get(entry.key) as NceValue, `${at}.${name}`);
  }
  for (const key of v.keys())
    if (!known.has(key)) throw new RecordError("UNKNOWN_KEY", at, `key ${key} is not in the ${s.name} key table`);
  return out as RecordOf<S>;
}

/** Canonical NCE bytes of a record. */
export function encodeRecord<S extends Schema>(s: RecordSchema<S>, value: RecordOf<S>): Uint8Array {
  return nceEncode(toNce(s, value));
}

/** Decodes canonical NCE bytes into a record. Non-canonical bytes are rejected by NCE itself. */
export function decodeRecord<S extends Schema>(s: RecordSchema<S>, input: Uint8Array): RecordOf<S> {
  return fromNce(s, nceDecode(input));
}

/**
 * The bytes of a record with some fields left out — the "structure without `signature`" of §23.3,
 * which is what `nodra/root-transition`, `nodra/registry` and `nodra/epoch-descriptor` hash and sign.
 * Omitting a required field here is deliberate, so it is not a `MISSING_FIELD`.
 */
export function encodeOmitting<S extends Schema>(
  s: RecordSchema<S>,
  value: RecordOf<S>,
  omit: readonly (keyof S & string)[],
): Uint8Array {
  return nceEncode(toNceOmitting(s, value, omit));
}

/**
 * The same "structure without `signature`" as {@link encodeOmitting}, but as the NCE map rather
 * than its bytes — which is what `Context(domain, structure)` (§23.3) nests as a field.
 */
export function toNceOmitting<S extends Schema>(
  s: RecordSchema<S>,
  value: RecordOf<S>,
  omit: readonly (keyof S & string)[],
): Map<number, NceValue> {
  // The names are checked before the value is encoded: a typo here means the caller is about to
  // sign or hash the wrong bytes, and that must surface whatever the value looks like.
  const dropped = omit.map((name) => {
    const entry = s.fields[name];
    if (entry === undefined) throw new Error(`${s.name}: no field named ${name}`);
    return entry.key;
  });
  const map = toNce(s, value);
  for (const key of dropped) map.delete(key);
  return map;
}
