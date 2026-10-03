import { readFileSync } from "node:fs";
import fc from "fast-check";
import { RECORD_SCHEMAS } from "../src/records.js";
import type { RecordName } from "../src/records.js";
import type { AnyField, AnyRecordSchema } from "../src/record.js";
import { fromHex } from "./support.js";

// --- vectors/records.json ------------------------------------------------------------------------

export type JsonField = string | number | boolean | null | JsonField[] | { [k: string]: JsonField };

export interface RecordVectors {
  fixtures: Record<string, string>;
  records: { name: string; record: RecordName; value: Record<string, JsonField>; hex: string }[];
}

export const recordVectors: RecordVectors = JSON.parse(
  readFileSync(new URL("../vectors/records.json", import.meta.url), "utf8"),
) as RecordVectors;

export interface SecretKeyVectors {
  alphabet: string;
  canonical: { name: string; bytes: string; chars: string; display: string }[];
  normalization: { name: string; input: string; bytes: string }[];
  invalid: { name: string; input: string; error: string }[];
}

export const secretKeyVectors: SecretKeyVectors = JSON.parse(
  readFileSync(new URL("../vectors/secret-key.json", import.meta.url), "utf8"),
) as SecretKeyVectors;

/** Turns the schema-driven JSON notation of `vectors/records.json` into a record value. */
export function fromJsonField(field: AnyField, json: JsonField): unknown {
  switch (field.kind) {
    case "bytes":
      return fromHex(json as string);
    case "uint":
      return json as number;
    case "text":
    case "enum":
      return json as string;
    case "bool":
      return json as boolean;
    case "nullable":
      return json === null ? null : fromJsonField(field.inner as AnyField, json);
    case "array":
      return (json as JsonField[]).map((item) => fromJsonField(field.inner as AnyField, item));
    case "record":
      return fromJsonRecord(field.schema as AnyRecordSchema, json as Record<string, JsonField>);
    case "roles":
      return (json as [number, JsonField][]).map(([code, value]) => ({
        code,
        value: fromJsonField(field.inner as AnyField, value),
      }));
  }
}

export function fromJsonRecord(
  schema: AnyRecordSchema,
  json: Record<string, JsonField>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const name of schema.order) {
    if (!(name in json)) continue;
    out[name] = fromJsonField(schema.fields[name]!.field as AnyField, json[name]!);
  }
  return out;
}

// --- fast-check arbitraries -----------------------------------------------------------------------

// ASCII only, so generated text is always NFC and NCE never rejects it for a reason unrelated to
// the schema. `/`, `.`, `_`, `-` and the space are the characters real paths and labels contain.
const TEXT_CHARS = [..."abcXYZ019/._- "];

export function arbField(field: AnyField): fc.Arbitrary<unknown> {
  switch (field.kind) {
    case "bytes":
      return field.byteLength === undefined
        ? fc.uint8Array({ maxLength: 8 })
        : fc.uint8Array({ minLength: field.byteLength, maxLength: field.byteLength });
    case "uint":
      return fc.nat({ max: 2 ** 40 });
    case "text":
      return fc.array(fc.constantFrom(...TEXT_CHARS), { maxLength: 12 }).map((cs) => cs.join(""));
    case "enum":
      return fc.constantFrom(...(field.enumValues as readonly string[]));
    case "bool":
      return fc.boolean();
    case "nullable":
      return fc.oneof(fc.constant(null), arbField(field.inner as AnyField));
    case "array":
      return fc.array(arbField(field.inner as AnyField), { maxLength: 3 });
    case "record":
      return arbRecord(field.schema as AnyRecordSchema);
    case "roles": {
      const codes = [...(field.roleCodes as readonly number[])];
      return fc
        .subarray(codes)
        .chain((chosen) =>
          fc
            .tuple(...chosen.map(() => arbField(field.inner as AnyField)))
            .map((values) => chosen.map((code, i) => ({ code, value: values[i] }))),
        );
    }
  }
}

export function arbRecord(schema: AnyRecordSchema): fc.Arbitrary<Record<string, unknown>> {
  const names = schema.order;
  const parts = names.map((name) => {
    const entry = schema.fields[name]!;
    const value = arbField(entry.field as AnyField);
    // An optional field is either present or absent — never present as `undefined` (§23.4).
    return entry.optional ? fc.option(value, { nil: undefined, freq: 3 }) : value;
  });
  return fc.tuple(...parts).map((values) => {
    const out: Record<string, unknown> = {};
    names.forEach((name, i) => {
      if (values[i] !== undefined) out[name] = values[i];
    });
    return out;
  });
}

export const ALL_SCHEMAS: AnyRecordSchema[] = Object.values(RECORD_SCHEMAS);
export const SCHEMA_NAMES = Object.keys(RECORD_SCHEMAS) as RecordName[];
