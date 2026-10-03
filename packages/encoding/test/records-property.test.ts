import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { NceError } from "../src/index.js";
import { RecordError, decodeRecord, encodeRecord } from "../src/records.js";
import { ALL_SCHEMAS, arbRecord, recordVectors } from "./record-support.js";
import { fromHex, toHex } from "./support.js";

const RUNS = 500;

describe("record property tests", () => {
  for (const schema of ALL_SCHEMAS) {
    it(`${schema.name}: decode(encode(r)) deep-equals r`, () => {
      fc.assert(
        fc.property(arbRecord(schema), (value) => {
          expect(decodeRecord(schema, encodeRecord(schema, value as never))).toEqual(value);
        }),
        { numRuns: RUNS },
      );
    });

    it(`${schema.name}: encoding is deterministic`, () => {
      fc.assert(
        fc.property(arbRecord(schema), (value) => {
          const once = encodeRecord(schema, value as never);
          const twice = encodeRecord(schema, value as never);
          expect(toHex(twice)).toBe(toHex(once));
          // And it is the canonical form: re-encoding what came back changes nothing.
          expect(toHex(encodeRecord(schema, decodeRecord(schema, once)))).toBe(toHex(once));
        }),
        { numRuns: RUNS },
      );
    });
  }

  it("a field omitted is never a field present as undefined (§23.4)", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...ALL_SCHEMAS).chain((schema) => arbRecord(schema).map((v) => [schema, v] as const)),
        ([schema, value]) => {
          const decoded = decodeRecord(schema, encodeRecord(schema, value as never)) as Record<string, unknown>;
          for (const name of Object.keys(decoded)) expect(decoded[name]).not.toBeUndefined();
        },
      ),
      { numRuns: RUNS },
    );
  });
});

describe("mutation: every accepted mutant re-encodes to itself", () => {
  // Over every canonical vector: flip one bit of one byte. The result must either be rejected
  // (NCE or schema) or decode to a record whose canonical encoding is exactly the mutated input.
  // A decoder that silently repaired or dropped something would break the second branch.
  const schemasByName = new Map(ALL_SCHEMAS.map((s) => [s.name, s]));

  it("holds for a bit flip anywhere in any vector", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...recordVectors.records),
        fc.nat(),
        fc.integer({ min: 0, max: 7 }),
        (vector, offset, bit) => {
          const schema = schemasByName.get(vector.record)!;
          const bytes = fromHex(vector.hex);
          const mutated = new Uint8Array(bytes);
          const i = offset % mutated.length;
          mutated[i] = mutated[i]! ^ (1 << bit);
          if (toHex(mutated) === vector.hex) return;
          let decoded: unknown;
          try {
            decoded = decodeRecord(schema, mutated);
          } catch (e) {
            expect(e instanceof NceError || e instanceof RecordError, `unexpected error ${String(e)}`).toBe(true);
            return;
          }
          expect(toHex(encodeRecord(schema, decoded as never))).toBe(toHex(mutated));
        },
      ),
      { numRuns: 4000 },
    );
  });

  it("truncating a vector is always rejected", () => {
    fc.assert(
      fc.property(fc.constantFrom(...recordVectors.records), fc.nat(), (vector, cut) => {
        const bytes = fromHex(vector.hex);
        const keep = cut % bytes.length;
        const schema = schemasByName.get(vector.record)!;
        expect(() => decodeRecord(schema, bytes.slice(0, keep))).toThrow();
      }),
      { numRuns: 2000 },
    );
  });

  it("appending a byte is always rejected", () => {
    for (const vector of recordVectors.records) {
      const schema = schemasByName.get(vector.record)!;
      const bytes = fromHex(vector.hex + "00");
      expect(() => decodeRecord(schema, bytes)).toThrow(NceError);
    }
  });
});
