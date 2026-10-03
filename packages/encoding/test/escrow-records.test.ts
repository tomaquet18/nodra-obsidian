// The ADR-021 additions of `crypto_version = 2` (§23.3, §23.4): the escrow records, SecurityBundle
// key 14 and the Managed profile shape.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  ACCOUNT_SECURITY_PROFILE,
  ROOT_TRANSITION,
  ESCROW_BLOB,
  ESCROW_REWRAP,
  ESCROW_SLOT,
  ESCROW_SLOTS,
  ESCROWED_RECOVERY_KEYS,
  OPERATION_TYPES,
  RecordError,
  SECURITY_BUNDLE,
  TRANSITION_TYPES,
  decodeRecord,
  encodeRecord,
  fromNce,
  toNce,
} from "../src/records.js";
import type { AnyRecordSchema, RecordErrorCode } from "../src/records.js";
import { arbRecord, fromJsonRecord, recordVectors } from "./record-support.js";

const RUNS = 1000;

const NEW_SCHEMAS: AnyRecordSchema[] = [ESCROW_SLOT, ESCROWED_RECOVERY_KEYS, ESCROW_BLOB, ESCROW_REWRAP];

function vectorValue(schema: AnyRecordSchema, name?: string): Record<string, unknown> {
  const v = recordVectors.records.find((r) => r.record === schema.name && (name === undefined || r.name === name));
  if (v === undefined) throw new Error(`no vector for ${schema.name} ${name ?? ""}`);
  return fromJsonRecord(schema, v.value);
}

function codeOf(fn: () => unknown): RecordErrorCode | "NO_ERROR" | "OTHER_ERROR" {
  try {
    fn();
    return "NO_ERROR";
  } catch (e) {
    return e instanceof RecordError ? e.code : "OTHER_ERROR";
  }
}

// --- edge-heavy arbitraries -----------------------------------------------------------------------

/** Empty, and lengths either side of the CBOR 1-byte (23/24) and 2-byte (255/256) length headers. */
const edgeBytes = fc.oneof(
  fc.constant(new Uint8Array(0)),
  fc.uint8Array({ maxLength: 8 }),
  fc.uint8Array({ minLength: 23, maxLength: 25 }),
  fc.uint8Array({ minLength: 255, maxLength: 257 }),
);
const id16 = fc.uint8Array({ minLength: 16, maxLength: 16 });

const arbSlot = fc.record(
  { slot: fc.constantFrom(...ESCROW_SLOTS), key_id: id16, wrapped_key: edgeBytes, payload_blob: edgeBytes },
  { requiredKeys: ["slot", "key_id", "wrapped_key"] },
);

const EDGE_ARBITRARIES: [AnyRecordSchema, fc.Arbitrary<Record<string, unknown>>][] = [
  [ESCROW_SLOT, arbSlot],
  [
    ESCROWED_RECOVERY_KEYS,
    fc.record({ recovery_encryption_private_key: edgeBytes, recovery_authority_private_key: edgeBytes }),
  ],
  // Every subset of slots, the empty one included: which slots an operation needs is a Worker rule
  // (§35.1.1 step 7), never a codec one.
  [ESCROW_BLOB, fc.record({ account_id: id16, unlock: arbSlot, recovery: arbSlot }, { requiredKeys: ["account_id"] })],
  [
    ESCROW_REWRAP,
    fc.record(
      { account_id: id16, slot: fc.constantFrom(...ESCROW_SLOTS), wrapped_key: edgeBytes, payload_blob: edgeBytes },
      { requiredKeys: ["account_id", "slot", "wrapped_key"] },
    ),
  ],
];

describe("ADR-021 type lists (§23.4, §28.2, §35.1.1)", () => {
  it("the escrow slots are exactly UNLOCK and RECOVERY", () => {
    expect([...ESCROW_SLOTS]).toEqual(["UNLOCK", "RECOVERY"]);
  });

  it("the transition types are the five of §28.2, in the spec's order", () => {
    expect([...TRANSITION_TYPES]).toEqual([
      "GENESIS", "RECOVERY_RESET", "RECOVERY_KIT_REPLACEMENT", "SWITCH_TO_PRIVATE", "SWITCH_TO_MANAGED",
    ]);
  });

  it("the operation types include the two mode switches (and, since ADR-022, the three recovery records)", () => {
    expect(OPERATION_TYPES).toContain("SWITCH_TO_PRIVATE");
    expect(OPERATION_TYPES).toContain("SWITCH_TO_MANAGED");
    expect(OPERATION_TYPES.length).toBe(16);
    expect(new Set(OPERATION_TYPES).size).toBe(16);
  });
});

describe("round trip over every new record schema, with edge values", () => {
  for (const [schema, arb] of EDGE_ARBITRARIES) {
    it(`${schema.name}: decode(encode(r)) deep-equals r and keeps omitted fields omitted`, () => {
      fc.assert(
        fc.property(arb, (value) => {
          const decoded = decodeRecord(schema, encodeRecord(schema, value as never)) as Record<string, unknown>;
          expect(decoded).toEqual(value);
          expect(Object.keys(decoded).sort()).toEqual(Object.keys(value).sort());
        }),
        { numRuns: RUNS },
      );
    });
  }

  it("the edge arbitraries cover every new schema", () => {
    expect(EDGE_ARBITRARIES.map(([s]) => s.name).sort()).toEqual(NEW_SCHEMAS.map((s) => s.name).sort());
  });

  it("an EscrowBlob with no slot at all round-trips (the codec does not decide the operation rules)", () => {
    const value = { account_id: new Uint8Array(16) };
    expect(decodeRecord(ESCROW_BLOB, encodeRecord(ESCROW_BLOB, value))).toEqual(value);
  });

  it("an empty payload_blob stays present and distinct from an absent one", () => {
    const base = { slot: "RECOVERY" as const, key_id: new Uint8Array(16), wrapped_key: new Uint8Array(0) };
    const withEmpty = encodeRecord(ESCROW_SLOT, { ...base, payload_blob: new Uint8Array(0) });
    const without = encodeRecord(ESCROW_SLOT, base);
    expect(withEmpty).not.toEqual(without);
    expect(decodeRecord(ESCROW_SLOT, withEmpty)).toHaveProperty("payload_blob");
    expect(decodeRecord(ESCROW_SLOT, without)).not.toHaveProperty("payload_blob");
  });

  it("SecurityBundle with and without key 14 round-trips", () => {
    fc.assert(
      fc.property(arbRecord(SECURITY_BUNDLE), (value) => {
        expect(decodeRecord(SECURITY_BUNDLE, encodeRecord(SECURITY_BUNDLE, value as never))).toEqual(value);
      }),
      { numRuns: 300 },
    );
  });

  it("a Managed AccountSecurityProfile (no kdf_salt, no argon2_params) round-trips", () => {
    fc.assert(
      fc.property(arbRecord(ACCOUNT_SECURITY_PROFILE), (value) => {
        const { kdf_salt: _s, argon2_params: _p, ...managed } = value;
        const decoded = decodeRecord(ACCOUNT_SECURITY_PROFILE, encodeRecord(ACCOUNT_SECURITY_PROFILE, managed as never));
        expect(decoded).toEqual(managed);
        expect(decoded).not.toHaveProperty("kdf_salt");
        expect(decoded).not.toHaveProperty("argon2_params");
      }),
      { numRuns: 300 },
    );
  });
});

// Transcribed from §23.4, not read from the schemas: a test that derived these from the schema under
// test would lose its case the moment a required field became optional, and still pass.
const SPEC_REQUIRED: Record<string, { fields: string[]; firstUnusedKey: number }> = {
  EscrowSlot: { fields: ["slot", "key_id", "wrapped_key"], firstUnusedKey: 5 },
  EscrowedRecoveryKeys: {
    fields: ["recovery_encryption_private_key", "recovery_authority_private_key"],
    firstUnusedKey: 3,
  },
  EscrowBlob: { fields: ["account_id"], firstUnusedKey: 4 },
  EscrowRewrap: { fields: ["account_id", "slot", "wrapped_key"], firstUnusedKey: 5 },
};

describe("strict decoding of the new records", () => {
  it("the spec transcription covers every new schema", () => {
    expect(Object.keys(SPEC_REQUIRED).sort()).toEqual(NEW_SCHEMAS.map((s) => s.name).sort());
  });

  for (const schema of NEW_SCHEMAS) {
    const { fields: required, firstUnusedKey: nextKey } = SPEC_REQUIRED[schema.name]!;

    it(`${schema.name}: rejects an unknown key (${nextKey})`, () => {
      const map = toNce(schema, vectorValue(schema) as never);
      map.set(nextKey, new Uint8Array(1));
      expect(codeOf(() => fromNce(schema, map))).toBe("UNKNOWN_KEY");
    });

    for (const name of required) {
      it(`${schema.name}: rejects a missing required field ${name}`, () => {
        const map = toNce(schema, vectorValue(schema) as never);
        map.delete(schema.fields[name]!.key);
        expect(codeOf(() => fromNce(schema, map))).toBe("MISSING_FIELD");
      });
    }
  }

  // Key 15 is ADR-022's `recovery` (recovery-records.test.ts); the first unused key is now 16.
  it("SecurityBundle: rejects an unknown key 16", () => {
    const map = toNce(SECURITY_BUNDLE, vectorValue(SECURITY_BUNDLE, recordVectors.records.find((r) => r.record === "SecurityBundle" && "escrow" in r.value)!.name) as never);
    map.set(16, 0);
    expect(codeOf(() => fromNce(SECURITY_BUNDLE, map))).toBe("UNKNOWN_KEY");
  });

  it("SecurityBundle: rejects escrow = null (omit, never null, §23.4)", () => {
    const map = toNce(SECURITY_BUNDLE, vectorValue(SECURITY_BUNDLE, "SecurityBundle, DELETE_ACCOUNT (every non-applicable field omitted)") as never);
    map.set(14, null);
    expect(codeOf(() => fromNce(SECURITY_BUNDLE, map))).toBe("NULL_NOT_ALLOWED");
  });

  const INVALID_SLOTS: string[] = ["unlock", "Recovery", "", "UNLOCK ", "RECOVERY_KEYS", "BOTH"];

  it("EscrowSlot: rejects every slot value outside UNLOCK/RECOVERY", () => {
    for (const bad of INVALID_SLOTS) {
      const map = toNce(ESCROW_SLOT, vectorValue(ESCROW_SLOT) as never);
      map.set(1, bad);
      expect(codeOf(() => fromNce(ESCROW_SLOT, map)), JSON.stringify(bad)).toBe("INVALID_ENUM");
    }
  });

  it("EscrowRewrap: rejects every slot value outside UNLOCK/RECOVERY", () => {
    for (const bad of INVALID_SLOTS) {
      const map = toNce(ESCROW_REWRAP, vectorValue(ESCROW_REWRAP) as never);
      map.set(2, bad);
      expect(codeOf(() => fromNce(ESCROW_REWRAP, map)), JSON.stringify(bad)).toBe("INVALID_ENUM");
    }
  });

  it("EscrowBlob: rejects an invalid slot value inside a nested slot", () => {
    const value = vectorValue(ESCROW_BLOB, "EscrowBlob, both slots (CREATE_ACCOUNT, SWITCH_TO_MANAGED)");
    const bad = { ...value, recovery: { ...(value.recovery as object), slot: "RECOVER" } };
    expect(codeOf(() => encodeRecord(ESCROW_BLOB, bad as never))).toBe("INVALID_ENUM");
  });

  it("EscrowSlot: a slot as a number is a wrong type, and key_id must be 16 bytes", () => {
    const map = toNce(ESCROW_SLOT, vectorValue(ESCROW_SLOT) as never);
    map.set(1, 1);
    expect(codeOf(() => fromNce(ESCROW_SLOT, map))).toBe("WRONG_TYPE");
    const map2 = toNce(ESCROW_SLOT, vectorValue(ESCROW_SLOT) as never);
    map2.set(2, new Uint8Array(15));
    expect(codeOf(() => fromNce(ESCROW_SLOT, map2))).toBe("WRONG_LENGTH");
  });

  it("SecurityBundle rejects a mode switch spelled differently", () => {
    const bundle = toNce(SECURITY_BUNDLE, vectorValue(SECURITY_BUNDLE, "SecurityBundle, DELETE_ACCOUNT (every non-applicable field omitted)") as never);
    bundle.set(1, "SWITCH_TO_MANAGED_MODE");
    expect(codeOf(() => fromNce(SECURITY_BUNDLE, bundle))).toBe("INVALID_ENUM");
  });

  it("RootTransition rejects a mode switch spelled differently", () => {
    const transition = toNce(ROOT_TRANSITION, vectorValue(ROOT_TRANSITION, "RootTransition, SWITCH_TO_MANAGED with roles 1 and 4") as never);
    transition.set(2, "SWITCH_TO_MANAGED_MODE");
    expect(codeOf(() => fromNce(ROOT_TRANSITION, transition))).toBe("INVALID_ENUM");
  });
});
