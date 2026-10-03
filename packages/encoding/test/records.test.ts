import { describe, expect, it } from "vitest";
import { NceError, encode as nceEncode } from "../src/index.js";
import {
  RECORD_SCHEMAS,
  RecordError,
  decodeRecord,
  encodeOmitting,
  encodeRecord,
  fromNce,
  toNce,
} from "../src/records.js";
import type { AnyRecordSchema, RecordErrorCode } from "../src/records.js";
import { ALL_SCHEMAS, fromJsonRecord, recordVectors } from "./record-support.js";
import { req, schema, uint } from "../src/record.js";
import { fromHex, toHex } from "./support.js";

type AnyRecord = Record<string, unknown>;

function schemaOf(name: string): AnyRecordSchema {
  const s = (RECORD_SCHEMAS as Record<string, AnyRecordSchema>)[name];
  if (s === undefined) throw new Error(`no schema named ${name}`);
  return s;
}

function expectRecordError(code: RecordErrorCode, fn: () => unknown): void {
  try {
    fn();
  } catch (e) {
    expect(e, `expected a RecordError, got ${String(e)}`).toBeInstanceOf(RecordError);
    expect((e as RecordError).code).toBe(code);
    return;
  }
  expect.unreachable(`expected RecordError ${code}, nothing was thrown`);
}

// The key tables of §8 and §23.4, transcribed again here from the spec. If `src/records.ts` and
// this table ever disagree, one of the two misread the spec — which is the point of repeating it.
const SPEC_KEY_TABLES: Record<string, Record<string, number>> = {
  RevisionManifest: {
    object_id: 1, revision_id: 2, parent_revision_id: 3, path: 4, mime: 5, mtime_ms: 6,
    content_blob_id: 7, content_fingerprint: 8, content_plaintext_size: 9, deleted: 10,
    content_epoch_id: 11,
  },
  WrappedPrivateKey: { key_role: 1, blob: 2 },
  Argon2Params: { memory_kib: 1, iterations: 2, parallelism: 3, version: 4 },
  AccountSecurityProfile: {
    account_id: 1, kdf_salt: 2, argon2_params: 3, wrapped_account_encryption_key: 4,
    wrapped_account_signing_key: 5, config_version: 6, config_blob: 7,
  },
  AccountSecurityConfig: {
    account_id: 1, config_version: 2, root_generation: 3, root_hash: 4, genesis_root_hash: 5,
    account_encryption_public_key_hash: 6, account_signing_public_key_hash: 7,
    recovery_encryption_public_key_hash: 8, recovery_authority_public_key_hash: 9,
    registry_version: 10, registry_hash: 11, crypto_version: 12,
  },
  RootDescriptor: {
    account_id: 1, root_generation: 2, account_encryption_public_key: 3,
    account_signing_public_key: 4, recovery_encryption_public_key: 5,
    recovery_authority_public_key: 6, previous_root_hash: 7, crypto_version: 8,
  },
  RootTransition: {
    account_id: 1, transition_type: 2, old_root_hash: 3, new_root_hash: 4,
    new_root_generation: 5, signatures: 6,
  },
  RegistryRecipient: {
    recipient_id: 1, type: 2, public_key: 3, label: 4, status: 5, added_version: 6,
    revoked_version: 7,
  },
  Registry: {
    account_id: 1, registry_version: 2, previous_registry_hash: 3, root_generation: 4,
    recipients: 5, signature: 6,
  },
  EpochDescriptor: {
    vault_id: 1, epoch_id: 2, previous_epoch_id: 3, previous_descriptor_hash: 4,
    root_generation: 5, root_hash: 6, registry_version: 7, registry_hash: 8,
    epoch_commitment: 9, envelope_set_hash: 10, crypto_version: 11, signature: 12,
  },
  EpochEnvelope: {
    vault_id: 1, epoch_id: 2, recipient_id: 3, recipient_type: 4, ciphertext: 5,
    algorithm_version: 6,
  },
  RecoveryKit: {
    account_id: 1, genesis_root_hash: 2, recovery_encryption_private_key: 3,
    recovery_authority_private_key: 4, recovery_encryption_public_key_hash: 5,
    recovery_authority_public_key_hash: 6, created_at: 7,
  },
  BundleEpoch: { descriptor: 1, envelopes: 2 },
  BundleExpected: { root_generation: 1, registry_version: 2, config_version: 3 },
  BundleDeletion: { vault_id: 1, nonce: 2, signature: 3 },
  SecurityBundle: {
    operation_type: 1, root_transition: 2, root_descriptor: 3, registry: 4, profile: 5,
    profile_signature: 6, config_blob: 7, config_version: 8, epochs: 9, coverage_envelopes: 10,
    expected: 11, deletion: 12, bundle_id: 13, escrow: 14, recovery: 15,
  },
  // crypto_version = 2 (ADR-021).
  EscrowSlot: { slot: 1, key_id: 2, wrapped_key: 3, payload_blob: 4 },
  EscrowedRecoveryKeys: { recovery_encryption_private_key: 1, recovery_authority_private_key: 2 },
  EscrowBlob: { account_id: 1, unlock: 2, recovery: 3 },
  EscrowRewrap: { account_id: 1, slot: 2, wrapped_key: 3, payload_blob: 4 },
  // ADR-022 (§23.4, any crypto_version).
  RecoveryRecord: { request_id: 1, kind: 2, root_generation: 3, root_hash: 4, signature: 5 },
};

describe("key tables (§8, §23.4)", () => {
  it("every frozen structure of crypto_version = 1 and 2 has a schema", () => {
    expect(Object.keys(RECORD_SCHEMAS).sort()).toEqual(Object.keys(SPEC_KEY_TABLES).sort());
  });

  for (const [name, table] of Object.entries(SPEC_KEY_TABLES)) {
    it(`${name} uses exactly the frozen keys`, () => {
      const schema = schemaOf(name);
      const actual = Object.fromEntries(schema.order.map((f: string) => [f, schema.fields[f]!.key]));
      expect(actual).toEqual(table);
    });
  }

  it("enum values are SCREAMING_SNAKE_CASE and never map keys (§23.2)", () => {
    const seen: string[] = [];
    const walk = (field: { kind: string; enumValues?: readonly string[]; inner?: unknown; schema?: unknown }): void => {
      if (field.enumValues) seen.push(...field.enumValues);
      if (field.inner) walk(field.inner as never);
      if (field.schema) for (const f of (field.schema as AnyRecordSchema).order)
        walk((field.schema as AnyRecordSchema).fields[f]!.field as never);
    };
    for (const schema of ALL_SCHEMAS)
      for (const f of schema.order) walk(schema.fields[f]!.field as never);
    expect(seen.length).toBeGreaterThan(20);
    for (const value of seen) expect(value).toMatch(/^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$/);
  });

  it("a duplicate key in a table is a load-time error", () => {
    // Deliberately malformed: two fields claiming key 1.
    expect(() =>
      schema("Broken", { a: req(1, uint), b: req(1, uint) }),
    ).toThrow(/duplicate key 1/);
  });
});

describe("canonical vectors", () => {
  for (const vector of recordVectors.records) {
    it(`${vector.name} encodes to its hand-written bytes`, () => {
      const schema = schemaOf(vector.record);
      const value = fromJsonRecord(schema, vector.value);
      expect(toHex(encodeRecord(schema, value as never))).toBe(vector.hex);
    });

    it(`${vector.name} round-trips byte for byte`, () => {
      const schema = schemaOf(vector.record);
      const bytes = fromHex(vector.hex);
      const decoded = decodeRecord(schema, bytes);
      expect(decoded).toEqual(fromJsonRecord(schema, vector.value));
      expect(toHex(encodeRecord(schema, decoded))).toBe(vector.hex);
    });
  }

  it("covers every frozen structure at least once", () => {
    const covered = new Set(recordVectors.records.map((v) => v.record));
    expect([...covered].sort()).toEqual(Object.keys(RECORD_SCHEMAS).sort());
  });
});

describe("strict decoding (§23.4)", () => {
  const bundleVector = recordVectors.records.find((v) => v.name === "SecurityBundle, CREATE_ACCOUNT")!;
  const manifestVector = recordVectors.records.find((v) => v.record === "RevisionManifest")!;
  const manifest = () => fromJsonRecord(schemaOf("RevisionManifest"), manifestVector.value) as AnyRecord;

  it("rejects an unknown map key", () => {
    const map = toNce(schemaOf("RevisionManifest"), manifest() as never);
    map.set(12, 1);
    expectRecordError("UNKNOWN_KEY", () => fromNce(schemaOf("RevisionManifest"), map));
  });

  it("rejects a missing required field", () => {
    const map = toNce(schemaOf("RevisionManifest"), manifest() as never);
    map.delete(4);
    expectRecordError("MISSING_FIELD", () => fromNce(schemaOf("RevisionManifest"), map));
  });

  it("rejects a wrong type", () => {
    const map = toNce(schemaOf("RevisionManifest"), manifest() as never);
    map.set(4, 7); // path as a uint
    expectRecordError("WRONG_TYPE", () => fromNce(schemaOf("RevisionManifest"), map));
  });

  it("rejects a bytes field of the wrong length", () => {
    const map = toNce(schemaOf("RevisionManifest"), manifest() as never);
    map.set(1, new Uint8Array(15));
    expectRecordError("WRONG_LENGTH", () => fromNce(schemaOf("RevisionManifest"), map));
    map.set(1, new Uint8Array(17));
    expectRecordError("WRONG_LENGTH", () => fromNce(schemaOf("RevisionManifest"), map));
  });

  it("rejects null where §23.4 requires omission", () => {
    const map = toNce(schemaOf("SecurityBundle"), fromJsonRecord(schemaOf("SecurityBundle"), bundleVector.value) as never);
    map.set(12, null); // `deletion` does not apply to CREATE_ACCOUNT: omit it, never send null
    expectRecordError("NULL_NOT_ALLOWED", () => fromNce(schemaOf("SecurityBundle"), map));
  });

  it("rejects null in a required non-nullable field", () => {
    const map = toNce(schemaOf("RevisionManifest"), manifest() as never);
    map.set(10, null); // `deleted` is a bool, never null
    expectRecordError("NULL_NOT_ALLOWED", () => fromNce(schemaOf("RevisionManifest"), map));
  });

  it("rejects an unknown enum value", () => {
    const map = toNce(schemaOf("EpochEnvelope"), fromJsonRecord(schemaOf("EpochEnvelope"), recordVectors.records.find((v) => v.record === "EpochEnvelope")!.value) as never);
    map.set(4, "account"); // lower case is a different value, not a normalization
    expectRecordError("INVALID_ENUM", () => fromNce(schemaOf("EpochEnvelope"), map));
  });

  it("rejects a uint above Number.MAX_SAFE_INTEGER", () => {
    const map = toNce(schemaOf("RevisionManifest"), manifest() as never);
    map.set(6, 2n ** 60n);
    expectRecordError("INT_NOT_SAFE", () => fromNce(schemaOf("RevisionManifest"), map));
  });

  it("rejects a negative integer in a uint field", () => {
    const map = toNce(schemaOf("RevisionManifest"), manifest() as never);
    map.set(6, -1);
    expectRecordError("WRONG_TYPE", () => fromNce(schemaOf("RevisionManifest"), map));
  });

  it("rejects something that is not a map", () => {
    expectRecordError("NOT_A_MAP", () => fromNce(schemaOf("RevisionManifest"), [1, 2]));
  });

  it("rejects out-of-order and duplicate map keys through NCE itself (§23.2)", () => {
    // key 2 before key 1, then key 1 twice: both are non-canonical CBOR, so they never reach the schema.
    expect(() => decodeRecord(schemaOf("Argon2Params"), fromHex("a202010104"))).toThrow(NceError);
    expect(() => decodeRecord(schemaOf("Argon2Params"), fromHex("a201010102"))).toThrow(NceError);
  });

  it("rejects an object property the key table does not name", () => {
    expectRecordError("UNKNOWN_FIELD", () =>
      encodeRecord(schemaOf("RevisionManifest"), { ...manifest(), extra: 1 } as never),
    );
  });

  it("encoding applies the same checks as decoding", () => {
    const bad = { ...manifest(), object_id: new Uint8Array(15) };
    expectRecordError("WRONG_LENGTH", () => encodeRecord(schemaOf("RevisionManifest"), bad as never));
    expectRecordError("MISSING_FIELD", () => {
      const { path: _dropped, ...rest } = manifest();
      return encodeRecord(schemaOf("RevisionManifest"), rest as never);
    });
  });
});

describe("role collections (§23.2, §28.2)", () => {
  const transition = () =>
    fromJsonRecord(schemaOf("RootTransition"), recordVectors.records.find((v) => v.record === "RootTransition")!.value) as AnyRecord;

  it("rejects role codes out of order", () => {
    const value = { ...transition(), signatures: [{ code: 4, value: new Uint8Array(64) }, { code: 2, value: new Uint8Array(64) }] };
    expectRecordError("UNSORTED_ROLES", () => encodeRecord(schemaOf("RootTransition"), value as never));
  });

  it("rejects a duplicate role code", () => {
    const value = { ...transition(), signatures: [{ code: 2, value: new Uint8Array(64) }, { code: 2, value: new Uint8Array(64) }] };
    expectRecordError("UNSORTED_ROLES", () => encodeRecord(schemaOf("RootTransition"), value as never));
  });

  it("rejects a role code outside the frozen set", () => {
    const value = { ...transition(), signatures: [{ code: 5, value: new Uint8Array(64) }] };
    expectRecordError("UNKNOWN_ROLE", () => encodeRecord(schemaOf("RootTransition"), value as never));
  });

  it("rejects a signature that is not 64 bytes", () => {
    const value = { ...transition(), signatures: [{ code: 2, value: new Uint8Array(32) }] };
    expectRecordError("WRONG_LENGTH", () => encodeRecord(schemaOf("RootTransition"), value as never));
  });

  it("rejects a pair that is not [code, value]", () => {
    const map = toNce(schemaOf("RootTransition"), transition() as never);
    map.set(6, [[2, new Uint8Array(64), 0]]);
    expectRecordError("BAD_ROLE_PAIR", () => fromNce(schemaOf("RootTransition"), map));
  });
});

describe("encodeOmitting (§23.3 'structure without signature')", () => {
  it("drops exactly the named key and leaves the rest canonical", () => {
    const schema = schemaOf("EpochDescriptor");
    const value = fromJsonRecord(schema, recordVectors.records.find((v) => v.record === "EpochDescriptor")!.value);
    const full = toNce(schema, value as never);
    full.delete(12);
    expect(toHex(encodeOmitting(schema, value as never, ["signature"]))).toBe(toHex(nceEncode(full)));
  });

  it("refuses a field name that is not in the table", () => {
    expect(() => encodeOmitting(schemaOf("Registry"), {} as never, ["nope"])).toThrow(/no field named nope/);
  });
});

describe("broken-variant proof: a lenient decoder must fail these tests", () => {
  // Same walk as `fromNce`, minus the unknown-key check — the one rule under test.
  function lenientFromNce(schema: AnyRecordSchema, v: Map<number, unknown>): AnyRecord {
    const out: AnyRecord = {};
    for (const name of schema.order) {
      const entry = schema.fields[name]!;
      if (!v.has(entry.key)) {
        if (entry.optional) continue;
        throw new RecordError("MISSING_FIELD", name, "required");
      }
      out[name] = entry.field.decode(v.get(entry.key) as never, name);
    }
    return out;
  }

  /** The oracle: "an unknown key is rejected". */
  function unknownKeyIsRejected(decode: (s: AnyRecordSchema, m: Map<number, unknown>) => unknown): boolean {
    const schema = schemaOf("Argon2Params");
    const map = new Map<number, unknown>([[1, 65536], [2, 3], [3, 4], [4, 1], [5, 99]]);
    try {
      decode(schema, map);
      return false;
    } catch (e) {
      return e instanceof RecordError && e.code === "UNKNOWN_KEY";
    }
  }

  it("holds for the real decoder", () => {
    expect(unknownKeyIsRejected((s, m) => fromNce(s, m as never))).toBe(true);
  });

  it("fails for a decoder that ignores unknown keys", () => {
    expect(unknownKeyIsRejected(lenientFromNce)).toBe(false);
  });
});
