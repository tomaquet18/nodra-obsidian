// The ADR-022 additions (§23.3, §23.4): `RecoveryRecord`, SecurityBundle key 15 and the three
// operation types of §35.15. Valid under every `crypto_version` by the explicit exception of §23.3.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  OPERATION_TYPES,
  RECOVERY_RECORD,
  RECOVERY_REQUEST_KINDS,
  RecordError,
  SECURITY_BUNDLE,
  decodeRecord,
  encodeRecord,
  fromNce,
  toNce,
} from "../src/records.js";
import type { RecordErrorCode } from "../src/records.js";
import { arbRecord, fromJsonRecord, recordVectors } from "./record-support.js";

function vectorValue(name: string): Record<string, unknown> {
  const v = recordVectors.records.find((r) => r.name === name);
  if (v === undefined) throw new Error(`no vector named ${name}`);
  return fromJsonRecord(v.record === "RecoveryRecord" ? RECOVERY_RECORD : SECURITY_BUNDLE, v.value);
}

const RESET_RECORD = "RecoveryRecord, RECOVERY_RESET request at generation 3";
const VETO_BUNDLE = "SecurityBundle, RECOVERY_VETO (key 15 recovery, every other non-applicable field omitted)";

function codeOf(fn: () => unknown): RecordErrorCode | "NO_ERROR" | "OTHER_ERROR" {
  try {
    fn();
    return "NO_ERROR";
  } catch (e) {
    return e instanceof RecordError ? e.code : "OTHER_ERROR";
  }
}

describe("ADR-022 type lists (§23.4, §35.15)", () => {
  it("a request names exactly the three delayed operations, in the spec's order", () => {
    expect([...RECOVERY_REQUEST_KINDS]).toEqual(["RECOVERY_RESET", "RECOVERY_KIT_REPLACEMENT", "SWITCH_TO_MANAGED"]);
  });

  it("the three record operations are SecurityBundle operation types", () => {
    for (const type of ["RECOVERY_REQUEST", "RECOVERY_VETO", "RECOVERY_CANCEL"]) expect(OPERATION_TYPES).toContain(type);
  });
});

describe("RecoveryRecord round trip", () => {
  it("decode(encode(r)) deep-equals r for every generated record", () => {
    fc.assert(
      fc.property(arbRecord(RECOVERY_RECORD), (value) => {
        expect(decodeRecord(RECOVERY_RECORD, encodeRecord(RECOVERY_RECORD, value as never))).toEqual(value);
      }),
      { numRuns: 1000 },
    );
  });

  it("SecurityBundle with and without key 15 round-trips", () => {
    fc.assert(
      fc.property(arbRecord(SECURITY_BUNDLE), (value) => {
        expect(decodeRecord(SECURITY_BUNDLE, encodeRecord(SECURITY_BUNDLE, value as never))).toEqual(value);
      }),
      { numRuns: 300 },
    );
  });
});

describe("strict decoding of RecoveryRecord", () => {
  // Transcribed from §23.4: every field is required.
  const REQUIRED = ["request_id", "kind", "root_generation", "root_hash", "signature"] as const;

  for (const name of REQUIRED) {
    it(`rejects a missing ${name}`, () => {
      const map = toNce(RECOVERY_RECORD, vectorValue(RESET_RECORD) as never);
      map.delete(RECOVERY_RECORD.fields[name]!.key);
      expect(codeOf(() => fromNce(RECOVERY_RECORD, map))).toBe("MISSING_FIELD");
    });
  }

  it("rejects an unknown key 6", () => {
    const map = toNce(RECOVERY_RECORD, vectorValue(RESET_RECORD) as never);
    map.set(6, 0);
    expect(codeOf(() => fromNce(RECOVERY_RECORD, map))).toBe("UNKNOWN_KEY");
  });

  it("rejects every kind outside the three of §35.15, including the other operation types", () => {
    for (const bad of ["CHANGE_SECRETS", "SWITCH_TO_PRIVATE", "recovery_reset", "RECOVERY_REQUEST", ""]) {
      const map = toNce(RECOVERY_RECORD, vectorValue(RESET_RECORD) as never);
      map.set(2, bad);
      expect(codeOf(() => fromNce(RECOVERY_RECORD, map)), bad).toBe("INVALID_ENUM");
    }
  });

  it("request_id is 16 bytes, root_hash 32 and the signature 64 (P1363)", () => {
    for (const [key, length] of [[1, 15], [4, 31], [5, 63]] as const) {
      const map = toNce(RECOVERY_RECORD, vectorValue(RESET_RECORD) as never);
      map.set(key, new Uint8Array(length));
      expect(codeOf(() => fromNce(RECOVERY_RECORD, map)), `key ${key}`).toBe("WRONG_LENGTH");
    }
  });

  it("SecurityBundle rejects recovery = null (omit, never null, §23.4)", () => {
    const map = toNce(SECURITY_BUNDLE, vectorValue(VETO_BUNDLE) as never);
    map.set(15, null);
    expect(codeOf(() => fromNce(SECURITY_BUNDLE, map))).toBe("NULL_NOT_ALLOWED");
  });

  it("SecurityBundle without key 15 decodes with no recovery field at all", () => {
    const { recovery: _r, ...without } = vectorValue(VETO_BUNDLE);
    const decoded = decodeRecord(SECURITY_BUNDLE, encodeRecord(SECURITY_BUNDLE, without as never));
    expect(decoded).not.toHaveProperty("recovery");
  });
});
