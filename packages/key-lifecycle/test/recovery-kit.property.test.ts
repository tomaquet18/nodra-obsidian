// Property runs over §27: the delivered bytes round-trip, and every single-byte mutation of every
// kit field is either refused by the codec or visible in the decoded kit — never a silent success.
import { beforeAll, describe, expect, it } from "vitest";
import fc from "fast-check";
import type { RecoveryKit } from "@nodra/encoding/records";
import { openRecoveryKit, parseRecoveryKit, selfTestRecoveryKit, serializeRecoveryKit } from "../src/recovery-kit.js";
import { kitPorts, makeKitFixture } from "./recovery-kit-support.js";
import type { KitFixture } from "./recovery-kit-support.js";
import { flipByte } from "./support.js";

let f: KitFixture;

beforeAll(async () => {
  f = await makeKitFixture();
}, 120_000);

const bytesOf = (length: number): fc.Arbitrary<Uint8Array> =>
  fc.uint8Array({ minLength: length, maxLength: length });

/** Arbitrary kits: the shapes of §27.1, with no requirement that the key material be real. */
const arbitraryKit: fc.Arbitrary<RecoveryKit> = fc.record({
  account_id: bytesOf(16),
  genesis_root_hash: bytesOf(32),
  recovery_encryption_private_key: fc.uint8Array({ minLength: 0, maxLength: 200 }),
  recovery_authority_private_key: fc.uint8Array({ minLength: 0, maxLength: 200 }),
  recovery_encryption_public_key_hash: bytesOf(32),
  recovery_authority_public_key_hash: bytesOf(32),
  created_at: fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
});

/**
 * The four fields whose bytes the self-test binds exactly: change one and §27.3 MUST reject.
 *
 * The two private-key fields are deliberately absent. §27.3 proves the kit *works*, not that its
 * PKCS#8 bytes are the ones that were written: a PKCS#8 RSA key carries redundant material (the
 * non-CRT private exponent, the embedded public key), so some single-byte changes leave a key
 * that still decrypts. That kit is still a good kit, which is exactly what the test is for — see
 * NOTES question 197. `created_at` is bound by nothing.
 */
const BOUND_FIELDS = [
  "account_id",
  "genesis_root_hash",
  "recovery_encryption_public_key_hash",
  "recovery_authority_public_key_hash",
] as const satisfies readonly (keyof RecoveryKit)[];

const PRIVATE_KEY_FIELDS = [
  "recovery_encryption_private_key",
  "recovery_authority_private_key",
] as const satisfies readonly (keyof RecoveryKit)[];

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

describe("§27.1 serialization", () => {
  it("round-trips every kit shape", () => {
    fc.assert(
      fc.property(arbitraryKit, (kit) => {
        const parsed = parseRecoveryKit(serializeRecoveryKit(kit));
        expect(parsed.ok).toBe(true);
        if (parsed.ok) expect(parsed.value).toEqual(kit);
      }),
      { numRuns: 200 },
    );
  });

  it("refuses bytes that decode to a kit but are not its canonical encoding", () => {
    fc.assert(
      fc.property(arbitraryKit, fc.integer({ min: 0, max: 4096 }), (kit, index) => {
        const serialized = serializeRecoveryKit(kit);
        const mutated = flipByte(serialized, index);
        const parsed = parseRecoveryKit(mutated);
        // Either the codec refuses it, or it decodes to a *different* kit — never back to `kit`.
        if (parsed.ok) expect(parsed.value).not.toEqual(kit);
      }),
      { numRuns: 300 },
    );
  });
});

describe("§27.3 single-byte mutation of a real kit", () => {
  it("is caught whenever it touches a field the self-test covers", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 0, max: 4096 }), async (index) => {
        const mutated = flipByte(f.kitA.serialized, index);
        const parsed = parseRecoveryKit(mutated);
        if (!parsed.ok) return; // the codec already rejected it

        const result = await selfTestRecoveryKit({
          serialized: mutated,
          accountId: f.accountId,
          genesisRootHash: f.genesisRootHash,
          pendingDescriptor: f.currentDescriptor,
          ports: kitPorts,
        });
        const changed = (fields: readonly (keyof RecoveryKit)[]): boolean =>
          fields.some((field) => !sameBytes(parsed.value[field] as Uint8Array, f.kitA.kit[field] as Uint8Array));

        if (changed(BOUND_FIELDS)) {
          expect(result.ok).toBe(false);
          return;
        }
        if (changed(PRIVATE_KEY_FIELDS)) {
          // Either the mutated key no longer works — rejected — or it is still the same key in a
          // different PKCS#8 spelling. That second case is not a silent success: the kit must
          // still hand out working handles, which is the whole claim §27.3 makes about it.
          if (result.ok) {
            const opened = await openRecoveryKit({
              serialized: mutated,
              accountId: f.accountId,
              genesisRootHash: f.genesisRootHash,
              currentDescriptor: f.currentDescriptor,
              ports: kitPorts,
            });
            expect(opened.ok).toBe(true);
          }
          return;
        }
        // Nothing the self-test binds changed: only `created_at` can have moved, and it must pass.
        expect(result.ok).toBe(true);
        expect(parsed.value.created_at).not.toBe(f.kitA.kit.created_at);
      }),
      { numRuns: 60 },
    );
  }, 120_000);
});
