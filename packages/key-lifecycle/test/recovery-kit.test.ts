// §27: the Recovery Kit, its self-test, and what a recovery operation reads out of it.
import { beforeAll, describe, expect, it } from "vitest";
import {
  domainContext,
  importEnvelopePublicKey,
  importVerifyingKey,
  openEpochSecret,
  randomBytes,
  sealEpochSecret,
  signContext,
  verifyContext,
} from "@nodra/crypto";
import { context } from "@nodra/encoding";
import { RECOVERY_KIT, toNce } from "@nodra/encoding/records";
import {
  SELF_TEST_NONCE_BYTES,
  createRecoveryKit,
  openRecoveryKit,
  parseRecoveryKit,
  selfTestRecoveryKit,
  serializeRecoveryKit,
  verifyRecoveryKit,
} from "../src/recovery-kit.js";
import type { RecoveryKitFailureCode } from "../src/recovery-kit.js";
import { rootTransitionContext } from "../src/contexts.js";
import { rootHash } from "../src/root-chain.js";
import { kitPorts, makeKitFixture, withKit } from "./recovery-kit-support.js";
import type { KitFixture } from "./recovery-kit-support.js";
import { FIXED_NOW, filled, flipByte } from "./support.js";

let f: KitFixture;

beforeAll(async () => {
  f = await makeKitFixture();
}, 120_000);

/** Every rejection in this file goes through here, so no test can pass on an `ok` result. */
async function selfTestCode(
  serialized: Uint8Array,
  overrides: Partial<Parameters<typeof selfTestRecoveryKit>[0]> = {},
): Promise<RecoveryKitFailureCode> {
  const result = await selfTestRecoveryKit({
    serialized,
    accountId: f.accountId,
    pendingDescriptor: f.currentDescriptor,
    ports: kitPorts,
    ...overrides,
  });
  if (result.ok) throw new Error("expected a rejection, the self-test passed");
  return result.failure.code;
}

describe("§27.1 the document", () => {
  it("carries exactly the seven fields, with the clock coming from the port", () => {
    const kit = f.kitA.kit;
    expect(kit.account_id).toEqual(f.accountId);
    expect(kit.genesis_root_hash).toEqual(f.genesisRootHash);
    expect(kit.recovery_encryption_private_key).toEqual(f.keysA.encryption.privateKeyPkcs8);
    expect(kit.recovery_authority_private_key).toEqual(f.keysA.authority.privateKeyPkcs8);
    expect(kit.recovery_encryption_public_key_hash).toEqual(f.keysA.encryption.publicKeyHash);
    expect(kit.recovery_authority_public_key_hash).toEqual(f.keysA.authority.publicKeyHash);
    expect(kit.created_at).toBe(FIXED_NOW());
  });

  it("is delivered as Context(\"nodra/recovery-kit\", RecoveryKit), deterministically", () => {
    // Recomputed here from the primitives, so the nesting decision of NOTES 189/196 is pinned by
    // an assertion and not only by the implementation that made it.
    expect(f.kitA.serialized).toEqual(context("nodra/recovery-kit", toNce(RECOVERY_KIT, f.kitA.kit)));
    expect(serializeRecoveryKit(f.kitA.kit)).toEqual(f.kitA.serialized);
  });

  it("round-trips through the delivered bytes", () => {
    const parsed = parseRecoveryKit(f.kitA.serialized);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.value).toEqual(f.kitA.kit);
  });

  it("refuses a clock that is not Unix milliseconds", async () => {
    await expect(
      createRecoveryKit({
        accountId: f.accountId,
        genesisRootHash: f.genesisRootHash,
        keys: f.keysA,
        ports: { ...kitPorts, now: () => 1.5 },
      }),
    ).rejects.toThrow(/created_at/);
  });
});

describe("§27.3 the self-test, against the pending root", () => {
  it("passes for a kit whose keys are the pending descriptor's", async () => {
    const result = await selfTestRecoveryKit({
      serialized: f.kitA.serialized,
      accountId: f.accountId,
      genesisRootHash: f.genesisRootHash,
      pendingDescriptor: f.currentDescriptor,
      ports: kitPorts,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.scope).toBe("PENDING");
      expect(result.value.nonce).toHaveLength(SELF_TEST_NONCE_BYTES);
    }
  });

  it("passes for the replacement kit against the pending descriptor of its replacement", async () => {
    const result = await selfTestRecoveryKit({
      serialized: f.kitB.serialized,
      accountId: f.accountId,
      pendingDescriptor: f.pendingDescriptor,
      ports: kitPorts,
    });
    expect(result.ok).toBe(true);
  });

  it("rejects a kit for another account before it builds the self-test label", async () => {
    const other = filled(16, 0x22);
    expect(await selfTestCode(withKit(f.kitA.kit, { account_id: other }))).toBe("ACCOUNT_MISMATCH");
    expect(
      await selfTestCode(f.kitA.serialized, {
        accountId: other,
        pendingDescriptor: { ...f.currentDescriptor, account_id: other },
      }),
    ).toBe("ACCOUNT_MISMATCH");
  });

  it("rejects a kit issued for another root chain", async () => {
    expect(await selfTestCode(f.kitA.serialized, { genesisRootHash: filled(32, 0xee) })).toBe("GENESIS_MISMATCH");
  });

  it("rejects a kit bound to a different root generation", async () => {
    // Kit A is correct for generation 1 and wrong for the generation-2 descriptor that replaces it.
    expect(await selfTestCode(f.kitA.serialized, { pendingDescriptor: f.pendingDescriptor })).toBe(
      "ENCRYPTION_ROUND_TRIP_FAILED",
    );
    expect(await selfTestCode(f.kitB.serialized)).toBe("ENCRYPTION_ROUND_TRIP_FAILED");
  });

  it("rejects a tampered kit record", async () => {
    expect(await selfTestCode(flipByte(f.kitA.serialized, 3))).toBe("MALFORMED_KIT");
  });

  describe("one corrupted input at a time", () => {
    it("step 1: a foreign Recovery Encryption private key", async () => {
      const serialized = withKit(f.kitA.kit, {
        recovery_encryption_private_key: f.keysB.encryption.privateKeyPkcs8,
      });
      expect(await selfTestCode(serialized)).toBe("ENCRYPTION_ROUND_TRIP_FAILED");
    });

    it("step 1: a Recovery Encryption private key that is not PKCS#8 at all", async () => {
      const serialized = withKit(f.kitA.kit, { recovery_encryption_private_key: filled(40, 0x00) });
      expect(await selfTestCode(serialized)).toBe("MALFORMED_KIT_PRIVATE_KEY");
    });

    it("step 1: a Root Descriptor whose recovery encryption key is not an SPKI key", async () => {
      expect(
        await selfTestCode(f.kitA.serialized, {
          pendingDescriptor: { ...f.currentDescriptor, recovery_encryption_public_key: filled(20, 0x07) },
        }),
      ).toBe("MALFORMED_ROOT_PUBLIC_KEY");
    });

    it("step 2: a foreign Recovery Authority private key", async () => {
      const serialized = withKit(f.kitA.kit, {
        recovery_authority_private_key: f.keysB.authority.privateKeyPkcs8,
      });
      expect(await selfTestCode(serialized)).toBe("AUTHORITY_SIGNATURE_FAILED");
    });

    it("step 2: a Recovery Authority private key that is not PKCS#8 at all", async () => {
      const serialized = withKit(f.kitA.kit, { recovery_authority_private_key: filled(40, 0x00) });
      expect(await selfTestCode(serialized)).toBe("MALFORMED_KIT_PRIVATE_KEY");
    });

    it("step 3: either recorded public key hash", async () => {
      expect(
        await selfTestCode(withKit(f.kitA.kit, { recovery_encryption_public_key_hash: filled(32, 0x00) })),
      ).toBe("KEY_HASH_MISMATCH");
      expect(
        await selfTestCode(withKit(f.kitA.kit, { recovery_authority_public_key_hash: filled(32, 0x00) })),
      ).toBe("KEY_HASH_MISMATCH");
    });
  });

  it("would catch a self-test that always returned pass", async () => {
    // The broken-variant proof of the project's evidence discipline: an invariant that cannot
    // fail proves nothing. Each of these kits is defective in a different way, and a "self-test"
    // that returned `ok` unconditionally would present every one of them to a user.
    const broken = [
      withKit(f.kitA.kit, { account_id: filled(16, 0x22) }),
      withKit(f.kitA.kit, { recovery_encryption_private_key: f.keysB.encryption.privateKeyPkcs8 }),
      withKit(f.kitA.kit, { recovery_authority_private_key: f.keysB.authority.privateKeyPkcs8 }),
      withKit(f.kitA.kit, { recovery_encryption_public_key_hash: filled(32, 0x00) }),
      withKit(f.kitA.kit, { recovery_authority_public_key_hash: filled(32, 0x00) }),
      flipByte(f.kitA.serialized, 3),
    ];
    expect(broken).not.toHaveLength(0);
    for (const serialized of broken) {
      const result = await selfTestRecoveryKit({
        serialized,
        accountId: f.accountId,
        pendingDescriptor: f.currentDescriptor,
        ports: kitPorts,
      });
      expect(result.ok).toBe(false);
    }
  });

  it("would catch a self-test that tested against the current root instead of the pending one", async () => {
    // §27.3 step 3 says "pendiente". In a RECOVERY_KIT_REPLACEMENT the root in force still holds
    // the *old* recovery keys, so the variant that checked the current root would reject the new
    // kit — the one the operation is about to commit — and accept nothing in its place.
    const againstPending = await selfTestRecoveryKit({
      serialized: f.kitB.serialized,
      accountId: f.accountId,
      pendingDescriptor: f.pendingDescriptor,
      ports: kitPorts,
    });
    const againstCurrent = await verifyRecoveryKit({
      serialized: f.kitB.serialized,
      accountId: f.accountId,
      currentDescriptor: f.currentDescriptor,
      ports: kitPorts,
    });
    expect(againstPending.ok).toBe(true);
    expect(againstCurrent.ok).toBe(false);
  });
});

describe("Verify Recovery Kit, against the root in force", () => {
  it("passes for the kit of the current root and reports that scope", async () => {
    const result = await verifyRecoveryKit({
      serialized: f.kitA.serialized,
      accountId: f.accountId,
      genesisRootHash: f.genesisRootHash,
      currentDescriptor: f.currentDescriptor,
      ports: kitPorts,
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.scope).toBe("CURRENT");
  });
});

describe("§27.2 what a recovery operation reads out of a kit", () => {
  it("opens a RECOVERY envelope and signs as Recovery Authority", async () => {
    const opened = await openRecoveryKit({
      serialized: f.kitA.serialized,
      accountId: f.accountId,
      genesisRootHash: f.genesisRootHash,
      currentDescriptor: f.currentDescriptor,
      ports: kitPorts,
    });
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;

    // §35.7 step 5: the RECOVERY envelope of an epoch, sealed to the root's recovery key.
    const label = domainContext(
      "nodra/envelope-label",
      filled(16, 0x51),
      filled(16, 0x52),
      filled(16, 0x53),
      "RECOVERY",
    );
    const epochSecret = randomBytes(32);
    const ciphertext = await sealEpochSecret(
      await importEnvelopePublicKey(f.currentDescriptor.recovery_encryption_public_key),
      label,
      epochSecret,
    );
    expect(await openEpochSecret(opened.value.encryptionKey, label, ciphertext)).toEqual(epochSecret);

    // §35.7 step 6: signer role 3 of a RECOVERY_RESET.
    const transition = rootTransitionContext({
      account_id: f.accountId,
      transition_type: "RECOVERY_RESET",
      old_root_hash: await rootHash(f.currentDescriptor),
      new_root_hash: filled(32, 0x61),
      new_root_generation: 2,
    });
    const signature = await signContext(opened.value.authorityKey, transition);
    const verifier = await importVerifyingKey(f.currentDescriptor.recovery_authority_public_key);
    expect(await verifyContext(verifier, transition, signature)).toBe(true);
  });

  it("hands out no handles when the kit does not match the root in force", async () => {
    const opened = await openRecoveryKit({
      serialized: f.kitB.serialized,
      accountId: f.accountId,
      currentDescriptor: f.currentDescriptor,
      ports: kitPorts,
    });
    expect(opened.ok).toBe(false);
    if (!opened.ok) expect(opened.failure.code).toBe("ENCRYPTION_ROUND_TRIP_FAILED");
  });
});
