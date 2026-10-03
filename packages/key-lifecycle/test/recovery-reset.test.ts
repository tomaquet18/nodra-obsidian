// §35.7: Recovery and Security Reset.
//
// The reset is the account's last resort, so the suite proves it by *using* the result: the new
// account keys must open the epochs that existed before the reset (through the coverage envelopes
// §33.2 created) and the epochs the reset itself created, the new secrets must open the new config,
// and the client that was trusted before must have no envelope anywhere in the new epochs.
//
// The broken variants are the two ways a reset can look right and be useless or unsafe:
//
//   (a) a reset that **reuses the old account recipient** instead of creating a new one. §28.2's
//       "Cambia" column makes both account keys MUST-change, so a descriptor that keeps them is
//       `INVALID_TRANSITION`; a bundle that keeps the new keys but seals coverage to the *old*
//       ACCOUNT recipient is `COVERAGE_STALE`. Both are tested, because they are the same mistake
//       at two different depths and only the first is visible in the transition.
//   (b) a reset that **forgets to re-envelope** for the new recipient: `COVERAGE_STALE`, which is
//       the only answer §34.2 allows the Worker to give.
import {
  importHkdfBase,
  importVerifyingKey,
  openEpochSecret,
  signContext,
  timingSafeEqual,
  verifyContext,
} from "@nodra/crypto";
import { describe, expect, it } from "vitest";
import { validateSecurityBundle } from "../src/bundle.js";
import { assembleBundle } from "../src/bundle-build.js";
import { expectedOf } from "../src/client-state.js";
import { envelopeLabelContext } from "../src/contexts.js";
import { deriveEpochCommitment, idKey, rootRecipientId } from "../src/epoch.js";
import { KeyLifecycleError } from "../src/errors.js";
import { recoveryReset } from "../src/recovery-reset.js";
import type { RecoveryReset } from "../src/recovery-reset.js";
import { openRecoveryKit } from "../src/recovery-kit.js";
import type { RecoveryHandles } from "../src/recovery-kit.js";
import { activeRecipients, nextRegistry, registryHash, signRegistry } from "../src/registry.js";
import { rotateLiveVaults } from "../src/rotation.js";
import { nextDescriptor, signRootTransition } from "../src/root-chain.js";
import { registryContext, rootTransitionContext } from "../src/contexts.js";
import { unlockSession } from "../src/unlock.js";
import { filled } from "./support.js";
import { envelopeFor, hasEnvelopeFor, operationWorld, withMaturedRequest, withScopes } from "./operations-support.js";

const RESET_BUNDLE_ID = filled(16, 0x91);
const NEW_EPOCH_A = filled(16, 0x9a);
const NEW_EPOCH_B = filled(16, 0x9b);
const NEW_PASSWORD = "the passphrase chosen during recovery";
const NEW_SALT = filled(16, 0x6c);

let handles: Promise<RecoveryHandles> | null = null;

/** §35.7 steps 1–2: the kit imported and proved against the root in force. */
async function kitHandles(): Promise<RecoveryHandles> {
  handles ??= (async () => {
    const world = await operationWorld();
    const opened = await openRecoveryKit({
      serialized: world.created.recoveryKit.serialized,
      accountId: world.accountId,
      genesisRootHash: world.view.genesisRootHash,
      currentDescriptor: world.view.root,
      ports: world.ports,
    });
    if (!opened.ok) throw new Error(`§35.7 step 2: ${opened.failure.code}`);
    return opened.value;
  })();
  return handles;
}

async function newEpochIds(): Promise<ReadonlyMap<string, Uint8Array>> {
  const world = await operationWorld();
  return new Map([
    [idKey(world.view.vaults[0]!.vaultId), NEW_EPOCH_A],
    [idKey(world.view.vaults[1]!.vaultId), NEW_EPOCH_B],
  ]);
}

/** The §35.7 result, built once: it generates two key pairs and runs Argon2id. */
let reset: Promise<RecoveryReset> | null = null;

async function performReset(): Promise<RecoveryReset> {
  reset ??= (async () => {
    const world = await operationWorld();
    const outcome = await recoveryReset({
      view: world.view,
      bundleId: RESET_BUNDLE_ID,
      recovery: await kitHandles(),
      password: NEW_PASSWORD,
      kdfSalt: NEW_SALT,
      newEpochIds: await newEpochIds(),
      sources: world.recoverySources,
      ports: world.ports,
    });
    if (!outcome.ok) throw new Error(`§35.7: ${outcome.failure.code} ${outcome.failure.message}`);
    return outcome.value;
  })();
  return reset;
}

describe("§35.7 the RECOVERY_RESET bundle", () => {
  it("is accepted by §35.1.1 with RECOVERY_CONTROL, a new epoch per vault and full coverage", async () => {
    const world = await operationWorld();
    const result = await performReset();
    const decision = await validateSecurityBundle(
      result.bundle,
      withMaturedRequest(withScopes(world.state, ["RECOVERY_CONTROL"]), "RECOVERY_RESET"),
    );
    expect(decision.ok).toBe(true);
    if (!decision.ok || decision.value.kind !== "ACCEPT") return;

    expect(decision.value.accepted.pendingRootGeneration).toBe(world.view.root.root_generation + 1);
    expect(decision.value.accepted.epochs).toHaveLength(2);
    expect(decision.value.accepted.coverageEnvelopes).toHaveLength(2);
    expect(decision.value.accepted.configVersion).toBe(world.view.configVersion + 1);
    expect(result.pins.epochs.map((pin) => idKey(pin.epochId))).toEqual([idKey(NEW_EPOCH_A), idKey(NEW_EPOCH_B)]);
  });

  it("changes exactly the keys §28.2 says it changes", async () => {
    const world = await operationWorld();
    const result = await performReset();
    const before = world.view.root;
    expect(timingSafeEqual(result.root.account_encryption_public_key, before.account_encryption_public_key)).toBe(false);
    expect(timingSafeEqual(result.root.account_signing_public_key, before.account_signing_public_key)).toBe(false);
    expect(timingSafeEqual(result.root.recovery_encryption_public_key, before.recovery_encryption_public_key)).toBe(true);
    expect(timingSafeEqual(result.root.recovery_authority_public_key, before.recovery_authority_public_key)).toBe(true);
    // §28.2: roles 3 (the kit in force) and 2 (the new Account Signing key), ascending.
    expect(result.rootTransition.signatures.map((s) => s.code)).toEqual([2, 3]);
  });

  it("leaves no recipient ACTIVE, and no envelope for the client that was trusted", async () => {
    const world = await operationWorld();
    const result = await performReset();
    expect(activeRecipients(result.registry)).toHaveLength(0);
    expect(result.revokedRecipientIds.map(idKey)).toEqual([idKey(world.client.recipient.recipientId)]);
    for (const epoch of result.epochs) {
      expect(hasEnvelopeFor(epoch.envelopes, world.client.recipient.recipientId)).toBe(false);
      expect(epoch.envelopes.map((e) => e.recipient_type).sort()).toEqual(["ACCOUNT", "RECOVERY"]);
    }
  });

  it("gives the NEW account keys real access: old epochs through coverage, new epochs directly", async () => {
    const world = await operationWorld();
    const result = await performReset();
    const newAccountId = await rootRecipientId(result.root.account_encryption_public_key);
    const privateKey = result.keyset.encryption.privateKey;

    // The coverage envelopes carry the *old* epoch secrets to the new key (§33.2, §34.2).
    for (const [i, envelope] of result.coverageEnvelopes.entries()) {
      const descriptor = world.recoverySources[i]!.descriptor;
      const label = envelopeLabelContext(descriptor.vault_id, descriptor.epoch_id, newAccountId, "ACCOUNT");
      const secret = await openEpochSecret(privateKey, label, envelope.ciphertext);
      const commitment = await deriveEpochCommitment(
        await importHkdfBase(secret),
        descriptor.vault_id,
        descriptor.epoch_id,
      );
      expect(timingSafeEqual(commitment, descriptor.epoch_commitment)).toBe(true);
    }

    // And the epochs the reset itself created open under the same key.
    for (const epoch of result.epochs) {
      const label = envelopeLabelContext(
        epoch.descriptor.vault_id,
        epoch.descriptor.epoch_id,
        newAccountId,
        "ACCOUNT",
      );
      const secret = await openEpochSecret(
        privateKey,
        label,
        envelopeFor(epoch.envelopes, newAccountId).ciphertext,
      );
      const commitment = await deriveEpochCommitment(
        await importHkdfBase(secret),
        epoch.descriptor.vault_id,
        epoch.descriptor.epoch_id,
      );
      expect(timingSafeEqual(commitment, epoch.descriptor.epoch_commitment)).toBe(true);
    }
  });

  it("makes the new secrets open the new config, at the new generation", async () => {
    const world = await operationWorld();
    const result = await performReset();
    const unlocked = await unlockSession({
      accountId: world.accountId,
      profile: result.profile,
      secrets: { password: NEW_PASSWORD, secretKey: result.setupKit!.accountSecretKey },
      ports: world.ports,
    });
    expect(unlocked.ok).toBe(true);
    if (!unlocked.ok) return;
    expect(unlocked.value.config.root_generation).toBe(result.root.root_generation);
    expect(timingSafeEqual(unlocked.value.config.root_hash, result.rootHash)).toBe(true);
    expect(unlocked.value.config.config_version).toBe(world.view.configVersion + 1);
    // §26: the genesis hash never moves, which is what the kit is pinned to (§27.1).
    expect(timingSafeEqual(unlocked.value.config.genesis_root_hash, world.view.genesisRootHash)).toBe(true);
  });

  it("signs the new registry and descriptors with the NEW Account Signing Key", async () => {
    const result = await performReset();
    const key = await importVerifyingKey(result.root.account_signing_public_key);
    expect(result.registry.root_generation).toBe(result.root.root_generation);
    // Checked directly, so the reason is visible rather than inferred from an error code: the
    // registry of a reset is signed by the key the *new* root names (§35.1.1 step 3).
    const { signature, ...unsigned } = result.registry;
    expect(await verifyContext(key, registryContext(unsigned), signature)).toBe(true);
    for (const epoch of result.epochs) {
      expect(epoch.descriptor.root_generation).toBe(result.root.root_generation);
      expect(epoch.descriptor.registry_version).toBe(result.registry.registry_version);
    }
  });
});

describe("§35.7 broken variants", () => {
  it("is INVALID_SIGNATURE when the transition does not carry exactly roles 3 and 2", async () => {
    const world = await operationWorld();
    const result = await performReset();
    // Roles 2 + 4 is GENESIS's set, and both signatures are producible here (the recovery keys do
    // not change in a reset, so "new Recovery Authority" is the kit's own key).
    const unsigned = {
      account_id: result.rootTransition.account_id,
      transition_type: result.rootTransition.transition_type,
      old_root_hash: result.rootTransition.old_root_hash,
      new_root_hash: result.rootTransition.new_root_hash,
      new_root_generation: result.rootTransition.new_root_generation,
    };
    const ctx = rootTransitionContext(unsigned);
    const kit = await kitHandles();
    const forgedTransition = {
      ...unsigned,
      signatures: [
        { code: 2 as const, value: await signContext(result.keyset.signing.privateKey, ctx) },
        { code: 4 as const, value: await signContext(kit.authorityKey, ctx) },
      ],
    };
    const forged = assembleBundle({
      operationType: "RECOVERY_RESET",
      bundleId: RESET_BUNDLE_ID,
      expected: expectedOf(world.view),
      rootTransition: forgedTransition,
      rootDescriptor: result.root,
      registry: result.registry,
      profile: result.profile,
      epochs: result.epochs.map((e) => ({ descriptor: e.descriptor, envelopes: [...e.envelopes] })),
      coverageEnvelopes: [...result.coverageEnvelopes],
    });
    const decision = await validateSecurityBundle(forged, withMaturedRequest(withScopes(world.state, ["RECOVERY_CONTROL"]), "RECOVERY_RESET"));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_SIGNATURE");
    expect(decision.failure.rule).toBe("transition/BAD_SIGNATURE_SET");
  });

  it("is INVALID_TRANSITION when it reuses the old account recipient instead of creating one", async () => {
    const world = await operationWorld();
    const result = await performReset();
    const kit = await kitHandles();
    // The mistake in its purest form: a RECOVERY_RESET whose new descriptor keeps the account keys
    // it is supposed to replace. Signed correctly, chained correctly — and still refused, because
    // §28.2 rule 6 is what makes a reset a reset.
    const sameKeys = await nextDescriptor(world.view.root, {});
    const transition = await signRootTransition({
      type: "RECOVERY_RESET",
      descriptor: sameKeys,
      previous: world.view.root,
      // The "new" Account Signing key is the old one here, which is exactly the point.
      signers: { 2: world.created.keyset.signing.privateKey, 3: kit.authorityKey },
    });
    const forged = assembleBundle({
      operationType: "RECOVERY_RESET",
      bundleId: RESET_BUNDLE_ID,
      expected: expectedOf(world.view),
      rootTransition: transition,
      rootDescriptor: sameKeys,
      registry: result.registry,
      profile: result.profile,
      epochs: result.epochs.map((e) => ({ descriptor: e.descriptor, envelopes: [...e.envelopes] })),
      coverageEnvelopes: [...result.coverageEnvelopes],
    });
    const decision = await validateSecurityBundle(forged, withMaturedRequest(withScopes(world.state, ["RECOVERY_CONTROL"]), "RECOVERY_RESET"));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_TRANSITION");
    expect(decision.failure.rule).toBe("transition/FORBIDDEN_KEY_CHANGE");
  });

  it("is COVERAGE_STALE when the coverage is sealed to the OLD account recipient", async () => {
    const world = await operationWorld();
    const result = await performReset();
    // New keys, new transition — but the coverage envelopes are the ones the old ACCOUNT key
    // already had. Nothing is missing, nothing is malformed; it simply covers the wrong key.
    const forged = assembleBundle({
      operationType: "RECOVERY_RESET",
      bundleId: RESET_BUNDLE_ID,
      expected: expectedOf(world.view),
      rootTransition: result.rootTransition,
      rootDescriptor: result.root,
      registry: result.registry,
      profile: result.profile,
      epochs: result.epochs.map((e) => ({ descriptor: e.descriptor, envelopes: [...e.envelopes] })),
      coverageEnvelopes: world.sources.map((source) => source.envelope),
    });
    const decision = await validateSecurityBundle(forged, withMaturedRequest(withScopes(world.state, ["RECOVERY_CONTROL"]), "RECOVERY_RESET"));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("COVERAGE_STALE");
    expect(decision.failure.retryable).toBe(true);
  });

  it("is COVERAGE_STALE when the reset forgets to re-envelope at all", async () => {
    const world = await operationWorld();
    const result = await performReset();
    const forged = assembleBundle({
      operationType: "RECOVERY_RESET",
      bundleId: RESET_BUNDLE_ID,
      expected: expectedOf(world.view),
      rootTransition: result.rootTransition,
      rootDescriptor: result.root,
      registry: result.registry,
      profile: result.profile,
      epochs: result.epochs.map((e) => ({ descriptor: e.descriptor, envelopes: [...e.envelopes] })),
      coverageEnvelopes: [],
    });
    const decision = await validateSecurityBundle(forged, withMaturedRequest(withScopes(world.state, ["RECOVERY_CONTROL"]), "RECOVERY_RESET"));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("COVERAGE_STALE");
    expect(decision.failure.rule).toBe("coverage/MISSING_ENVELOPE");
  });

  it("is INVALID_REGISTRY when a recipient survives the reset", async () => {
    const world = await operationWorld();
    const result = await performReset();
    // §35.1.1's "Forma del registry": RECOVERY_RESET leaves nobody ACTIVE. A registry that only
    // moves the generation would let a compromised device keep its slot through a Security Reset.
    const survivor = await signRegistry(
      await nextRegistry(world.view.registry, { rootGeneration: result.root.root_generation }),
      result.keyset.signing.privateKey,
    );
    // The epochs are rebuilt against that registry, so the bundle is consistent everywhere else
    // (§36.2) and the only thing left to reject is the shape §35.1.1 demands.
    const rotation = await rotateLiveVaults({
      vaults: world.view.vaults,
      root: result.root,
      rootHash: result.rootHash,
      registry: survivor,
      registryHash: await registryHash(survivor),
      newEpochIds: await newEpochIds(),
      signingKey: result.keyset.signing.privateKey,
      ports: world.ports,
    });
    const forged = assembleBundle({
      operationType: "RECOVERY_RESET",
      bundleId: RESET_BUNDLE_ID,
      expected: expectedOf(world.view),
      rootTransition: result.rootTransition,
      rootDescriptor: result.root,
      registry: survivor,
      profile: result.profile,
      epochs: [...rotation.bundleEpochs],
      coverageEnvelopes: [...result.coverageEnvelopes],
    });
    const decision = await validateSecurityBundle(forged, withMaturedRequest(withScopes(world.state, ["RECOVERY_CONTROL"]), "RECOVERY_RESET"));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_REGISTRY");
    expect(decision.failure.rule).toBe("registry/none-active");
  });

  it("needs RECOVERY_CONTROL: no other scope authorizes a reset (§11.3)", async () => {
    const world = await operationWorld();
    const result = await performReset();
    const decision = await validateSecurityBundle(result.bundle, withScopes(world.state, ["TRUSTED_SECURITY"]));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("SCOPE_REQUIRED");
  });

  it("refuses to build when a live vault has no new epoch id", async () => {
    const world = await operationWorld();
    await expect(
      recoveryReset({
        view: world.view,
        bundleId: filled(16, 0x92),
        recovery: await kitHandles(),
        password: NEW_PASSWORD,
        kdfSalt: NEW_SALT,
        newEpochIds: new Map([[idKey(world.view.vaults[0]!.vaultId), NEW_EPOCH_A]]),
        sources: world.recoverySources,
        ports: world.ports,
      }),
    ).rejects.toBeInstanceOf(KeyLifecycleError);
  });

  it("stops locally, before any signature, when a source envelope is missing", async () => {
    const world = await operationWorld();
    const outcome = await recoveryReset({
      view: world.view,
      bundleId: filled(16, 0x93),
      recovery: await kitHandles(),
      password: NEW_PASSWORD,
      kdfSalt: NEW_SALT,
      newEpochIds: await newEpochIds(),
      sources: [world.recoverySources[0]!],
      ports: world.ports,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.failure.code).toBe("MISSING_SOURCE_ENVELOPE");
    expect(outcome.failure.step).toBe(5);
  });
});
