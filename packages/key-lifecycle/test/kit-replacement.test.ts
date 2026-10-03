// §35.9: replacing the Recovery Kit.
//
// What must be true afterwards is asymmetric, and both halves are tested with the real keys: the
// NEW kit must open everything the account holds — the epochs that existed before (through the
// coverage envelopes of §33.2) and the epochs the replacement created — while the OLD kit must
// open nothing new. That asymmetry is the entire point of rotating every vault in step 7; without
// it a kit that was photographed, lost or copied would keep reading the account forever.
//
// The two broken variants are §35.9's own preconditions:
//
//   (a) a kit that fails its self-test (§27.3) is never returned, so no bundle exists to send;
//   (b) a replacement that **skips the round-trip** produces coverage the Worker accepts (§32.3 is
//       presence only) and the new kit cannot open. The test asserts both halves, which is the
//       argument for why §33.2 makes the round-trip mandatory rather than advisory.
import { importHkdfBase, importVerifyingKey, openEpochSecret, signContext, timingSafeEqual, verifyContext } from "@nodra/crypto";
import { describe, expect, it } from "vitest";
import { validateSecurityBundle } from "../src/bundle.js";
import { assembleBundle } from "../src/bundle-build.js";
import { expectedOf } from "../src/client-state.js";
import { envelopeLabelContext, registryContext, rootTransitionContext } from "../src/contexts.js";
import { deriveEpochCommitment, idKey, rootRecipientId } from "../src/epoch.js";
import { KeyLifecycleError } from "../src/errors.js";
import { replaceRecoveryKit } from "../src/kit-replacement.js";
import type { ReplacedRecoveryKit } from "../src/kit-replacement.js";
import { proveEnvelope } from "../src/re-envelope.js";
import { generateRecoveryKeyPairs, verifyRecoveryKit } from "../src/recovery-kit.js";
import type { RecoveryKeyPairs } from "../src/recovery-kit.js";
import { nextRegistry, registryHash, signRegistry } from "../src/registry.js";
import { rotateLiveVaults } from "../src/rotation.js";
import { importEnvelopeDecryptKey } from "@nodra/crypto";
import { filled } from "./support.js";
import { envelopeFor, operationWorld, recoveryDecryptKey, withMaturedRequest, withScopes } from "./operations-support.js";

const KIT_BUNDLE_ID = filled(16, 0xa1);
const NEW_EPOCH_A = filled(16, 0xaa);
const NEW_EPOCH_B = filled(16, 0xab);

async function newEpochIds(): Promise<ReadonlyMap<string, Uint8Array>> {
  const world = await operationWorld();
  return new Map([
    [idKey(world.view.vaults[0]!.vaultId), NEW_EPOCH_A],
    [idKey(world.view.vaults[1]!.vaultId), NEW_EPOCH_B],
  ]);
}

/** The §35.9 result, built once: two fresh recovery pairs plus the rotation of both vaults. */
let replaced: Promise<ReplacedRecoveryKit> | null = null;

async function replacement(): Promise<ReplacedRecoveryKit> {
  replaced ??= (async () => {
    const world = await operationWorld();
    const outcome = await replaceRecoveryKit({
      view: world.view,
      bundleId: KIT_BUNDLE_ID,
      keys: world.keys,
      newEpochIds: await newEpochIds(),
      sources: world.sources,
      ports: world.ports,
    });
    if (!outcome.ok) throw new Error(`§35.9: ${outcome.failure.code} ${outcome.failure.message}`);
    return outcome.value;
  })();
  return replaced;
}

describe("§35.9 the RECOVERY_KIT_REPLACEMENT bundle", () => {
  it("is accepted by §35.1.1, with the identical recipient list at a new generation", async () => {
    const world = await operationWorld();
    const result = await replacement();
    const decision = await validateSecurityBundle(
      result.bundle,
      withMaturedRequest(withScopes(world.state, ["TRUSTED_SECURITY"]), "RECOVERY_KIT_REPLACEMENT"),
    );
    expect(decision.ok).toBe(true);
    if (!decision.ok || decision.value.kind !== "ACCEPT") return;

    expect(decision.value.accepted.pendingRootGeneration).toBe(world.view.root.root_generation + 1);
    expect(decision.value.accepted.epochs).toHaveLength(2);
    expect(decision.value.accepted.coverageEnvelopes).toHaveLength(2);
    expect(decision.value.accepted.configVersion).toBe(world.view.configVersion + 1);
    // "Forma del registry": the same recipients, in the same states, one version further on.
    expect(result.registry.recipients.map((r) => [idKey(r.recipient_id), r.status])).toEqual(
      world.view.registry.recipients.map((r) => [idKey(r.recipient_id), r.status]),
    );
    expect(result.registry.root_generation).toBe(result.root.root_generation);
  });

  it("changes exactly the keys §28.2 says it changes, signed by roles 1 and 4", async () => {
    const world = await operationWorld();
    const result = await replacement();
    const before = world.view.root;
    expect(timingSafeEqual(result.root.recovery_encryption_public_key, before.recovery_encryption_public_key)).toBe(false);
    expect(timingSafeEqual(result.root.recovery_authority_public_key, before.recovery_authority_public_key)).toBe(false);
    expect(timingSafeEqual(result.root.account_encryption_public_key, before.account_encryption_public_key)).toBe(true);
    expect(timingSafeEqual(result.root.account_signing_public_key, before.account_signing_public_key)).toBe(true);
    expect(result.rootTransition.signatures.map((s) => s.code)).toEqual([1, 4]);
    // The Account Signing key did not move, so the registry is signed by the same key as before.
    const key = await importVerifyingKey(result.root.account_signing_public_key);
    const { signature, ...unsigned } = result.registry;
    expect(await verifyContext(key, registryContext(unsigned), signature)).toBe(true);
  });

  it("self-tests the new kit against the PENDING root, which the root in force would reject", async () => {
    const world = await operationWorld();
    const result = await replacement();
    expect(result.selfTest.scope).toBe("PENDING");

    const againstPending = await verifyRecoveryKit({
      serialized: result.recoveryKit.serialized,
      accountId: world.accountId,
      genesisRootHash: world.view.genesisRootHash,
      currentDescriptor: result.root,
      ports: world.ports,
    });
    expect(againstPending.ok).toBe(true);

    const againstCurrent = await verifyRecoveryKit({
      serialized: result.recoveryKit.serialized,
      accountId: world.accountId,
      genesisRootHash: world.view.genesisRootHash,
      currentDescriptor: world.view.root,
      ports: world.ports,
    });
    expect(againstCurrent.ok).toBe(false);
    if (againstCurrent.ok) return;
    expect(againstCurrent.failure.code).toBe("ENCRYPTION_ROUND_TRIP_FAILED");
  });

  it("lets the NEW kit open the old epochs through coverage and the new epochs directly", async () => {
    const world = await operationWorld();
    const result = await replacement();
    const newRecoveryId = await rootRecipientId(result.root.recovery_encryption_public_key);
    const kitKey = await importEnvelopeDecryptKey(result.recoveryKit.kit.recovery_encryption_private_key);

    for (const [i, envelope] of result.coverageEnvelopes.entries()) {
      const descriptor = world.sources[i]!.descriptor;
      const label = envelopeLabelContext(descriptor.vault_id, descriptor.epoch_id, newRecoveryId, "RECOVERY");
      const secret = await openEpochSecret(kitKey, label, envelope.ciphertext);
      const commitment = await deriveEpochCommitment(
        await importHkdfBase(secret),
        descriptor.vault_id,
        descriptor.epoch_id,
      );
      expect(timingSafeEqual(commitment, descriptor.epoch_commitment)).toBe(true);
    }

    for (const epoch of result.epochs) {
      const label = envelopeLabelContext(
        epoch.descriptor.vault_id,
        epoch.descriptor.epoch_id,
        newRecoveryId,
        "RECOVERY",
      );
      const secret = await openEpochSecret(
        kitKey,
        label,
        envelopeFor(epoch.envelopes, newRecoveryId).ciphertext,
      );
      const commitment = await deriveEpochCommitment(
        await importHkdfBase(secret),
        epoch.descriptor.vault_id,
        epoch.descriptor.epoch_id,
      );
      expect(timingSafeEqual(commitment, epoch.descriptor.epoch_commitment)).toBe(true);
    }
  });

  it("leaves the OLD kit with no envelope in the new epochs (§35.9 step 7)", async () => {
    const world = await operationWorld();
    const result = await replacement();
    const oldKey = await recoveryDecryptKey(world.recoveryKit);
    const oldRecoveryId = world.recovery.recipientId;

    for (const epoch of result.epochs) {
      expect(epoch.envelopes.some((e) => idKey(e.recipient_id) === idKey(oldRecoveryId))).toBe(false);
      // Even the envelope that *is* there, sealed to the new RECOVERY key, does not open for it.
      const newRecoveryId = await rootRecipientId(result.root.recovery_encryption_public_key);
      const label = envelopeLabelContext(
        epoch.descriptor.vault_id,
        epoch.descriptor.epoch_id,
        newRecoveryId,
        "RECOVERY",
      );
      await expect(
        openEpochSecret(oldKey, label, envelopeFor(epoch.envelopes, newRecoveryId).ciphertext),
      ).rejects.toBeTruthy();
    }
  });
});

describe("§35.9 broken variants", () => {
  it("returns no kit, and no bundle, when the new kit fails its self-test", async () => {
    const world = await operationWorld();
    // A kit assembled from two different pairs: its serialized private key is not the one whose
    // public half the pending descriptor carries. §27.3 step 1 is exactly this check.
    const good = await generateRecoveryKeyPairs();
    const other = await generateRecoveryKeyPairs();
    const mismatched: RecoveryKeyPairs = {
      encryption: { ...good.encryption, privateKeyPkcs8: other.encryption.privateKeyPkcs8 },
      authority: good.authority,
    };
    const outcome = await replaceRecoveryKit({
      view: world.view,
      bundleId: filled(16, 0xa2),
      keys: world.keys,
      newEpochIds: await newEpochIds(),
      sources: world.sources,
      recoveryKeys: mismatched,
      ports: world.ports,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.failure.code).toBe("ENCRYPTION_ROUND_TRIP_FAILED");
    expect(outcome.failure.step).toBe(3);
  });

  it("would ship unreadable coverage if the round-trip were skipped, and the Worker could not tell", async () => {
    const world = await operationWorld();
    const result = await replacement();
    const newRecoveryId = await rootRecipientId(result.root.recovery_encryption_public_key);

    // The classic mistake: *relabel* the ACCOUNT ciphertext as the new RECOVERY recipient's
    // envelope instead of re-enveloping it. It is sealed to the account key and labelled for the
    // kit, so nobody can open it — and §32.3 gives the Worker no way to notice.
    const relabelled = world.sources.map((source) => ({
      ...source.envelope,
      recipient_id: newRecoveryId,
      recipient_type: "RECOVERY" as const,
    }));
    const forged = assembleBundle({
      operationType: "RECOVERY_KIT_REPLACEMENT",
      bundleId: KIT_BUNDLE_ID,
      expected: expectedOf(world.view),
      rootTransition: result.rootTransition,
      rootDescriptor: result.root,
      registry: result.registry,
      configBlob: result.configBlob,
      configVersion: result.configVersion,
      epochs: result.epochs.map((e) => ({ descriptor: e.descriptor, envelopes: [...e.envelopes] })),
      coverageEnvelopes: relabelled,
    });
    const decision = await validateSecurityBundle(forged, withMaturedRequest(withScopes(world.state, ["TRUSTED_SECURITY"]), "RECOVERY_KIT_REPLACEMENT"));
    expect(decision.ok).toBe(true);

    // §33.2's round-trip is the only thing that catches it, and it does.
    const kitKey = await importEnvelopeDecryptKey(result.recoveryKit.kit.recovery_encryption_private_key);
    const proved = await proveEnvelope(
      world.sources[0]!.descriptor,
      relabelled[0]!,
      { recipientId: newRecoveryId, type: "RECOVERY" },
      { kind: "DECRYPT", privateKey: kitKey },
    );
    expect(proved.ok).toBe(false);
    if (proved.ok) return;
    expect(proved.failure.code).toBe("ROUND_TRIP_FAILED");
  });

  it("is INVALID_SIGNATURE when role 4 is the OLD Recovery Authority (no proof of possession)", async () => {
    const world = await operationWorld();
    const result = await replacement();
    const unsigned = {
      account_id: result.rootTransition.account_id,
      transition_type: result.rootTransition.transition_type,
      old_root_hash: result.rootTransition.old_root_hash,
      new_root_hash: result.rootTransition.new_root_hash,
      new_root_generation: result.rootTransition.new_root_generation,
    };
    const ctx = rootTransitionContext(unsigned);
    const forgedTransition = {
      ...unsigned,
      signatures: [
        { code: 1 as const, value: await signContext(world.keys.signingKey, ctx) },
        // The kit being replaced signs in place of the new one: §28.2's "prueba de posesión" is
        // precisely what stops a client installing a kit it does not hold.
        { code: 4 as const, value: await signContext(world.created.recoveryKit.keys.authority.privateKey, ctx) },
      ],
    };
    const forged = assembleBundle({
      operationType: "RECOVERY_KIT_REPLACEMENT",
      bundleId: KIT_BUNDLE_ID,
      expected: expectedOf(world.view),
      rootTransition: forgedTransition,
      rootDescriptor: result.root,
      registry: result.registry,
      configBlob: result.configBlob,
      configVersion: result.configVersion,
      epochs: result.epochs.map((e) => ({ descriptor: e.descriptor, envelopes: [...e.envelopes] })),
      coverageEnvelopes: [...result.coverageEnvelopes],
    });
    const decision = await validateSecurityBundle(forged, withMaturedRequest(withScopes(world.state, ["TRUSTED_SECURITY"]), "RECOVERY_KIT_REPLACEMENT"));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_SIGNATURE");
    expect(decision.failure.rule).toBe("transition/BAD_SIGNATURE");
  });

  it("is INVALID_REGISTRY when the recipient list is not identical", async () => {
    const world = await operationWorld();
    const result = await replacement();
    const changedList = await signRegistry(
      await nextRegistry(world.view.registry, {
        revoke: [world.client.recipient.recipientId],
        rootGeneration: result.root.root_generation,
      }),
      world.keys.signingKey,
    );
    // Rebuilt against that registry, so §36.2 is satisfied and the shape rule is what answers.
    const rotation = await rotateLiveVaults({
      vaults: world.view.vaults,
      root: result.root,
      rootHash: result.rootHash,
      registry: changedList,
      registryHash: await registryHash(changedList),
      newEpochIds: await newEpochIds(),
      signingKey: world.keys.signingKey,
      ports: world.ports,
    });
    const forged = assembleBundle({
      operationType: "RECOVERY_KIT_REPLACEMENT",
      bundleId: KIT_BUNDLE_ID,
      expected: expectedOf(world.view),
      rootTransition: result.rootTransition,
      rootDescriptor: result.root,
      registry: changedList,
      configBlob: result.configBlob,
      configVersion: result.configVersion,
      epochs: [...rotation.bundleEpochs],
      coverageEnvelopes: [...result.coverageEnvelopes],
    });
    const decision = await validateSecurityBundle(forged, withMaturedRequest(withScopes(world.state, ["TRUSTED_SECURITY"]), "RECOVERY_KIT_REPLACEMENT"));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_REGISTRY");
    expect(decision.failure.rule).toBe("registry/unchanged");
  });

  it("is COVERAGE_STALE when an epoch of the RequiredEpochSet has no envelope", async () => {
    const world = await operationWorld();
    const result = await replacement();
    const forged = assembleBundle({
      operationType: "RECOVERY_KIT_REPLACEMENT",
      bundleId: KIT_BUNDLE_ID,
      expected: expectedOf(world.view),
      rootTransition: result.rootTransition,
      rootDescriptor: result.root,
      registry: result.registry,
      configBlob: result.configBlob,
      configVersion: result.configVersion,
      epochs: result.epochs.map((e) => ({ descriptor: e.descriptor, envelopes: [...e.envelopes] })),
      coverageEnvelopes: [result.coverageEnvelopes[0]!],
    });
    const decision = await validateSecurityBundle(forged, withMaturedRequest(withScopes(world.state, ["TRUSTED_SECURITY"]), "RECOVERY_KIT_REPLACEMENT"));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("COVERAGE_STALE");
    expect(decision.failure.rule).toBe("coverage/MISSING_ENVELOPE");
  });

  it("needs TRUSTED_SECURITY (§11.3), and one new epoch id per live vault", async () => {
    const world = await operationWorld();
    const result = await replacement();
    const decision = await validateSecurityBundle(result.bundle, withScopes(world.state, ["ACCOUNT_SECURITY"]));
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.failure.code).toBe("SCOPE_REQUIRED");

    await expect(
      replaceRecoveryKit({
        view: world.view,
        bundleId: filled(16, 0xa3),
        keys: world.keys,
        newEpochIds: new Map([[idKey(world.view.vaults[0]!.vaultId), NEW_EPOCH_A]]),
        sources: world.sources,
        recoveryKeys: await generateRecoveryKeyPairs(),
        ports: world.ports,
      }),
    ).rejects.toBeInstanceOf(KeyLifecycleError);
  });
});
