// §35.14: from Private to Managed (`SWITCH_TO_MANAGED`, ADR-021).
//
// It gives the operator read access, which is the point, so it keeps the account keys and does not
// re-encrypt history. It replaces the Recovery keys, whose old privates exist only in the user's
// Recovery Kit, and rotates every vault forward like a revocation, so the old kit reads nothing
// written afterwards (it still opens the RECOVERY envelopes of the existing epochs: §35.14's honest
// residue).
//
//   - steps 3–4: a random `RootUnlockKey`, the §24 keys derived from it, and the **same** keyset
//     re-wrapped under them (as §35.6), with the Re-wrap temporal handles of §25.1;
//   - step 5: new Recovery pairs serialized as `EscrowedRecoveryKeys` and self-tested against the
//     pending root, with no kit shown;
//   - step 6: every epoch of the `RequiredEpochSet` re-enveloped from the ACCOUNT envelope towards
//     the new RECOVERY key, round-tripped (§33.2);
//   - step 7: roles 1 + 4, and a version-1 root becomes version 2 (§28.2 rule 5);
//   - steps 8–11: the identical recipient list, a Managed profile with its `profile_signature`
//     (§35.6), a new epoch per live vault for the ACCOUNT in force, the new RECOVERY and the ACTIVE
//     recipients only, and both escrow slots.
import { zeroize } from "@nodra/crypto";
import { SECURITY_BUNDLE, encodeRecord } from "@nodra/encoding/records";
import type {
  AccountSecurityConfig,
  AccountSecurityProfile,
  EpochEnvelope,
  EscrowBlob,
  Registry,
  RootDescriptor,
  RootTransition,
  SecurityBundle,
} from "@nodra/encoding/records";
import { assembleBundle, signProfileUpdate } from "./bundle-build.js";
import type { AccountView, ClientPins, OperationFailure } from "./client-state.js";
import { expectedOf, sealNextConfig } from "./client-state.js";
import type { RewrapHandles } from "./change-secrets.js";
import { requiredEpochSet } from "./coverage.js";
import { rootRecipientId, rootRecipients } from "./epoch.js";
import type { CreatedEpoch, EnvelopeRecipient, RecipientIdentity } from "./epoch.js";
import type { Outcome } from "./errors.js";
import { buildEscrowBlob } from "./escrow.js";
import type { EscrowPublicKey } from "./escrow.js";
import { buildAccountSecurityProfile, wrapAccountPrivateKeys } from "./keyset.js";
import { defaultPorts } from "./ports.js";
import type { KeyLifecyclePorts } from "./ports.js";
import { buildCoverage } from "./re-envelope.js";
import type { EnvelopeSource, ReEnvelopeFailureCode } from "./re-envelope.js";
import {
  escrowedRecoveryKeysOf,
  generateRecoveryKeyPairs,
  recoveryRootKeys,
  selfTestEscrowedRecoveryKeys,
  serializeEscrowedRecoveryKeys,
} from "./recovery-kit.js";
import type { RecoveryKeyPairs, RecoveryKitFailureCode } from "./recovery-kit.js";
import { nextRegistry, registryHash, signRegistry } from "./registry.js";
import { nextDescriptor, rootHash, signRootTransition } from "./root-chain.js";
import { rotateLiveVaults } from "./rotation.js";
import { ROOT_UNLOCK_KEY_BYTES, deriveManagedAccountKeys } from "./secrets.js";
import type { DerivedAccountKeys } from "./secrets.js";

export type SwitchToManagedFailureCode = RecoveryKitFailureCode | ReEnvelopeFailureCode;

export type SwitchToManagedFailure = OperationFailure<SwitchToManagedFailureCode>;

export interface SwitchToManagedRequest {
  /** The verified state of a **trusted client** of a Private account (§35.1). */
  readonly view: AccountView;
  readonly bundleId: Uint8Array;
  /**
   * Step 1: the Re-wrap temporal handles of §25.1 (`unlockForRewrap`, Private Root Unlock). The
   * encryption one (`["decrypt"]`) also opens the ACCOUNT envelopes of step 6; the signing one signs
   * roles 1, the registry, the descriptors and the profile.
   */
  readonly keys: RewrapHandles;
  /** Step 2 is the caller's: the user's explicit confirmation. This builder assumes it was given. */
  readonly escrowKey: EscrowPublicKey;
  /** Step 10: one fresh UUIDv7 per live vault, keyed by the lowercase hex of its `vault_id`. */
  readonly newEpochIds: ReadonlyMap<string, Uint8Array>;
  /** Step 6: the ACCOUNT envelope of every epoch of the `RequiredEpochSet`. */
  readonly sources: readonly EnvelopeSource[];
  /** Step 5 generates them; supplied only so a test can reuse pairs. */
  readonly recoveryKeys?: RecoveryKeyPairs;
  readonly ports?: KeyLifecyclePorts;
}

export interface SwitchedToManaged {
  readonly bundle: SecurityBundle;
  readonly serializedBundle: Uint8Array;
  /** Step 11: both slots, already in `bundle`. */
  readonly escrow: EscrowBlob;
  readonly rootTransition: RootTransition;
  readonly root: RootDescriptor;
  readonly rootHash: Uint8Array;
  readonly registry: Registry;
  readonly registryHash: Uint8Array;
  /** Step 6: for the new RECOVERY key. */
  readonly coverageEnvelopes: readonly EpochEnvelope[];
  readonly epochs: readonly CreatedEpoch[];
  readonly config: AccountSecurityConfig;
  readonly profile: AccountSecurityProfile;
  readonly profileSignature: Uint8Array;
  readonly pins: ClientPins;
  /** Step 14: what to discard. The `RootUnlockKey` bytes are already zeroized. */
  readonly derived: DerivedAccountKeys;
  readonly recoveryKeys: RecoveryKeyPairs;
}

/** §35.14 steps 3–11, returning what steps 12–14 need. */
export async function switchToManaged(
  request: SwitchToManagedRequest,
): Promise<Outcome<SwitchedToManaged, SwitchToManagedFailure>> {
  const ports = request.ports ?? defaultPorts;
  const view = request.view;

  // Step 3: the RootUnlockKey and its keys (§24).
  const rootUnlockKey = ports.randomBytes(ROOT_UNLOCK_KEY_BYTES);
  try {
    const derived = await deriveManagedAccountKeys(rootUnlockKey);

    // Step 4: the same two privates, wrapped under the new AccountKeyWrapKey.
    const wrapped = await wrapAccountPrivateKeys(derived.keyWrapKey, view.accountId, {
      encryption: request.keys.encryptionKey,
      signing: request.keys.signingKey,
    });

    // Step 5: new Recovery pairs, the pending root (version 2), and the self-test of the escrow form.
    const recoveryKeys = request.recoveryKeys ?? (await generateRecoveryKeyPairs());
    const root = await nextDescriptor(view.root, recoveryRootKeys(recoveryKeys), 2);
    const hash = await rootHash(root);
    const selfTest = await selfTestEscrowedRecoveryKeys({
      serialized: serializeEscrowedRecoveryKeys(recoveryKeys),
      accountId: view.accountId,
      pendingDescriptor: root,
      ports,
    });
    if (!selfTest.ok) {
      return { ok: false, failure: { code: selfTest.failure.code, step: 5, message: selfTest.failure.message } };
    }

    // Step 6: from each ACCOUNT envelope towards the new RECOVERY key, round-tripped with its private.
    const accountSource = (await rootRecipients(view.root))[0] as EnvelopeRecipient;
    const sourceRecipient: RecipientIdentity = { recipientId: accountSource.recipientId, type: accountSource.type };
    const coverage = await buildCoverage({
      required: requiredEpochSet(view.vaults),
      sources: request.sources,
      sourceRecipient,
      openingKey: request.keys.encryptionKey,
      target: {
        recipientId: await rootRecipientId(recoveryKeys.encryption.publicKeySpki),
        type: "RECOVERY",
        publicKey: recoveryKeys.encryption.publicKeySpki,
      },
      prover: { kind: "DECRYPT", privateKey: recoveryKeys.encryption.privateKey },
    });
    if (!coverage.ok) {
      const { code, vaultId, epochId, message } = coverage.failure;
      return {
        ok: false,
        failure: { code, step: 6, ...(vaultId === undefined ? {} : { vaultId }), ...(epochId === undefined ? {} : { epochId }), message },
      };
    }

    // Step 7: roles 1 (Account Signing, unchanged) and 4 (new Recovery Authority).
    const rootTransition = await signRootTransition({
      type: "SWITCH_TO_MANAGED",
      descriptor: root,
      previous: view.root,
      signers: { 1: request.keys.signingKey, 4: recoveryKeys.authority.privateKey },
    });

    // Step 8: the same list at the new generation.
    const registry = await signRegistry(
      await nextRegistry(view.registry, { rootGeneration: root.root_generation }),
      request.keys.signingKey,
    );
    const rHash = await registryHash(registry);

    // Step 9: a Managed profile (no KDF fields) and the config under the new AccountConfigKey,
    // signed over the config_version in force (§35.6).
    const sealed = await sealNextConfig(derived.configKey, {
      root,
      rootHash: hash,
      genesisRootHash: view.genesisRootHash,
      registryVersion: registry.registry_version,
      registryHash: rHash,
      configVersion: view.configVersion + 1,
    });
    const profile = buildAccountSecurityProfile({
      accountId: view.accountId,
      wrappedEncryptionKey: wrapped.encryption,
      wrappedSigningKey: wrapped.signing,
      configVersion: sealed.configVersion,
      configBlob: sealed.blob,
    });
    const profileSignature = await signProfileUpdate(request.keys.signingKey, view.accountId, view.configVersion, profile);

    // Step 10: a new epoch per live vault — ACCOUNT in force, new RECOVERY, ACTIVE recipients; none
    // for the old Recovery key.
    const rotation = await rotateLiveVaults({
      vaults: view.vaults,
      root,
      rootHash: hash,
      registry,
      registryHash: rHash,
      newEpochIds: request.newEpochIds,
      signingKey: request.keys.signingKey,
      ports,
    });

    // Step 11: both slots, wrapped to the Escrow Key.
    const escrow = await buildEscrowBlob({
      accountId: view.accountId,
      escrowKey: request.escrowKey,
      rootUnlockKey,
      recoveryKeys: escrowedRecoveryKeysOf(recoveryKeys),
      ports,
    });

    const bundle = assembleBundle({
      operationType: "SWITCH_TO_MANAGED",
      bundleId: request.bundleId,
      expected: expectedOf(view),
      rootTransition,
      rootDescriptor: root,
      registry,
      profile,
      profileSignature,
      epochs: rotation.bundleEpochs,
      coverageEnvelopes: coverage.value,
      escrow,
    });

    return {
      ok: true,
      value: {
        bundle,
        serializedBundle: encodeRecord(SECURITY_BUNDLE, bundle),
        escrow,
        rootTransition,
        root,
        rootHash: hash,
        registry,
        registryHash: rHash,
        coverageEnvelopes: coverage.value,
        epochs: rotation.epochs,
        config: sealed.config,
        profile,
        profileSignature,
        pins: {
          rootGeneration: root.root_generation,
          rootHash: hash,
          genesisRootHash: view.genesisRootHash,
          registryVersion: registry.registry_version,
          registryHash: rHash,
          configVersion: sealed.configVersion,
          epochs: rotation.pins,
        },
        derived,
        recoveryKeys,
      },
    };
  } finally {
    // §35.14 step 14: the RootUnlockKey bytes were needed only to derive and to escrow.
    zeroize(rootUnlockKey);
  }
}
