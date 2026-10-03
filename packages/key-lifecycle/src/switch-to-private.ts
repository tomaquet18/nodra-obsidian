// §35.13: from Managed to Private (`SWITCH_TO_PRIVATE`, ADR-021).
//
// One atomic bundle that does what CHANGE_SECRETS and RECOVERY_KIT_REPLACEMENT do, and also replaces
// the account keys, because the server could unwrap the old ones from the escrow. From the commit
// on, no key the operator ever held opens a new epoch: the account and recovery privates are new
// and were never escrowed, and the recipients' never were.
//
//   - steps 2–5: the two secrets and a Setup Kit, new account pairs, new recovery pairs and a
//     Recovery Kit self-tested against the pending root (§27.3);
//   - step 6: every epoch of the `RequiredEpochSet` is re-enveloped from the ACCOUNT envelope in
//     force towards **both** new keys, each round-tripped (§33.2) — coverage for "nuevas claves
//     ACCOUNT y RECOVERY";
//   - step 7: roles 1 + 2 + 4 — the Account Signing in force authorizes, the new Account Signing
//     and the new Recovery Authority prove possession (§28.2);
//   - steps 8–10: the identical recipient list under the new generation, one new epoch per live
//     vault, the profile and config under the keys of the new secrets.
//
// The history re-encryption of step 14 is a separate, resumable process and not part of this bundle.
import { importEnvelopeDecryptKey } from "@nodra/crypto";
import type { Argon2Params } from "@nodra/crypto";
import { SECURITY_BUNDLE, encodeRecord } from "@nodra/encoding/records";
import type {
  AccountSecurityConfig,
  AccountSecurityProfile,
  EpochEnvelope,
  Registry,
  RootDescriptor,
  RootTransition,
  SecurityBundle,
} from "@nodra/encoding/records";
import { assembleBundle } from "./bundle-build.js";
import type { AccountView, ClientPins, OperationFailure, OperationKeys } from "./client-state.js";
import { expectedOf, sealNextConfig } from "./client-state.js";
import { requiredEpochSet } from "./coverage.js";
import { rootRecipientId, rootRecipients } from "./epoch.js";
import type { CreatedEpoch, EnvelopeRecipient, RecipientIdentity } from "./epoch.js";
import type { Outcome, UnlockFailureCode } from "./errors.js";
import { buildAccountSecurityProfile, createAccountRootKeyset } from "./keyset.js";
import type { CreatedAccountRootKeyset } from "./keyset.js";
import { defaultPorts } from "./ports.js";
import type { KeyLifecyclePorts } from "./ports.js";
import { buildCoverage } from "./re-envelope.js";
import type { EnvelopeProver, EnvelopeSource, ReEnvelopeFailure, ReEnvelopeFailureCode } from "./re-envelope.js";
import { createRecoveryKit, recoveryRootKeys, selfTestRecoveryKit } from "./recovery-kit.js";
import type { CreatedRecoveryKit, RecoveryKeyPairs, RecoveryKitFailureCode } from "./recovery-kit.js";
import { nextRegistry, registryHash, signRegistry } from "./registry.js";
import { nextDescriptor, rootHash, signRootTransition } from "./root-chain.js";
import { rotateLiveVaults } from "./rotation.js";
import type { AccountSecretKeyInput } from "./secrets.js";

export type SwitchToPrivateFailureCode = UnlockFailureCode | RecoveryKitFailureCode | ReEnvelopeFailureCode;

export type SwitchToPrivateFailure = OperationFailure<SwitchToPrivateFailureCode>;

export interface SwitchToPrivateRequest {
  /** The verified state of a **trusted client** of a Managed account (§35.1). */
  readonly view: AccountView;
  readonly bundleId: Uint8Array;
  /** Step 1: the Operation and Signing handles of the account keys in force (Managed Root Unlock). */
  readonly keys: Pick<OperationKeys, "operationKey" | "signingKey">;
  /** Step 2: the Encryption Password the user defines. */
  readonly password: string;
  /** Step 2 generates one when omitted: it becomes the Setup Kit. */
  readonly secretKey?: AccountSecretKeyInput;
  readonly argon2Params?: Argon2Params;
  readonly kdfSalt?: Uint8Array;
  /** Step 9: one fresh UUIDv7 per live vault, keyed by the lowercase hex of its `vault_id`. */
  readonly newEpochIds: ReadonlyMap<string, Uint8Array>;
  /** Step 6: the ACCOUNT envelope of every epoch of the `RequiredEpochSet`. */
  readonly sources: readonly EnvelopeSource[];
  /** Step 4 generates them; supplied only so a test can reuse pairs. */
  readonly recoveryKeys?: RecoveryKeyPairs;
  readonly ports?: KeyLifecyclePorts;
}

export interface SwitchedToPrivate {
  readonly bundle: SecurityBundle;
  readonly serializedBundle: Uint8Array;
  /** Step 2: the Setup Kit. Shown once, stored nowhere; the caller zeroizes the bytes. */
  readonly setupKit: { readonly accountSecretKey: Uint8Array; readonly accountSecretKeyText: string };
  /** Step 5: only present because the self-test passed (§27.3). */
  readonly recoveryKit: CreatedRecoveryKit;
  readonly rootTransition: RootTransition;
  readonly root: RootDescriptor;
  readonly rootHash: Uint8Array;
  readonly registry: Registry;
  readonly registryHash: Uint8Array;
  /** Step 6: for the new ACCOUNT key, then for the new RECOVERY key. */
  readonly coverageEnvelopes: readonly EpochEnvelope[];
  /** Step 9: the new epoch of every live vault; the Worker records it as `private_since_epoch_id`. */
  readonly epochs: readonly CreatedEpoch[];
  readonly config: AccountSecurityConfig;
  readonly profile: AccountSecurityProfile;
  readonly pins: ClientPins;
  /** Step 13: the handles to discard when the operation ends. */
  readonly keyset: CreatedAccountRootKeyset;
}

function coverageFailed(step: number, failure: ReEnvelopeFailure): Outcome<never, SwitchToPrivateFailure> {
  const { code, vaultId, epochId, message } = failure;
  return {
    ok: false,
    failure: { code, step, ...(vaultId === undefined ? {} : { vaultId }), ...(epochId === undefined ? {} : { epochId }), message },
  };
}

/** §35.13 steps 2–10, returning what steps 11–13 need. */
export async function switchToPrivate(
  request: SwitchToPrivateRequest,
): Promise<Outcome<SwitchedToPrivate, SwitchToPrivateFailure>> {
  const ports = request.ports ?? defaultPorts;
  const view = request.view;

  // Steps 2–3 (and the wrapping of step 10): the secrets, their keys and the new account pairs.
  const created = await createAccountRootKeyset({
    accountId: view.accountId,
    password: request.password,
    ...(request.secretKey === undefined ? {} : { secretKey: request.secretKey }),
    ...(request.argon2Params === undefined ? {} : { argon2Params: request.argon2Params }),
    ...(request.kdfSalt === undefined ? {} : { kdfSalt: request.kdfSalt }),
    ports,
  });
  if (!created.ok) {
    return { ok: false, failure: { code: created.failure.code, step: 2, message: created.failure.message } };
  }
  const keyset = created.value;

  // Steps 4–5: the recovery pairs and kit, and the pending root in which all four keys are new.
  const recoveryKit = await createRecoveryKit({
    accountId: view.accountId,
    genesisRootHash: view.genesisRootHash,
    ...(request.recoveryKeys === undefined ? {} : { keys: request.recoveryKeys }),
    ports,
  });
  const root = await nextDescriptor(view.root, {
    accountEncryption: keyset.encryption.publicKeySpki,
    accountSigning: keyset.signing.publicKeySpki,
    ...recoveryRootKeys(recoveryKit.keys),
  });
  const hash = await rootHash(root);
  const selfTest = await selfTestRecoveryKit({
    serialized: recoveryKit.serialized,
    accountId: view.accountId,
    genesisRootHash: view.genesisRootHash,
    pendingDescriptor: root,
    ports,
  });
  if (!selfTest.ok) {
    return { ok: false, failure: { code: selfTest.failure.code, step: 5, message: selfTest.failure.message } };
  }

  // Step 6: from the ACCOUNT envelope in force towards each new key, each round-tripped.
  const accountSource = (await rootRecipients(view.root))[0] as EnvelopeRecipient;
  const sourceRecipient: RecipientIdentity = { recipientId: accountSource.recipientId, type: accountSource.type };
  const required = requiredEpochSet(view.vaults);
  const cover = async (type: "ACCOUNT" | "RECOVERY", spki: Uint8Array, prover: EnvelopeProver) =>
    buildCoverage({
      required,
      sources: request.sources,
      sourceRecipient,
      openingKey: request.keys.operationKey,
      target: { recipientId: await rootRecipientId(spki), type, publicKey: spki },
      prover,
    });
  const toAccount = await cover("ACCOUNT", keyset.encryption.publicKeySpki, { kind: "DECRYPT", privateKey: keyset.encryption.privateKey });
  if (!toAccount.ok) return coverageFailed(6, toAccount.failure);
  const kitDecryptKey = await importEnvelopeDecryptKey(recoveryKit.kit.recovery_encryption_private_key);
  const toRecovery = await cover("RECOVERY", recoveryKit.keys.encryption.publicKeySpki, { kind: "DECRYPT", privateKey: kitDecryptKey });
  if (!toRecovery.ok) return coverageFailed(6, toRecovery.failure);
  const coverageEnvelopes = [...toAccount.value, ...toRecovery.value];

  // Step 7: roles 1 (Account Signing in force), 2 (new Account Signing), 4 (new Recovery Authority).
  const rootTransition = await signRootTransition({
    type: "SWITCH_TO_PRIVATE",
    descriptor: root,
    previous: view.root,
    signers: { 1: request.keys.signingKey, 2: keyset.signing.privateKey, 4: recoveryKit.keys.authority.privateKey },
  });

  // Step 8: the same list at the new generation, signed with the new Account Signing Key.
  const registry = await signRegistry(
    await nextRegistry(view.registry, { rootGeneration: root.root_generation }),
    keyset.signing.privateKey,
  );
  const rHash = await registryHash(registry);

  // Step 9: a new epoch per live vault, for the new ACCOUNT and RECOVERY and the ACTIVE recipients.
  const rotation = await rotateLiveVaults({
    vaults: view.vaults,
    root,
    rootHash: hash,
    registry,
    registryHash: rHash,
    newEpochIds: request.newEpochIds,
    signingKey: keyset.signing.privateKey,
    ports,
  });

  // Step 10: the config under the keys of the new secrets, and a Private profile (§23.4).
  const sealed = await sealNextConfig(keyset.derived.configKey, {
    root,
    rootHash: hash,
    genesisRootHash: view.genesisRootHash,
    registryVersion: registry.registry_version,
    registryHash: rHash,
    configVersion: view.configVersion + 1,
  });
  const profile = buildAccountSecurityProfile({
    accountId: view.accountId,
    kdfSalt: keyset.kdfSalt,
    argon2Params: keyset.argon2Params,
    wrappedEncryptionKey: keyset.encryption.wrapped,
    wrappedSigningKey: keyset.signing.wrapped,
    configVersion: sealed.configVersion,
    configBlob: sealed.blob,
  });

  const bundle = assembleBundle({
    operationType: "SWITCH_TO_PRIVATE",
    bundleId: request.bundleId,
    expected: expectedOf(view),
    rootTransition,
    rootDescriptor: root,
    registry,
    profile,
    epochs: rotation.bundleEpochs,
    coverageEnvelopes,
  });

  return {
    ok: true,
    value: {
      bundle,
      serializedBundle: encodeRecord(SECURITY_BUNDLE, bundle),
      setupKit: { accountSecretKey: keyset.accountSecretKey, accountSecretKeyText: keyset.accountSecretKeyText },
      recoveryKit,
      rootTransition,
      root,
      rootHash: hash,
      registry,
      registryHash: rHash,
      coverageEnvelopes,
      epochs: rotation.epochs,
      config: sealed.config,
      profile,
      pins: {
        rootGeneration: root.root_generation,
        rootHash: hash,
        genesisRootHash: view.genesisRootHash,
        registryVersion: registry.registry_version,
        registryHash: rHash,
        configVersion: sealed.configVersion,
        epochs: rotation.pins,
      },
      keyset,
    },
  };
}
