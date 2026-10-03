// §35.9: replacing the Recovery Kit (`RECOVERY_KIT_REPLACEMENT`).
//
// The mirror image of §35.7. There the kit authorizes new account keys; here the account keys
// authorize a new kit — roles 1 + 4 (§28.2), the current Account Signing key and the *new*
// Recovery Authority key, which is the proof of possession that stops anyone installing a kit they
// do not hold. §35.9 is explicit that the **previous** kit is not required: if it were, a lost kit
// would be unreplaceable, and a lost kit is one of the three cases this operation exists for.
//
// Three things must happen before the server ever sees the bundle, and all three are here:
//
//   1. **The self-test against the pending root** (§35.9 step 3, §27.3). The kit is tested against
//      the descriptor about to be committed, not the one in force — in this operation the two hold
//      *different* recovery keys, so testing against the current root would reject every good kit.
//      A kit that fails is never returned, so nothing can show the user a document that does not
//      work.
//   2. **The round-trip with the new kit's private key** (§35.9 step 4, §33.2). The coverage
//      envelopes are sealed to a public key whose private half exists only inside the kit that is
//      about to be printed and discarded from memory. If they do not open now, they never will:
//      the Worker checks presence only (§32.3), and the failure would surface years later as an
//      unrecoverable account.
//   3. **A new epoch in every live vault** (§35.9 step 7), so the *previous* kit — which may be in
//      a drawer, a photo or an attacker's hands — reads no future data. §35.1.1 step 7 answers
//      `VAULT_SET_STALE` when one is missing.
//
// §35.9's accepted MVP risk is stated in the spec and not mitigated here: whoever holds Password +
// Secret Key can replace the kit. That is a gate of the public beta (§3.2), not of this module.
import { importEnvelopeDecryptKey } from "@nodra/crypto";
import { SECURITY_BUNDLE, encodeRecord } from "@nodra/encoding/records";
import type {
  AccountSecurityConfig,
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
import type { CreatedEpoch, EnvelopeRecipient, RecipientIdentity } from "./epoch.js";
import { rootRecipientId, rootRecipients } from "./epoch.js";
import type { Outcome } from "./errors.js";
import { defaultPorts } from "./ports.js";
import type { KeyLifecyclePorts } from "./ports.js";
import { buildCoverage } from "./re-envelope.js";
import type { EnvelopeSource, ReEnvelopeFailureCode } from "./re-envelope.js";
import { createRecoveryKit, recoveryRootKeys, selfTestRecoveryKit } from "./recovery-kit.js";
import type { CreatedRecoveryKit, RecoveryKeyPairs, RecoveryKitFailureCode, RecoveryKitProof } from "./recovery-kit.js";
import { nextRegistry, registryHash, signRegistry } from "./registry.js";
import { nextDescriptor, rootHash, signRootTransition } from "./root-chain.js";
import { rotateLiveVaults } from "./rotation.js";

/** Whatever stopped §35.9: the self-test of step 3, or the re-enveloping of step 4. */
export type ReplaceRecoveryKitFailureCode = RecoveryKitFailureCode | ReEnvelopeFailureCode;

export type ReplaceRecoveryKitFailure = OperationFailure<ReplaceRecoveryKitFailureCode>;

export interface ReplaceRecoveryKitRequest {
  /** The verified state of a **trusted client** (§35.1): this operation seals for another key. */
  readonly view: AccountView;
  readonly bundleId: Uint8Array;
  /** §35.9 step 1: the Operation handle for §33.2, the Signing handle, and the `AccountConfigKey`. */
  readonly keys: OperationKeys;
  /** Step 7: one fresh UUIDv7 per live vault, keyed by the lowercase hex of its `vault_id`. */
  readonly newEpochIds: ReadonlyMap<string, Uint8Array>;
  /** Step 4: the **ACCOUNT** envelope of every epoch of the `RequiredEpochSet` (§22, §34.3). */
  readonly sources: readonly EnvelopeSource[];
  /** Step 2 generates them; supplied only so a test can reuse pairs or assemble a broken kit. */
  readonly recoveryKeys?: RecoveryKeyPairs;
  readonly ports?: KeyLifecyclePorts;
}

export interface ReplacedRecoveryKit {
  readonly bundle: SecurityBundle;
  readonly serializedBundle: Uint8Array;
  /** Step 2/3: only present because the self-test passed — §27.3 forbids showing any other kit. */
  readonly recoveryKit: CreatedRecoveryKit;
  /** The proof itself, with the nonce the run used (§27.3). */
  readonly selfTest: RecoveryKitProof;
  readonly rootTransition: RootTransition;
  readonly root: RootDescriptor;
  readonly rootHash: Uint8Array;
  readonly registry: Registry;
  readonly registryHash: Uint8Array;
  /** Step 4: one envelope per epoch of the `RequiredEpochSet`, for the new RECOVERY key (§34.2). */
  readonly coverageEnvelopes: readonly EpochEnvelope[];
  readonly epochs: readonly CreatedEpoch[];
  readonly config: AccountSecurityConfig;
  readonly configBlob: Uint8Array;
  readonly configVersion: number;
  readonly pins: ClientPins;
}

/**
 * §35.9 steps 2–8, returning what step 9 and the client's own bookkeeping need. Step 1's handles
 * arrive as an argument and are the caller's to discard when the operation ends (§25.1).
 */
export async function replaceRecoveryKit(
  request: ReplaceRecoveryKitRequest,
): Promise<Outcome<ReplacedRecoveryKit, ReplaceRecoveryKitFailure>> {
  const ports = request.ports ?? defaultPorts;
  const view = request.view;

  // Step 2: the new pairs and the document. `genesis_root_hash` never changes (§27.1).
  const recoveryKit = await createRecoveryKit({
    accountId: view.accountId,
    genesisRootHash: view.genesisRootHash,
    ...(request.recoveryKeys === undefined ? {} : { keys: request.recoveryKeys }),
    ports,
  });

  // Step 3: the pending root — only the two recovery keys move (§28.2) — and the §27.3 self-test
  // against it. A kit that fails here is discarded with the operation and never shown.
  const root = await nextDescriptor(view.root, recoveryRootKeys(recoveryKit.keys));
  const hash = await rootHash(root);
  const selfTest = await selfTestRecoveryKit({
    serialized: recoveryKit.serialized,
    accountId: view.accountId,
    genesisRootHash: view.genesisRootHash,
    pendingDescriptor: root,
    ports,
  });
  if (!selfTest.ok) {
    return { ok: false, failure: { code: selfTest.failure.code, step: 3, message: selfTest.failure.message } };
  }

  // Step 4: §33.2 from each ACCOUNT envelope towards the new RECOVERY public key, round-tripped
  // with the kit's own private key as §27.2 imports it — `["decrypt"]`, so §33.2's second shape.
  const accountSource = (await rootRecipients(view.root))[0] as EnvelopeRecipient;
  const sourceRecipient: RecipientIdentity = { recipientId: accountSource.recipientId, type: accountSource.type };
  const target: EnvelopeRecipient = {
    recipientId: await rootRecipientId(recoveryKit.keys.encryption.publicKeySpki),
    type: "RECOVERY",
    publicKey: recoveryKit.keys.encryption.publicKeySpki,
  };
  const kitDecryptKey = await importEnvelopeDecryptKey(recoveryKit.kit.recovery_encryption_private_key);
  const coverage = await buildCoverage({
    required: requiredEpochSet(view.vaults),
    sources: request.sources,
    sourceRecipient,
    openingKey: request.keys.operationKey,
    target,
    prover: { kind: "DECRYPT", privateKey: kitDecryptKey },
  });
  if (!coverage.ok) {
    const { code, vaultId, epochId, message } = coverage.failure;
    return {
      ok: false,
      failure: {
        code,
        step: 4,
        ...(vaultId === undefined ? {} : { vaultId }),
        ...(epochId === undefined ? {} : { epochId }),
        message,
      },
    };
  }

  // Step 5: roles 1 (the Account Signing key in force) and 4 (the new Recovery Authority).
  const rootTransition = await signRootTransition({
    type: "RECOVERY_KIT_REPLACEMENT",
    descriptor: root,
    previous: view.root,
    signers: { 1: request.keys.signingKey, 4: recoveryKit.keys.authority.privateKey },
  });

  // Step 6: the same recipient list at the new generation (§35.1.1, "Forma del registry"). The
  // Account Signing key did not change, so it is the same handle that signs it.
  const registry = await signRegistry(
    await nextRegistry(view.registry, { rootGeneration: root.root_generation }),
    request.keys.signingKey,
  );
  const rHash = await registryHash(registry);

  // Step 7: one new epoch per live vault, so the previous kit reads nothing written from now on.
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

  // Step 8: the config, under the same `AccountConfigKey` — this operation changes no secret.
  const sealed = await sealNextConfig(request.keys.configKey, {
    root,
    rootHash: hash,
    genesisRootHash: view.genesisRootHash,
    registryVersion: registry.registry_version,
    registryHash: rHash,
    configVersion: view.configVersion + 1,
  });

  const bundle = assembleBundle({
    operationType: "RECOVERY_KIT_REPLACEMENT",
    bundleId: request.bundleId,
    expected: expectedOf(view),
    rootTransition,
    rootDescriptor: root,
    registry,
    configBlob: sealed.blob,
    configVersion: sealed.configVersion,
    epochs: rotation.bundleEpochs,
    coverageEnvelopes: coverage.value,
  });

  return {
    ok: true,
    value: {
      bundle,
      serializedBundle: encodeRecord(SECURITY_BUNDLE, bundle),
      recoveryKit,
      selfTest: selfTest.value,
      rootTransition,
      root,
      rootHash: hash,
      registry,
      registryHash: rHash,
      coverageEnvelopes: coverage.value,
      epochs: rotation.epochs,
      config: sealed.config,
      configBlob: sealed.blob,
      configVersion: sealed.configVersion,
      pins: {
        rootGeneration: root.root_generation,
        rootHash: hash,
        genesisRootHash: view.genesisRootHash,
        registryVersion: registry.registry_version,
        registryHash: rHash,
        configVersion: sealed.configVersion,
        epochs: rotation.pins,
      },
    },
  };
}
