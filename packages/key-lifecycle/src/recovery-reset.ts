// §35.7: Recovery and Security Reset (`RECOVERY_RESET`).
//
// This is the operation the whole Recovery Kit exists for, and the only one that can be performed
// by someone who has lost *every* other credential: login plus the kit, and nothing else (§3.2).
// The same flow covers "I lost my secrets" and "my secrets may be in someone else's hands", which
// is why it does all of these at once:
//
//   - it creates a **new** Account Encryption and Account Signing pair (§35.7 step 4). Reusing the
//     old ACCOUNT recipient would leave an attacker who already knows Password + Secret Key in
//     possession of the account, so §28.2 makes both keys MUST-change for this transition type;
//   - it re-envelopes every epoch of the `RequiredEpochSet` from the **RECOVERY** envelope towards
//     that new ACCOUNT key (§35.7 step 5, §33.2), with the mandatory round-trip. Without it the
//     account survives but every byte written before the reset becomes unreadable, and the Worker
//     cannot detect the omission cryptographically (§32.3) — only as `COVERAGE_STALE` (§34.2);
//   - it revokes every recipient (§35.7 step 7) and rotates every live vault (step 8), so a
//     compromised device keeps only what it already downloaded (§35.5's honest guarantee). What
//     those clients do next is §35.8, and `planReEnrollment` is where it lives;
//   - it re-derives the §24 keys from the new secrets and rewrites the config (step 9), which is
//     also what makes the new Setup Kit real.
//
// The transition is signed by roles 3 + 2 (§28.2): the **current** Recovery Authority — the kit —
// authorizes the change, and the **new** Account Signing key proves the holder of the new keys
// participated. The kit's own keys are untouched by a reset, so §27.3's advice to replace the kit
// afterwards (§35.9) is a separate operation, not part of this one.
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
import { zeroize } from "@nodra/crypto";
import type { Argon2Params } from "@nodra/crypto";
import type { Argon2Params as Argon2ParamsRecord, EscrowBlob } from "@nodra/encoding/records";
import { buildEscrowBlob } from "./escrow.js";
import type { EscrowPublicKey } from "./escrow.js";
import { assembleBundle } from "./bundle-build.js";
import type { AccountView, ClientPins, OperationFailure } from "./client-state.js";
import { expectedOf, sealNextConfig } from "./client-state.js";
import { requiredEpochSet } from "./coverage.js";
import type { CreatedEpoch, EnvelopeRecipient, RecipientIdentity } from "./epoch.js";
import { rootRecipientId, rootRecipients } from "./epoch.js";
import type { Outcome, UnlockFailureCode } from "./errors.js";
import { buildAccountSecurityProfile, createAccountRootKeyset, createManagedAccountKeyset } from "./keyset.js";
import type { AccountKeyset } from "./keyset.js";
import { defaultPorts } from "./ports.js";
import type { KeyLifecyclePorts } from "./ports.js";
import { buildCoverage } from "./re-envelope.js";
import type { EnvelopeSource, ReEnvelopeFailureCode } from "./re-envelope.js";
import type { RecoveryHandles } from "./recovery-kit.js";
import { activeRecipients, nextRegistry, registryHash, signRegistry } from "./registry.js";
import { nextDescriptor, rootHash, signRootTransition } from "./root-chain.js";
import { rotateLiveVaults } from "./rotation.js";
import type { AccountSecretKeyInput } from "./secrets.js";

/** Whatever stopped §35.7: the §24/§25 keyset (step 4) or the re-enveloping of step 5. */
export type RecoveryResetFailureCode = UnlockFailureCode | ReEnvelopeFailureCode;

export type RecoveryResetFailure = OperationFailure<RecoveryResetFailureCode>;

interface RecoveryResetBase {
  /**
   * The verified state (§26, §28.3, §29, §34.3). A resetting client usually has no pins — it may
   * be a browser that never saw this account — so "verified" here means the chains replayed from
   * GENESIS against the kit's `genesis_root_hash`, which §35.7 step 2 requires anyway.
   */
  readonly view: AccountView;
  readonly bundleId: Uint8Array;
  /**
   * §35.7 steps 1–2: the Recovery handles, already proved against the root in force — from
   * `openRecoveryKit` (Private) or `openEscrowedRecoveryKeys` over the RECOVERY slot (Managed).
   */
  readonly recovery: Pick<RecoveryHandles, "encryptionKey" | "authorityKey">;
  /** Step 8: one fresh UUIDv7 per live vault, keyed by the lowercase hex of its `vault_id`. */
  readonly newEpochIds: ReadonlyMap<string, Uint8Array>;
  /**
   * Step 5: the **RECOVERY** envelope of every epoch of the `RequiredEpochSet`. The kit's private
   * key is the only thing that opens them, and it is the only credential this client has.
   */
  readonly sources: readonly EnvelopeSource[];
  readonly ports?: KeyLifecyclePorts;
}

/** §35.7 in Private: new secrets and a new Setup Kit. */
export interface PrivateRecoveryResetRequest extends RecoveryResetBase {
  /** Step 3: the Encryption Password the user chooses now. */
  readonly password: string;
  /** Step 3: omitted generates one, which is the normal case — it becomes the new Setup Kit. */
  readonly secretKey?: AccountSecretKeyInput;
  readonly argon2Params?: Argon2Params;
  readonly kdfSalt?: Uint8Array;
  readonly escrowKey?: never;
}

/**
 * §35.7 in Managed: step 3 is not run; step 9 derives from a new `RootUnlockKey` and sends only the
 * new UNLOCK slot as `escrow`, wrapped to this Escrow Key. The RECOVERY slot is kept, because the
 * Recovery keys do not change.
 */
export interface ManagedRecoveryResetRequest extends RecoveryResetBase {
  readonly escrowKey: EscrowPublicKey;
  readonly password?: never;
}

export type RecoveryResetRequest = PrivateRecoveryResetRequest | ManagedRecoveryResetRequest;

export interface RecoveryReset {
  readonly bundle: SecurityBundle;
  /** Persisted before sending, like every other bundle: a lost response is resent verbatim (§35.1). */
  readonly serializedBundle: Uint8Array;
  /** Step 3 (Private only): the new Setup Kit. Shown once, stored nowhere; the caller zeroizes it. */
  readonly setupKit?: { readonly accountSecretKey: Uint8Array; readonly accountSecretKeyText: string };
  /** Managed only: SecurityBundle key 14 with the new UNLOCK slot alone, already in `bundle`. */
  readonly escrow?: EscrowBlob;
  readonly rootTransition: RootTransition;
  readonly root: RootDescriptor;
  readonly rootHash: Uint8Array;
  readonly registry: Registry;
  readonly registryHash: Uint8Array;
  /** Step 5: one envelope per epoch of the `RequiredEpochSet`, for the new ACCOUNT key (§34.2). */
  readonly coverageEnvelopes: readonly EpochEnvelope[];
  /** Step 8: the new epoch of every live vault, in `view.vaults` order. */
  readonly epochs: readonly CreatedEpoch[];
  readonly config: AccountSecurityConfig;
  readonly profile: AccountSecurityProfile;
  readonly configVersion: number;
  /**
   * §35.7, "Después del reset": every recipient that was ACTIVE is now REVOKED and its client
   * needs §35.8. The ids are returned as the fact they are — this operation revokes them; it does
   * not decide what those clients do, which is `planReEnrollment`'s business.
   */
  readonly revokedRecipientIds: readonly Uint8Array[];
  /** Step 12: the pins to keep — new root, new registry, new config, new epoch per vault. */
  readonly pins: ClientPins;
  /** Step 12 again: the handles to discard when the operation ends (§25.2, §24.1). */
  readonly keyset: AccountKeyset;
}

/**
 * §35.7 steps 3–9, in the order the section numbers them, returning what steps 10–12 need.
 *
 * Step 5 runs *before* the new root is built on purpose: it is the step that can fail on data the
 * server supplied (a broken envelope, a missing one), and failing there means nothing has been
 * signed yet. §33.2's "cualquier fallo aborta la operación completa antes de tocar el servidor" is
 * enforced by `buildCoverage`, which round-trips every envelope with the new private key.
 */
export async function recoveryReset(
  request: RecoveryResetRequest,
): Promise<Outcome<RecoveryReset, RecoveryResetFailure>> {
  const ports = request.ports ?? defaultPorts;
  const view = request.view;

  // Steps 3–4 (and the wrapping of step 9): the new secrets — or, in Managed, a new RootUnlockKey —
  // and the new account key pairs.
  let keyset: AccountKeyset;
  let privateParts: { setupKit: NonNullable<RecoveryReset["setupKit"]>; kdf: { kdfSalt: Uint8Array; argon2Params: Argon2ParamsRecord } } | null = null;
  let escrow: EscrowBlob | undefined;
  if (request.escrowKey === undefined) {
    const created = await createAccountRootKeyset({
      accountId: view.accountId,
      password: request.password,
      ...(request.secretKey === undefined ? {} : { secretKey: request.secretKey }),
      ...(request.argon2Params === undefined ? {} : { argon2Params: request.argon2Params }),
      ...(request.kdfSalt === undefined ? {} : { kdfSalt: request.kdfSalt }),
      ports,
    });
    if (!created.ok) {
      return { ok: false, failure: { code: created.failure.code, step: 4, message: created.failure.message } };
    }
    keyset = created.value;
    privateParts = {
      setupKit: { accountSecretKey: created.value.accountSecretKey, accountSecretKeyText: created.value.accountSecretKeyText },
      kdf: { kdfSalt: created.value.kdfSalt, argon2Params: created.value.argon2Params },
    };
  } else {
    const managed = await createManagedAccountKeyset({ accountId: view.accountId, ports });
    try {
      escrow = await buildEscrowBlob({ accountId: view.accountId, escrowKey: request.escrowKey, rootUnlockKey: managed.rootUnlockKey, ports });
    } finally {
      zeroize(managed.rootUnlockKey);
    }
    keyset = managed;
  }

  // Step 5: §33.2 from each RECOVERY envelope towards the new ACCOUNT public key, round-tripped
  // with the new private key — which is why the pairs of step 4 must exist before this runs.
  const recoverySource = (await rootRecipients(view.root))[1] as EnvelopeRecipient;
  const sourceRecipient: RecipientIdentity = { recipientId: recoverySource.recipientId, type: recoverySource.type };
  const target: EnvelopeRecipient = {
    recipientId: await rootRecipientId(keyset.encryption.publicKeySpki),
    type: "ACCOUNT",
    publicKey: keyset.encryption.publicKeySpki,
  };
  const coverage = await buildCoverage({
    required: requiredEpochSet(view.vaults),
    sources: request.sources,
    sourceRecipient,
    openingKey: request.recovery.encryptionKey,
    target,
    prover: { kind: "DECRYPT", privateKey: keyset.encryption.privateKey },
  });
  if (!coverage.ok) {
    const { code, vaultId, epochId, message } = coverage.failure;
    return {
      ok: false,
      failure: {
        code,
        step: 5,
        ...(vaultId === undefined ? {} : { vaultId }),
        ...(epochId === undefined ? {} : { epochId }),
        message,
      },
    };
  }

  // Step 6: the new root, with the recovery keys untouched (§28.2, column "Cambia"), and the
  // transition signed by the kit (role 3) and the new Account Signing key (role 2).
  const root = await nextDescriptor(view.root, {
    accountEncryption: keyset.encryption.publicKeySpki,
    accountSigning: keyset.signing.publicKeySpki,
  });
  const hash = await rootHash(root);
  const rootTransition = await signRootTransition({
    type: "RECOVERY_RESET",
    descriptor: root,
    previous: view.root,
    signers: { 2: keyset.signing.privateKey, 3: request.recovery.authorityKey },
  });

  // Step 7: the new registry — same list, nobody ACTIVE, signed by the new Account Signing key of
  // the new generation (§35.1.1 step 3). §29 forbids adding a recipient on a root transition.
  const revokedRecipientIds = activeRecipients(view.registry).map((recipient) => recipient.recipient_id);
  const registry = await signRegistry(
    await nextRegistry(view.registry, { revoke: revokedRecipientIds, rootGeneration: root.root_generation }),
    keyset.signing.privateKey,
  );
  const rHash = await registryHash(registry);

  // Step 8: one new epoch per live vault. Its envelope set is ACCOUNT (the new key) and RECOVERY
  // only — the pending registry has no ACTIVE recipient left.
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

  // Step 9: the config under the new AccountConfigKey, and the profile that carries it (§23.4).
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
    ...(privateParts?.kdf ?? {}),
    wrappedEncryptionKey: keyset.encryption.wrapped,
    wrappedSigningKey: keyset.signing.wrapped,
    configVersion: sealed.configVersion,
    configBlob: sealed.blob,
  });

  const bundle = assembleBundle({
    operationType: "RECOVERY_RESET",
    bundleId: request.bundleId,
    expected: expectedOf(view),
    rootTransition,
    rootDescriptor: root,
    registry,
    profile,
    epochs: rotation.bundleEpochs,
    coverageEnvelopes: coverage.value,
    ...(escrow === undefined ? {} : { escrow }),
  });

  return {
    ok: true,
    value: {
      bundle,
      serializedBundle: encodeRecord(SECURITY_BUNDLE, bundle),
      ...(privateParts === null ? {} : { setupKit: privateParts.setupKit }),
      ...(escrow === undefined ? {} : { escrow }),
      rootTransition,
      root,
      rootHash: hash,
      registry,
      registryHash: rHash,
      coverageEnvelopes: coverage.value,
      epochs: rotation.epochs,
      config: sealed.config,
      profile,
      configVersion: sealed.configVersion,
      revokedRecipientIds,
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
