// The client half of §35: assembling a `SecurityBundle` and producing the two signatures that are
// not already produced elsewhere (`profile_signature` of §35.6 and `deletion.signature` of
// §35.11/§35.12). The operations themselves — what each one *computes* before it gets here — are
// §35.2–§35.12 and are not in this slice.
//
// Like every other builder in this package, these enforce nothing. {@link assembleBundle} omits a
// part the caller did not supply and includes one the caller did, whether or not
// §35.1.1's table allows it for that `operation_type`; `validateSecurityBundle` is the single place
// those rules live, and a builder that silently dropped a forbidden field would make the negative
// tests unwritable and hide a client bug instead of surfacing it as `INVALID_BUNDLE`.
import { signContext } from "@nodra/crypto";
import type { AnySigningKey } from "@nodra/crypto";
import type {
  AccountSecurityProfile,
  BundleDeletion,
  BundleEpoch,
  BundleExpected,
  EpochEnvelope,
  EscrowBlob,
  RecoveryRecord,
  Registry,
  RootDescriptor,
  RootTransition,
  SecurityBundle,
} from "@nodra/encoding/records";
import { deleteAccountContext, deleteVaultContext, profileHash, profileUpdateContext, recoveryRequestContext } from "./contexts.js";
import type { OperationType, RecoveryRecordOperation, RecoveryRequestKind } from "./operations.js";

export interface BundleParts {
  readonly operationType: OperationType;
  /** UUIDv7 (§23.2). Like every other id in this package, the caller's, not generated here. */
  readonly bundleId: Uint8Array;
  readonly expected: BundleExpected;
  readonly rootTransition?: RootTransition;
  readonly rootDescriptor?: RootDescriptor;
  readonly registry?: Registry;
  readonly profile?: AccountSecurityProfile;
  readonly profileSignature?: Uint8Array;
  readonly configBlob?: Uint8Array;
  readonly configVersion?: number;
  /** §23.4: an *applicable* collection that is empty travels as `[]`, so pass `[]`, not `undefined`. */
  readonly epochs?: readonly BundleEpoch[];
  readonly coverageEnvelopes?: readonly EpochEnvelope[];
  readonly deletion?: BundleDeletion;
  /** Key 14 (§23.4): the escrow slots this bundle replaces. */
  readonly escrow?: EscrowBlob;
  /** Key 15 (§23.4, §35.15): the signed request, veto or cancellation. */
  readonly recovery?: RecoveryRecord;
}

/** The §23.4 key table as one object, with every part the caller left out omitted rather than null. */
export function assembleBundle(parts: BundleParts): SecurityBundle {
  return {
    operation_type: parts.operationType,
    ...(parts.rootTransition === undefined ? {} : { root_transition: parts.rootTransition }),
    ...(parts.rootDescriptor === undefined ? {} : { root_descriptor: parts.rootDescriptor }),
    ...(parts.registry === undefined ? {} : { registry: parts.registry }),
    ...(parts.profile === undefined ? {} : { profile: parts.profile }),
    ...(parts.profileSignature === undefined ? {} : { profile_signature: parts.profileSignature }),
    ...(parts.configBlob === undefined ? {} : { config_blob: parts.configBlob }),
    ...(parts.configVersion === undefined ? {} : { config_version: parts.configVersion }),
    ...(parts.epochs === undefined ? {} : { epochs: [...parts.epochs] }),
    ...(parts.coverageEnvelopes === undefined ? {} : { coverage_envelopes: [...parts.coverageEnvelopes] }),
    expected: parts.expected,
    ...(parts.deletion === undefined ? {} : { deletion: parts.deletion }),
    bundle_id: parts.bundleId,
    ...(parts.escrow === undefined ? {} : { escrow: parts.escrow }),
    ...(parts.recovery === undefined ? {} : { recovery: parts.recovery }),
  };
}

/**
 * §35.6: signs `Context("nodra/profile-update", account_id, config_version anterior, SHA-256(NCE(perfil nuevo)))`
 * with the Account Signing Key. `previousConfigVersion` is the one **in force**, not the profile's.
 */
export async function signProfileUpdate(
  key: AnySigningKey,
  accountId: Uint8Array,
  previousConfigVersion: number,
  profile: AccountSecurityProfile,
): Promise<Uint8Array> {
  return signContext(key, profileUpdateContext(accountId, previousConfigVersion, await profileHash(profile)));
}

export interface DeletionRequest {
  readonly operationType: OperationType;
  readonly accountId: Uint8Array;
  /** Present for `DELETE_VAULT` / `CANCEL_DELETE_VAULT`, absent for the two account operations. */
  readonly vaultId?: Uint8Array;
  readonly rootGeneration: number;
  /** bytes(16), fresh per attempt (§35.11 step 5: a cancellation uses a new one). */
  readonly nonce: Uint8Array;
}

/**
 * §35.11 step 3 / §35.12 step 3: the `deletion` sub-map, signed with the Account Signing Key over
 * the Context its subject selects. `operation_type` is a signed field, so a `DELETE_*` signature
 * can never be replayed as the `CANCEL_DELETE_*` that undoes it.
 */
export async function signDeletion(key: AnySigningKey, request: DeletionRequest): Promise<BundleDeletion> {
  const ctx =
    request.vaultId === undefined
      ? deleteAccountContext(request.operationType, request.accountId, request.rootGeneration, request.nonce)
      : deleteVaultContext(request.operationType, request.accountId, request.vaultId, request.rootGeneration, request.nonce);
  return {
    ...(request.vaultId === undefined ? {} : { vault_id: request.vaultId }),
    nonce: request.nonce,
    signature: await signContext(key, ctx),
  };
}

export interface RecoveryRecordRequest {
  readonly operationType: RecoveryRecordOperation;
  readonly accountId: Uint8Array;
  /** bytes(16), UUIDv7 chosen by the requester; a veto or cancel repeats the request's own. */
  readonly requestId: Uint8Array;
  readonly kind: RecoveryRequestKind;
  readonly rootGeneration: number;
  readonly rootHash: Uint8Array;
}

/**
 * §35.15: the `recovery` sub-map (key 15), signed over `Context("nodra/recovery-request", …)` with
 * whatever key the caller passes. Which role that must be is the validator's rule
 * (`RECOVERY_RECORD_SIGNERS`); signing with the wrong one is a bundle a test must be able to build.
 */
export async function signRecoveryRecord(key: AnySigningKey, request: RecoveryRecordRequest): Promise<RecoveryRecord> {
  const ctx = recoveryRequestContext(
    request.operationType,
    request.accountId,
    request.requestId,
    request.kind,
    request.rootGeneration,
    request.rootHash,
  );
  return {
    request_id: request.requestId,
    kind: request.kind,
    root_generation: request.rootGeneration,
    root_hash: request.rootHash,
    signature: await signContext(key, ctx),
  };
}
