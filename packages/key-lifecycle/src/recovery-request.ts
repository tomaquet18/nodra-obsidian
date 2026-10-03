// §35.15: the request, veto and cancellation of a delayed recovery operation (ADR-022).
//
// A Private `RECOVERY_RESET`, `RECOVERY_KIT_REPLACEMENT` or `SWITCH_TO_MANAGED` now happens in two
// phases. Phase 1 is one of these bundles: a signed `RecoveryRecord` and nothing else. Phase 2 is the
// operation's own bundle, built exactly as before once the request has matured (§35.7, §35.9,
// §35.14) — never here, because a bundle built 72 hours early would fail every CAS of §35.1.
//
// What makes each record mean what it says is inside the signed bytes: the `operation_type` (so a
// request can never count as a veto), the `kind` and `request_id` (so a veto ends exactly one
// request), and the root in force (so nothing survives a root change). Which **role** must sign is
// the cross-veto table `RECOVERY_RECORD_SIGNERS`; these builders sign with the key they are given
// and enforce none of it, like every other builder here — `validateSecurityBundle` is the one place
// the rules live.
import { importVerifyingKey, verifyContext } from "@nodra/crypto";
import type { AnySigningKey } from "@nodra/crypto";
import { SECURITY_BUNDLE, encodeRecord } from "@nodra/encoding/records";
import type { RecoveryRecord, RootDescriptor, SecurityBundle } from "@nodra/encoding/records";
import { assembleBundle, signRecoveryRecord } from "./bundle-build.js";
import type { AccountView } from "./client-state.js";
import { recoveryRequestContext } from "./contexts.js";
import { RECOVERY_RECORD_SIGNERS } from "./operations.js";
import type { RecoveryRecordOperation, RecoveryRequestKind } from "./operations.js";

/**
 * The part of the verified view a record is prepared over: the root in force it binds, and the CAS
 * triple of §35.1.1 step 0d. A kit holder on a new browser has it from replaying the chains against
 * the kit's `genesis_root_hash` (§35.7 step 2), with no pins.
 */
export type RecoveryRecordView = Pick<AccountView, "accountId" | "root" | "rootHash" | "registry" | "configVersion">;

export interface RecoveryRecordBundleRequest {
  readonly view: RecoveryRecordView;
  readonly bundleId: Uint8Array;
  readonly requestId: Uint8Array;
  readonly kind: RecoveryRequestKind;
  /**
   * The role `RECOVERY_RECORD_SIGNERS` names for (`operation_type`, `kind`): the Recovery Authority of
   * the kit (role 3) or the Signing handle of Root Unlock (role 1). Used once and never kept.
   */
  readonly signingKey: AnySigningKey;
}

export interface BuiltRecoveryRecord {
  readonly bundle: SecurityBundle;
  /** §35.1: persisted with the `bundle_id` until an answer arrives; a lost answer is resent verbatim. */
  readonly serializedBundle: Uint8Array;
  readonly record: RecoveryRecord;
}

async function buildRecoveryRecordBundle(
  operationType: RecoveryRecordOperation,
  request: RecoveryRecordBundleRequest,
): Promise<BuiltRecoveryRecord> {
  const { view } = request;
  const record = await signRecoveryRecord(request.signingKey, {
    operationType,
    accountId: view.accountId,
    requestId: request.requestId,
    kind: request.kind,
    rootGeneration: view.root.root_generation,
    rootHash: view.rootHash,
  });
  const bundle = assembleBundle({
    operationType,
    bundleId: request.bundleId,
    // §35.1.1 step 0d: the same CAS triple as `expectedOf`, from the narrower view.
    expected: {
      root_generation: view.root.root_generation,
      registry_version: view.registry.registry_version,
      config_version: view.configVersion,
    },
    recovery: record,
  });
  return { bundle, serializedBundle: encodeRecord(SECURITY_BUNDLE, bundle), record };
}

/**
 * §35.7 phase 1 (`kind` = `RECOVERY_RESET`, signed with the kit's Recovery Authority), §35.9 and
 * §35.14 phase 1 (signed with the Account Signing handle). `requestId` is a fresh UUIDv7: one that
 * this account has seen before answers `NONCE_REUSED`.
 */
export function requestRecovery(request: RecoveryRecordBundleRequest): Promise<BuiltRecoveryRecord> {
  return buildRecoveryRecordBundle("RECOVERY_REQUEST", request);
}

/**
 * §35.15: the veto, by the authority the requester does **not** hold — Password + Secret Key for a
 * reset, the Recovery Kit for a kit replacement or a switch. Final: a vetoed request never matures.
 */
export function vetoRecovery(request: RecoveryRecordBundleRequest): Promise<BuiltRecoveryRecord> {
  return buildRecoveryRecordBundle("RECOVERY_VETO", request);
}

/** §35.15: the requester takes its own request back, with the role it requested with. Final too. */
export function cancelRecovery(request: RecoveryRecordBundleRequest): Promise<BuiltRecoveryRecord> {
  return buildRecoveryRecordBundle("RECOVERY_CANCEL", request);
}

/** A live request as `getRootState` returns it (§22): the signed fields, and dates that are not signed. */
export interface PendingRecoveryRequest {
  readonly requestId: Uint8Array;
  readonly kind: RecoveryRequestKind;
  readonly rootGeneration: number;
  readonly rootHash: Uint8Array;
  readonly signature: Uint8Array;
  readonly requestedAt: number;
  readonly maturesAt: number;
  readonly expiresAt: number;
}

/**
 * §35.15: "El cliente PUEDE verificar la firma de la solicitud contra su pin antes de mostrarla."
 * True only if the request names `root` (the client's verified root in force) and is signed by the
 * role that may request its `kind`. The dates are the server's and prove nothing (§39.2).
 */
export async function verifyRecoveryRequest(
  accountId: Uint8Array,
  root: RootDescriptor,
  rootHash: Uint8Array,
  request: Pick<PendingRecoveryRequest, "requestId" | "kind" | "rootGeneration" | "rootHash" | "signature">,
): Promise<boolean> {
  if (request.rootGeneration !== root.root_generation || !sameBytes(request.rootHash, rootHash)) return false;
  const role = RECOVERY_RECORD_SIGNERS.RECOVERY_REQUEST[request.kind].role;
  const spki = role === 1 ? root.account_signing_public_key : root.recovery_authority_public_key;
  try {
    const key = await importVerifyingKey(spki);
    const ctx = recoveryRequestContext("RECOVERY_REQUEST", accountId, request.requestId, request.kind, request.rootGeneration, request.rootHash);
    return await verifyContext(key, ctx, request.signature);
  } catch {
    return false;
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
