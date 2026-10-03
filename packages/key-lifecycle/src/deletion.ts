// §35.11 and §35.12: scheduling a deletion, and cancelling one.
//
// "El borrado de datos es una operación de seguridad, nunca un endpoint que solo compruebe el
// login" (§35.11). The whole operation is therefore one signed sub-map: no transition, no
// registry, no config, no epochs, no coverage — §35.1.1's row for all four types is "— (solo
// `deletion`)". What makes it a security operation is what is *inside* that sub-map, and two
// properties of it are the reason these builders exist rather than a bare `signDeletion` call:
//
//   1. **`operation_type` is a signed field.** The Context of §35.11 step 3 and §35.12 step 3 both
//      begin with it, so a `DELETE_VAULT` signature can never be presented as the
//      `CANCEL_DELETE_VAULT` that undoes it, nor the other way round. That is the only thing
//      standing between "the user cancelled" and "an attacker replayed the cancel to re-arm the
//      deletion", because the two travel over the same wire with the same shape.
//   2. **`root_generation` is signed too.** A deletion prepared under one root is not valid under
//      the next, so a signature captured before a `RECOVERY_RESET` dies with it — which is exactly
//      what §35.12 step 4 relies on when it lets the kit holder take an account back from an
//      attacker who scheduled its deletion.
//
// Everything else is the Worker's: the 14-day timer, the state precondition of §35.12's table, the
// nonce registry, the physical deletion. `validateSecurityBundle` implements those, and these
// builders enforce none of them — a bundle that names a vault in the wrong state is exactly the
// bundle a test must be able to build.
import { SECURITY_BUNDLE, encodeRecord } from "@nodra/encoding/records";
import type { BundleDeletion, SecurityBundle } from "@nodra/encoding/records";
import { assembleBundle, signDeletion } from "./bundle-build.js";
import type { AccountState } from "./bundle.js";
import type { AccountView, SigningKeys } from "./client-state.js";
import { expectedOf } from "./client-state.js";
import type { VaultState } from "./coverage.js";
import { OPERATION_RULES } from "./operations.js";
import type { OperationType } from "./operations.js";

/** The two vault operations of §35.11, and the two account operations of §35.12. */
export type VaultDeletionType = "DELETE_VAULT" | "CANCEL_DELETE_VAULT";
export type AccountDeletionType = "DELETE_ACCOUNT" | "CANCEL_DELETE_ACCOUNT";

/**
 * §35.11/§35.12 need only the Signing handle: no config is rewritten and no envelope sealed. For a
 * cancel sent with a `RECOVERY_CONTROL` token (ADR-022) it is the kit's Recovery Authority instead;
 * the token's scope decides which key the Worker verifies with (§35.1.1 step 7, deletion block).
 */
export type DeletionKeys = Pick<SigningKeys, "signingKey">;

interface CommonDeletionRequest {
  /** The verified state (§35.11 step 1, §35.12 step 1: a trusted client after Root Unlock). */
  readonly view: AccountView;
  readonly bundleId: Uint8Array;
  /**
   * bytes(16), fresh for **every** attempt. §35.11 step 5 is explicit that a cancellation carries
   * a new one, and §35.1.1 step 7 (c) answers `NONCE_REUSED` for a repeat — including a repeat of
   * the client's own, which is why nothing here derives it from the operation.
   */
  readonly nonce: Uint8Array;
  /** §35.11 step 1 / §35.12 step 1: the Signing handle of Root Unlock. */
  readonly keys: DeletionKeys;
}

export interface VaultDeletionRequest extends CommonDeletionRequest {
  readonly operationType: VaultDeletionType;
  /** §35.11 step 2: the vault the user confirmed **by name** in the UI. */
  readonly vaultId: Uint8Array;
}

export interface AccountDeletionRequest extends CommonDeletionRequest {
  readonly operationType: AccountDeletionType;
}

/**
 * §35.11: what the client must do differently once the Worker applies the bundle. A scheduled
 * deletion is reversible for 14 days, so reads continue and security operations keep rotating this
 * vault's epoch (§35.1.1 step 7 still counts a `DELETING_SCHEDULED` vault); only writes stop.
 */
export interface VaultDeletionEffects {
  readonly vaultId: Uint8Array;
  readonly vaultState: Extract<VaultState, "ACTIVE" | "DELETING_SCHEDULED">;
  /**
   * §35.11: `prepareUpload`, PUT, `commitMutation` and `releaseUpload` answer `VAULT_DELETING`.
   * The client stops attempting them, **keeps its outbox** and notifies the user (§12.6) — the
   * outbox is what drains if the deletion is cancelled, so discarding it would lose the edits.
   */
  readonly writesRejected: boolean;
}

/** §35.12: the same, one level up. Every vault of the account stops accepting writes. */
export interface AccountDeletionEffects {
  readonly accountState: Extract<AccountState, "ACTIVE" | "DELETING_SCHEDULED">;
  readonly writesRejected: boolean;
}

interface BuiltDeletion {
  readonly bundle: SecurityBundle;
  /**
   * §35.1: the exact bytes to persist with the `bundle_id` until an answer arrives. A deletion is
   * the operation where that matters most — a lost response must be recovered by resending the
   * same `bundle_id`, never by signing a second nonce, which step 7 (c) would answer
   * `NONCE_REUSED` while the first one may well have been applied.
   */
  readonly serializedBundle: Uint8Array;
  readonly deletion: BundleDeletion;
}

export interface ScheduledVaultDeletion extends BuiltDeletion {
  readonly effects: VaultDeletionEffects;
}

export interface ScheduledAccountDeletion extends BuiltDeletion {
  readonly effects: AccountDeletionEffects;
}

async function buildDeletionBundle(
  operationType: OperationType,
  request: CommonDeletionRequest,
  vaultId: Uint8Array | undefined,
): Promise<BuiltDeletion> {
  const { view } = request;
  const deletion = await signDeletion(request.keys.signingKey, {
    operationType,
    accountId: view.accountId,
    ...(vaultId === undefined ? {} : { vaultId }),
    // §35.1.1 step 7 (b) verifies under the **pending** root, and these operations install none,
    // so the pending root is the one in force and its generation is what must be signed.
    rootGeneration: view.root.root_generation,
    nonce: request.nonce,
  });
  const bundle = assembleBundle({
    operationType,
    bundleId: request.bundleId,
    expected: expectedOf(view),
    deletion,
  });
  return { bundle, serializedBundle: encodeRecord(SECURITY_BUNDLE, bundle), deletion };
}

/**
 * §35.11 steps 1–3, and step 5 for the cancel. One function for both directions because they
 * differ in exactly one byte-level input — the `operation_type` inside the signed Context — and
 * writing them twice would be writing that distinction twice.
 */
export async function buildVaultDeletion(request: VaultDeletionRequest): Promise<ScheduledVaultDeletion> {
  const built = await buildDeletionBundle(request.operationType, request, request.vaultId);
  const scheduling = request.operationType === "DELETE_VAULT";
  return {
    ...built,
    effects: {
      vaultId: request.vaultId,
      vaultState: scheduling ? "DELETING_SCHEDULED" : "ACTIVE",
      writesRejected: scheduling,
    },
  };
}

/** §35.12 steps 1–3, and the cancel of the same section. */
export async function buildAccountDeletion(request: AccountDeletionRequest): Promise<ScheduledAccountDeletion> {
  const built = await buildDeletionBundle(request.operationType, request, undefined);
  const scheduling = request.operationType === "DELETE_ACCOUNT";
  return {
    ...built,
    effects: {
      accountState: scheduling ? "DELETING_SCHEDULED" : "ACTIVE",
      writesRejected: scheduling,
    },
  };
}

/** §35.11 step 3: schedules the deletion of one vault, 14 days ahead. */
export async function deleteVault(
  request: Omit<VaultDeletionRequest, "operationType">,
): Promise<ScheduledVaultDeletion> {
  return buildVaultDeletion({ ...request, operationType: "DELETE_VAULT" });
}

/** §35.11 step 5: takes it back, with a new nonce and a signature over its own `operation_type`. */
export async function cancelDeleteVault(
  request: Omit<VaultDeletionRequest, "operationType">,
): Promise<ScheduledVaultDeletion> {
  return buildVaultDeletion({ ...request, operationType: "CANCEL_DELETE_VAULT" });
}

/** §35.12 step 3: schedules the deletion of the account, 14 days ahead. */
export async function deleteAccount(
  request: Omit<AccountDeletionRequest, "operationType">,
): Promise<ScheduledAccountDeletion> {
  return buildAccountDeletion({ ...request, operationType: "DELETE_ACCOUNT" });
}

/** §35.12: the cancel, which `ACCOUNT_SECURITY` also authorizes (§35.1.1 step 0). */
export async function cancelDeleteAccount(
  request: Omit<AccountDeletionRequest, "operationType">,
): Promise<ScheduledAccountDeletion> {
  return buildAccountDeletion({ ...request, operationType: "CANCEL_DELETE_ACCOUNT" });
}

/**
 * §35.12 step 4: the operations a `DELETING_SCHEDULED` account still accepts, read out of the
 * per-operation table rather than listed again. A client that shows a user what they may still do
 * during the grace period asks this, so the answer can never drift from what the Worker enforces
 * in §35.1.1 step 0c.
 */
export function operationsAllowedWhileAccountDeleting(): readonly OperationType[] {
  return (Object.keys(OPERATION_RULES) as OperationType[]).filter(
    (type) => OPERATION_RULES[type].allowedWhileAccountDeleting,
  );
}
