// §35.1.1: the Worker's ordered validation of one `SecurityBundle`.
//
// This is a **composition**, not a re-implementation. Every cryptographic rule it needs already
// lives in exactly one function in this package — `verifyRootChain` (§28.2), `verifyRegistryChain`
// (§29), `verifyEpochChain` (§32.1/§36.2), `checkCoverage` (§34.2), `checkKdfParams` (§24) — and
// this file calls them in the order §35.1.1 numbers its steps, maps their failures onto the
// response codes of §35.1, and adds only what no existing verifier owns: the per-operation
// applicability table (`operations.ts`), the CAS, the deletion block, and the exactness rules that
// relate a bundle to the account state read under lock.
//
// Two properties the tests hold it to:
//
//   1. **Order is observable.** Every failure names the step that produced it, and a bundle that
//      breaks rules in two steps always fails at the earlier one. A validator that reordered the
//      steps would be a different function with different answers — see the broken-variant proofs.
//   2. **A step never peeks ahead.** Step 0 reads no account state at all (that is the whole point
//      of §35.1's "los del paso 0 … no consumen nonces"), step 0b reads only the stored result, and
//      the existence of a foreign `vault_id` is settled once, in 0c, so that no later retryable
//      code (`EPOCH_STALE`, `VAULT_SET_STALE`, `COVERAGE_STALE`) can act as an existence oracle.
//
// Pure: no I/O, no clock, no randomness. The Worker reads its state under the locks of §5.2/§11.4
// and hands it here as a {@link BundleState}; everything this returns is a decision about that
// snapshot. Step 8 ("persistir todo y emitir security_event / sync_events") is deliberately not
// here — {@link AcceptedBundle} is exactly the input that step needs.
import { ARGON2_LIMITS, importVerifyingKey, verifyContext } from "@nodra/crypto";
import type { VerifyingKey } from "@nodra/crypto";
import type {
  AccountSecurityProfile,
  BundleEpoch,
  EpochEnvelope,
  EscrowBlob,
  Registry,
  RegistryRecipient,
  RootDescriptor,
  SecurityBundle,
} from "@nodra/encoding/records";
import { deleteAccountContext, deleteVaultContext, profileHash, profileUpdateContext, recoveryRequestContext } from "./contexts.js";
import { checkCoverage, requiredEpochSet } from "./coverage.js";
import type { ListedEpoch, RequiredEpoch, VaultState } from "./coverage.js";
import type { Outcome } from "./errors.js";
import { envelopeSetHash, epochRecipients, idKey, rootRecipientId } from "./epoch.js";
import type { RecipientIdentity } from "./epoch.js";
import { verifyEpochChain } from "./epoch-chain.js";
import type { EpochChainState } from "./epoch-chain.js";
import { RECOVERY_RECORD_SIGNERS, forbiddenFields, isRecoveryRecordOperation, operationRules, requiredFields } from "./operations.js";
import type { OperationRules, OperationType, RecoveryRequestKind, Scope } from "./operations.js";
import { isLive, isMature } from "./recovery-request-state.js";
import type { StoredRecoveryRequest } from "./recovery-request-state.js";
import { activeRecipients, verifyRegistryChain } from "./registry.js";
import type { RegistryState } from "./registry.js";
import { modeAfter, verifyRootChain } from "./root-chain.js";
import type { RootState } from "./root-chain.js";
import { checkKdfParams, toArgon2Params } from "./secrets.js";

// --- Failure vocabulary ------------------------------------------------------------------------

/** The steps of §35.1.1, in order. A failure always names the one that produced it. */
export const BUNDLE_STEPS = ["0", "0b", "0c", "0d", "1", "3", "5", "6", "7"] as const;
export type BundleStep = (typeof BUNDLE_STEPS)[number];

/**
 * The response codes of §35.1. Split exactly as that table does: the first five are **retryable**
 * (a correct client can hit them through concurrency, or recover by re-authenticating, and must be
 * told so), the rest are definitive.
 */
export type BundleFailureCode =
  | "SECURITY_STATE_STALE"
  | "EPOCH_STALE"
  | "VAULT_SET_STALE"
  | "COVERAGE_STALE"
  | "REAUTH_REQUIRED"
  | "WRITE_CAPABILITY_REQUIRED"
  | "SCOPE_REQUIRED"
  | "RECIPIENT_REVOKED"
  | "INVALID_SIGNATURE"
  | "INVALID_REGISTRY"
  | "INVALID_TRANSITION"
  | "INVALID_STATE"
  | "NONCE_REUSED"
  | "INVALID_BUNDLE"
  | "PLAN_LIMIT_EXCEEDED"
  | "NOT_APPLICABLE_IN_MANAGED"
  // §35.15 (ADR-022).
  | "RECOVERY_NOT_MATURE"
  | "RECOVERY_REQUEST_REQUIRED"
  | "RECOVERY_REQUEST_EXISTS"
  // §35.2 / §3.7 (ADR-023).
  | "EMAIL_UNCONFIRMED";

const RETRYABLE: ReadonlySet<BundleFailureCode> = new Set<BundleFailureCode>([
  "SECURITY_STATE_STALE",
  "EPOCH_STALE",
  "VAULT_SET_STALE",
  "COVERAGE_STALE",
  // §35.1: "reintentable tras reautenticarse; no consume nonce ni se guarda".
  "REAUTH_REQUIRED",
  // §35.15: retryable from `matures_at` on; not stored.
  "RECOVERY_NOT_MATURE",
  // §35.2: "reintentable tras confirmar el email; no se guarda".
  "EMAIL_UNCONFIRMED",
]);

/**
 * §35.1: the one definitive code that is **not** stored and consumes nothing, so the same
 * `bundle_id` can be resent once a new request matures (§35.15).
 */
const DEFINITIVE_NOT_STORED: ReadonlySet<BundleFailureCode> = new Set<BundleFailureCode>(["RECOVERY_REQUEST_REQUIRED"]);

/** §35.1: the three codes of step 0, which are emitted before any state is read. */
const STEP_0_CODES: ReadonlySet<BundleFailureCode> = new Set<BundleFailureCode>([
  "WRITE_CAPABILITY_REQUIRED",
  "SCOPE_REQUIRED",
  "RECIPIENT_REVOKED",
]);

export interface BundleFailure {
  readonly code: BundleFailureCode;
  /** The step of §35.1.1 that rejected. */
  readonly step: BundleStep;
  /** The rule inside that step, for logs and for tests that assert on the rule, not the prose. */
  readonly rule: string;
  /** §35.1: a retryable code carries the state in force; a definitive one never does. */
  readonly retryable: boolean;
  /** §35.1: the Worker stores definitive rejections emitted from step 0c on, by `bundle_id`. */
  readonly stored: boolean;
  /** §35.1/§35.11: whether this outcome registers the bundle's `deletion.nonce` as consumed. */
  readonly consumesNonce: boolean;
  /** `SECURITY_STATE_STALE` carries the three values in force. */
  readonly expected?: { readonly rootGeneration: number; readonly registryVersion: number; readonly configVersion: number };
  /** `VAULT_SET_STALE` carries the live vault list; `COVERAGE_STALE` the `RequiredEpochSet`. */
  readonly vaultIds?: readonly Uint8Array[];
  readonly required?: readonly RequiredEpoch[];
  /** `RECOVERY_NOT_MATURE` carries the request's `matures_at` (Unix ms, §35.15). */
  readonly maturesAt?: number;
  /** `RECOVERY_REQUEST_EXISTS` carries the live request's `kind` and dates (§35.1). */
  readonly liveRequest?: { readonly kind: RecoveryRequestKind; readonly maturesAt: number; readonly expiresAt: number };
  readonly message: string;
}

// --- Input: the account state, read under the locks of §5.2 -------------------------------------

/** §35.12: the account states. */
export type AccountState = "ACTIVE" | "DELETING_SCHEDULED" | "DELETING" | "ORPHANED";

/** §11.3: a Write Capability Token as step 0 sees it — never re-derived from the session. */
export interface WriteCapability {
  readonly scopes: readonly Scope[];
  /**
   * §11.3: revocation is eager, so "is the token live" is one row read. A token marked
   * `RECIPIENT_REVOKED` answers that code; any other non-live token is `WRITE_CAPABILITY_REQUIRED`
   * and reaches this function as an absent token.
   */
  readonly revokedReason?: "RECIPIENT_REVOKED" | "ROOT_CHANGED";
}

export interface BundleAuthorization {
  /** A live Supabase session. Without one there is no request to validate at all. */
  readonly authenticated: boolean;
  /** Absent means no live token: `WRITE_CAPABILITY_REQUIRED` for every type but `CREATE_ACCOUNT`. */
  readonly token?: WriteCapability;
  /**
   * §35.12 step 2: seconds since the session's most recent **primary** authentication (never `iat`),
   * as the Worker computed it from its own clock. Absent means unknown, which is not recent.
   */
  readonly primaryAuthAgeSeconds?: number;
  /**
   * §35.2 / §3.7: whether the session's Supabase user has a confirmed email, as the Worker read it
   * (`nodra_account_email_confirmed`). Read for CREATE_ACCOUNT only; absent means not confirmed.
   */
  readonly emailConfirmed?: boolean;
}

/** §35.12 step 2: "hace 5 minutos o menos". */
export const REAUTH_WINDOW_SECONDS = 5 * 60;

/** §35.1: what the Worker kept for a `bundle_id`, for the 180-day replay window. */
export interface StoredBundleResult<T = unknown> {
  readonly operationType: OperationType;
  readonly result: T;
}

/** One vault of this account as read under its lock. */
export interface BundleVault {
  readonly vaultId: Uint8Array;
  readonly state: VaultState;
  /**
   * The vault's verified epoch chain state, or `null` for a vault with no epoch yet. Step 6 uses
   * it as `verifyEpochChain`'s `from`, which is what turns §36.2's "`current_write_epoch_id` ==
   * expected" and "`previous_descriptor_hash` == hash of the descriptor in force" into one call.
   */
  readonly currentEpoch: EpochChainState | null;
  /** `listEpochDescriptors` for this vault (§22), for the `RequiredEpochSet` of §34.1. */
  readonly epochs: readonly ListedEpoch[];
}

export interface BundleState {
  /** Step 0's only input: the session and the Write Capability Token, with no state behind them. */
  readonly authorization: BundleAuthorization;
  /** The authenticated `account_id`. Never read from the bundle (NOTES questions 183, 195). */
  readonly accountId: Uint8Array;
  readonly accountState: AccountState;
  /** The root in force, or `null` for an account that has no root yet (before GENESIS). */
  readonly root: RootState | null;
  readonly registry: RegistryState | null;
  /** 0 before GENESIS (§35.1.1 step 5). */
  readonly configVersion: number;
  /**
   * §3.6 / §35.1.1 step 0c: the account's `account_escrows` row, read under the account lock. Its
   * presence is the account's mode on the Worker: Managed with a row, Private without.
   */
  readonly escrow: EscrowBlob | null;
  /** Every vault of this account, including `DELETED` ones (step 6 needs them to filter). */
  readonly vaults: readonly BundleVault[];
  /** §35.12: `vault_id`s of purged vaults, which are never reused. */
  readonly retiredVaultIds?: readonly Uint8Array[];
  /** §35.11/§35.12: `deletion.nonce` values already consumed by this account. */
  readonly consumedNonces?: readonly Uint8Array[];
  /** §40: the plan's ceiling on `ACTIVE` `PLUGIN_INSTALLATION` recipients. Absent means no limit. */
  readonly pluginLimit?: number;
  /** §40: the plan's ceiling on live vaults. Absent means no limit. */
  readonly vaultLimit?: number;
  /** §35.1 step 0b: the stored outcome for this `bundle_id`, if the Worker kept one. */
  readonly storedResult?: StoredBundleResult | null;
  /**
   * §35.15: the database clock (Unix ms) read under the account lock. Without it no request is
   * live or mature, so a delayed operation fails closed with `RECOVERY_REQUEST_REQUIRED`.
   */
  readonly now?: number;
  /** §35.15: every `recovery_requests` row of this account, terminal ones included. Absent: none. */
  readonly recoveryRequests?: readonly StoredRecoveryRequest[];
}

// --- Output ------------------------------------------------------------------------------------

/**
 * Everything step 8 needs to persist, and nothing the caller would have to recompute. In
 * particular the pending root and registry (steps 2 and 4) and the survivors of step 6's filter.
 */
export interface AcceptedBundle {
  readonly operationType: OperationType;
  readonly rules: OperationRules;
  readonly pendingRoot: RootDescriptor;
  readonly pendingRootHash: Uint8Array;
  readonly pendingRootGeneration: number;
  /** `null` only for `CREATE_ACCOUNT` before its own registry — never in practice. */
  readonly pendingRegistry: Registry;
  readonly pendingRegistryHash: Uint8Array;
  readonly pendingRegistryVersion: number;
  /** The `config_version` this bundle installs: the one in force + 1 (step 5). */
  readonly configVersion: number;
  /** Epochs that survived step 6's filter, in bundle order. */
  readonly epochs: readonly BundleEpoch[];
  /** Epochs discarded in step 6: own `DELETED` vaults. Not an error (§35.1). */
  readonly discardedEpochs: readonly BundleEpoch[];
  readonly coverageEnvelopes: readonly EpochEnvelope[];
  readonly discardedCoverage: readonly EpochEnvelope[];
  /** §35.11/§35.12: the nonce to register as consumed, if this operation carries one. */
  readonly consumedNonce: Uint8Array | null;
  /** §35.1.1 step 7: what step 8 does to `account_escrows` in the same transaction. */
  readonly escrowChange: EscrowChange | null;
  /** §35.1.1 step 8 (§35.15): what step 8 does to `recovery_requests` in the same transaction. */
  readonly recoveryChange: RecoveryChange | null;
}

/**
 * §35.15 in step 8. Besides this, every applied root transition sets every *other* `PENDING` request
 * of the account to `INVALIDATED` — a rule of step 8 that needs no input beyond the transition.
 */
export type RecoveryChange =
  /** RECOVERY_REQUEST: insert the row `PENDING`, with the delay the Worker holds now. */
  | {
      readonly kind: "REQUEST";
      readonly requestId: Uint8Array;
      readonly requestKind: RecoveryRequestKind;
      readonly rootGeneration: number;
      readonly rootHash: Uint8Array;
      readonly signerRole: 1 | 3;
      readonly signature: Uint8Array;
    }
  /** RECOVERY_VETO / RECOVERY_CANCEL: the live request leaves `PENDING` for good. */
  | { readonly kind: "VETO" | "CANCEL"; readonly requestId: Uint8Array; readonly signature: Uint8Array }
  /** A delayed operation applied in Private: the matured request that authorized it. */
  | { readonly kind: "CONSUME"; readonly requestId: Uint8Array };

export type EscrowChange =
  /** CREATE_ACCOUNT in Managed, SWITCH_TO_MANAGED: create the row with both slots. */
  | { readonly kind: "CREATE"; readonly escrow: EscrowBlob }
  /** RECOVERY_RESET in Managed: replace the slots present (UNLOCK), keep the others. */
  | { readonly kind: "REPLACE"; readonly escrow: EscrowBlob }
  /** SWITCH_TO_PRIVATE: delete the row, and set each vault's `private_since_epoch_id` to its new epoch. */
  | { readonly kind: "DELETE" };

export type BundleDecision<T = unknown> =
  /** Steps 0–7 passed: hand this to step 8. */
  | { readonly kind: "ACCEPT"; readonly accepted: AcceptedBundle }
  /** Step 0b: the Worker already answered this `bundle_id`; return that answer unchanged. */
  | { readonly kind: "STORED"; readonly stored: StoredBundleResult<T> };

export type BundleOutcome<T = unknown> = Outcome<BundleDecision<T>, BundleFailure>;

// --- Failure helpers ---------------------------------------------------------------------------

interface FailExtras {
  readonly expected?: BundleFailure["expected"];
  readonly vaultIds?: readonly Uint8Array[];
  readonly required?: readonly RequiredEpoch[];
  readonly maturesAt?: number;
  readonly liveRequest?: BundleFailure["liveRequest"];
}

/**
 * The one place a failure is built, so the retryable / stored / nonce classification of §35.1 is
 * *derived* from (step, code) rather than restated at ~40 call sites where one could drift.
 */
function failure(
  step: BundleStep,
  code: BundleFailureCode,
  rule: string,
  message: string,
  hasNonce: boolean,
  extras: FailExtras = {},
): Outcome<never, BundleFailure> {
  const retryable = RETRYABLE.has(code);
  // §35.1: "Los códigos reintentables no consumen nonces. Los definitivos emitidos a partir del
  // paso 0c sí; los del paso 0 … y el INVALID_BUNDLE del paso 0b no." RECOVERY_REQUEST_REQUIRED is
  // the one definitive exception (§35.15).
  const stored =
    !retryable && step !== "0" && step !== "0b" && !STEP_0_CODES.has(code) && !DEFINITIVE_NOT_STORED.has(code);
  const base: BundleFailure = { code, step, rule, retryable, stored, consumesNonce: stored && hasNonce, message };
  return {
    ok: false,
    failure: {
      ...base,
      ...(extras.expected === undefined ? {} : { expected: extras.expected }),
      ...(extras.vaultIds === undefined ? {} : { vaultIds: extras.vaultIds }),
      ...(extras.required === undefined ? {} : { required: extras.required }),
      ...(extras.maturesAt === undefined ? {} : { maturesAt: extras.maturesAt }),
      ...(extras.liveRequest === undefined ? {} : { liveRequest: extras.liveRequest }),
    },
  };
}

// --- The algorithm -----------------------------------------------------------------------------

/**
 * §35.1.1, step by step. `state` is the snapshot the Worker read inside its transaction, under the
 * locks the §11.4 table fixes from the `operation_type` — never from the `vault_id`s the bundle
 * carries, which is precisely what step 0c then checks.
 */
export async function validateSecurityBundle<T = unknown>(
  bundle: SecurityBundle,
  state: BundleState,
): Promise<BundleOutcome<T>> {
  const operationType = bundle.operation_type;
  const rules = operationRules(operationType);
  const nonce = bundle.deletion?.nonce;
  const hasNonce = nonce !== undefined;

  // ---- 0. authorization, WITHOUT reading any account state ------------------------------------
  const step0 = checkAuthorization(bundle, rules, operationType, state, hasNonce);
  if (step0 !== null) return step0;

  // ---- 0b. bundle_id lookup -------------------------------------------------------------------
  const stored = state.storedResult;
  if (stored !== undefined && stored !== null) {
    if (stored.operationType !== operationType) {
      return failure(
        "0b",
        "INVALID_BUNDLE",
        "bundle_id/operation_type",
        `bundle_id was already used for ${stored.operationType}, not ${operationType}`,
        hasNonce,
      );
    }
    return { ok: true, value: { kind: "STORED", stored: stored as StoredBundleResult<T> } };
  }

  // ---- 0c. account and target-vault state (first state read) ----------------------------------
  const step0c = check0c(bundle, rules, operationType, state, hasNonce);
  if (step0c !== null) return step0c;

  // ---- 0d. CAS of `expected` ------------------------------------------------------------------
  const inForce = {
    rootGeneration: state.root?.rootGeneration ?? 0,
    registryVersion: state.registry?.registry.registry_version ?? 0,
    configVersion: state.configVersion,
  };
  const expected = bundle.expected;
  if (
    expected.root_generation !== inForce.rootGeneration ||
    expected.registry_version !== inForce.registryVersion ||
    expected.config_version !== inForce.configVersion
  ) {
    return failure("0d", "SECURITY_STATE_STALE", "expected/cas", "the bundle was prepared over another security state", hasNonce, {
      expected: inForce,
    });
  }

  // ---- 1. transition (if any): the complete §28.2 validation -----------------------------------
  let pendingRoot: RootDescriptor | null = state.root?.descriptor ?? null;
  let pendingRootHash: Uint8Array | null = state.root?.rootHash ?? null;
  let pendingRootGeneration = state.root?.rootGeneration ?? 0;

  if (bundle.root_transition !== undefined) {
    if (bundle.root_descriptor === undefined) {
      return failure("1", "INVALID_TRANSITION", "transition/descriptor", "a transition must travel with the Root Descriptor it installs (§28.2 rule 2)", hasNonce);
    }
    const replay = await verifyRootChain([{ transition: bundle.root_transition, descriptor: bundle.root_descriptor }], {
      accountId: state.accountId,
      ...(state.root === null ? {} : { from: state.root }),
    });
    if (!replay.ok) {
      const code: BundleFailureCode =
        replay.failure.code === "BAD_SIGNATURE" || replay.failure.code === "BAD_SIGNATURE_SET"
          ? "INVALID_SIGNATURE"
          : "INVALID_TRANSITION";
      return failure("1", code, `transition/${replay.failure.code}`, replay.failure.message, hasNonce);
    }
    // ---- 2. PENDING root = the new one --------------------------------------------------------
    pendingRoot = replay.value.descriptor;
    pendingRootHash = replay.value.rootHash;
    pendingRootGeneration = replay.value.rootGeneration;
  }

  if (pendingRoot === null || pendingRootHash === null) {
    // Only reachable for CREATE_ACCOUNT without a GENESIS transition; 0c guarantees the rest.
    return failure("1", "INVALID_TRANSITION", "transition/absent", "this account has no root and the bundle installs none", hasNonce);
  }

  // ---- 3. registry (if any) -------------------------------------------------------------------
  let pendingRegistry: Registry | null = state.registry?.registry ?? null;
  let pendingRegistryHash: Uint8Array | null = state.registry?.registryHash ?? null;

  if (bundle.registry !== undefined) {
    // §35.1.1 step 3: signed by the Account Signing Key of the **pending** root, and carrying that
    // root's generation. One-entry maps, not a history: §36.2 binds to the pending root only.
    const replay = await verifyRegistryChain([bundle.registry], {
      accountId: state.accountId,
      accountSigningKeys: new Map([[pendingRootGeneration, pendingRoot.account_signing_public_key]]),
      currentRootGeneration: pendingRootGeneration,
      ...(state.registry === null ? {} : { from: state.registry }),
    });
    if (!replay.ok) {
      const code: BundleFailureCode = replay.failure.code === "BAD_SIGNATURE" ? "INVALID_SIGNATURE" : "INVALID_REGISTRY";
      return failure("3", code, `registry/${replay.failure.code}`, replay.failure.message, hasNonce);
    }
    // ---- 4. PENDING registry = the new one ----------------------------------------------------
    pendingRegistry = replay.value.registry;
    pendingRegistryHash = replay.value.registryHash;
  }

  if (pendingRegistry === null || pendingRegistryHash === null) {
    return failure("3", "INVALID_REGISTRY", "registry/absent", "this account has no Recipient Registry and the bundle installs none", hasNonce);
  }

  // ---- 5. profile and config ------------------------------------------------------------------
  const step5 = check5(bundle, state, hasNonce);
  if (step5 !== null) return step5;
  // "config_version = vigente + 1" applies to the bundles that *install* a config. The four
  // deletion types and `CREATE_VAULT` carry none (their row is **—**), so the version in force
  // does not move: a step 8 that bumped it anyway would leave the account claiming a
  // `config_version` no stored config has, which is exactly what §26 reads as a rolled-back config
  // — and would make the next bundle's `expected` CAS fail for every correct client.
  const configVersion = rules.config === null ? state.configVersion : state.configVersion + 1;

  // ---- 6. filter, then §36.2 over what survives ------------------------------------------------
  const deletedVaultIds = state.vaults.filter((v) => v.state === "DELETED").map((v) => v.vaultId);
  const deleted = new Set(deletedVaultIds.map(idKey));
  const allEpochs = bundle.epochs ?? [];
  const epochs = allEpochs.filter((e) => !deleted.has(idKey(e.descriptor.vault_id)));
  const discardedEpochs = allEpochs.filter((e) => deleted.has(idKey(e.descriptor.vault_id)));
  const allCoverage = bundle.coverage_envelopes ?? [];
  const coverageEnvelopes = allCoverage.filter((e) => !deleted.has(idKey(e.vault_id)));
  const discardedCoverage = allCoverage.filter((e) => deleted.has(idKey(e.vault_id)));

  const step6 = await check6(epochs, state, {
    generation: pendingRootGeneration,
    cryptoVersion: pendingRoot.crypto_version,
    signing: pendingRoot.account_signing_public_key,
    hash: pendingRootHash,
    registryVersion: pendingRegistry.registry_version,
    registryHash: pendingRegistryHash,
  }, hasNonce);
  if (step6 !== null) return step6;

  // ---- 7. rules of the operation ---------------------------------------------------------------
  const step7 = await check7(bundle, rules, operationType, state, {
    pendingRoot,
    pendingRegistry,
    epochs,
    coverageEnvelopes,
    configVersion,
    pendingRootGeneration,
    deletedVaultIds,
  }, hasNonce);
  if (step7 !== null) return step7;

  return {
    ok: true,
    value: {
      kind: "ACCEPT",
      accepted: {
        operationType,
        rules,
        pendingRoot,
        pendingRootHash,
        pendingRootGeneration,
        pendingRegistry,
        pendingRegistryHash,
        pendingRegistryVersion: pendingRegistry.registry_version,
        configVersion,
        epochs,
        discardedEpochs,
        coverageEnvelopes,
        discardedCoverage,
        consumedNonce: nonce ?? null,
        escrowChange: escrowChangeOf(bundle, state),
        recoveryChange: recoveryChangeOf(bundle, rules, operationType, state),
      },
    },
  };
}

// --- Step 0 ------------------------------------------------------------------------------------

function checkAuthorization(
  bundle: SecurityBundle,
  rules: OperationRules,
  operationType: OperationType,
  state: BundleState,
  hasNonce: boolean,
): Outcome<never, BundleFailure> | null {
  const auth = state.authorization;
  if (!auth.authenticated) {
    return failure("0", "WRITE_CAPABILITY_REQUIRED", "auth/session", "no authenticated session", hasNonce);
  }
  // §11.3: CREATE_ACCOUNT is the single exception — login alone, on an account with no root yet.
  if (rules.scopes.length === 0) return null;

  const token = auth.token;
  if (token === undefined) {
    return failure("0", "WRITE_CAPABILITY_REQUIRED", "auth/token", `${operationType} needs a live Write Capability Token`, hasNonce);
  }
  if (token.revokedReason === "RECIPIENT_REVOKED") {
    return failure("0", "RECIPIENT_REVOKED", "auth/revoked", "the token's recipient is revoked", hasNonce);
  }
  if (token.revokedReason !== undefined) {
    return failure("0", "WRITE_CAPABILITY_REQUIRED", "auth/token", `the token is no longer live (${token.revokedReason})`, hasNonce);
  }
  // §35.15: the scope of a recovery record follows from `operation_type` and `recovery.kind`, both in
  // the bundle. Without a record the scope cannot be deduced: INVALID_BUNDLE here, still unstored.
  let scopes = rules.scopes;
  if (isRecoveryRecordOperation(operationType)) {
    const kind = bundle.recovery?.kind;
    if (kind === undefined) {
      return failure("0", "INVALID_BUNDLE", "auth/recovery-absent", `${operationType} must carry a recovery record`, hasNonce);
    }
    scopes = RECOVERY_RECORD_SIGNERS[operationType][kind].scopes;
  }
  if (!scopes.some((scope) => token.scopes.includes(scope))) {
    return failure("0", "SCOPE_REQUIRED", "auth/scope", `${operationType} requires one of ${scopes.join(", ")}`, hasNonce);
  }
  return null;
}

// --- Step 0c -----------------------------------------------------------------------------------

function check0c(
  bundle: SecurityBundle,
  rules: OperationRules,
  operationType: OperationType,
  state: BundleState,
  hasNonce: boolean,
): Outcome<never, BundleFailure> | null {
  const owned = new Map(state.vaults.map((v) => [idKey(v.vaultId), v]));
  const retired = new Set((state.retiredVaultIds ?? []).map(idKey));

  // The account's own root state first: CREATE_ACCOUNT needs none, everything else needs one.
  if (operationType === "CREATE_ACCOUNT") {
    if (state.root !== null) {
      return failure("0c", "INVALID_STATE", "account/has-root", "this account already has a root", hasNonce);
    }
    // §44.5: an escrow row only exists next to the root that justifies it; never adopt a leftover one.
    if (state.escrow !== null) {
      return failure("0c", "INVALID_STATE", "account/has-escrow", "this account already has an account_escrows row", hasNonce);
    }
    // §35.2 (ADR-023): §37 and the §35.15 veto need a proven address, whatever the sign-in method.
    if (state.authorization.emailConfirmed !== true) {
      return failure("0c", "EMAIL_UNCONFIRMED", "account/email-unconfirmed", "the login's email is not confirmed yet", hasNonce);
    }
  } else if (state.root === null) {
    return failure("0c", "INVALID_STATE", "account/no-root", "this account has no root yet; only CREATE_ACCOUNT is accepted", hasNonce);
  }

  // §11.4 / §35.12: which operations a deleting account still accepts.
  if (state.accountState === "DELETING" || state.accountState === "ORPHANED") {
    return failure("0c", "INVALID_STATE", "account/deleting", `no SecurityBundle is accepted while the account is ${state.accountState}`, hasNonce);
  }
  if (state.accountState === "DELETING_SCHEDULED" && !rules.allowedWhileAccountDeleting) {
    return failure("0c", "INVALID_STATE", "account/delete-scheduled", `${operationType} is not accepted while the account deletion is scheduled`, hasNonce);
  }

  // §3.6: the protection mode, read here from `account_escrows` (Managed iff the row exists).
  const managed = state.escrow !== null;
  if (rules.requiredMode !== null && managed !== (rules.requiredMode === "MANAGED")) {
    return failure("0c", "INVALID_STATE", "mode/wrong-mode", `${operationType} requires a ${rules.requiredMode} account`, hasNonce);
  }
  if (managed && rules.inManaged === "NOT_APPLICABLE") {
    return failure("0c", "NOT_APPLICABLE_IN_MANAGED", "mode/not-applicable", `${operationType} does not exist in a Managed account (§35.6, §35.9)`, hasNonce);
  }
  // §35.12 step 2: evaluated with the mode, before anything that could consume the nonce.
  if (managed && rules.inManaged === "REAUTH") {
    const age = state.authorization.primaryAuthAgeSeconds;
    if (age === undefined || age > REAUTH_WINDOW_SECONDS) {
      return failure("0c", "REAUTH_REQUIRED", "auth/reauth", `${operationType} in a Managed account needs a re-authentication within ${REAUTH_WINDOW_SECONDS} s`, hasNonce);
    }
  }

  // §35.15: delay and veto, in an account without escrow, after the mode check. A Managed
  // RECOVERY_RESET is exempt; the other two delayed operations cannot reach here in Managed.
  if (!managed && rules.delayed) {
    const gate = checkMaturedRequest(operationType as RecoveryRequestKind, state, hasNonce);
    if (gate !== null) return gate;
  }

  // Vault operations: the target `vault_id` must belong to this account, or — for the two that
  // create one — must exist nowhere, not even in `retired_ids`.
  const creating = new Set<string>();
  if (rules.epochs === "ONE_NEW_VAULT") {
    for (const epoch of bundle.epochs ?? []) {
      const key = idKey(epoch.descriptor.vault_id);
      creating.add(key);
      if (owned.has(key) || retired.has(key)) {
        return failure("0c", "INVALID_STATE", "vault/not-free", "the vault this bundle creates already exists", hasNonce);
      }
    }
  }
  if (rules.deletion === "VAULT") {
    const target = bundle.deletion?.vault_id;
    // A missing `vault_id` does not belong to this account either; §35.11 never distinguishes the
    // cases, so the same INVALID_STATE answers both (and consumes the nonce).
    if (target === undefined || !owned.has(idKey(target))) {
      return failure("0c", "INVALID_STATE", "vault/not-mine", "the deletion target is not a vault of this account", hasNonce);
    }
  }

  // Every `epochs` / `coverage_envelopes` entry: own vault (any state), or the one being created.
  // Evaluated here, before §36.2, so no later retryable code becomes an existence oracle.
  for (const epoch of bundle.epochs ?? []) {
    const key = idKey(epoch.descriptor.vault_id);
    if (!owned.has(key) && !creating.has(key)) {
      return failure("0c", "INVALID_BUNDLE", "epochs/foreign-vault", "an epoch names a vault that is not this account's", hasNonce);
    }
  }
  for (const envelope of bundle.coverage_envelopes ?? []) {
    const key = idKey(envelope.vault_id);
    if (!owned.has(key) && !creating.has(key)) {
      return failure("0c", "INVALID_BUNDLE", "coverage/foreign-vault", "a coverage envelope names a vault that is not this account's", hasNonce);
    }
  }
  return null;
}

// --- Step 5 ------------------------------------------------------------------------------------

function check5(
  bundle: SecurityBundle,
  state: BundleState,
  hasNonce: boolean,
): Outcome<never, BundleFailure> | null {
  const next = state.configVersion + 1;
  if (bundle.profile !== undefined && bundle.profile.config_version !== next) {
    return failure("5", "INVALID_BUNDLE", "config/version", `config_version must be ${next}, got ${bundle.profile.config_version}`, hasNonce);
  }
  if (bundle.config_version !== undefined && bundle.config_version !== next) {
    return failure("5", "INVALID_BUNDLE", "config/version", `config_version must be ${next}, got ${bundle.config_version}`, hasNonce);
  }
  // §35.1.1, right below the table: "El Worker rechaza cualquier bundle que cambie raíz o registry
  // sin config". Derived from the row, so it cannot disagree with it.
  const changesRootOrRegistry = bundle.root_transition !== undefined || bundle.registry !== undefined;
  const carriesConfig = bundle.profile !== undefined || bundle.config_blob !== undefined;
  if (changesRootOrRegistry && !carriesConfig) {
    return failure("5", "INVALID_BUNDLE", "config/required", "a bundle that changes the root or the registry must carry a config", hasNonce);
  }
  return null;
}

// --- Step 6 ------------------------------------------------------------------------------------

interface Pending {
  readonly generation: number;
  readonly cryptoVersion: number;
  readonly signing: Uint8Array;
  readonly hash: Uint8Array;
  readonly registryVersion: number;
  readonly registryHash: Uint8Array;
}

/**
 * §36.2 as a per-vault `verifyEpochChain` against the **pending** root and registry, plus the
 * `envelope_set_hash` binding that verifier deliberately leaves to its caller (it is a hash over
 * the envelopes, which a chain replay does not have).
 */
async function check6(
  epochs: readonly BundleEpoch[],
  state: BundleState,
  pending: Pending,
  hasNonce: boolean,
): Promise<Outcome<never, BundleFailure> | null> {
  const byVault = new Map(state.vaults.map((v) => [idKey(v.vaultId), v]));
  const accountSigningKeys = new Map([[pending.generation, pending.signing]]);
  const rootHashes = new Map([[pending.generation, pending.hash]]);
  const rootCryptoVersions = new Map([[pending.generation, pending.cryptoVersion]]);
  const registryHashes = new Map([[pending.registryVersion, pending.registryHash]]);

  for (const epoch of epochs) {
    const vaultId = epoch.descriptor.vault_id;
    const from = byVault.get(idKey(vaultId))?.currentEpoch ?? null;
    const replay = await verifyEpochChain([epoch.descriptor], {
      vaultId,
      accountSigningKeys,
      rootHashes,
      rootCryptoVersions,
      registryHashes,
      ...(from === null ? {} : { from }),
    });
    if (!replay.ok) {
      return failure("6", epochFailureCode(replay.failure.code), `epoch/${replay.failure.code}`, replay.failure.message, hasNonce);
    }
    const setHash = await envelopeSetHash(vaultId, epoch.descriptor.epoch_id, epoch.envelopes);
    if (!equalBytes(setHash, epoch.descriptor.envelope_set_hash)) {
      return failure("6", "INVALID_BUNDLE", "epoch/envelope-set-hash", "envelope_set_hash does not cover the envelopes that travelled with the descriptor", hasNonce);
    }
  }
  return null;
}

/**
 * §35.1: a descriptor that links to the wrong predecessor is what a *concurrent* rotation looks
 * like, so all four link failures answer the retryable `EPOCH_STALE`, and only a broken binding or
 * signature is definitive.
 */
function epochFailureCode(code: string): BundleFailureCode {
  switch (code) {
    case "EPOCH_LINK_MISMATCH":
    case "BROKEN_LINK":
    case "NOT_INITIAL":
    case "UNEXPECTED_FIRST_EPOCH":
      return "EPOCH_STALE";
    case "BAD_SIGNATURE":
      return "INVALID_SIGNATURE";
    default:
      return "INVALID_BUNDLE";
  }
}

// --- Step 7 ------------------------------------------------------------------------------------

interface Step7Input {
  readonly pendingRoot: RootDescriptor;
  readonly pendingRegistry: Registry;
  readonly epochs: readonly BundleEpoch[];
  readonly coverageEnvelopes: readonly EpochEnvelope[];
  readonly configVersion: number;
  readonly pendingRootGeneration: number;
  readonly deletedVaultIds: readonly Uint8Array[];
}

async function check7(
  bundle: SecurityBundle,
  rules: OperationRules,
  operationType: OperationType,
  state: BundleState,
  input: Step7Input,
  hasNonce: boolean,
): Promise<Outcome<never, BundleFailure> | null> {
  // 7.0 applicability. First inside step 7 on purpose: a definitively malformed bundle must not
  // receive the retryable VAULT_SET_STALE of rule 1 below.
  const applicability = checkApplicability(bundle, rules, operationType, hasNonce);
  if (applicability !== null) return applicability;

  // 7.0b escrow and the profile's shape per mode (§3.6, §23.4 key 14).
  const escrow = checkEscrow(bundle, rules, operationType, state, input.pendingRoot, hasNonce);
  if (escrow !== null) return escrow;

  // 7.1 REVOKE_CLIENT / RECOVERY_*: a new epoch for every live vault, or VAULT_SET_STALE.
  const live = state.vaults.filter((v) => v.state === "ACTIVE" || v.state === "DELETING_SCHEDULED");
  if (rules.epochs === "EVERY_LIVE_VAULT") {
    const covered = new Set(input.epochs.map((e) => idKey(e.descriptor.vault_id)));
    const missing = live.filter((v) => !covered.has(idKey(v.vaultId)));
    if (missing.length > 0) {
      return failure("7", "VAULT_SET_STALE", "epochs/every-live-vault", `${missing.length} live vault(s) have no new epoch in this bundle`, hasNonce, {
        vaultIds: live.map((v) => v.vaultId),
      });
    }
  }

  // 7.2 shape of the registry.
  const shape = checkRegistryShape(rules, operationType, state, input.pendingRegistry, hasNonce);
  if (shape !== null) return shape;

  // 7.3 envelopes of each new epoch: exactly ACCOUNT, RECOVERY and the ACTIVE recipients.
  const expectedRecipients = await epochRecipients(input.pendingRoot, input.pendingRegistry);
  const expectedIds = new Map(expectedRecipients.map((r) => [idKey(r.recipientId), r.type]));
  for (const epoch of input.epochs) {
    const seen = new Set<string>();
    for (const envelope of epoch.envelopes) {
      const key = idKey(envelope.recipient_id);
      const type = expectedIds.get(key);
      if (type === undefined) {
        return failure("7", "INVALID_BUNDLE", "epoch/envelope-extra", "an epoch carries an envelope for a recipient that is not ACCOUNT, RECOVERY or ACTIVE", hasNonce);
      }
      if (type !== envelope.recipient_type) {
        return failure("7", "INVALID_BUNDLE", "epoch/envelope-type", "an envelope declares the wrong recipient_type for its recipient_id", hasNonce);
      }
      if (
        !equalBytes(envelope.vault_id, epoch.descriptor.vault_id) ||
        !equalBytes(envelope.epoch_id, epoch.descriptor.epoch_id)
      ) {
        return failure("7", "INVALID_BUNDLE", "epoch/envelope-misbound", "an envelope names another vault or epoch than its descriptor", hasNonce);
      }
      if (seen.has(key)) {
        return failure("7", "INVALID_BUNDLE", "epoch/envelope-duplicate", "two envelopes of one epoch address the same recipient", hasNonce);
      }
      seen.add(key);
    }
    if (seen.size !== expectedIds.size) {
      return failure("7", "INVALID_BUNDLE", "epoch/envelope-missing", "an epoch is missing an envelope for a recipient that must receive one", hasNonce);
    }
  }

  // 7.4 coverage_envelopes against the RequiredEpochSet computed BEFORE applying the bundle.
  if (rules.coverage !== null) {
    const added = await addedReadingKeys(rules, state, input.pendingRoot, input.pendingRegistry);
    if (added === null) {
      return failure("7", "INVALID_BUNDLE", "coverage/no-added-key", "the operation must activate exactly one new reading key", hasNonce);
    }
    const required = requiredEpochSet(
      state.vaults.map((v) => ({ vaultId: v.vaultId, state: v.state, epochs: v.epochs })),
    );
    const result = checkCoverage({
      required,
      recipients: added,
      envelopes: input.coverageEnvelopes,
      deletedVaultIds: input.deletedVaultIds,
    });
    if (!result.ok) {
      return failure("7", "COVERAGE_STALE", `coverage/${result.failure.gaps[0]?.code ?? "MISMATCH"}`, result.failure.message, hasNonce, { required });
    }
  }

  // 7.5 exactly one new epoch per affected vault; CREATE_ACCOUNT exactly one vault.
  const vaultIds = input.epochs.map((e) => idKey(e.descriptor.vault_id));
  if (new Set(vaultIds).size !== vaultIds.length) {
    return failure("7", "INVALID_BUNDLE", "epochs/duplicate-vault", "two epochs in one bundle rotate the same vault", hasNonce);
  }
  if (rules.epochs === "ONE_NEW_VAULT" && input.epochs.length !== 1) {
    return failure("7", "INVALID_BUNDLE", "epochs/exactly-one", `${operationType} must carry exactly one epoch, got ${input.epochs.length}`, hasNonce);
  }
  if (rules.epochs === "ONE_NEW_VAULT" && state.vaultLimit !== undefined && live.length >= state.vaultLimit) {
    return failure("7", "PLAN_LIMIT_EXCEEDED", "epochs/vault-limit", `the plan allows ${state.vaultLimit} vault(s)`, hasNonce);
  }

  // 7.6 `expected` is always present — a codec-level `req` field (§23.4), nothing to check here.

  // 7.7 the profile: kdf_salt of 16 bytes (codec) and Argon2 parameters within the limits in force.
  // A Managed profile has neither KDF field (7.0b), so the ADR-004 limits apply to a Private one only.
  if (bundle.profile !== undefined) {
    const argon2Params = bundle.profile.argon2_params;
    if (argon2Params !== undefined) {
      const params = checkKdfParams(toArgon2Params(argon2Params));
      if (!params.ok) {
        return failure("7", "INVALID_BUNDLE", `profile/${params.failure.code}`, params.failure.message, hasNonce);
      }
      if (argon2Params.version !== currentArgon2Version()) {
        return failure("7", "INVALID_BUNDLE", "profile/stale-version", "the profile must use the ADR-004 version in force", hasNonce);
      }
    }
    if (!equalBytes(bundle.profile.account_id, state.accountId)) {
      return failure("7", "INVALID_BUNDLE", "profile/account", "the profile names another account", hasNonce);
    }
  }

  // 7.8 the root's four public keys must be distinct from one another.
  if (bundle.root_descriptor !== undefined && !distinctRootKeys(bundle.root_descriptor)) {
    return failure("7", "INVALID_BUNDLE", "root/duplicate-keys", "the four root public keys must differ from one another", hasNonce);
  }

  // 7.9 profile_signature: mandatory iff CHANGE_SECRETS or SWITCH_TO_MANAGED (presence is rule 7.0's).
  if (rules.profileSignature) {
    const signature = bundle.profile_signature;
    const profile = bundle.profile;
    if (signature === undefined || profile === undefined) {
      return failure("7", "INVALID_BUNDLE", "profile-signature/absent", `${operationType} must carry profile and profile_signature`, hasNonce);
    }
    const ok = await verifyProfileSignature(input.pendingRoot, state, profile, signature);
    if (!ok) {
      return failure("7", "INVALID_SIGNATURE", "profile-signature/invalid", "profile_signature does not verify under the pending Account Signing Key", hasNonce);
    }
  }

  // 7.10 the deletion block, last, in the order §35.1.1 fixes: state, then signature, then nonce.
  if (rules.deletion !== null) {
    return checkDeletion(bundle, rules, operationType, state, input, hasNonce);
  }
  // 7.11 the recovery block (§35.15), also last: root, state, signature, request_id.
  if (rules.recovery) {
    return checkRecoveryRecord(bundle, operationType, state, hasNonce);
  }
  return null;
}

function checkApplicability(
  bundle: SecurityBundle,
  rules: OperationRules,
  operationType: OperationType,
  hasNonce: boolean,
): Outcome<never, BundleFailure> | null {
  const present = (name: string): boolean => (bundle as unknown as Record<string, unknown>)[name] !== undefined;
  for (const name of forbiddenFields(rules)) {
    if (present(name)) {
      return failure("7", "INVALID_BUNDLE", `applicability/forbidden:${name}`, `${operationType} must not carry ${name}`, hasNonce);
    }
  }
  for (const name of requiredFields(rules)) {
    if (!present(name)) {
      return failure("7", "INVALID_BUNDLE", `applicability/missing:${name}`, `${operationType} must carry ${name}`, hasNonce);
    }
  }
  // The transition column names a type, not merely "some transition".
  if (rules.transition !== null && bundle.root_transition?.transition_type !== rules.transition) {
    return failure("7", "INVALID_BUNDLE", "applicability/transition-type", `${operationType} carries a ${rules.transition} transition`, hasNonce);
  }
  // §23.4: `deletion.vault_id` belongs to the vault deletions only.
  if (rules.deletion === "ACCOUNT" && bundle.deletion?.vault_id !== undefined) {
    return failure("7", "INVALID_BUNDLE", "applicability/deletion-vault-id", "an account deletion names no vault", hasNonce);
  }
  return null;
}

function checkRegistryShape(
  rules: OperationRules,
  operationType: OperationType,
  state: BundleState,
  pending: Registry,
  hasNonce: boolean,
): Outcome<never, BundleFailure> | null {
  if (rules.registry === null) return null;
  const before = state.registry?.registry.recipients ?? [];
  const beforeIds = new Set(before.map((r) => idKey(r.recipient_id)));
  const added = pending.recipients.filter((r) => !beforeIds.has(idKey(r.recipient_id)));
  const newlyRevoked = pending.recipients.filter(
    (r) => r.status === "REVOKED" && before.some((b) => idKey(b.recipient_id) === idKey(r.recipient_id) && b.status === "ACTIVE"),
  );
  const stillActive = activeRecipients(pending);

  switch (rules.registry) {
    case "INITIAL":
      if (pending.registry_version !== 1 || pending.previous_registry_hash !== null || stillActive.length !== 1 || pending.recipients.length !== 1) {
        return failure("7", "INVALID_REGISTRY", "registry/initial", "CREATE_ACCOUNT needs registry version 1 with exactly one ACTIVE recipient", hasNonce);
      }
      return null;
    case "ONE_ADDED":
      if (added.length !== 1 || newlyRevoked.length !== 0) {
        return failure("7", "INVALID_REGISTRY", "registry/one-added", "ENROLL_CLIENT adds exactly one recipient and revokes none", hasNonce);
      }
      return checkPluginLimit(state, stillActive, hasNonce);
    case "SOME_REVOKED":
      if (newlyRevoked.length === 0 || added.length !== 0) {
        return failure("7", "INVALID_REGISTRY", "registry/some-revoked", "REVOKE_CLIENT revokes at least one recipient and adds none", hasNonce);
      }
      return null;
    case "NONE_ACTIVE":
      if (stillActive.length !== 0 || added.length !== 0) {
        return failure("7", "INVALID_REGISTRY", "registry/none-active", "RECOVERY_RESET leaves no recipient ACTIVE and adds none", hasNonce);
      }
      return null;
    case "UNCHANGED":
      if (added.length !== 0 || newlyRevoked.length !== 0 || pending.recipients.length !== before.length) {
        return failure("7", "INVALID_REGISTRY", "registry/unchanged", `${operationType} keeps the recipient list identical`, hasNonce);
      }
      return null;
  }
}

function checkPluginLimit(
  state: BundleState,
  active: readonly RegistryRecipient[],
  hasNonce: boolean,
): Outcome<never, BundleFailure> | null {
  const limit = state.pluginLimit;
  if (limit === undefined) return null;
  const plugins = active.filter((r) => r.type === "PLUGIN_INSTALLATION").length;
  if (plugins > limit) {
    return failure("7", "PLAN_LIMIT_EXCEEDED", "registry/plugin-limit", `the plan allows ${limit} plugin installation(s)`, hasNonce);
  }
  return null;
}

/**
 * §35.1.1's "Cobertura (clave lectora añadida)" column, resolved against the pending structures:
 * one key, or the two of SWITCH_TO_PRIVATE ("nuevas claves ACCOUNT y RECOVERY").
 */
async function addedReadingKeys(
  rules: OperationRules,
  state: BundleState,
  pendingRoot: RootDescriptor,
  pendingRegistry: Registry,
): Promise<readonly RecipientIdentity[] | null> {
  const account = async (): Promise<RecipientIdentity> => ({
    recipientId: await rootRecipientId(pendingRoot.account_encryption_public_key),
    type: "ACCOUNT",
  });
  const recovery = async (): Promise<RecipientIdentity> => ({
    recipientId: await rootRecipientId(pendingRoot.recovery_encryption_public_key),
    type: "RECOVERY",
  });
  switch (rules.coverage) {
    case "ADDED_RECIPIENT": {
      const beforeIds = new Set((state.registry?.registry.recipients ?? []).map((r) => idKey(r.recipient_id)));
      const added = pendingRegistry.recipients.filter((r) => !beforeIds.has(idKey(r.recipient_id)));
      const one = added[0];
      if (added.length !== 1 || one === undefined) return null;
      return [{ recipientId: one.recipient_id, type: one.type }];
    }
    case "NEW_ACCOUNT_KEY":
      return [await account()];
    case "NEW_RECOVERY_KEY":
      return [await recovery()];
    case "NEW_ACCOUNT_AND_RECOVERY_KEYS":
      return [await account(), await recovery()];
    case null:
      return null;
  }
}

/**
 * §3.6: whether the account is Managed once this bundle is applied. A transition decides when it
 * sets the mode (GENESIS by its version, the two switches by their type); otherwise the mode read in
 * step 0c stands.
 */
function managedAfter(bundle: SecurityBundle, state: BundleState, pendingRoot: RootDescriptor): boolean {
  const before = state.escrow === null ? "PRIVATE" : "MANAGED";
  const type = bundle.root_transition?.transition_type;
  return (type === undefined ? before : modeAfter(before, type, pendingRoot.crypto_version)) === "MANAGED";
}

/**
 * §35.1.1 step 7, first bullet: `escrow` present iff the row allows it and the account ends Managed,
 * with exactly the slots of key 14, each well formed; and the profile, when there is one, carries
 * `kdf_salt` and `argon2_params` iff the account ends without escrow.
 */
function checkEscrow(
  bundle: SecurityBundle,
  rules: OperationRules,
  operationType: OperationType,
  state: BundleState,
  pendingRoot: RootDescriptor,
  hasNonce: boolean,
): Outcome<never, BundleFailure> | null {
  const managed = managedAfter(bundle, state, pendingRoot);
  const expected = rules.escrow !== null && (rules.escrow.when === "ALWAYS" || managed) ? rules.escrow : null;
  const escrow = bundle.escrow;
  if ((expected === null) !== (escrow === undefined)) {
    return failure("7", "INVALID_BUNDLE", "escrow/presence", `${operationType} ${expected === null ? "must not" : "must"} carry escrow here`, hasNonce);
  }
  if (expected !== null && escrow !== undefined) {
    const { unlock, recovery } = escrow;
    const wantRecovery = expected.slots === "UNLOCK_AND_RECOVERY";
    const unlockOk = unlock !== undefined && unlock.slot === "UNLOCK" && unlock.payload_blob === undefined;
    const recoveryOk =
      recovery === undefined
        ? !wantRecovery
        : wantRecovery && recovery.slot === "RECOVERY" && recovery.payload_blob !== undefined;
    if (!unlockOk || !recoveryOk) {
      const slots = wantRecovery ? "the UNLOCK and RECOVERY slots" : "only the UNLOCK slot";
      return failure("7", "INVALID_BUNDLE", "escrow/slots", `${operationType} carries ${slots}, each well formed`, hasNonce);
    }
  }
  const profile = bundle.profile;
  if (profile !== undefined) {
    const hasKdf = profile.kdf_salt !== undefined || profile.argon2_params !== undefined;
    const fullKdf = profile.kdf_salt !== undefined && profile.argon2_params !== undefined;
    if (managed && hasKdf) {
      return failure("7", "INVALID_BUNDLE", "profile/kdf-present", "a Managed profile has no kdf_salt and no argon2_params (§23.4)", hasNonce);
    }
    if (!managed && !fullKdf) {
      return failure("7", "INVALID_BUNDLE", "profile/kdf-absent", "a Private profile carries kdf_salt and argon2_params (§23.4)", hasNonce);
    }
  }
  return null;
}

function escrowChangeOf(bundle: SecurityBundle, state: BundleState): EscrowChange | null {
  if (bundle.operation_type === "SWITCH_TO_PRIVATE") return { kind: "DELETE" };
  if (bundle.escrow === undefined) return null;
  return state.escrow === null ? { kind: "CREATE", escrow: bundle.escrow } : { kind: "REPLACE", escrow: bundle.escrow };
}

async function checkDeletion(
  bundle: SecurityBundle,
  rules: OperationRules,
  operationType: OperationType,
  state: BundleState,
  input: Step7Input,
  hasNonce: boolean,
): Promise<Outcome<never, BundleFailure> | null> {
    const deletion = bundle.deletion;
    const pre = rules.precondition;
    if (deletion === undefined || pre === null) {
      return failure("7", "INVALID_BUNDLE", "deletion/absent", `${operationType} must carry a deletion block`, hasNonce);
    }
    // (a) the state precondition of §35.12's table.
    if (pre.subject === "VAULT") {
      const target = state.vaults.find((v) => deletion.vault_id !== undefined && idKey(v.vaultId) === idKey(deletion.vault_id));
      if (target === undefined || target.state !== pre.state) {
        return failure("7", "INVALID_STATE", "deletion/precondition", `${operationType} requires the vault to be ${pre.state}`, hasNonce);
      }
    } else if (state.accountState !== pre.state) {
      return failure("7", "INVALID_STATE", "deletion/precondition", `${operationType} requires the account to be ${pre.state}`, hasNonce);
    }

    // (b) the signature, under the Account Signing Key of the PENDING root — or, for a cancel sent
    // with a RECOVERY_CONTROL token, the Recovery Authority of the root in force (role 3, ADR-022).
    // The token's scope picks the key, never the bundle; these operations install no root, so the
    // pending root is the one in force.
    const kitSigned = state.authorization.token?.scopes.includes("RECOVERY_CONTROL") === true;
    const key = await importOrNull(
      kitSigned ? input.pendingRoot.recovery_authority_public_key : input.pendingRoot.account_signing_public_key,
    );
    const ctx =
      rules.deletion === "VAULT"
        ? deleteVaultContext(operationType, state.accountId, deletion.vault_id as Uint8Array, input.pendingRootGeneration, deletion.nonce)
        : deleteAccountContext(operationType, state.accountId, input.pendingRootGeneration, deletion.nonce);
    if (key === null || !(await verifyContext(key, ctx, deletion.signature))) {
      const signer = kitSigned ? "the Recovery Authority in force" : "the pending Account Signing Key";
      return failure("7", "INVALID_SIGNATURE", "deletion/signature", `deletion.signature does not verify under ${signer}`, hasNonce);
    }

    // (c) the nonce, not consumed in this account.
    if ((state.consumedNonces ?? []).some((n) => equalBytes(n, deletion.nonce))) {
      return failure("7", "NONCE_REUSED", "deletion/nonce", "this deletion nonce was already consumed", hasNonce);
    }
    return null;
}

// --- §35.15: delay and veto ---------------------------------------------------------------------

/**
 * Step 0c's gate: a delayed operation in a Private account needs a live, matured request of the
 * same `kind` at the root generation in force. Neither failure is stored or consumes anything.
 */
function checkMaturedRequest(
  kind: RecoveryRequestKind,
  state: BundleState,
  hasNonce: boolean,
): Outcome<never, BundleFailure> | null {
  const generation = state.root?.rootGeneration ?? 0;
  const candidates = (state.recoveryRequests ?? []).filter(
    (r) => r.kind === kind && r.rootGeneration === generation && isLive(r, state.now),
  );
  if (candidates.some((r) => isMature(r, state.now))) return null;
  const pending = candidates[0];
  if (pending !== undefined) {
    return failure("0c", "RECOVERY_NOT_MATURE", "recovery/not-mature", `the ${kind} request matures at ${pending.maturesAt}`, hasNonce, {
      maturesAt: pending.maturesAt,
    });
  }
  return failure("0c", "RECOVERY_REQUEST_REQUIRED", "recovery/required", `${kind} needs a matured request of its kind in a Private account (§35.15)`, hasNonce);
}

/** The one matured request a delayed operation consumes. Only called after step 0c accepted it. */
function maturedRequest(kind: RecoveryRequestKind, state: BundleState): StoredRecoveryRequest | undefined {
  const generation = state.root?.rootGeneration ?? 0;
  return (state.recoveryRequests ?? []).find(
    (r) => r.kind === kind && r.rootGeneration === generation && isMature(r, state.now),
  );
}

/**
 * §35.1.1 step 7, the `recovery` block, in its fixed order: (a) the record names the root in force,
 * (b) the state precondition, (c) the signature of the role §35.15 assigns, (d) a fresh request_id.
 */
async function checkRecoveryRecord(
  bundle: SecurityBundle,
  operationType: OperationType,
  state: BundleState,
  hasNonce: boolean,
): Promise<Outcome<never, BundleFailure> | null> {
  const record = bundle.recovery;
  const root = state.root;
  if (record === undefined || root === null || !isRecoveryRecordOperation(operationType)) {
    return failure("7", "INVALID_BUNDLE", "recovery/absent", `${operationType} must carry a recovery block`, hasNonce);
  }
  // (a) the root in force; the generation equals `expected`, already compared in 0d.
  if (record.root_generation !== root.rootGeneration || !equalBytes(record.root_hash, root.rootHash)) {
    return failure("7", "INVALID_BUNDLE", "recovery/root", "the recovery record does not name the root in force", hasNonce);
  }
  // (b) the state precondition.
  const live = (state.recoveryRequests ?? []).filter((r) => isLive(r, state.now));
  if (operationType === "RECOVERY_REQUEST") {
    const existing = live[0];
    if (existing !== undefined) {
      return failure("7", "RECOVERY_REQUEST_EXISTS", "recovery/exists", "this account already has a live recovery request", hasNonce, {
        liveRequest: { kind: existing.kind, maturesAt: existing.maturesAt, expiresAt: existing.expiresAt },
      });
    }
    if (state.accountState === "DELETING_SCHEDULED" && record.kind !== "RECOVERY_RESET") {
      return failure("7", "INVALID_STATE", "recovery/delete-scheduled", "only a RECOVERY_RESET can be requested while the account deletion is scheduled", hasNonce);
    }
  } else if (!live.some((r) => equalBytes(r.requestId, record.request_id) && r.kind === record.kind)) {
    // "inexistente" and "ya terminada" are never told apart.
    return failure("7", "INVALID_STATE", "recovery/not-live", `${operationType} names no live request of this account`, hasNonce);
  }
  // (c) the signature, with the key of the role (operation_type, kind) fixes, from the root in force.
  const role = RECOVERY_RECORD_SIGNERS[operationType][record.kind].role;
  const key = await importOrNull(role === 1 ? root.descriptor.account_signing_public_key : root.descriptor.recovery_authority_public_key);
  const ctx = recoveryRequestContext(operationType, state.accountId, record.request_id, record.kind, record.root_generation, record.root_hash);
  if (key === null || !(await verifyContext(key, ctx, record.signature))) {
    return failure("7", "INVALID_SIGNATURE", "recovery/signature", `recovery.signature does not verify under role ${role} of the root in force`, hasNonce);
  }
  // (d) RECOVERY_REQUEST only: a request_id is never reused in this account, whatever its fate.
  if (operationType === "RECOVERY_REQUEST" && (state.recoveryRequests ?? []).some((r) => equalBytes(r.requestId, record.request_id))) {
    return failure("7", "NONCE_REUSED", "recovery/request-id", "this request_id was already used in this account", hasNonce);
  }
  return null;
}

function recoveryChangeOf(
  bundle: SecurityBundle,
  rules: OperationRules,
  operationType: OperationType,
  state: BundleState,
): RecoveryChange | null {
  const record = bundle.recovery;
  if (record !== undefined && isRecoveryRecordOperation(operationType)) {
    if (operationType === "RECOVERY_REQUEST") {
      return {
        kind: "REQUEST",
        requestId: record.request_id,
        requestKind: record.kind,
        rootGeneration: record.root_generation,
        rootHash: record.root_hash,
        signerRole: RECOVERY_RECORD_SIGNERS.RECOVERY_REQUEST[record.kind].role,
        signature: record.signature,
      };
    }
    return { kind: operationType === "RECOVERY_VETO" ? "VETO" : "CANCEL", requestId: record.request_id, signature: record.signature };
  }
  if (rules.delayed && state.escrow === null) {
    const consumed = maturedRequest(operationType as RecoveryRequestKind, state);
    return consumed === undefined ? null : { kind: "CONSUME", requestId: consumed.requestId };
  }
  return null;
}

async function verifyProfileSignature(
  pendingRoot: RootDescriptor,
  state: BundleState,
  profile: AccountSecurityProfile,
  signature: Uint8Array,
): Promise<boolean> {
  const key = await importOrNull(pendingRoot.account_signing_public_key);
  if (key === null) return false;
  // §35.6: the **previous** config_version is what is signed.
  const ctx = profileUpdateContext(state.accountId, state.configVersion, await profileHash(profile));
  return verifyContext(key, ctx, signature);
}

// --- Small shared helpers ----------------------------------------------------------------------

async function importOrNull(spki: Uint8Array): Promise<VerifyingKey | null> {
  try {
    return await importVerifyingKey(spki);
  } catch {
    return null;
  }
}

/**
 * §35.1.1 step 7 asks for "la versión VIGENTE de ADR-004", not merely a version this client knows,
 * so a new profile may never be created at an older one. The version in force is the highest row
 * of `ARGON2_LIMITS`; `checkKdfParams` separately accepts every published version, which is what
 * lets an *existing* account keep unlocking (§24).
 */
export function currentArgon2Version(): number {
  return Math.max(...ARGON2_LIMITS.keys());
}

function distinctRootKeys(root: RootDescriptor): boolean {
  const keys = [
    root.account_encryption_public_key,
    root.account_signing_public_key,
    root.recovery_encryption_public_key,
    root.recovery_authority_public_key,
  ];
  const seen = new Set(keys.map((k) => Array.from(k, (b) => b.toString(16).padStart(2, "0")).join("")));
  return seen.size === keys.length;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}
