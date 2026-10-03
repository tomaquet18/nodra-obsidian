// The two per-operation tables of §35.1.1, as data.
//
// §35.1.1 states its per-operation rules as two markdown tables — "Contenido obligatorio por
// operación" and "Forma del registry" — plus the scope list of step 0 (which §11.3 repeats). Every
// one of those is a lookup keyed by `operation_type`, so they live here as one frozen record and
// `bundle.ts` reads them. There is exactly one copy: no `switch (operation_type)` anywhere, and no
// per-operation validator that could drift from its row.
//
// This table decides *applicability* only — which parts a bundle of each type must carry, must not
// carry, and what shape they must have. It never decides whether a part is **valid**; that is the
// business of `verifyRootChain`, `verifyRegistryChain`, `verifyEpochChain` and `checkCoverage`,
// which `bundle.ts` composes in the order §35.1.1 numbers them.
import type { OPERATION_TYPES, RECOVERY_REQUEST_KINDS } from "@nodra/encoding/records";

export type OperationType = (typeof OPERATION_TYPES)[number];

/** §35.15: the three operations a recovery request can name, which are also its `kind`. */
export type RecoveryRequestKind = (typeof RECOVERY_REQUEST_KINDS)[number];

/** §35.15: the three `SecurityBundle` types that carry a `RecoveryRecord` (key 15) and nothing else. */
export type RecoveryRecordOperation = "RECOVERY_REQUEST" | "RECOVERY_VETO" | "RECOVERY_CANCEL";

/** The Write Capability scopes of §11.3. Only the four names; issuance is the Worker's. */
export type Scope = "VAULT_WRITE" | "TRUSTED_SECURITY" | "ACCOUNT_SECURITY" | "RECOVERY_CONTROL";

/**
 * The "Transición" column. A non-null value is the `transition_type` the bundle MUST carry (with
 * its `root_descriptor`); `null` is the table's **—**: both fields MUST be absent.
 */
export type TransitionRequirement =
  | "GENESIS"
  | "RECOVERY_RESET"
  | "RECOVERY_KIT_REPLACEMENT"
  | "SWITCH_TO_PRIVATE"
  | "SWITCH_TO_MANAGED"
  | null;

/**
 * The "Registry" column crossed with the "Forma del registry" table. `null` is **—**: no `registry`
 * field at all. The five other values are that second table's five rows.
 */
export type RegistryShape =
  /** `CREATE_ACCOUNT`: version 1, `previous_registry_hash` null, exactly one ACTIVE recipient. */
  | "INITIAL"
  /** `ENROLL_CLIENT`: exactly one recipient added, none revoked (plus the §40 plugin limit). */
  | "ONE_ADDED"
  /** `REVOKE_CLIENT`: at least one revoked, none added. */
  | "SOME_REVOKED"
  /** `RECOVERY_RESET`: no recipient left ACTIVE, none added. */
  | "NONE_ACTIVE"
  /**
   * `RECOVERY_KIT_REPLACEMENT` and the two mode switches: the identical list — only version,
   * generation, hash and signature move.
   */
  | "UNCHANGED";

/**
 * The "Perfil y config" column. §23.4 makes the two mutually exclusive: when `profile` (key 5) is
 * present the config travels **only** inside it, and keys 7/8 MUST be absent. So one enum, not two
 * booleans — "perfil y config" is `PROFILE`, a bare "config" is `CONFIG`, and **—** is `null`.
 */
export type ConfigRequirement = "PROFILE" | "CONFIG" | null;

/** The "Epochs" column. `null` is **—**: the `epochs` field MUST be absent. */
export type EpochsRequirement =
  /** `CREATE_ACCOUNT`, `CREATE_VAULT`: exactly one epoch, for a vault that does not exist yet. */
  | "ONE_NEW_VAULT"
  /** `REVOKE_CLIENT`, `RECOVERY_*`: one new epoch per ACTIVE/DELETING_SCHEDULED vault, no more. */
  | "EVERY_LIVE_VAULT";

/**
 * The "Cobertura (clave lectora añadida)" column: which newly activated reading key needs an
 * envelope for every epoch of the `RequiredEpochSet` (§34.2). `null` is **—**: no
 * `coverage_envelopes` field at all, because the operation activates no new reading key.
 */
export type CoverageRequirement =
  /** `ENROLL_CLIENT`: the one recipient the registry step added. */
  | "ADDED_RECIPIENT"
  /** `RECOVERY_RESET`: the ACCOUNT key of the **new** root. */
  | "NEW_ACCOUNT_KEY"
  /** `RECOVERY_KIT_REPLACEMENT`, `SWITCH_TO_MANAGED`: the RECOVERY key of the **new** root. */
  | "NEW_RECOVERY_KEY"
  /** `SWITCH_TO_PRIVATE`: both the ACCOUNT and the RECOVERY key of the **new** root. */
  | "NEW_ACCOUNT_AND_RECOVERY_KEYS";

/**
 * SecurityBundle key 14 (§23.4, §35.1.1 step 7): which escrow slots the bundle replaces, and when.
 * `null` is "never": the `escrow` field MUST be absent. `IF_MANAGED` applies the row only when the
 * account is Managed after the bundle (a version-2 GENESIS, or a RECOVERY_RESET of an account with
 * escrow); otherwise the field MUST be absent too.
 */
export interface EscrowRequirement {
  readonly slots: "UNLOCK_AND_RECOVERY" | "UNLOCK_ONLY";
  readonly when: "ALWAYS" | "IF_MANAGED";
}

/** The `deletion` sub-map of §35.11/§35.12, and which Context signs it. `null` is **—**. */
export type DeletionRequirement = "VAULT" | "ACCOUNT" | null;

/** The state precondition of §35.12's table, re-evaluated in step 7 block (a). */
export type DeletionPrecondition =
  | { readonly subject: "VAULT"; readonly state: "ACTIVE" | "DELETING_SCHEDULED" }
  | { readonly subject: "ACCOUNT"; readonly state: "ACTIVE" | "DELETING_SCHEDULED" };

export interface OperationRules {
  /** Step 0: any one of these scopes authorizes the bundle. Empty means "login alone" (§11.3). */
  readonly scopes: readonly Scope[];
  readonly transition: TransitionRequirement;
  readonly registry: RegistryShape | null;
  readonly config: ConfigRequirement;
  readonly epochs: EpochsRequirement | null;
  readonly coverage: CoverageRequirement | null;
  readonly deletion: DeletionRequirement;
  /** Present iff {@link deletion} is; the §35.12 row this operation re-checks in step 7 (a). */
  readonly precondition: DeletionPrecondition | null;
  /** Step 7: `profile_signature` is mandatory if and only if this is true (§35.6, §35.14). */
  readonly profileSignature: boolean;
  readonly escrow: EscrowRequirement | null;
  /**
   * §35.1.1 step 0c, the protection mode read from `account_escrows`: the mode the account MUST be
   * in before the bundle (INVALID_STATE otherwise), and what a Managed account answers instead of
   * validating (`NOT_APPLICABLE_IN_MANAGED`, or `REAUTH_REQUIRED` without a recent re-authentication).
   */
  readonly requiredMode: "MANAGED" | "PRIVATE" | null;
  readonly inManaged: "NOT_APPLICABLE" | "REAUTH" | null;
  /**
   * §35.12 step 4 and §35.15: the operations a `DELETING_SCHEDULED` account still accepts. Everything else is
   * `INVALID_STATE` in step 0c. (`DELETING` and `ORPHANED` accept nothing at all.)
   */
  readonly allowedWhileAccountDeleting: boolean;
  /**
   * §35.15: SecurityBundle key 15. True only for the three record operations, which carry a
   * `RecoveryRecord` and nothing but `expected` and `bundle_id`; for every other type it is **—**.
   */
  readonly recovery: boolean;
  /**
   * §35.15 / §35.1.1 step 0c: in a Private account this operation applies only with a matured, live
   * request of its own `kind` at the root generation in force, which the applied bundle consumes.
   */
  readonly delayed: boolean;
}

const NO_DELETION = { deletion: null, precondition: null } as const;
const NO_RECOVERY = { recovery: false, delayed: false } as const;
const NO_ESCROW = { escrow: null } as const;
const ANY_MODE = { requiredMode: null, inManaged: null } as const;

/**
 * §35.15: the request, veto and cancel of a delayed recovery operation. Only `recovery` (key 15),
 * `expected` and `bundle_id`. They are refused in Managed and accepted while a deletion is scheduled;
 * whether a request of a given `kind` is, is step 7's rule (`RECOVERY_RESET` only).
 */
const RECOVERY_RECORD_ROW: OperationRules = {
  scopes: ["TRUSTED_SECURITY", "ACCOUNT_SECURITY", "RECOVERY_CONTROL"],
  transition: null,
  registry: null,
  config: null,
  epochs: null,
  coverage: null,
  ...NO_DELETION,
  profileSignature: false,
  ...NO_ESCROW,
  allowedWhileAccountDeleting: true,
  recovery: true,
  delayed: false,
  requiredMode: null,
  inManaged: "NOT_APPLICABLE",
};

/**
 * §35.1.1 step 0 / §35.15: §28.2's role that signs a `RecoveryRecord`, and the scopes that may carry
 * it, by (`operation_type`, `kind`). Each operation is vetoed by the authority its requester does
 * **not** hold: the kit (role 3) requests a reset and the root (role 1) vetoes it; the root requests
 * a kit replacement or a switch and the kit vetoes it. A cancel is signed by the requester's role.
 */
export const RECOVERY_RECORD_SIGNERS: Readonly<
  Record<RecoveryRecordOperation, Readonly<Record<RecoveryRequestKind, { readonly role: 1 | 3; readonly scopes: readonly Scope[] }>>>
> = {
  RECOVERY_REQUEST: {
    RECOVERY_RESET: { role: 3, scopes: ["RECOVERY_CONTROL"] },
    RECOVERY_KIT_REPLACEMENT: { role: 1, scopes: ["TRUSTED_SECURITY"] },
    SWITCH_TO_MANAGED: { role: 1, scopes: ["TRUSTED_SECURITY"] },
  },
  RECOVERY_CANCEL: {
    RECOVERY_RESET: { role: 3, scopes: ["RECOVERY_CONTROL"] },
    RECOVERY_KIT_REPLACEMENT: { role: 1, scopes: ["TRUSTED_SECURITY", "ACCOUNT_SECURITY"] },
    SWITCH_TO_MANAGED: { role: 1, scopes: ["TRUSTED_SECURITY", "ACCOUNT_SECURITY"] },
  },
  // §35.15: a reset veto is accepted from any client with Root Unlock; it creates no envelope.
  RECOVERY_VETO: {
    RECOVERY_RESET: { role: 1, scopes: ["TRUSTED_SECURITY", "ACCOUNT_SECURITY"] },
    RECOVERY_KIT_REPLACEMENT: { role: 3, scopes: ["RECOVERY_CONTROL"] },
    SWITCH_TO_MANAGED: { role: 3, scopes: ["RECOVERY_CONTROL"] },
  },
};

export function isRecoveryRecordOperation(operationType: OperationType): operationType is RecoveryRecordOperation {
  return operationType === "RECOVERY_REQUEST" || operationType === "RECOVERY_VETO" || operationType === "RECOVERY_CANCEL";
}

/**
 * §35.15: the vetoing authority of a request of this `kind`, which is what a client asks for when it
 * offers the veto: Password + Secret Key (role 1) for a reset, the Recovery Kit (role 3) otherwise.
 */
export function vetoRole(kind: RecoveryRequestKind): 1 | 3 {
  return RECOVERY_RECORD_SIGNERS.RECOVERY_VETO[kind].role;
}

/**
 * §35.1.1's two tables, row by row. Reading order matches the spec's columns so a reviewer can
 * diff this against the document without translating anything.
 */
export const OPERATION_RULES: Readonly<Record<OperationType, OperationRules>> = {
  // | CREATE_ACCOUNT | GENESIS | v1 | sí | E1 del primer vault | — |
  CREATE_ACCOUNT: {
    // §11.3, §35.1.1 step 0: the single exception — login alone, on an account with no root yet.
    scopes: [],
    transition: "GENESIS",
    registry: "INITIAL",
    config: "PROFILE",
    epochs: "ONE_NEW_VAULT",
    coverage: null,
    ...NO_DELETION,
    profileSignature: false,
    // Below the table: "En modo Managed, CREATE_ACCOUNT lleva además escrow"; key 14: both slots.
    escrow: { slots: "UNLOCK_AND_RECOVERY", when: "IF_MANAGED" },
    allowedWhileAccountDeleting: false,
    ...NO_RECOVERY,
    ...ANY_MODE,
  },
  // | ENROLL_CLIENT | — | sí | config | — | recipient añadido |
  ENROLL_CLIENT: {
    scopes: ["ACCOUNT_SECURITY", "TRUSTED_SECURITY"],
    transition: null,
    registry: "ONE_ADDED",
    config: "CONFIG",
    epochs: null,
    coverage: "ADDED_RECIPIENT",
    ...NO_DELETION,
    profileSignature: false,
    ...NO_ESCROW,
    // §35.12 step 4: so a user who lost their only trusted client can enrol one and cancel.
    allowedWhileAccountDeleting: true,
    ...NO_RECOVERY,
    ...ANY_MODE,
  },
  // | CREATE_VAULT | — | — | — | E1 del vault nuevo | — |
  CREATE_VAULT: {
    scopes: ["TRUSTED_SECURITY"],
    transition: null,
    registry: null,
    config: null,
    epochs: "ONE_NEW_VAULT",
    coverage: null,
    ...NO_DELETION,
    profileSignature: false,
    ...NO_ESCROW,
    allowedWhileAccountDeleting: false,
    ...NO_RECOVERY,
    ...ANY_MODE,
  },
  // | REVOKE_CLIENT | — | sí | config | uno nuevo por vault | — |
  REVOKE_CLIENT: {
    scopes: ["TRUSTED_SECURITY"],
    transition: null,
    registry: "SOME_REVOKED",
    config: "CONFIG",
    epochs: "EVERY_LIVE_VAULT",
    coverage: null,
    ...NO_DELETION,
    profileSignature: false,
    ...NO_ESCROW,
    allowedWhileAccountDeleting: false,
    ...NO_RECOVERY,
    ...ANY_MODE,
  },
  // | CHANGE_SECRETS | — | — | perfil y config, con firma | — | — |
  CHANGE_SECRETS: {
    scopes: ["ACCOUNT_SECURITY", "TRUSTED_SECURITY"],
    transition: null,
    registry: null,
    config: "PROFILE",
    epochs: null,
    coverage: null,
    ...NO_DELETION,
    profileSignature: true,
    ...NO_ESCROW,
    allowedWhileAccountDeleting: false,
    ...NO_RECOVERY,
    // §35.1: CHANGE_SECRETS only exists in Private; a Managed account has no secrets to change.
    requiredMode: null,
    inManaged: "NOT_APPLICABLE",
  },
  // | RECOVERY_RESET | RECOVERY_RESET | sí | perfil y config | uno nuevo por vault | nueva clave ACCOUNT |
  RECOVERY_RESET: {
    scopes: ["RECOVERY_CONTROL"],
    transition: "RECOVERY_RESET",
    registry: "NONE_ACTIVE",
    config: "PROFILE",
    epochs: "EVERY_LIVE_VAULT",
    coverage: "NEW_ACCOUNT_KEY",
    ...NO_DELETION,
    // §44.3: "RECOVERY_RESET sin profile_signature → aceptado".
    profileSignature: false,
    // §35.7 (Managed): only the new UNLOCK slot; the RECOVERY slot is kept.
    escrow: { slots: "UNLOCK_ONLY", when: "IF_MANAGED" },
    // §35.12 step 4: the kit holder must be able to take the account back from an attacker.
    allowedWhileAccountDeleting: true,
    // §35.15: in Private, only with a matured request of this kind (ADR-022).
    recovery: false,
    delayed: true,
    ...ANY_MODE,
  },
  // | RECOVERY_KIT_REPLACEMENT | RECOVERY_KIT_REPLACEMENT | sí | config | uno nuevo por vault | nueva clave RECOVERY |
  RECOVERY_KIT_REPLACEMENT: {
    scopes: ["TRUSTED_SECURITY"],
    transition: "RECOVERY_KIT_REPLACEMENT",
    registry: "UNCHANGED",
    config: "CONFIG",
    epochs: "EVERY_LIVE_VAULT",
    coverage: "NEW_RECOVERY_KEY",
    ...NO_DELETION,
    profileSignature: false,
    ...NO_ESCROW,
    allowedWhileAccountDeleting: false,
    // §35.15: in Private, only with a matured request of this kind (ADR-022).
    recovery: false,
    delayed: true,
    // §35.9: no kit to replace in Managed.
    requiredMode: null,
    inManaged: "NOT_APPLICABLE",
  },
  // | DELETE_VAULT, CANCEL_DELETE_VAULT | — | — | — | — | — (solo `deletion`) |
  DELETE_VAULT: {
    scopes: ["TRUSTED_SECURITY"],
    transition: null,
    registry: null,
    config: null,
    epochs: null,
    coverage: null,
    deletion: "VAULT",
    precondition: { subject: "VAULT", state: "ACTIVE" },
    profileSignature: false,
    ...NO_ESCROW,
    allowedWhileAccountDeleting: false,
    ...NO_RECOVERY,
    ...ANY_MODE,
  },
  CANCEL_DELETE_VAULT: {
    // §35.11 step 5 (ADR-022): also the current Recovery Authority, with a role-3 signature.
    scopes: ["TRUSTED_SECURITY", "RECOVERY_CONTROL"],
    transition: null,
    registry: null,
    config: null,
    epochs: null,
    coverage: null,
    deletion: "VAULT",
    precondition: { subject: "VAULT", state: "DELETING_SCHEDULED" },
    profileSignature: false,
    ...NO_ESCROW,
    allowedWhileAccountDeleting: false,
    ...NO_RECOVERY,
    ...ANY_MODE,
  },
  // | DELETE_ACCOUNT, CANCEL_DELETE_ACCOUNT | — | — | — | — | — (solo `deletion`) |
  DELETE_ACCOUNT: {
    scopes: ["TRUSTED_SECURITY"],
    transition: null,
    registry: null,
    config: null,
    epochs: null,
    coverage: null,
    deletion: "ACCOUNT",
    precondition: { subject: "ACCOUNT", state: "ACTIVE" },
    profileSignature: false,
    ...NO_ESCROW,
    allowedWhileAccountDeleting: false,
    ...NO_RECOVERY,
    // §35.12 step 2: in Managed, a re-authentication of at most 5 minutes replaces the password.
    requiredMode: null,
    inManaged: "REAUTH",
  },
  CANCEL_DELETE_ACCOUNT: {
    // §35.12 (ADR-022): also the current Recovery Authority, with a role-3 signature, no delay, no veto.
    scopes: ["TRUSTED_SECURITY", "ACCOUNT_SECURITY", "RECOVERY_CONTROL"],
    transition: null,
    registry: null,
    config: null,
    epochs: null,
    coverage: null,
    deletion: "ACCOUNT",
    precondition: { subject: "ACCOUNT", state: "DELETING_SCHEDULED" },
    profileSignature: false,
    ...NO_ESCROW,
    allowedWhileAccountDeleting: true,
    ...NO_RECOVERY,
    ...ANY_MODE,
  },
  // | SWITCH_TO_PRIVATE | SWITCH_TO_PRIVATE | sí | perfil y config | uno nuevo por vault | nuevas claves ACCOUNT y RECOVERY |
  SWITCH_TO_PRIVATE: {
    // §35.1.1 step 0: it creates envelopes for other recipients (§35.1).
    scopes: ["TRUSTED_SECURITY"],
    transition: "SWITCH_TO_PRIVATE",
    registry: "UNCHANGED",
    config: "PROFILE",
    epochs: "EVERY_LIVE_VAULT",
    coverage: "NEW_ACCOUNT_AND_RECOVERY_KEYS",
    ...NO_DELETION,
    profileSignature: false,
    // Applied, it deletes the escrow row (step 7); it carries none.
    ...NO_ESCROW,
    allowedWhileAccountDeleting: false,
    ...NO_RECOVERY,
    requiredMode: "MANAGED",
    inManaged: null,
  },
  // | SWITCH_TO_MANAGED | SWITCH_TO_MANAGED | sí | perfil y config, con firma | uno nuevo por vault | nueva clave RECOVERY (y escrow) |
  SWITCH_TO_MANAGED: {
    scopes: ["TRUSTED_SECURITY"],
    transition: "SWITCH_TO_MANAGED",
    registry: "UNCHANGED",
    config: "PROFILE",
    epochs: "EVERY_LIVE_VAULT",
    coverage: "NEW_RECOVERY_KEY",
    ...NO_DELETION,
    // §35.14 step 9: it re-wraps the same keyset, like §35.6.
    profileSignature: true,
    escrow: { slots: "UNLOCK_AND_RECOVERY", when: "ALWAYS" },
    allowedWhileAccountDeleting: false,
    // §35.15: in Private, only with a matured request of this kind (ADR-022).
    recovery: false,
    delayed: true,
    requiredMode: "PRIVATE",
    inManaged: null,
  },
  // | RECOVERY_REQUEST, RECOVERY_VETO, RECOVERY_CANCEL | — | — | — | — | — (solo `recovery`) |
  // Step 0's scope depends on `recovery.kind` (RECOVERY_RECORD_SIGNERS below); `scopes` is their union.
  RECOVERY_REQUEST: RECOVERY_RECORD_ROW,
  RECOVERY_VETO: RECOVERY_RECORD_ROW,
  RECOVERY_CANCEL: RECOVERY_RECORD_ROW,
} as const;

/** The rules of one operation. Throwing here is a programming error: the type is a closed enum. */
export function operationRules(operationType: OperationType): OperationRules {
  return OPERATION_RULES[operationType];
}

/**
 * The `SecurityBundle` fields the table marks **—** for this operation, by name. Used by step 7's
 * "partes marcadas — presentes" rule, so the list of forbidden fields is derived from the same row
 * that says which are required rather than written out a second time.
 */
export function forbiddenFields(rules: OperationRules): readonly string[] {
  const forbidden: string[] = [];
  if (rules.transition === null) forbidden.push("root_transition", "root_descriptor");
  if (rules.registry === null) forbidden.push("registry");
  // §23.4: with `profile` present the config travels only inside it, so keys 7/8 are forbidden too.
  if (rules.config !== "PROFILE") forbidden.push("profile");
  if (rules.config !== "CONFIG") forbidden.push("config_blob", "config_version");
  if (rules.epochs === null) forbidden.push("epochs");
  if (rules.coverage === null) forbidden.push("coverage_envelopes");
  if (rules.deletion === null) forbidden.push("deletion");
  if (!rules.profileSignature) forbidden.push("profile_signature");
  if (rules.escrow === null) forbidden.push("escrow");
  if (!rules.recovery) forbidden.push("recovery");
  return forbidden;
}

/**
 * The fields the table marks as applicable. §23.4: an applicable field is never omitted — an
 * applicable *collection* that happens to be empty travels as `[]`, which is why this is presence,
 * not emptiness.
 */
export function requiredFields(rules: OperationRules): readonly string[] {
  const required: string[] = [];
  if (rules.transition !== null) required.push("root_transition", "root_descriptor");
  if (rules.registry !== null) required.push("registry");
  if (rules.config === "PROFILE") required.push("profile");
  if (rules.config === "CONFIG") required.push("config_blob", "config_version");
  if (rules.epochs !== null) required.push("epochs");
  if (rules.coverage !== null) required.push("coverage_envelopes");
  if (rules.deletion !== null) required.push("deletion");
  if (rules.profileSignature) required.push("profile_signature");
  if (rules.recovery) required.push("recovery");
  // `escrow` is conditional on the mode the bundle ends in, so step 7's escrow rule owns its presence.
  return required;
}
