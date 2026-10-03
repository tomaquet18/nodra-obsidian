// The frozen NCE key tables of `crypto_version = 1`: §8 (Revision Manifest) and §23.4, with the
// field semantics of §25–§35, plus the ADR-021 additions of `crypto_version = 2` (escrow records,
// SecurityBundle key 14, the Managed profile shape and the two mode switches). One schema per
// structure; the key numbers are normative and must never change without a new `crypto_version`.
import {
  arrayOf,
  bool,
  bytes,
  enumOf,
  nullable,
  opt,
  record,
  req,
  roles,
  schema,
  text,
  uint,
} from "./record.js";
import type { AnyRecordSchema, RecordOf } from "./record.js";

/** `*_id` values are 16 bytes (§6, §23.2): UUIDv7, or the first 16 bytes of SHA-256(SPKI) (§30.1). */
const id = bytes(16);
/** Hashes, fingerprints and commitments (§23.2). */
const hash = bytes(32);
/** ECDSA P-256 signatures, IEEE P1363 (§23.1, §23.2). */
const signature = bytes(64);
/** SPKI DER, PKCS#8 DER, ciphertext, AES-GCM blobs: variable-length byte strings. */
const blob = bytes();
/** Unix milliseconds (§23.2). */
const timestamp = uint;

// --- §8 Revision Manifest -----------------------------------------------------------------------

export const REVISION_MANIFEST = schema("RevisionManifest", {
  object_id: req(1, id),
  revision_id: req(2, id),
  parent_revision_id: req(3, nullable(id)),
  path: req(4, text),
  mime: req(5, text),
  mtime_ms: req(6, timestamp),
  content_blob_id: req(7, nullable(id)),
  content_fingerprint: req(8, nullable(hash)),
  content_plaintext_size: req(9, nullable(uint)),
  deleted: req(10, bool),
  content_epoch_id: req(11, nullable(id)),
});
export type RevisionManifest = RecordOf<typeof REVISION_MANIFEST.fields>;

// --- §23.4 / §25 Account Root Keyset --------------------------------------------------------------

/** The two account private keys of §25, which is also the `key_role` of the AAD `nodra/aad/account-private-key`. */
export const KEY_ROLES = ["ACCOUNT_ENCRYPTION", "ACCOUNT_SIGNING"] as const;

export const WRAPPED_PRIVATE_KEY = schema("WrappedPrivateKey", {
  key_role: req(1, enumOf(KEY_ROLES)),
  // Generic AES-GCM blob of §23.4: nonce(12) ‖ ciphertext‖tag, from `wrapKey("pkcs8")`.
  blob: req(2, blob),
});
export type WrappedPrivateKey = RecordOf<typeof WRAPPED_PRIVATE_KEY.fields>;

// --- §23.4 / §24 Account Security Profile (plaintext on the server) -------------------------------

export const ARGON2_PARAMS = schema("Argon2Params", {
  memory_kib: req(1, uint),
  iterations: req(2, uint),
  parallelism: req(3, uint),
  // Nodra profile version of ADR-004, not the Argon2 algorithm version (crypto NOTES Q166).
  version: req(4, uint),
});
export type Argon2Params = RecordOf<typeof ARGON2_PARAMS.fields>;

export const ACCOUNT_SECURITY_PROFILE = schema("AccountSecurityProfile", {
  account_id: req(1, id),
  // Present if and only if the account is Private; a Managed profile omits both (§23.4, §24). That
  // rule depends on the account's mode, so the Worker and the client check it, not the codec.
  kdf_salt: opt(2, bytes(16)),
  argon2_params: opt(3, record(ARGON2_PARAMS)),
  wrapped_account_encryption_key: req(4, record(WRAPPED_PRIVATE_KEY)),
  wrapped_account_signing_key: req(5, record(WRAPPED_PRIVATE_KEY)),
  config_version: req(6, uint),
  config_blob: req(7, blob),
});
export type AccountSecurityProfile = RecordOf<typeof ACCOUNT_SECURITY_PROFILE.fields>;

// --- §26 Account Security Config (inside the AES-GCM blob) ----------------------------------------

export const ACCOUNT_SECURITY_CONFIG = schema("AccountSecurityConfig", {
  account_id: req(1, id),
  config_version: req(2, uint),
  root_generation: req(3, uint),
  root_hash: req(4, hash),
  genesis_root_hash: req(5, hash),
  account_encryption_public_key_hash: req(6, hash),
  account_signing_public_key_hash: req(7, hash),
  recovery_encryption_public_key_hash: req(8, hash),
  recovery_authority_public_key_hash: req(9, hash),
  registry_version: req(10, uint),
  registry_hash: req(11, hash),
  crypto_version: req(12, uint),
});
export type AccountSecurityConfig = RecordOf<typeof ACCOUNT_SECURITY_CONFIG.fields>;

// --- §28 Root chain ------------------------------------------------------------------------------

export const ROOT_DESCRIPTOR = schema("RootDescriptor", {
  account_id: req(1, id),
  root_generation: req(2, uint),
  account_encryption_public_key: req(3, blob),
  account_signing_public_key: req(4, blob),
  recovery_encryption_public_key: req(5, blob),
  recovery_authority_public_key: req(6, blob),
  previous_root_hash: req(7, nullable(hash)),
  crypto_version: req(8, uint),
});
export type RootDescriptor = RecordOf<typeof ROOT_DESCRIPTOR.fields>;

/** The only transitions the MVP accepts (§28.2); the two mode switches are `crypto_version = 2`. */
export const TRANSITION_TYPES = [
  "GENESIS",
  "RECOVERY_RESET",
  "RECOVERY_KIT_REPLACEMENT",
  "SWITCH_TO_PRIVATE",
  "SWITCH_TO_MANAGED",
] as const;

/** Signer role codes of §28.2: 1 current Account Signing, 2 new, 3 current Recovery Authority, 4 new. */
export const TRANSITION_SIGNER_ROLES = [1, 2, 3, 4] as const;

export const ROOT_TRANSITION = schema("RootTransition", {
  account_id: req(1, id),
  transition_type: req(2, enumOf(TRANSITION_TYPES)),
  old_root_hash: req(3, nullable(hash)),
  new_root_hash: req(4, hash),
  new_root_generation: req(5, uint),
  signatures: req(6, roles(TRANSITION_SIGNER_ROLES, signature)),
});
export type RootTransition = RecordOf<typeof ROOT_TRANSITION.fields>;

// --- §29 Recipient Registry ----------------------------------------------------------------------

/** Recipient types that live in the Registry (§29, §30.1). ACCOUNT and RECOVERY live in the root. */
export const REGISTRY_RECIPIENT_TYPES = ["PLUGIN_INSTALLATION", "TRUSTED_BROWSER"] as const;
export const RECIPIENT_STATUSES = ["ACTIVE", "REVOKED"] as const;
/** Every recipient type, including the two root ones, as used by an Epoch Envelope (§30.1, §32.2). */
export const RECIPIENT_TYPES = ["ACCOUNT", "RECOVERY", ...REGISTRY_RECIPIENT_TYPES] as const;

export const REGISTRY_RECIPIENT = schema("RegistryRecipient", {
  recipient_id: req(1, id),
  type: req(2, enumOf(REGISTRY_RECIPIENT_TYPES)),
  public_key: req(3, blob),
  label: req(4, text),
  status: req(5, enumOf(RECIPIENT_STATUSES)),
  added_version: req(6, uint),
  revoked_version: req(7, nullable(uint)),
});
export type RegistryRecipient = RecordOf<typeof REGISTRY_RECIPIENT.fields>;

export const REGISTRY = schema("Registry", {
  account_id: req(1, id),
  registry_version: req(2, uint),
  previous_registry_hash: req(3, nullable(hash)),
  root_generation: req(4, uint),
  // §29 requires strictly increasing recipient_id; that is a registry rule, not a codec one.
  recipients: req(5, arrayOf(record(REGISTRY_RECIPIENT))),
  signature: req(6, signature),
});
export type Registry = RecordOf<typeof REGISTRY.fields>;

// --- §32 Epochs ------------------------------------------------------------------------------------

export const EPOCH_DESCRIPTOR = schema("EpochDescriptor", {
  vault_id: req(1, id),
  epoch_id: req(2, id),
  previous_epoch_id: req(3, nullable(id)),
  previous_descriptor_hash: req(4, nullable(hash)),
  root_generation: req(5, uint),
  root_hash: req(6, hash),
  registry_version: req(7, uint),
  registry_hash: req(8, hash),
  epoch_commitment: req(9, hash),
  envelope_set_hash: req(10, hash),
  crypto_version: req(11, uint),
  signature: req(12, signature),
});
export type EpochDescriptor = RecordOf<typeof EPOCH_DESCRIPTOR.fields>;

export const EPOCH_ENVELOPE = schema("EpochEnvelope", {
  vault_id: req(1, id),
  epoch_id: req(2, id),
  recipient_id: req(3, id),
  recipient_type: req(4, enumOf(RECIPIENT_TYPES)),
  ciphertext: req(5, blob),
  /** 1 = RSA-OAEP-3072/SHA-256 (§23.4). */
  algorithm_version: req(6, uint),
});
export type EpochEnvelope = RecordOf<typeof EPOCH_ENVELOPE.fields>;

// --- §27.1 Recovery Kit -----------------------------------------------------------------------------

export const RECOVERY_KIT = schema("RecoveryKit", {
  account_id: req(1, id),
  genesis_root_hash: req(2, hash),
  recovery_encryption_private_key: req(3, blob),
  recovery_authority_private_key: req(4, blob),
  recovery_encryption_public_key_hash: req(5, hash),
  recovery_authority_public_key_hash: req(6, hash),
  created_at: req(7, timestamp),
});
export type RecoveryKit = RecordOf<typeof RECOVERY_KIT.fields>;

// --- §3.6 / §23.4 Escrow (crypto_version = 2, ADR-021) -------------------------------------------

/** The two escrow slots (§3.6): the `RootUnlockKey`, and the Recovery private keys. */
export const ESCROW_SLOTS = ["UNLOCK", "RECOVERY"] as const;

export const ESCROW_SLOT = schema("EscrowSlot", {
  slot: req(1, enumOf(ESCROW_SLOTS)),
  key_id: req(2, id),
  // RSA-OAEP-3072 to the Escrow Key `key_id`, label Context("nodra/escrow", account_id, key_id, slot).
  wrapped_key: req(3, blob),
  // Only RECOVERY: NCE(EscrowedRecoveryKeys) under the AES-256-GCM key `wrapped_key` wraps. Whether it
  // is present for the slot at hand is a Worker rule (§35.1.1 step 7), not a codec one.
  payload_blob: opt(4, blob),
});
export type EscrowSlot = RecordOf<typeof ESCROW_SLOT.fields>;

export const ESCROWED_RECOVERY_KEYS = schema("EscrowedRecoveryKeys", {
  recovery_encryption_private_key: req(1, blob),
  recovery_authority_private_key: req(2, blob),
});
export type EscrowedRecoveryKeys = RecordOf<typeof ESCROWED_RECOVERY_KEYS.fields>;

/**
 * The slots a bundle **replaces** (SecurityBundle key 14); an absent slot keeps its current value.
 * Both are optional here: which ones each operation must carry is a §35.1.1 step 7 rule.
 */
export const ESCROW_BLOB = schema("EscrowBlob", {
  account_id: req(1, id),
  unlock: opt(2, record(ESCROW_SLOT)),
  recovery: opt(3, record(ESCROW_SLOT)),
});
export type EscrowBlob = RecordOf<typeof ESCROW_BLOB.fields>;

/** One slot re-wrapped by the Worker to the client's ephemeral key (§24.2, §35.7). */
export const ESCROW_REWRAP = schema("EscrowRewrap", {
  account_id: req(1, id),
  slot: req(2, enumOf(ESCROW_SLOTS)),
  // RSA-OAEP-3072 to the ephemeral key, label Context("nodra/escrow-rewrap", account_id, SHA-256(SPKI), slot).
  wrapped_key: req(3, blob),
  payload_blob: opt(4, blob),
});
export type EscrowRewrap = RecordOf<typeof ESCROW_REWRAP.fields>;

// --- §35 Security Bundle -----------------------------------------------------------------------------

/** The `operation_type` values of §35.1.1. */
export const OPERATION_TYPES = [
  "CREATE_ACCOUNT",
  "ENROLL_CLIENT",
  "CREATE_VAULT",
  "REVOKE_CLIENT",
  "CHANGE_SECRETS",
  "RECOVERY_RESET",
  "RECOVERY_KIT_REPLACEMENT",
  "DELETE_VAULT",
  "CANCEL_DELETE_VAULT",
  "DELETE_ACCOUNT",
  "CANCEL_DELETE_ACCOUNT",
  "SWITCH_TO_PRIVATE",
  "SWITCH_TO_MANAGED",
  // ADR-022 (§35.15): the signed request, veto and cancellation of a delayed recovery operation.
  "RECOVERY_REQUEST",
  "RECOVERY_VETO",
  "RECOVERY_CANCEL",
] as const;

/** One new epoch of a bundle: its descriptor and the envelopes created with it (§23.4 key 9). */
export const BUNDLE_EPOCH = schema("BundleEpoch", {
  descriptor: req(1, record(EPOCH_DESCRIPTOR)),
  envelopes: req(2, arrayOf(record(EPOCH_ENVELOPE))),
});
export type BundleEpoch = RecordOf<typeof BUNDLE_EPOCH.fields>;

/** CAS values the Worker checks in step 0d; all three are 0 before GENESIS (§35.1.1). */
export const BUNDLE_EXPECTED = schema("BundleExpected", {
  root_generation: req(1, uint),
  registry_version: req(2, uint),
  config_version: req(3, uint),
});
export type BundleExpected = RecordOf<typeof BUNDLE_EXPECTED.fields>;

/** Only in DELETE_* / CANCEL_DELETE_* (§35.11, §35.12). `vault_id` is absent for account deletions. */
export const BUNDLE_DELETION = schema("BundleDeletion", {
  vault_id: opt(1, id),
  nonce: req(2, bytes(16)),
  signature: req(3, signature),
});
export type BundleDeletion = RecordOf<typeof BUNDLE_DELETION.fields>;

// --- §35.15 Recovery requests (ADR-022) ---------------------------------------------------------

/** The three operations §35.15 delays and makes vetoable, which is what a request names as its `kind`. */
export const RECOVERY_REQUEST_KINDS = ["RECOVERY_RESET", "RECOVERY_KIT_REPLACEMENT", "SWITCH_TO_MANAGED"] as const;

/**
 * SecurityBundle key 15 (§23.4): the signed record of a `RECOVERY_REQUEST`, `RECOVERY_VETO` or
 * `RECOVERY_CANCEL`. The signature is over `Context("nodra/recovery-request", operation_type,
 * account_id, request_id, kind, root_generation, root_hash)`; `account_id` comes from the session.
 * Added without a new `crypto_version` by the explicit exception of §23.3 (ADR-022).
 */
export const RECOVERY_RECORD = schema("RecoveryRecord", {
  request_id: req(1, id),
  kind: req(2, enumOf(RECOVERY_REQUEST_KINDS)),
  root_generation: req(3, uint),
  root_hash: req(4, hash),
  signature: req(5, signature),
});
export type RecoveryRecord = RecordOf<typeof RECOVERY_RECORD.fields>;

export const SECURITY_BUNDLE = schema("SecurityBundle", {
  operation_type: req(1, enumOf(OPERATION_TYPES)),
  root_transition: opt(2, record(ROOT_TRANSITION)),
  root_descriptor: opt(3, record(ROOT_DESCRIPTOR)),
  registry: opt(4, record(REGISTRY)),
  profile: opt(5, record(ACCOUNT_SECURITY_PROFILE)),
  profile_signature: opt(6, signature),
  config_blob: opt(7, blob),
  config_version: opt(8, uint),
  // Applicable-but-empty collections travel as `[]`; only a non-applicable field is omitted (§23.4).
  epochs: opt(9, arrayOf(record(BUNDLE_EPOCH))),
  coverage_envelopes: opt(10, arrayOf(record(EPOCH_ENVELOPE))),
  expected: req(11, record(BUNDLE_EXPECTED)),
  deletion: opt(12, record(BUNDLE_DELETION)),
  bundle_id: req(13, id),
  escrow: opt(14, record(ESCROW_BLOB)),
  // Only, and always, in RECOVERY_REQUEST / RECOVERY_VETO / RECOVERY_CANCEL (§35.15); any crypto_version.
  recovery: opt(15, record(RECOVERY_RECORD)),
});
export type SecurityBundle = RecordOf<typeof SECURITY_BUNDLE.fields>;

/** Every frozen key table of `crypto_version` 1 and 2 (and the ADR-022 record valid in both), by name. Used by the vector and property tests. */
export const RECORD_SCHEMAS = {
  RevisionManifest: REVISION_MANIFEST,
  WrappedPrivateKey: WRAPPED_PRIVATE_KEY,
  Argon2Params: ARGON2_PARAMS,
  AccountSecurityProfile: ACCOUNT_SECURITY_PROFILE,
  AccountSecurityConfig: ACCOUNT_SECURITY_CONFIG,
  RootDescriptor: ROOT_DESCRIPTOR,
  RootTransition: ROOT_TRANSITION,
  RegistryRecipient: REGISTRY_RECIPIENT,
  Registry: REGISTRY,
  EpochDescriptor: EPOCH_DESCRIPTOR,
  EpochEnvelope: EPOCH_ENVELOPE,
  RecoveryKit: RECOVERY_KIT,
  BundleEpoch: BUNDLE_EPOCH,
  BundleExpected: BUNDLE_EXPECTED,
  BundleDeletion: BUNDLE_DELETION,
  SecurityBundle: SECURITY_BUNDLE,
  EscrowSlot: ESCROW_SLOT,
  EscrowedRecoveryKeys: ESCROWED_RECOVERY_KEYS,
  EscrowBlob: ESCROW_BLOB,
  EscrowRewrap: ESCROW_REWRAP,
  RecoveryRecord: RECOVERY_RECORD,
} as const satisfies Record<string, AnyRecordSchema>;

export type RecordName = keyof typeof RECORD_SCHEMAS;

export {
  RecordError,
  decodeRecord,
  encodeOmitting,
  encodeRecord,
  fromNce,
  toNce,
  toNceOmitting,
} from "./record.js";
export type {
  AnyField,
  AnyRecordSchema,
  Field,
  FieldKind,
  RecordErrorCode,
  RecordOf,
  RecordSchema,
  RolePair,
  Schema,
} from "./record.js";
