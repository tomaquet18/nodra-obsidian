// The §23.3 domains this package uses, as named functions, so no call site ever builds one by
// hand and every argument order is fixed in one place.
import { domainContext, sha256 } from "@nodra/crypto";
import type { DomainContext } from "@nodra/crypto";
import type { AccountKeyRole } from "@nodra/crypto";
import {
  ACCOUNT_SECURITY_PROFILE,
  EPOCH_DESCRIPTOR,
  RECOVERY_KIT,
  REGISTRY,
  ROOT_DESCRIPTOR,
  ROOT_TRANSITION,
  encodeRecord,
  toNce,
  toNceOmitting,
} from "@nodra/encoding/records";
import type {
  AccountSecurityProfile,
  EpochDescriptor,
  EpochEnvelope,
  Registry,
  RecoveryKit,
  RootDescriptor,
  RootTransition,
} from "@nodra/encoding/records";

/** `info` of the `AccountKeyWrapKey` derivation (§24). No fields. */
export const ACCOUNT_KEYWRAP_INFO: DomainContext = domainContext("nodra/hkdf/account-keywrap");

/** `info` of the `AccountConfigKey` derivation (§24). No fields. */
export const ACCOUNT_CONFIG_INFO: DomainContext = domainContext("nodra/hkdf/account-config");

/**
 * AAD of a wrapped account private key (§23.3, §25). The `account_id` is the one the caller
 * authenticated with, never the one written in the unauthenticated profile — that is what makes a
 * profile stolen from another account fail to open (§44.3 "Secret Key incorrecta o key_role
 * incorrecto → unwrap del keyset falla").
 */
export function accountPrivateKeyAad(accountId: Uint8Array, keyRole: AccountKeyRole): DomainContext {
  return domainContext("nodra/aad/account-private-key", accountId, keyRole);
}

/** AAD of the Account Security Config blob (§26). */
export function accountConfigAad(accountId: Uint8Array, configVersion: number): DomainContext {
  return domainContext("nodra/aad/account-config", accountId, configVersion);
}

/**
 * `Context("nodra/root-descriptor", RootDescriptor)` (§23.3). The structure travels as **one**
 * field — its NCE map — not as its fields spread into the context array, so the frozen key
 * numbers of §23.4 stay normative for the hash as well (NOTES question 189).
 */
export function rootDescriptorContext(descriptor: RootDescriptor): DomainContext {
  return domainContext("nodra/root-descriptor", toNce(ROOT_DESCRIPTOR, descriptor));
}

/**
 * `Context("nodra/root-transition", campos 1–5)` (§28.2): the transition without `signatures`,
 * which is both its hash context and what every role signs.
 */
export function rootTransitionContext(transition: Omit<RootTransition, "signatures">): DomainContext {
  // The placeholder is dropped again by `toNceOmitting`; it exists only so an unsigned draft and
  // a signed transition produce the very same bytes — what is signed is what is verified.
  return domainContext("nodra/root-transition", toNceOmitting(ROOT_TRANSITION, { ...transition, signatures: [] }, ["signatures"]));
}

/**
 * `Context("nodra/registry", registry sin signature)` (§23.3, §29). The same bytes are hashed to
 * get `registry_hash` and signed by the Account Signing Key of `root_generation`.
 */
export function registryContext(registry: Omit<Registry, "signature">): DomainContext {
  return domainContext("nodra/registry", toNceOmitting(REGISTRY, { ...registry, signature: PLACEHOLDER_SIGNATURE }, ["signature"]));
}

/** Never encoded: `toNceOmitting` removes it. It only satisfies the schema's required field. */
const PLACEHOLDER_SIGNATURE = new Uint8Array(64);

/**
 * `Context("nodra/epoch-descriptor", descriptor sin signature)` (§23.3, §32.1). Same bytes are
 * hashed to get `descriptor_hash` and signed by the Account Signing Key of `root_generation`, and
 * the structure nests as one field for the same reason as §28/§29 (NOTES question 189).
 */
export function epochDescriptorContext(descriptor: Omit<EpochDescriptor, "signature">): DomainContext {
  return domainContext(
    "nodra/epoch-descriptor",
    toNceOmitting(EPOCH_DESCRIPTOR, { ...descriptor, signature: PLACEHOLDER_SIGNATURE }, ["signature"]),
  );
}

/** One entry of the envelope set: a recipient and the hash of *its* envelope ciphertext (§23.3). */
export interface EnvelopeSetEntry {
  readonly recipientId: Uint8Array;
  /** `SHA-256(ciphertext del envelope)` — raw bytes, no context (§23.0 rule 6, exception 2). */
  readonly ciphertextHash: Uint8Array;
}

/**
 * `Context("nodra/envelope-set", vault_id, epoch_id, [[recipient_id, SHA-256(ciphertext)]…])`
 * (§23.3). The caller supplies the entries already ordered by `recipient_id`; ordering is a rule
 * of the structure, not of the codec, exactly as in §29 (NOTES question 190).
 *
 * Unlike the §23.2 "colecciones con rol" the pairs are **not** `[código uint, valor]`: §23.3 spells
 * the pair out as `[recipient_id, hash]`, and a `recipient_id` is bytes(16), not a role code.
 */
export function envelopeSetContext(
  vaultId: Uint8Array,
  epochId: Uint8Array,
  entries: readonly EnvelopeSetEntry[],
): DomainContext {
  return domainContext(
    "nodra/envelope-set",
    vaultId,
    epochId,
    entries.map((entry) => [entry.recipientId, entry.ciphertextHash]),
  );
}

/**
 * `Context("nodra/envelope-label", vault_id, epoch_id, recipient_id, recipient_type)` (§23.3):
 * the OAEP label of §32.2, and the single reason an envelope moved to another vault, epoch or
 * recipient fails to open (§32.3).
 */
export function envelopeLabelContext(
  vaultId: Uint8Array,
  epochId: Uint8Array,
  recipientId: Uint8Array,
  recipientType: EpochEnvelope["recipient_type"],
): DomainContext {
  return domainContext("nodra/envelope-label", vaultId, epochId, recipientId, recipientType);
}

/** `info` of the content key derivation (§31.2). */
export function contentKeyInfo(blobId: Uint8Array): DomainContext {
  return domainContext("nodra/hkdf/content", blobId);
}

/** `info` of the manifest key derivation (§31.2): the manifest's own `blob_id`, never the content's. */
export function manifestKeyInfo(blobId: Uint8Array): DomainContext {
  return domainContext("nodra/hkdf/manifest", blobId);
}

/** `info` of the dedup key derivation (§31.2). No fields. */
export const DEDUP_KEY_INFO: DomainContext = domainContext("nodra/hkdf/dedup");

/** `info` of the epoch commitment derivation (§31.2). The commitment is public. */
export function epochCommitmentInfo(vaultId: Uint8Array, epochId: Uint8Array): DomainContext {
  return domainContext("nodra/hkdf/epoch-commitment", vaultId, epochId);
}

/**
 * AAD of a content blob (§31.3). It names the vault, the epoch and the blob and **nothing else**:
 * §31.3 keeps `object_id`, `revision_id` and the path out on purpose, so one content blob can be
 * referenced by several revisions (dedup, rename, §9). The binding to an object is the manifest's.
 */
export function contentBlobAad(vaultId: Uint8Array, epochId: Uint8Array, blobId: Uint8Array): DomainContext {
  return domainContext("nodra/aad/content", vaultId, epochId, blobId);
}

/** The revision a manifest blob is bound to by its AAD (§31.3). */
export interface ManifestBinding {
  readonly objectId: Uint8Array;
  readonly revisionId: Uint8Array;
  /** `null` on the revision that creates the object (§8). */
  readonly parentRevisionId: Uint8Array | null;
}

/**
 * AAD of a manifest blob (§31.3). Unlike the content AAD it names the revision, which is what ties
 * a manifest to exactly one place in one object's history: a manifest replayed under another
 * revision, or under another parent, does not open. §13.1 carries `parent_revision_id` on the event
 * precisely so a client can build this AAD without having seen the previous revision.
 */
export function manifestBlobAad(
  vaultId: Uint8Array,
  epochId: Uint8Array,
  blobId: Uint8Array,
  binding: ManifestBinding,
): DomainContext {
  return domainContext(
    "nodra/aad/manifest",
    vaultId,
    epochId,
    blobId,
    binding.objectId,
    binding.revisionId,
    binding.parentRevisionId,
  );
}

/**
 * `Context("nodra/recovery-kit", RecoveryKit)` (§23.3, §27.1): the bytes the kit is *delivered*
 * as — file, printable page or QR. Same nesting decision as the Root Descriptor (NOTES question
 * 189): the structure travels as one field, its NCE map, so the frozen key numbers of §23.4 are
 * normative for the delivered bytes too.
 */
export function recoveryKitContext(kit: RecoveryKit): DomainContext {
  return domainContext("nodra/recovery-kit", toNce(RECOVERY_KIT, kit));
}

/**
 * `Context("nodra/self-test", account_id, nonce)` (§23.3): both the OAEP label of step 1 and the
 * signed message of step 2 of §27.3 — the spec gives one expression for both. `nonce` is
 * bytes(16) (§23.4, last bullet).
 */
export function selfTestContext(accountId: Uint8Array, nonce: Uint8Array): DomainContext {
  return domainContext("nodra/self-test", accountId, nonce);
}

/**
 * `Context("nodra/profile-update", account_id, config_version anterior, SHA-256(NCE(perfil nuevo)))`
 * (§23.3, §35.6): what `SecurityBundle.profile_signature` covers. The *previous* `config_version`
 * is what is signed — the new profile already carries the new one in its own key 6, so signing the
 * old one binds the update to exactly one predecessor and a replay against a later config fails.
 */
export function profileUpdateContext(
  accountId: Uint8Array,
  previousConfigVersion: number,
  profileHash: Uint8Array,
): DomainContext {
  return domainContext("nodra/profile-update", accountId, previousConfigVersion, profileHash);
}

/** `SHA-256(NCE(AccountSecurityProfile))`, the third field of {@link profileUpdateContext}. */
export async function profileHash(profile: AccountSecurityProfile): Promise<Uint8Array> {
  return sha256(encodeRecord(ACCOUNT_SECURITY_PROFILE, profile));
}

/**
 * `Context("nodra/delete-vault", operation_type, account_id, vault_id, root_generation, nonce)`
 * (§35.11 step 3). `operation_type` is in the signed fields, so a `DELETE_VAULT` signature can
 * never be replayed as the `CANCEL_DELETE_VAULT` that undoes it (§35.11 step 5).
 */
export function deleteVaultContext(
  operationType: string,
  accountId: Uint8Array,
  vaultId: Uint8Array,
  rootGeneration: number,
  nonce: Uint8Array,
): DomainContext {
  return domainContext("nodra/delete-vault", operationType, accountId, vaultId, rootGeneration, nonce);
}

/**
 * `Context("nodra/delete-account", operation_type, account_id, root_generation, nonce)` (§35.12
 * step 3). No `vault_id`: an account deletion names no vault, and §23.4 makes `deletion.vault_id`
 * optional for exactly this pair of operations.
 */
export function deleteAccountContext(
  operationType: string,
  accountId: Uint8Array,
  rootGeneration: number,
  nonce: Uint8Array,
): DomainContext {
  return domainContext("nodra/delete-account", operationType, accountId, rootGeneration, nonce);
}

/**
 * `Context("nodra/recovery-request", operation_type, account_id, request_id, kind, root_generation,
 * root_hash)` (§23.3, §35.15). One domain for the request, the veto and the cancellation: the
 * `operation_type` inside the signed bytes is what keeps a request signature from ever counting as a
 * veto or a cancel, and the root inside it makes every record useless after a root change.
 */
export function recoveryRequestContext(
  operationType: string,
  accountId: Uint8Array,
  requestId: Uint8Array,
  kind: string,
  rootGeneration: number,
  rootHash: Uint8Array,
): DomainContext {
  return domainContext("nodra/recovery-request", operationType, accountId, requestId, kind, rootGeneration, rootHash);
}
