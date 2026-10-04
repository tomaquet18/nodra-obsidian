// Epochs (§31–§33): creating one, sealing its envelopes, opening an envelope with the §32.3
// validation, and deriving the keys §31.2 names from the Epoch Key.
//
// Three rules shape this file.
//
//   1. **The `epoch_secret` exists as bytes for exactly one function.** §31.1 allows it in two
//      moments only, and this slice owns the first: {@link createEpoch} generates it, seals every
//      envelope, imports the HKDF handle, derives the commitment and zeroizes it in a `finally`.
//      Nothing else in the package returns raw secret bytes, and nothing persists one (§44.5).
//   2. **The label of an open is built from what the *client* expects, never from the envelope.**
//      §32.3's whole point is that an envelope moved to another vault, epoch or recipient must
//      fail. Reading `recipient_id` out of the envelope to build the label would reconstruct the
//      label the attacker wants and defeat the check, so {@link openEpoch} takes the expected
//      identity as an argument and rejects an envelope that declares anything else.
//   3. **The commitment comparison is not optional.** §32.3 step 3 is the only cryptographic
//      validation an envelope ever gets — the Worker can check presence and structure and nothing
//      more — so a successful unwrap that does not reproduce `descriptor.epoch_commitment` is
//      `BROKEN_OR_WRONG_ENVELOPE` and the key is dropped.
//
// Pure domain plus the `randomBytes` port: no network, no storage, no DOM, no clock (§32 has no
// timestamps).
import {
  EMPTY_SALT,
  EPOCH_SECRET_BYTES,
  deriveAeadKey,
  deriveBits,
  deriveMacKey,
  hashContext,
  importEnvelopePublicKey,
  importHkdfBase,
  sealEpochSecret,
  sha256,
  signContext,
  timingSafeEqual,
  unwrapEpochKey,
  zeroize,
} from "@nodra/crypto";
import type {
  AeadKey,
  AnySigningKey,
  EnvelopeUnwrapKey,
  HkdfBase,
  MacKey,
} from "@nodra/crypto";
import type { EpochDescriptor, EpochEnvelope, Registry, RootDescriptor } from "@nodra/encoding/records";
import {
  DEDUP_KEY_INFO,
  contentKeyInfo,
  envelopeLabelContext,
  envelopeSetContext,
  epochCommitmentInfo,
  epochDescriptorContext,
  manifestKeyInfo,
} from "./contexts.js";
import type { EnvelopeSetEntry } from "./contexts.js";
import { KeyLifecycleError } from "./errors.js";
import type { Outcome } from "./errors.js";
import { defaultPorts } from "./ports.js";
import type { KeyLifecyclePorts } from "./ports.js";
import { activeRecipients, compareRecipientIds } from "./registry.js";

/** §31.2: the commitment is 256 derived bits. */
export const EPOCH_COMMITMENT_BITS = 256;

/** §23.4: `algorithm_version` 1 is RSA-OAEP-3072 / SHA-256. */
export const ENVELOPE_ALGORITHM_VERSION = 1;

/** §30.1: `recipient_id` of ACCOUNT and RECOVERY is the first 16 bytes of `SHA-256(SPKI)`. */
export const RECIPIENT_ID_BYTES = 16;

/** Every recipient type an envelope can name (§30.1), including the two that live in the root. */
export type EnvelopeRecipientType = EpochEnvelope["recipient_type"];

/** A public key an envelope can be sealed to, in the three forms §32.2 needs (§30.1). */
export interface EnvelopeRecipient {
  readonly recipientId: Uint8Array;
  readonly type: EnvelopeRecipientType;
  /** SPKI DER of the RSA-OAEP-3072 public key. */
  readonly publicKey: Uint8Array;
}

/** Who an envelope is being opened *as*: the client's own identity, never the envelope's (§32.3). */
export interface RecipientIdentity {
  readonly recipientId: Uint8Array;
  readonly type: EnvelopeRecipientType;
}

/**
 * An opened Epoch Key (§31.1) with the identity it was proved against. Carrying the vault and
 * epoch with the handle is what stops a caller deriving a content key for the wrong epoch: the
 * AADs of §31.3 name both, and they come from here rather than from a second argument.
 */
export interface EpochKey {
  readonly vaultId: Uint8Array;
  readonly epochId: Uint8Array;
  /** Non-extractable HKDF handle; §31.1 forbids its bytes existing on the normal path. */
  readonly key: HkdfBase;
}

// --- Recipient identity ---------------------------------------------------------------------

/** `recipient_id` of an ACCOUNT or RECOVERY key: first 16 bytes of `SHA-256(SPKI)` (§30.1). */
export async function rootRecipientId(spki: Uint8Array): Promise<Uint8Array> {
  return (await sha256(spki)).slice(0, RECIPIENT_ID_BYTES);
}

/** The two root recipients of §30.1, derived from a verified Root Descriptor (§28.1). */
export async function rootRecipients(root: RootDescriptor): Promise<readonly EnvelopeRecipient[]> {
  return [
    {
      recipientId: await rootRecipientId(root.account_encryption_public_key),
      type: "ACCOUNT",
      publicKey: root.account_encryption_public_key,
    },
    {
      recipientId: await rootRecipientId(root.recovery_encryption_public_key),
      type: "RECOVERY",
      publicKey: root.recovery_encryption_public_key,
    },
  ];
}

/**
 * §36.1 step 2 as data: ACCOUNT and RECOVERY of the pending root, plus every ACTIVE recipient of
 * the pending registry. A REVOKED recipient is absent by construction — that is the whole point
 * of a rotation — and the two structures must be the *pending* ones of the bundle (§36.2).
 */
export async function epochRecipients(
  root: RootDescriptor,
  registry: Registry,
): Promise<readonly EnvelopeRecipient[]> {
  return [
    ...(await rootRecipients(root)),
    ...activeRecipients(registry).map((recipient) => ({
      recipientId: recipient.recipient_id,
      type: recipient.type,
      publicKey: recipient.public_key,
    })),
  ];
}

// --- Hashing and building -----------------------------------------------------------------

/** `descriptor_hash = SHA-256(Context("nodra/epoch-descriptor", descriptor sin signature))` (§32.1). */
export async function epochDescriptorHash(descriptor: Omit<EpochDescriptor, "signature">): Promise<Uint8Array> {
  return hashContext(epochDescriptorContext(descriptor));
}

/**
 * `envelope_set_hash` (§23.3, §32.1): over `[[recipient_id, SHA-256(ciphertext)]…]` ordered by
 * `recipient_id`. Sorting happens here so a caller cannot change the hash by reordering the array
 * it passes; §34's duplicate detection is a separate question and lives in `coverage.ts`.
 */
export async function envelopeSetHash(
  vaultId: Uint8Array,
  epochId: Uint8Array,
  envelopes: readonly EpochEnvelope[],
): Promise<Uint8Array> {
  const entries: EnvelopeSetEntry[] = [];
  for (const envelope of envelopes) {
    entries.push({ recipientId: envelope.recipient_id, ciphertextHash: await sha256(envelope.ciphertext) });
  }
  entries.sort((a, b) => compareRecipientIds(a.recipientId, b.recipientId));
  return hashContext(envelopeSetContext(vaultId, epochId, entries));
}

/** Signs `Context("nodra/epoch-descriptor", …)` with the Account Signing Key of `root_generation`. */
export async function signEpochDescriptor(
  draft: Omit<EpochDescriptor, "signature">,
  key: AnySigningKey,
): Promise<EpochDescriptor> {
  return { ...draft, signature: await signContext(key, epochDescriptorContext(draft)) };
}

/** Seals one envelope: `RSA-OAEP(recipient, epoch_secret, label)` of §32.2. */
export async function sealEnvelope(
  recipient: EnvelopeRecipient,
  vaultId: Uint8Array,
  epochId: Uint8Array,
  epochSecret: Uint8Array,
): Promise<EpochEnvelope> {
  const publicKey = await importEnvelopePublicKey(recipient.publicKey);
  const label = envelopeLabelContext(vaultId, epochId, recipient.recipientId, recipient.type);
  return {
    vault_id: vaultId,
    epoch_id: epochId,
    recipient_id: recipient.recipientId,
    recipient_type: recipient.type,
    ciphertext: await sealEpochSecret(publicKey, label, epochSecret),
    algorithm_version: ENVELOPE_ALGORITHM_VERSION,
  };
}

// --- Creation (§36.1, the client half) ------------------------------------------------------

/** What a new descriptor links back to: the vault's current epoch, or null for a new vault (§32.1). */
export interface PreviousEpoch {
  readonly epochId: Uint8Array;
  readonly descriptorHash: Uint8Array;
}

export interface CreateEpochRequest {
  readonly vaultId: Uint8Array;
  /** UUIDv7 of the new epoch (§23.2). Supplied by the caller; this package has no id generator. */
  readonly epochId: Uint8Array;
  readonly previous: PreviousEpoch | null;
  /**
   * The **pending** root of the bundle: its generation, `root_hash` (§36.2) and `crypto_version`,
   * which §32.1 says the new descriptor MUST carry.
   */
  readonly root: { readonly generation: number; readonly hash: Uint8Array; readonly cryptoVersion: number };
  /** The **pending** registry of the bundle: its version and `registry_hash` (§36.2). */
  readonly registry: { readonly version: number; readonly hash: Uint8Array };
  /** §36.1 step 2; build it with {@link epochRecipients} from those same pending structures. */
  readonly recipients: readonly EnvelopeRecipient[];
  /** Account Signing Key of `root.generation` (§32.1). */
  readonly signingKey: AnySigningKey;
  readonly ports?: KeyLifecyclePorts;
}

export interface CreatedEpoch {
  readonly descriptor: EpochDescriptor;
  readonly descriptorHash: Uint8Array;
  /** In `recipients` order; `envelope_set_hash` sorts them itself. */
  readonly envelopes: readonly EpochEnvelope[];
  /** The Epoch Key of §31.1, ready to use — the creator never re-opens its own envelope. */
  readonly epochKey: EpochKey;
}

/**
 * §36.1 in order: secret, envelopes, HKDF import, commitment, zeroize, signed descriptor. The
 * order matters for one reason only — the secret's bytes must be gone before anything that can
 * reject (signing, hashing) runs — and the `finally` guarantees it even when a recipient's SPKI
 * turns out not to import.
 *
 * Like every other builder in this package it enforces no policy: it will happily seal a duplicate
 * recipient or link to the wrong previous epoch, and {@link verifyEpochChain} and the coverage
 * checker are the single place those rules live.
 */
export async function createEpoch(request: CreateEpochRequest): Promise<CreatedEpoch> {
  const ports = request.ports ?? defaultPorts;
  const { vaultId, epochId } = request;
  const epochSecret = ports.randomBytes(EPOCH_SECRET_BYTES);
  if (epochSecret.length !== EPOCH_SECRET_BYTES) {
    throw new KeyLifecycleError(`epoch_secret must be ${EPOCH_SECRET_BYTES} bytes, got ${epochSecret.length}`);
  }
  let envelopes: EpochEnvelope[];
  let base: HkdfBase;
  let commitment: Uint8Array;
  try {
    envelopes = [];
    for (const recipient of request.recipients) {
      envelopes.push(await sealEnvelope(recipient, vaultId, epochId, epochSecret));
    }
    base = await importHkdfBase(epochSecret);
    commitment = await deriveEpochCommitment(base, vaultId, epochId);
  } finally {
    zeroize(epochSecret);
  }

  const draft: Omit<EpochDescriptor, "signature"> = {
    vault_id: vaultId,
    epoch_id: epochId,
    previous_epoch_id: request.previous === null ? null : request.previous.epochId,
    previous_descriptor_hash: request.previous === null ? null : request.previous.descriptorHash,
    root_generation: request.root.generation,
    root_hash: request.root.hash,
    registry_version: request.registry.version,
    registry_hash: request.registry.hash,
    epoch_commitment: commitment,
    envelope_set_hash: await envelopeSetHash(vaultId, epochId, envelopes),
    crypto_version: request.root.cryptoVersion,
  };
  const descriptor = await signEpochDescriptor(draft, request.signingKey);
  return {
    descriptor,
    descriptorHash: await epochDescriptorHash(draft),
    envelopes,
    epochKey: { vaultId, epochId, key: base },
  };
}

// --- Opening an envelope (§32.3) ------------------------------------------------------------

export type EpochOpenFailureCode =
  /**
   * The envelope declares another vault, epoch, recipient or `algorithm_version`. Caught before
   * any crypto runs: the label is built from what the client expects, so this envelope would fail
   * to open anyway — naming the mismatch is more useful than "broken".
   */
  | "ENVELOPE_MISBOUND"
  /**
   * §32.3: the unwrap failed, or the commitment does not match the signed descriptor. One code for
   * both, because the spec gives one: a wrong key, a moved envelope and a corrupted ciphertext are
   * the same answer — do not use this key.
   */
  | "BROKEN_OR_WRONG_ENVELOPE";

export interface EpochOpenFailure {
  readonly code: EpochOpenFailureCode;
  readonly message: string;
}

export interface OpenEpochRequest {
  /** A descriptor whose signature and chain were already accepted by {@link verifyEpochChain}. */
  readonly descriptor: EpochDescriptor;
  readonly envelope: EpochEnvelope;
  /** The opening client's own identity (§32.3): what the expected label is built from. */
  readonly recipient: RecipientIdentity;
  /** The Session handle of §25.1 — `["unwrapKey"]`, so the secret never becomes bytes (§33.1). */
  readonly privateKey: EnvelopeUnwrapKey;
}

/**
 * §33.1 followed by the three steps of §32.3: unwrap with the expected label, derive the
 * commitment, compare it with the signed descriptor. Any failure returns the key nowhere.
 */
export async function openEpoch(request: OpenEpochRequest): Promise<Outcome<EpochKey, EpochOpenFailure>> {
  const { descriptor, envelope, recipient } = request;
  const vaultId = descriptor.vault_id;
  const epochId = descriptor.epoch_id;

  const misbound = describeMisbinding(envelope, vaultId, epochId, recipient);
  if (misbound !== null) return { ok: false, failure: { code: "ENVELOPE_MISBOUND", message: misbound } };

  const label = envelopeLabelContext(vaultId, epochId, recipient.recipientId, recipient.type);
  let base: HkdfBase;
  try {
    base = await unwrapEpochKey(request.privateKey, label, envelope.ciphertext);
  } catch {
    return {
      ok: false,
      failure: { code: "BROKEN_OR_WRONG_ENVELOPE", message: "the envelope did not unwrap under this key and label" },
    };
  }
  const commitment = await deriveEpochCommitment(base, vaultId, epochId);
  if (!timingSafeEqual(commitment, descriptor.epoch_commitment)) {
    return {
      ok: false,
      failure: {
        code: "BROKEN_OR_WRONG_ENVELOPE",
        message: "the derived epoch commitment does not match the signed descriptor",
      },
    };
  }
  return { ok: true, value: { vaultId, epochId, key: base } };
}

function describeMisbinding(
  envelope: EpochEnvelope,
  vaultId: Uint8Array,
  epochId: Uint8Array,
  recipient: RecipientIdentity,
): string | null {
  if (!timingSafeEqual(envelope.vault_id, vaultId)) return "the envelope names another vault";
  if (!timingSafeEqual(envelope.epoch_id, epochId)) return "the envelope names another epoch";
  if (!timingSafeEqual(envelope.recipient_id, recipient.recipientId)) return "the envelope names another recipient";
  if (envelope.recipient_type !== recipient.type) return "the envelope names another recipient type";
  if (envelope.algorithm_version !== ENVELOPE_ALGORITHM_VERSION) {
    return `unsupported envelope algorithm_version ${envelope.algorithm_version}`;
  }
  return null;
}

// --- Using an Epoch Key (§31.2, §33) --------------------------------------------------------

/** `deriveBits(Context("nodra/hkdf/epoch-commitment", vault_id, epoch_id))`, 256 bits (§31.2). */
export async function deriveEpochCommitment(
  base: HkdfBase,
  vaultId: Uint8Array,
  epochId: Uint8Array,
): Promise<Uint8Array> {
  return deriveBits(base, { salt: EMPTY_SALT, info: epochCommitmentInfo(vaultId, epochId) }, EPOCH_COMMITMENT_BITS);
}

/** Content key of §31.2: AES-GCM-256, one per `blob_id`. */
export async function deriveContentKey(epoch: EpochKey, blobId: Uint8Array): Promise<AeadKey> {
  return deriveAeadKey(epoch.key, { salt: EMPTY_SALT, info: contentKeyInfo(blobId) });
}

/**
 * Manifest key of §31.2: AES-GCM-256, derived from the **manifest's** `blob_id`, so re-encrypting
 * the same revision in another attempt produces a different key.
 */
export async function deriveManifestKey(epoch: EpochKey, manifestBlobId: Uint8Array): Promise<AeadKey> {
  return deriveAeadKey(epoch.key, { salt: EMPTY_SALT, info: manifestKeyInfo(manifestBlobId) });
}

/**
 * Dedup key of §31.2: HMAC-SHA-256, `["sign"]`. §31.4 takes the fingerprint with the key of the
 * **content** epoch, never the manifest's — which is why this returns a key rather than computing
 * the fingerprint from an `EpochKey` the caller happens to hold.
 */
export async function deriveDedupKey(epoch: EpochKey): Promise<MacKey> {
  return deriveMacKey(epoch.key, { salt: EMPTY_SALT, info: DEDUP_KEY_INFO });
}

/** Lowercase hex of an id, for use as a `Map` key. Ids are 16 opaque bytes (§23.2). */
export function idKey(id: Uint8Array): string {
  let out = "";
  for (const byte of id) out += byte.toString(16).padStart(2, "0");
  return out;
}
