// RSA-OAEP-3072 with SHA-256 (§23.1). The only plaintext this carries is a 32-byte `epoch_secret`
// (§32.2), and the OAEP `label` is always `Context("nodra/envelope-label", …)` (§23.3), which is
// what stops an envelope being replayed into another vault, epoch or recipient (§39.1).
import type { ESCROW_SLOTS } from "@nodra/encoding/records";
import { AEAD_KEY_BYTES } from "./aead.js";
import type { AeadKey } from "./aead.js";
import { domainContext } from "./context.js";
import { assertLength, CryptoError } from "./errors.js";
import { sha256 } from "./hash.js";
import { decrypting, subtle } from "./runtime.js";
import type { DomainContext } from "./context.js";
import type { HkdfBase } from "./hkdf.js";
import type { MacKey } from "./hash.js";

export const ENVELOPE_MODULUS_BITS = 3072;
export const EPOCH_SECRET_BYTES = 32;

const RSA_OAEP: RsaHashedKeyGenParams = {
  name: "RSA-OAEP",
  modulusLength: ENVELOPE_MODULUS_BITS,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: "SHA-256",
};
const RSA_OAEP_IMPORT: RsaHashedImportParams = { name: "RSA-OAEP", hash: "SHA-256" };

declare const envelopeBrand: unique symbol;

/** A recipient's RSA-OAEP public key, imported from the SPKI DER stored in the Registry (§30.1). */
export type EnvelopePublicKey = CryptoKey & { readonly [envelopeBrand]: "nodra/envelope-public" };

/**
 * The Session handle of §25.1: non-extractable, `["unwrapKey"]` only. It can turn an envelope into
 * an `EpochKey` and nothing else — §44.3 requires that it cannot `decrypt()`.
 */
export type EnvelopeUnwrapKey = CryptoKey & { readonly [envelopeBrand]: "nodra/envelope-unwrap" };

/**
 * The Operation handle of §25.1: non-extractable, `["decrypt"]`. Only privileged re-enveloping
 * (§33.2) needs the `epoch_secret` as bytes.
 */
export type EnvelopeDecryptKey = CryptoKey & { readonly [envelopeBrand]: "nodra/envelope-decrypt" };

/**
 * An extractable RSA-OAEP private key: freshly generated (§25.2) or the temporary Re-wrap handle
 * of §25.1. It exists only so it can be wrapped, and must be dropped when the operation ends.
 */
export type ExtractableEnvelopePrivateKey = CryptoKey & {
  readonly [envelopeBrand]: "nodra/envelope-extractable";
};

/** Any handle that may decrypt an envelope to raw bytes. */
export type EnvelopeOpeningKey = EnvelopeDecryptKey | ExtractableEnvelopePrivateKey;

export interface EnvelopeKeyPair {
  readonly publicKey: EnvelopePublicKey;
  readonly privateKey: ExtractableEnvelopePrivateKey;
}

/** Generates an Account or recipient encryption key pair (§25.2). The private key is extractable
 * only so it can be wrapped immediately; it is never persisted unwrapped. */
export async function generateEnvelopeKeyPair(): Promise<EnvelopeKeyPair> {
  const pair = (await subtle().generateKey(RSA_OAEP, true, ["encrypt", "decrypt"])) as CryptoKeyPair;
  return {
    publicKey: pair.publicKey as EnvelopePublicKey,
    privateKey: pair.privateKey as ExtractableEnvelopePrivateKey,
  };
}

/** A plugin or trusted browser recipient pair (§30.1): the private half never leaves the device. */
export interface RecipientKeyPair {
  readonly publicKey: EnvelopePublicKey;
  readonly privateKey: EnvelopeUnwrapKey;
}

/**
 * §30.1: "Plugins y trusted browsers se generan con `generateKey(…, extractable = false, …)`: su
 * privada nunca es exportable y su pública (SPKI) sí." The usage list is what splits the pair —
 * Web Crypto gives the public key the `encrypt` usage and the private key `unwrapKey`, and nothing
 * else, so the private half can turn an envelope into an `EpochKey` (§33.1) and can never
 * `decrypt()` one to bytes. `extractable = false` applies to the private key; a generated public
 * key is always extractable, which is how its SPKI reaches the Registry.
 */
export async function generateRecipientKeyPair(): Promise<RecipientKeyPair> {
  const pair = (await subtle().generateKey(RSA_OAEP, false, ["encrypt", "unwrapKey"])) as CryptoKeyPair;
  return {
    publicKey: pair.publicKey as EnvelopePublicKey,
    privateKey: pair.privateKey as EnvelopeUnwrapKey,
  };
}

/** Imports an SPKI DER public key (§23.1 "Clave pública — SPKI DER"). */
export async function importEnvelopePublicKey(spki: Uint8Array): Promise<EnvelopePublicKey> {
  return (await subtle().importKey("spki", spki as BufferSource, RSA_OAEP_IMPORT, true, [
    "encrypt",
  ])) as EnvelopePublicKey;
}

/**
 * Imports a PKCS#8 private key as the Session handle of §25.1. Used when the key arrives already
 * unwrapped; the normal path is {@link unwrapSessionKey}.
 */
export async function importEnvelopeUnwrapKey(pkcs8: Uint8Array): Promise<EnvelopeUnwrapKey> {
  return (await subtle().importKey("pkcs8", pkcs8 as BufferSource, RSA_OAEP_IMPORT, false, [
    "unwrapKey",
  ])) as EnvelopeUnwrapKey;
}

/** Imports a PKCS#8 private key as the Operation handle of §25.1 (`["decrypt"]`). */
export async function importEnvelopeDecryptKey(pkcs8: Uint8Array): Promise<EnvelopeDecryptKey> {
  return (await subtle().importKey("pkcs8", pkcs8 as BufferSource, RSA_OAEP_IMPORT, false, [
    "decrypt",
  ])) as EnvelopeDecryptKey;
}

/** Exports SPKI DER. §25.2: hashes are taken over the bytes actually stored, never a re-export. */
export async function exportEnvelopePublicKey(key: EnvelopePublicKey): Promise<Uint8Array> {
  return new Uint8Array(await subtle().exportKey("spki", key));
}

/** Exports PKCS#8 DER. Only ever done to wrap the key or to place it in a Recovery Kit (§23.1). */
export async function exportEnvelopePrivateKey(key: ExtractableEnvelopePrivateKey): Promise<Uint8Array> {
  return new Uint8Array(await subtle().exportKey("pkcs8", key));
}

/** Encrypts a 32-byte `epoch_secret` under a recipient's public key and an envelope label (§32.2). */
export async function sealEpochSecret(
  key: EnvelopePublicKey,
  label: DomainContext,
  epochSecret: Uint8Array,
): Promise<Uint8Array> {
  assertLength(epochSecret, EPOCH_SECRET_BYTES, "epoch_secret");
  const ciphertext = await subtle().encrypt(
    { name: "RSA-OAEP", label: label as BufferSource },
    key,
    epochSecret as BufferSource,
  );
  return new Uint8Array(ciphertext);
}

/**
 * The normal read path of §33.1: turns an envelope straight into the `EpochKey` of §31.1 without
 * the `epoch_secret` ever existing as bytes. Web Crypto gives back a non-extractable HKDF key.
 */
export async function unwrapEpochKey(
  session: EnvelopeUnwrapKey,
  label: DomainContext,
  ciphertext: Uint8Array,
): Promise<HkdfBase> {
  return decrypting("envelope unwrap", async () =>
    (await subtle().unwrapKey(
      "raw",
      ciphertext as BufferSource,
      session,
      { name: "RSA-OAEP", label: label as BufferSource },
      { name: "HKDF" },
      false,
      ["deriveKey", "deriveBits"],
    )) as HkdfBase,
  );
}

/**
 * Privileged re-enveloping (§33.2) and epoch creation need the raw secret. The caller must zeroize
 * the result when the operation ends (§44.5: Nodra never persists an `epoch_secret`).
 */
export async function openEpochSecret(
  key: EnvelopeOpeningKey,
  label: DomainContext,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const plaintext = await unsafeOpenWithLabel(key, label, ciphertext);
  assertLength(plaintext, EPOCH_SECRET_BYTES, "decrypted epoch_secret");
  return plaintext;
}

/**
 * @internal OAEP decryption of an arbitrary plaintext with arbitrary label bytes, for the
 * Wycheproof known-answer vectors. Production code uses {@link openEpochSecret}.
 */
export async function unsafeOpenWithLabel(
  key: EnvelopeOpeningKey,
  label: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  return decrypting("RSA-OAEP decrypt", async () => {
    const plaintext = await subtle().decrypt(
      { name: "RSA-OAEP", label: label as BufferSource },
      key,
      ciphertext as BufferSource,
    );
    return new Uint8Array(plaintext);
  });
}

/** @internal Imports a PKCS#8 private key as an extractable `["decrypt"]` handle (test vectors, §35.6). */
export async function importExtractableEnvelopePrivateKey(
  pkcs8: Uint8Array,
): Promise<ExtractableEnvelopePrivateKey> {
  return (await subtle().importKey("pkcs8", pkcs8 as BufferSource, RSA_OAEP_IMPORT, true, [
    "decrypt",
  ])) as ExtractableEnvelopePrivateKey;
}

// --- §11.3 write capability ------------------------------------------------------------------

/** The `nonce` of the §11.3 proof of possession: 32 bytes, which is also an HMAC-SHA-256 key. */
export const CAPABILITY_NONCE_BYTES = 32;

/**
 * §11.3 step 3: `RSA-OAEP-Encrypt(public key of the recipient, nonce, label = Context(...))`.
 * Same primitive as {@link sealEpochSecret} with a different plaintext and a different label
 * domain; kept apart so no call site can pass an `epoch_secret` where a capability nonce belongs.
 */
export async function sealCapabilityNonce(
  key: EnvelopePublicKey,
  label: DomainContext,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  assertLength(nonce, CAPABILITY_NONCE_BYTES, "write capability nonce");
  return new Uint8Array(
    await subtle().encrypt({ name: "RSA-OAEP", label: label as BufferSource }, key, nonce as BufferSource),
  );
}

/**
 * §11.3 step 4, first bullet: with an `["unwrapKey"]` private key the client turns the sealed nonce
 * straight into a non-extractable HMAC-SHA-256 `["sign"]` key. The nonce never exists as bytes on
 * this path — the property Annex B verifies, and the reason a Session handle can prove possession
 * without ever being able to `decrypt()` (§25.1).
 */
export async function unwrapCapabilityMacKey(
  session: EnvelopeUnwrapKey,
  label: DomainContext,
  ciphertext: Uint8Array,
): Promise<MacKey> {
  return decrypting("capability nonce unwrap", async () =>
    (await subtle().unwrapKey(
      "raw",
      ciphertext as BufferSource,
      session,
      { name: "RSA-OAEP", label: label as BufferSource },
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    )) as MacKey,
  );
}

/**
 * §11.3 step 4, second bullet: a Recovery Kit key is `["decrypt"]`, so the nonce does exist as
 * bytes for as long as it takes to import it. The caller zeroizes the buffer the moment the
 * `MacKey` exists — which is why this returns both and not only the key.
 */
export async function openCapabilityNonce(
  key: EnvelopeOpeningKey,
  label: DomainContext,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const nonce = await unsafeOpenWithLabel(key, label, ciphertext);
  assertLength(nonce, CAPABILITY_NONCE_BYTES, "decrypted write capability nonce");
  return nonce;
}

// --- ADR-021 escrow (§3.6, §23.3, §23.4, §24.2; crypto_version = 2) ---------------------------------
//
// One pipeline, the same RSA-OAEP-3072/SHA-256 as the envelopes. What travels is always 32 bytes:
// the `RootUnlockKey` (slot UNLOCK) or the random AES-256-GCM key that seals the Recovery private
// keys (slot RECOVERY, `payload_blob` sealed with `seal`/`unseal` under the same Context as AAD).
// The client wraps to the Escrow Key; the Worker opens with it and re-wraps to the client's
// ephemeral key (a `generateRecipientKeyPair` pair: non-extractable, `["unwrapKey"]` only), and the
// client unwraps straight into a non-extractable handle.

/** `slot` of `EscrowSlot` / `EscrowRewrap` (§23.4). */
export type EscrowSlotName = (typeof ESCROW_SLOTS)[number];

/** What an escrow slot or re-wrap carries: a `RootUnlockKey` or an AES-256-GCM key, 32 bytes. */
export const ESCROW_SECRET_BYTES = 32;

const ID_BYTES = 16;

/** `Context("nodra/escrow", account_id, key_id, slot)`: OAEP label and AAD of an escrow slot (§23.3). */
export function escrowLabel(accountId: Uint8Array, keyId: Uint8Array, slot: EscrowSlotName): DomainContext {
  assertLength(accountId, ID_BYTES, "account_id");
  assertLength(keyId, ID_BYTES, "key_id");
  return domainContext("nodra/escrow", accountId, keyId, slot);
}

/**
 * `Context("nodra/escrow-rewrap", account_id, SHA-256(ephemeral SPKI), slot)`: OAEP label and AAD of
 * the ephemeral re-wrap (§23.3). `ephemeralSpki` is the exact SPKI DER the client sent.
 */
export async function escrowRewrapLabel(
  accountId: Uint8Array,
  ephemeralSpki: Uint8Array,
  slot: EscrowSlotName,
): Promise<DomainContext> {
  assertLength(accountId, ID_BYTES, "account_id");
  return domainContext("nodra/escrow-rewrap", accountId, await sha256(ephemeralSpki), slot);
}

/**
 * Wraps a 32-byte escrow secret under an RSA-OAEP public key and an escrow label: the client to the
 * Escrow Key (`escrowLabel`), or the Worker to the client's ephemeral key (`escrowRewrapLabel`).
 */
export async function sealEscrowKey(
  key: EnvelopePublicKey,
  label: DomainContext,
  secret: Uint8Array,
): Promise<Uint8Array> {
  assertLength(secret, ESCROW_SECRET_BYTES, "escrow secret");
  return new Uint8Array(
    await subtle().encrypt({ name: "RSA-OAEP", label: label as BufferSource }, key, secret as BufferSource),
  );
}

/**
 * The Worker side (§3.6): opens a slot with the Escrow Key private half. The result exists as bytes
 * only for the instant it takes to re-wrap it (§24.2); the caller zeroizes it and never logs it.
 */
export async function openEscrowKey(
  key: EnvelopeOpeningKey,
  label: DomainContext,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const secret = await unsafeOpenWithLabel(key, label, ciphertext);
  assertLength(secret, ESCROW_SECRET_BYTES, "opened escrow secret");
  return secret;
}

/**
 * §24.2 step 4: the client turns the re-wrapped `RootUnlockKey` straight into `RootUnlockBase` (§24),
 * a non-extractable HKDF handle; the bytes never exist on the client. An HKDF key does not expose its
 * length, so the plaintext is first unwrapped as a throwaway HMAC key (whose `length` is the raw
 * length in bits) and anything but 32 bytes is rejected before it can become an HKDF base.
 */
export async function unwrapRootUnlockBase(
  ephemeral: EnvelopeUnwrapKey,
  label: DomainContext,
  ciphertext: Uint8Array,
): Promise<HkdfBase> {
  const probe = await decrypting("escrow unwrap", async () =>
    subtle().unwrapKey(
      "raw",
      ciphertext as BufferSource,
      ephemeral,
      { name: "RSA-OAEP", label: label as BufferSource },
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    ),
  );
  const bits = (probe.algorithm as HmacKeyAlgorithm).length;
  if (bits !== ESCROW_SECRET_BYTES * 8) {
    throw new CryptoError("BAD_LENGTH", `RootUnlockKey must be ${ESCROW_SECRET_BYTES * 8} bits, got ${bits}`);
  }
  return decrypting("escrow unwrap", async () =>
    (await subtle().unwrapKey(
      "raw",
      ciphertext as BufferSource,
      ephemeral,
      { name: "RSA-OAEP", label: label as BufferSource },
      { name: "HKDF" },
      false,
      ["deriveKey", "deriveBits"],
    )) as HkdfBase,
  );
}

/**
 * §35.7 (Managed): the client turns the re-wrapped RECOVERY key into the non-extractable AES-256-GCM
 * key that opens the re-wrap `payload_blob`. Anything but 256 bits is rejected, so a 16-byte
 * plaintext can never become an AES-128 key.
 */
export async function unwrapEscrowPayloadKey(
  ephemeral: EnvelopeUnwrapKey,
  label: DomainContext,
  ciphertext: Uint8Array,
): Promise<AeadKey> {
  const key = await decrypting("escrow unwrap", async () =>
    subtle().unwrapKey(
      "raw",
      ciphertext as BufferSource,
      ephemeral,
      { name: "RSA-OAEP", label: label as BufferSource },
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    ),
  );
  const bits = (key.algorithm as AesKeyAlgorithm).length;
  if (bits !== AEAD_KEY_BYTES * 8) {
    throw new CryptoError("BAD_LENGTH", `escrow payload key must be ${AEAD_KEY_BYTES * 8} bits, got ${bits}`);
  }
  return key as AeadKey;
}
