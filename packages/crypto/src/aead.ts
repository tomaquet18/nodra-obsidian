// AES-256-GCM (§23.1) and the generic blob format of §23.4/§31.3:
//     blob = nonce (12 bytes) ‖ ciphertext with 128-bit tag
// The nonce is freshly random on every encryption and there is no public way to supply one,
// so the "same key, same nonce" catastrophe is unreachable through this API.
import { assertLength, CryptoError } from "./errors.js";
import { concatBytes, randomBytes } from "./bytes.js";
import { decrypting, subtle } from "./runtime.js";
import type { DomainContext } from "./context.js";

export const AEAD_KEY_BYTES = 32;
export const AEAD_NONCE_BYTES = 12;
export const AEAD_TAG_BYTES = 16;
/** Smallest possible blob: nonce plus the tag of an empty plaintext. */
export const AEAD_BLOB_OVERHEAD_BYTES = AEAD_NONCE_BYTES + AEAD_TAG_BYTES;

const TAG_BITS = AEAD_TAG_BYTES * 8;

declare const aeadKeyBrand: unique symbol;
/** An AES-256-GCM key handle with `["encrypt", "decrypt"]`. Never extractable. */
export type AeadKey = CryptoKey & { readonly [aeadKeyBrand]: "nodra/aead" };

/**
 * Imports 32 raw bytes as an AES-256-GCM key. Production keys are derived with HKDF (§31.2, §24);
 * this exists for test vectors and for keys that arrive as bytes from outside Web Crypto.
 */
export async function importAeadKey(raw: Uint8Array): Promise<AeadKey> {
  assertLength(raw, AEAD_KEY_BYTES, "AES-256-GCM key");
  return (await subtle().importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ])) as AeadKey;
}

/**
 * Encrypts with a fresh random nonce and returns `nonce ‖ ciphertext‖tag`.
 * `aad` is a `DomainContext`, so the AADs of §31.3 and §26 cannot be forgotten or mistyped.
 */
export async function seal(key: AeadKey, aad: DomainContext, plaintext: Uint8Array): Promise<Uint8Array> {
  return unsafeSealWithNonce(key, randomBytes(AEAD_NONCE_BYTES), aad, plaintext);
}

/** Authenticates and decrypts a `nonce ‖ ciphertext‖tag` blob. */
export async function unseal(key: AeadKey, aad: DomainContext, blob: Uint8Array): Promise<Uint8Array> {
  if (blob.length < AEAD_BLOB_OVERHEAD_BYTES) {
    throw new CryptoError(
      "BAD_LENGTH",
      `AES-GCM blob must be at least ${AEAD_BLOB_OVERHEAD_BYTES} bytes, got ${blob.length}`,
    );
  }
  const nonce = blob.subarray(0, AEAD_NONCE_BYTES);
  const ciphertext = blob.subarray(AEAD_NONCE_BYTES);
  return decrypting("AES-GCM open", async () => {
    const params = { name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource, tagLength: TAG_BITS };
    return new Uint8Array(await subtle().decrypt(params, key, ciphertext as BufferSource));
  });
}

/**
 * @internal Encryption with a caller-chosen nonce. Reachable only from inside this package and
 * its tests (the package `exports` map publishes nothing but the root). Known-answer vectors need
 * a fixed nonce; production code must use {@link seal}, which never repeats one.
 */
export async function unsafeSealWithNonce(
  key: AeadKey,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  assertLength(nonce, AEAD_NONCE_BYTES, "AES-GCM nonce");
  const params = { name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource, tagLength: TAG_BITS };
  const ciphertext = new Uint8Array(await subtle().encrypt(params, key, plaintext as BufferSource));
  return concatBytes(nonce, ciphertext);
}

/** Splits a blob into its nonce and its ciphertext‖tag, for vector checks and diagnostics. */
export function splitBlob(blob: Uint8Array): { nonce: Uint8Array; ciphertext: Uint8Array } {
  if (blob.length < AEAD_BLOB_OVERHEAD_BYTES) {
    throw new CryptoError("BAD_LENGTH", `AES-GCM blob must be at least ${AEAD_BLOB_OVERHEAD_BYTES} bytes`);
  }
  return { nonce: blob.subarray(0, AEAD_NONCE_BYTES), ciphertext: blob.subarray(AEAD_NONCE_BYTES) };
}
