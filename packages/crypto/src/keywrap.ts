// `WrappedPrivateKey` (§23.4): `wrapKey("pkcs8")` under AES-256-GCM with the `AccountKeyWrapKey`
// of §24, stored in the generic blob format `nonce ‖ ciphertext‖tag`.
//
// Every unwrap entry point below is one row of the handle table of §25.1. There is no generic
// "unwrap with these usages" function on purpose: the five handles are the whole vocabulary, and
// a reviewer can see at the call site which one a piece of code asked for.
import { CryptoError } from "./errors.js";
import { concatBytes, randomBytes } from "./bytes.js";
import { decrypting, subtle } from "./runtime.js";
import { AEAD_BLOB_OVERHEAD_BYTES, AEAD_NONCE_BYTES, AEAD_TAG_BYTES } from "./aead.js";
import type { DomainContext } from "./context.js";
import type {
  EnvelopeDecryptKey,
  EnvelopeUnwrapKey,
  ExtractableEnvelopePrivateKey,
} from "./envelope.js";
import type { ExtractableSigningKey, SigningKey } from "./signature.js";

declare const keyWrapBrand: unique symbol;

/** The `AccountKeyWrapKey` of §24: AES-256-GCM limited to `["wrapKey", "unwrapKey"]`. */
export type KeyWrapKey = CryptoKey & { readonly [keyWrapBrand]: "nodra/keywrap" };

/** The `key_role` values of §25 that select the AAD of a wrapped account private key. */
export type AccountKeyRole = "ACCOUNT_ENCRYPTION" | "ACCOUNT_SIGNING";

/** A private key that may be wrapped: it must have been created or imported as extractable. */
export type WrappablePrivateKey = ExtractableEnvelopePrivateKey | ExtractableSigningKey;

const RSA_OAEP_IMPORT: RsaHashedImportParams = { name: "RSA-OAEP", hash: "SHA-256" };
const ECDSA_IMPORT: EcKeyImportParams = { name: "ECDSA", namedCurve: "P-256" };

function gcmParams(nonce: Uint8Array, aad: DomainContext): AesGcmParams {
  return {
    name: "AES-GCM",
    iv: nonce as BufferSource,
    additionalData: aad as BufferSource,
    tagLength: AEAD_TAG_BYTES * 8,
  };
}

function split(blob: Uint8Array): { nonce: Uint8Array; ciphertext: Uint8Array } {
  if (blob.length < AEAD_BLOB_OVERHEAD_BYTES) {
    throw new CryptoError("BAD_LENGTH", `WrappedPrivateKey blob must be at least ${AEAD_BLOB_OVERHEAD_BYTES} bytes`);
  }
  return { nonce: blob.subarray(0, AEAD_NONCE_BYTES), ciphertext: blob.subarray(AEAD_NONCE_BYTES) };
}

/**
 * Wraps a private key as PKCS#8 under the `AccountKeyWrapKey`, with a fresh random nonce.
 * `aad` is `Context("nodra/aad/account-private-key", account_id, key_role)` (§23.3), which is what
 * makes a keyset blob refuse to open under the wrong role or the wrong account (§44.3).
 */
export async function wrapPrivateKey(
  wrappingKey: KeyWrapKey,
  aad: DomainContext,
  key: WrappablePrivateKey,
): Promise<Uint8Array> {
  const nonce = randomBytes(AEAD_NONCE_BYTES);
  const wrapped = new Uint8Array(await subtle().wrapKey("pkcs8", key, wrappingKey, gcmParams(nonce, aad)));
  return concatBytes(nonce, wrapped);
}

async function unwrap(
  wrappingKey: KeyWrapKey,
  aad: DomainContext,
  blob: Uint8Array,
  algorithm: RsaHashedImportParams | EcKeyImportParams,
  extractable: boolean,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  const { nonce, ciphertext } = split(blob);
  return decrypting("WrappedPrivateKey unwrap", () =>
    subtle().unwrapKey(
      "pkcs8",
      ciphertext as BufferSource,
      wrappingKey,
      gcmParams(nonce, aad),
      algorithm,
      extractable,
      usages,
    ),
  );
}

/** §25.1 Session: Account Encryption, non-extractable, `["unwrapKey"]`. Lives while unlocked. */
export async function unwrapSessionKey(
  wrappingKey: KeyWrapKey,
  aad: DomainContext,
  blob: Uint8Array,
): Promise<EnvelopeUnwrapKey> {
  return (await unwrap(wrappingKey, aad, blob, RSA_OAEP_IMPORT, false, ["unwrapKey"])) as EnvelopeUnwrapKey;
}

/** §25.1 Operation: Account Encryption, non-extractable, `["decrypt"]`. Never persisted. */
export async function unwrapOperationKey(
  wrappingKey: KeyWrapKey,
  aad: DomainContext,
  blob: Uint8Array,
): Promise<EnvelopeDecryptKey> {
  return (await unwrap(wrappingKey, aad, blob, RSA_OAEP_IMPORT, false, ["decrypt"])) as EnvelopeDecryptKey;
}

/** §25.1 Signing: Account Signing, non-extractable, `["sign"]`. Never persisted. */
export async function unwrapSigningKey(
  wrappingKey: KeyWrapKey,
  aad: DomainContext,
  blob: Uint8Array,
): Promise<SigningKey> {
  return (await unwrap(wrappingKey, aad, blob, ECDSA_IMPORT, false, ["sign"])) as SigningKey;
}

/**
 * §25.1 Re-wrap temporal (Account Encryption): extractable, declared `["decrypt"]` because Web
 * Crypto refuses an empty usage list on a private key import, although §35.6 only re-wraps it.
 */
export async function unwrapRewrapEncryptionKey(
  wrappingKey: KeyWrapKey,
  aad: DomainContext,
  blob: Uint8Array,
): Promise<ExtractableEnvelopePrivateKey> {
  return (await unwrap(
    wrappingKey,
    aad,
    blob,
    RSA_OAEP_IMPORT,
    true,
    ["decrypt"],
  )) as ExtractableEnvelopePrivateKey;
}

/** §25.1 Re-wrap temporal (Account Signing): extractable, declared `["sign"]`. */
export async function unwrapRewrapSigningKey(
  wrappingKey: KeyWrapKey,
  aad: DomainContext,
  blob: Uint8Array,
): Promise<ExtractableSigningKey> {
  return (await unwrap(wrappingKey, aad, blob, ECDSA_IMPORT, true, ["sign"])) as ExtractableSigningKey;
}
