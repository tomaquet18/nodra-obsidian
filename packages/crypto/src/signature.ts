// ECDSA P-256 with SHA-256 (§23.1). Signatures are the 64-byte IEEE P1363 form Web Crypto
// produces natively, and what gets signed is always `Context(domain, structure)` (§23.3) — never
// an ad-hoc concatenation, and never a pre-computed digest.
import { assertLength, CryptoError } from "./errors.js";
import { subtle } from "./runtime.js";
import type { DomainContext } from "./context.js";

export const SIGNATURE_BYTES = 64;

const ECDSA_KEYGEN: EcKeyGenParams = { name: "ECDSA", namedCurve: "P-256" };
const ECDSA_IMPORT: EcKeyImportParams = { name: "ECDSA", namedCurve: "P-256" };
const ECDSA_SIGN: EcdsaParams = { name: "ECDSA", hash: "SHA-256" };

declare const signatureBrand: unique symbol;

/** A P-256 public key, imported from the SPKI DER stored in the root or the Registry. */
export type VerifyingKey = CryptoKey & { readonly [signatureBrand]: "nodra/verifying" };

/** The Signing handle of §25.1: non-extractable, `["sign"]`, alive only during an operation. */
export type SigningKey = CryptoKey & { readonly [signatureBrand]: "nodra/signing" };

/** A freshly generated (§25.2) or Re-wrap (§25.1) signing key: extractable so it can be wrapped. */
export type ExtractableSigningKey = CryptoKey & { readonly [signatureBrand]: "nodra/signing-extractable" };

/** Any handle allowed to sign. */
export type AnySigningKey = SigningKey | ExtractableSigningKey;

export interface SigningKeyPair {
  readonly publicKey: VerifyingKey;
  readonly privateKey: ExtractableSigningKey;
}

/** Generates an Account Signing or Recovery Authority key pair (§25.2). */
export async function generateSigningKeyPair(): Promise<SigningKeyPair> {
  const pair = (await subtle().generateKey(ECDSA_KEYGEN, true, ["sign", "verify"])) as CryptoKeyPair;
  return {
    publicKey: pair.publicKey as VerifyingKey,
    privateKey: pair.privateKey as ExtractableSigningKey,
  };
}

/** Imports an SPKI DER public key. */
export async function importVerifyingKey(spki: Uint8Array): Promise<VerifyingKey> {
  return (await subtle().importKey("spki", spki as BufferSource, ECDSA_IMPORT, true, ["verify"])) as VerifyingKey;
}

/** Imports a PKCS#8 private key as the non-extractable Signing handle of §25.1. */
export async function importSigningKey(pkcs8: Uint8Array): Promise<SigningKey> {
  return (await subtle().importKey("pkcs8", pkcs8 as BufferSource, ECDSA_IMPORT, false, ["sign"])) as SigningKey;
}

/** Exports SPKI DER (§25.2: key hashes are taken over the stored bytes). */
export async function exportVerifyingKey(key: VerifyingKey): Promise<Uint8Array> {
  return new Uint8Array(await subtle().exportKey("spki", key));
}

/** Exports PKCS#8 DER, only to wrap the key or to place it in a Recovery Kit. */
export async function exportSigningKey(key: ExtractableSigningKey): Promise<Uint8Array> {
  return new Uint8Array(await subtle().exportKey("pkcs8", key));
}

/** Signs `Context(domain, structure)`; Web Crypto applies SHA-256 internally (§23.3). */
export async function signContext(key: AnySigningKey, ctx: DomainContext): Promise<Uint8Array> {
  const signature = new Uint8Array(await subtle().sign(ECDSA_SIGN, key, ctx as BufferSource));
  assertLength(signature, SIGNATURE_BYTES, "ECDSA P1363 signature");
  return signature;
}

/** Verifies a 64-byte P1363 signature over `Context(domain, structure)`. */
export async function verifyContext(
  key: VerifyingKey,
  ctx: DomainContext,
  signature: Uint8Array,
): Promise<boolean> {
  return unsafeVerifyRaw(key, ctx, signature);
}

/**
 * @internal Verification over arbitrary message bytes, for the Wycheproof known-answer vectors.
 * A signature that is not exactly 64 bytes is rejected here rather than handed to Web Crypto,
 * so DER-encoded or range-extended signatures can never be accepted.
 */
export async function unsafeVerifyRaw(
  key: VerifyingKey,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  if (signature.length !== SIGNATURE_BYTES) return false;
  return subtle().verify(ECDSA_SIGN, key, signature as BufferSource, message as BufferSource);
}

/** @internal Imports a PKCS#8 private key as an extractable `["sign"]` handle (§35.6, test vectors). */
export async function importExtractableSigningKey(pkcs8: Uint8Array): Promise<ExtractableSigningKey> {
  return (await subtle().importKey("pkcs8", pkcs8 as BufferSource, ECDSA_IMPORT, true, [
    "sign",
  ])) as ExtractableSigningKey;
}

/** Guards against a caller handing a non-P1363 signature to a protocol structure. */
export function assertSignatureLength(signature: Uint8Array): void {
  if (signature.length !== SIGNATURE_BYTES) {
    throw new CryptoError("BAD_LENGTH", `signature must be ${SIGNATURE_BYTES} bytes (P1363), got ${signature.length}`);
  }
}
