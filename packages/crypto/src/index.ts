// `@nodra/crypto` — the `crypto_version = 1` primitives of §23.1 and nothing else.
//
// The package deliberately exposes no protocol structures: §24–§35 (unlock, keyset, registry,
// epochs, security operations) are built on top of these entry points in later slices.
//
// Three rules shape the surface:
//   1. every AAD, HKDF `info` and OAEP `label` is a `DomainContext`, so `Context(domain, fields…)`
//      is the only way to reach a primitive that takes one (§23.0 rule 6);
//   2. key handles are branded by role and usage, mirroring the handle table of §25.1, so a
//      Session key cannot be passed where a decrypting key is required;
//   3. nonces are generated inside `seal`/`wrapPrivateKey` and cannot be supplied (§23.1).
//
// The `unsafe*` helpers used by the known-answer vectors live in the individual modules and are
// not re-exported here; the package `exports` map publishes only this entry point.

export { CryptoError } from "./errors.js";
export type { CryptoErrorCode } from "./errors.js";

export { assertSecureCryptoCapabilities } from "./runtime.js";

export { concatBytes, randomBytes, timingSafeEqual, zeroize } from "./bytes.js";

export { domainContext } from "./context.js";
export type { DomainContext, NceDomain, NceValue } from "./context.js";

export { HASH_BYTES, MAC_BYTES, hashContext, hmacSha256, importMacKey, sha256 } from "./hash.js";
export type { MacKey } from "./hash.js";

export {
  AEAD_BLOB_OVERHEAD_BYTES,
  AEAD_KEY_BYTES,
  AEAD_NONCE_BYTES,
  AEAD_TAG_BYTES,
  importAeadKey,
  seal,
  splitBlob,
  unseal,
} from "./aead.js";
export type { AeadKey } from "./aead.js";

export {
  EMPTY_SALT,
  deriveAeadKey,
  deriveBits,
  deriveKeyWrapKey,
  deriveMacKey,
  importHkdfBase,
} from "./hkdf.js";
export type { HkdfBase, HkdfInput } from "./hkdf.js";

export {
  unwrapOperationKey,
  unwrapRewrapEncryptionKey,
  unwrapRewrapSigningKey,
  unwrapSessionKey,
  unwrapSigningKey,
  wrapPrivateKey,
} from "./keywrap.js";
export type { AccountKeyRole, KeyWrapKey, WrappablePrivateKey } from "./keywrap.js";

export {
  CAPABILITY_NONCE_BYTES,
  ENVELOPE_MODULUS_BITS,
  EPOCH_SECRET_BYTES,
  ESCROW_SECRET_BYTES,
  escrowLabel,
  escrowRewrapLabel,
  exportEnvelopePrivateKey,
  exportEnvelopePublicKey,
  generateEnvelopeKeyPair,
  generateRecipientKeyPair,
  importEnvelopeDecryptKey,
  importEnvelopePublicKey,
  importEnvelopeUnwrapKey,
  openCapabilityNonce,
  openEpochSecret,
  openEscrowKey,
  sealCapabilityNonce,
  sealEpochSecret,
  sealEscrowKey,
  unwrapCapabilityMacKey,
  unwrapEpochKey,
  unwrapEscrowPayloadKey,
  unwrapRootUnlockBase,
} from "./envelope.js";
export type {
  EnvelopeDecryptKey,
  EnvelopeKeyPair,
  EnvelopeOpeningKey,
  EnvelopePublicKey,
  EnvelopeUnwrapKey,
  EscrowSlotName,
  ExtractableEnvelopePrivateKey,
  RecipientKeyPair,
} from "./envelope.js";

export {
  SIGNATURE_BYTES,
  assertSignatureLength,
  exportSigningKey,
  exportVerifyingKey,
  generateSigningKeyPair,
  importSigningKey,
  importVerifyingKey,
  signContext,
  verifyContext,
} from "./signature.js";
export type {
  AnySigningKey,
  ExtractableSigningKey,
  SigningKey,
  SigningKeyPair,
  VerifyingKey,
} from "./signature.js";

export {
  ARGON2_ALGORITHM_VERSION,
  ARGON2_LIMITS,
  ARGON2_PARAMS_V1,
  KDF_SALT_BYTES,
  PASSWORD_KEY_BYTES,
  assertArgon2ParamsAccepted,
  derivePasswordKey,
} from "./argon2.js";
export type { Argon2Limits, Argon2Params } from "./argon2.js";
