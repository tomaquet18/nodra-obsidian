// HKDF-SHA-256 (§23.1). `salt` is explicit at every call site — the spec says so, and making the
// field required means nobody silently inherits an empty salt where §24 needs the Account Secret
// Key. `info` is always a `DomainContext` (§23.3), never free-form bytes.
import { subtle } from "./runtime.js";
import type { AeadKey } from "./aead.js";
import type { MacKey } from "./hash.js";
import type { KeyWrapKey } from "./keywrap.js";
import type { DomainContext } from "./context.js";

declare const hkdfBaseBrand: unique symbol;
/**
 * A non-extractable HKDF input keying material handle (`["deriveKey", "deriveBits"]`).
 * This is `PasswordBase` in §24 and the `EpochKey` in §31.1; Web Crypto never lets its bytes out.
 */
export type HkdfBase = CryptoKey & { readonly [hkdfBaseBrand]: "nodra/hkdf-base" };

/** The explicit empty salt of §23.1 ("vacío salvo §24"). */
export const EMPTY_SALT: Uint8Array = new Uint8Array(0);

export interface HkdfInput {
  /** §23.1: explicit at every use. {@link EMPTY_SALT} for the §31.2 derivations. */
  readonly salt: Uint8Array;
  /** `Context(domain, fields…)` of §23.3. */
  readonly info: DomainContext;
}

/** Imports raw keying material as an HKDF base (`PasswordKey` in §24, `epoch_secret` in §31.1). */
export async function importHkdfBase(ikm: Uint8Array): Promise<HkdfBase> {
  return (await subtle().importKey("raw", ikm as BufferSource, "HKDF", false, [
    "deriveKey",
    "deriveBits",
  ])) as HkdfBase;
}

function params(input: HkdfInput): HkdfParams {
  return { name: "HKDF", hash: "SHA-256", salt: input.salt as BufferSource, info: input.info as BufferSource };
}

/** Derives an AES-256-GCM key for `["encrypt", "decrypt"]` (content, manifest, `AccountConfigKey`). */
export async function deriveAeadKey(base: HkdfBase, input: HkdfInput): Promise<AeadKey> {
  return (await subtle().deriveKey(params(input), base, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ])) as AeadKey;
}

/**
 * Derives the `AccountKeyWrapKey` of §24: AES-256-GCM restricted to `["wrapKey", "unwrapKey"]`,
 * so it can never be used to encrypt or decrypt arbitrary data.
 */
export async function deriveKeyWrapKey(base: HkdfBase, input: HkdfInput): Promise<KeyWrapKey> {
  return (await subtle().deriveKey(params(input), base, { name: "AES-GCM", length: 256 }, false, [
    "wrapKey",
    "unwrapKey",
  ])) as KeyWrapKey;
}

/** Derives the dedup key of §31.2: HMAC-SHA-256, 256 bits, `["sign"]`. */
export async function deriveMacKey(base: HkdfBase, input: HkdfInput): Promise<MacKey> {
  return (await subtle().deriveKey(params(input), base, { name: "HMAC", hash: "SHA-256", length: 256 }, false, [
    "sign",
  ])) as MacKey;
}

/** Derives public bits, such as the epoch commitment of §31.2 (256 bits). */
export async function deriveBits(base: HkdfBase, input: HkdfInput, bits: number): Promise<Uint8Array> {
  return new Uint8Array(await subtle().deriveBits(params(input), base, bits));
}

/**
 * @internal Derivation with arbitrary `info` bytes, for the RFC 5869 known-answer vectors, whose
 * `info` values are not NCE contexts. Production code uses the `DomainContext` entry points above.
 */
export async function unsafeDeriveBitsWithInfo(
  base: HkdfBase,
  salt: Uint8Array,
  info: Uint8Array,
  bits: number,
): Promise<Uint8Array> {
  const raw: HkdfParams = { name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: info as BufferSource };
  return new Uint8Array(await subtle().deriveBits(raw, base, bits));
}
