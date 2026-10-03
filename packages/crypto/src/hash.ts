// SHA-256 and HMAC-SHA-256 (§23.1).
import { assertLength } from "./errors.js";
import { subtle } from "./runtime.js";
import type { DomainContext } from "./context.js";

export const HASH_BYTES = 32;
export const MAC_BYTES = 32;

declare const macKeyBrand: unique symbol;
/** An HMAC-SHA-256 key handle (`["sign"]`). Dedup keys come from HKDF (§31.2). */
export type MacKey = CryptoKey & { readonly [macKeyBrand]: "nodra/mac" };

/**
 * SHA-256 over raw bytes without a context. Only for the three exceptions of §23.0 rule 6:
 * `SHA-256(SPKI DER)` (§26, §30.1), `SHA-256(envelope ciphertext)` (§23.3 `envelope-set`),
 * and hashing NCE bytes a caller already built. Structures use {@link hashContext}.
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest("SHA-256", data as BufferSource));
}

/** `SHA-256(Context(domain, structure))` — the structure hash of §23.3. */
export async function hashContext(ctx: DomainContext): Promise<Uint8Array> {
  return sha256(ctx);
}

/** Imports 32 raw bytes as an HMAC-SHA-256 key. Non-extractable, `["sign"]` only. */
export async function importMacKey(raw: Uint8Array): Promise<MacKey> {
  assertLength(raw, MAC_BYTES, "HMAC key");
  return (await subtle().importKey("raw", raw as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ])) as MacKey;
}

/**
 * HMAC-SHA-256 over raw bytes. Used for `content_fingerprint = HMAC(DedupKey, plaintext)` (§31.4),
 * which §23.0 rule 6 exempts from NCE because it covers plaintext, not a structure.
 */
export async function hmacSha256(key: MacKey, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().sign("HMAC", key, data as BufferSource));
}
