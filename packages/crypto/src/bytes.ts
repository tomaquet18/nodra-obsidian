// Random bytes, best-effort zeroization and constant-time comparison.
import { CryptoError } from "./errors.js";

/** `getRandomValues` refuses more than 65 536 bytes per call. */
const MAX_RANDOM_CHUNK = 65_536;

/** CSPRNG bytes. The only randomness source in the package. */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new CryptoError("BAD_LENGTH", `randomBytes length must be a non-negative integer, got ${String(length)}`);
  }
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (c === undefined || typeof c.getRandomValues !== "function") {
    throw new CryptoError("UNSUPPORTED_SECURE_CLIENT", "crypto.getRandomValues is not available");
  }
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += MAX_RANDOM_CHUNK) {
    c.getRandomValues(out.subarray(offset, Math.min(offset + MAX_RANDOM_CHUNK, length)));
  }
  return out;
}

/**
 * Overwrites a buffer with zeros. Best effort only: §24 and §33.2 ask for it on the bytes of
 * `PasswordKey`, the Account Secret Key and an `epoch_secret`, and JS cannot promise the engine
 * kept no copy. §44.3 requires that it never throws.
 */
export function zeroize(...buffers: (Uint8Array | undefined)[]): void {
  for (const b of buffers) {
    if (b !== undefined && b.length > 0) b.fill(0);
  }
}

/**
 * Comparison whose running time does not depend on where the inputs differ.
 * Lengths are compared first: every value compared this way (hashes, fingerprints, commitments,
 * tags) has a length fixed by the protocol, so the length is not a secret.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/** Concatenates byte strings (used for the `nonce ‖ ciphertext` blob format of §23.4). */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
