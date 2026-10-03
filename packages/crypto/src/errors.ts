/** Failure codes of `@nodra/crypto`. Mirrors the shape of `NceError` in `@nodra/encoding`. */
export type CryptoErrorCode =
  /** §23.0 rule 7: the runtime lacks a mandatory capability. Never degrade silently. */
  | "UNSUPPORTED_SECURE_CLIENT"
  /** A fixed-length input (key, nonce, salt, tag, signature, epoch secret) had the wrong size. */
  | "BAD_LENGTH"
  /** Argon2id parameters outside the limits of the ADR-004 profile (§24). */
  | "BAD_PARAMS"
  /** AEAD open / OAEP unwrap failed: wrong key, wrong AAD or label, or tampered ciphertext. */
  | "DECRYPT_FAILED";

export class CryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = "CryptoError";
    this.code = code;
  }
}

export function assertLength(bytes: Uint8Array, expected: number, what: string): void {
  if (bytes.length !== expected) {
    throw new CryptoError("BAD_LENGTH", `${what} must be ${expected} bytes, got ${bytes.length}`);
  }
}
