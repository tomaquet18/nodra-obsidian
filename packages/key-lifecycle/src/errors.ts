// Failure vocabulary of the two-secret unlock (§24) and of Account Root Keyset creation (§25).
//
// Every failure a caller can reach is a *value*, not an exception: `unlock*` returns
// `{ ok: false, failure }`. A thrown `KeyLifecycleError` means a programming error in the caller
// (wrong byte lengths, a record that does not typecheck) or an unsupported runtime — never
// "these secrets are wrong".
//
// The single most important rule here is `SECRETS_REJECTED`. §24 wants this property:
//
//   > con la DB completa (salts, parámetros, keyset envuelto) pero sin Account Secret Key,
//   > un atacante NO puede verificar intentos de contraseña offline.
//
// A distinguishable "wrong password" failure would hand exactly that oracle to anyone who *does*
// hold the Secret Key, and a distinguishable "wrong Secret Key" failure would let a password
// guesser confirm a password. So a wrong password, a wrong Secret Key, both wrong, and a tampered
// wrapped key or config blob all produce the *same* code and the *same* message. There is
// nothing to tell apart: AES-GCM authentication gives the client no more information either.

/** A failure the caller of an unlock can actually reach and should render. */
export type UnlockFailureCode =
  /** The profile bytes are not a canonical `AccountSecurityProfile`, or name another account. */
  | "MALFORMED_PROFILE"
  /** `argon2_params.version` is a profile version this client has no ADR-004 limits for (§24). */
  | "UNSUPPORTED_KDF_PROFILE"
  /** Argon2id parameters outside the ADR-004 limits of their version (§24, §44.3). */
  | "KDF_PARAMS_REJECTED"
  /** The typed Account Secret Key does not decode to 20 bytes (§24). A client-side input error. */
  | "BAD_SECRET_KEY_FORMAT"
  /**
   * Wrong password, wrong Account Secret Key, both, or tampered wrapped material.
   * Deliberately indistinguishable — see the note at the top of this file.
   */
  | "SECRETS_REJECTED"
  /** The config blob opened, but its plaintext is not a canonical `AccountSecurityConfig`. */
  | "MALFORMED_CONFIG"
  /** The config opened but its inner `account_id` / `config_version` contradict its own AAD. */
  | "CONFIG_MISMATCH"
  /** The config announces a `crypto_version` this client does not implement (§23.0 rule 7). */
  | "UNSUPPORTED_CRYPTO_VERSION";

export interface UnlockFailure {
  readonly code: UnlockFailureCode;
  readonly message: string;
}

/**
 * The shape every verifier in this package returns: a value, or a typed rejection. Used by the
 * unlock (§24), by the root chain (§28) and by the Registry (§29), each with its own failure
 * vocabulary, so no caller can confuse "these secrets are wrong" with "this chain forks".
 */
export type Outcome<T, F> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly failure: F };

export type Result<T> = Outcome<T, UnlockFailure>;

export function ok<T>(value: T): Result<T> {
  return { ok: true, value };
}

export function fail<T>(code: UnlockFailureCode, message: string): Result<T> {
  return { ok: false, failure: { code, message } };
}

/**
 * The one message every secret-dependent failure carries. Constant on purpose: a message that
 * named the step that failed would be the oracle §24 forbids, even if the code did not.
 */
export const SECRETS_REJECTED_MESSAGE =
  "the Encryption Password and Account Secret Key did not open this account's keyset";

export function secretsRejected<T>(): Result<T> {
  return fail("SECRETS_REJECTED", SECRETS_REJECTED_MESSAGE);
}

/** A programming error or an unsupported runtime, never a wrong secret. */
export class KeyLifecycleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyLifecycleError";
  }
}
