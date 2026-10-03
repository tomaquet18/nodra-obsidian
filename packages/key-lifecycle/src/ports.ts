// The two impure things this package needs. Everything else is pure or comes from Web Crypto
// through `@nodra/crypto`.
//
// `derivePasswordKey` is a port and not a direct import for a production reason, not a test one:
// Argon2id at the ADR-004 profile blocks its thread for over a second, so a browser client runs
// it in a Worker and a plugin may hand it to a native build. The port is the seam where that
// happens. Tests use it to memoize the *real* KDF, so no oracle is weakened by the seam; the
// ADR-004 limit check (§24) stays in this package, before the port is ever called, so a port
// implementation cannot be talked into running parameters the spec rejects.
import { derivePasswordKey as webArgon2id, randomBytes as webRandomBytes } from "@nodra/crypto";
import type { Argon2Params } from "@nodra/crypto";

export interface KeyLifecyclePorts {
  /** CSPRNG bytes: the `kdf_salt` of §23.4 and the Account Secret Key of §24. */
  readonly randomBytes: (length: number) => Uint8Array;
  /**
   * Unix milliseconds (§23.2). The one clock this package touches: `created_at` of the Recovery
   * Kit (§27.1). It is a port and not `Date.now()` at the call site because a kit is a document
   * the user keeps for years — a test that could not fix the timestamp could not fix the kit's
   * bytes either, and §27 has no other source of nondeterminism once the key pairs are given.
   */
  readonly now: () => number;
  /** `PasswordKey = Argon2id(EncryptionPassword, kdf_salt, params)` (§24), exactly 32 bytes. */
  readonly derivePasswordKey: (password: string, kdfSalt: Uint8Array, params: Argon2Params) => Promise<Uint8Array>;
}

/** Web Crypto plus the audited Argon2id of `@nodra/crypto` (§23.0 rule 3). */
export const defaultPorts: KeyLifecyclePorts = {
  randomBytes: webRandomBytes,
  now: () => Date.now(),
  derivePasswordKey: webArgon2id,
};
