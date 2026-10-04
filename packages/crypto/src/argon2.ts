// Argon2id password KDF (§23.1, §24). The only primitive that is not native Web Crypto, because
// no browser exposes one; §23.0 rule 3 allows exactly this exception ("Argon2id auditado").
//
// Parameters are the ADR-004 profile. §24 requires the client to reject parameters read from the
// server that fall outside the limits of their profile version, because the profile is not
// authenticated before the unlock: a hostile server must not be able to weaken the KDF, nor to
// hang the client with an absurd memory cost.
import { argon2idAsync } from "@noble/hashes/argon2.js";
import { toNFC } from "@nodra/path-projection";
import { CryptoError } from "./errors.js";

/** Argon2 algorithm version 0x13 (1.3), fixed by RFC 9106. Not the profile version below. */
export const ARGON2_ALGORITHM_VERSION = 0x13;

/** §23.1: the KDF output is 32 bytes. */
export const PASSWORD_KEY_BYTES = 32;

/** §23.4: `kdf_salt` is bytes(16). */
export const KDF_SALT_BYTES = 16;

/**
 * The `argon2_params` map of §23.4. `version` is the **profile** version of ADR-004 (1, 2, …),
 * which selects the limits below — not the Argon2 algorithm version, which is fixed at 0x13.
 */
export interface Argon2Params {
  readonly memoryKib: number;
  readonly iterations: number;
  readonly parallelism: number;
  readonly version: number;
}

export interface Argon2Limits {
  readonly memoryKib: readonly [min: number, max: number];
  readonly iterations: readonly [min: number, max: number];
  readonly parallelism: readonly [min: number, max: number];
}

/**
 * ADR-004 profile 1 (proposed, see `NOTES.md`): RFC 9106 SECOND RECOMMENDED option, the one meant
 * for memory-constrained environments — t = 3, p = 4, m = 2^16 KiB (64 MiB), 128-bit salt,
 * 256-bit tag. The FIRST RECOMMENDED option (2 GiB) cannot run in a browser tab.
 */
export const ARGON2_PARAMS_V1: Argon2Params = {
  memoryKib: 65_536,
  iterations: 3,
  parallelism: 4,
  version: 1,
};

/**
 * Limits per profile version. §24: a published version never raises its minimum, so an existing
 * account can always unlock and then move to a stronger profile with `CHANGE_SECRETS`.
 * The maxima exist only to bound the work a not-yet-authenticated profile can impose on a client.
 */
export const ARGON2_LIMITS: ReadonlyMap<number, Argon2Limits> = new Map([
  [
    1,
    {
      memoryKib: [65_536, 262_144],
      iterations: [3, 10],
      parallelism: [1, 4],
    },
  ],
]);

function inRange(value: number, [min, max]: readonly [number, number]): boolean {
  return Number.isSafeInteger(value) && value >= min && value <= max;
}

/**
 * Rejects parameters a client must not run (§24, §44.3 "parámetros de Argon2id fuera de los
 * límites de ADR-004 → rechazados por el cliente"). An unknown profile version is a rejection too:
 * without its limits there is nothing to check against.
 */
export function assertArgon2ParamsAccepted(params: Argon2Params): void {
  const limits = ARGON2_LIMITS.get(params.version);
  if (limits === undefined) {
    throw new CryptoError("BAD_PARAMS", `unknown argon2 profile version ${String(params.version)}`);
  }
  if (!inRange(params.memoryKib, limits.memoryKib)) {
    throw new CryptoError(
      "BAD_PARAMS",
      `memory_kib ${String(params.memoryKib)} outside [${limits.memoryKib[0]}, ${limits.memoryKib[1]}]`,
    );
  }
  if (!inRange(params.iterations, limits.iterations)) {
    throw new CryptoError(
      "BAD_PARAMS",
      `iterations ${String(params.iterations)} outside [${limits.iterations[0]}, ${limits.iterations[1]}]`,
    );
  }
  if (!inRange(params.parallelism, limits.parallelism)) {
    throw new CryptoError(
      "BAD_PARAMS",
      `parallelism ${String(params.parallelism)} outside [${limits.parallelism[0]}, ${limits.parallelism[1]}]`,
    );
  }
}

/**
 * `PasswordKey = Argon2id(EncryptionPassword, kdf_salt, params)` (§24), 32 bytes.
 *
 * The password is encoded as UTF-8 of its NFC form, using the Unicode tables pinned by ADR-013,
 * so a password typed on a Mac and on Windows derives the same key on every runtime. The caller
 * zeroizes the result once the derived keys exist (§24).
 */
export async function derivePasswordKey(
  password: string,
  kdfSalt: Uint8Array,
  params: Argon2Params,
): Promise<Uint8Array> {
  assertArgon2ParamsAccepted(params);
  if (kdfSalt.length !== KDF_SALT_BYTES) {
    throw new CryptoError("BAD_LENGTH", `kdf_salt must be ${KDF_SALT_BYTES} bytes, got ${kdfSalt.length}`);
  }
  const encoded = new TextEncoder().encode(toNFC(password));
  try {
    return await unsafeArgon2id(encoded, kdfSalt, {
      m: params.memoryKib,
      t: params.iterations,
      p: params.parallelism,
      dkLen: PASSWORD_KEY_BYTES,
    });
  } finally {
    encoded.fill(0);
  }
}

export interface Argon2RawOptions {
  readonly m: number;
  readonly t: number;
  readonly p: number;
  readonly dkLen: number;
  /** RFC 9106 "secret" input. Nodra does not use it; the test vector of §5.3 does. */
  readonly key?: Uint8Array;
  /** RFC 9106 "associated data" input. Nodra does not use it; the test vector of §5.3 does. */
  readonly associatedData?: Uint8Array;
}

/**
 * @internal Argon2id over raw bytes with unconstrained parameters, for the RFC 9106 known-answer
 * vector. Production code uses {@link derivePasswordKey}, which enforces the ADR-004 limits.
 */
export async function unsafeArgon2id(
  password: Uint8Array,
  salt: Uint8Array,
  options: Argon2RawOptions,
): Promise<Uint8Array> {
  return argon2idAsync(password, salt, {
    t: options.t,
    m: options.m,
    p: options.p,
    dkLen: options.dkLen,
    version: ARGON2_ALGORITHM_VERSION,
    ...(options.key === undefined ? {} : { key: options.key }),
    ...(options.associatedData === undefined ? {} : { personalization: options.associatedData }),
  });
}
