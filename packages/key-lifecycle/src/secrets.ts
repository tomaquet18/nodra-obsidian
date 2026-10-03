// The two secrets of §24 on their way in, and the §24 derivation itself, for both modes (§3.6).
import {
  ACCOUNT_SECRET_KEY_BYTES,
  SecretKeyError,
  decodeAccountSecretKey,
} from "@nodra/encoding/secret-key";
import type { Argon2Params as Argon2ParamsRecord } from "@nodra/encoding/records";
import {
  ARGON2_LIMITS,
  EMPTY_SALT,
  assertArgon2ParamsAccepted,
  deriveAeadKey,
  deriveKeyWrapKey,
  importHkdfBase,
  zeroize,
} from "@nodra/crypto";
import type { AeadKey, Argon2Params, HkdfBase, KeyWrapKey } from "@nodra/crypto";
import { ACCOUNT_CONFIG_INFO, ACCOUNT_KEYWRAP_INFO } from "./contexts.js";
import { KeyLifecycleError, fail, ok } from "./errors.js";
import type { Result } from "./errors.js";
import { defaultPorts } from "./ports.js";
import type { KeyLifecyclePorts } from "./ports.js";

/**
 * The Account Secret Key as the user supplies it: the 32-character Setup Kit text (any casing,
 * with or without hyphens, with the `I`/`L`/`O` confusions of §24) or the 20 decoded bytes.
 */
export type AccountSecretKeyInput = string | Uint8Array;

export interface AccountSecrets {
  /** The Encryption Password. Normalized to NFC inside the KDF (`@nodra/crypto`). */
  readonly password: string;
  readonly secretKey: AccountSecretKeyInput;
}

/**
 * The pair of §24. Both handles are non-extractable and usage-restricted: `AccountKeyWrapKey`
 * can only wrap and unwrap, `AccountConfigKey` can only encrypt and decrypt, so neither can
 * stand in for the other even by accident.
 */
export interface DerivedAccountKeys {
  readonly keyWrapKey: KeyWrapKey;
  readonly configKey: AeadKey;
}

/** §24: the HKDF salt is the 20 decoded bytes, never the typed text. */
export function resolveAccountSecretKey(input: AccountSecretKeyInput): Result<Uint8Array> {
  if (typeof input === "string") {
    try {
      return ok(decodeAccountSecretKey(input));
    } catch (cause) {
      if (cause instanceof SecretKeyError) return fail("BAD_SECRET_KEY_FORMAT", cause.message);
      throw cause;
    }
  }
  if (!(input instanceof Uint8Array)) {
    throw new KeyLifecycleError("the Account Secret Key must be text or bytes");
  }
  if (input.length !== ACCOUNT_SECRET_KEY_BYTES) {
    return fail(
      "BAD_SECRET_KEY_FORMAT",
      `the Account Secret Key must be ${ACCOUNT_SECRET_KEY_BYTES} bytes, got ${input.length}`,
    );
  }
  return ok(input);
}

/** The `argon2_params` record of §23.4 as the camelCase shape `@nodra/crypto` takes. */
export function toArgon2Params(params: Argon2ParamsRecord): Argon2Params {
  return {
    memoryKib: params.memory_kib,
    iterations: params.iterations,
    parallelism: params.parallelism,
    version: params.version,
  };
}

/** The inverse, for building an `AccountSecurityProfile`. */
export function toArgon2ParamsRecord(params: Argon2Params): Argon2ParamsRecord {
  return {
    memory_kib: params.memoryKib,
    iterations: params.iterations,
    parallelism: params.parallelism,
    version: params.version,
  };
}

/**
 * §24: rejects parameters read from the not-yet-authenticated profile before any work is done.
 * Splits `@nodra/crypto`'s single `BAD_PARAMS` into the two cases a UI must word differently:
 * a profile version this build has no limits for, and values outside the limits it does have.
 */
export function checkKdfParams(params: Argon2Params): Result<Argon2Params> {
  if (!ARGON2_LIMITS.has(params.version)) {
    return fail(
      "UNSUPPORTED_KDF_PROFILE",
      `argon2_params.version ${String(params.version)} is not an ADR-004 profile this client knows`,
    );
  }
  try {
    assertArgon2ParamsAccepted(params);
  } catch (cause) {
    return fail("KDF_PARAMS_REJECTED", cause instanceof Error ? cause.message : String(cause));
  }
  return ok(params);
}

/**
 * The two-secret unlock of §24, exactly as written:
 *
 * ```text
 * PasswordKey       = Argon2id(EncryptionPassword, kdf_salt, params)
 * PasswordBase      = importKey("raw", PasswordKey, "HKDF", …)
 * AccountKeyWrapKey = HKDF{salt = AccountSecretKey, info = Context("nodra/hkdf/account-keywrap")}
 * AccountConfigKey  = HKDF{salt = AccountSecretKey, info = Context("nodra/hkdf/account-config")}
 * ```
 *
 * The Account Secret Key is the HKDF **salt**, which is what makes an offline password attack on
 * a stolen database impossible: without those 20 bytes there is no candidate to verify against.
 *
 * `PasswordKey` is zeroized before returning (§24, best effort — see NOTES Q172). The caller owns
 * zeroizing the Secret Key bytes it passed in.
 */
export async function deriveAccountKeys(
  secretKeyBytes: Uint8Array,
  password: string,
  kdfSalt: Uint8Array,
  params: Argon2Params,
  ports: KeyLifecyclePorts = defaultPorts,
): Promise<DerivedAccountKeys> {
  const passwordKey = await ports.derivePasswordKey(password, kdfSalt, params);
  try {
    const base = await importHkdfBase(passwordKey);
    const [keyWrapKey, configKey] = await Promise.all([
      deriveKeyWrapKey(base, { salt: secretKeyBytes, info: ACCOUNT_KEYWRAP_INFO }),
      deriveAeadKey(base, { salt: secretKeyBytes, info: ACCOUNT_CONFIG_INFO }),
    ]);
    return { keyWrapKey, configKey };
  } finally {
    zeroize(passwordKey);
  }
}

/**
 * The Managed key source of §24 (ADR-021): the 32 random bytes of the `RootUnlockKey` (at creation
 * and in §35.14, where the client generates them), or the non-extractable `RootUnlockBase` the
 * client unwraps straight from the escrow re-wrap (§24.2 step 4), whose bytes never exist here.
 */
export type RootUnlockKeySource = Uint8Array | HkdfBase;

/** §3.6: the `RootUnlockKey` is 256 random bits. */
export const ROOT_UNLOCK_KEY_BYTES = 32;

/**
 * The Managed derivation of §24: the same two HKDF calls as {@link deriveAccountKeys}, with the
 * `RootUnlockKey` as the base and the empty salt, so everything derived after it is identical in
 * both modes.
 *
 * ```text
 * RootUnlockBase    = importKey("raw", RootUnlockKey, "HKDF", false, …)
 * AccountKeyWrapKey = HKDF{salt = empty, info = Context("nodra/hkdf/account-keywrap")}
 * AccountConfigKey  = HKDF{salt = empty, info = Context("nodra/hkdf/account-config")}
 * ```
 *
 * The caller owns zeroizing the bytes it passed in (§24: right after deriving, and after sealing
 * them into the escrow when it generated them).
 */
export async function deriveManagedAccountKeys(rootUnlockKey: RootUnlockKeySource): Promise<DerivedAccountKeys> {
  let base: HkdfBase;
  if (rootUnlockKey instanceof Uint8Array) {
    if (rootUnlockKey.length !== ROOT_UNLOCK_KEY_BYTES) {
      throw new KeyLifecycleError(`the RootUnlockKey must be ${ROOT_UNLOCK_KEY_BYTES} bytes, got ${rootUnlockKey.length}`);
    }
    base = await importHkdfBase(rootUnlockKey);
  } else {
    base = rootUnlockKey;
  }
  const [keyWrapKey, configKey] = await Promise.all([
    deriveKeyWrapKey(base, { salt: EMPTY_SALT, info: ACCOUNT_KEYWRAP_INFO }),
    deriveAeadKey(base, { salt: EMPTY_SALT, info: ACCOUNT_CONFIG_INFO }),
  ]);
  return { keyWrapKey, configKey };
}
