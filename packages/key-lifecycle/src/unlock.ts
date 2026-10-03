// The unlock of both protection modes (§24, §24.2) and the handle table of §25.1.
//
// One private core (`openAccount`) does the §24 derivation — from the two secrets (Private) or from
// the `RootUnlockKey` (Managed, ADR-021) — opens the §26 config and hands back
// the pieces; the three exported entry points are exactly the three "cuándo existe" rows of
// §25.1, so a call site says which handles it is entitled to and gets nothing else:
//
//   unlockSession      §35.3   Session handle only. §24.1: the derived keys are dropped here.
//   unlockForOperation §35     Operation + Signing, plus the derived keys the operation rewrites
//                              the config with. Never persisted; dropped when the operation ends.
//   unlockForRewrap    §35.6   The two extractable Re-wrap handles, so the keyset can be wrapped
//                              again under new secrets.
import { unseal } from "@nodra/crypto";
import {
  unwrapOperationKey,
  unwrapRewrapEncryptionKey,
  unwrapRewrapSigningKey,
  unwrapSessionKey,
  unwrapSigningKey,
} from "@nodra/crypto";
import type {
  AeadKey,
  EnvelopeDecryptKey,
  EnvelopeUnwrapKey,
  ExtractableEnvelopePrivateKey,
  ExtractableSigningKey,
  KeyWrapKey,
  SigningKey,
} from "@nodra/crypto";
import { NceError } from "@nodra/encoding";
import { ACCOUNT_SECURITY_CONFIG, ACCOUNT_SECURITY_PROFILE, RecordError, decodeRecord } from "@nodra/encoding/records";
import type { AccountSecurityConfig, AccountSecurityProfile } from "@nodra/encoding/records";
import { accountConfigAad, accountPrivateKeyAad } from "./contexts.js";
import { fail, ok, secretsRejected } from "./errors.js";
import type { Result } from "./errors.js";
import { defaultPorts } from "./ports.js";
import type { KeyLifecyclePorts } from "./ports.js";
import {
  checkKdfParams,
  deriveAccountKeys,
  deriveManagedAccountKeys,
  resolveAccountSecretKey,
  toArgon2Params,
} from "./secrets.js";
import type { AccountSecrets, DerivedAccountKeys, RootUnlockKeySource } from "./secrets.js";

/**
 * The `crypto_version`s this build implements (§23.1): 1, and 2 (ADR-021), which adds the escrow
 * and the mode switches over exactly the same primitives. Anything else is refused, never degraded
 * (§23.0 rule 7).
 */
export const CRYPTO_VERSIONS = [1, 2] as const;
export type CryptoVersion = (typeof CRYPTO_VERSIONS)[number];

export function isSupportedCryptoVersion(version: number): version is CryptoVersion {
  return (CRYPTO_VERSIONS as readonly number[]).includes(version);
}

interface UnlockRequestBase {
  /**
   * The account the caller authenticated as (Supabase Auth). Used for every AAD; the
   * `account_id` inside the profile is not trusted, only cross-checked against this one.
   */
  readonly accountId: Uint8Array;
  /** The `AccountSecurityProfile` as read from the server: canonical NCE bytes, or the record. */
  readonly profile: Uint8Array | AccountSecurityProfile;
  readonly ports?: KeyLifecyclePorts;
}

/**
 * The key source of §24, one per mode (§3.6). The client picks it from the mode it derived from
 * the verified root chain, never from the profile; the profile's shape is then cross-checked
 * against it (§23.4: `kdf_salt` and `argon2_params` present if and only if the account is Private).
 */
export type UnlockRequest = UnlockRequestBase &
  (
    | { readonly secrets: AccountSecrets; readonly rootUnlockKey?: never }
    | { readonly rootUnlockKey: RootUnlockKeySource; readonly secrets?: never }
  );

/** What every unlock establishes before any handle exists: the verified §26 config. */
export interface UnlockedAccount {
  readonly accountId: Uint8Array;
  readonly config: AccountSecurityConfig;
}

/** §35.3, and the steady state of an unlocked client. §24.1: no derived key survives this. */
export interface SessionUnlock extends UnlockedAccount {
  /** §25.1 Session: Account Encryption, `extractable = false`, `["unwrapKey"]`. */
  readonly sessionKey: EnvelopeUnwrapKey;
}

/** §35 security operations. Every handle here dies with the operation (§25.1). */
export interface OperationUnlock extends UnlockedAccount {
  /** §25.1 Operation: Account Encryption, `extractable = false`, `["decrypt"]`. */
  readonly operationKey: EnvelopeDecryptKey;
  /** §25.1 Signing: Account Signing, `extractable = false`, `["sign"]`. */
  readonly signingKey: SigningKey;
  /** Needed to rewrite the config in the same commit (§26) and to re-wrap the keyset (§35.6). */
  readonly derived: DerivedAccountKeys;
}

/** §35.6 only: the two Re-wrap temporal rows of §25.1, both `extractable = true`. */
export interface RewrapUnlock extends UnlockedAccount {
  readonly encryptionKey: ExtractableEnvelopePrivateKey;
  readonly signingKey: ExtractableSigningKey;
  readonly derived: DerivedAccountKeys;
}

interface OpenedAccount {
  readonly accountId: Uint8Array;
  readonly config: AccountSecurityConfig;
  readonly profile: AccountSecurityProfile;
  readonly derived: DerivedAccountKeys;
}

/**
 * Decodes an `AccountSecurityProfile` from canonical NCE bytes. Truncated, garbage,
 * non-canonical or schema-violating input is `MALFORMED_PROFILE`, never an exception.
 */
export function parseAccountSecurityProfile(bytes: Uint8Array): Result<AccountSecurityProfile> {
  try {
    return ok(decodeRecord(ACCOUNT_SECURITY_PROFILE, bytes));
  } catch (cause) {
    if (cause instanceof NceError || cause instanceof RecordError) return fail("MALFORMED_PROFILE", cause.message);
    throw cause;
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

/**
 * Opens the §26 Account Security Config with the `AccountConfigKey`.
 *
 * The AAD is `Context("nodra/aad/account-config", account_id, config_version)` built from the
 * caller's `accountId` and the server's plaintext copy of `config_version` (§23.4 key 6). That
 * copy is unauthenticated, so the AAD is what actually binds it: a server that lies about it
 * cannot produce a blob that opens. The two fields are then re-checked *inside* the plaintext,
 * because nothing forces the sealed record to agree with the AAD it was sealed under.
 */
export async function openAccountSecurityConfig(
  configKey: AeadKey,
  accountId: Uint8Array,
  configVersion: number,
  configBlob: Uint8Array,
): Promise<Result<AccountSecurityConfig>> {
  let plaintext: Uint8Array;
  try {
    plaintext = await unseal(configKey, accountConfigAad(accountId, configVersion), configBlob);
  } catch {
    return secretsRejected();
  }
  let config: AccountSecurityConfig;
  try {
    config = decodeRecord(ACCOUNT_SECURITY_CONFIG, plaintext);
  } catch (cause) {
    if (cause instanceof NceError || cause instanceof RecordError) return fail("MALFORMED_CONFIG", cause.message);
    throw cause;
  }
  if (!sameBytes(config.account_id, accountId)) {
    return fail("CONFIG_MISMATCH", "the config names an account other than the one it was sealed for");
  }
  if (config.config_version !== configVersion) {
    return fail(
      "CONFIG_MISMATCH",
      `the config says config_version ${config.config_version}, its AAD says ${configVersion}`,
    );
  }
  if (!isSupportedCryptoVersion(config.crypto_version)) {
    return fail(
      "UNSUPPORTED_CRYPTO_VERSION",
      `the account uses crypto_version ${config.crypto_version}; this client implements ${CRYPTO_VERSIONS.join(", ")}`,
    );
  }
  return ok(config);
}

async function openAccount(request: UnlockRequest): Promise<Result<OpenedAccount>> {
  const { accountId, ports = defaultPorts } = request;

  const parsed =
    request.profile instanceof Uint8Array ? parseAccountSecurityProfile(request.profile) : ok(request.profile);
  if (!parsed.ok) return parsed;
  const profile = parsed.value;

  // The profile is not authenticated before the unlock (§24), so its `account_id` is a claim.
  // A profile for another account can only be an attempt to make this client derive and unwrap
  // under someone else's AAD; refuse before spending a second on Argon2id.
  if (!sameBytes(profile.account_id, accountId)) {
    return fail("MALFORMED_PROFILE", "the profile belongs to another account");
  }

  const derived = await deriveFor(request, profile, ports);
  if (!derived.ok) return derived;

  const config = await openAccountSecurityConfig(
    derived.value.configKey,
    accountId,
    profile.config_version,
    profile.config_blob,
  );
  if (!config.ok) return config;

  return ok({ accountId, config: config.value, profile, derived: derived.value });
}

/**
 * §24 for the request's key source, after checking that the profile has the shape of that mode.
 * A Private unlock of a profile without `kdf_salt` (or a Managed unlock of one with it) means the
 * server's profile and the client's derived mode disagree: refused before any derivation.
 */
async function deriveFor(
  request: UnlockRequest,
  profile: AccountSecurityProfile,
  ports: KeyLifecyclePorts,
): Promise<Result<DerivedAccountKeys>> {
  const { kdf_salt: kdfSalt, argon2_params: argon2Params } = profile;
  if (request.rootUnlockKey !== undefined) {
    if (kdfSalt !== undefined || argon2Params !== undefined) {
      return fail("MALFORMED_PROFILE", "a Managed profile has no kdf_salt and no argon2_params (§23.4)");
    }
    return ok(await deriveManagedAccountKeys(request.rootUnlockKey));
  }
  if (kdfSalt === undefined || argon2Params === undefined) {
    return fail("MALFORMED_PROFILE", "a Private profile has kdf_salt and argon2_params (§23.4)");
  }

  const params = checkKdfParams(toArgon2Params(argon2Params));
  if (!params.ok) return params;

  const secretKey = resolveAccountSecretKey(request.secrets.secretKey);
  if (!secretKey.ok) return secretKey;

  return ok(await deriveAccountKeys(secretKey.value, request.secrets.password, kdfSalt, params.value, ports));
}

/** Turns any unwrap rejection into the one indistinguishable failure of §24. */
async function unwrapping<T>(run: () => Promise<T>): Promise<Result<T>> {
  try {
    return ok(await run());
  } catch {
    return secretsRejected();
  }
}

/**
 * §35.3 "Navegador nuevo (sin trust)": Password + Secret Key → config → Session handle.
 * §24.1 is enforced by the return type: `AccountKeyWrapKey` and `AccountConfigKey` are not in it,
 * and nothing else in this module holds a reference once this function returns.
 */
export async function unlockSession(request: UnlockRequest): Promise<Result<SessionUnlock>> {
  const opened = await openAccount(request);
  if (!opened.ok) return opened;
  const { accountId, config, profile, derived } = opened.value;
  const session = await unwrapping(() =>
    unwrapSessionKey(
      derived.keyWrapKey,
      accountPrivateKeyAad(accountId, "ACCOUNT_ENCRYPTION"),
      profile.wrapped_account_encryption_key.blob,
    ),
  );
  if (!session.ok) return session;
  return ok({ accountId, config, sessionKey: session.value });
}

/** A §35 security operation: the Operation and Signing handles of §25.1, plus the derived keys. */
export async function unlockForOperation(request: UnlockRequest): Promise<Result<OperationUnlock>> {
  const opened = await openAccount(request);
  if (!opened.ok) return opened;
  const { accountId, config, profile, derived } = opened.value;
  const handles = await unwrapping(async () => ({
    operationKey: await unwrapOperationKey(
      derived.keyWrapKey,
      accountPrivateKeyAad(accountId, "ACCOUNT_ENCRYPTION"),
      profile.wrapped_account_encryption_key.blob,
    ),
    signingKey: await unwrapSigningKey(
      derived.keyWrapKey,
      accountPrivateKeyAad(accountId, "ACCOUNT_SIGNING"),
      profile.wrapped_account_signing_key.blob,
    ),
  }));
  if (!handles.ok) return handles;
  return ok({ accountId, config, derived, ...handles.value });
}

/** §35.6 only: the extractable Re-wrap temporal handles, so the keyset can be wrapped again. */
export async function unlockForRewrap(request: UnlockRequest): Promise<Result<RewrapUnlock>> {
  const opened = await openAccount(request);
  if (!opened.ok) return opened;
  const { accountId, config, profile, derived } = opened.value;
  const handles = await unwrapping(async () => ({
    encryptionKey: await unwrapRewrapEncryptionKey(
      derived.keyWrapKey,
      accountPrivateKeyAad(accountId, "ACCOUNT_ENCRYPTION"),
      profile.wrapped_account_encryption_key.blob,
    ),
    signingKey: await unwrapRewrapSigningKey(
      derived.keyWrapKey,
      accountPrivateKeyAad(accountId, "ACCOUNT_SIGNING"),
      profile.wrapped_account_signing_key.blob,
    ),
  }));
  if (!handles.ok) return handles;
  return ok({ accountId, config, derived, ...handles.value });
}
