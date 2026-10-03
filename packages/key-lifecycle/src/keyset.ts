// Account Root Keyset creation (§25) and the records it feeds (§23.4, §26).
//
// This is steps 3–5, 10 and 14 of §35.2, and nothing else: the root chain (§28), the Recovery Kit
// (§27), the Registry (§29) and epochs (§31–§34) compose *on top* of what this returns. The order
// here is the order §35.2 gives, and it matters: the key pairs are generated extractable only so
// they can be wrapped (§25.2), and the caller drops those references when its operation ends.
import {
  KDF_SALT_BYTES,
  ARGON2_PARAMS_V1,
  exportEnvelopePublicKey,
  exportVerifyingKey,
  generateEnvelopeKeyPair,
  generateSigningKeyPair,
  seal,
  sha256,
  wrapPrivateKey,
} from "@nodra/crypto";
import type {
  AeadKey,
  Argon2Params,
  EnvelopePublicKey,
  ExtractableEnvelopePrivateKey,
  ExtractableSigningKey,
  KeyWrapKey,
  VerifyingKey,
} from "@nodra/crypto";
import { ACCOUNT_SECURITY_CONFIG, ACCOUNT_SECURITY_PROFILE, encodeRecord } from "@nodra/encoding/records";
import type {
  AccountSecurityConfig,
  AccountSecurityProfile,
  Argon2Params as Argon2ParamsRecord,
  WrappedPrivateKey,
} from "@nodra/encoding/records";
import {
  ACCOUNT_SECRET_KEY_BYTES,
  formatAccountSecretKey,
} from "@nodra/encoding/secret-key";
import { accountConfigAad, accountPrivateKeyAad } from "./contexts.js";
import { KeyLifecycleError } from "./errors.js";
import type { Result } from "./errors.js";
import { defaultPorts } from "./ports.js";
import type { KeyLifecyclePorts } from "./ports.js";
import {
  ROOT_UNLOCK_KEY_BYTES,
  checkKdfParams,
  deriveAccountKeys,
  deriveManagedAccountKeys,
  resolveAccountSecretKey,
  toArgon2ParamsRecord,
} from "./secrets.js";
import type { AccountSecretKeyInput, DerivedAccountKeys } from "./secrets.js";

/** One of the two rows of the §25 table, in every form the rest of §35.2 needs it. */
export interface AccountKeyMaterial<Private, Public> {
  /**
   * §25.2: extractable, so it can be wrapped, and usable for the signatures of the same
   * operation. It MUST be dropped when the operation ends and MUST NOT be persisted unwrapped.
   */
  readonly privateKey: Private;
  readonly publicKey: Public;
  /** The exact SPKI DER bytes that go into the Root Descriptor (§25.2). */
  readonly publicKeySpki: Uint8Array;
  /** `SHA-256(SPKI)` over those exact bytes, never over a re-export (§25.2). */
  readonly publicKeyHash: Uint8Array;
  readonly wrapped: WrappedPrivateKey;
}

/** The two account key pairs of §25, wrapped under the derived keys of either mode (§3.6). */
export interface AccountKeyset {
  /** Alive for the rest of the creating operation (§24.1); dropped when it ends. */
  readonly derived: DerivedAccountKeys;
  readonly encryption: AccountKeyMaterial<ExtractableEnvelopePrivateKey, EnvelopePublicKey>;
  readonly signing: AccountKeyMaterial<ExtractableSigningKey, VerifyingKey>;
}

/**
 * §35.2 / §35.7 in Managed (§24, ADR-021): the keyset wrapped under the keys of a fresh 32-byte
 * `RootUnlockKey`. The bytes are returned because the escrow must wrap them (§3.6); the caller
 * zeroizes them once the `EscrowBlob` exists and never persists them (§24).
 */
export interface CreatedManagedKeyset extends AccountKeyset {
  readonly rootUnlockKey: Uint8Array;
}

export interface CreatedAccountRootKeyset extends AccountKeyset {
  /**
   * §24: 20 bytes. Shown once in the Setup Kit and stored nowhere (§3.3). The caller zeroizes it
   * when the operation ends; this package keeps no copy.
   */
  readonly accountSecretKey: Uint8Array;
  /** The Setup Kit form: 32 Crockford Base32 characters in groups of 4 (§24). */
  readonly accountSecretKeyText: string;
  readonly kdfSalt: Uint8Array;
  readonly argon2Params: Argon2ParamsRecord;
}

export interface CreateAccountRootKeysetRequest {
  readonly accountId: Uint8Array;
  readonly password: string;
  /** Omitted at account creation (§35.2 step 3 generates it); supplied by §35.6 when it changes. */
  readonly secretKey?: AccountSecretKeyInput;
  /** Defaults to ADR-004 profile 1. Always re-checked against the limits of its own version. */
  readonly argon2Params?: Argon2Params;
  /** Omitted at account creation; §35.6 keeps the salt only when the password did not change. */
  readonly kdfSalt?: Uint8Array;
  readonly ports?: KeyLifecyclePorts;
}

/** §23.4: `kdf_salt` is bytes(16); `account_id` and every other id is bytes(16) (§23.2). */
const ID_BYTES = 16;

function assertId(value: Uint8Array, what: string): void {
  if (!(value instanceof Uint8Array) || value.length !== ID_BYTES) {
    throw new KeyLifecycleError(`${what} must be ${ID_BYTES} bytes`);
  }
}

/**
 * Wraps the two account private keys under an `AccountKeyWrapKey` (§25, §23.4).
 * Exported because §35.6 re-wraps exactly these two blobs under the keys derived from the new
 * secrets, and there is no second way to do it.
 */
export async function wrapAccountPrivateKeys(
  keyWrapKey: KeyWrapKey,
  accountId: Uint8Array,
  privateKeys: {
    readonly encryption: ExtractableEnvelopePrivateKey;
    readonly signing: ExtractableSigningKey;
  },
): Promise<{ readonly encryption: WrappedPrivateKey; readonly signing: WrappedPrivateKey }> {
  assertId(accountId, "account_id");
  const [encryption, signing] = await Promise.all([
    wrapPrivateKey(keyWrapKey, accountPrivateKeyAad(accountId, "ACCOUNT_ENCRYPTION"), privateKeys.encryption),
    wrapPrivateKey(keyWrapKey, accountPrivateKeyAad(accountId, "ACCOUNT_SIGNING"), privateKeys.signing),
  ]);
  return {
    encryption: { key_role: "ACCOUNT_ENCRYPTION", blob: encryption },
    signing: { key_role: "ACCOUNT_SIGNING", blob: signing },
  };
}

/**
 * §35.2 steps 3–5 and 10: generate (or accept) the Account Secret Key, derive the §24 keys,
 * generate the Account Encryption and Account Signing key pairs, and wrap their privates.
 *
 * What comes back is everything the rest of the operation needs and nothing it does not: the
 * public SPKI bytes and their hashes for the Root Descriptor (§28.1) and the config (§26), the
 * wrapped blobs for the profile (§23.4), and the two derived keys, which §24.1 says live only
 * until the operation ends.
 */
export async function createAccountRootKeyset(
  request: CreateAccountRootKeysetRequest,
): Promise<Result<CreatedAccountRootKeyset>> {
  const { accountId, ports = defaultPorts } = request;
  assertId(accountId, "account_id");

  const params = checkKdfParams(request.argon2Params ?? ARGON2_PARAMS_V1);
  if (!params.ok) return params;

  const secretKey =
    request.secretKey === undefined
      ? { ok: true as const, value: ports.randomBytes(ACCOUNT_SECRET_KEY_BYTES) }
      : resolveAccountSecretKey(request.secretKey);
  if (!secretKey.ok) return secretKey;

  const kdfSalt = request.kdfSalt ?? ports.randomBytes(KDF_SALT_BYTES);
  if (kdfSalt.length !== KDF_SALT_BYTES) {
    throw new KeyLifecycleError(`kdf_salt must be ${KDF_SALT_BYTES} bytes, got ${kdfSalt.length}`);
  }

  const derived = await deriveAccountKeys(secretKey.value, request.password, kdfSalt, params.value, ports);
  return {
    ok: true,
    value: {
      accountSecretKey: secretKey.value,
      accountSecretKeyText: formatAccountSecretKey(secretKey.value),
      kdfSalt,
      argon2Params: toArgon2ParamsRecord(params.value),
      ...(await generateAccountKeyset(accountId, derived)),
    },
  };
}

/**
 * §35.2 in Managed, steps 4, 5 and 10: a random `RootUnlockKey`, the §24 keys derived from it, and
 * the two account pairs wrapped under them — the same keyset as in Private (§3.6).
 */
export async function createManagedAccountKeyset(request: {
  readonly accountId: Uint8Array;
  readonly ports?: KeyLifecyclePorts;
}): Promise<CreatedManagedKeyset> {
  const { accountId, ports = defaultPorts } = request;
  assertId(accountId, "account_id");
  const rootUnlockKey = ports.randomBytes(ROOT_UNLOCK_KEY_BYTES);
  const derived = await deriveManagedAccountKeys(rootUnlockKey);
  return { rootUnlockKey, ...(await generateAccountKeyset(accountId, derived)) };
}

/** §35.2 step 5 and 10: the two account pairs (§25.2: extractable only to be wrapped), wrapped. */
async function generateAccountKeyset(accountId: Uint8Array, derived: DerivedAccountKeys): Promise<AccountKeyset> {
  const [encryptionPair, signingPair] = await Promise.all([generateEnvelopeKeyPair(), generateSigningKeyPair()]);
  const [encryptionSpki, signingSpki] = await Promise.all([
    exportEnvelopePublicKey(encryptionPair.publicKey),
    exportVerifyingKey(signingPair.publicKey),
  ]);
  const [encryptionHash, signingHash] = await Promise.all([sha256(encryptionSpki), sha256(signingSpki)]);
  const wrapped = await wrapAccountPrivateKeys(derived.keyWrapKey, accountId, {
    encryption: encryptionPair.privateKey,
    signing: signingPair.privateKey,
  });

  return {
    derived,
    encryption: {
      privateKey: encryptionPair.privateKey,
      publicKey: encryptionPair.publicKey,
      publicKeySpki: encryptionSpki,
      publicKeyHash: encryptionHash,
      wrapped: wrapped.encryption,
    },
    signing: {
      privateKey: signingPair.privateKey,
      publicKey: signingPair.publicKey,
      publicKeySpki: signingSpki,
      publicKeyHash: signingHash,
      wrapped: wrapped.signing,
    },
  };
}

/**
 * §26: the config as an AES-GCM blob under the `AccountConfigKey`, AAD
 * `Context("nodra/aad/account-config", account_id, config_version)`.
 *
 * The AAD takes the record's own `account_id` and `config_version` here, because on this side the
 * caller *is* the author: sealing under anything else would produce a blob that no client can
 * open, which `openAccountSecurityConfig` would then report as `CONFIG_MISMATCH`.
 */
export async function sealAccountSecurityConfig(
  configKey: AeadKey,
  config: AccountSecurityConfig,
): Promise<Uint8Array> {
  return seal(configKey, accountConfigAad(config.account_id, config.config_version), encodeRecord(ACCOUNT_SECURITY_CONFIG, config));
}

export interface AccountSecurityProfileParts {
  readonly accountId: Uint8Array;
  /** §23.4: both present for a Private account, both absent for a Managed one. */
  readonly kdfSalt?: Uint8Array;
  readonly argon2Params?: Argon2ParamsRecord;
  readonly wrappedEncryptionKey: WrappedPrivateKey;
  readonly wrappedSigningKey: WrappedPrivateKey;
  /** §26: the plaintext copy the server keeps, so a client can compute "vigente + 1" (§23.4). */
  readonly configVersion: number;
  readonly configBlob: Uint8Array;
}

/** The `AccountSecurityProfile` of §23.4, in plaintext on the server. */
export function buildAccountSecurityProfile(parts: AccountSecurityProfileParts): AccountSecurityProfile {
  if ((parts.kdfSalt === undefined) !== (parts.argon2Params === undefined)) {
    throw new KeyLifecycleError("kdf_salt and argon2_params are both present (Private) or both absent (Managed)");
  }
  return {
    account_id: parts.accountId,
    ...(parts.kdfSalt === undefined ? {} : { kdf_salt: parts.kdfSalt }),
    ...(parts.argon2Params === undefined ? {} : { argon2_params: parts.argon2Params }),
    wrapped_account_encryption_key: parts.wrappedEncryptionKey,
    wrapped_account_signing_key: parts.wrappedSigningKey,
    config_version: parts.configVersion,
    config_blob: parts.configBlob,
  };
}

