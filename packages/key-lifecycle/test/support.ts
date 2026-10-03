import { readFileSync } from "node:fs";
import { ARGON2_PARAMS_V1, KDF_SALT_BYTES, derivePasswordKey, randomBytes } from "@nodra/crypto";
import type { Argon2Params } from "@nodra/crypto";
import { ACCOUNT_SECURITY_PROFILE, encodeRecord } from "@nodra/encoding/records";
import type { AccountSecurityConfig, AccountSecurityProfile } from "@nodra/encoding/records";
import {
  buildAccountSecurityProfile,
  createAccountRootKeyset,
  sealAccountSecurityConfig,
} from "../src/keyset.js";
import type { CreatedAccountRootKeyset } from "../src/keyset.js";
import type { KeyLifecyclePorts } from "../src/ports.js";
import { filled, fromHex, toHex } from "./bytes-support.js";

export { filled, flipByte, fromHex, toHex } from "./bytes-support.js";

/**
 * ADR-004 profile 1, which is also its own minimum (crypto NOTES Q167): §24 defines no cheaper
 * test profile, so every test that runs the real KDF runs the production parameters. That costs
 * over a second per distinct (password, salt) pair, which is why {@link memoPorts} exists.
 */
export const TEST_PARAMS: Argon2Params = ARGON2_PARAMS_V1;

/**
 * A fixed clock for the one timestamp this package writes (§27.1 `created_at`). Ambient `Date.now`
 * would make a kit's bytes differ between runs, and §27's determinism assertions need them fixed.
 */
export const FIXED_NOW = (): number => 1_764_000_000_000;

/**
 * The real Argon2id, memoized. Memoization is not a stub: the same inputs would produce the same
 * bytes anyway, so nothing an assertion depends on is weakened — only the wall clock.
 */
export function memoPorts(): KeyLifecyclePorts {
  const cache = new Map<string, Promise<Uint8Array>>();
  return {
    randomBytes,
    now: FIXED_NOW,
    derivePasswordKey: (password, kdfSalt, params) => {
      const key = `${JSON.stringify(password)}|${toHex(kdfSalt)}|${params.memoryKib}|${params.iterations}|${params.parallelism}|${params.version}`;
      let hit = cache.get(key);
      if (hit === undefined) {
        hit = derivePasswordKey(password, kdfSalt, params);
        cache.set(key, hit);
      }
      // A fresh copy per call: callers zeroize what they receive (§24).
      return hit.then((bytes) => Uint8Array.from(bytes));
    },
  };
}

/**
 * A cheap stand-in for Argon2id, for property runs that exercise the *composition* around it
 * (HKDF salting, AAD binding, wrap/unwrap) rather than the KDF itself, which has its own
 * known-answer vectors in `@nodra/crypto`. It is a real function of all three inputs — a
 * different password or salt gives different bytes — but it costs microseconds.
 *
 * It deliberately does **not** normalize the password to NFC, so it cannot accidentally make the
 * NFC/NFD test pass; that test uses {@link memoPorts}.
 */
export function stubKdfPorts(): KeyLifecyclePorts {
  return {
    randomBytes,
    now: FIXED_NOW,
    derivePasswordKey: async (password, kdfSalt, params) => {
      const encoded = new TextEncoder().encode(
        `${password}\u0000${toHex(kdfSalt)}\u0000${params.memoryKib}:${params.iterations}:${params.parallelism}:${params.version}`,
      );
      return new Uint8Array(await crypto.subtle.digest("SHA-256", encoded));
    },
  };
}

/** Deterministic `randomBytes`, so a whole account can be rebuilt byte for byte from a seed. */
export function seededPorts(seed: number, kdf: KeyLifecyclePorts): KeyLifecyclePorts {
  let state = seed >>> 0;
  return {
    derivePasswordKey: kdf.derivePasswordKey,
    now: kdf.now,
    randomBytes: (length) => {
      const out = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        state = (state * 1_664_525 + 1_013_904_223) >>> 0;
        out[i] = (state >>> 24) & 0xff;
      }
      return out;
    },
  };
}

/** A Private account's profile: `kdf_salt` and `argon2_params` present (§23.4). */
export type PrivateProfile = AccountSecurityProfile & Required<Pick<AccountSecurityProfile, "kdf_salt" | "argon2_params">>;

export interface Fixture {
  readonly accountId: Uint8Array;
  readonly password: string;
  readonly secretKey: Uint8Array;
  readonly secretKeyText: string;
  readonly keyset: CreatedAccountRootKeyset;
  readonly config: AccountSecurityConfig;
  readonly profile: PrivateProfile;
  readonly profileBytes: Uint8Array;
}

export interface FixtureRequest {
  readonly ports: KeyLifecyclePorts;
  readonly accountId?: Uint8Array;
  readonly password?: string;
  readonly secretKey?: string | Uint8Array;
  readonly kdfSalt?: Uint8Array;
  readonly argon2Params?: Argon2Params;
  readonly configVersion?: number;
}

/**
 * §35.2 steps 3–5, 10 and 14, condensed: a created account with its profile and config, exactly
 * as a server would hold them. The root, registry and recovery hashes are filler — §27–§29 are
 * not in this slice, and nothing here reads them.
 */
export async function createFixture(request: FixtureRequest): Promise<Fixture> {
  const accountId = request.accountId ?? filled(16, 0x11);
  const password = request.password ?? "correct horse battery staple";
  const configVersion = request.configVersion ?? 1;

  const created = await createAccountRootKeyset({
    accountId,
    password,
    ...(request.secretKey === undefined ? {} : { secretKey: request.secretKey }),
    ...(request.kdfSalt === undefined ? {} : { kdfSalt: request.kdfSalt }),
    argon2Params: request.argon2Params ?? TEST_PARAMS,
    ports: request.ports,
  });
  if (!created.ok) throw new Error(`fixture: ${created.failure.code} ${created.failure.message}`);
  const keyset = created.value;

  const config = makeConfig(accountId, configVersion, keyset);
  const configBlob = await sealAccountSecurityConfig(keyset.derived.configKey, config);
  const profile: PrivateProfile = {
    ...buildAccountSecurityProfile({
    accountId,
    kdfSalt: keyset.kdfSalt,
    argon2Params: keyset.argon2Params,
    wrappedEncryptionKey: keyset.encryption.wrapped,
    wrappedSigningKey: keyset.signing.wrapped,
    configVersion,
    configBlob,
    }),
    kdf_salt: keyset.kdfSalt,
    argon2_params: keyset.argon2Params,
  };

  return {
    accountId,
    password,
    secretKey: keyset.accountSecretKey,
    secretKeyText: keyset.accountSecretKeyText,
    keyset,
    config,
    profile,
    profileBytes: encodeRecord(ACCOUNT_SECURITY_PROFILE, profile),
  };
}

export function makeConfig(
  accountId: Uint8Array,
  configVersion: number,
  keyset: CreatedAccountRootKeyset,
): AccountSecurityConfig {
  return {
    account_id: accountId,
    config_version: configVersion,
    root_generation: 1,
    root_hash: filled(32, 0xa1),
    genesis_root_hash: filled(32, 0xa1),
    account_encryption_public_key_hash: keyset.encryption.publicKeyHash,
    account_signing_public_key_hash: keyset.signing.publicKeyHash,
    recovery_encryption_public_key_hash: filled(32, 0xb1),
    recovery_authority_public_key_hash: filled(32, 0xb2),
    registry_version: 1,
    registry_hash: filled(32, 0xc1),
    crypto_version: 1,
  };
}

/** Returns a copy of a profile with one field replaced. */
export function withProfile(
  profile: PrivateProfile,
  patch: Partial<AccountSecurityProfile>,
): AccountSecurityProfile {
  return { ...profile, ...patch };
}

export interface UnlockVectorCase {
  name: string;
  password: string;
  secretKeyText: string;
  secretKeyHex: string;
  kdfSaltHex: string;
  argon2Params: { memoryKib: number; iterations: number; parallelism: number; version: number };
  passwordKeyHex: string;
  accountKeyWrapKeyHex: string;
  accountConfigKeyHex: string;
}

export interface UnlockVectors {
  note: string;
  contexts: { accountKeywrapInfoHex: string; accountConfigInfoHex: string; accountPrivateKeyAadHex: string; accountConfigAadHex: string };
  cases: UnlockVectorCase[];
}

export const unlockVectors: UnlockVectors = JSON.parse(
  readFileSync(new URL("../vectors/unlock.json", import.meta.url), "utf8"),
) as UnlockVectors;

export { KDF_SALT_BYTES };
