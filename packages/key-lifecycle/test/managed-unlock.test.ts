// ADR-021: the Managed unlock (§24, §24.2) is the Private one with another key source. Same two HKDF
// calls with the `RootUnlockKey` as base and the empty salt, same keyset wrapping, same config, same
// unwrap calls and handles (§3.6: "Todo lo que cuelga de ella … es idéntico en los dos modos").
import fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";
import {
  EMPTY_SALT,
  deriveAeadKey,
  deriveKeyWrapKey,
  importHkdfBase,
  openEpochSecret,
  randomBytes,
  seal,
  sealEpochSecret,
  signContext,
  unseal,
  unwrapSigningKey,
  verifyContext,
} from "@nodra/crypto";
import type { HkdfBase } from "@nodra/crypto";
import { ACCOUNT_SECURITY_CONFIG, ACCOUNT_SECURITY_PROFILE, encodeRecord } from "@nodra/encoding/records";
import type { AccountSecurityConfig, AccountSecurityProfile } from "@nodra/encoding/records";
import { ACCOUNT_CONFIG_INFO, ACCOUNT_KEYWRAP_INFO, accountConfigAad, accountPrivateKeyAad, selfTestContext } from "../src/contexts.js";
import type { Result } from "../src/errors.js";
import { buildAccountConfig } from "../src/client-state.js";
import { sealAccountSecurityConfig, wrapAccountPrivateKeys } from "../src/keyset.js";
import { genesisDescriptor } from "../src/root-chain.js";
import { deriveManagedAccountKeys } from "../src/secrets.js";
import type { DerivedAccountKeys, RootUnlockKeySource } from "../src/secrets.js";
import { openAccountSecurityConfig, unlockForOperation, unlockForRewrap, unlockSession } from "../src/unlock.js";
import { createFixture, filled, makeConfig, memoPorts, toHex } from "./support.js";
import type { Fixture } from "./support.js";

const ports = memoPorts();

let fixture: Fixture; // a Private account: its key pairs are reused for the Managed ones

beforeAll(async () => {
  fixture = await createFixture({ ports });
}, 120_000);

interface ManagedAccount {
  readonly rootUnlockKey: Uint8Array;
  readonly config: AccountSecurityConfig;
  readonly profile: AccountSecurityProfile;
  readonly profileBytes: Uint8Array;
}

/** §35.2 in Managed, condensed: the same keyset, wrapped under the keys of a `RootUnlockKey`. */
async function managedAccount(
  rootUnlockKey: Uint8Array,
  derive: (key: Uint8Array) => Promise<DerivedAccountKeys> = deriveManagedAccountKeys,
): Promise<ManagedAccount> {
  const derived = await derive(rootUnlockKey);
  const wrapped = await wrapAccountPrivateKeys(derived.keyWrapKey, fixture.accountId, {
    encryption: fixture.keyset.encryption.privateKey,
    signing: fixture.keyset.signing.privateKey,
  });
  const config = { ...makeConfig(fixture.accountId, 1, fixture.keyset), crypto_version: 2 };
  const profile: AccountSecurityProfile = {
    account_id: fixture.accountId,
    wrapped_account_encryption_key: wrapped.encryption,
    wrapped_account_signing_key: wrapped.signing,
    config_version: 1,
    config_blob: await sealAccountSecurityConfig(derived.configKey, config),
  };
  return { rootUnlockKey, config, profile, profileBytes: encodeRecord(ACCOUNT_SECURITY_PROFILE, profile) };
}

function failureOf(result: Result<unknown>): string {
  if (result.ok) throw new Error("expected a failure");
  return result.failure.code;
}

function usagesOf(key: CryptoKey): string[] {
  return [...key.usages].sort();
}

describe("§24 Managed derivation", () => {
  /**
   * The oracle: `derive` is §24's Managed derivation exactly — HKDF over the `RootUnlockKey` with the
   * empty salt and the two account infos — checked against keys derived independently here.
   */
  async function isTheSpecDerivation(derive: (key: Uint8Array) => Promise<DerivedAccountKeys>): Promise<boolean> {
    const rootUnlockKey = randomBytes(32);
    const base = await importHkdfBase(rootUnlockKey);
    const configKey = await deriveAeadKey(base, { salt: EMPTY_SALT, info: ACCOUNT_CONFIG_INFO });
    const keyWrapKey = await deriveKeyWrapKey(base, { salt: EMPTY_SALT, info: ACCOUNT_KEYWRAP_INFO });
    const derived = await derive(rootUnlockKey);
    const aad = accountConfigAad(fixture.accountId, 1);
    try {
      await unseal(configKey, aad, await seal(derived.configKey, aad, new Uint8Array([1, 2, 3])));
      const wrapped = await wrapAccountPrivateKeys(derived.keyWrapKey, fixture.accountId, {
        encryption: fixture.keyset.encryption.privateKey,
        signing: fixture.keyset.signing.privateKey,
      });
      await unwrapSigningKey(keyWrapKey, accountPrivateKeyAad(fixture.accountId, "ACCOUNT_SIGNING"), wrapped.signing.blob);
      return true;
    } catch {
      return false;
    }
  }

  it("is HKDF(RootUnlockKey, salt = empty, info = the account contexts)", async () => {
    expect(await isTheSpecDerivation(deriveManagedAccountKeys)).toBe(true);
  });

  it("broken variant: a salted derivation is caught", async () => {
    const salted = async (key: Uint8Array): Promise<DerivedAccountKeys> => {
      const base = await importHkdfBase(key);
      return {
        keyWrapKey: await deriveKeyWrapKey(base, { salt: fixture.accountId, info: ACCOUNT_KEYWRAP_INFO }),
        configKey: await deriveAeadKey(base, { salt: fixture.accountId, info: ACCOUNT_CONFIG_INFO }),
      };
    };
    expect(await isTheSpecDerivation(salted)).toBe(false);
  });

  it("broken variant: swapped infos are caught", async () => {
    const swapped = async (key: Uint8Array): Promise<DerivedAccountKeys> => {
      const base = await importHkdfBase(key);
      return {
        keyWrapKey: await deriveKeyWrapKey(base, { salt: EMPTY_SALT, info: ACCOUNT_CONFIG_INFO }),
        configKey: await deriveAeadKey(base, { salt: EMPTY_SALT, info: ACCOUNT_KEYWRAP_INFO }),
      };
    };
    expect(await isTheSpecDerivation(swapped)).toBe(false);
  });

  it("the RootUnlockKey bytes and the RootUnlockBase handle derive the same keys (§24.2 step 4)", async () => {
    const bytes = randomBytes(32);
    const fromBytes = await deriveManagedAccountKeys(bytes);
    const fromBase = await deriveManagedAccountKeys(await importHkdfBase(bytes));
    const aad = accountConfigAad(fixture.accountId, 1);
    const sealed = await seal(fromBytes.configKey, aad, new Uint8Array([7]));
    expect(toHex(await unseal(fromBase.configKey, aad, sealed))).toBe("07");
  });

  it("refuses a RootUnlockKey that is not 32 bytes", async () => {
    for (const n of [0, 16, 31, 33]) {
      await expect(deriveManagedAccountKeys(new Uint8Array(n))).rejects.toThrow(/32 bytes/);
    }
  });
});

describe("§24.2 Managed unlock entry points", () => {
  let managed: ManagedAccount;

  beforeAll(async () => {
    managed = await managedAccount(randomBytes(32));
  });

  const request = (rootUnlockKey: RootUnlockKeySource, profile: Uint8Array = managed.profileBytes) => ({
    accountId: fixture.accountId,
    profile,
    rootUnlockKey,
  });

  it("unlockSession opens the config and gives the Session handle of §25.1", async () => {
    const result = await unlockSession(request(managed.rootUnlockKey));
    if (!result.ok) throw new Error(result.failure.code);
    expect(result.value.config).toEqual(managed.config);
    expect(result.value.sessionKey.extractable).toBe(false);
    expect(usagesOf(result.value.sessionKey)).toEqual(["unwrapKey"]);
  });

  it("unlockForOperation and unlockForRewrap give the same handles as in Private", async () => {
    const op = await unlockForOperation(request(managed.rootUnlockKey));
    if (!op.ok) throw new Error(op.failure.code);
    expect(usagesOf(op.value.operationKey)).toEqual(["decrypt"]);
    expect(usagesOf(op.value.signingKey)).toEqual(["sign"]);
    const rewrap = await unlockForRewrap(request(managed.rootUnlockKey));
    if (!rewrap.ok) throw new Error(rewrap.failure.code);
    expect(rewrap.value.encryptionKey.extractable).toBe(true);
    expect(rewrap.value.signingKey.extractable).toBe(true);
  });

  it("accepts the RootUnlockBase handle an escrow re-wrap yields", async () => {
    const base: HkdfBase = await importHkdfBase(managed.rootUnlockKey);
    expect((await unlockSession(request(base))).ok).toBe(true);
  });

  it("a wrong RootUnlockKey is SECRETS_REJECTED, like wrong secrets", async () => {
    expect(failureOf(await unlockSession(request(randomBytes(32))))).toBe("SECRETS_REJECTED");
  });

  it("a Managed unlock of a Private profile, or a Private unlock of a Managed one, is MALFORMED_PROFILE (§23.4)", async () => {
    expect(failureOf(await unlockSession(request(managed.rootUnlockKey, fixture.profileBytes)))).toBe("MALFORMED_PROFILE");
    const privateOfManaged = await unlockSession({
      accountId: fixture.accountId,
      profile: managed.profileBytes,
      secrets: { password: fixture.password, secretKey: fixture.secretKey },
      ports,
    });
    expect(failureOf(privateOfManaged)).toBe("MALFORMED_PROFILE");
    // Half a KDF profile is neither mode.
    const { argon2_params: _dropped, ...halfPrivate } = fixture.profile;
    const half = await unlockSession({
      accountId: fixture.accountId,
      profile: halfPrivate,
      secrets: { password: fixture.password, secretKey: fixture.secretKey },
      ports,
    });
    expect(failureOf(half)).toBe("MALFORMED_PROFILE");
  });
});

describe("one pipeline (§3.6), property", () => {
  it("a Managed and a Private keyset open through the same unwrap calls into interchangeable handles", async () => {
    const ctx = selfTestContext(fixture.accountId, filled(16, 0x33));
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ minLength: 32, maxLength: 32 }), fc.uint8Array({ minLength: 32, maxLength: 32 }), async (rootUnlockKey, secret) => {
        const managed = await managedAccount(rootUnlockKey);
        const viaManaged = await unlockForOperation({ accountId: fixture.accountId, profile: managed.profile, rootUnlockKey });
        const viaPrivate = await unlockForOperation({
          accountId: fixture.accountId,
          profile: fixture.profile,
          secrets: { password: fixture.password, secretKey: fixture.secretKey },
          ports,
        });
        if (!viaManaged.ok || !viaPrivate.ok) throw new Error("both modes must unlock");
        // What one mode's signing handle signs, the account's public key verifies — for both.
        for (const unlocked of [viaManaged.value, viaPrivate.value]) {
          const signature = await signContext(unlocked.signingKey, ctx);
          expect(await verifyContext(fixture.keyset.signing.publicKey, ctx, signature)).toBe(true);
        }
        // And both Operation handles open one envelope to the account's encryption key.
        const envelope = await sealEpochSecret(fixture.keyset.encryption.publicKey, ctx, secret);
        for (const unlocked of [viaManaged.value, viaPrivate.value]) {
          expect(toHex(await openEpochSecret(unlocked.operationKey, ctx, envelope))).toBe(toHex(secret));
        }
      }),
      { numRuns: 6 },
    );
  }, 120_000);
});

describe("crypto_version (§23.1)", () => {
  async function openWithVersion(version: number): Promise<Result<AccountSecurityConfig>> {
    const derived = await deriveManagedAccountKeys(filled(32, 0x42));
    const config = { ...makeConfig(fixture.accountId, 1, fixture.keyset), crypto_version: version };
    const blob = await seal(derived.configKey, accountConfigAad(fixture.accountId, 1), encodeRecord(ACCOUNT_SECURITY_CONFIG, config));
    return openAccountSecurityConfig(derived.configKey, fixture.accountId, 1, blob);
  }

  it("accepts versions 1 and 2", async () => {
    expect((await openWithVersion(1)).ok).toBe(true);
    expect((await openWithVersion(2)).ok).toBe(true);
  });

  it("§23.0 rule 7: refuses any other version instead of degrading", async () => {
    for (const version of [0, 3, 1000]) expect(failureOf(await openWithVersion(version))).toBe("UNSUPPORTED_CRYPTO_VERSION");
  });
});

describe("the config carries the account's crypto_version (§26, §23.1)", () => {
  it("buildAccountConfig copies the pending root's version", async () => {
    for (const version of [1, 2]) {
      const root = genesisDescriptor(
        fixture.accountId,
        { accountEncryption: filled(8, 1), accountSigning: filled(8, 2), recoveryEncryption: filled(8, 3), recoveryAuthority: filled(8, 4) },
        version,
      );
      const config = await buildAccountConfig({
        root,
        rootHash: filled(32, 5),
        genesisRootHash: filled(32, 5),
        registryVersion: 1,
        registryHash: filled(32, 6),
        configVersion: 1,
      });
      expect(config.crypto_version).toBe(version);
    }
  });
});
