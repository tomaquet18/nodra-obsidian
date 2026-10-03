// The two-secret unlock (§24) and the handle table (§25.1).
//
// The negatives are the point of this file. §24 asks for one property above all — that a stolen
// database gives no way to verify a password offline — and the only way a test can hold the
// implementation to it is to check that *every* secret-dependent failure is the same value.
import { beforeAll, describe, expect, it } from "vitest";
import {
  deriveBits,
  derivePasswordKey,
  importAeadKey,
  importHkdfBase,
  seal,
  sha256,
  unseal,
  verifyContext,
} from "@nodra/crypto";
import type { KeyWrapKey } from "@nodra/crypto";
import { encode } from "@nodra/encoding";
import { ACCOUNT_SECURITY_CONFIG, ACCOUNT_SECURITY_PROFILE, encodeRecord } from "@nodra/encoding/records";
import { formatAccountSecretKey } from "@nodra/encoding/secret-key";
import { ACCOUNT_CONFIG_INFO, ACCOUNT_KEYWRAP_INFO, accountConfigAad, accountPrivateKeyAad } from "../src/contexts.js";
import { SECRETS_REJECTED_MESSAGE } from "../src/errors.js";
import type { Result } from "../src/errors.js";
import { deriveAccountKeys } from "../src/secrets.js";
import { wrapAccountPrivateKeys } from "../src/keyset.js";
import {
  openAccountSecurityConfig,
  parseAccountSecurityProfile,
  unlockForOperation,
  unlockForRewrap,
  unlockSession,
} from "../src/unlock.js";
import type { KeyLifecyclePorts } from "../src/ports.js";
import {
  TEST_PARAMS,
  createFixture,
  filled,
  flipByte,
  fromHex,
  memoPorts,
  seededPorts,
  toHex,
  unlockVectors,
  withProfile,
} from "./support.js";
import type { Fixture } from "./support.js";

const ports = memoPorts();

/** A second, unrelated Account Secret Key. */
const OTHER_SECRET_KEY = new Uint8Array(20).map((_, i) => (i * 31 + 5) & 0xff);

function usagesOf(key: CryptoKey): string[] {
  return [...key.usages].sort();
}

function failureOf(result: Result<unknown>): { code: string; message: string } {
  if (result.ok) throw new Error("expected a failure, got a successful unlock");
  return { code: result.failure.code, message: result.failure.message };
}

describe("§24 two-secret unlock", () => {
  let fixture: Fixture;

  beforeAll(async () => {
    fixture = await createFixture({ ports });
  }, 120_000);

  function request(overrides: Partial<{ password: string; secretKey: string | Uint8Array; profile: Uint8Array; accountId: Uint8Array }> = {}) {
    return {
      accountId: overrides.accountId ?? fixture.accountId,
      profile: overrides.profile ?? fixture.profileBytes,
      secrets: {
        password: overrides.password ?? fixture.password,
        secretKey: overrides.secretKey ?? fixture.secretKey,
      },
      ports,
    };
  }

  describe("the happy path (§35.3)", () => {
    it("opens the §26 config with the right secrets", async () => {
      const result = await unlockSession(request());
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.config).toEqual(fixture.config);
      expect(toHex(result.value.accountId)).toBe(toHex(fixture.accountId));
    });

    it("accepts the Setup Kit text with hyphens, lower case and the O/0 and I/L/1 confusions", async () => {
      // §44.3: "Secret Key tecleada en minúsculas, con guiones y confusiones O/0, I/L/1 →
      // misma derivación". The grouped text is what the user actually retypes.
      const mangled = fixture.secretKeyText.toLowerCase().replace(/0/g, "o").replace(/1/g, "l");
      const result = await unlockSession(request({ secretKey: mangled }));
      expect(result.ok).toBe(true);
    });

    it("accepts the 20 decoded bytes and the text interchangeably", async () => {
      const fromText = await unlockSession(request({ secretKey: formatAccountSecretKey(fixture.secretKey) }));
      const fromBytes = await unlockSession(request({ secretKey: fixture.secretKey }));
      expect(fromText.ok && fromBytes.ok).toBe(true);
    });

    it("accepts an already-decoded profile record as well as its bytes", async () => {
      const result = await unlockSession({ ...request(), profile: fixture.profile });
      expect(result.ok).toBe(true);
    });
  });

  describe("§25.1 handle table", () => {
    it("Session: Account Encryption, extractable = false, ['unwrapKey']", async () => {
      const result = await unlockSession(request());
      if (!result.ok) throw new Error(result.failure.code);
      const key = result.value.sessionKey;
      expect(key.type).toBe("private");
      expect(key.algorithm.name).toBe("RSA-OAEP");
      expect(key.extractable).toBe(false);
      expect(usagesOf(key)).toEqual(["unwrapKey"]);
    });

    it("§44.3: the Session handle cannot decrypt()", async () => {
      const result = await unlockSession(request());
      if (!result.ok) throw new Error(result.failure.code);
      await expect(
        crypto.subtle.decrypt({ name: "RSA-OAEP" }, result.value.sessionKey, new Uint8Array(384)),
      ).rejects.toThrow();
    });

    it("§24.1: the Session unlock hands back no derived key", async () => {
      const result = await unlockSession(request());
      if (!result.ok) throw new Error(result.failure.code);
      expect(Object.keys(result.value).sort()).toEqual(["accountId", "config", "sessionKey"]);
    });

    it("Operation and Signing: extractable = false, ['decrypt'] and ['sign']", async () => {
      const result = await unlockForOperation(request());
      if (!result.ok) throw new Error(result.failure.code);
      expect(result.value.operationKey.algorithm.name).toBe("RSA-OAEP");
      expect(result.value.operationKey.extractable).toBe(false);
      expect(usagesOf(result.value.operationKey)).toEqual(["decrypt"]);
      expect(result.value.signingKey.algorithm.name).toBe("ECDSA");
      expect(result.value.signingKey.extractable).toBe(false);
      expect(usagesOf(result.value.signingKey)).toEqual(["sign"]);
    });

    it("Re-wrap temporal (§35.6): extractable = true, with the non-empty usages Web Crypto demands", async () => {
      const result = await unlockForRewrap(request());
      if (!result.ok) throw new Error(result.failure.code);
      expect(result.value.encryptionKey.extractable).toBe(true);
      expect(usagesOf(result.value.encryptionKey)).toEqual(["decrypt"]);
      expect(result.value.signingKey.extractable).toBe(true);
      expect(usagesOf(result.value.signingKey)).toEqual(["sign"]);
    });

    it("the unwrapped keys are the ones that were wrapped", async () => {
      const result = await unlockForOperation(request());
      if (!result.ok) throw new Error(result.failure.code);
      const ctx = accountConfigAad(fixture.accountId, 7); // any context; this is an identity check
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        result.value.signingKey,
        ctx as BufferSource,
      );
      expect(await verifyContext(fixture.keyset.signing.publicKey, ctx, new Uint8Array(signature))).toBe(true);
    });
  });

  describe("wrong secrets are one indistinguishable failure (§24)", () => {
    it("right password + wrong Secret Key", async () => {
      expect(failureOf(await unlockSession(request({ secretKey: OTHER_SECRET_KEY })))).toEqual({
        code: "SECRETS_REJECTED",
        message: SECRETS_REJECTED_MESSAGE,
      });
    });

    it("wrong password + right Secret Key", async () => {
      expect(failureOf(await unlockSession(request({ password: "not the password" })))).toEqual({
        code: "SECRETS_REJECTED",
        message: SECRETS_REJECTED_MESSAGE,
      });
    });

    it("both wrong", async () => {
      expect(
        failureOf(await unlockSession(request({ password: "not the password", secretKey: OTHER_SECRET_KEY }))),
      ).toEqual({ code: "SECRETS_REJECTED", message: SECRETS_REJECTED_MESSAGE });
    });

    it("the three failures are the same value, code and message", async () => {
      // This is the executable form of §24's "sin Account Secret Key, un atacante NO puede
      // verificar intentos de contraseña offline": an attacker who could tell these apart would
      // have exactly the oracle the design exists to deny.
      const [wrongKey, wrongPassword, both] = await Promise.all([
        unlockSession(request({ secretKey: OTHER_SECRET_KEY })),
        unlockSession(request({ password: "not the password" })),
        unlockSession(request({ password: "not the password", secretKey: OTHER_SECRET_KEY })),
      ]);
      expect(failureOf(wrongPassword)).toEqual(failureOf(wrongKey));
      expect(failureOf(both)).toEqual(failureOf(wrongKey));
    });

    it("a tampered wrapped key is the same failure again", async () => {
      const profile = withProfile(fixture.profile, {
        wrapped_account_encryption_key: {
          key_role: "ACCOUNT_ENCRYPTION",
          blob: flipByte(fixture.profile.wrapped_account_encryption_key.blob, 30),
        },
      });
      expect(failureOf(await unlockSession(request({ profile: encodeRecord(ACCOUNT_SECURITY_PROFILE, profile) })))).toEqual(
        { code: "SECRETS_REJECTED", message: SECRETS_REJECTED_MESSAGE },
      );
    });

    it("a tampered config blob, and a tampered kdf_salt, are the same failure again", async () => {
      const tamperedConfig = withProfile(fixture.profile, { config_blob: flipByte(fixture.profile.config_blob, 20) });
      const tamperedSalt = withProfile(fixture.profile, { kdf_salt: flipByte(fixture.profile.kdf_salt, 3) });
      for (const profile of [tamperedConfig, tamperedSalt]) {
        expect(
          failureOf(await unlockSession(request({ profile: encodeRecord(ACCOUNT_SECURITY_PROFILE, profile) }))),
        ).toEqual({ code: "SECRETS_REJECTED", message: SECRETS_REJECTED_MESSAGE });
      }
    });

    it("the Session unlock does not authenticate the wrapped signing key", async () => {
      // Found by the tampering property, and it is what §35.3 asks for: the Session handle is the
      // Account *Encryption* key, so a corrupted `wrapped_account_signing_key` survives an unlock
      // and only surfaces when a §35 operation asks for the Signing handle. Recorded as a fact,
      // not a hole to widen: narrowing the Session unlock's reach is deliberate (NOTES Q182).
      const profile = withProfile(fixture.profile, {
        wrapped_account_signing_key: {
          key_role: "ACCOUNT_SIGNING",
          blob: flipByte(fixture.profile.wrapped_account_signing_key.blob, 40),
        },
      });
      const bytes = encodeRecord(ACCOUNT_SECURITY_PROFILE, profile);
      expect((await unlockSession(request({ profile: bytes }))).ok).toBe(true);
      expect(failureOf(await unlockForOperation(request({ profile: bytes }))).code).toBe("SECRETS_REJECTED");
      expect(failureOf(await unlockForRewrap(request({ profile: bytes }))).code).toBe("SECRETS_REJECTED");
    });

    it("§44.3: the wrong key_role fails the unwrap", async () => {
      // The two blobs swapped. Each still decodes as a `WrappedPrivateKey`, but the AAD of §23.3
      // binds `key_role`, so neither opens under the other's role.
      const profile = withProfile(fixture.profile, {
        wrapped_account_encryption_key: {
          key_role: "ACCOUNT_ENCRYPTION",
          blob: fixture.profile.wrapped_account_signing_key.blob,
        },
        wrapped_account_signing_key: {
          key_role: "ACCOUNT_SIGNING",
          blob: fixture.profile.wrapped_account_encryption_key.blob,
        },
      });
      expect(failureOf(await unlockSession(request({ profile: encodeRecord(ACCOUNT_SECURITY_PROFILE, profile) })))).toEqual(
        { code: "SECRETS_REJECTED", message: SECRETS_REJECTED_MESSAGE },
      );
    });
  });

  describe("the profile is not trusted before the unlock (§24)", () => {
    it("rejects parameters below the ADR-004 minimum without running the KDF", async () => {
      let kdfCalls = 0;
      const counting: KeyLifecyclePorts = {
        ...ports,
        derivePasswordKey: (...args) => {
          kdfCalls += 1;
          return ports.derivePasswordKey(...args);
        },
      };
      const profile = withProfile(fixture.profile, {
        argon2_params: { ...fixture.profile.argon2_params, memory_kib: 8 },
      });
      const result = await unlockSession({
        ...request({ profile: encodeRecord(ACCOUNT_SECURITY_PROFILE, profile) }),
        ports: counting,
      });
      expect(failureOf(result).code).toBe("KDF_PARAMS_REJECTED");
      expect(kdfCalls).toBe(0);
    });

    it("rejects parameters above the ADR-004 maximum", async () => {
      for (const patch of [{ memory_kib: 1_048_576 }, { iterations: 1_000 }, { parallelism: 64 }]) {
        const profile = withProfile(fixture.profile, {
          argon2_params: { ...fixture.profile.argon2_params, ...patch },
        });
        const result = await unlockSession(request({ profile: encodeRecord(ACCOUNT_SECURITY_PROFILE, profile) }));
        expect(failureOf(result).code).toBe("KDF_PARAMS_REJECTED");
      }
    });

    it("rejects an unsupported profile version rather than guessing its limits", async () => {
      const profile = withProfile(fixture.profile, {
        argon2_params: { ...fixture.profile.argon2_params, version: 99 },
      });
      const result = await unlockSession(request({ profile: encodeRecord(ACCOUNT_SECURITY_PROFILE, profile) }));
      expect(failureOf(result).code).toBe("UNSUPPORTED_KDF_PROFILE");
    });

    it("rejects a profile that names another account before spending a second on Argon2id", async () => {
      let kdfCalls = 0;
      const counting: KeyLifecyclePorts = {
        ...ports,
        derivePasswordKey: (...args) => {
          kdfCalls += 1;
          return ports.derivePasswordKey(...args);
        },
      };
      const result = await unlockSession({ ...request({ accountId: filled(16, 0x99) }), ports: counting });
      expect(failureOf(result).code).toBe("MALFORMED_PROFILE");
      expect(kdfCalls).toBe(0);
    });

    it("rejects truncated, padded and garbage profile bytes", async () => {
      const cases = [
        fixture.profileBytes.subarray(0, fixture.profileBytes.length - 1),
        fixture.profileBytes.subarray(1),
        new Uint8Array([...fixture.profileBytes, 0x00]),
        new Uint8Array(0),
        filled(64, 0xff),
      ];
      for (const bytes of cases) {
        expect(failureOf(parseAccountSecurityProfile(bytes)).code).toBe("MALFORMED_PROFILE");
        expect(failureOf(await unlockSession(request({ profile: bytes }))).code).toBe("MALFORMED_PROFILE");
      }
    });

    it("rejects a Secret Key that does not decode to 20 bytes", async () => {
      const bad: (string | Uint8Array)[] = [
        "",
        "not base 32 at all!",
        fixture.secretKeyText.slice(0, 20), // truncated
        `${fixture.secretKeyText}-0000`, // too long
        "U".repeat(32), // Crockford excludes U (encoding NOTES Q177)
        new Uint8Array(19),
      ];
      for (const secretKey of bad) {
        expect(failureOf(await unlockSession(request({ secretKey }))).code).toBe("BAD_SECRET_KEY_FORMAT");
      }
    });
  });

  describe("§26 config checks", () => {
    it("rejects a config whose plaintext contradicts the AAD it was sealed under", async () => {
      // Reachable: the AAD carries `account_id` and `config_version` alongside a record that
      // repeats them, and nothing in AES-GCM forces the two copies to agree.
      const lying = { ...fixture.config, account_id: filled(16, 0x77) };
      const blob = await seal(
        fixture.keyset.derived.configKey,
        accountConfigAad(fixture.accountId, fixture.config.config_version),
        encodeRecord(ACCOUNT_SECURITY_CONFIG, lying),
      );
      const result = await openAccountSecurityConfig(
        fixture.keyset.derived.configKey,
        fixture.accountId,
        fixture.config.config_version,
        blob,
      );
      expect(failureOf(result).code).toBe("CONFIG_MISMATCH");
    });

    it("rejects a config whose config_version contradicts the AAD", async () => {
      const lying = { ...fixture.config, config_version: 42 };
      const blob = await seal(
        fixture.keyset.derived.configKey,
        accountConfigAad(fixture.accountId, fixture.config.config_version),
        encodeRecord(ACCOUNT_SECURITY_CONFIG, lying),
      );
      const result = await openAccountSecurityConfig(
        fixture.keyset.derived.configKey,
        fixture.accountId,
        fixture.config.config_version,
        blob,
      );
      expect(failureOf(result).code).toBe("CONFIG_MISMATCH");
    });

    it("rejects a config that is not a canonical AccountSecurityConfig", async () => {
      const blob = await seal(
        fixture.keyset.derived.configKey,
        accountConfigAad(fixture.accountId, fixture.config.config_version),
        encode([1, 2, 3]),
      );
      const result = await openAccountSecurityConfig(
        fixture.keyset.derived.configKey,
        fixture.accountId,
        fixture.config.config_version,
        blob,
      );
      expect(failureOf(result).code).toBe("MALFORMED_CONFIG");
    });

    it("§23.0 rule 7: refuses a crypto_version it does not implement instead of degrading", async () => {
      const future = { ...fixture.config, crypto_version: 3 };
      const blob = await seal(
        fixture.keyset.derived.configKey,
        accountConfigAad(fixture.accountId, fixture.config.config_version),
        encodeRecord(ACCOUNT_SECURITY_CONFIG, future),
      );
      const result = await openAccountSecurityConfig(
        fixture.keyset.derived.configKey,
        fixture.accountId,
        fixture.config.config_version,
        blob,
      );
      expect(failureOf(result).code).toBe("UNSUPPORTED_CRYPTO_VERSION");
    });
  });

  describe("broken-variant proofs", () => {
    it("a derivation that ignores the Account Secret Key is caught by these tests", async () => {
      // The variant: HKDF with an empty salt instead of the Secret Key. It is a perfectly
      // working unlock — and it hands an attacker with the database an offline password oracle,
      // which is the single property §24 exists to provide.
      const brokenDerive = async (password: string, kdfSalt: Uint8Array) =>
        deriveAccountKeys(new Uint8Array(0), password, kdfSalt, TEST_PARAMS, ports);

      const broken = await brokenDerive(fixture.password, fixture.profile.kdf_salt);
      const wrapped = await wrapAccountPrivateKeys(broken.keyWrapKey, fixture.accountId, {
        encryption: fixture.keyset.encryption.privateKey,
        signing: fixture.keyset.signing.privateKey,
      });
      const blob = await seal(
        broken.configKey,
        accountConfigAad(fixture.accountId, 1),
        encodeRecord(ACCOUNT_SECURITY_CONFIG, fixture.config),
      );
      const brokenProfile = withProfile(fixture.profile, {
        wrapped_account_encryption_key: wrapped.encryption,
        wrapped_account_signing_key: wrapped.signing,
        config_blob: blob,
      });

      // Under the broken wrapping, *any* Secret Key opens the account — the oracle is live.
      const brokenUnlock = await deriveAccountKeys(new Uint8Array(0), fixture.password, fixture.profile.kdf_salt, TEST_PARAMS, ports);
      await expect(
        unseal(brokenUnlock.configKey, accountConfigAad(fixture.accountId, 1), blob),
      ).resolves.toBeInstanceOf(Uint8Array);

      // The real unlock refuses it, with the right Secret Key and with the wrong one alike.
      const bytes = encodeRecord(ACCOUNT_SECURITY_PROFILE, brokenProfile);
      expect(failureOf(await unlockSession(request({ profile: bytes }))).code).toBe("SECRETS_REJECTED");
      expect(failureOf(await unlockSession(request({ profile: bytes, secretKey: OTHER_SECRET_KEY }))).code).toBe(
        "SECRETS_REJECTED",
      );
    });

    it("an unlock that used the profile's own account_id would accept another account's profile", async () => {
      // `openAccount` builds every AAD from the caller's authenticated `accountId`. Had it used
      // `profile.account_id`, this stolen-profile case would succeed; it must not.
      const other = await createFixture({ ports, accountId: filled(16, 0x55), password: fixture.password });
      const stolen = await unlockSession({
        accountId: fixture.accountId,
        profile: other.profileBytes,
        secrets: { password: other.password, secretKey: other.secretKey },
        ports,
      });
      expect(failureOf(stolen).code).toBe("MALFORMED_PROFILE");
    }, 120_000);
  });

  describe("determinism and frozen vectors", () => {
    it("reproduces the §23.3 context bytes", () => {
      expect(toHex(ACCOUNT_KEYWRAP_INFO)).toBe(unlockVectors.contexts.accountKeywrapInfoHex);
      expect(toHex(ACCOUNT_CONFIG_INFO)).toBe(unlockVectors.contexts.accountConfigInfoHex);
      expect(toHex(accountPrivateKeyAad(filled(16, 0x11), "ACCOUNT_ENCRYPTION"))).toBe(
        unlockVectors.contexts.accountPrivateKeyAadHex,
      );
      expect(toHex(accountConfigAad(filled(16, 0x11), 1))).toBe(unlockVectors.contexts.accountConfigAadHex);
    });

    it.each(unlockVectors.cases.map((c) => [c.name, c] as const))(
      "reproduces the derived key material: %s",
      async (_name, vector) => {
        const salt = fromHex(vector.kdfSaltHex);
        const secretKey = fromHex(vector.secretKeyHex);
        const params = vector.argon2Params;

        const passwordKey = await derivePasswordKey(vector.password, salt, params);
        expect(toHex(passwordKey)).toBe(vector.passwordKeyHex);

        const base = await importHkdfBase(passwordKey);
        expect(toHex(await deriveBits(base, { salt: secretKey, info: ACCOUNT_KEYWRAP_INFO }, 256))).toBe(
          vector.accountKeyWrapKeyHex,
        );
        expect(toHex(await deriveBits(base, { salt: secretKey, info: ACCOUNT_CONFIG_INFO }, 256))).toBe(
          vector.accountConfigKeyHex,
        );
      },
      120_000,
    );

    it("the frozen bytes are the keys `deriveAccountKeys` actually returns", async () => {
      // `AccountKeyWrapKey` and `AccountConfigKey` are non-extractable, so the vector cannot be
      // compared byte for byte against them directly. Instead the vector bytes are imported as
      // independent handles and each pair is required to open what the other produced.
      const vector = unlockVectors.cases[0]!;
      const derived = await deriveAccountKeys(
        fromHex(vector.secretKeyHex),
        vector.password,
        fromHex(vector.kdfSaltHex),
        vector.argon2Params,
        ports,
      );

      const aad = accountConfigAad(fixture.accountId, 1);
      const fromVector = await importAeadKey(fromHex(vector.accountConfigKeyHex));
      const sealed = await seal(derived.configKey, aad, new Uint8Array([0xde, 0xad]));
      expect(toHex(await unseal(fromVector, aad, sealed))).toBe("dead");

      const wrapAad = accountPrivateKeyAad(fixture.accountId, "ACCOUNT_SIGNING");
      const importedWrapKey = (await crypto.subtle.importKey(
        "raw",
        fromHex(vector.accountKeyWrapKeyHex) as BufferSource,
        { name: "AES-GCM" },
        false,
        ["wrapKey", "unwrapKey"],
      )) as KeyWrapKey;
      const { signing } = await wrapAccountPrivateKeys(derived.keyWrapKey, fixture.accountId, {
        encryption: fixture.keyset.encryption.privateKey,
        signing: fixture.keyset.signing.privateKey,
      });
      await expect(
        crypto.subtle.unwrapKey(
          "pkcs8",
          signing.blob.subarray(12) as BufferSource,
          importedWrapKey,
          { name: "AES-GCM", iv: signing.blob.subarray(0, 12) as BufferSource, additionalData: wrapAad as BufferSource, tagLength: 128 },
          { name: "ECDSA", namedCurve: "P-256" },
          false,
          ["sign"],
        ),
      ).resolves.toBeDefined();
    }, 120_000);

    it("NFC and NFD spellings of one password derive the same key material (D8)", () => {
      const nfc = unlockVectors.cases.find((c) => c.name.includes("NFC"));
      const nfd = unlockVectors.cases.find((c) => c.name.includes("NFD"));
      expect(nfc?.password).not.toBe(nfd?.password); // different code points…
      expect(nfc?.passwordKeyHex).toBe(nfd?.passwordKeyHex); // …one key
      expect(nfc?.accountKeyWrapKeyHex).toBe(nfd?.accountKeyWrapKeyHex);
    });

    it("the same seed rebuilds the same salt and Secret Key", async () => {
      const a = await createFixture({ ports: seededPorts(7, ports) });
      const b = await createFixture({ ports: seededPorts(7, ports) });
      expect(toHex(a.keyset.kdfSalt)).toBe(toHex(b.keyset.kdfSalt));
      expect(a.secretKeyText).toBe(b.secretKeyText);
      // The RSA and ECDSA key pairs come from Web Crypto, which takes no seed, so the wrapped
      // blobs differ; the profile that is derived from the secrets does not.
      expect(toHex(await sha256(a.keyset.kdfSalt))).toBe(toHex(await sha256(b.keyset.kdfSalt)));
    }, 180_000);
  });
});
