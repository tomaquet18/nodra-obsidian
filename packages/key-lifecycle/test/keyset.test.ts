// Account Root Keyset creation (§25, §35.2 steps 3–5, 10, 14) and the records it feeds (§23.4).
import { beforeAll, describe, expect, it } from "vitest";
import { ARGON2_PARAMS_V1, KDF_SALT_BYTES, seal, sha256, verifyContext, wrapPrivateKey } from "@nodra/crypto";
import { ACCOUNT_SECURITY_CONFIG, ACCOUNT_SECURITY_PROFILE, decodeRecord, encodeRecord } from "@nodra/encoding/records";
import { ACCOUNT_SECRET_KEY_BYTES, decodeAccountSecretKey } from "@nodra/encoding/secret-key";
import { accountConfigAad, accountPrivateKeyAad } from "../src/contexts.js";
import {
  buildAccountSecurityProfile,
  createAccountRootKeyset,
  sealAccountSecurityConfig,
  wrapAccountPrivateKeys,
} from "../src/keyset.js";
import { KeyLifecycleError } from "../src/errors.js";
import { deriveAccountKeys } from "../src/secrets.js";
import { unlockForOperation, unlockForRewrap, unlockSession } from "../src/unlock.js";
import { TEST_PARAMS, createFixture, filled, makeConfig, memoPorts, toHex } from "./support.js";
import type { Fixture } from "./support.js";

const ports = memoPorts();

describe("§25 Account Root Keyset creation", () => {
  let fixture: Fixture;

  beforeAll(async () => {
    fixture = await createFixture({ ports });
  }, 120_000);

  it("generates a 20-byte Account Secret Key and its Setup Kit text (§24)", () => {
    expect(fixture.keyset.accountSecretKey).toHaveLength(ACCOUNT_SECRET_KEY_BYTES);
    expect(fixture.keyset.accountSecretKeyText).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){7}$/);
    expect(toHex(decodeAccountSecretKey(fixture.keyset.accountSecretKeyText))).toBe(
      toHex(fixture.keyset.accountSecretKey),
    );
  });

  it("generates a 16-byte kdf_salt and defaults to ADR-004 profile 1", () => {
    expect(fixture.keyset.kdfSalt).toHaveLength(KDF_SALT_BYTES);
    expect(fixture.keyset.argon2Params).toEqual({
      memory_kib: ARGON2_PARAMS_V1.memoryKib,
      iterations: ARGON2_PARAMS_V1.iterations,
      parallelism: ARGON2_PARAMS_V1.parallelism,
      version: ARGON2_PARAMS_V1.version,
    });
  });

  it("produces the two algorithms and key_roles of §25", () => {
    expect(fixture.keyset.encryption.publicKey.algorithm).toMatchObject({ name: "RSA-OAEP", modulusLength: 3072 });
    expect(fixture.keyset.signing.publicKey.algorithm).toMatchObject({ name: "ECDSA", namedCurve: "P-256" });
    expect(fixture.keyset.encryption.wrapped.key_role).toBe("ACCOUNT_ENCRYPTION");
    expect(fixture.keyset.signing.wrapped.key_role).toBe("ACCOUNT_SIGNING");
  });

  it("§25.2: the private keys are extractable only so they can be wrapped", () => {
    expect(fixture.keyset.encryption.privateKey.extractable).toBe(true);
    expect(fixture.keyset.signing.privateKey.extractable).toBe(true);
  });

  it("§25.2: SHA-256(SPKI) is taken over the exact stored bytes", async () => {
    expect(toHex(fixture.keyset.encryption.publicKeyHash)).toBe(toHex(await sha256(fixture.keyset.encryption.publicKeySpki)));
    expect(toHex(fixture.keyset.signing.publicKeyHash)).toBe(toHex(await sha256(fixture.keyset.signing.publicKeySpki)));
  });

  it("rejects an account_id or kdf_salt of the wrong length", async () => {
    await expect(
      createAccountRootKeyset({ accountId: filled(15, 1), password: "x", ports }),
    ).rejects.toBeInstanceOf(KeyLifecycleError);
    await expect(
      createAccountRootKeyset({ accountId: filled(16, 1), password: "x", kdfSalt: filled(8, 1), ports }),
    ).rejects.toBeInstanceOf(KeyLifecycleError);
  });

  it("refuses to create an account under parameters ADR-004 rejects", async () => {
    const result = await createAccountRootKeyset({
      accountId: filled(16, 1),
      password: "x",
      argon2Params: { ...TEST_PARAMS, memoryKib: 1024 },
      ports,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe("KDF_PARAMS_REJECTED");
  });

  it("accepts an Account Secret Key supplied as text (§35.6 supplies the new one)", async () => {
    const created = await createAccountRootKeyset({
      accountId: filled(16, 1),
      password: "x",
      secretKey: fixture.secretKeyText,
      ports,
    });
    expect(created.ok).toBe(true);
    if (created.ok) expect(toHex(created.value.accountSecretKey)).toBe(toHex(fixture.secretKey));
  });
});

describe("§23.4 / §26 records", () => {
  let fixture: Fixture;

  beforeAll(async () => {
    fixture = await createFixture({ ports });
  }, 120_000);

  it("the profile round-trips through canonical NCE", () => {
    expect(decodeRecord(ACCOUNT_SECURITY_PROFILE, fixture.profileBytes)).toEqual(fixture.profile);
    expect(toHex(encodeRecord(ACCOUNT_SECURITY_PROFILE, fixture.profile))).toBe(toHex(fixture.profileBytes));
  });

  it("the profile carries the plaintext copy of config_version (§23.4 key 6)", () => {
    expect(fixture.profile.config_version).toBe(fixture.config.config_version);
  });

  it("the config blob is the generic AES-GCM format: nonce(12) ‖ ciphertext‖tag", () => {
    const plaintext = encodeRecord(ACCOUNT_SECURITY_CONFIG, fixture.config);
    expect(fixture.profile.config_blob).toHaveLength(12 + plaintext.length + 16);
  });

  it("a config sealed for config_version n does not open as n + 1", async () => {
    const next = { ...fixture.config, config_version: fixture.config.config_version + 1 };
    const blob = await sealAccountSecurityConfig(fixture.keyset.derived.configKey, next);
    const profile = buildAccountSecurityProfile({
      accountId: fixture.accountId,
      kdfSalt: fixture.keyset.kdfSalt,
      argon2Params: fixture.keyset.argon2Params,
      wrappedEncryptionKey: fixture.keyset.encryption.wrapped,
      wrappedSigningKey: fixture.keyset.signing.wrapped,
      configVersion: fixture.config.config_version, // the server's copy still says n
      configBlob: blob,
    });
    const result = await unlockSession({
      accountId: fixture.accountId,
      profile: encodeRecord(ACCOUNT_SECURITY_PROFILE, profile),
      secrets: { password: fixture.password, secretKey: fixture.secretKey },
      ports,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe("SECRETS_REJECTED");
  });
});

describe("§35.6 re-wrap (the shape this slice owes the next one)", () => {
  let fixture: Fixture;

  beforeAll(async () => {
    fixture = await createFixture({ ports });
  }, 120_000);

  it("§44.3: the re-wrapped keyset opens with the new secrets and not with the old", async () => {
    const opened = await unlockForRewrap({
      accountId: fixture.accountId,
      profile: fixture.profileBytes,
      secrets: { password: fixture.password, secretKey: fixture.secretKey },
      ports,
    });
    if (!opened.ok) throw new Error(opened.failure.code);

    const newPassword = "a completely different Encryption Password";
    const newSecretKey = new Uint8Array(20).map((_, i) => (i * 13 + 3) & 0xff);
    const newSalt = filled(KDF_SALT_BYTES, 0x5a); // §24: regenerated on every password change
    const newKeys = await deriveAccountKeys(newSecretKey, newPassword, newSalt, TEST_PARAMS, ports);

    const wrapped = await wrapAccountPrivateKeys(newKeys.keyWrapKey, fixture.accountId, {
      encryption: opened.value.encryptionKey,
      signing: opened.value.signingKey,
    });
    const nextConfig = { ...fixture.config, config_version: fixture.config.config_version + 1 };
    const profile = buildAccountSecurityProfile({
      accountId: fixture.accountId,
      kdfSalt: newSalt,
      argon2Params: fixture.keyset.argon2Params,
      wrappedEncryptionKey: wrapped.encryption,
      wrappedSigningKey: wrapped.signing,
      configVersion: nextConfig.config_version,
      configBlob: await sealAccountSecurityConfig(newKeys.configKey, nextConfig),
    });
    const bytes = encodeRecord(ACCOUNT_SECURITY_PROFILE, profile);

    const withNew = await unlockForOperation({
      accountId: fixture.accountId,
      profile: bytes,
      secrets: { password: newPassword, secretKey: newSecretKey },
      ports,
    });
    expect(withNew.ok).toBe(true);

    const withOld = await unlockSession({
      accountId: fixture.accountId,
      profile: bytes,
      secrets: { password: fixture.password, secretKey: fixture.secretKey },
      ports,
    });
    expect(withOld.ok).toBe(false);
    if (!withOld.ok) expect(withOld.failure.code).toBe("SECRETS_REJECTED");

    // Same keys, new wrapping: the signing handle still matches the original public key, so the
    // Root Descriptor and the Registry stay valid across a secret change.
    if (!withNew.ok) return;
    const ctx = accountConfigAad(fixture.accountId, 99);
    const signature = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, withNew.value.signingKey, ctx as BufferSource),
    );
    expect(await verifyContext(fixture.keyset.signing.publicKey, ctx, signature)).toBe(true);
  }, 180_000);

  it("broken-variant proof: a wrap that ignored key_role would pass a weaker test, not this one", async () => {
    // The variant wraps both privates under the ACCOUNT_ENCRYPTION AAD. A test that only checked
    // "the account unlocks" would still be green, because the encryption key opens fine.
    const derived = fixture.keyset.derived;
    const brokenSigningBlob = await wrapPrivateKey(
      derived.keyWrapKey,
      accountPrivateKeyAad(fixture.accountId, "ACCOUNT_ENCRYPTION"),
      fixture.keyset.signing.privateKey,
    );
    const profile = buildAccountSecurityProfile({
      accountId: fixture.accountId,
      kdfSalt: fixture.keyset.kdfSalt,
      argon2Params: fixture.keyset.argon2Params,
      wrappedEncryptionKey: fixture.keyset.encryption.wrapped,
      wrappedSigningKey: { key_role: "ACCOUNT_SIGNING", blob: brokenSigningBlob },
      configVersion: fixture.config.config_version,
      configBlob: fixture.profile.config_blob,
    });
    const bytes = encodeRecord(ACCOUNT_SECURITY_PROFILE, profile);
    const secrets = { password: fixture.password, secretKey: fixture.secretKey };

    // The weaker assertion the variant would survive:
    expect((await unlockSession({ accountId: fixture.accountId, profile: bytes, secrets, ports })).ok).toBe(true);
    // The assertion that catches it:
    const operation = await unlockForOperation({ accountId: fixture.accountId, profile: bytes, secrets, ports });
    expect(operation.ok).toBe(false);
    if (!operation.ok) expect(operation.failure.code).toBe("SECRETS_REJECTED");
  }, 120_000);
});

describe("a second account is independent", () => {
  it("one account's profile never opens another's, even with the same password", async () => {
    const a = await createFixture({ ports, accountId: filled(16, 0x01), password: "shared password" });
    const b = await createFixture({
      ports,
      accountId: filled(16, 0x02),
      password: "shared password",
      secretKey: a.secretKey,
      kdfSalt: a.keyset.kdfSalt,
    });
    // Same password, same salt, same Secret Key: the derived keys are identical by construction.
    // Only the AAD of §23.3 separates the two accounts — and it does.
    const sealedForB = await seal(
      a.keyset.derived.configKey,
      accountConfigAad(b.accountId, 1),
      encodeRecord(ACCOUNT_SECURITY_CONFIG, makeConfig(b.accountId, 1, b.keyset)),
    );
    expect(sealedForB.length).toBeGreaterThan(0);

    const crossed = await unlockSession({
      accountId: b.accountId,
      profile: encodeRecord(
        ACCOUNT_SECURITY_PROFILE,
        buildAccountSecurityProfile({
          accountId: b.accountId,
          kdfSalt: b.keyset.kdfSalt,
          argon2Params: b.keyset.argon2Params,
          // A's wrapped keys, under B's account_id: the AAD no longer matches.
          wrappedEncryptionKey: a.keyset.encryption.wrapped,
          wrappedSigningKey: a.keyset.signing.wrapped,
          configVersion: 1,
          configBlob: sealedForB,
        }),
      ),
      secrets: { password: "shared password", secretKey: a.secretKey },
      ports,
    });
    expect(crossed.ok).toBe(false);
    if (!crossed.ok) expect(crossed.failure.code).toBe("SECRETS_REJECTED");
  }, 240_000);
});
