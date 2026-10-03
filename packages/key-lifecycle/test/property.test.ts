// Property-based coverage of §24 and §25.
//
// Building an account costs an RSA-3072 keygen and (with the real KDF) over a second of Argon2id,
// so these runs reuse one key pair and a cheap KDF stand-in: the properties below are about the
// *composition* around the KDF — the Secret Key as HKDF salt, the AAD binding of §23.3, and the
// AEAD authentication of every wrapped byte — none of which the KDF choice affects. Argon2id
// itself has known-answer vectors in `@nodra/crypto`, and the one property that genuinely depends
// on it (NFC/NFD password spelling) runs the real thing, with a small `numRuns`.
import { beforeAll, describe, expect, it } from "vitest";
import fc from "fast-check";
import { KDF_SALT_BYTES, generateEnvelopeKeyPair, generateSigningKeyPair, unseal } from "@nodra/crypto";
import type { ExtractableEnvelopePrivateKey, ExtractableSigningKey } from "@nodra/crypto";
import { ACCOUNT_SECURITY_PROFILE, encodeRecord } from "@nodra/encoding/records";
import type { AccountSecurityProfile } from "@nodra/encoding/records";
import { ACCOUNT_SECRET_KEY_BYTES, formatAccountSecretKey } from "@nodra/encoding/secret-key";
import {
  buildAccountSecurityProfile,
  sealAccountSecurityConfig,
  wrapAccountPrivateKeys,
} from "../src/keyset.js";
import { deriveAccountKeys } from "../src/secrets.js";
import { unlockForOperation, unlockSession } from "../src/unlock.js";
import { accountConfigAad } from "../src/contexts.js";
import type { KeyLifecyclePorts } from "../src/ports.js";
import type { AccountSecurityConfig } from "@nodra/encoding/records";
import { TEST_PARAMS, filled, flipByte, memoPorts, stubKdfPorts, toHex } from "./support.js";
import type { PrivateProfile } from "./support.js";

const stub = stubKdfPorts();
const real = memoPorts();

const ACCOUNT_ID = filled(16, 0x42);
const CONFIG_VERSION = 3;

/** The §26 config, with filler hashes: §27–§29 are not in this slice and nothing here reads them. */
const CONFIG: AccountSecurityConfig = {
  account_id: ACCOUNT_ID,
  config_version: CONFIG_VERSION,
  root_generation: 1,
  root_hash: filled(32, 0xa1),
  genesis_root_hash: filled(32, 0xa1),
  account_encryption_public_key_hash: filled(32, 0xa2),
  account_signing_public_key_hash: filled(32, 0xa3),
  recovery_encryption_public_key_hash: filled(32, 0xb1),
  recovery_authority_public_key_hash: filled(32, 0xb2),
  registry_version: 1,
  registry_hash: filled(32, 0xc1),
  crypto_version: 1,
};

let privateKeys: {
  readonly encryption: ExtractableEnvelopePrivateKey;
  readonly signing: ExtractableSigningKey;
};

/**
 * Everything §35.2 puts on the server for one pair of secrets, without regenerating the key pair.
 * That is faithful: the wrapped blobs and the config blob are the only things the secrets touch.
 */
async function profileFor(
  ports: KeyLifecyclePorts,
  password: string,
  secretKey: Uint8Array,
  kdfSalt: Uint8Array,
): Promise<PrivateProfile> {
  const derived = await deriveAccountKeys(secretKey, password, kdfSalt, TEST_PARAMS, ports);
  const wrapped = await wrapAccountPrivateKeys(derived.keyWrapKey, ACCOUNT_ID, privateKeys);
  const profile = buildAccountSecurityProfile({
    accountId: ACCOUNT_ID,
    kdfSalt,
    argon2Params: {
      memory_kib: TEST_PARAMS.memoryKib,
      iterations: TEST_PARAMS.iterations,
      parallelism: TEST_PARAMS.parallelism,
      version: TEST_PARAMS.version,
    },
    wrappedEncryptionKey: wrapped.encryption,
    wrappedSigningKey: wrapped.signing,
    configVersion: CONFIG_VERSION,
    configBlob: await sealAccountSecurityConfig(derived.configKey, CONFIG),
  });
  return { ...profile, kdf_salt: kdfSalt, argon2_params: profile.argon2_params! };
}

function unlock(ports: KeyLifecyclePorts, profile: AccountSecurityProfile, password: string, secretKey: Uint8Array | string) {
  return unlockSession({
    accountId: ACCOUNT_ID,
    profile: encodeRecord(ACCOUNT_SECURITY_PROFILE, profile),
    secrets: { password, secretKey },
    ports,
  });
}

/** Passwords a real user can produce: ASCII, accented, CJK, emoji, whitespace, empty. */
const password = fc.oneof(
  fc.string({ minLength: 0, maxLength: 40 }),
  fc.string({ unit: "grapheme", minLength: 1, maxLength: 24 }),
  fc.constantFrom("", " ", "  trailing  ", "contraseña", "日本語のパスワード", "🔐🔐🔐", "é", "é"),
);

const secretKeyBytes = fc.uint8Array({ minLength: ACCOUNT_SECRET_KEY_BYTES, maxLength: ACCOUNT_SECRET_KEY_BYTES });
const saltBytes = fc.uint8Array({ minLength: KDF_SALT_BYTES, maxLength: KDF_SALT_BYTES });

describe("§24 / §25 properties", () => {
  beforeAll(async () => {
    const [encryption, signing] = await Promise.all([generateEnvelopeKeyPair(), generateSigningKeyPair()]);
    privateKeys = { encryption: encryption.privateKey, signing: signing.privateKey };
  }, 120_000);

  it("any password and any Secret Key round-trip", async () => {
    await fc.assert(
      fc.asyncProperty(password, secretKeyBytes, saltBytes, async (pw, sk, salt) => {
        const profile = await profileFor(stub, pw, sk, salt);
        const result = await unlock(stub, profile, pw, sk);
        expect(result.ok).toBe(true);
        if (result.ok) expect(result.value.config).toEqual(CONFIG);
      }),
      { numRuns: 60 },
    );
  });

  it("a different Secret Key never opens the account, whatever the password", async () => {
    await fc.assert(
      fc.asyncProperty(password, secretKeyBytes, secretKeyBytes, saltBytes, async (pw, sk, other, salt) => {
        fc.pre(toHex(sk) !== toHex(other));
        const profile = await profileFor(stub, pw, sk, salt);
        const result = await unlock(stub, profile, pw, other);
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.failure.code).toBe("SECRETS_REJECTED");
      }),
      { numRuns: 60 },
    );
  });

  it("a different password never opens the account, whatever the Secret Key", async () => {
    await fc.assert(
      fc.asyncProperty(password, password, secretKeyBytes, saltBytes, async (pw, other, sk, salt) => {
        fc.pre(pw.normalize("NFC") !== other.normalize("NFC"));
        const profile = await profileFor(stub, pw, sk, salt);
        const result = await unlock(stub, profile, other, sk);
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.failure.code).toBe("SECRETS_REJECTED");
      }),
      { numRuns: 60 },
    );
  });

  it("the typed Setup Kit text round-trips through the §24 normalization", async () => {
    // §44.3: "Secret Key tecleada en minúsculas, con guiones y confusiones O/0, I/L/1 → misma
    // derivación". The perturbations are exactly the ones §24 says to undo.
    const mangle = fc.func(fc.boolean());
    await fc.assert(
      fc.asyncProperty(password, secretKeyBytes, saltBytes, mangle, async (pw, sk, salt, pick) => {
        const canonical = formatAccountSecretKey(sk);
        let typed = "";
        for (const [i, c] of [...canonical].entries()) {
          if (c === "-") {
            if (pick(i)) typed += " ";
            else if (pick(i + 1000)) typed += "-";
            continue; // sometimes dropped entirely
          }
          if (c === "0" && pick(i + 1)) typed += "O";
          else if (c === "1" && pick(i + 2)) typed += pick(i + 3) ? "I" : "L";
          else typed += pick(i + 4) ? c.toLowerCase() : c;
        }
        const profile = await profileFor(stub, pw, sk, salt);
        const result = await unlock(stub, profile, pw, typed);
        expect(result.ok).toBe(true);
      }),
      { numRuns: 60 },
    );
  });

  // Routed through `unlockForOperation`, which is the only unlock that reads *all* of the wrapped
  // material: §35.3's Session unlock never touches the wrapped signing key (see the unit test
  // "the Session unlock does not authenticate the wrapped signing key" and NOTES Q182).
  it("any single changed byte of the wrapped material fails the unlock", async () => {
    await fc.assert(
      fc.asyncProperty(
        password,
        secretKeyBytes,
        saltBytes,
        fc.constantFrom(
          "wrapped_account_encryption_key" as const,
          "wrapped_account_signing_key" as const,
          "config_blob" as const,
          "kdf_salt" as const,
        ),
        fc.nat(),
        async (pw, sk, salt, field, index) => {
          const profile = await profileFor(stub, pw, sk, salt);
          const tampered: AccountSecurityProfile =
            field === "config_blob"
              ? { ...profile, config_blob: flipByte(profile.config_blob, index) }
              : field === "kdf_salt"
                ? { ...profile, kdf_salt: flipByte(profile.kdf_salt, index) }
                : {
                    ...profile,
                    [field]: { ...profile[field], blob: flipByte(profile[field].blob, index) },
                  };
          const result = await unlockForOperation({
            accountId: ACCOUNT_ID,
            profile: encodeRecord(ACCOUNT_SECURITY_PROFILE, tampered),
            secrets: { password: pw, secretKey: sk },
            ports: stub,
          });
          expect(result.ok).toBe(false);
          if (!result.ok) expect(result.failure.code).toBe("SECRETS_REJECTED");
        },
      ),
      { numRuns: 80 },
    );
  });

  it("broken-variant proof: an unlock that ignored the Secret Key would fail the property above", async () => {
    // The variant: HKDF with an empty salt, so the Account Secret Key is not an input at all.
    // It round-trips perfectly, which is why "it unlocks" is not a sufficient test.
    const brokenDerive = (pw: string, salt: Uint8Array) =>
      deriveAccountKeys(new Uint8Array(0), pw, salt, TEST_PARAMS, stub);
    async function brokenOpens(profile: PrivateProfile, pw: string, _secretKey: Uint8Array): Promise<boolean> {
      const derived = await brokenDerive(pw, profile.kdf_salt);
      try {
        await unseal(derived.configKey, accountConfigAad(ACCOUNT_ID, CONFIG_VERSION), profile.config_blob);
        return true;
      } catch {
        return false;
      }
    }

    const pw = "a password";
    const salt = filled(KDF_SALT_BYTES, 0x0c);
    const sk = filled(ACCOUNT_SECRET_KEY_BYTES, 0x01);
    const other = filled(ACCOUNT_SECRET_KEY_BYTES, 0x02);

    // An account created by the variant: "a different Secret Key never opens the account" is FALSE.
    const brokenProfile = await profileFor(stub, pw, new Uint8Array(0), salt);
    expect(await brokenOpens(brokenProfile, pw, sk)).toBe(true);
    expect(await brokenOpens(brokenProfile, pw, other)).toBe(true);

    // The same oracle on the real implementation: only the right Secret Key opens it.
    const good = await profileFor(stub, pw, sk, salt);
    expect((await unlock(stub, good, pw, sk)).ok).toBe(true);
    expect((await unlock(stub, good, pw, other)).ok).toBe(false);
  });

  it("the real Argon2id treats NFC and NFD spellings of one password as the same (D8)", async () => {
    // Deliberately few runs: each distinct (password, salt) pair costs a full ADR-004 Argon2id.
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom("é", "pássword", "ñandú", "ｶﾞ"),
        async (raw) => {
          const nfc = raw.normalize("NFC");
          const nfd = raw.normalize("NFD");
          fc.pre(nfc !== nfd);
          const sk = filled(ACCOUNT_SECRET_KEY_BYTES, 0x0a);
          const salt = filled(KDF_SALT_BYTES, 0x0b);
          const profile = await profileFor(real, nfc, sk, salt);
          expect((await unlock(real, profile, nfd, sk)).ok).toBe(true);
        },
      ),
      { numRuns: 3 },
    );
  }, 300_000);
});
