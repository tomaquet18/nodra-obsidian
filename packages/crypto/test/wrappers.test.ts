// Behaviour of the wrappers themselves: round trips, the negatives the spec demands, the §25.1
// handle table, and broken-variant proofs that show the oracles above would catch a bad wrapper.
import { beforeAll, describe, expect, it } from "vitest";
import {
  AEAD_BLOB_OVERHEAD_BYTES,
  AEAD_NONCE_BYTES,
  importAeadKey,
  seal,
  splitBlob,
  unsafeSealWithNonce,
  unseal,
} from "../src/aead.js";
import type { AeadKey } from "../src/aead.js";
import { randomBytes, timingSafeEqual, zeroize } from "../src/bytes.js";
import { domainContext } from "../src/context.js";
import type { DomainContext } from "../src/context.js";
import {
  ARGON2_LIMITS,
  ARGON2_PARAMS_V1,
  KDF_SALT_BYTES,
  PASSWORD_KEY_BYTES,
  assertArgon2ParamsAccepted,
  derivePasswordKey,
} from "../src/argon2.js";
import {
  EMPTY_SALT,
  deriveAeadKey,
  deriveBits,
  deriveKeyWrapKey,
  deriveMacKey,
  importHkdfBase,
} from "../src/hkdf.js";
import { hmacSha256, sha256 } from "../src/hash.js";
import {
  EPOCH_SECRET_BYTES,
  exportEnvelopePublicKey,
  generateEnvelopeKeyPair,
  generateRecipientKeyPair,
  importEnvelopePublicKey,
  openEpochSecret,
  sealEpochSecret,
  unwrapEpochKey,
} from "../src/envelope.js";
import type { EnvelopeKeyPair } from "../src/envelope.js";
import {
  unwrapOperationKey,
  unwrapRewrapEncryptionKey,
  unwrapRewrapSigningKey,
  unwrapSessionKey,
  unwrapSigningKey,
  wrapPrivateKey,
} from "../src/keywrap.js";
import type { KeyWrapKey } from "../src/keywrap.js";
import {
  SIGNATURE_BYTES,
  assertSignatureLength,
  exportVerifyingKey,
  generateSigningKeyPair,
  importVerifyingKey,
  signContext,
  verifyContext,
} from "../src/signature.js";
import type { SigningKeyPair } from "../src/signature.js";
import { assertSecureCryptoCapabilities } from "../src/runtime.js";
import { asContext, flipByte, toHex } from "./support.js";

const VAULT = new Uint8Array(16).fill(0xa1);
const EPOCH = new Uint8Array(16).fill(0xb2);
const BLOB = new Uint8Array(16).fill(0xc3);
const ACCOUNT = new Uint8Array(16).fill(0xd4);
const RECIPIENT = new Uint8Array(16).fill(0xe5);

const contentAad = domainContext("nodra/aad/content", VAULT, EPOCH, BLOB);
const otherBlobAad = domainContext("nodra/aad/content", VAULT, EPOCH, new Uint8Array(16).fill(0xc4));
const envelopeLabel = domainContext("nodra/envelope-label", VAULT, EPOCH, RECIPIENT, "BROWSER");
const otherEnvelopeLabel = domainContext("nodra/envelope-label", VAULT, EPOCH, RECIPIENT, "PLUGIN");
const encryptionAad = domainContext("nodra/aad/account-private-key", ACCOUNT, "ACCOUNT_ENCRYPTION");
const signingAad = domainContext("nodra/aad/account-private-key", ACCOUNT, "ACCOUNT_SIGNING");

async function freshAeadKey(): Promise<AeadKey> {
  return importAeadKey(randomBytes(32));
}

describe("runtime capabilities (§23.0 rule 7)", () => {
  it("accepts this runtime", async () => {
    await expect(assertSecureCryptoCapabilities()).resolves.toBeUndefined();
  });
});

describe("AES-GCM wrapper", () => {
  it("round trips and uses the documented blob layout", async () => {
    const key = await freshAeadKey();
    const plaintext = randomBytes(100);
    const blob = await seal(key, contentAad, plaintext);
    expect(blob.length).toBe(plaintext.length + AEAD_BLOB_OVERHEAD_BYTES);
    expect(splitBlob(blob).nonce.length).toBe(AEAD_NONCE_BYTES);
    expect(toHex(await unseal(key, contentAad, blob))).toBe(toHex(plaintext));
  });

  it("refuses a blob sealed under a different AAD context (§31.3, content swap)", async () => {
    const key = await freshAeadKey();
    const blob = await seal(key, contentAad, randomBytes(32));
    await expect(unseal(key, otherBlobAad, blob)).rejects.toThrow(/DECRYPT_FAILED/);
  });

  it("refuses a blob sealed under a different key", async () => {
    const blob = await seal(await freshAeadKey(), contentAad, randomBytes(32));
    await expect(unseal(await freshAeadKey(), contentAad, blob)).rejects.toThrow(/DECRYPT_FAILED/);
  });

  it("refuses tampered ciphertext, a tampered nonce and a tampered tag", async () => {
    const key = await freshAeadKey();
    const blob = await seal(key, contentAad, randomBytes(48));
    for (const index of [0, AEAD_NONCE_BYTES + 3, blob.length - 1]) {
      await expect(unseal(key, contentAad, flipByte(blob, index))).rejects.toThrow(/DECRYPT_FAILED/);
    }
  });

  it("refuses truncated blobs", async () => {
    const key = await freshAeadKey();
    const blob = await seal(key, contentAad, randomBytes(48));
    await expect(unseal(key, contentAad, blob.subarray(0, AEAD_BLOB_OVERHEAD_BYTES - 1))).rejects.toThrow(
      /BAD_LENGTH/,
    );
    await expect(unseal(key, contentAad, blob.subarray(0, blob.length - 1))).rejects.toThrow(/DECRYPT_FAILED/);
  });

  it("never repeats a nonce across seals of the same plaintext under the same key", async () => {
    const key = await freshAeadKey();
    const plaintext = randomBytes(16);
    const nonces = new Set<string>();
    for (let i = 0; i < 64; i++) {
      nonces.add(toHex(splitBlob(await seal(key, contentAad, plaintext)).nonce));
    }
    expect(nonces.size).toBe(64);
  });
});

describe("broken-variant proofs for the AEAD oracles", () => {
  // Two oracles, each run against the real wrapper and against a deliberately broken one.
  // A test that only ever ran against the real implementation would prove nothing.
  interface AeadImpl {
    seal(key: AeadKey, aad: DomainContext, plaintext: Uint8Array): Promise<Uint8Array>;
    unseal(key: AeadKey, aad: DomainContext, blob: Uint8Array): Promise<Uint8Array>;
  }

  const real: AeadImpl = { seal, unseal };

  const emptyAad = asContext(new Uint8Array(0));
  /** A wrapper that drops the AAD: ciphertexts stay readable under any context. */
  const ignoresAad: AeadImpl = {
    seal: (key, _aad, plaintext) => unsafeSealWithNonce(key, randomBytes(AEAD_NONCE_BYTES), emptyAad, plaintext),
    unseal: (key, _aad, blob) => unseal(key, emptyAad, blob),
  };

  const fixedNonce = new Uint8Array(AEAD_NONCE_BYTES).fill(7);
  /** A wrapper with a hard-coded nonce: catastrophic for AES-GCM key reuse. */
  const reusesNonce: AeadImpl = {
    seal: (key, aad, plaintext) => unsafeSealWithNonce(key, fixedNonce, aad, plaintext),
    unseal,
  };

  /** True when the implementation binds the AAD: a blob does not open under another context. */
  async function bindsAad(impl: AeadImpl): Promise<boolean> {
    const key = await freshAeadKey();
    const blob = await impl.seal(key, contentAad, randomBytes(32));
    try {
      await impl.unseal(key, otherBlobAad, blob);
      return false;
    } catch {
      return true;
    }
  }

  /** True when repeated seals under one key produce distinct nonces. */
  async function usesFreshNonces(impl: AeadImpl): Promise<boolean> {
    const key = await freshAeadKey();
    const plaintext = randomBytes(16);
    const a = splitBlob(await impl.seal(key, contentAad, plaintext)).nonce;
    const b = splitBlob(await impl.seal(key, contentAad, plaintext)).nonce;
    return toHex(a) !== toHex(b);
  }

  it("the AAD oracle passes for the real wrapper and fails for one that ignores the AAD", async () => {
    expect(await bindsAad(real)).toBe(true);
    expect(await bindsAad(ignoresAad)).toBe(false);
  });

  it("the nonce oracle passes for the real wrapper and fails for one that reuses a nonce", async () => {
    expect(await usesFreshNonces(real)).toBe(true);
    expect(await usesFreshNonces(reusesNonce)).toBe(false);
  });
});

describe("HKDF wrapper", () => {
  it("separates domains: the same base with a different info yields a different key", async () => {
    const base = await importHkdfBase(randomBytes(32));
    const contentKey = await deriveAeadKey(base, {
      salt: EMPTY_SALT,
      info: domainContext("nodra/hkdf/content", BLOB),
    });
    const manifestKey = await deriveAeadKey(base, {
      salt: EMPTY_SALT,
      info: domainContext("nodra/hkdf/manifest", BLOB),
    });
    const blob = await seal(contentKey, contentAad, randomBytes(32));
    await expect(unseal(manifestKey, contentAad, blob)).rejects.toThrow(/DECRYPT_FAILED/);
  });

  it("separates by field: the same domain with a different blob_id yields a different key", async () => {
    const base = await importHkdfBase(randomBytes(32));
    const a = await deriveAeadKey(base, { salt: EMPTY_SALT, info: domainContext("nodra/hkdf/content", BLOB) });
    const b = await deriveAeadKey(base, {
      salt: EMPTY_SALT,
      info: domainContext("nodra/hkdf/content", new Uint8Array(16).fill(0xc4)),
    });
    const blob = await seal(a, contentAad, randomBytes(32));
    await expect(unseal(b, contentAad, blob)).rejects.toThrow(/DECRYPT_FAILED/);
  });

  it("the salt is part of the derivation, which is what two-secret unlock rests on (§24)", async () => {
    const base = await importHkdfBase(randomBytes(32));
    const info = domainContext("nodra/hkdf/account-config");
    const withSecret = await deriveBits(base, { salt: randomBytes(20), info }, 256);
    const withOther = await deriveBits(base, { salt: randomBytes(20), info }, 256);
    const withEmpty = await deriveBits(base, { salt: EMPTY_SALT, info }, 256);
    expect(toHex(withSecret)).not.toBe(toHex(withOther));
    expect(toHex(withSecret)).not.toBe(toHex(withEmpty));
  });

  it("derives a dedup MAC key that is deterministic per epoch (§31.4)", async () => {
    const secret = randomBytes(32);
    const info = domainContext("nodra/hkdf/dedup");
    const first = await deriveMacKey(await importHkdfBase(secret), { salt: EMPTY_SALT, info });
    const second = await deriveMacKey(await importHkdfBase(secret), { salt: EMPTY_SALT, info });
    const plaintext = randomBytes(64);
    expect(toHex(await hmacSha256(first, plaintext))).toBe(toHex(await hmacSha256(second, plaintext)));

    const otherEpoch = await deriveMacKey(await importHkdfBase(randomBytes(32)), { salt: EMPTY_SALT, info });
    expect(toHex(await hmacSha256(otherEpoch, plaintext))).not.toBe(toHex(await hmacSha256(first, plaintext)));
  });
});

describe("RSA-OAEP envelopes", () => {
  let pair: EnvelopeKeyPair;
  beforeAll(async () => {
    pair = await generateEnvelopeKeyPair();
  });

  it("round trips a 32-byte epoch secret through an SPKI-imported public key", async () => {
    const spki = await exportEnvelopePublicKey(pair.publicKey);
    const imported = await importEnvelopePublicKey(spki);
    const secret = randomBytes(EPOCH_SECRET_BYTES);
    const ciphertext = await sealEpochSecret(imported, envelopeLabel, secret);
    expect(toHex(await openEpochSecret(pair.privateKey, envelopeLabel, ciphertext))).toBe(toHex(secret));
  });

  it("refuses to seal anything that is not a 32-byte epoch secret", async () => {
    await expect(sealEpochSecret(pair.publicKey, envelopeLabel, randomBytes(31))).rejects.toThrow(/BAD_LENGTH/);
    await expect(sealEpochSecret(pair.publicKey, envelopeLabel, randomBytes(33))).rejects.toThrow(/BAD_LENGTH/);
  });

  it("refuses an envelope whose label belongs to another recipient (§39.1)", async () => {
    const ciphertext = await sealEpochSecret(pair.publicKey, envelopeLabel, randomBytes(EPOCH_SECRET_BYTES));
    await expect(openEpochSecret(pair.privateKey, otherEnvelopeLabel, ciphertext)).rejects.toThrow(
      /DECRYPT_FAILED/,
    );
  });

  it("refuses a tampered envelope", async () => {
    const ciphertext = await sealEpochSecret(pair.publicKey, envelopeLabel, randomBytes(EPOCH_SECRET_BYTES));
    await expect(openEpochSecret(pair.privateKey, envelopeLabel, flipByte(ciphertext, 5))).rejects.toThrow(
      /DECRYPT_FAILED/,
    );
    await expect(
      openEpochSecret(pair.privateKey, envelopeLabel, ciphertext.subarray(0, ciphertext.length - 1)),
    ).rejects.toThrow(/DECRYPT_FAILED/);
  });

  it("generates a §30.1 recipient pair whose private half can only unwrap", async () => {
    const recipient = await generateRecipientKeyPair();
    // §30.1: "se generan con generateKey(…, extractable = false, …)"; the public SPKI still exports.
    expect(recipient.privateKey.extractable).toBe(false);
    expect([...recipient.privateKey.usages]).toEqual(["unwrapKey"]);
    expect(recipient.publicKey.extractable).toBe(true);
    expect([...recipient.publicKey.usages]).toEqual(["encrypt"]);

    const secret = randomBytes(EPOCH_SECRET_BYTES);
    const spki = await exportEnvelopePublicKey(recipient.publicKey);
    const ciphertext = await sealEpochSecret(await importEnvelopePublicKey(spki), envelopeLabel, secret);
    const epochKey = await unwrapEpochKey(recipient.privateKey, envelopeLabel, ciphertext);
    expect(epochKey.extractable).toBe(false);

    // §30.2 is honest that this is not a defence against same-origin code, but the handle itself
    // cannot hand back the bytes: `decrypt` is not among its usages.
    await expect(openEpochSecret(recipient.privateKey as never, envelopeLabel, ciphertext)).rejects.toThrow();
    await expect(crypto.subtle.exportKey("pkcs8", recipient.privateKey)).rejects.toThrow();
  });

  it("the normal read path yields an EpochKey without the secret ever becoming bytes (§33.1)", async () => {
    const secret = randomBytes(EPOCH_SECRET_BYTES);
    const ciphertext = await sealEpochSecret(pair.publicKey, envelopeLabel, secret);
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const session = (await crypto.subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["unwrapKey"],
    )) as Parameters<typeof unwrapEpochKey>[0];

    const epochKey = await unwrapEpochKey(session, envelopeLabel, ciphertext);
    expect(epochKey.extractable).toBe(false);
    expect([...epochKey.usages].sort()).toEqual(["deriveBits", "deriveKey"]);

    // It must be the same key material the bytes would have produced.
    const info = domainContext("nodra/hkdf/content", BLOB);
    const fromHandle = await deriveAeadKey(epochKey, { salt: EMPTY_SALT, info });
    const fromBytes = await deriveAeadKey(await importHkdfBase(secret), { salt: EMPTY_SALT, info });
    const blob = await seal(fromBytes, contentAad, new Uint8Array([1, 2, 3]));
    expect(toHex(await unseal(fromHandle, contentAad, blob))).toBe("010203");

    // §44.3: the Session handle can unwrap, never decrypt.
    await expect(openEpochSecret(session as never, envelopeLabel, ciphertext)).rejects.toThrow();
    await expect(unwrapEpochKey(session, otherEnvelopeLabel, ciphertext)).rejects.toThrow(/DECRYPT_FAILED/);
  });
});

describe("ECDSA signatures", () => {
  let pair: SigningKeyPair;
  beforeAll(async () => {
    pair = await generateSigningKeyPair();
  });

  it("produces 64-byte P1363 signatures that verify over the context bytes", async () => {
    const ctx = domainContext("nodra/delete-vault", "DELETE_VAULT", ACCOUNT, VAULT, 7, new Uint8Array(16).fill(1));
    const signature = await signContext(pair.privateKey, ctx);
    expect(signature.length).toBe(SIGNATURE_BYTES);
    expect(() => {
      assertSignatureLength(signature);
    }).not.toThrow();

    const verifying = await importVerifyingKey(await exportVerifyingKey(pair.publicKey));
    expect(await verifyContext(verifying, ctx, signature)).toBe(true);
  });

  it("rejects a signature over a different context, a tampered signature and a wrong length", async () => {
    const ctx = domainContext("nodra/delete-account", "DELETE_ACCOUNT", ACCOUNT, 7, new Uint8Array(16).fill(1));
    const other = domainContext("nodra/delete-account", "DELETE_ACCOUNT", ACCOUNT, 8, new Uint8Array(16).fill(1));
    const signature = await signContext(pair.privateKey, ctx);

    expect(await verifyContext(pair.publicKey, other, signature)).toBe(false);
    expect(await verifyContext(pair.publicKey, asContext(flipByte(ctx, 4)), signature)).toBe(false);
    expect(await verifyContext(pair.publicKey, ctx, flipByte(signature, 10))).toBe(false);
    expect(await verifyContext(pair.publicKey, ctx, signature.subarray(0, 63))).toBe(false);
    expect(() => {
      assertSignatureLength(signature.subarray(0, 63));
    }).toThrow(/BAD_LENGTH/);
  });

  it("the same structure in another domain produces a different signed message (§44.2)", async () => {
    const fields = [ACCOUNT, 1] as const;
    const a = domainContext("nodra/hkdf/content", ...fields);
    const b = domainContext("nodra/hkdf/manifest", ...fields);
    const signature = await signContext(pair.privateKey, a);
    expect(await verifyContext(pair.publicKey, b, signature)).toBe(false);
  });
});

describe("WrappedPrivateKey and the §25.1 handle table", () => {
  let keyWrapKey: KeyWrapKey;
  let otherKeyWrapKey: KeyWrapKey;
  let encryptionBlob: Uint8Array;
  let signingBlob: Uint8Array;

  beforeAll(async () => {
    const base = await importHkdfBase(randomBytes(32));
    const info = domainContext("nodra/hkdf/account-keywrap");
    keyWrapKey = await deriveKeyWrapKey(base, { salt: randomBytes(20), info });
    otherKeyWrapKey = await deriveKeyWrapKey(base, { salt: randomBytes(20), info });
    encryptionBlob = await wrapPrivateKey(keyWrapKey, encryptionAad, (await generateEnvelopeKeyPair()).privateKey);
    signingBlob = await wrapPrivateKey(keyWrapKey, signingAad, (await generateSigningKeyPair()).privateKey);
  });

  it("the key wrap key can only wrap and unwrap", () => {
    expect([...keyWrapKey.usages].sort()).toEqual(["unwrapKey", "wrapKey"]);
    expect(keyWrapKey.extractable).toBe(false);
  });

  it("produces each handle of §25.1 with exactly the listed usages and extractability", async () => {
    const session = await unwrapSessionKey(keyWrapKey, encryptionAad, encryptionBlob);
    expect([...session.usages]).toEqual(["unwrapKey"]);
    expect(session.extractable).toBe(false);

    const operation = await unwrapOperationKey(keyWrapKey, encryptionAad, encryptionBlob);
    expect([...operation.usages]).toEqual(["decrypt"]);
    expect(operation.extractable).toBe(false);

    const signing = await unwrapSigningKey(keyWrapKey, signingAad, signingBlob);
    expect([...signing.usages]).toEqual(["sign"]);
    expect(signing.extractable).toBe(false);

    const rewrapEncryption = await unwrapRewrapEncryptionKey(keyWrapKey, encryptionAad, encryptionBlob);
    expect([...rewrapEncryption.usages]).toEqual(["decrypt"]);
    expect(rewrapEncryption.extractable).toBe(true);

    const rewrapSigning = await unwrapRewrapSigningKey(keyWrapKey, signingAad, signingBlob);
    expect([...rewrapSigning.usages]).toEqual(["sign"]);
    expect(rewrapSigning.extractable).toBe(true);
  });

  it("a blob wrapped under one key_role does not open under the other (§44.3)", async () => {
    await expect(unwrapSessionKey(keyWrapKey, signingAad, encryptionBlob)).rejects.toThrow(/DECRYPT_FAILED/);
    await expect(unwrapSigningKey(keyWrapKey, encryptionAad, signingBlob)).rejects.toThrow(/DECRYPT_FAILED/);
  });

  it("a keyset does not open under another Account Secret Key (§24)", async () => {
    await expect(unwrapSessionKey(otherKeyWrapKey, encryptionAad, encryptionBlob)).rejects.toThrow(
      /DECRYPT_FAILED/,
    );
  });

  it("rejects tampered and truncated keyset blobs", async () => {
    await expect(unwrapSessionKey(keyWrapKey, encryptionAad, flipByte(encryptionBlob, 40))).rejects.toThrow(
      /DECRYPT_FAILED/,
    );
    await expect(unwrapSessionKey(keyWrapKey, encryptionAad, encryptionBlob.subarray(0, 20))).rejects.toThrow(
      /DECRYPT_FAILED|BAD_LENGTH/,
    );
  });

  it("a re-wrapped keyset opens under the new secrets and not under the old ones (§35.6)", async () => {
    const rewrapped = await wrapPrivateKey(
      otherKeyWrapKey,
      encryptionAad,
      await unwrapRewrapEncryptionKey(keyWrapKey, encryptionAad, encryptionBlob),
    );
    await expect(unwrapSessionKey(otherKeyWrapKey, encryptionAad, rewrapped)).resolves.toBeDefined();
    await expect(unwrapSessionKey(keyWrapKey, encryptionAad, rewrapped)).rejects.toThrow(/DECRYPT_FAILED/);
  });
});

describe("Argon2id parameters (ADR-004 profile 1)", () => {
  const limits = ARGON2_LIMITS.get(1);

  it("the shipped profile is RFC 9106's second recommended option", () => {
    expect(ARGON2_PARAMS_V1).toEqual({ memoryKib: 65_536, iterations: 3, parallelism: 4, version: 1 });
  });

  it("the shipped profile sits inside its own limits, so the default never gets rejected", () => {
    expect(limits).toBeDefined();
    expect(() => {
      assertArgon2ParamsAccepted(ARGON2_PARAMS_V1);
    }).not.toThrow();
    expect(ARGON2_PARAMS_V1.memoryKib).toBeGreaterThanOrEqual(limits?.memoryKib[0] ?? Infinity);
    expect(ARGON2_PARAMS_V1.memoryKib).toBeLessThanOrEqual(limits?.memoryKib[1] ?? 0);
    expect(ARGON2_PARAMS_V1.iterations).toBeGreaterThanOrEqual(limits?.iterations[0] ?? Infinity);
    expect(ARGON2_PARAMS_V1.iterations).toBeLessThanOrEqual(limits?.iterations[1] ?? 0);
  });

  it("rejects parameters below the minimum, above the maximum, and unknown profiles (§24)", () => {
    const below = [
      { ...ARGON2_PARAMS_V1, memoryKib: (limits?.memoryKib[0] ?? 1) - 1 },
      { ...ARGON2_PARAMS_V1, iterations: (limits?.iterations[0] ?? 1) - 1 },
      { ...ARGON2_PARAMS_V1, parallelism: 0 },
    ];
    const above = [
      { ...ARGON2_PARAMS_V1, memoryKib: (limits?.memoryKib[1] ?? 0) + 1 },
      { ...ARGON2_PARAMS_V1, iterations: (limits?.iterations[1] ?? 0) + 1 },
      { ...ARGON2_PARAMS_V1, parallelism: (limits?.parallelism[1] ?? 0) + 1 },
    ];
    for (const params of [...below, ...above]) {
      expect(() => {
        assertArgon2ParamsAccepted(params);
      }).toThrow(/BAD_PARAMS/);
    }
    expect(() => {
      assertArgon2ParamsAccepted({ ...ARGON2_PARAMS_V1, version: 2 });
    }).toThrow(/BAD_PARAMS/);
    expect(() => {
      assertArgon2ParamsAccepted({ ...ARGON2_PARAMS_V1, memoryKib: 65_536.5 });
    }).toThrow(/BAD_PARAMS/);
  });

  it("derivePasswordKey refuses out-of-range parameters before doing any work", async () => {
    await expect(
      derivePasswordKey("hunter2hunter2", randomBytes(KDF_SALT_BYTES), { ...ARGON2_PARAMS_V1, memoryKib: 8 }),
    ).rejects.toThrow(/BAD_PARAMS/);
  });

  it("derivePasswordKey requires a 16-byte kdf_salt (§23.4)", async () => {
    await expect(derivePasswordKey("hunter2hunter2", randomBytes(15), ARGON2_PARAMS_V1)).rejects.toThrow(
      /BAD_LENGTH/,
    );
  });
});

describe("derivePasswordKey (§24)", () => {
  // One real derivation at the shipped cost; everything else uses the cheapest accepted profile.
  const cheap = { ...ARGON2_PARAMS_V1, memoryKib: 65_536, iterations: 3 };

  it("is deterministic, 32 bytes, and normalizes the password to NFC", async () => {
    const salt = new Uint8Array(KDF_SALT_BYTES).fill(9);
    const composed = "café latte"; // e + combining acute
    const precomposed = "café latte";

    const a = await derivePasswordKey(composed, salt, cheap);
    const b = await derivePasswordKey(precomposed, salt, cheap);
    expect(a.length).toBe(PASSWORD_KEY_BYTES);
    expect(toHex(a)).toBe(toHex(b));

    const other = await derivePasswordKey(`${precomposed}!`, salt, cheap);
    expect(toHex(other)).not.toBe(toHex(a));
  });

  it("a different kdf_salt gives a different key (§35.6 regenerates it)", async () => {
    const a = await derivePasswordKey("hunter2hunter2", new Uint8Array(KDF_SALT_BYTES).fill(1), cheap);
    const b = await derivePasswordKey("hunter2hunter2", new Uint8Array(KDF_SALT_BYTES).fill(2), cheap);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it("without the Account Secret Key the password alone opens nothing (§24, §39.1)", async () => {
    // The attacker has the whole database: salt, parameters, wrapped keyset, and the right password.
    const salt = new Uint8Array(KDF_SALT_BYTES).fill(3);
    const passwordKey = await derivePasswordKey("hunter2hunter2", salt, cheap);
    const info = domainContext("nodra/hkdf/account-keywrap");
    const secretKey = randomBytes(20);

    const owner = await deriveKeyWrapKey(await importHkdfBase(passwordKey), { salt: secretKey, info });
    const blob = await wrapPrivateKey(owner, signingAad, (await generateSigningKeyPair()).privateKey);

    const guess = await deriveKeyWrapKey(await importHkdfBase(passwordKey), { salt: randomBytes(20), info });
    await expect(unwrapSigningKey(guess, signingAad, blob)).rejects.toThrow(/DECRYPT_FAILED/);
    await expect(unwrapSigningKey(owner, signingAad, blob)).resolves.toBeDefined();
  });
});

describe("byte helpers", () => {
  it("timingSafeEqual compares content and length", () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2]))).toBe(false);
    expect(timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });

  it("zeroize clears buffers and never throws (§44.3)", () => {
    const secret = randomBytes(32);
    expect(() => {
      zeroize(secret, undefined, new Uint8Array(0));
    }).not.toThrow();
    expect(toHex(secret)).toBe("00".repeat(32));
  });

  it("randomBytes spans more than one getRandomValues chunk and does not repeat", () => {
    const big = randomBytes(70_000);
    expect(big.length).toBe(70_000);
    expect(toHex(big.subarray(65_530, 65_542))).not.toBe("00".repeat(12));
    expect(toHex(randomBytes(32))).not.toBe(toHex(randomBytes(32)));
    expect(randomBytes(0).length).toBe(0);
    expect(() => randomBytes(-1)).toThrow(/BAD_LENGTH/);
  });

  it("sha256 hashes raw bytes (the §23.0 rule 6 exceptions)", async () => {
    // FIPS 180-4 "abc".
    expect(toHex(await sha256(new TextEncoder().encode("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});
