// Known-answer tests. Every expected value comes from vectors/primitives.json, whose contents were
// copied from RFC 5869, RFC 9106 and Project Wycheproof — never from this implementation.
import { describe, expect, it } from "vitest";
import { importAeadKey, unsafeSealWithNonce, unseal } from "../src/aead.js";
import { importHkdfBase, unsafeDeriveBitsWithInfo } from "../src/hkdf.js";
import { unsafeArgon2id } from "../src/argon2.js";
import {
  importExtractableEnvelopePrivateKey,
  unsafeOpenWithLabel,
} from "../src/envelope.js";
import { importVerifyingKey, unsafeVerifyRaw } from "../src/signature.js";
import { hmacSha256, importMacKey } from "../src/hash.js";
import { asContext, fromHex, toHex, vectors } from "./support.js";

describe("HKDF-SHA-256 (RFC 5869)", () => {
  for (const v of vectors.hkdf) {
    it(v.name, async () => {
      const base = await importHkdfBase(fromHex(v.ikm));
      const okm = await unsafeDeriveBitsWithInfo(base, fromHex(v.salt), fromHex(v.info), v.okmBytes * 8);
      expect(toHex(okm)).toBe(v.okm);
    });
  }
});

describe("Argon2id (RFC 9106)", () => {
  for (const v of vectors.argon2id) {
    it(v.name, async () => {
      const tag = await unsafeArgon2id(fromHex(v.password), fromHex(v.salt), {
        m: v.memoryKib,
        t: v.iterations,
        p: v.parallelism,
        dkLen: v.tagBytes,
        key: fromHex(v.secret),
        associatedData: fromHex(v.associatedData),
      });
      expect(toHex(tag)).toBe(v.tag);
    });
  }
});

describe("AES-256-GCM (Wycheproof)", () => {
  it("has both valid and invalid cases", () => {
    expect(vectors.aesGcm.filter((v) => v.result === "valid").length).toBeGreaterThan(10);
    expect(vectors.aesGcm.filter((v) => v.result === "invalid").length).toBeGreaterThan(10);
  });

  for (const v of vectors.aesGcm) {
    const label = `tc${String(v.tcId)} ${v.result}${v.comment === undefined ? "" : ` (${v.comment})`}`;
    it(label, async () => {
      const key = await importAeadKey(fromHex(v.key));
      const aad = asContext(fromHex(v.aad));
      const blob = new Uint8Array([...fromHex(v.nonce), ...fromHex(v.ciphertext), ...fromHex(v.tag)]);
      if (v.result === "valid") {
        // Encryption with the vector's nonce must reproduce the vector's ciphertext and tag.
        const sealed = await unsafeSealWithNonce(key, fromHex(v.nonce), aad, fromHex(v.plaintext));
        expect(toHex(sealed)).toBe(v.nonce + v.ciphertext + v.tag);
        expect(toHex(await unseal(key, aad, blob))).toBe(v.plaintext);
      } else {
        await expect(unseal(key, aad, blob)).rejects.toThrow(/DECRYPT_FAILED|BAD_LENGTH/);
      }
    });
  }
});

describe("RSA-OAEP-3072/SHA-256 (Wycheproof)", () => {
  for (const v of vectors.rsaOaep.tests) {
    const label = `tc${String(v.tcId)} ${v.result}${v.comment === undefined ? "" : ` (${v.comment})`}`;
    it(label, async () => {
      const key = await importExtractableEnvelopePrivateKey(fromHex(vectors.rsaOaep.privateKeyPkcs8));
      const run = unsafeOpenWithLabel(key, fromHex(v.label), fromHex(v.ciphertext));
      if (v.result === "valid") {
        expect(toHex(await run)).toBe(v.plaintext);
      } else {
        await expect(run).rejects.toThrow(/DECRYPT_FAILED/);
      }
    });
  }

  it("a valid ciphertext under the wrong label is rejected", async () => {
    const valid = vectors.rsaOaep.tests.find((t) => t.result === "valid");
    expect(valid).toBeDefined();
    const key = await importExtractableEnvelopePrivateKey(fromHex(vectors.rsaOaep.privateKeyPkcs8));
    const wrongLabel = fromHex(`${valid?.label ?? ""}00`);
    await expect(unsafeOpenWithLabel(key, wrongLabel, fromHex(valid?.ciphertext ?? ""))).rejects.toThrow(
      /DECRYPT_FAILED/,
    );
  });
});

describe("ECDSA P-256 / SHA-256, P1363 signatures (Wycheproof)", () => {
  it("has both valid and invalid cases", () => {
    expect(vectors.ecdsaP1363.tests.filter((v) => v.result === "valid").length).toBeGreaterThan(5);
    expect(vectors.ecdsaP1363.tests.filter((v) => v.result === "invalid").length).toBeGreaterThan(5);
  });

  for (const v of vectors.ecdsaP1363.tests) {
    const label = `tc${String(v.tcId)} ${v.result}${v.comment === undefined ? "" : ` (${v.comment})`}`;
    it(label, async () => {
      const key = await importVerifyingKey(fromHex(vectors.ecdsaP1363.publicKeySpki));
      const ok = await unsafeVerifyRaw(key, fromHex(v.message), fromHex(v.signature));
      expect(ok).toBe(v.result === "valid");
    });
  }
});

describe("HMAC-SHA-256 (Wycheproof)", () => {
  for (const v of vectors.hmacSha256) {
    it(`tc${String(v.tcId)}`, async () => {
      const key = await importMacKey(fromHex(v.key));
      expect(toHex(await hmacSha256(key, fromHex(v.message)))).toBe(v.tag);
    });
  }
});
