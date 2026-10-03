// Property tests for the wrappers. They exercise the shapes the unit tests fix, over random keys,
// plaintexts and context fields.
import fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";
import { importAeadKey, seal, unseal } from "../src/aead.js";
import { randomBytes, timingSafeEqual } from "../src/bytes.js";
import { domainContext } from "../src/context.js";
import { EMPTY_SALT, deriveBits, importHkdfBase } from "../src/hkdf.js";
import { hmacSha256, importMacKey } from "../src/hash.js";
import { generateSigningKeyPair, signContext, verifyContext } from "../src/signature.js";
import type { SigningKeyPair } from "../src/signature.js";
import { asContext, flipByte, toHex } from "./support.js";

const RUNS = 40;

const bytes = (length: number) => fc.uint8Array({ minLength: length, maxLength: length });
const id16 = bytes(16);
const payload = fc.uint8Array({ minLength: 0, maxLength: 512 });

describe("AES-GCM wrapper properties", () => {
  it("round trips any plaintext under any key and any content context", async () => {
    await fc.assert(
      fc.asyncProperty(bytes(32), id16, id16, id16, payload, async (raw, vault, epoch, blobId, plaintext) => {
        const key = await importAeadKey(raw);
        const aad = domainContext("nodra/aad/content", vault, epoch, blobId);
        const blob = await seal(key, aad, plaintext);
        expect(toHex(await unseal(key, aad, blob))).toBe(toHex(plaintext));
      }),
      { numRuns: RUNS },
    );
  });

  it("any single changed byte of the context makes the blob unreadable", async () => {
    await fc.assert(
      fc.asyncProperty(
        bytes(32),
        id16,
        id16,
        id16,
        payload,
        fc.nat(),
        async (raw, vault, epoch, blobId, plaintext, index) => {
          const key = await importAeadKey(raw);
          const aad = domainContext("nodra/aad/content", vault, epoch, blobId);
          const blob = await seal(key, aad, plaintext);
          await expect(unseal(key, asContext(flipByte(aad, index)), blob)).rejects.toThrow(/DECRYPT_FAILED/);
        },
      ),
      { numRuns: RUNS },
    );
  });

  it("any single changed byte of the blob makes it unreadable", async () => {
    await fc.assert(
      fc.asyncProperty(bytes(32), id16, payload, fc.nat(), async (raw, blobId, plaintext, index) => {
        const key = await importAeadKey(raw);
        const aad = domainContext("nodra/hkdf/content", blobId);
        const blob = await seal(key, aad, plaintext);
        await expect(unseal(key, aad, flipByte(blob, index))).rejects.toThrow(/DECRYPT_FAILED/);
      }),
      { numRuns: RUNS },
    );
  });
});

describe("HKDF properties", () => {
  it("is deterministic, and distinct contexts give distinct bits", async () => {
    await fc.assert(
      fc.asyncProperty(bytes(32), id16, id16, async (ikm, a, b) => {
        fc.pre(toHex(a) !== toHex(b));
        const base = await importHkdfBase(ikm);
        const infoA = domainContext("nodra/hkdf/content", a);
        const infoB = domainContext("nodra/hkdf/content", b);
        const first = await deriveBits(base, { salt: EMPTY_SALT, info: infoA }, 256);
        const again = await deriveBits(await importHkdfBase(ikm), { salt: EMPTY_SALT, info: infoA }, 256);
        const other = await deriveBits(base, { salt: EMPTY_SALT, info: infoB }, 256);
        expect(toHex(first)).toBe(toHex(again));
        expect(toHex(first)).not.toBe(toHex(other));
      }),
      { numRuns: RUNS },
    );
  });
});

describe("HMAC properties", () => {
  it("is deterministic per key and separates keys", async () => {
    await fc.assert(
      fc.asyncProperty(bytes(32), bytes(32), payload, async (rawA, rawB, message) => {
        fc.pre(toHex(rawA) !== toHex(rawB));
        const a = await importMacKey(rawA);
        const b = await importMacKey(rawB);
        const tag = await hmacSha256(a, message);
        expect(tag.length).toBe(32);
        expect(toHex(await hmacSha256(a, message))).toBe(toHex(tag));
        expect(toHex(await hmacSha256(b, message))).not.toBe(toHex(tag));
      }),
      { numRuns: RUNS },
    );
  });
});

describe("ECDSA properties", () => {
  let pair: SigningKeyPair;
  beforeAll(async () => {
    pair = await generateSigningKeyPair();
  });

  it("verifies its own signatures and rejects any mutated context", async () => {
    await fc.assert(
      fc.asyncProperty(id16, fc.nat({ max: 2 ** 31 }), fc.nat(), async (account, generation, index) => {
        const ctx = domainContext("nodra/delete-account", "DELETE_ACCOUNT", account, generation, account);
        const signature = await signContext(pair.privateKey, ctx);
        expect(await verifyContext(pair.publicKey, ctx, signature)).toBe(true);
        expect(await verifyContext(pair.publicKey, asContext(flipByte(ctx, index)), signature)).toBe(false);
        expect(await verifyContext(pair.publicKey, ctx, flipByte(signature, index))).toBe(false);
      }),
      { numRuns: RUNS },
    );
  });
});

describe("timingSafeEqual properties", () => {
  it("agrees with byte equality", () => {
    fc.assert(
      fc.property(payload, payload, (a, b) => {
        expect(timingSafeEqual(a, b)).toBe(toHex(a) === toHex(b));
      }),
      { numRuns: 500 },
    );
  });

  it("is true for a buffer against its own copy", () => {
    fc.assert(
      fc.property(fc.nat({ max: 128 }), (length) => {
        const a = randomBytes(length);
        expect(timingSafeEqual(a, Uint8Array.from(a))).toBe(true);
      }),
      { numRuns: 200 },
    );
  });
});
