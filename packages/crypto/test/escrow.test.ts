// ADR-021 escrow primitives (§3.6, §23.3, §23.4, §24.2): the client wraps a 32-byte secret to the
// Escrow Key under Context("nodra/escrow", account_id, key_id, slot); the Worker opens it and
// re-wraps it to the client's ephemeral key under Context("nodra/escrow-rewrap", account_id,
// SHA-256(ephemeral SPKI), slot); the client unwraps it without the bytes ever leaving Web Crypto.
import fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";
import { AEAD_KEY_BYTES, importAeadKey, seal, unseal } from "../src/aead.js";
import { randomBytes } from "../src/bytes.js";
import { domainContext } from "../src/context.js";
import type { DomainContext } from "../src/context.js";
import {
  ESCROW_SECRET_BYTES,
  escrowLabel,
  escrowRewrapLabel,
  exportEnvelopePublicKey,
  generateEnvelopeKeyPair,
  generateRecipientKeyPair,
  openEscrowKey,
  sealEscrowKey,
  unwrapEscrowPayloadKey,
  unwrapRootUnlockBase,
} from "../src/envelope.js";
import type { EnvelopeKeyPair, EscrowSlotName, RecipientKeyPair } from "../src/envelope.js";
import { CryptoError } from "../src/errors.js";
import { sha256 } from "../src/hash.js";
import { EMPTY_SALT, deriveBits, importHkdfBase } from "../src/hkdf.js";
import { subtle } from "../src/runtime.js";
import { toHex } from "./support.js";

// RSA-3072 operations are slow; the keys are generated once and every run reuses them.
const RUNS = 12;

const bytes = (length: number) => fc.uint8Array({ minLength: length, maxLength: length });
const id16 = bytes(16);
const secret32 = bytes(32);
const slotArb = fc.constantFrom<EscrowSlotName>("UNLOCK", "RECOVERY");
const payloadArb = fc.oneof(fc.constant(new Uint8Array(0)), fc.uint8Array({ maxLength: 400 }));

let escrow: EnvelopeKeyPair; // the server's Escrow Key pair (the Worker holds the private half)
let ephemeral: RecipientKeyPair; // the client's per-unlock pair (§24.2 step 2)
let ephemeralSpki: Uint8Array;
let otherSpki: Uint8Array;

beforeAll(async () => {
  escrow = await generateEnvelopeKeyPair();
  ephemeral = await generateRecipientKeyPair();
  ephemeralSpki = await exportEnvelopePublicKey(ephemeral.publicKey);
  otherSpki = await exportEnvelopePublicKey((await generateRecipientKeyPair()).publicKey);
});

/** Same HKDF output from both bases ⇒ same input keying material. */
async function sameHkdfBase(a: CryptoKey, b: CryptoKey): Promise<boolean> {
  const info = domainContext("nodra/hkdf/account-keywrap");
  const x = await deriveBits(a as never, { salt: EMPTY_SALT, info }, 256);
  const y = await deriveBits(b as never, { salt: EMPTY_SALT, info }, 256);
  return toHex(x) === toHex(y);
}

async function rejects(p: Promise<unknown>): Promise<CryptoError> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(CryptoError);
    return e as CryptoError;
  }
  return expect.unreachable("expected a CryptoError, nothing was thrown");
}

describe("labels (§23.3)", () => {
  it("nodra/escrow is Context(domain, account_id, key_id, slot)", () => {
    const a = randomBytes(16);
    const k = randomBytes(16);
    expect(toHex(escrowLabel(a, k, "UNLOCK"))).toBe(toHex(domainContext("nodra/escrow", a, k, "UNLOCK")));
  });

  it("nodra/escrow-rewrap is Context(domain, account_id, SHA-256(ephemeral SPKI), slot)", async () => {
    const a = randomBytes(16);
    const label = await escrowRewrapLabel(a, ephemeralSpki, "RECOVERY");
    expect(toHex(label)).toBe(toHex(domainContext("nodra/escrow-rewrap", a, await sha256(ephemeralSpki), "RECOVERY")));
  });

  it("ids must be 16 bytes", async () => {
    expect(() => escrowLabel(new Uint8Array(15), randomBytes(16), "UNLOCK")).toThrow(/BAD_LENGTH/);
    expect(() => escrowLabel(randomBytes(16), new Uint8Array(17), "UNLOCK")).toThrow(/BAD_LENGTH/);
    await expect(escrowRewrapLabel(new Uint8Array(15), ephemeralSpki, "UNLOCK")).rejects.toThrow(/BAD_LENGTH/);
  });
});

describe("round trips (fast-check)", () => {
  it("sealEscrowKey → openEscrowKey returns the same 32 bytes", async () => {
    await fc.assert(
      fc.asyncProperty(secret32, id16, id16, slotArb, async (secret, accountId, keyId, slot) => {
        const label = escrowLabel(accountId, keyId, slot);
        const wrapped = await sealEscrowKey(escrow.publicKey, label, secret);
        expect(toHex(await openEscrowKey(escrow.privateKey, label, wrapped))).toBe(toHex(secret));
      }),
      { numRuns: RUNS },
    );
  });

  it("unwrapRootUnlockBase yields the HKDF base of the sealed RootUnlockKey (§24)", async () => {
    await fc.assert(
      fc.asyncProperty(secret32, id16, async (rootUnlockKey, accountId) => {
        const label = await escrowRewrapLabel(accountId, ephemeralSpki, "UNLOCK");
        const wrapped = await sealEscrowKey(ephemeral.publicKey, label, rootUnlockKey);
        const base = await unwrapRootUnlockBase(ephemeral.privateKey, label, wrapped);
        expect(await sameHkdfBase(base, await importHkdfBase(rootUnlockKey))).toBe(true);
      }),
      { numRuns: RUNS },
    );
  });

  it("unwrapEscrowPayloadKey yields the AES-256-GCM key the payload was sealed with", async () => {
    await fc.assert(
      fc.asyncProperty(secret32, id16, payloadArb, async (keyBytes, accountId, payload) => {
        const label = await escrowRewrapLabel(accountId, ephemeralSpki, "RECOVERY");
        const blob = await seal(await importAeadKey(keyBytes), label, payload);
        const wrapped = await sealEscrowKey(ephemeral.publicKey, label, keyBytes);
        const key = await unwrapEscrowPayloadKey(ephemeral.privateKey, label, wrapped);
        expect(toHex(await unseal(key, label, blob))).toBe(toHex(payload));
        // And the other way: what the unwrapped key seals, the original key opens.
        const back = await seal(key, label, payload);
        expect(toHex(await unseal(await importAeadKey(keyBytes), label, back))).toBe(toHex(payload));
      }),
      { numRuns: RUNS },
    );
  });

  it("the whole RECOVERY pipeline: client wraps, Worker re-wraps, client opens (§23.4, §35.7)", async () => {
    await fc.assert(
      fc.asyncProperty(id16, id16, payloadArb, async (accountId, keyId, recoveryKeys) => {
        // Client, at creation: random AES key, payload under the escrow Context, key to the Escrow Key.
        const slotLabel = escrowLabel(accountId, keyId, "RECOVERY");
        const aesBytes = randomBytes(AEAD_KEY_BYTES);
        const payloadBlob = await seal(await importAeadKey(aesBytes), slotLabel, recoveryKeys);
        const wrappedKey = await sealEscrowKey(escrow.publicKey, slotLabel, aesBytes);
        // Worker: open with the Escrow Key, re-seal the payload under the rewrap AAD, re-wrap the key.
        const opened = await openEscrowKey(escrow.privateKey, slotLabel, wrappedKey);
        const inner = await unseal(await importAeadKey(opened), slotLabel, payloadBlob);
        const rewrapLabel = await escrowRewrapLabel(accountId, ephemeralSpki, "RECOVERY");
        const rewrapBlob = await seal(await importAeadKey(opened), rewrapLabel, inner);
        const rewrapped = await sealEscrowKey(ephemeral.publicKey, rewrapLabel, opened);
        // Client: unwrap with the non-extractable ephemeral key, then open.
        const key = await unwrapEscrowPayloadKey(ephemeral.privateKey, rewrapLabel, rewrapped);
        expect(toHex(await unseal(key, rewrapLabel, rewrapBlob))).toBe(toHex(recoveryKeys));
      }),
      { numRuns: RUNS },
    );
  });
});

describe("binding (§44.3 T15 at the primitive level)", () => {
  const A = new Uint8Array(16).fill(0xa1);
  const A2 = new Uint8Array(16).fill(0xa2);
  const K = new Uint8Array(16).fill(0xb1);
  const K2 = new Uint8Array(16).fill(0xb2);

  it("an escrow slot opens only under its own account_id, key_id and slot", async () => {
    const secret = randomBytes(32);
    const wrapped = await sealEscrowKey(escrow.publicKey, escrowLabel(A, K, "UNLOCK"), secret);
    for (const wrong of [escrowLabel(A2, K, "UNLOCK"), escrowLabel(A, K2, "UNLOCK"), escrowLabel(A, K, "RECOVERY")]) {
      expect((await rejects(openEscrowKey(escrow.privateKey, wrong, wrapped))).code).toBe("DECRYPT_FAILED");
    }
    expect(toHex(await openEscrowKey(escrow.privateKey, escrowLabel(A, K, "UNLOCK"), wrapped))).toBe(toHex(secret));
  });

  it("a re-wrap opens only under its own account_id, ephemeral SPKI and slot", async () => {
    const secret = randomBytes(32);
    const right = await escrowRewrapLabel(A, ephemeralSpki, "UNLOCK");
    const wrongs = [
      await escrowRewrapLabel(A2, ephemeralSpki, "UNLOCK"),
      await escrowRewrapLabel(A, otherSpki, "UNLOCK"),
      await escrowRewrapLabel(A, ephemeralSpki, "RECOVERY"),
    ];
    const wrapped = await sealEscrowKey(ephemeral.publicKey, right, secret);
    for (const wrong of wrongs) {
      expect((await rejects(unwrapRootUnlockBase(ephemeral.privateKey, wrong, wrapped))).code).toBe("DECRYPT_FAILED");
      expect((await rejects(unwrapEscrowPayloadKey(ephemeral.privateKey, wrong, wrapped))).code).toBe("DECRYPT_FAILED");
    }
    // The payload AAD is the same Context, so a payload moved across accounts, keys or slots fails too.
    const key = await unwrapEscrowPayloadKey(ephemeral.privateKey, right, wrapped);
    const blob = await seal(key, right, randomBytes(40));
    for (const wrong of wrongs) {
      expect((await rejects(unseal(key, wrong, blob))).code).toBe("DECRYPT_FAILED");
    }
  });

  // The oracle: "changing account_id alone makes the open fail", for a given label builder.
  async function accountIdIsBound(label: (accountId: Uint8Array) => DomainContext): Promise<boolean> {
    const wrapped = await sealEscrowKey(escrow.publicKey, label(A), randomBytes(32));
    try {
      await openEscrowKey(escrow.privateKey, label(A2), wrapped);
      return false;
    } catch (e) {
      return e instanceof CryptoError && e.code === "DECRYPT_FAILED";
    }
  }

  it("holds for the real label", async () => {
    expect(await accountIdIsBound((a) => escrowLabel(a, K, "UNLOCK"))).toBe(true);
  });

  it("fails for a label variant that drops account_id", async () => {
    expect(await accountIdIsBound((_a) => domainContext("nodra/escrow", K, "UNLOCK"))).toBe(false);
  });
});

describe("the ephemeral private key (§24.2 step 2)", () => {
  it("is non-extractable and can only unwrap", async () => {
    const pair = await generateRecipientKeyPair();
    expect(pair.privateKey.extractable).toBe(false);
    expect([...pair.privateKey.usages]).toEqual(["unwrapKey"]);
    await expect(subtle().exportKey("pkcs8", pair.privateKey)).rejects.toThrow();
    await expect(subtle().exportKey("jwk", pair.privateKey)).rejects.toThrow();
  });

  it("the keys it unwraps are non-extractable too", async () => {
    const label = await escrowRewrapLabel(randomBytes(16), ephemeralSpki, "RECOVERY");
    const wrapped = await sealEscrowKey(ephemeral.publicKey, label, randomBytes(32));
    const base = await unwrapRootUnlockBase(ephemeral.privateKey, label, wrapped);
    const aes = await unwrapEscrowPayloadKey(ephemeral.privateKey, label, wrapped);
    expect(base.extractable).toBe(false);
    expect(aes.extractable).toBe(false);
    await expect(subtle().exportKey("raw", aes)).rejects.toThrow();
  });
});

describe("lengths", () => {
  it("sealEscrowKey accepts exactly 32 bytes", async () => {
    const label = escrowLabel(randomBytes(16), randomBytes(16), "UNLOCK");
    expect(ESCROW_SECRET_BYTES).toBe(32);
    for (const n of [0, 16, 31, 33]) {
      expect((await rejects(sealEscrowKey(escrow.publicKey, label, new Uint8Array(n)))).code).toBe("BAD_LENGTH");
    }
  });

  it("a payload key that is not 256 bits is rejected, never silently used as AES-128", async () => {
    const label = await escrowRewrapLabel(randomBytes(16), ephemeralSpki, "RECOVERY");
    const short = new Uint8Array(await subtle().encrypt({ name: "RSA-OAEP", label: label as BufferSource }, ephemeral.publicKey, randomBytes(16) as BufferSource));
    expect((await rejects(unwrapEscrowPayloadKey(ephemeral.privateKey, label, short))).code).toBe("BAD_LENGTH");
  });

  it("a re-wrapped RootUnlockKey that is not 32 bytes is rejected before it becomes an HKDF base", async () => {
    const label = await escrowRewrapLabel(randomBytes(16), ephemeralSpki, "UNLOCK");
    for (const n of [1, 16, 31, 33, 64]) {
      const wrong = new Uint8Array(await subtle().encrypt({ name: "RSA-OAEP", label: label as BufferSource }, ephemeral.publicKey, randomBytes(n) as BufferSource));
      expect((await rejects(unwrapRootUnlockBase(ephemeral.privateKey, label, wrong))).code).toBe("BAD_LENGTH");
    }
  });

  it("an opened escrow secret that is not 32 bytes is rejected", async () => {
    const label = escrowLabel(randomBytes(16), randomBytes(16), "UNLOCK");
    const short = new Uint8Array(await subtle().encrypt({ name: "RSA-OAEP", label: label as BufferSource }, escrow.publicKey, randomBytes(16) as BufferSource));
    expect((await rejects(openEscrowKey(escrow.privateKey, label, short))).code).toBe("BAD_LENGTH");
  });
});

describe("no plaintext in any thrown error", () => {
  function forms(secret: Uint8Array): string[] {
    const hex = toHex(secret);
    return [hex, hex.toUpperCase(), Buffer.from(secret).toString("base64"), Array.from(secret).join(","), Array.from(secret).join(", ")];
  }

  it("holds for every failure path of the escrow primitives", async () => {
    const secret = Uint8Array.from({ length: 32 }, (_, i) => 0x80 + i);
    const shortSecret = secret.subarray(0, 16);
    const A = randomBytes(16);
    const label = escrowLabel(A, randomBytes(16), "RECOVERY");
    const rewrap = await escrowRewrapLabel(A, ephemeralSpki, "RECOVERY");
    const otherRewrap = await escrowRewrapLabel(A, otherSpki, "RECOVERY");
    const wrapped = await sealEscrowKey(escrow.publicKey, label, secret);
    const rewrapped = await sealEscrowKey(ephemeral.publicKey, rewrap, secret);
    const encryptRaw = async (key: CryptoKey, l: DomainContext, p: Uint8Array) =>
      new Uint8Array(await subtle().encrypt({ name: "RSA-OAEP", label: l as BufferSource }, key, p as BufferSource));
    const payload = await seal(await importAeadKey(secret), rewrap, secret);

    const errors = [
      await rejects(sealEscrowKey(escrow.publicKey, label, secret.subarray(0, 31))),
      await rejects(openEscrowKey(escrow.privateKey, escrowLabel(A, randomBytes(16), "RECOVERY"), wrapped)),
      await rejects(openEscrowKey(escrow.privateKey, label, await encryptRaw(escrow.publicKey, label, shortSecret))),
      await rejects(unwrapRootUnlockBase(ephemeral.privateKey, otherRewrap, rewrapped)),
      await rejects(unwrapEscrowPayloadKey(ephemeral.privateKey, otherRewrap, rewrapped)),
      await rejects(unwrapEscrowPayloadKey(ephemeral.privateKey, rewrap, await encryptRaw(ephemeral.publicKey, rewrap, shortSecret))),
      await rejects(unseal(await importAeadKey(secret), otherRewrap, payload)),
    ];
    expect(errors.length).toBe(7);
    for (const e of errors) {
      const text = `${e.message} ${String(e.stack)}`;
      for (const form of [...forms(secret), ...forms(shortSecret)]) expect(text).not.toContain(form);
    }
  });
});
