// §31.3 (blob framing and AADs) and §31.4 (content fingerprint).
//
// Every negative case here breaks exactly ONE field of a blob that otherwise round-trips, so a
// rejection proves the rule named in the test and not that AES-GCM works. The two "broken variant"
// suites at the bottom are the evidence discipline of CLAUDE.md: a crypto that ignores the AAD and
// one that repeats a nonce are both built here and both caught by the same assertions that pass
// against the real implementation.
import { AEAD_NONCE_BYTES, CryptoError, importAeadKey, seal, splitBlob } from "@nodra/crypto";
import { describe, expect, it } from "vitest";
import {
  contentFingerprint,
  openContentBlob,
  openManifestBlob,
  sealContentBlob,
  sealManifestBlob,
} from "../src/blob.js";
import { contentBlobAad, manifestBlobAad } from "../src/contexts.js";
import type { ManifestBinding } from "../src/contexts.js";
import { deriveContentKey, deriveManifestKey } from "../src/epoch.js";
import type { EpochKey } from "../src/epoch.js";
import { type EpochWorld, makeEpoch, makeWorld } from "./epoch-support.js";
import { filled, flipByte, toHex } from "./support.js";

const BLOB_A = filled(16, 0xb1);
const BLOB_B = filled(16, 0xb2);

const binding: ManifestBinding = {
  objectId: filled(16, 0x01),
  revisionId: filled(16, 0x02),
  parentRevisionId: filled(16, 0x03),
};

let cached: Promise<{ world: EpochWorld; first: EpochKey; second: EpochKey }> | null = null;

/** One world with two epochs of the same vault: enough for every cross-epoch case below. */
function world(): Promise<{ world: EpochWorld; first: EpochKey; second: EpochKey }> {
  cached ??= (async () => {
    const w = await makeWorld();
    const e1 = await makeEpoch(w, 0x41, null);
    const e2 = await makeEpoch(w, 0x42, e1);
    return { world: w, first: e1.epochKey, second: e2.epochKey };
  })();
  return cached;
}

const bytes = (...values: number[]) => Uint8Array.from(values);

describe("content blobs (§31.3)", () => {
  it("round-trips the exact bytes, including an empty plaintext and binary", async () => {
    const { first } = await world();
    for (const plaintext of [new Uint8Array(0), bytes(0, 1, 2, 255, 128, 0), filled(70_000, 0x5a)]) {
      const blob = await sealContentBlob(first, BLOB_A, plaintext);
      expect(await openContentBlob(first, BLOB_A, blob)).toEqual(plaintext);
    }
  });

  it("frames the blob as nonce ‖ ciphertext‖tag with a 12-byte nonce", async () => {
    const { first } = await world();
    const plaintext = bytes(7, 7, 7);
    const blob = await sealContentBlob(first, BLOB_A, plaintext);
    // 12-byte nonce + plaintext + 16-byte tag, and nothing else: the size is known before encrypting.
    expect(blob.length).toBe(AEAD_NONCE_BYTES + plaintext.length + 16);
    expect(splitBlob(blob).nonce.length).toBe(AEAD_NONCE_BYTES);
  });

  it("never repeats a nonce across blobs sealed with the same key", async () => {
    const { first } = await world();
    const nonces = new Set<string>();
    for (let i = 0; i < 64; i++) nonces.add(toHex(splitBlob(await sealContentBlob(first, BLOB_A, bytes(i))).nonce));
    expect(nonces.size).toBe(64);
  });

  it("does not open under another blob id (the AAD and the key both name it)", async () => {
    const { first } = await world();
    const blob = await sealContentBlob(first, BLOB_A, bytes(1, 2, 3));
    await expect(openContentBlob(first, BLOB_B, blob)).rejects.toBeInstanceOf(CryptoError);
  });

  it("does not open under another epoch of the same vault", async () => {
    const { first, second } = await world();
    const blob = await sealContentBlob(first, BLOB_A, bytes(1, 2, 3));
    await expect(openContentBlob(second, BLOB_A, blob)).rejects.toBeInstanceOf(CryptoError);
  });

  it("does not open when a single ciphertext byte is flipped", async () => {
    const { first } = await world();
    const blob = await sealContentBlob(first, BLOB_A, bytes(1, 2, 3));
    for (const index of [0, AEAD_NONCE_BYTES, blob.length - 1]) {
      await expect(openContentBlob(first, BLOB_A, flipByte(blob, index))).rejects.toBeInstanceOf(CryptoError);
    }
  });

  it("does not open under the wrong AAD, even with the right key and nonce", async () => {
    const { first } = await world();
    const key = await deriveContentKey(first, BLOB_A);
    // The AAD of §31.3 names the vault: one built for another vault must fail under the same key.
    const wrong = await seal(key, contentBlobAad(filled(16, 0x99), first.epochId, BLOB_A), bytes(4, 5));
    await expect(openContentBlob(first, BLOB_A, wrong)).rejects.toBeInstanceOf(CryptoError);
  });
});

describe("manifest blobs (§31.3)", () => {
  it("round-trips under its own revision binding", async () => {
    const { first } = await world();
    const plaintext = bytes(9, 9, 9, 0);
    const blob = await sealManifestBlob(first, BLOB_A, binding, plaintext);
    expect(await openManifestBlob(first, BLOB_A, binding, blob)).toEqual(plaintext);
  });

  it("accepts a null parent_revision_id and binds to it", async () => {
    const { first } = await world();
    const created: ManifestBinding = { ...binding, parentRevisionId: null };
    const blob = await sealManifestBlob(first, BLOB_A, created, bytes(1));
    expect(await openManifestBlob(first, BLOB_A, created, blob)).toEqual(bytes(1));
    await expect(openManifestBlob(first, BLOB_A, binding, blob)).rejects.toBeInstanceOf(CryptoError);
  });

  it("rejects every single-field change of the binding", async () => {
    const { first } = await world();
    const blob = await sealManifestBlob(first, BLOB_A, binding, bytes(1, 2));
    const wrong: ManifestBinding[] = [
      { ...binding, objectId: filled(16, 0xee) },
      { ...binding, revisionId: filled(16, 0xee) },
      { ...binding, parentRevisionId: filled(16, 0xee) },
      { ...binding, parentRevisionId: null },
    ];
    for (const b of wrong) await expect(openManifestBlob(first, BLOB_A, b, blob)).rejects.toBeInstanceOf(CryptoError);
  });

  it("is not openable as a content blob and vice versa (different key and AAD)", async () => {
    const { first } = await world();
    const manifest = await sealManifestBlob(first, BLOB_A, binding, bytes(1));
    const content = await sealContentBlob(first, BLOB_A, bytes(1));
    await expect(openContentBlob(first, BLOB_A, manifest)).rejects.toBeInstanceOf(CryptoError);
    await expect(openManifestBlob(first, BLOB_A, binding, content)).rejects.toBeInstanceOf(CryptoError);
  });
});

describe("content fingerprint (§31.4)", () => {
  it("is 32 bytes and deterministic for the same plaintext and epoch", async () => {
    const { first } = await world();
    const a = await contentFingerprint(first, bytes(1, 2, 3));
    const b = await contentFingerprint(first, bytes(1, 2, 3));
    expect(a.length).toBe(32);
    expect(toHex(a)).toBe(toHex(b));
  });

  it("does not depend on the blob id: the same bytes dedup within the epoch", async () => {
    const { first } = await world();
    // §31.4 takes the plaintext and the epoch's dedup key, nothing else — that IS the dedup scope.
    const a = await contentFingerprint(first, filled(100, 0x7));
    const b = await contentFingerprint(first, filled(100, 0x7));
    expect(toHex(a)).toBe(toHex(b));
  });

  it("differs between epochs of the same vault: no dedup across epochs", async () => {
    const { first, second } = await world();
    const a = await contentFingerprint(first, bytes(1, 2, 3));
    const b = await contentFingerprint(second, bytes(1, 2, 3));
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it("differs for different plaintexts", async () => {
    const { first } = await world();
    const a = await contentFingerprint(first, bytes(1, 2, 3));
    const b = await contentFingerprint(first, bytes(1, 2, 4));
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

// ------------------------------------------------------------------------------------------------
// Broken variants. Each one is a plausible implementation that this suite's own assertions catch.

describe("broken variants are caught", () => {
  it("(a) a crypto that ignores the AAD lets a manifest open under the wrong revision", async () => {
    const { first } = await world();
    // The variant: same per-blob manifest key, but the §31.3 AAD is dropped. It is a perfectly
    // working AEAD — which is the point: only a test that changes the binding can tell them apart.
    const key = await deriveManifestKey(first, BLOB_A);
    const empty = new Uint8Array(0);
    const variantSeal = async (_binding: ManifestBinding, plaintext: Uint8Array) => {
      const nonce = crypto.getRandomValues(new Uint8Array(AEAD_NONCE_BYTES));
      const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as Uint8Array<ArrayBuffer>, additionalData: empty }, key, plaintext as Uint8Array<ArrayBuffer>));
      const out = new Uint8Array(nonce.length + sealed.length);
      out.set(nonce);
      out.set(sealed, nonce.length);
      return out;
    };
    const variantOpen = async (_binding: ManifestBinding, blob: Uint8Array) =>
      new Uint8Array(
        await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: blob.subarray(0, AEAD_NONCE_BYTES) as Uint8Array<ArrayBuffer>, additionalData: empty },
          key,
          blob.subarray(AEAD_NONCE_BYTES) as Uint8Array<ArrayBuffer>,
        ),
      );

    const elsewhere: ManifestBinding = { ...binding, revisionId: filled(16, 0xee) };
    const payload = bytes(1, 2);

    // The variant hands the manifest over under a revision it was never sealed for.
    expect(await variantOpen(elsewhere, await variantSeal(binding, payload))).toEqual(payload);
    // The real implementation refuses the same move.
    await expect(openManifestBlob(first, BLOB_A, elsewhere, await sealManifestBlob(first, BLOB_A, binding, payload))).rejects.toBeInstanceOf(CryptoError);
  });

  it("(b) a crypto that reuses one nonce across blobs is caught by the nonce-uniqueness assertion", async () => {
    const { first } = await world();
    const key = await deriveContentKey(first, BLOB_A);
    const fixed = filled(AEAD_NONCE_BYTES, 0x5a);
    const sealReusingNonce = async (plaintext: Uint8Array) => {
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: fixed as Uint8Array<ArrayBuffer>, additionalData: contentBlobAad(first.vaultId, first.epochId, BLOB_A) as Uint8Array<ArrayBuffer> },
          key,
          plaintext as Uint8Array<ArrayBuffer>,
        ),
      );
      const out = new Uint8Array(AEAD_NONCE_BYTES + ciphertext.length);
      out.set(fixed);
      out.set(ciphertext, AEAD_NONCE_BYTES);
      return out;
    };
    const variant = new Set<string>();
    for (let i = 0; i < 8; i++) variant.add(toHex(splitBlob(await sealReusingNonce(bytes(i))).nonce));
    expect(variant.size).toBe(1); // the variant repeats it…

    const real = new Set<string>();
    for (let i = 0; i < 8; i++) real.add(toHex(splitBlob(await sealContentBlob(first, BLOB_A, bytes(i))).nonce));
    expect(real.size).toBe(8); // …and the real one never does.

    // The catastrophe the reuse enables, shown rather than asserted about: with one nonce and one
    // key, the XOR of two ciphertexts is the XOR of the two plaintexts.
    const one = (await sealReusingNonce(bytes(0xaa, 0xbb))).subarray(AEAD_NONCE_BYTES, AEAD_NONCE_BYTES + 2);
    const two = (await sealReusingNonce(bytes(0x00, 0x00))).subarray(AEAD_NONCE_BYTES, AEAD_NONCE_BYTES + 2);
    expect([...one].map((b, i) => b ^ (two[i] as number))).toEqual([0xaa, 0xbb]);
  });

  it("(c) a fingerprint that ignores the epoch dedups across epochs", async () => {
    const { first, second } = await world();
    const ignoringEpoch = async (plaintext: Uint8Array) =>
      toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", plaintext as Uint8Array<ArrayBuffer>)));
    expect(await ignoringEpoch(bytes(1))).toBe(await ignoringEpoch(bytes(1))); // same across epochs
    expect(toHex(await contentFingerprint(first, bytes(1)))).not.toBe(toHex(await contentFingerprint(second, bytes(1))));
  });
});

describe("importAeadKey is not a way around the per-blob key", () => {
  it("a key imported from raw bytes cannot open a blob sealed under a derived key", async () => {
    const { first } = await world();
    const blob = await sealContentBlob(first, BLOB_A, bytes(1));
    const foreign = await importAeadKey(filled(32, 0x11));
    await expect(
      (async () => {
        const aad = contentBlobAad(first.vaultId, first.epochId, BLOB_A);
        return crypto.subtle.decrypt(
          { name: "AES-GCM", iv: blob.subarray(0, AEAD_NONCE_BYTES) as Uint8Array<ArrayBuffer>, additionalData: aad as Uint8Array<ArrayBuffer> },
          foreign,
          blob.subarray(AEAD_NONCE_BYTES) as Uint8Array<ArrayBuffer>,
        );
      })(),
    ).rejects.toBeTruthy();
  });
});

describe("the AAD contexts themselves", () => {
  it("are different bytes for content and manifest, even with the same ids", async () => {
    const c = contentBlobAad(filled(16, 1), filled(16, 2), filled(16, 3));
    const m = manifestBlobAad(filled(16, 1), filled(16, 2), filled(16, 3), binding);
    expect(toHex(c)).not.toBe(toHex(m));
  });
});
