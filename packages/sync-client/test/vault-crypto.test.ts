import { type EpochWorld, makeEpoch, makeWorld } from "@nodra/key-lifecycle/test-support/epoch";
import { filled, flipByte } from "@nodra/key-lifecycle/test-support/bytes";
import type { CreatedEpoch } from "@nodra/key-lifecycle";
import { idKey, rootRecipientId } from "@nodra/key-lifecycle";
import type { EpochDescriptor, EpochEnvelope } from "@nodra/encoding/records";
import { beforeAll, describe, expect, it } from "vitest";
import { bytesToUuid } from "../src/manifest.js";
import type { ManifestBinding } from "../src/ports.js";
import { type EpochDirectory, VaultCryptoError, epochAccess, vaultCrypto } from "../src/vault-crypto.js";

// The real VaultCrypto on the sync path: §31.3 blobs, §31.4 fingerprints, §32 chain and envelopes,
// §34 coverage and the §9 check on the way down.
//
// The world is one account, one root generation, one registry and a vault with two chained epochs —
// the fixture the §31–§34 suites already use. Every negative case breaks exactly one thing in it.

const OBJECT = "0190a1b2-0000-7000-8000-00000000a001";
const REVISION = "0190a1b2-0000-7000-8000-00000000b001";
const PARENT = "0190a1b2-0000-7000-8000-00000000b000";
const BLOB_A = "0190a1b2-0000-7000-8000-0000000000a1";
const BLOB_B = "0190a1b2-0000-7000-8000-0000000000a2";

const binding: ManifestBinding = { objectId: OBJECT, revisionId: REVISION, parentRevisionId: PARENT };

interface Fixture {
  readonly world: EpochWorld;
  readonly vaultId: string;
  readonly first: CreatedEpoch;
  readonly second: CreatedEpoch;
  /** The recipient this test client is: a registry PLUGIN_INSTALLATION with a private key. */
  readonly me: { recipientId: Uint8Array; type: "PLUGIN_INSTALLATION" };
}

let fixture: Fixture;

beforeAll(async () => {
  const world = await makeWorld();
  const first = await makeEpoch(world, 0x41, null);
  const second = await makeEpoch(world, 0x42, first);
  fixture = { world, vaultId: bytesToUuid(world.vaultId), first, second, me: { recipientId: filled(16, 0x31), type: "PLUGIN_INSTALLATION" } };
});

/** A directory serving exactly these epochs, counting how often it was asked. */
function directory(epochs: readonly CreatedEpoch[], omitEnvelopesOf: readonly CreatedEpoch[] = []) {
  const omitted = new Set(omitEnvelopesOf.map((e) => idKey(e.descriptor.epoch_id)));
  const calls = { count: 0 };
  const dir: EpochDirectory = {
    async list() {
      calls.count++;
      const descriptors: EpochDescriptor[] = epochs.map((e) => e.descriptor);
      const envelopes: EpochEnvelope[] = epochs.filter((e) => !omitted.has(idKey(e.descriptor.epoch_id))).flatMap((e) => [...e.envelopes]);
      return { descriptors, envelopes };
    },
  };
  return { dir, calls };
}

function accessTo(epochs: readonly CreatedEpoch[], omit: readonly CreatedEpoch[] = []) {
  const { dir, calls } = directory(epochs, omit);
  const world = fixture.world;
  const access = epochAccess({
    vaultId: fixture.vaultId,
    directory: dir,
    recipient: fixture.me,
    privateKey: world.privateKeys.get(idKey(fixture.me.recipientId))!,
    ...proofs(world),
  });
  return { access, calls, crypto: vaultCrypto(access) };
}

const epochOf = (e: CreatedEpoch) => bytesToUuid(e.descriptor.epoch_id);

/** The verifier inputs of the world, WITHOUT its `vaultId`: here the vault travels as a uuid string. */
const proofs = (world: EpochWorld) => ({
  accountSigningKeys: world.accountSigningKeys,
  rootHashes: world.rootHashes,
  rootCryptoVersions: world.rootCryptoVersions,
  registryHashes: world.registryHashes,
});

const failureOf = async (p: Promise<unknown>) => {
  try {
    await p;
    return null;
  } catch (e) {
    return e instanceof VaultCryptoError ? e.code : `not a VaultCryptoError: ${String(e)}`;
  }
};

describe("sealing and opening on the real path (§31.3)", () => {
  it("round-trips content byte for byte, text and binary alike", async () => {
    const { crypto } = accessTo([fixture.first]);
    const epochId = epochOf(fixture.first);
    const payloads = [
      new Uint8Array(0),
      new TextEncoder().encode("# a note\n\nwith text\n"),
      // Invalid UTF-8, a NUL, a BOM and every byte value: an attachment (§2.1).
      Uint8Array.from([0xef, 0xbb, 0xbf, 0, 0xff, 0xc3, 0x28, ...Array.from({ length: 256 }, (_, i) => i)]),
      filled(200_000, 0x5a),
    ];
    for (const payload of payloads) {
      const sealed = await crypto.encryptBlob({ epochId, blobId: BLOB_A, kind: "CONTENT", payload });
      expect(await crypto.open({ epochId, blobId: BLOB_A, kind: "CONTENT", ciphertext: sealed.ciphertext })).toEqual(payload);
      // §11.1: the declared size is exact and known before encrypting (§31.3 framing).
      expect(sealed.declaredSize).toBe(sealed.ciphertext.byteLength);
      expect(crypto.declaredSize(payload)).toBe(sealed.ciphertext.byteLength);
    }
  });

  it("round-trips a §8 manifest and refuses it under any other revision (§31.3 AAD)", async () => {
    const { crypto } = accessTo([fixture.first]);
    const epochId = epochOf(fixture.first);
    const payload = crypto.encodeManifest({
      ...binding,
      path: "notes/a.md",
      mtimeMs: 1_700_000_000_000,
      deleted: false,
      content: { blobId: BLOB_B, epochId, fingerprint: "ab".repeat(32), plaintextSize: 3 },
    });
    const sealed = await crypto.encryptBlob({ epochId, blobId: BLOB_A, kind: "MANIFEST", payload, binding });
    const opened = crypto.decodeManifest(await crypto.open({ epochId, blobId: BLOB_A, kind: "MANIFEST", ciphertext: sealed.ciphertext, binding }));
    expect(opened).toEqual({
      ...binding,
      path: "notes/a.md",
      mtimeMs: 1_700_000_000_000,
      deleted: false,
      content: { blobId: BLOB_B, epochId, fingerprint: "ab".repeat(32), plaintextSize: 3 },
    });

    for (const wrong of [
      { ...binding, objectId: BLOB_B },
      { ...binding, revisionId: BLOB_B },
      { ...binding, parentRevisionId: null },
    ]) {
      expect(await failureOf(crypto.open({ epochId, blobId: BLOB_A, kind: "MANIFEST", ciphertext: sealed.ciphertext, binding: wrong }))).toBe("CORRUPTION_OR_MISBINDING");
    }
  });

  it("refuses a blob under the wrong blob id, the wrong epoch, or with one byte flipped", async () => {
    const { crypto } = accessTo([fixture.first, fixture.second]);
    const epochId = epochOf(fixture.first);
    const payload = new TextEncoder().encode("secret");
    const { ciphertext } = await crypto.encryptBlob({ epochId, blobId: BLOB_A, kind: "CONTENT", payload });

    expect(await failureOf(crypto.open({ epochId, blobId: BLOB_B, kind: "CONTENT", ciphertext }))).toBe("CORRUPTION_OR_MISBINDING");
    expect(await failureOf(crypto.open({ epochId: epochOf(fixture.second), blobId: BLOB_A, kind: "CONTENT", ciphertext }))).toBe("CORRUPTION_OR_MISBINDING");
    for (const index of [0, 12, ciphertext.length - 1]) {
      expect(await failureOf(crypto.open({ epochId, blobId: BLOB_A, kind: "CONTENT", ciphertext: flipByte(ciphertext, index) }))).toBe("CORRUPTION_OR_MISBINDING");
    }
  });

  it("a manifest sealed without its binding is refused before any crypto runs", async () => {
    const { crypto } = accessTo([fixture.first]);
    const epochId = epochOf(fixture.first);
    expect(await failureOf(crypto.encryptBlob({ epochId, blobId: BLOB_A, kind: "MANIFEST", payload: new Uint8Array(1) }))).toBe("MISSING_MANIFEST_BINDING");
  });

  it("never reuses a nonce and never produces the same ciphertext twice for the same plaintext", async () => {
    const { crypto } = accessTo([fixture.first]);
    const epochId = epochOf(fixture.first);
    const payload = new TextEncoder().encode("same bytes");
    const nonces = new Set<string>();
    for (let i = 0; i < 32; i++) {
      const { ciphertext } = await crypto.encryptBlob({ epochId, blobId: BLOB_A, kind: "CONTENT", payload });
      nonces.add([...ciphertext.subarray(0, 12)].join(","));
    }
    expect(nonces.size).toBe(32);
  });
});

describe("content fingerprints (§31.4) and the §9 check", () => {
  it("the same bytes under the same epoch give the same fingerprint; another epoch gives another", async () => {
    const { crypto } = accessTo([fixture.first, fixture.second]);
    const payload = new TextEncoder().encode("dedup me");
    const a = await crypto.encryptBlob({ epochId: epochOf(fixture.first), blobId: BLOB_A, kind: "CONTENT", payload });
    const b = await crypto.encryptBlob({ epochId: epochOf(fixture.first), blobId: BLOB_B, kind: "CONTENT", payload });
    const c = await crypto.encryptBlob({ epochId: epochOf(fixture.second), blobId: BLOB_A, kind: "CONTENT", payload });
    expect(a.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(b.fingerprint).toBe(a.fingerprint); // dedup scope is vault + epoch, never the blob id
    expect(c.fingerprint).not.toBe(a.fingerprint); // …and never across epochs
  });

  it("a manifest blob carries no fingerprint (§31.4 is about content)", async () => {
    const { crypto } = accessTo([fixture.first]);
    const epochId = epochOf(fixture.first);
    const sealed = await crypto.encryptBlob({ epochId, blobId: BLOB_A, kind: "MANIFEST", payload: new Uint8Array([1]), binding });
    expect(sealed.fingerprint).toBeUndefined();
  });

  it("§9: a content blob whose fingerprint is not the manifest's is refused, and nothing comes back", async () => {
    const { crypto } = accessTo([fixture.first]);
    const epochId = epochOf(fixture.first);
    const payload = new TextEncoder().encode("hello");
    const sealed = await crypto.encryptBlob({ epochId, blobId: BLOB_A, kind: "CONTENT", payload });
    // The right blob under its right fingerprint opens.
    expect(await crypto.open({ epochId, blobId: BLOB_A, kind: "CONTENT", ciphertext: sealed.ciphertext, expectFingerprint: sealed.fingerprint! })).toEqual(payload);
    // A manifest claiming another content's fingerprint does not.
    const other = await crypto.encryptBlob({ epochId, blobId: BLOB_B, kind: "CONTENT", payload: new TextEncoder().encode("other") });
    expect(await failureOf(crypto.open({ epochId, blobId: BLOB_A, kind: "CONTENT", ciphertext: sealed.ciphertext, expectFingerprint: other.fingerprint! }))).toBe("CORRUPTION_OR_MISBINDING");
  });
});

describe("epoch selection, rotation and coverage", () => {
  it("a revision written under an older epoch is still readable after a rotation", async () => {
    const { crypto } = accessTo([fixture.first, fixture.second]);
    const old = epochOf(fixture.first);
    const payload = new TextEncoder().encode("written before the rotation");
    const sealed = await crypto.encryptBlob({ epochId: old, blobId: BLOB_A, kind: "CONTENT", payload });
    // The write epoch has moved on; the read still names the epoch the blob was written under (§8).
    const fresh = await crypto.encryptBlob({ epochId: epochOf(fixture.second), blobId: BLOB_B, kind: "CONTENT", payload });
    expect(await crypto.open({ epochId: old, blobId: BLOB_A, kind: "CONTENT", ciphertext: sealed.ciphertext, expectFingerprint: sealed.fingerprint! })).toEqual(payload);
    expect(await crypto.open({ epochId: epochOf(fixture.second), blobId: BLOB_B, kind: "CONTENT", ciphertext: fresh.ciphertext })).toEqual(payload);
  });

  it("an epoch this process has not seen makes it ask the directory once more, and only once per unknown id", async () => {
    // The directory starts by serving only the first epoch, then the rotation lands.
    let epochs: readonly CreatedEpoch[] = [fixture.first];
    const calls = { count: 0 };
    const dir: EpochDirectory = {
      async list() {
        calls.count++;
        return { descriptors: epochs.map((e) => e.descriptor), envelopes: epochs.flatMap((e) => [...e.envelopes]) };
      },
    };
    const access = epochAccess({
      vaultId: fixture.vaultId,
      directory: dir,
      recipient: fixture.me,
      privateKey: fixture.world.privateKeys.get(idKey(fixture.me.recipientId))!,
      ...proofs(fixture.world),
    });
    const crypto = vaultCrypto(access);
    const payload = new TextEncoder().encode("x");

    await crypto.encryptBlob({ epochId: epochOf(fixture.first), blobId: BLOB_A, kind: "CONTENT", payload });
    expect(calls.count).toBe(1);
    // The write epoch rotated (EPOCH_STALE → the runner learns the new one and re-seals).
    epochs = [fixture.first, fixture.second];
    await crypto.encryptBlob({ epochId: epochOf(fixture.second), blobId: BLOB_B, kind: "CONTENT", payload });
    expect(calls.count).toBe(2);
    // The key is cached: sealing again under either epoch asks nobody.
    await crypto.encryptBlob({ epochId: epochOf(fixture.second), blobId: BLOB_A, kind: "CONTENT", payload });
    await crypto.encryptBlob({ epochId: epochOf(fixture.first), blobId: BLOB_B, kind: "CONTENT", payload });
    expect(calls.count).toBe(2);
  });

  it("§34: a replica with no envelope for an epoch refuses to write under it, typed, instead of writing unreadable content", async () => {
    // The chain has both epochs; the coverage of the second one is missing for this recipient.
    const { crypto } = accessTo([fixture.first, fixture.second], [fixture.second]);
    const payload = new TextEncoder().encode("must not be sealed");
    expect(await failureOf(crypto.encryptBlob({ epochId: epochOf(fixture.second), blobId: BLOB_A, kind: "CONTENT", payload }))).toBe("EPOCH_NOT_COVERED");
    // Reading an old revision still works: the gap is per epoch, not per vault.
    const sealed = await crypto.encryptBlob({ epochId: epochOf(fixture.first), blobId: BLOB_A, kind: "CONTENT", payload });
    expect(await crypto.open({ epochId: epochOf(fixture.first), blobId: BLOB_A, kind: "CONTENT", ciphertext: sealed.ciphertext })).toEqual(payload);
  });

  it("a coverage gap that a §35 operation closes becomes readable without a new client", async () => {
    let covered: readonly CreatedEpoch[] = [fixture.first];
    const dir: EpochDirectory = {
      async list() {
        return { descriptors: [fixture.first.descriptor, fixture.second.descriptor], envelopes: covered.flatMap((e) => [...e.envelopes]) };
      },
    };
    const access = epochAccess({
      vaultId: fixture.vaultId,
      directory: dir,
      recipient: fixture.me,
      privateKey: fixture.world.privateKeys.get(idKey(fixture.me.recipientId))!,
      ...proofs(fixture.world),
    });
    const crypto = vaultCrypto(access);
    expect(await failureOf(crypto.encryptBlob({ epochId: epochOf(fixture.second), blobId: BLOB_A, kind: "CONTENT", payload: new Uint8Array(1) }))).toBe("EPOCH_NOT_COVERED");
    covered = [fixture.first, fixture.second];
    // The failed open was not cached, so the next attempt asks again and now succeeds.
    expect(await failureOf(crypto.encryptBlob({ epochId: epochOf(fixture.second), blobId: BLOB_A, kind: "CONTENT", payload: new Uint8Array(1) }))).toBeNull();
  });

  it("an epoch id the chain does not contain at all is EPOCH_UNKNOWN, not a guess", async () => {
    const { crypto } = accessTo([fixture.first]);
    expect(await failureOf(crypto.encryptBlob({ epochId: "0190a1b2-0000-7000-8000-0000000000ff", blobId: BLOB_A, kind: "CONTENT", payload: new Uint8Array(1) }))).toBe("EPOCH_UNKNOWN");
  });
});

describe("the chain and the envelopes are proved, never believed (§32)", () => {
  it("a descriptor signed by a key of no root generation is rejected", async () => {
    const forged = await makeEpoch(fixture.world, 0x51, null, { signingKey: fixture.world.stranger.privateKey });
    const { dir } = directory([forged]);
    const access = epochAccess({
      vaultId: fixture.vaultId,
      directory: dir,
      recipient: fixture.me,
      privateKey: fixture.world.privateKeys.get(idKey(fixture.me.recipientId))!,
      ...proofs(fixture.world),
    });
    expect(await failureOf(access.epochKey(epochOf(forged)))).toBe("EPOCH_CHAIN_INVALID");
  });

  it("an envelope addressed to another recipient is not used, even with a valid chain", async () => {
    const { dir } = directory([fixture.first]);
    const stranger = await rootRecipientId(new Uint8Array(32)); // a recipient id nobody holds
    const access = epochAccess({
      vaultId: fixture.vaultId,
      directory: dir,
      recipient: { recipientId: stranger, type: "PLUGIN_INSTALLATION" },
      privateKey: fixture.world.privateKeys.get(idKey(fixture.me.recipientId))!,
      ...proofs(fixture.world),
    });
    // §32.3 builds the label from the client's own identity: there is simply no envelope for it.
    expect(await failureOf(access.epochKey(epochOf(fixture.first)))).toBe("EPOCH_NOT_COVERED");
  });

  it("an envelope this recipient cannot unwrap is BROKEN_OR_WRONG_ENVELOPE, and the key is not used", async () => {
    // The envelope of recipient 0x31, opened with the private key of recipient 0x32.
    const other = filled(16, 0x32);
    const { dir } = directory([fixture.first]);
    const access = epochAccess({
      vaultId: fixture.vaultId,
      directory: dir,
      recipient: { recipientId: fixture.me.recipientId, type: "PLUGIN_INSTALLATION" },
      privateKey: fixture.world.privateKeys.get(idKey(other))!,
      ...proofs(fixture.world),
    });
    expect(await failureOf(access.epochKey(epochOf(fixture.first)))).toBe("BROKEN_OR_WRONG_ENVELOPE");
  });

  it("the proved chain is available for the §32.1 pin", async () => {
    const { access } = accessTo([fixture.first, fixture.second]);
    expect(access.chain()).toBeNull();
    await access.epochKey(epochOf(fixture.second));
    expect(access.chain()?.epochIds.map(idKey)).toEqual([fixture.first, fixture.second].map((e) => idKey(e.descriptor.epoch_id)));
  });
});
