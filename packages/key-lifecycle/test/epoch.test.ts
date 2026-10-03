// §31–§33: creating an epoch, opening its envelopes, and the keys an Epoch Key derives.
import { beforeAll, describe, expect, it } from "vitest";
import {
  AEAD_NONCE_BYTES,
  hmacSha256,
  importEnvelopePublicKey,
  sealEpochSecret,
  seal,
  timingSafeEqual,
  unseal,
} from "@nodra/crypto";
import { EPOCH_DESCRIPTOR } from "@nodra/encoding/records";
import type { EpochEnvelope } from "@nodra/encoding/records";
import { envelopeLabelContext, epochCommitmentInfo } from "../src/contexts.js";
import {
  ENVELOPE_ALGORITHM_VERSION,
  deriveContentKey,
  deriveDedupKey,
  deriveManifestKey,
  envelopeSetHash,
  epochRecipients,
  idKey,
  openEpoch,
  rootRecipientId,
  sealEnvelope,
} from "../src/epoch.js";
import type { CreatedEpoch, EnvelopeRecipient } from "../src/epoch.js";
import { verifyEpochChain } from "../src/epoch-chain.js";
import { checkCoverage, requiredEpochSet } from "../src/coverage.js";
import { chainOptions, makeEpoch, makeWorld, resignDescriptor } from "./epoch-support.js";
import type { EpochWorld } from "./epoch-support.js";
import { filled } from "./support.js";
import { mutateRecord } from "./chain-support.js";

let world: EpochWorld;
let epoch: CreatedEpoch;

beforeAll(async () => {
  world = await makeWorld();
  epoch = await makeEpoch(world, 0x41, null);
});

function envelopeFor(recipient: EnvelopeRecipient, created = epoch): EpochEnvelope {
  const found = created.envelopes.find((envelope) => timingSafeEqual(envelope.recipient_id, recipient.recipientId));
  if (found === undefined) throw new Error("no envelope for that recipient");
  return found;
}

describe("creating an epoch (§36.1, §32)", () => {
  it("seals one envelope per recipient of the pending root and registry (§36.1 step 2)", () => {
    expect(epoch.envelopes).toHaveLength(world.recipients.length);
    expect(world.recipients.map((r) => r.type)).toEqual([
      "ACCOUNT",
      "RECOVERY",
      "PLUGIN_INSTALLATION",
      "TRUSTED_BROWSER",
    ]);
    for (const envelope of epoch.envelopes) {
      expect(envelope.algorithm_version).toBe(ENVELOPE_ALGORITHM_VERSION);
      expect(timingSafeEqual(envelope.vault_id, world.vaultId)).toBe(true);
      expect(timingSafeEqual(envelope.epoch_id, epoch.descriptor.epoch_id)).toBe(true);
    }
  });

  it("leaves a REVOKED recipient out (§29, §36.1)", async () => {
    const ids = epoch.envelopes.map((envelope) => idKey(envelope.recipient_id));
    expect(ids).not.toContain(idKey(world.revoked.recipientId));
    // ...and it is not even offered: `epochRecipients` filters on the registry's status.
    const offered = await epochRecipients(world.root, world.registry);
    expect(offered.map((r) => idKey(r.recipientId))).not.toContain(idKey(world.revoked.recipientId));
  });

  it("gives the two root recipients the ids §30.1 defines", async () => {
    expect(idKey(world.recipients[0]?.recipientId as Uint8Array)).toBe(
      idKey(await rootRecipientId(world.root.account_encryption_public_key)),
    );
    expect(idKey(world.recipients[1]?.recipientId as Uint8Array)).toBe(
      idKey(await rootRecipientId(world.root.recovery_encryption_public_key)),
    );
  });

  it("stamps the pending root's crypto_version on the descriptor (§32.1)", async () => {
    for (const cryptoVersion of [1, 2]) {
      const created = await makeEpoch(world, 0x61, null, { root: { generation: 1, hash: world.rootHash, cryptoVersion } });
      expect(created.descriptor.crypto_version).toBe(cryptoVersion);
    }
  });

  it("produces a descriptor that verifies and covers its own envelope set (§32.1)", async () => {
    const verified = await verifyEpochChain([epoch.descriptor], chainOptions(world));
    expect(verified.ok).toBe(true);
    const recomputed = await envelopeSetHash(world.vaultId, epoch.descriptor.epoch_id, epoch.envelopes);
    expect(timingSafeEqual(recomputed, epoch.descriptor.envelope_set_hash)).toBe(true);
  });

  it("hashes the envelope set independently of the array order, and not of its membership", async () => {
    const reversed = [...epoch.envelopes].reverse();
    const same = await envelopeSetHash(world.vaultId, epoch.descriptor.epoch_id, reversed);
    expect(timingSafeEqual(same, epoch.descriptor.envelope_set_hash)).toBe(true);

    const fewer = await envelopeSetHash(world.vaultId, epoch.descriptor.epoch_id, epoch.envelopes.slice(1));
    expect(timingSafeEqual(fewer, epoch.descriptor.envelope_set_hash)).toBe(false);
  });

  it("binds the envelope set to its vault and epoch", async () => {
    const elsewhere = await envelopeSetHash(filled(16, 0x99), epoch.descriptor.epoch_id, epoch.envelopes);
    expect(timingSafeEqual(elsewhere, epoch.descriptor.envelope_set_hash)).toBe(false);
  });
});

describe("opening an envelope (§32.3, §33.1)", () => {
  it("every recipient opens exactly its own envelope", async () => {
    for (const recipient of world.recipients) {
      const opened = await openEpoch({
        descriptor: epoch.descriptor,
        envelope: envelopeFor(recipient),
        recipient,
        privateKey: world.privateKeys.get(idKey(recipient.recipientId)) as never,
      });
      expect(opened.ok).toBe(true);
    }
  });

  it("all recipients reach the same Epoch Key: one seals, another opens and decrypts", async () => {
    const [account, , plugin] = world.recipients as readonly EnvelopeRecipient[];
    const a = await openEpoch({
      descriptor: epoch.descriptor,
      envelope: envelopeFor(account as EnvelopeRecipient),
      recipient: account as EnvelopeRecipient,
      privateKey: world.privateKeys.get(idKey((account as EnvelopeRecipient).recipientId)) as never,
    });
    const b = await openEpoch({
      descriptor: epoch.descriptor,
      envelope: envelopeFor(plugin as EnvelopeRecipient),
      recipient: plugin as EnvelopeRecipient,
      privateKey: world.privateKeys.get(idKey((plugin as EnvelopeRecipient).recipientId)) as never,
    });
    if (!a.ok || !b.ok) throw new Error("both opens must succeed");

    const blobId = filled(16, 0x77);
    const blob = await seal(await deriveContentKey(a.value, blobId), epochCommitmentInfo(world.vaultId, epoch.descriptor.epoch_id), new Uint8Array([1, 2, 3]));
    const back = await unseal(await deriveContentKey(b.value, blobId), epochCommitmentInfo(world.vaultId, epoch.descriptor.epoch_id), blob);
    expect(Array.from(back)).toEqual([1, 2, 3]);
    expect(blob.length).toBeGreaterThan(AEAD_NONCE_BYTES);
  });

  it("rejects an envelope addressed to another recipient (ENVELOPE_MISBOUND)", async () => {
    const [account, , plugin] = world.recipients as readonly EnvelopeRecipient[];
    const opened = await openEpoch({
      descriptor: epoch.descriptor,
      envelope: envelopeFor(plugin as EnvelopeRecipient),
      recipient: account as EnvelopeRecipient,
      privateKey: world.privateKeys.get(idKey((account as EnvelopeRecipient).recipientId)) as never,
    });
    expect(opened.ok).toBe(false);
    if (!opened.ok) expect(opened.failure.code).toBe("ENVELOPE_MISBOUND");
  });

  it("rejects an envelope whose label binds another recipient, even when it claims to be ours", async () => {
    // A hostile server relabels the *fields* of an envelope sealed for someone else: the fields
    // now say "yours", the OAEP label inside still says "theirs". Only the label decides (§32.3).
    const [account, , plugin] = world.recipients as readonly EnvelopeRecipient[];
    const stolen: EpochEnvelope = {
      ...envelopeFor(plugin as EnvelopeRecipient),
      recipient_id: (account as EnvelopeRecipient).recipientId,
      recipient_type: "ACCOUNT",
    };
    const opened = await openEpoch({
      descriptor: epoch.descriptor,
      envelope: stolen,
      recipient: account as EnvelopeRecipient,
      privateKey: world.privateKeys.get(idKey((account as EnvelopeRecipient).recipientId)) as never,
    });
    expect(opened.ok).toBe(false);
    if (!opened.ok) expect(opened.failure.code).toBe("BROKEN_OR_WRONG_ENVELOPE");
  });

  it("rejects an envelope whose label binds another vault or epoch", async () => {
    const [account] = world.recipients as readonly EnvelopeRecipient[];
    const recipient = account as EnvelopeRecipient;
    const key = await importEnvelopePublicKey(recipient.publicKey);
    const secret = filled(32, 0x5a);
    for (const label of [
      envelopeLabelContext(filled(16, 0x99), epoch.descriptor.epoch_id, recipient.recipientId, recipient.type),
      envelopeLabelContext(world.vaultId, filled(16, 0x98), recipient.recipientId, recipient.type),
    ]) {
      const moved: EpochEnvelope = {
        ...envelopeFor(recipient),
        ciphertext: await sealEpochSecret(key, label, secret),
      };
      const opened = await openEpoch({
        descriptor: epoch.descriptor,
        envelope: moved,
        recipient,
        privateKey: world.privateKeys.get(idKey(recipient.recipientId)) as never,
      });
      expect(opened.ok).toBe(false);
      if (!opened.ok) expect(opened.failure.code).toBe("BROKEN_OR_WRONG_ENVELOPE");
    }
  });

  it("rejects a tampered ciphertext", async () => {
    const [account] = world.recipients as readonly EnvelopeRecipient[];
    const recipient = account as EnvelopeRecipient;
    const original = envelopeFor(recipient);
    const ciphertext = Uint8Array.from(original.ciphertext);
    ciphertext[7] = (ciphertext[7] as number) ^ 0x01;
    const opened = await openEpoch({
      descriptor: epoch.descriptor,
      envelope: { ...original, ciphertext },
      recipient,
      privateKey: world.privateKeys.get(idKey(recipient.recipientId)) as never,
    });
    expect(opened.ok).toBe(false);
    if (!opened.ok) expect(opened.failure.code).toBe("BROKEN_OR_WRONG_ENVELOPE");
  });

  it("rejects a good envelope against a descriptor with another commitment (§32.3 step 3)", async () => {
    // The whole point of the commitment: a *signed* descriptor whose epoch_commitment belongs to
    // another epoch must not be usable with this epoch's envelope.
    const other = await makeEpoch(world, 0x42, null);
    const swapped = await resignDescriptor(
      epoch.descriptor,
      { epoch_commitment: other.descriptor.epoch_commitment },
      world.signer,
    );
    const [account] = world.recipients as readonly EnvelopeRecipient[];
    const recipient = account as EnvelopeRecipient;
    const opened = await openEpoch({
      descriptor: swapped,
      envelope: envelopeFor(recipient),
      recipient,
      privateKey: world.privateKeys.get(idKey(recipient.recipientId)) as never,
    });
    expect(opened.ok).toBe(false);
    if (!opened.ok) expect(opened.failure.code).toBe("BROKEN_OR_WRONG_ENVELOPE");
  });

  it("rejects an unsupported algorithm_version", async () => {
    const [account] = world.recipients as readonly EnvelopeRecipient[];
    const recipient = account as EnvelopeRecipient;
    const opened = await openEpoch({
      descriptor: epoch.descriptor,
      envelope: { ...envelopeFor(recipient), algorithm_version: 2 },
      recipient,
      privateKey: world.privateKeys.get(idKey(recipient.recipientId)) as never,
    });
    expect(opened.ok).toBe(false);
    if (!opened.ok) expect(opened.failure.code).toBe("ENVELOPE_MISBOUND");
  });

  it("a revoked recipient's own key opens nothing in a later epoch", async () => {
    // Its envelope was never created, so there is nothing to present: the honest client holds an
    // envelope of an *older* epoch, whose label names that older epoch and therefore fails here.
    const revokedKey = world.privateKeys.get(idKey(world.revoked.recipientId));
    const forged = await sealEnvelope(world.revoked, world.vaultId, filled(16, 0x40), filled(32, 0x11));
    const opened = await openEpoch({
      descriptor: epoch.descriptor,
      envelope: { ...forged, epoch_id: epoch.descriptor.epoch_id },
      recipient: world.revoked,
      privateKey: revokedKey as never,
    });
    expect(opened.ok).toBe(false);
    if (!opened.ok) expect(opened.failure.code).toBe("BROKEN_OR_WRONG_ENVELOPE");
  });
});

describe("using an Epoch Key (§31.2)", () => {
  it("derives a different content, manifest and dedup key per blob and per epoch", async () => {
    const [account] = world.recipients as readonly EnvelopeRecipient[];
    const recipient = account as EnvelopeRecipient;
    const opened = await openEpoch({
      descriptor: epoch.descriptor,
      envelope: envelopeFor(recipient),
      recipient,
      privateKey: world.privateKeys.get(idKey(recipient.recipientId)) as never,
    });
    if (!opened.ok) throw new Error("open must succeed");
    const key = opened.value;

    const aad = epochCommitmentInfo(world.vaultId, epoch.descriptor.epoch_id);
    const blobA = filled(16, 0x01);
    const blobB = filled(16, 0x02);

    // Content and manifest keys of the same blob_id are different domains (§23.3).
    const contentBlob = await seal(await deriveContentKey(key, blobA), aad, new Uint8Array([9]));
    await expect(unseal(await deriveManifestKey(key, blobA), aad, contentBlob)).rejects.toThrow();
    // A different blob_id is a different key.
    await expect(unseal(await deriveContentKey(key, blobB), aad, contentBlob)).rejects.toThrow();

    // The dedup key is an HMAC key: same plaintext, same fingerprint, within this epoch (§31.4).
    const mac = await deriveDedupKey(key);
    const one = await hmacSha256(mac, new Uint8Array([7, 7]));
    const two = await hmacSha256(await deriveDedupKey(key), new Uint8Array([7, 7]));
    expect(timingSafeEqual(one, two)).toBe(true);
  });

  it("an epoch's commitment is the only public value that proves the key (§31.2)", async () => {
    const other = await makeEpoch(world, 0x43, null);
    expect(timingSafeEqual(other.descriptor.epoch_commitment, epoch.descriptor.epoch_commitment)).toBe(false);
  });
});

describe("an epoch's own coverage (§34)", () => {
  it("the created envelope set covers every recipient of the new epoch", () => {
    const required = requiredEpochSet([
      { vaultId: world.vaultId, state: "ACTIVE", epochs: [{ descriptor: epoch.descriptor, state: "ACTIVE" }] },
    ]);
    const result = checkCoverage({ required, recipients: world.recipients, envelopes: epoch.envelopes });
    expect(result.ok).toBe(true);
  });
});

describe("the descriptor codec still refuses non-canonical bytes", () => {
  it("a single flipped byte either fails to decode or changes the record", () => {
    const mutated = mutateRecord(EPOCH_DESCRIPTOR, epoch.descriptor, 11);
    if (mutated !== null) {
      expect(JSON.stringify(mutated)).not.toBe(JSON.stringify(epoch.descriptor));
    }
  });
});
