// §33.2: privileged re-enveloping, with real RSA and real HKDF throughout.
//
// The assertions that matter are the two §33.2 calls "obligatorias": the commitment check before
// sealing, and the round-trip of the new envelope afterwards. Each one has a broken variant that
// proves it detects what it exists to detect.
import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { checkCoverage, requiredEpochSet } from "../src/coverage.js";
import { deriveEpochCommitment, idKey, openEpoch } from "../src/epoch.js";
import { prepareEnrollment } from "../src/enrollment.js";
import { buildCoverage, proveEnvelope, reEnvelope } from "../src/re-envelope.js";
import { filled } from "./support.js";
import { envelopeFor, operationWorld, recoveryDecryptKey, strangerSpki, withDescriptor } from "./operations-support.js";

describe("§33.2 re-enveloping one epoch", () => {
  it("hands a new public key an envelope that opens to the same Epoch Key", async () => {
    const world = await operationWorld();
    const target = await prepareEnrollment({ recipientId: filled(16, 0x51), type: "TRUSTED_BROWSER", label: "new" });
    const source = world.sources[0]!;

    const created = await reEnvelope({
      source,
      sourceRecipient: world.account,
      openingKey: world.keys.operationKey,
      target: {
        recipientId: target.recipient.recipientId,
        type: target.recipient.type,
        publicKey: target.recipient.publicKey,
      },
    });
    expect(created.ok).toBe(true);
    if (!created.ok) return;

    // The new recipient opens it on the normal path of §33.1 and reproduces the commitment.
    const opened = await openEpoch({
      descriptor: source.descriptor,
      envelope: created.value,
      recipient: { recipientId: target.recipient.recipientId, type: target.recipient.type },
      privateKey: target.privateKey,
    });
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    const commitment = await deriveEpochCommitment(opened.value.key, source.descriptor.vault_id, source.descriptor.epoch_id);
    expect(Array.from(commitment)).toEqual(Array.from(source.descriptor.epoch_commitment));
  });

  it("refuses to re-envelope when the source commitment is not the descriptor's", async () => {
    const world = await operationWorld();
    const target = await prepareEnrollment({ recipientId: filled(16, 0x52), type: "TRUSTED_BROWSER", label: "new" });
    const source = world.sources[0]!;

    const created = await reEnvelope({
      source: {
        descriptor: withDescriptor(source.descriptor, { epoch_commitment: filled(32, 0xee) }),
        envelope: source.envelope,
      },
      sourceRecipient: world.account,
      openingKey: world.keys.operationKey,
      target: {
        recipientId: target.recipient.recipientId,
        type: target.recipient.type,
        publicKey: target.recipient.publicKey,
      },
    });
    expect(created.ok).toBe(false);
    if (created.ok) return;
    expect(created.failure.code).toBe("BROKEN_OR_WRONG_ENVELOPE");
  });

  it("rejects a source envelope that belongs to another epoch before any decryption", async () => {
    const world = await operationWorld();
    const [first, second] = [world.sources[0]!, world.sources[1]!];
    const created = await reEnvelope({
      // The descriptor of vault A with the envelope of vault B: §32.3's "moved envelope".
      source: { descriptor: first.descriptor, envelope: second.envelope },
      sourceRecipient: world.account,
      openingKey: world.keys.operationKey,
      target: { recipientId: filled(16, 0x53), type: "TRUSTED_BROWSER", publicKey: await strangerSpki() },
    });
    expect(created.ok).toBe(false);
    if (created.ok) return;
    expect(created.failure.code).toBe("ENVELOPE_MISBOUND");
  });

  it("rejects a source envelope this client is not the recipient of", async () => {
    const world = await operationWorld();
    const source = world.sources[0]!;
    const created = await reEnvelope({
      source,
      // The client's own identity, but the ACCOUNT envelope: the label would not match.
      sourceRecipient: { recipientId: world.client.recipient.recipientId, type: world.client.recipient.type },
      openingKey: world.keys.operationKey,
      target: { recipientId: filled(16, 0x54), type: "TRUSTED_BROWSER", publicKey: await strangerSpki() },
    });
    expect(created.ok).toBe(false);
    if (created.ok) return;
    expect(created.failure.code).toBe("ENVELOPE_MISBOUND");
  });
});

describe("§33.2 the obligatory round-trip", () => {
  it("fails when the envelope was sealed to a public key the prover does not hold", async () => {
    const world = await operationWorld();
    const target = await prepareEnrollment({ recipientId: filled(16, 0x55), type: "TRUSTED_BROWSER", label: "new" });
    const source = world.sources[0]!;

    // Sealed to a stranger's key under the target's label, then proved with the target's key.
    const created = await reEnvelope({
      source,
      sourceRecipient: world.account,
      openingKey: world.keys.operationKey,
      target: {
        recipientId: target.recipient.recipientId,
        type: target.recipient.type,
        publicKey: await strangerSpki(),
      },
    });
    expect(created.ok).toBe(true);
    if (!created.ok) return;

    const proved = await proveEnvelope(
      source.descriptor,
      created.value,
      { recipientId: target.recipient.recipientId, type: target.recipient.type },
      target.prover,
    );
    expect(proved.ok).toBe(false);
    if (proved.ok) return;
    expect(proved.failure.code).toBe("ROUND_TRIP_FAILED");
  });

  it("accepts the recovery kit's ['decrypt'] key through the same check (§33.2)", async () => {
    const world = await operationWorld();
    const source = world.sources[0]!;
    const recovery = {
      recipientId: envelopeFor(world.created.epoch.envelopes, recoveryIdOf(world)).recipient_id,
      type: "RECOVERY" as const,
    };
    const proved = await proveEnvelope(
      source.descriptor,
      envelopeFor(world.created.epoch.envelopes, recovery.recipientId),
      recovery,
      { kind: "DECRYPT", privateKey: await recoveryDecryptKey(world.recoveryKit) },
    );
    expect(proved.ok).toBe(true);
  });
});

describe("§34.2 building coverage", () => {
  it("produces exactly one envelope per required epoch, and they all open", async () => {
    const world = await operationWorld();
    const target = await prepareEnrollment({ recipientId: filled(16, 0x56), type: "TRUSTED_BROWSER", label: "new" });
    const required = requiredEpochSet(world.view.vaults);

    const coverage = await buildCoverage({
      required,
      sources: world.sources,
      sourceRecipient: world.account,
      openingKey: world.keys.operationKey,
      target: {
        recipientId: target.recipient.recipientId,
        type: target.recipient.type,
        publicKey: target.recipient.publicKey,
      },
      prover: target.prover,
    });
    expect(coverage.ok).toBe(true);
    if (!coverage.ok) return;
    expect(coverage.value).toHaveLength(required.length);

    const matched = checkCoverage({
      required,
      recipients: [{ recipientId: target.recipient.recipientId, type: target.recipient.type }],
      envelopes: coverage.value,
    });
    expect(matched.ok).toBe(true);
  });

  it("names the epoch when no source envelope was supplied for it", async () => {
    const world = await operationWorld();
    const target = await prepareEnrollment({ recipientId: filled(16, 0x57), type: "TRUSTED_BROWSER", label: "new" });
    const required = requiredEpochSet(world.view.vaults);

    const coverage = await buildCoverage({
      required,
      sources: [world.sources[0]!],
      sourceRecipient: world.account,
      openingKey: world.keys.operationKey,
      target: {
        recipientId: target.recipient.recipientId,
        type: target.recipient.type,
        publicKey: target.recipient.publicKey,
      },
      prover: target.prover,
    });
    expect(coverage.ok).toBe(false);
    if (coverage.ok) return;
    expect(coverage.failure.code).toBe("MISSING_SOURCE_ENVELOPE");
    expect(idKey(coverage.failure.vaultId as Uint8Array)).toBe(idKey(world.sources[1]!.descriptor.vault_id));
  });

  it("is driven by the required set, whatever order or surplus the sources arrive in", async () => {
    const world = await operationWorld();
    const target = await prepareEnrollment({ recipientId: filled(16, 0x58), type: "TRUSTED_BROWSER", label: "new" });
    const required = requiredEpochSet(world.view.vaults);

    await fc.assert(
      fc.asyncProperty(fc.shuffledSubarray([0, 1], { minLength: 2, maxLength: 2 }), async (order) => {
        const coverage = await buildCoverage({
          required,
          // The same two sources, permuted, plus a duplicate the loop must ignore.
          sources: [...order.map((i) => world.sources[i]!), world.sources[0]!],
          sourceRecipient: world.account,
          openingKey: world.keys.operationKey,
          target: {
            recipientId: target.recipient.recipientId,
            type: target.recipient.type,
            publicKey: target.recipient.publicKey,
          },
          prover: target.prover,
        });
        expect(coverage.ok).toBe(true);
        if (!coverage.ok) return;
        expect(coverage.value.map((envelope) => idKey(envelope.epoch_id))).toEqual(
          required.map((epoch) => idKey(epoch.epochId)),
        );
      }),
      { numRuns: 4 },
    );
  });
});

/** The RECOVERY `recipient_id` of the world's root, read off the envelope set of E1. */
function recoveryIdOf(world: Awaited<ReturnType<typeof operationWorld>>): Uint8Array {
  const recovery = world.created.epoch.envelopes.find((envelope) => envelope.recipient_type === "RECOVERY");
  if (recovery === undefined) throw new Error("E1 has no RECOVERY envelope");
  return recovery.recipient_id;
}
