// §35.3, §35.4 and §35.8.
//
// The broken variant this suite exists for is the one a reasonable implementer would write: reuse
// the ACCOUNT envelope and just change whose name is on it. The Worker accepts that bundle — §32.3
// says it can only check presence — so the test asserts *both* halves: the validator says yes, and
// §33.2's round-trip says no. That is the whole argument for why §33.2 makes the round-trip
// mandatory rather than advisory.
import { describe, expect, it } from "vitest";
import { validateSecurityBundle } from "../src/bundle.js";
import { assembleBundle } from "../src/bundle-build.js";
import { expectedOf } from "../src/client-state.js";
import { checkCoverage, requiredEpochSet } from "../src/coverage.js";
import { deriveEpochCommitment, idKey, openEpoch } from "../src/epoch.js";
import { enrollClient, planReEnrollment, prepareEnrollment } from "../src/enrollment.js";
import type { EnrollmentKeys } from "../src/enrollment.js";
import { proveEnvelope } from "../src/re-envelope.js";
import { activeRecipients } from "../src/registry.js";
import { filled } from "./support.js";
import { envelopeFor, operationWorld } from "./operations-support.js";

const NEW_CLIENT_ID = filled(16, 0x61);
const ENROLL_BUNDLE_ID = filled(16, 0x72);

async function newClient(id: Uint8Array = NEW_CLIENT_ID): Promise<EnrollmentKeys> {
  return prepareEnrollment({ recipientId: id, type: "TRUSTED_BROWSER", label: "a new browser" });
}

async function enroll(client: EnrollmentKeys) {
  const world = await operationWorld();
  const outcome = await enrollClient({
    view: world.view,
    bundleId: ENROLL_BUNDLE_ID,
    recipient: client.recipient,
    prover: client.prover,
    keys: world.keys,
    sources: world.sources,
  });
  if (!outcome.ok) throw new Error(`§35.4: ${outcome.failure.code} ${outcome.failure.message}`);
  return { world, enrolled: outcome.value };
}

describe("§35.3 / §35.4 step 2: the pair a new client generates", () => {
  it("keeps the private key non-extractable and `['unwrapKey']` only (§30.1)", async () => {
    const client = await newClient(filled(16, 0x62));
    expect(client.privateKey.extractable).toBe(false);
    expect(client.privateKey.usages).toEqual(["unwrapKey"]);
    expect(client.recipient.publicKey.length).toBeGreaterThan(0);
    expect(client.prover.kind).toBe("UNWRAP");
  });
});

describe("§35.4 the ENROLL_CLIENT bundle", () => {
  it("is accepted by §35.1.1 against the state it was prepared over", async () => {
    const { world, enrolled } = await enroll(await newClient());
    const decision = await validateSecurityBundle(enrolled.bundle, world.state);
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.value.kind).toBe("ACCEPT");
    if (decision.value.kind !== "ACCEPT") return;
    expect(decision.value.accepted.coverageEnvelopes).toHaveLength(world.view.vaults.length);
    expect(decision.value.accepted.configVersion).toBe(2);
  });

  it("adds exactly one recipient, revokes none, and rotates no epoch", async () => {
    const { world, enrolled } = await enroll(await newClient());
    expect(enrolled.registry.registry_version).toBe(world.view.registry.registry_version + 1);
    expect(activeRecipients(enrolled.registry)).toHaveLength(2);
    expect(enrolled.bundle.epochs).toBeUndefined();
    expect(enrolled.pins.epochs.map((pin) => idKey(pin.epochId))).toEqual(
      world.view.vaults.map((vault) => idKey(vault.current!.epochId)),
    );
    expect(enrolled.configVersion).toBe(world.view.configVersion + 1);
  });

  it("covers every epoch of the RequiredEpochSet, and the new client opens each one", async () => {
    const client = await newClient(filled(16, 0x63));
    const { world, enrolled } = await enroll(client);
    const required = requiredEpochSet(world.view.vaults);

    const matched = checkCoverage({
      required,
      recipients: [{ recipientId: client.recipient.recipientId, type: client.recipient.type }],
      envelopes: enrolled.coverageEnvelopes,
    });
    expect(matched.ok).toBe(true);

    for (const vault of world.view.vaults) {
      const descriptor = vault.epochs[0]!.descriptor;
      const envelope = envelopeFor(enrolled.coverageEnvelopes, client.recipient.recipientId);
      const mine = enrolled.coverageEnvelopes.find(
        (candidate) => idKey(candidate.epoch_id) === idKey(descriptor.epoch_id),
      );
      expect(mine).toBeDefined();
      expect(idKey(envelope.recipient_id)).toBe(idKey(client.recipient.recipientId));

      const opened = await openEpoch({
        descriptor,
        envelope: mine!,
        recipient: { recipientId: client.recipient.recipientId, type: client.recipient.type },
        privateKey: client.privateKey,
      });
      expect(opened.ok).toBe(true);
      if (!opened.ok) return;
      const commitment = await deriveEpochCommitment(opened.value.key, vault.vaultId, descriptor.epoch_id);
      expect(Array.from(commitment)).toEqual(Array.from(descriptor.epoch_commitment));
    }
  });
});

describe("§35.4 broken variants", () => {
  it("copying the ACCOUNT envelope passes the Worker and fails §33.2's round-trip", async () => {
    const client = await newClient(filled(16, 0x64));
    const { world, enrolled } = await enroll(client);

    // The mistake: keep the ciphertext, change the name on it.
    const copied = world.sources.map((source) => ({
      ...source.envelope,
      recipient_id: client.recipient.recipientId,
      recipient_type: client.recipient.type,
    }));
    const forged = assembleBundle({
      operationType: "ENROLL_CLIENT",
      bundleId: ENROLL_BUNDLE_ID,
      expected: expectedOf(world.view),
      registry: enrolled.registry,
      configBlob: enrolled.configBlob,
      configVersion: enrolled.configVersion,
      coverageEnvelopes: copied,
    });

    // §32.3: the Worker validates structure, labels declared and presence — and accepts this.
    const decision = await validateSecurityBundle(forged, world.state);
    expect(decision.ok).toBe(true);

    // The client's own round-trip is what catches it, before anything is sent.
    const proved = await proveEnvelope(
      world.sources[0]!.descriptor,
      copied[0]!,
      { recipientId: client.recipient.recipientId, type: client.recipient.type },
      client.prover,
    );
    expect(proved.ok).toBe(false);
    if (proved.ok) return;
    expect(proved.failure.code).toBe("ROUND_TRIP_FAILED");
  });

  it("is COVERAGE_STALE when one epoch's envelope is missing", async () => {
    const { world, enrolled } = await enroll(await newClient(filled(16, 0x65)));
    const short = assembleBundle({
      operationType: "ENROLL_CLIENT",
      bundleId: ENROLL_BUNDLE_ID,
      expected: expectedOf(world.view),
      registry: enrolled.registry,
      configBlob: enrolled.configBlob,
      configVersion: enrolled.configVersion,
      coverageEnvelopes: enrolled.coverageEnvelopes.slice(0, 1),
    });
    const decision = await validateSecurityBundle(short, world.state);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("COVERAGE_STALE");
    expect(decision.failure.step).toBe("7");
    expect(decision.failure.required).toHaveLength(2);
  });

  it("refuses to build at all when a source envelope for a required epoch is missing", async () => {
    const world = await operationWorld();
    const client = await newClient(filled(16, 0x66));
    const outcome = await enrollClient({
      view: world.view,
      bundleId: ENROLL_BUNDLE_ID,
      recipient: client.recipient,
      prover: client.prover,
      keys: world.keys,
      sources: [world.sources[0]!],
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.failure.code).toBe("MISSING_SOURCE_ENVELOPE");
    expect(outcome.failure.step).toBe(4);
  });

  it("is SECURITY_STATE_STALE at step 0d when the state moved under the operation", async () => {
    const { world, enrolled } = await enroll(await newClient(filled(16, 0x67)));
    const moved = { ...world.state, configVersion: world.state.configVersion + 1 };
    const decision = await validateSecurityBundle(enrolled.bundle, moved);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("SECURITY_STATE_STALE");
    expect(decision.failure.step).toBe("0d");
    expect(decision.failure.retryable).toBe(true);
  });
});

describe("§35.8 re-enrollment after a reset", () => {
  it("adopts the verified pins, keeps cache and outbox, and discards the old private key", async () => {
    const world = await operationWorld();
    const plan = planReEnrollment({
      accepted: world.view,
      rootHashes: new Map([[1, world.created.rootHash]]),
      previous: world.created.pins,
      recipientId: world.client.recipient.recipientId,
    });
    expect(plan.ok).toBe(true);
    if (!plan.ok) return;
    expect(plan.value.retained).toEqual(["CACHE", "OUTBOX", "DEVICE_LOCAL_KEY"]);
    expect(idKey(plan.value.discardedRecipientId)).toBe(idKey(world.client.recipient.recipientId));
    expect(plan.value.next).toBe("ENROLL_CLIENT");
    expect(plan.value.pins.registryVersion).toBe(world.view.registry.registry_version);
    expect(plan.value.pins.epochs).toHaveLength(2);
  });

  it("refuses a chain that does not contain this client's pinned root (§26)", async () => {
    const world = await operationWorld();
    const plan = planReEnrollment({
      accepted: world.view,
      // A chain that claims generation 1 with another hash: a fork, not a continuation.
      rootHashes: new Map([[1, filled(32, 0xaa)]]),
      previous: world.created.pins,
      recipientId: world.client.recipient.recipientId,
    });
    expect(plan.ok).toBe(false);
    if (plan.ok) return;
    expect(plan.failure.code).toBe("PINS_NOT_CONTINUOUS");
    expect(plan.failure.step).toBe(1);
  });
});
