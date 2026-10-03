// Property runs over §31–§34. RSA-3072 keygen is the expensive part, so every run reuses the one
// world built in `beforeAll`; what varies is the shape of the chain, the mutation, and the set of
// envelopes. No test asserts on timing.
import { beforeAll, describe, expect, it } from "vitest";
import fc from "fast-check";
import { timingSafeEqual } from "@nodra/crypto";
import { EPOCH_DESCRIPTOR } from "@nodra/encoding/records";
import type { EpochDescriptor, EpochEnvelope } from "@nodra/encoding/records";
import { checkCoverage, requiredEpochSet } from "../src/coverage.js";
import type { VaultEpochs } from "../src/coverage.js";
import { epochRecipients, idKey, sealEnvelope } from "../src/epoch.js";
import type { CreatedEpoch, EnvelopeRecipient, RecipientIdentity } from "../src/epoch.js";
import { verifyEpochChain } from "../src/epoch-chain.js";
import { activeRecipients, nextRegistry, registryHash, signRegistry } from "../src/registry.js";
import { chainOptions, makeEpochChain, makeWorld } from "./epoch-support.js";
import type { EpochWorld } from "./epoch-support.js";
import { mutateRecord } from "./chain-support.js";
import { filled } from "./support.js";

const CHAIN_LENGTH = 4;

let world: EpochWorld;
let chain: readonly CreatedEpoch[];
let descriptors: readonly EpochDescriptor[];
let newcomer: EnvelopeRecipient;
let coverage: readonly EpochEnvelope[];

beforeAll(async () => {
  world = await makeWorld();
  chain = await makeEpochChain(world, CHAIN_LENGTH);
  descriptors = chain.map((epoch) => epoch.descriptor);
  newcomer = { ...world.revoked, recipientId: filled(16, 0x61), type: "TRUSTED_BROWSER" };
  const envelopes: EpochEnvelope[] = [];
  for (const epoch of chain) {
    envelopes.push(await sealEnvelope(newcomer, world.vaultId, epoch.descriptor.epoch_id, filled(32, 0x42)));
  }
  coverage = envelopes;
});

function identity(recipient: EnvelopeRecipient): RecipientIdentity {
  return { recipientId: recipient.recipientId, type: recipient.type };
}

describe("a valid chain always verifies", () => {
  it("every prefix of a chain verifies, and verification is deterministic", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: CHAIN_LENGTH }), async (length) => {
        const prefix = descriptors.slice(0, length);
        const first = await verifyEpochChain(prefix, chainOptions(world));
        const second = await verifyEpochChain(prefix, chainOptions(world));
        expect(first.ok).toBe(true);
        expect(second.ok).toBe(true);
        if (first.ok && second.ok) {
          expect(timingSafeEqual(first.value.currentHash, second.value.currentHash)).toBe(true);
          expect(first.value.epochIds).toHaveLength(length);
        }
      }),
      { numRuns: 12 },
    );
  });

  it("every epoch of the chain is pinnable, and a history that stops earlier is rejected", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 0, max: CHAIN_LENGTH - 1 }), async (index) => {
        const pinned = chain[index] as CreatedEpoch;
        const pin = { epochId: pinned.descriptor.epoch_id, descriptorHash: pinned.descriptorHash };
        const full = await verifyEpochChain(descriptors, { ...chainOptions(world), pin });
        expect(full.ok).toBe(true);
        if (index > 0) {
          const short = await verifyEpochChain(descriptors.slice(0, index), { ...chainOptions(world), pin });
          expect(short.ok).toBe(false);
          if (!short.ok) expect(short.failure.code).toBe("PIN_ROLLBACK");
        }
      }),
      { numRuns: 12 },
    );
  });
});

describe("any single-byte change to a signed descriptor is rejected", () => {
  it("holds for every byte position of every descriptor in the chain", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: CHAIN_LENGTH - 1 }),
        fc.integer({ min: 0, max: 4096 }),
        async (index, byteIndex) => {
          const original = descriptors[index] as EpochDescriptor;
          const mutated = mutateRecord(EPOCH_DESCRIPTOR, original, byteIndex);
          // Bytes the codec itself refuses are already a rejection.
          if (mutated === null) return;
          if (JSON.stringify(mutated) === JSON.stringify(original)) return;
          const list = [...descriptors.slice(0, index), mutated];
          const result = await verifyEpochChain(list, chainOptions(world));
          expect(result.ok).toBe(false);
        },
      ),
      { numRuns: 60 },
    );
  });

  it("the generator actually reaches every byte of a descriptor", () => {
    const lengths = descriptors.map((descriptor) => {
      let count = 0;
      for (let i = 0; i < 4096; i++) if (mutateRecord(EPOCH_DESCRIPTOR, descriptor, i) !== null) count++;
      return count;
    });
    // Some positions are refused by the codec; the point is that the range is not degenerate.
    for (const count of lengths) expect(count).toBeGreaterThan(50);
  });
});

describe("coverage never reports complete when an envelope is missing", () => {
  const vaultOf = (retired: readonly number[]): VaultEpochs => ({
    vaultId: world.vaultId,
    state: "ACTIVE",
    epochs: chain.map((epoch, i) => ({
      descriptor: epoch.descriptor,
      state: retired.includes(i) ? "RETIRED" : "ACTIVE",
    })),
  });

  it("dropping any non-empty subset of the envelopes always fails", () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(fc.integer({ min: 0, max: CHAIN_LENGTH - 1 }), { minLength: 0, maxLength: 2 }),
        fc.uniqueArray(fc.integer({ min: 0, max: CHAIN_LENGTH - 1 }), { minLength: 1, maxLength: CHAIN_LENGTH }),
        (retired, dropped) => {
          const required = requiredEpochSet([vaultOf(retired)]);
          const keptIds = new Set(required.map((epoch) => idKey(epoch.epochId)));
          const envelopes = coverage.filter(
            (envelope, i) => keptIds.has(idKey(envelope.epoch_id)) && !dropped.includes(i),
          );
          const result = checkCoverage({ required, recipients: [identity(newcomer)], envelopes });
          if (envelopes.length === required.length) {
            expect(result.ok).toBe(true);
          } else {
            expect(result.ok).toBe(false);
            if (!result.ok) expect(result.failure.gaps.some((gap) => gap.code === "MISSING_ENVELOPE")).toBe(true);
          }
        },
      ),
      { numRuns: 200 },
    );
  });

  it("a complete set stays complete under reordering", () => {
    const required = requiredEpochSet([vaultOf([])]);
    fc.assert(
      fc.property(fc.shuffledSubarray([...coverage], { minLength: coverage.length }), (shuffled) => {
        const result = checkCoverage({ required, recipients: [identity(newcomer)], envelopes: shuffled });
        expect(result.ok).toBe(true);
      }),
      { numRuns: 50 },
    );
  });
});

describe("epochRecipients follows the registry", () => {
  it("is the two root recipients plus exactly the ACTIVE ones, whatever is revoked", async () => {
    const ids = world.registry.recipients.map((recipient) => recipient.recipient_id);
    await fc.assert(
      fc.asyncProperty(
        fc.uniqueArray(fc.integer({ min: 0, max: ids.length - 1 }), { minLength: 0, maxLength: ids.length }),
        async (revoking) => {
          const next = await signRegistry(
            await nextRegistry(world.registry, { revoke: revoking.map((i) => ids[i] as Uint8Array) }),
            world.signer.privateKey,
          );
          const recipients = await epochRecipients(world.root, next);
          const expected = activeRecipients(next).map((recipient) => idKey(recipient.recipient_id));
          expect(recipients.slice(2).map((recipient) => idKey(recipient.recipientId))).toEqual(expected);
          expect(recipients.slice(0, 2).map((recipient) => recipient.type)).toEqual(["ACCOUNT", "RECOVERY"]);
          // The registry hash changes with it, so a descriptor cannot name the old set (§32.1).
          expect(timingSafeEqual(await registryHash(next), world.registryHash)).toBe(false);
        },
      ),
      { numRuns: 12 },
    );
  });
});
