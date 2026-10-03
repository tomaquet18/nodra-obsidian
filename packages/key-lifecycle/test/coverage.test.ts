// §34: `RequiredEpochSet` and whether a set of envelopes covers it.
import { beforeAll, describe, expect, it } from "vitest";
import type { EpochEnvelope } from "@nodra/encoding/records";
import { belongsToRequiredVaults, checkCoverage, requiredEpochSet } from "../src/coverage.js";
import type { CoverageGapCode, VaultEpochs } from "../src/coverage.js";
import { idKey, sealEnvelope } from "../src/epoch.js";
import type { CreatedEpoch, EnvelopeRecipient, RecipientIdentity } from "../src/epoch.js";
import { makeEpoch, makeEpochChain, makeWorld } from "./epoch-support.js";
import type { EpochWorld } from "./epoch-support.js";
import { filled } from "./support.js";

let world: EpochWorld;
let chain: readonly CreatedEpoch[];
/** The new public key an operation is activating (§34.2) — here, an enrolling browser. */
let newcomer: EnvelopeRecipient;

beforeAll(async () => {
  world = await makeWorld();
  chain = await makeEpochChain(world, 3);
  newcomer = { ...world.revoked, recipientId: filled(16, 0x61), type: "TRUSTED_BROWSER" };
});

function vault(state: VaultEpochs["state"], retired: readonly number[] = [], vaultId = world.vaultId): VaultEpochs {
  return {
    vaultId,
    state,
    epochs: chain.map((epoch, i) => ({
      descriptor: epoch.descriptor,
      state: retired.includes(i) ? "RETIRED" : "ACTIVE",
    })),
  };
}

/** One coverage envelope per required epoch, sealed to the new key (§33.2's output shape). */
async function coverFor(
  recipient: EnvelopeRecipient,
  epochs: readonly CreatedEpoch[] = chain,
): Promise<EpochEnvelope[]> {
  const out: EpochEnvelope[] = [];
  for (const epoch of epochs) {
    out.push(await sealEnvelope(recipient, world.vaultId, epoch.descriptor.epoch_id, filled(32, 0x42)));
  }
  return out;
}

function identity(recipient: EnvelopeRecipient): RecipientIdentity {
  return { recipientId: recipient.recipientId, type: recipient.type };
}

function codes(result: ReturnType<typeof checkCoverage>): CoverageGapCode[] {
  return result.ok ? [] : result.failure.gaps.map((gap) => gap.code);
}

describe("requiredEpochSet (§34.1, §34.3)", () => {
  it("is every non-RETIRED epoch of every vault that is not DELETED", () => {
    expect(requiredEpochSet([vault("ACTIVE")])).toHaveLength(3);
    expect(requiredEpochSet([vault("DELETING_SCHEDULED")])).toHaveLength(3);
    expect(requiredEpochSet([vault("DELETED")])).toHaveLength(0);
    expect(requiredEpochSet([vault("ACTIVE", [1])])).toHaveLength(2);
  });

  it("spans vaults", () => {
    const required = requiredEpochSet([vault("ACTIVE", [0, 1]), vault("ACTIVE", [2], filled(16, 0x22))]);
    expect(required).toHaveLength(3);
    expect(belongsToRequiredVaults(required, filled(16, 0x22))).toBe(true);
    expect(belongsToRequiredVaults(required, filled(16, 0x23))).toBe(false);
  });
});

describe("checkCoverage (§34.2)", () => {
  it("accepts one envelope per new key per required epoch", async () => {
    const result = checkCoverage({
      required: requiredEpochSet([vault("ACTIVE")]),
      recipients: [identity(newcomer)],
      envelopes: await coverFor(newcomer),
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.envelopes).toHaveLength(3);
  });

  it("covers several new keys at once (§35.7 activates two)", async () => {
    const second: EnvelopeRecipient = { ...newcomer, recipientId: filled(16, 0x62), type: "ACCOUNT" };
    const complete = checkCoverage({
      required: requiredEpochSet([vault("ACTIVE")]),
      recipients: [identity(newcomer), identity(second)],
      envelopes: [...(await coverFor(newcomer)), ...(await coverFor(second))],
    });
    expect(complete.ok).toBe(true);

    const half = checkCoverage({
      required: requiredEpochSet([vault("ACTIVE")]),
      recipients: [identity(newcomer), identity(second)],
      envelopes: await coverFor(newcomer),
    });
    expect(codes(half)).toEqual(["MISSING_ENVELOPE", "MISSING_ENVELOPE", "MISSING_ENVELOPE"]);
  });

  it("MISSING_ENVELOPE: 'falta uno'", async () => {
    const envelopes = await coverFor(newcomer);
    const result = checkCoverage({
      required: requiredEpochSet([vault("ACTIVE")]),
      recipients: [identity(newcomer)],
      envelopes: envelopes.slice(1),
    });
    expect(codes(result)).toEqual(["MISSING_ENVELOPE"]);
    if (!result.ok) {
      expect(idKey(result.failure.gaps[0]?.epochId as Uint8Array)).toBe(
        idKey((chain[0] as CreatedEpoch).descriptor.epoch_id),
      );
    }
  });

  it("UNEXPECTED_ENVELOPE: 'sobra uno' — an epoch outside the set", async () => {
    const retiredEpoch = await makeEpoch(world, 0x51, null);
    const extra = await sealEnvelope(newcomer, world.vaultId, retiredEpoch.descriptor.epoch_id, filled(32, 0x42));
    const result = checkCoverage({
      required: requiredEpochSet([vault("ACTIVE")]),
      recipients: [identity(newcomer)],
      envelopes: [...(await coverFor(newcomer)), extra],
    });
    expect(codes(result)).toEqual(["UNEXPECTED_ENVELOPE"]);
  });

  it("DUPLICATE_ENVELOPE: 'duplicado'", async () => {
    const envelopes = await coverFor(newcomer);
    const result = checkCoverage({
      required: requiredEpochSet([vault("ACTIVE")]),
      recipients: [identity(newcomer)],
      envelopes: [...envelopes, envelopes[0] as EpochEnvelope],
    });
    expect(codes(result)).toEqual(["DUPLICATE_ENVELOPE"]);
  });

  it("UNKNOWN_RECIPIENT: an envelope for a revoked or unknown key", async () => {
    const stray = await coverFor(world.revoked);
    const result = checkCoverage({
      required: requiredEpochSet([vault("ACTIVE")]),
      recipients: [identity(newcomer)],
      envelopes: [...(await coverFor(newcomer)), stray[0] as EpochEnvelope],
    });
    expect(codes(result)).toEqual(["UNKNOWN_RECIPIENT"]);
  });

  it("RECIPIENT_TYPE_MISMATCH: the right id with a type its label does not use", async () => {
    const envelopes = await coverFor(newcomer);
    const mistyped: EpochEnvelope = { ...(envelopes[0] as EpochEnvelope), recipient_type: "PLUGIN_INSTALLATION" };
    const result = checkCoverage({
      required: requiredEpochSet([vault("ACTIVE")]),
      recipients: [identity(newcomer)],
      envelopes: [mistyped, ...envelopes.slice(1)],
    });
    expect(codes(result)).toEqual(["RECIPIENT_TYPE_MISMATCH", "MISSING_ENVELOPE"]);
  });

  it("discards an envelope for an already DELETED vault without error (§34.2 exception 2)", async () => {
    const deletedVaultId = filled(16, 0x2f);
    const stray = await sealEnvelope(newcomer, deletedVaultId, (chain[0] as CreatedEpoch).descriptor.epoch_id, filled(32, 0x42));
    const result = checkCoverage({
      required: requiredEpochSet([vault("ACTIVE")]),
      recipients: [identity(newcomer)],
      envelopes: [...(await coverFor(newcomer)), stray],
      deletedVaultIds: [deletedVaultId],
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.discarded).toHaveLength(1);
  });

  it("an empty account is covered by an empty envelope list (§23.4: applicable but empty)", () => {
    const result = checkCoverage({ required: [], recipients: [identity(newcomer)], envelopes: [] });
    expect(result.ok).toBe(true);
  });
});

// --- Broken-variant proof -------------------------------------------------------------------

/**
 * The coverage checker §34.2 explicitly forbids: it counts envelopes instead of matching
 * recipients and epochs. It looks right — one envelope per required epoch is exactly the rule —
 * and it accepts the one bundle that must never be accepted: the right *number* of envelopes,
 * one epoch covered twice and another not at all. The new key is then activated without ever
 * being able to read that epoch's data, which §34's opening sentence exists to prevent.
 */
function coversByCount(required: readonly unknown[], envelopes: readonly EpochEnvelope[]): boolean {
  return envelopes.length === required.length;
}

describe("broken variant: a coverage checker that counts envelopes", () => {
  it("accepts a duplicate standing in for a missing epoch; checkCoverage does not", async () => {
    const envelopes = await coverFor(newcomer);
    const wrong = [envelopes[0] as EpochEnvelope, envelopes[0] as EpochEnvelope, envelopes[1] as EpochEnvelope];
    const required = requiredEpochSet([vault("ACTIVE")]);

    expect(coversByCount(required, wrong)).toBe(true);
    const result = checkCoverage({ required, recipients: [identity(newcomer)], envelopes: wrong });
    expect(codes(result).sort()).toEqual(["DUPLICATE_ENVELOPE", "MISSING_ENVELOPE"]);
  });
});
