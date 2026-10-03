// §32.1 and §32.3: the Epoch Descriptor chain of a vault. One negative case per rule, each one
// correctly signed, so a rejection proves the rule rather than proving that ECDSA works.
import { beforeAll, describe, expect, it } from "vitest";
import { signContext, timingSafeEqual, verifyContext } from "@nodra/crypto";
import { importVerifyingKey } from "@nodra/crypto";
import type { EpochDescriptor } from "@nodra/encoding/records";
import { epochDescriptorContext, registryContext } from "../src/contexts.js";
import { epochDescriptorHash } from "../src/epoch.js";
import { verifyEpochChain } from "../src/epoch-chain.js";
import type { EpochChainFailureCode, VerifyEpochChainOptions } from "../src/epoch-chain.js";
import { chainOptions, makeEpoch, makeEpochChain, makeWorld, resignDescriptor } from "./epoch-support.js";
import type { EpochWorld } from "./epoch-support.js";
import type { CreatedEpoch } from "../src/epoch.js";
import { filled } from "./support.js";

let world: EpochWorld;
let chain: readonly CreatedEpoch[];

beforeAll(async () => {
  world = await makeWorld();
  chain = await makeEpochChain(world, 3);
});

function descriptors(created: readonly CreatedEpoch[] = chain): EpochDescriptor[] {
  return created.map((epoch) => epoch.descriptor);
}

async function expectFailure(
  list: readonly EpochDescriptor[],
  code: EpochChainFailureCode,
  options: Partial<VerifyEpochChainOptions> = {},
): Promise<void> {
  const result = await verifyEpochChain(list, { ...chainOptions(world), ...options });
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.failure.code).toBe(code);
}

describe("a valid chain", () => {
  it("verifies and returns the epoch in force", async () => {
    const result = await verifyEpochChain(descriptors(), chainOptions(world));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(timingSafeEqual(result.value.current.epoch_id, (chain[2] as CreatedEpoch).descriptor.epoch_id)).toBe(true);
    expect(result.value.epochIds).toHaveLength(3);
    expect(timingSafeEqual(result.value.currentHash, (chain[2] as CreatedEpoch).descriptorHash)).toBe(true);
  });

  it("continues from a previously verified state instead of replaying (§22 listEpochDescriptors)", async () => {
    const first = await verifyEpochChain(descriptors(chain.slice(0, 2)), chainOptions(world));
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const rest = await verifyEpochChain(descriptors(chain.slice(2)), { ...chainOptions(world), from: first.value });
    expect(rest.ok).toBe(true);
    if (rest.ok) expect(rest.value.epochIds).toHaveLength(3);
  });

  it("accepts a pin on any epoch it proved, and rejects a truncated or forked history", async () => {
    const pinned = chain[1] as CreatedEpoch;
    const pin = { epochId: pinned.descriptor.epoch_id, descriptorHash: pinned.descriptorHash };
    const ok = await verifyEpochChain(descriptors(), { ...chainOptions(world), pin });
    expect(ok.ok).toBe(true);

    // A history that stops before the pin: the server rolled the vault back.
    await expectFailure(descriptors(chain.slice(0, 1)), "PIN_ROLLBACK", { pin });

    // The pinned epoch_id present with another descriptor_hash: a fork.
    const forked = await resignDescriptor(pinned.descriptor, { registry_version: 1, registry_hash: world.registryHashes.get(1) as Uint8Array }, world.signer);
    await expectFailure([(chain[0] as CreatedEpoch).descriptor, forked], "PIN_NOT_ANCESTOR", { pin });
  });
});

describe("one negative per rule of §32.1", () => {
  it("EMPTY_CHAIN", async () => {
    await expectFailure([], "EMPTY_CHAIN");
  });

  it("VAULT_MISMATCH: a descriptor of another vault", async () => {
    await expectFailure(descriptors(), "VAULT_MISMATCH", { vaultId: filled(16, 0x99) });
  });

  it("NOT_INITIAL: a replay from nothing that does not start at the vault's first epoch", async () => {
    await expectFailure(descriptors(chain.slice(1)), "NOT_INITIAL");
  });

  it("UNEXPECTED_FIRST_EPOCH: a second descriptor with null previous_* fields", async () => {
    const second = await resignDescriptor(
      (chain[1] as CreatedEpoch).descriptor,
      { previous_epoch_id: null, previous_descriptor_hash: null },
      world.signer,
    );
    await expectFailure([(chain[0] as CreatedEpoch).descriptor, second], "UNEXPECTED_FIRST_EPOCH");
  });

  it("EPOCH_LINK_MISMATCH: previous_epoch_id names another epoch", async () => {
    const second = await resignDescriptor(
      (chain[1] as CreatedEpoch).descriptor,
      { previous_epoch_id: filled(16, 0x77) },
      world.signer,
    );
    await expectFailure([(chain[0] as CreatedEpoch).descriptor, second], "EPOCH_LINK_MISMATCH");
  });

  it("BROKEN_LINK: previous_descriptor_hash is not the hash before it", async () => {
    const second = await resignDescriptor(
      (chain[1] as CreatedEpoch).descriptor,
      { previous_descriptor_hash: filled(32, 0x77) },
      world.signer,
    );
    await expectFailure([(chain[0] as CreatedEpoch).descriptor, second], "BROKEN_LINK");
  });

  it("DUPLICATE_EPOCH: the same epoch_id twice", async () => {
    const first = (chain[0] as CreatedEpoch).descriptor;
    const repeat = await resignDescriptor(
      (chain[1] as CreatedEpoch).descriptor,
      { epoch_id: first.epoch_id },
      world.signer,
    );
    await expectFailure([first, repeat], "DUPLICATE_EPOCH");
  });

  it("ROOT_GENERATION_REGRESSED: root_generation decreases along the chain", async () => {
    const world2 = world;
    const keys = new Map(world2.accountSigningKeys);
    keys.set(2, world2.signer.spki);
    const hashes = new Map(world2.rootHashes);
    hashes.set(2, world2.rootHash);
    const versions = new Map(world2.rootCryptoVersions);
    versions.set(2, 1);
    const first = await resignDescriptor((chain[0] as CreatedEpoch).descriptor, { root_generation: 2 }, world2.signer);
    const second = await resignDescriptor(
      (chain[1] as CreatedEpoch).descriptor,
      { previous_descriptor_hash: await epochDescriptorHash(withoutSignature(first)), root_generation: 1 },
      world2.signer,
    );
    const result = await verifyEpochChain([first, second], {
      ...chainOptions(world2),
      accountSigningKeys: keys,
      rootHashes: hashes,
      rootCryptoVersions: versions,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe("ROOT_GENERATION_REGRESSED");
  });

  it("UNKNOWN_ROOT_GENERATION: no verified root for that generation", async () => {
    const odd = await resignDescriptor((chain[0] as CreatedEpoch).descriptor, { root_generation: 7 }, world.signer);
    await expectFailure([odd], "UNKNOWN_ROOT_GENERATION");
  });

  it("ROOT_HASH_MISMATCH: the right generation with another root_hash", async () => {
    const odd = await resignDescriptor((chain[0] as CreatedEpoch).descriptor, { root_hash: filled(32, 0x55) }, world.signer);
    await expectFailure([odd], "ROOT_HASH_MISMATCH");
  });

  it("UNKNOWN_REGISTRY_VERSION and REGISTRY_HASH_MISMATCH", async () => {
    const unknown = await resignDescriptor((chain[0] as CreatedEpoch).descriptor, { registry_version: 9 }, world.signer);
    await expectFailure([unknown], "UNKNOWN_REGISTRY_VERSION");

    // The dangerous one: a descriptor that claims the registry version in force but carries the
    // hash of an older one, where a since-revoked device was still ACTIVE.
    const stale = await resignDescriptor(
      (chain[0] as CreatedEpoch).descriptor,
      { registry_hash: world.registryHashes.get(1) as Uint8Array },
      world.signer,
    );
    await expectFailure([stale], "REGISTRY_HASH_MISMATCH");
  });

  it("BAD_SIGNATURE: signed by a key that is not that generation's", async () => {
    const stranger = await resignDescriptor((chain[0] as CreatedEpoch).descriptor, {}, world.stranger);
    await expectFailure([stranger], "BAD_SIGNATURE");
  });

  it("BAD_SIGNATURE: the right key over the wrong context", async () => {
    const descriptor = (chain[0] as CreatedEpoch).descriptor;
    const wrongDomain: EpochDescriptor = {
      ...descriptor,
      signature: await signContext(world.signer.privateKey, registryContext(world.registry)),
    };
    await expectFailure([wrongDomain], "BAD_SIGNATURE");
  });

  it("MALFORMED_PUBLIC_KEY: the generation's signing key is not importable SPKI", async () => {
    await expectFailure(descriptors(chain.slice(0, 1)), "MALFORMED_PUBLIC_KEY", {
      accountSigningKeys: new Map([[1, filled(40, 0x00)]]),
    });
  });

  it("UNSUPPORTED_CRYPTO_VERSION: §32.1 (a), crypto_version outside {1, 2}", async () => {
    for (const version of [0, 3]) {
      const future = await resignDescriptor((chain[0] as CreatedEpoch).descriptor, { crypto_version: version }, world.signer);
      await expectFailure([future], "UNSUPPORTED_CRYPTO_VERSION", { rootCryptoVersions: new Map([[1, 2]]) });
    }
  });
});

describe("§32.1 epoch crypto_version (ADR-021)", () => {
  /** chain[0] and chain[1] re-signed with the given versions, still linked to each other. */
  async function pair(firstVersion: number, secondVersion: number, secondGeneration = 1): Promise<EpochDescriptor[]> {
    const first = await resignDescriptor((chain[0] as CreatedEpoch).descriptor, { crypto_version: firstVersion }, world.signer);
    const second = await resignDescriptor(
      (chain[1] as CreatedEpoch).descriptor,
      {
        previous_descriptor_hash: await epochDescriptorHash(withoutSignature(first)),
        crypto_version: secondVersion,
        root_generation: secondGeneration,
      },
      world.signer,
    );
    return [first, second];
  }

  /** A second root generation, with the same signer and root hash, at crypto_version 2. */
  function twoGenerations(): Partial<VerifyEpochChainOptions> {
    return {
      accountSigningKeys: new Map([...world.accountSigningKeys, [2, world.signer.spki]]),
      rootHashes: new Map([...world.rootHashes, [2, world.rootHash]]),
      rootCryptoVersions: new Map([[1, 1], [2, 2]]),
    };
  }

  it("accepts version-1 epochs followed by a version-2 epoch of the version-2 root (a SWITCH_TO_MANAGED)", async () => {
    const result = await verifyEpochChain(await pair(1, 2, 2), { ...chainOptions(world), ...twoGenerations() });
    expect(result.ok).toBe(true);
  });

  it("CRYPTO_VERSION_ABOVE_ROOT: (b) a version-2 epoch under a version-1 root", async () => {
    const future = await resignDescriptor((chain[0] as CreatedEpoch).descriptor, { crypto_version: 2 }, world.signer);
    await expectFailure([future], "CRYPTO_VERSION_ABOVE_ROOT");
    await expectFailure(await pair(1, 2, 1), "CRYPTO_VERSION_ABOVE_ROOT", twoGenerations());
  });

  it("CRYPTO_VERSION_REGRESSED: (c) the version decreases along the vault's chain", async () => {
    await expectFailure(await pair(2, 1), "CRYPTO_VERSION_REGRESSED", { rootCryptoVersions: new Map([[1, 2]]) });
    await expectFailure(await pair(2, 1, 2), "CRYPTO_VERSION_REGRESSED", {
      ...twoGenerations(),
      rootCryptoVersions: new Map([[1, 2], [2, 2]]),
    });
  });

  it("a root generation without a known crypto_version is refused, never assumed", async () => {
    await expectFailure(descriptors(chain.slice(0, 1)), "UNKNOWN_ROOT_GENERATION", { rootCryptoVersions: new Map() });
  });
});

// --- Broken-variant proof -------------------------------------------------------------------

/**
 * A verifier that does everything the real one does **except** bind the descriptor to a registry
 * version and hash — the natural shortcut, since the signature already covers those fields and
 * "the Account Signing Key vouched for it" feels like enough.
 *
 * It is not enough. The signature proves the account authored the descriptor, not that the
 * descriptor names the registry in force. A server that replays a correctly signed descriptor
 * pinned to registry version 1 hands a client an epoch whose envelope set was computed when a
 * since-revoked device was still ACTIVE (§39.1: "epochs creados tras su revocación").
 */
async function verifyIgnoringRegistryBinding(
  list: readonly EpochDescriptor[],
  options: VerifyEpochChainOptions,
): Promise<boolean> {
  let previous: EpochDescriptor | null = null;
  let previousHash: Uint8Array | null = null;
  for (const descriptor of list) {
    if (previous !== null) {
      if (descriptor.previous_descriptor_hash === null || previousHash === null) return false;
      if (!timingSafeEqual(descriptor.previous_descriptor_hash, previousHash)) return false;
    }
    const spki = options.accountSigningKeys.get(descriptor.root_generation);
    if (spki === undefined) return false;
    const key = await importVerifyingKey(spki);
    if (!(await verifyContext(key, epochDescriptorContext(descriptor), descriptor.signature))) return false;
    previous = descriptor;
    previousHash = await epochDescriptorHash(withoutSignature(descriptor));
  }
  return previous !== null;
}

function withoutSignature(descriptor: EpochDescriptor): Omit<EpochDescriptor, "signature"> {
  const { signature: _signature, ...rest } = descriptor;
  return rest;
}

describe("broken variant: a verifier that ignores the registry binding", () => {
  it("accepts a descriptor pinned to a superseded registry that verifyEpochChain rejects", async () => {
    const stale = await resignDescriptor(
      (chain[0] as CreatedEpoch).descriptor,
      { registry_hash: world.registryHashes.get(1) as Uint8Array },
      world.signer,
    );
    expect(await verifyIgnoringRegistryBinding([stale], chainOptions(world))).toBe(true);
    await expectFailure([stale], "REGISTRY_HASH_MISMATCH");
  });

  it("also accepts one pinned to a root generation nobody verified", async () => {
    const world2 = world;
    const forged = await resignDescriptor((chain[0] as CreatedEpoch).descriptor, { root_hash: filled(32, 0x55) }, world2.signer);
    expect(await verifyIgnoringRegistryBinding([forged], chainOptions(world2))).toBe(true);
    await expectFailure([forged], "ROOT_HASH_MISMATCH");
  });
});

describe("a fresh epoch always links onto the chain it was given", () => {
  it("createEpoch's previous fields reproduce the descriptor hash", async () => {
    const fourth = await makeEpoch(world, 0x4a, chain[2] as CreatedEpoch);
    const result = await verifyEpochChain([...descriptors(), fourth.descriptor], chainOptions(world));
    expect(result.ok).toBe(true);
  });
});
