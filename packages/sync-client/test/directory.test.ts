import { EPOCH_DESCRIPTOR, EPOCH_ENVELOPE, REGISTRY, ROOT_DESCRIPTOR, ROOT_TRANSITION, decodeRecord, encodeRecord } from "@nodra/encoding/records";
import type { Registry, RootDescriptor, RootTransition } from "@nodra/encoding/records";
import { type EpochWorld, makeEpoch, makeWorld } from "@nodra/key-lifecycle/test-support/epoch";
import { makeSigner, signRoles, unsignedFor } from "@nodra/key-lifecycle/test-support/chain";
import { filled } from "@nodra/key-lifecycle/test-support/bytes";
import type { CreatedEpoch, RecipientIdentity } from "@nodra/key-lifecycle";
import { activeRecipients, idKey, nextDescriptor, nextRegistry, registryHash, rootHash, signRegistry, verifyEpochChain, verifyRegistryChain, verifyRootChain } from "@nodra/key-lifecycle";
import type * as P from "@nodra/protocol";
import { beforeAll, describe, expect, it } from "vitest";
import { type DirectoryTransport, DirectoryError, openCryptoDirectory, vaultStorePins } from "../src/directory.js";
import { bytesToUuid } from "../src/manifest.js";
import { type StoredPins, openVaultStore } from "../src/store.js";
import { epochAccess, vaultCrypto } from "../src/vault-crypto.js";
import { freshIdb } from "./fixtures.js";

// The client's own §28/§29/§32.1 view: what it proves, what it refuses, and what it pins.
//
// Every case here serves the SAME records a real Worker would, through a transport the test writes
// by hand, and then breaks exactly one thing about how they are served: the order, an omission, a
// forged extra link, a stale registry. The point is never that the crypto works — the §28/§29/§32
// suites own that — but that this module believes nothing the server says about its own answer.
//
// Two of them are broken-variant proofs. A rule nobody can violate proves nothing, so each of those
// builds a directory with one check removed, shows it accepts the attack, and shows the real one
// does not. They are the evidence that the checks are load-bearing.

const RECIPIENT = filled(16, 0x31);
const ME: RecipientIdentity = { recipientId: RECIPIENT, type: "PLUGIN_INSTALLATION" };
const REVOKED_LATER = filled(16, 0x32);
/** The fixture world's account (); §30.1 ids are not UUIDv7-shaped. */
/** The fixture world's account id, 16 bytes of 0x11: §30.1 ids are not UUIDv7-shaped. */
const ACCOUNT = "11111111-1111-1111-1111-111111111111";
const VAULT = "00000000-0000-7000-8000-0000000000a1";
const BLOB = "0190a1b2-0000-7000-8000-0000000000a1";

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const bytes = (uuid: string) => {
  const h = uuid.replaceAll("-", "");
  return Uint8Array.from({ length: h.length / 2 }, (_, i) => Number.parseInt(h.slice(i * 2, i * 2 + 2), 16));
};

interface World {
  readonly keys: EpochWorld;
  readonly epochs: readonly CreatedEpoch[];
  /** A second root generation (RECOVERY_KIT_REPLACEMENT: the account signing key does not change). */
  readonly gen2: { readonly descriptor: RootDescriptor; readonly transition: RootTransition };
  /** Version 3, bound to generation 2, revoking {@link REVOKED_LATER}. */
  readonly registryV3: Registry;
}

let world: World;

beforeAll(async () => {
  const keys = await makeWorld();
  const first = await makeEpoch(keys, 0, null, { vaultId: bytes(VAULT), epochId: bytes("00000000-0000-7000-8000-0000000000e1") });
  const second = await makeEpoch(keys, 0, first, { vaultId: bytes(VAULT), epochId: bytes("00000000-0000-7000-8000-0000000000e2") });

  // §28.2 RECOVERY_KIT_REPLACEMENT: roles 1 (the account signing key in force) and 4 (the NEW
  // recovery authority). It is the one transition this fixture can build, because it never needs
  // the old recovery authority's private key.
  const newRecoveryAuthority = await makeSigner();
  const descriptor = await nextDescriptor(keys.root, { recoveryEncryption: filled(32, 0x55), recoveryAuthority: newRecoveryAuthority.spki });
  const transition = await signRoles(await unsignedFor("RECOVERY_KIT_REPLACEMENT", descriptor, keys.root), [
    [1, keys.signer.privateKey],
    [4, newRecoveryAuthority.privateKey],
  ]);
  // §29 bullet 6: a root transition's registry may change only `root_generation`, the signature and
  // revocations. This one revokes a device, which is exactly what a stale registry would hide.
  const registryV3 = await signRegistry(await nextRegistry(keys.registry, { rootGeneration: 2, revoke: [REVOKED_LATER] }), keys.signer.privateKey);

  world = { keys, epochs: [first, second], gen2: { descriptor, transition }, registryV3 };
}, 120_000);

// --- The server, as this test can bend it ---------------------------------------------------

interface ServerOptions {
  /** Generations to serve, in the order to serve them. Default: generation 1 alone. */
  readonly rootLinks?: ReadonlyArray<{ descriptor: RootDescriptor; transition: RootTransition }>;
  readonly registries?: readonly Registry[];
  readonly epochs?: readonly CreatedEpoch[];
  readonly vaultMissing?: boolean;
}

function server(o: ServerOptions = {}): DirectoryTransport {
  const links = o.rootLinks ?? [{ descriptor: world.keys.root, transition: world.keys.genesis }];
  const registries = o.registries ?? world.keys.registries;
  const epochs = o.epochs ?? world.epochs;
  return {
    async rootChain() {
      return {
        kind: "ROOT_CHAIN",
        links: links.map((l) => ({
          generation: l.descriptor.root_generation,
          descriptor: hex(encodeRecord(ROOT_DESCRIPTOR, l.descriptor)),
          transition: hex(encodeRecord(ROOT_TRANSITION, l.transition)),
        })),
      };
    },
    async registry() {
      return { kind: "REGISTRY_CHAIN", versions: registries.map((r) => ({ version: r.registry_version, registry: hex(encodeRecord(REGISTRY, r)) })) };
    },
    async vaultDirectory() {
      if (o.vaultMissing === true) return { kind: "VAULT_NOT_FOUND" };
      return {
        kind: "DIRECTORY",
        epochs: epochs.map((e) => ({
          epochId: bytesToUuid(e.descriptor.epoch_id),
          descriptor: hex(encodeRecord(EPOCH_DESCRIPTOR, e.descriptor)),
          descriptorHash: hex(e.descriptorHash),
          state: "ACTIVE" as const,
        })),
        envelopes: epochs.flatMap((e) =>
          [...e.envelopes]
            .filter((x) => idKey(x.recipient_id) === idKey(RECIPIENT))
            .map((x) => ({ epochId: bytesToUuid(x.epoch_id), envelope: hex(encodeRecord(EPOCH_ENVELOPE, x)) })),
        ),
      } satisfies P.VaultDirectoryResponse;
    },
  };
}

/** A pin repository in memory, so a case can start from any prior belief and read back what it wrote. */
function memoryPins(initial: StoredPins = {}) {
  let held: StoredPins = initial;
  return {
    get current(): StoredPins {
      return held;
    },
    repo: {
      read: async () => held,
      write: async (pins: StoredPins) => {
        held = { ...held, ...pins };
      },
    },
  };
}

const open = (transport: DirectoryTransport, pins = memoryPins().repo, recipient: RecipientIdentity = ME) =>
  openCryptoDirectory({ transport, accountId: ACCOUNT, vaultId: VAULT, recipient, pins });

const failure = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "no failure";
  } catch (e) {
    return e instanceof DirectoryError ? e.code : `not a DirectoryError: ${String(e)}`;
  }
};

// --- What an honest server buys -------------------------------------------------------------

describe("an honest server", () => {
  it("proves the root and registry, and hands `epochAccess` the maps it needs", async () => {
    const directory = await open(server());
    await directory.refresh();
    expect([...directory.accountSigningKeys.keys()]).toEqual([1]);
    expect(hex(directory.accountSigningKeys.get(1)!)).toBe(hex(world.keys.signer.spki));
    expect(hex(directory.rootHashes.get(1)!)).toBe(hex(world.keys.rootHash));
    // Both registry versions, hashed here rather than taken from the answer.
    expect([...directory.registryHashes.keys()].sort()).toEqual([1, 2]);
    expect(hex(directory.registryHashes.get(2)!)).toBe(hex(world.keys.registryHash));
  });

  it("drives the real VaultCrypto end to end: a blob sealed and opened under a proved epoch", async () => {
    const directory = await open(server());
    const crypto = vaultCrypto(
      epochAccess({
        vaultId: VAULT,
        directory: directory.epochDirectory,
        recipient: ME,
        privateKey: world.keys.privateKeys.get(idKey(RECIPIENT))!,
        accountSigningKeys: directory.accountSigningKeys,
        rootHashes: directory.rootHashes,
        rootCryptoVersions: directory.rootCryptoVersions,
        registryHashes: directory.registryHashes,
        onChainProved: directory.onChainProved,
      }),
    );
    const epochId = bytesToUuid(world.epochs[1]!.descriptor.epoch_id);
    const plaintext = new TextEncoder().encode("a note nobody but this recipient can read");
    const sealed = await crypto.encryptBlob({ epochId, blobId: BLOB, kind: "CONTENT", payload: plaintext });
    const opened = await crypto.open({ epochId, blobId: BLOB, kind: "CONTENT", ciphertext: sealed.ciphertext, expectFingerprint: sealed.fingerprint! });
    expect(new TextDecoder().decode(opened)).toBe("a note nobody but this recipient can read");
  });

  it("refreshes the maps before listing, so a rotation's new generation is already known", async () => {
    const directory = await open(server({ rootLinks: [{ descriptor: world.keys.root, transition: world.keys.genesis }, world.gen2], registries: [...world.keys.registries, world.registryV3] }));
    // Nothing is known before the first listing; `list()` is what refreshes §28 and §29.
    expect([...directory.accountSigningKeys.keys()]).toEqual([]);
    await directory.epochDirectory.list();
    expect([...directory.accountSigningKeys.keys()].sort()).toEqual([1, 2]);
    expect([...directory.registryHashes.keys()].sort()).toEqual([1, 2, 3]);
  });

  it("carries VAULT_NOT_FOUND through as itself", async () => {
    const directory = await open(server({ vaultMissing: true }));
    expect(await failure(directory.epochDirectory.list())).toBe("VAULT_NOT_FOUND");
  });
});

// --- What a dishonest one does not --------------------------------------------------------

describe("a server that reorders, omits or forges", () => {
  it("refuses a reordered root chain", async () => {
    const two = [{ descriptor: world.keys.root, transition: world.keys.genesis }, world.gen2];
    const directory = await open(server({ rootLinks: [two[1]!, two[0]!], registries: [...world.keys.registries, world.registryV3] }));
    expect(await failure(directory.refresh())).toBe("ROOT_CHAIN_INVALID");
  });

  it("refuses a root chain that omits GENESIS", async () => {
    const directory = await open(server({ rootLinks: [world.gen2] }));
    expect(await failure(directory.refresh())).toBe("ROOT_CHAIN_INVALID");
  });

  it("refuses a forged generation appended by the server", async () => {
    const forged = await forgedGeneration();
    const directory = await open(server({ rootLinks: [{ descriptor: world.keys.root, transition: world.keys.genesis }, forged] }));
    expect(await failure(directory.refresh())).toBe("ROOT_CHAIN_INVALID");
  });

  it("refuses a registry chain with a version missing from the middle", async () => {
    const directory = await open(server({ registries: [world.keys.registries[0]!, world.registryV3] }));
    expect(await failure(directory.refresh())).toBe("REGISTRY_INVALID");
  });

  it("refuses a reordered registry chain", async () => {
    const directory = await open(server({ registries: [world.keys.registries[1]!, world.keys.registries[0]!] }));
    expect(await failure(directory.refresh())).toBe("REGISTRY_INVALID");
  });

  it("refuses a registry that is not the one the root in force signs for (§29)", async () => {
    const directory = await open(server({ rootLinks: [{ descriptor: world.keys.root, transition: world.keys.genesis }, world.gen2] }));
    expect(await failure(directory.refresh())).toBe("REGISTRY_NOT_BOUND_TO_ROOT");
  });

  it("refuses an epoch chain served out of order (§32.1)", async () => {
    const directory = await open(server({ epochs: [world.epochs[1]!, world.epochs[0]!] }));
    const access = accessFor(directory);
    expect(await failureOfAccess(access, bytesToUuid(world.epochs[1]!.descriptor.epoch_id))).toBe("EPOCH_CHAIN_INVALID");
  });

  it("refuses to serve a replica whose recipient the registry no longer lists as ACTIVE (§18.3)", async () => {
    const directory = await open(server({ rootLinks: [{ descriptor: world.keys.root, transition: world.keys.genesis }, world.gen2], registries: [...world.keys.registries, world.registryV3] }), memoryPins().repo, {
      recipientId: REVOKED_LATER,
      type: "TRUSTED_BROWSER",
    });
    expect(await failure(directory.refresh())).toBe("RECIPIENT_NOT_ACTIVE");
  });

  it("refuses a record that is not decodable at all", async () => {
    const honest = server();
    const directory = await open({
      ...honest,
      rootChain: async () => ({ kind: "ROOT_CHAIN", links: [{ generation: 1, descriptor: "00ff", transition: "00ff" }] }),
    });
    expect(await failure(directory.refresh())).toBe("MALFORMED_RECORD");
  });
});

// --- Pins (§28.3, §29, §32.1) ----------------------------------------------------------------

describe("pins are facts, and they are durable", () => {
  it("writes the root and registry pins it proved, and refuses a later rollback", async () => {
    const pins = memoryPins();
    const first = await open(server({ rootLinks: [{ descriptor: world.keys.root, transition: world.keys.genesis }, world.gen2], registries: [...world.keys.registries, world.registryV3] }), pins.repo);
    await first.refresh();
    expect(pins.current.root).toEqual({ generation: 2, rootHash: hex(await rootHash(world.gen2.descriptor)) });
    expect(pins.current.registry).toEqual({ version: 3, registryHash: hex(await registryHash(world.registryV3)) });

    // The server now serves the history it served before generation 2 ever existed.
    const again = await open(server(), pins.repo);
    expect(await failure(again.refresh())).toBe("ROOT_CHAIN_INVALID");
  });

  it("writes the §32.1 epoch pin the moment the chain is proved, and refuses a truncated history next time", async () => {
    const pins = memoryPins();
    const directory = await open(server(), pins.repo);
    const access = accessFor(directory);
    await access.epochKey(bytesToUuid(world.epochs[1]!.descriptor.epoch_id));
    expect(pins.current.epoch).toEqual({
      epochId: bytesToUuid(world.epochs[1]!.descriptor.epoch_id),
      descriptorHash: hex(world.epochs[1]!.descriptorHash),
    });

    // A restart, against a server that has "forgotten" the second epoch.
    const restarted = await open(server({ epochs: [world.epochs[0]!] }), pins.repo);
    const after = accessFor(restarted);
    expect(await failureOfAccess(after, bytesToUuid(world.epochs[0]!.descriptor.epoch_id))).toBe("EPOCH_CHAIN_INVALID");
  });

  it("survives a restart through the real Dexie store", async () => {
    const idb = freshIdb();
    const store = await openVaultStore({ installNs: "plugin:0001", vaultId: VAULT, ...idb });
    const directory = await open(server(), vaultStorePins(store));
    const access = accessFor(directory);
    await access.epochKey(bytesToUuid(world.epochs[1]!.descriptor.epoch_id));
    store.db.close();

    const reopened = await openVaultStore({ installNs: "plugin:0001", vaultId: VAULT, ...idb });
    const pins = await vaultStorePins(reopened).read();
    expect(pins.root?.generation).toBe(1);
    expect(pins.registry?.version).toBe(2);
    expect(pins.epoch?.epochId).toBe(bytesToUuid(world.epochs[1]!.descriptor.epoch_id));
    // And the pin is used: a truncated history is refused after the restart.
    const truncated = await open(server({ epochs: [world.epochs[0]!] }), vaultStorePins(reopened));
    expect(await failureOfAccess(accessFor(truncated), bytesToUuid(world.epochs[0]!.descriptor.epoch_id))).toBe("EPOCH_CHAIN_INVALID");
    reopened.db.close();
  });
});

// --- Broken variants: the proof that the two checks are load-bearing -------------------------

describe("broken variants", () => {
  it("(a) a directory that trusts the server's order accepts a forged head; the real one does not", async () => {
    const forged = await forgedGeneration();
    const links = [{ descriptor: world.keys.root, transition: world.keys.genesis }, forged];
    const transport = server({ rootLinks: links });

    // The shortcut: "the server sends them in chain order, so the last one is the root in force."
    // No replay, so no transition is ever checked — the forged link's signatures are never looked at.
    const answer = await transport.rootChain();
    const trusted = answer.links.at(-1)!;
    const head = decodeRootDescriptor(trusted.descriptor);
    const brokenSigningKeys = new Map([[head.root_generation, head.account_signing_public_key]]);
    const brokenRootHashes = new Map([[head.root_generation, await rootHash(head)]]);
    expect(hex(brokenSigningKeys.get(2)!)).toBe(hex(world.keys.stranger.spki));

    // And that is enough to make an Epoch Descriptor signed by the stranger verify.
    const forgedEpoch = await forgedEpochUnder(head);
    const accepted = await verifyEpochChain([forgedEpoch], {
      vaultId: bytes(VAULT),
      accountSigningKeys: brokenSigningKeys,
      rootHashes: brokenRootHashes,
      rootCryptoVersions: new Map([...brokenRootHashes.keys()].map((generation) => [generation, 1])),
      registryHashes: world.keys.registryHashes,
    });
    expect(accepted.ok).toBe(true);

    // The real directory never gets there: the chain does not replay, so no key is ever recorded.
    const directory = await open(transport);
    expect(await failure(directory.refresh())).toBe("ROOT_CHAIN_INVALID");
    expect([...directory.accountSigningKeys.keys()]).toEqual([]);
    // For completeness: the replay the real one runs is the thing that says no.
    const replay = await verifyRootChain(
      answer.links.map((l) => ({ descriptor: decodeRootDescriptor(l.descriptor), transition: decodeRootTransition(l.transition) })),
      { accountId: world.keys.accountId },
    );
    expect(replay.ok).toBe(false);
  });

  it("(b) a directory that skips the §29 registry binding accepts a stale registry that still lists a revoked device", async () => {
    // Root at generation 2, but the server serves only the registries bound to generation 1 — the
    // ones taken before {@link REVOKED_LATER} was revoked.
    const transport = server({ rootLinks: [{ descriptor: world.keys.root, transition: world.keys.genesis }, world.gen2] });
    const stale = (await transport.registry()).versions.at(-1)!;
    const staleRegistry = decodeRegistry(stale.registry);

    // The broken variant: everything the real one does, minus `currentRootGeneration`. The chain
    // itself is perfectly valid, which is why only the binding check can catch it.
    const broken = await verifyRegistryChainWithout(transport);
    expect(broken).toBe(true);
    expect(activeRecipients(staleRegistry).some((r) => idKey(r.recipient_id) === idKey(REVOKED_LATER))).toBe(true);
    // Under the registry the root in force actually signs for, that device is gone.
    expect(activeRecipients(world.registryV3).some((r) => idKey(r.recipient_id) === idKey(REVOKED_LATER))).toBe(false);

    const directory = await open(transport);
    expect(await failure(directory.refresh())).toBe("REGISTRY_NOT_BOUND_TO_ROOT");
  });
});

// --- Helpers ---------------------------------------------------------------------------------

function accessFor(directory: Awaited<ReturnType<typeof openCryptoDirectory>>) {
  return epochAccess({
    vaultId: VAULT,
    directory: directory.epochDirectory,
    recipient: ME,
    privateKey: world.keys.privateKeys.get(idKey(RECIPIENT))!,
    accountSigningKeys: directory.accountSigningKeys,
    rootHashes: directory.rootHashes,
    rootCryptoVersions: directory.rootCryptoVersions,
    registryHashes: directory.registryHashes,
    onChainProved: directory.onChainProved,
    ...(directory.epochPin === undefined ? {} : { pin: directory.epochPin }),
  });
}

async function failureOfAccess(access: ReturnType<typeof epochAccess>, epochId: string): Promise<string> {
  try {
    await access.epochKey(epochId);
    return "no failure";
  } catch (e) {
    return (e as { code?: string }).code ?? String(e);
  }
}

/** A generation 2 whose Account Signing Key is the stranger's, with a transition nobody can verify. */
async function forgedGeneration(): Promise<{ descriptor: RootDescriptor; transition: RootTransition }> {
  const descriptor = await nextDescriptor(world.keys.root, { accountEncryption: filled(32, 0x77), accountSigning: world.keys.stranger.spki });
  const transition = await signRoles(await unsignedFor("RECOVERY_RESET", descriptor, world.keys.root), [
    [2, world.keys.stranger.privateKey],
    // Role 3 must be the recovery authority in force; the stranger is not it.
    [3, world.keys.stranger.privateKey],
  ]);
  return { descriptor, transition };
}

/** An Epoch Descriptor signed by the stranger, claiming the forged generation. */
async function forgedEpochUnder(head: RootDescriptor) {
  const forged = await makeEpoch(world.keys, 0, null, {
    vaultId: bytes(VAULT),
    epochId: bytes("00000000-0000-7000-8000-0000000000ef"),
    root: { generation: head.root_generation, hash: await rootHash(head), cryptoVersion: head.crypto_version },
    signingKey: world.keys.stranger.privateKey,
  });
  return forged.descriptor;
}

const unhex = (h: string) => Uint8Array.from({ length: h.length / 2 }, (_, i) => Number.parseInt(h.slice(i * 2, i * 2 + 2), 16));
const decodeRootDescriptor = (h: string) => decodeRecord(ROOT_DESCRIPTOR, unhex(h));
const decodeRootTransition = (h: string) => decodeRecord(ROOT_TRANSITION, unhex(h));
const decodeRegistry = (h: string) => decodeRecord(REGISTRY, unhex(h));

/**
 * The broken variant of the §29 binding check: the real replay minus `currentRootGeneration`.
 * Everything else — signatures, hash chain, append-only evolution — still runs and still passes,
 * which is the whole point: only the binding says that this chain is the wrong one for this root.
 */
async function verifyRegistryChainWithout(transport: DirectoryTransport): Promise<boolean> {
  const answer = await transport.registry();
  const replay = await verifyRegistryChain(answer.versions.map((v) => decodeRegistry(v.registry)), {
    accountId: world.keys.accountId,
    accountSigningKeys: world.keys.accountSigningKeys,
  });
  return replay.ok;
}
