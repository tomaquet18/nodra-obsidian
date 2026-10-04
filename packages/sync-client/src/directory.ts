import * as P from "@nodra/protocol";
import {
  EPOCH_DESCRIPTOR,
  EPOCH_ENVELOPE,
  REGISTRY,
  ROOT_DESCRIPTOR,
  ROOT_TRANSITION,
  decodeRecord,
} from "@nodra/encoding/records";
import type { Registry } from "@nodra/encoding/records";
import { activeRecipients, idKey, verifyRegistryChain, verifyRootChain } from "@nodra/key-lifecycle";
import type { EpochChainState, RecipientIdentity, RootChainLink } from "@nodra/key-lifecycle";
import type { EnvelopeUnwrapKey } from "@nodra/crypto";
import { type EpochDirectory, epochAccess, vaultCrypto } from "./vault-crypto.js";
import type { BlobOpener } from "./http-backend.js";
import type { BlobCrypto } from "./ports.js";
import { uuidToBytes } from "./manifest.js";
import { type StoredPins, type VaultStore, readPins, writePins } from "./store.js";

// The client's own view of §28, §29 and §32.1: the three chains a replica must have PROVED before
// it can open a single byte, and the pins it keeps so it can never be walked backwards.
//
// The whole point of this module is what it does **not** do. The server stores these records and
// hands them back; it is not an authority over any of them, and nothing here treats it as one:
//
//   * **Order is not believed.** The records go into `verifyRootChain` / `verifyRegistryChain` /
//     `verifyEpochChain` in the order the server sent them. Those verifiers link each record to the
//     one before it by hash and check its signature, so a reordered, forged, duplicated or omitted
//     entry does not produce a "wrong-looking" chain — it produces no chain at all.
//   * **Labels are not believed.** The `generation` / `version` / `epochId` fields the JSON carries
//     are only routing; every value that matters is read back out of the decoded record itself, and
//     `descriptorHash` (unsigned, §22) is recomputed by the verifier rather than taken.
//   * **The registry's binding to the root is checked, not assumed.** §29 requires the registry in
//     force to carry the generation of the root in force, and §32.1 makes every Epoch Descriptor
//     name the `root_hash` and `registry_hash` it was signed under. Skipping either would let a
//     server pair a current root with a stale registry — one that still lists a revoked device.
//   * **Pins are facts, written when they are proved.** §28.3 and §32.1 exist so that a client that
//     has seen a longer history cannot later be served a shorter one. That is worth nothing if the
//     pin is not durable before the key it authorizes is used, so each pin is awaited.
//
// The three maps this hands to `epochAccess` are live: `refresh()` updates them in place and always
// runs before a listing returns, so a rotation that adds a root generation is already in them by
// the time `verifyEpochChain` looks a generation up. They are never shrunk — a generation once
// proved stays proved.

export type DirectoryFailureCode =
  /** §28: the root chain did not replay, or does not contain this client's pin. */
  | "ROOT_CHAIN_INVALID"
  /** §29: the registry chain did not replay, or does not contain this client's pin. */
  | "REGISTRY_INVALID"
  /** §29: the registry in force is not the one the root in force signs for. */
  | "REGISTRY_NOT_BOUND_TO_ROOT"
  /** §18.3: this replica's recipient is not ACTIVE in the registry in force; it must re-enrol. */
  | "RECIPIENT_NOT_ACTIVE"
  /** A record that is not decodable NCE, or not the record it was served as. */
  | "MALFORMED_RECORD"
  /** §11.3: the vault does not exist, is DELETED, or is not this account's. */
  | "VAULT_NOT_FOUND";

export class DirectoryError extends Error {
  constructor(
    readonly code: DirectoryFailureCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "DirectoryError";
  }
}

/** The three reads of §22 this module needs, as the Worker exposes them (`@nodra/protocol`). */
export interface DirectoryTransport {
  rootChain(): Promise<P.RootChainResponse>;
  registry(sinceVersion?: number): Promise<P.RegistryChainResponse>;
  vaultDirectory(vaultId: string, recipientId: string): Promise<P.VaultDirectoryResponse | { readonly kind: "VAULT_NOT_FOUND" }>;
}

/** §22 `LocalStore.pins`. The vault store implements it; a test can hand a map instead. */
export interface PinRepository {
  read(): Promise<StoredPins>;
  write(pins: StoredPins): Promise<void>;
}

export const vaultStorePins = (store: VaultStore): PinRepository => ({
  read: () => readPins(store),
  write: (pins) => writePins(store, pins),
});

export interface CryptoDirectoryOptions {
  readonly transport: DirectoryTransport;
  /** The account this session authenticated as. Never read from the chain itself (§28.2). */
  readonly accountId: string;
  readonly vaultId: string;
  /** Who this replica is (§30.1). A registry recipient must be ACTIVE for the directory to serve it. */
  readonly recipient: RecipientIdentity;
  readonly pins: PinRepository;
}

export interface CryptoDirectory {
  /** SPKI of the Account Signing Key of each PROVED generation (§28). Live; never shrinks. */
  readonly accountSigningKeys: ReadonlyMap<number, Uint8Array>;
  /** `root_hash` of each proved generation, recomputed here (§28.1). */
  readonly rootHashes: ReadonlyMap<number, Uint8Array>;
  /** `crypto_version` of each proved generation's Root Descriptor (§32.1 (b)). */
  readonly rootCryptoVersions: ReadonlyMap<number, number>;
  /** `registry_hash` of each proved version, recomputed here (§29). */
  readonly registryHashes: ReadonlyMap<number, Uint8Array>;
  /** §32.1: the pin this client held when it opened, if any. */
  readonly epochPin?: { readonly epochId: Uint8Array; readonly descriptorHash: Uint8Array };
  /** What `epochAccess` lists: the vault's chain and this recipient's envelopes, after a refresh. */
  readonly epochDirectory: EpochDirectory;
  /** What `epochAccess` calls once it has proved a chain: the §32.1 pin becomes durable here. */
  onChainProved(state: EpochChainState): Promise<void>;
  /** §28 then §29, verified and pinned. Called by `epochDirectory.list()`; exposed for tests. */
  refresh(): Promise<void>;
}

const hex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

function fromHex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** NCE in, record out. A record that does not decode is the server's problem, never a crash here. */
function decode<T>(what: string, read: (bytes: Uint8Array) => T, hexBytes: string): T {
  try {
    return read(fromHex(hexBytes));
  } catch (e) {
    throw new DirectoryError("MALFORMED_RECORD", `a ${what} did not decode: ${String(e)}`);
  }
}

export async function openCryptoDirectory(o: CryptoDirectoryOptions): Promise<CryptoDirectory> {
  const accountId = uuidToBytes(o.accountId);
  const stored = await o.pins.read();
  const accountSigningKeys = new Map<number, Uint8Array>();
  const rootHashes = new Map<number, Uint8Array>();
  const rootCryptoVersions = new Map<number, number>();
  const registryHashes = new Map<number, Uint8Array>();
  // The pins as they were on disk when this directory opened. They are raised as chains are proved.
  let rootPin = stored.root;
  let registryPin = stored.registry;
  const epochPin = stored.epoch;
  let refreshing: Promise<void> | null = null;

  async function replayRoot(): Promise<{ generation: number; rootHash: Uint8Array }> {
    const answer = await o.transport.rootChain();
    // In the order served. `verifyRootChain` links each transition to the descriptor before it, so a
    // shuffled or spliced chain fails here rather than being silently re-sorted into shape.
    const links: RootChainLink[] = answer.links.map((link) => ({
      transition: decode("RootTransition", (b) => decodeRecord(ROOT_TRANSITION, b), link.transition),
      descriptor: decode("RootDescriptor", (b) => decodeRecord(ROOT_DESCRIPTOR, b), link.descriptor),
    }));
    const replay = await verifyRootChain(links, {
      accountId,
      ...(rootPin === undefined ? {} : { pin: { rootGeneration: rootPin.generation, rootHash: fromHex(rootPin.rootHash) } }),
    });
    if (!replay.ok) throw new DirectoryError("ROOT_CHAIN_INVALID", `${replay.failure.code}: ${replay.failure.message}`);
    // Only now are the descriptors usable. The generation and the key come out of the descriptor the
    // replay accepted, never out of the JSON that carried it.
    for (const { descriptor } of links) {
      const generation = descriptor.root_generation;
      const proved = replay.value.hashes.get(generation);
      if (proved === undefined) continue;
      accountSigningKeys.set(generation, descriptor.account_signing_public_key);
      rootHashes.set(generation, proved);
      rootCryptoVersions.set(generation, descriptor.crypto_version);
    }
    return { generation: replay.value.rootGeneration, rootHash: replay.value.rootHash };
  }

  async function replayRegistry(rootGeneration: number): Promise<{ version: number; registryHash: Uint8Array; registry: Registry }> {
    // Always from version 1: §29 lets a client continue from its pin, but continuing needs the
    // pinned version's own record, and §28.3 only asks a client to keep the hash. The pin is still
    // what makes this safe — it must appear in the replay, with that hash, or the chain is refused.
    const answer = await o.transport.registry();
    const versions = answer.versions.map((v) => decode("Registry", (b) => decodeRecord(REGISTRY, b), v.registry));
    const replay = await verifyRegistryChain(versions, {
      accountId,
      accountSigningKeys,
      // §29: "El Registry vigente DEBE tener root_generation igual a la generación de la raíz vigente."
      currentRootGeneration: rootGeneration,
      ...(registryPin === undefined ? {} : { pin: { registryVersion: registryPin.version, registryHash: fromHex(registryPin.registryHash) } }),
    });
    if (!replay.ok) {
      const code = replay.failure.code === "STALE_ROOT_GENERATION" ? "REGISTRY_NOT_BOUND_TO_ROOT" : "REGISTRY_INVALID";
      throw new DirectoryError(code, `${replay.failure.code}: ${replay.failure.message}`);
    }
    for (const version of versions) {
      const proved = replay.value.hashes.get(version.registry_version);
      if (proved !== undefined) registryHashes.set(version.registry_version, proved);
    }
    return { version: replay.value.registry.registry_version, registryHash: replay.value.registryHash, registry: replay.value.registry };
  }

  /** §18.3: a device whose recipient is not ACTIVE any more must re-enrol, not keep reading keys. */
  function checkRecipient(registry: Registry): void {
    if (o.recipient.type !== "PLUGIN_INSTALLATION" && o.recipient.type !== "TRUSTED_BROWSER") return;
    const mine = idKey(o.recipient.recipientId);
    const active = activeRecipients(registry).some((r) => idKey(r.recipient_id) === mine && r.type === o.recipient.type);
    if (!active) throw new DirectoryError("RECIPIENT_NOT_ACTIVE", "this replica's recipient is not ACTIVE in the registry in force");
  }

  async function refreshOnce(): Promise<void> {
    const root = await replayRoot();
    const registry = await replayRegistry(root.generation);
    checkRecipient(registry.registry);
    // Both proved: raise the pins together, so a restart never continues from a root the registry
    // it was verified against no longer matches.
    rootPin = { generation: root.generation, rootHash: hex(root.rootHash) };
    registryPin = { version: registry.version, registryHash: hex(registry.registryHash) };
    await o.pins.write({ root: rootPin, registry: registryPin });
  }

  /** §28 then §29, once. One refresh at a time; a failure is not cached, so the next caller asks again. */
  function refresh(): Promise<void> {
    refreshing ??= refreshOnce().finally(() => {
      refreshing = null;
    });
    return refreshing;
  }

  const epochDirectory: EpochDirectory = {
    async list() {
      // §28 and §29 first: an Epoch Descriptor names the root and registry it was signed under, so
      // a chain fetched before them could only be verified against a stale view.
      await refresh();
      const answer = await o.transport.vaultDirectory(o.vaultId, uuidFromBytes(o.recipient.recipientId));
      if (answer.kind === "VAULT_NOT_FOUND") throw new DirectoryError("VAULT_NOT_FOUND", `vault ${o.vaultId} is not readable`);
      return {
        descriptors: answer.epochs.map((e) => decode("EpochDescriptor", (b) => decodeRecord(EPOCH_DESCRIPTOR, b), e.descriptor)),
        envelopes: answer.envelopes.map((e) => decode("EpochEnvelope", (b) => decodeRecord(EPOCH_ENVELOPE, b), e.envelope)),
      };
    },
  };

  return {
    accountSigningKeys,
    rootHashes,
    rootCryptoVersions,
    registryHashes,
    ...(epochPin === undefined ? {} : { epochPin: { epochId: uuidToBytes(epochPin.epochId), descriptorHash: fromHex(epochPin.descriptorHash) } }),
    epochDirectory,
    refresh,
    async onChainProved(state) {
      await o.pins.write({ epoch: { epochId: uuidFromBytes(state.current.epoch_id), descriptorHash: hex(state.currentHash) } });
    },
  };
}

/** A uuid string from the 16 bytes §23.2 carries an id as. */
function uuidFromBytes(bytes: Uint8Array): string {
  const h = hex(bytes);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

/** The HTTP shape of the three reads (§22), beside `httpSyncBackend`'s. */
export function httpDirectory(o: {
  readonly baseUrl: string;
  readonly fetch: typeof fetch;
  readonly headers: () => Record<string, string> | Promise<Record<string, string>>;
}): DirectoryTransport & { rootState(): Promise<P.RootStateResponse> } {
  const base = o.baseUrl.replace(/\/+$/, "");
  async function get<S extends import("zod").ZodType>(path: string, schema: S): Promise<import("zod").output<S> | { kind: "VAULT_NOT_FOUND" }> {
    const res = await o.fetch(`${base}${path}`, { method: "GET", headers: await o.headers() });
    const value: unknown = await res.json().catch(() => null);
    if (!res.ok) {
      const error = P.ErrorBody.safeParse(value);
      if (error.success && error.data.error === "VAULT_NOT_FOUND") return { kind: "VAULT_NOT_FOUND" };
      throw new DirectoryError("MALFORMED_RECORD", `the server refused: ${error.success ? error.data.error : res.status}`);
    }
    const parsed = schema.safeParse(value);
    if (!parsed.success) throw new DirectoryError("MALFORMED_RECORD", "the answer is not the schema of this route");
    return parsed.data;
  }
  return {
    rootChain: () => get(P.directoryRoutes.rootChain, P.RootChainResponse) as Promise<P.RootChainResponse>,
    registry: (sinceVersion) => get(P.directoryRoutes.registry(sinceVersion), P.RegistryChainResponse) as Promise<P.RegistryChainResponse>,
    vaultDirectory: (vaultId, recipientId) => get(P.directoryRoutes.vaultDirectory(vaultId, recipientId), P.VaultDirectoryResponse),
    // §22 `getRootState` (profile, config in force, vaults): what §35.3/§35.4 unlock and plan with.
    rootState: () => get(P.directoryRoutes.rootState, P.RootStateResponse) as Promise<P.RootStateResponse>,
  };
}

/**
 * The whole §22 `VaultCrypto` of a trusted client, in one call: the directory over HTTP, the pins
 * in this vault's store, and the §31 crypto on top.
 *
 * This is the one place the plugin and the web need; everything above it is what a test bends.
 * `privateKey` is the recipient's own `["unwrapKey"]` handle (§30.1) — it never leaves its owner,
 * and nothing here writes it anywhere.
 */
export async function realVaultCrypto(o: {
  readonly transport: DirectoryTransport;
  readonly accountId: string;
  readonly vaultId: string;
  readonly recipient: RecipientIdentity;
  readonly privateKey: EnvelopeUnwrapKey;
  readonly store: VaultStore;
}): Promise<BlobCrypto & BlobOpener> {
  const directory = await openCryptoDirectory({
    transport: o.transport,
    accountId: o.accountId,
    vaultId: o.vaultId,
    recipient: o.recipient,
    pins: vaultStorePins(o.store),
  });
  return vaultCrypto(
    epochAccess({
      vaultId: o.vaultId,
      directory: directory.epochDirectory,
      recipient: o.recipient,
      privateKey: o.privateKey,
      accountSigningKeys: directory.accountSigningKeys,
      rootHashes: directory.rootHashes,
      rootCryptoVersions: directory.rootCryptoVersions,
      registryHashes: directory.registryHashes,
      onChainProved: (state) => directory.onChainProved(state),
      ...(directory.epochPin === undefined ? {} : { pin: directory.epochPin }),
    }),
  );
}
