// The Epoch Descriptor chain of a vault (§32.1) and its validation (§32.3, Worker side §36.2).
//
// Same shape as §28 and §29: one implementation of the rules, builders that enforce nothing, and
// the keys and hashes a descriptor is checked against arrive as **data** — maps produced by a
// `verifyRootChain` / `verifyRegistryChain` the caller already ran — so the verifier stays a pure,
// deterministic function of its arguments.
//
// What it does *not* check is `epoch_commitment`: proving it requires the `epoch_secret`, which
// only a recipient holding a private key has. That is §32.3, it lives in `openEpoch`, and it is
// the reason the spec says "la validez criptográfica de un envelope solo la comprueba el cliente
// que lo abre".
import { importVerifyingKey, timingSafeEqual, verifyContext } from "@nodra/crypto";
import type { VerifyingKey } from "@nodra/crypto";
import type { EpochDescriptor } from "@nodra/encoding/records";
import { epochDescriptorContext } from "./contexts.js";
import type { Outcome } from "./errors.js";
import { epochDescriptorHash, idKey } from "./epoch.js";
import { isSupportedCryptoVersion } from "./unlock.js";

export type EpochChainFailureCode =
  /** Nothing to verify and no previously verified state to continue from. */
  | "EMPTY_CHAIN"
  /** §32.1: the descriptor belongs to another vault. */
  | "VAULT_MISMATCH"
  /** A replay from nothing must start at the vault's first epoch: both `previous_*` null. */
  | "NOT_INITIAL"
  /** A later descriptor claims to be a first epoch — two genesis epochs in one vault. */
  | "UNEXPECTED_FIRST_EPOCH"
  /** §32.1: `previous_descriptor_hash` is not the hash of the descriptor before it. */
  | "BROKEN_LINK"
  /** §32.1: `previous_epoch_id` is not the `epoch_id` of the descriptor before it. */
  | "EPOCH_LINK_MISMATCH"
  /** The same `epoch_id` twice in one chain: a cycle, or a replayed descriptor. */
  | "DUPLICATE_EPOCH"
  /** §32.1: "`root_generation` no decrece a lo largo de la cadena". */
  | "ROOT_GENERATION_REGRESSED"
  /** No Account Signing Key was supplied for this descriptor's `root_generation`. */
  | "UNKNOWN_ROOT_GENERATION"
  /** §36.2: `root_hash` is not the hash of the root of that generation. */
  | "ROOT_HASH_MISMATCH"
  /** No registry hash was supplied for this descriptor's `registry_version`. */
  | "UNKNOWN_REGISTRY_VERSION"
  /** §36.2: `registry_hash` is not the hash of that registry version. */
  | "REGISTRY_HASH_MISMATCH"
  /** The Account Signing Key of that generation is not importable SPKI. */
  | "MALFORMED_PUBLIC_KEY"
  /** §32.1: the Account Signing signature of `root_generation` does not verify. */
  | "BAD_SIGNATURE"
  /** §23.0 rule 7 and §32.1 (a): a `crypto_version` this client does not implement. */
  | "UNSUPPORTED_CRYPTO_VERSION"
  /** §32.1 (b): above the `crypto_version` of the Root Descriptor of its `root_generation`. */
  | "CRYPTO_VERSION_ABOVE_ROOT"
  /** §32.1 (c): below the `crypto_version` of the descriptor before it in the vault's chain. */
  | "CRYPTO_VERSION_REGRESSED"
  /** §32.1: the chain does not reach the epoch this client pinned — a truncated history. */
  | "PIN_ROLLBACK"
  /** §32.1: the pinned epoch is on this chain with another `descriptor_hash` — a fork. */
  | "PIN_NOT_ANCESTOR";

export interface EpochChainFailure {
  readonly code: EpochChainFailureCode;
  /** The `epoch_id` of the rejected descriptor, when the failure belongs to one. */
  readonly epochId?: Uint8Array;
  readonly message: string;
}

/** What a trusted client pins per vault (§32.1: "el último `descriptor_hash` de cada vault"). */
export interface EpochPin {
  readonly epochId: Uint8Array;
  readonly descriptorHash: Uint8Array;
}

export interface EpochChainState {
  readonly vaultId: Uint8Array;
  /** The last descriptor of the chain: the vault's current epoch. */
  readonly current: EpochDescriptor;
  readonly currentHash: Uint8Array;
  /** Every epoch id the replay proved, in chain order — the ancestry a pin is checked against. */
  readonly epochIds: readonly Uint8Array[];
  /** `descriptor_hash` by `epoch_id` (lowercase hex), for the pin check and for re-linking. */
  readonly hashes: ReadonlyMap<string, Uint8Array>;
}

export interface VerifyEpochChainOptions {
  /** The vault the caller asked for. Never read from the descriptors themselves. */
  readonly vaultId?: Uint8Array;
  /** SPKI DER of the Account Signing Key of each root generation (from `verifyRootChain`). */
  readonly accountSigningKeys: ReadonlyMap<number, Uint8Array>;
  /** `root_hash` of each generation (from `verifyRootChain`), so §36.2's binding can be checked. */
  readonly rootHashes: ReadonlyMap<number, Uint8Array>;
  /** `crypto_version` of the Root Descriptor of each generation (from `verifyRootChain`), for §32.1 (b). */
  readonly rootCryptoVersions: ReadonlyMap<number, number>;
  /** `registry_hash` of each version (from `verifyRegistryChain`). */
  readonly registryHashes: ReadonlyMap<number, Uint8Array>;
  /** A previously verified state to continue from; absent means "replay from the first epoch". */
  readonly from?: EpochChainState;
  readonly pin?: EpochPin;
}

function fail(code: EpochChainFailureCode, message: string, epochId?: Uint8Array): Outcome<never, EpochChainFailure> {
  return { ok: false, failure: epochId === undefined ? { code, message } : { code, epochId, message } };
}

async function importOrNull(spki: Uint8Array): Promise<VerifyingKey | null> {
  try {
    return await importVerifyingKey(spki);
  } catch {
    return null;
  }
}

/**
 * Replays a vault's descriptor chain, in order, and returns the epoch in force.
 *
 * §32.1's rule "un descriptor firmado por una generación ya superada solo es válido si es ancestro
 * del primer descriptor de la generación siguiente" needs no separate check: generations never
 * decrease along the chain, and each descriptor is verified under the key of the generation it
 * names, so a descriptor of an older generation can only appear *before* the newer ones — which is
 * exactly "being an ancestor".
 */
export async function verifyEpochChain(
  descriptors: readonly EpochDescriptor[],
  options: VerifyEpochChainOptions,
): Promise<Outcome<EpochChainState, EpochChainFailure>> {
  let current: EpochDescriptor | null = options.from?.current ?? null;
  let currentHash: Uint8Array | null = options.from?.currentHash ?? null;
  const epochIds: Uint8Array[] = [...(options.from?.epochIds ?? [])];
  const hashes = new Map<string, Uint8Array>(options.from?.hashes ?? []);
  let vaultId: Uint8Array | null = options.vaultId ?? options.from?.vaultId ?? null;

  if (descriptors.length === 0 && current === null) {
    return fail("EMPTY_CHAIN", "an epoch history must contain at least the vault's first descriptor");
  }

  for (const descriptor of descriptors) {
    const epochId = descriptor.epoch_id;
    if (vaultId === null) vaultId = descriptor.vault_id;

    if (!timingSafeEqual(vaultId, descriptor.vault_id)) {
      return fail("VAULT_MISMATCH", "the descriptor belongs to another vault", epochId);
    }
    if (!isSupportedCryptoVersion(descriptor.crypto_version)) {
      return fail("UNSUPPORTED_CRYPTO_VERSION", `crypto_version ${descriptor.crypto_version} is not implemented`, epochId);
    }
    if (hashes.has(idKey(epochId))) {
      return fail("DUPLICATE_EPOCH", "the same epoch_id appears twice in this chain", epochId);
    }

    if (current === null) {
      if (descriptor.previous_epoch_id !== null || descriptor.previous_descriptor_hash !== null) {
        return fail("NOT_INITIAL", "a replay from nothing must start at the vault's first epoch", epochId);
      }
    } else {
      if (descriptor.previous_epoch_id === null || descriptor.previous_descriptor_hash === null) {
        return fail("UNEXPECTED_FIRST_EPOCH", "only the vault's first epoch may have null previous_* fields", epochId);
      }
      if (!timingSafeEqual(descriptor.previous_epoch_id, current.epoch_id)) {
        return fail("EPOCH_LINK_MISMATCH", "previous_epoch_id is not the epoch before it", epochId);
      }
      if (currentHash === null || !timingSafeEqual(descriptor.previous_descriptor_hash, currentHash)) {
        return fail("BROKEN_LINK", "previous_descriptor_hash is not the hash of the descriptor before it", epochId);
      }
      if (descriptor.root_generation < current.root_generation) {
        return fail(
          "ROOT_GENERATION_REGRESSED",
          `root_generation ${descriptor.root_generation} is below ${current.root_generation}`,
          epochId,
        );
      }
      if (descriptor.crypto_version < current.crypto_version) {
        return fail(
          "CRYPTO_VERSION_REGRESSED",
          `crypto_version ${descriptor.crypto_version} is below ${current.crypto_version}`,
          epochId,
        );
      }
    }

    const rootVersion = options.rootCryptoVersions.get(descriptor.root_generation);
    if (rootVersion === undefined) {
      return fail("UNKNOWN_ROOT_GENERATION", `no crypto_version for generation ${descriptor.root_generation}`, epochId);
    }
    if (descriptor.crypto_version > rootVersion) {
      return fail(
        "CRYPTO_VERSION_ABOVE_ROOT",
        `crypto_version ${descriptor.crypto_version} is above the ${rootVersion} of generation ${descriptor.root_generation}`,
        epochId,
      );
    }

    const rootHash = options.rootHashes.get(descriptor.root_generation);
    if (rootHash === undefined) {
      return fail("UNKNOWN_ROOT_GENERATION", `no verified root for generation ${descriptor.root_generation}`, epochId);
    }
    if (!timingSafeEqual(rootHash, descriptor.root_hash)) {
      return fail("ROOT_HASH_MISMATCH", `root_hash is not the hash of generation ${descriptor.root_generation}`, epochId);
    }
    const registryHash = options.registryHashes.get(descriptor.registry_version);
    if (registryHash === undefined) {
      return fail("UNKNOWN_REGISTRY_VERSION", `no verified registry at version ${descriptor.registry_version}`, epochId);
    }
    if (!timingSafeEqual(registryHash, descriptor.registry_hash)) {
      return fail(
        "REGISTRY_HASH_MISMATCH",
        `registry_hash is not the hash of registry version ${descriptor.registry_version}`,
        epochId,
      );
    }

    const spki = options.accountSigningKeys.get(descriptor.root_generation);
    if (spki === undefined) {
      return fail("UNKNOWN_ROOT_GENERATION", `no Account Signing Key for generation ${descriptor.root_generation}`, epochId);
    }
    const key = await importOrNull(spki);
    if (key === null) {
      return fail("MALFORMED_PUBLIC_KEY", `the Account Signing Key of generation ${descriptor.root_generation} is not importable SPKI`, epochId);
    }
    if (!(await verifyContext(key, epochDescriptorContext(descriptor), descriptor.signature))) {
      return fail("BAD_SIGNATURE", `the Account Signing signature of generation ${descriptor.root_generation} does not verify`, epochId);
    }

    current = descriptor;
    currentHash = await epochDescriptorHash(descriptor);
    epochIds.push(epochId);
    hashes.set(idKey(epochId), currentHash);
  }

  if (current === null || currentHash === null || vaultId === null) {
    return fail("EMPTY_CHAIN", "an epoch history must contain at least the vault's first descriptor");
  }

  const pin = options.pin;
  if (pin !== undefined) {
    const pinned = hashes.get(idKey(pin.epochId));
    if (pinned === undefined) {
      return fail("PIN_ROLLBACK", "this history does not reach the pinned epoch");
    }
    if (!timingSafeEqual(pinned, pin.descriptorHash)) {
      return fail("PIN_NOT_ANCESTOR", "the pinned epoch has another descriptor_hash on this history", pin.epochId);
    }
  }

  return { ok: true, value: { vaultId, current, currentHash, epochIds, hashes } };
}
