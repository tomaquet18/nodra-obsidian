// "Para cada vault: nuevo epoch (§36.1)" — the one sentence §35.5 step 3, §35.7 step 8 and §35.9
// step 7 each write, and the rule §35.1.1 step 7 answers `VAULT_SET_STALE` for.
//
// It lives here rather than three times over because the three operations differ only in *which*
// pending root and registry the new epochs bind to (§36.2); the loop itself — every vault that is
// not `DELETED` (§34.1), chained onto the descriptor in force (§32.1), with the envelope set of the
// pending structures (§36.1 step 2) — is the same sentence. A vault with no new `epoch_id` is a
// caller mistake that would earn `VAULT_SET_STALE` from the Worker, so it throws here instead.
import type { AnySigningKey } from "@nodra/crypto";
import type { BundleEpoch, Registry, RootDescriptor } from "@nodra/encoding/records";
import type { ClientVault, VaultEpochPin } from "./client-state.js";
import { createEpoch, epochRecipients, idKey } from "./epoch.js";
import type { CreatedEpoch } from "./epoch.js";
import { KeyLifecycleError } from "./errors.js";
import type { KeyLifecyclePorts } from "./ports.js";

export interface RotateLiveVaultsRequest {
  /** The vaults as the client verified them; `DELETED` ones are skipped (§34.1). */
  readonly vaults: readonly ClientVault[];
  /** The **pending** root of the bundle: the new one when the operation installs one (§36.2). */
  readonly root: RootDescriptor;
  readonly rootHash: Uint8Array;
  /** The **pending** registry, whose ACTIVE recipients decide the envelope set (§36.1 step 2). */
  readonly registry: Registry;
  readonly registryHash: Uint8Array;
  /** One fresh UUIDv7 per rotating vault, keyed by the lowercase hex of its `vault_id`. */
  readonly newEpochIds: ReadonlyMap<string, Uint8Array>;
  /** The Account Signing Key of the pending root's generation (§32.1). */
  readonly signingKey: AnySigningKey;
  readonly ports?: KeyLifecyclePorts;
}

export interface Rotation {
  /** In `vaults` order, with each Epoch Key ready to use — the creator never re-opens its own. */
  readonly epochs: readonly CreatedEpoch[];
  /** The same epochs in the shape a `SecurityBundle` carries (§23.4). */
  readonly bundleEpochs: readonly BundleEpoch[];
  readonly pins: readonly VaultEpochPin[];
}

/** §34.1: the vaults a rotation must cover. A `DELETED` vault is not one of them (§35.1.1 step 7). */
export function liveVaults(vaults: readonly ClientVault[]): readonly ClientVault[] {
  return vaults.filter((vault) => vault.state !== "DELETED");
}

export async function rotateLiveVaults(request: RotateLiveVaultsRequest): Promise<Rotation> {
  const recipients = await epochRecipients(request.root, request.registry);
  const epochs: CreatedEpoch[] = [];
  const bundleEpochs: BundleEpoch[] = [];
  const pins: VaultEpochPin[] = [];

  for (const vault of liveVaults(request.vaults)) {
    const epochId = request.newEpochIds.get(idKey(vault.vaultId));
    if (epochId === undefined) {
      throw new KeyLifecycleError(
        `§35 rotates every live vault: no new epoch_id was supplied for vault ${idKey(vault.vaultId)}`,
      );
    }
    const created = await createEpoch({
      vaultId: vault.vaultId,
      epochId,
      previous: vault.current,
      root: { generation: request.root.root_generation, hash: request.rootHash, cryptoVersion: request.root.crypto_version },
      registry: { version: request.registry.registry_version, hash: request.registryHash },
      recipients,
      signingKey: request.signingKey,
      ...(request.ports === undefined ? {} : { ports: request.ports }),
    });
    epochs.push(created);
    bundleEpochs.push({ descriptor: created.descriptor, envelopes: [...created.envelopes] });
    pins.push({ vaultId: vault.vaultId, epochId, descriptorHash: created.descriptorHash });
  }
  return { epochs, bundleEpochs, pins };
}
