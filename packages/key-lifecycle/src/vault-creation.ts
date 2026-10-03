// §35.10: creating an additional vault.
//
// The operation is the shortest in §35 — no transition, no registry, no config, no coverage — and
// that shortness is the whole design. A new vault carries **one** epoch, E1, and the only thing
// that can go wrong is its envelope set: §35.1.1 step 7 requires "exactamente ACCOUNT, RECOVERY y
// los recipients ACTIVE del registry pendiente; ni uno más ni uno menos", and the pending registry
// here is the one in force, because this bundle changes none. A client that sealed E1 only to
// itself would produce a vault its own other installations could never read, and — since a new
// vault's epoch is *not* part of the `RequiredEpochSet` computed before the bundle (§35.1.1 step 7:
// "los epochs creados por el propio bundle quedan cubiertos por sus envelopes y no llevan
// cobertura") — no coverage rule would catch it later either. `epochRecipients` is therefore not a
// convenience: it is the one place the set is decided, from the verified registry §35.1 insists a
// trusted client holds.
//
// Two §35.10 steps are deliberately *not* enforced here:
//
//   - step 1's plan limit ("cuentan los vaults en ACTIVE y en DELETING_SCHEDULED"). §35.10 step 5
//     has the Worker apply it with the same count, and `validateSecurityBundle` does; a builder
//     that refused locally would only turn a `PLAN_LIMIT_EXCEEDED` a UI can explain into a client
//     exception. {@link liveVaults} is exported for the UI check of step 1.
//   - step 2's `vault_id`. Like every other id in this package it is the caller's (§23.2), and
//     §35.1.1 step 0c is what decides whether it is free.
import { SECURITY_BUNDLE, encodeRecord } from "@nodra/encoding/records";
import type { SecurityBundle } from "@nodra/encoding/records";
import { assembleBundle } from "./bundle-build.js";
import type { AccountView, ClientPins, SigningKeys } from "./client-state.js";
import { expectedOf } from "./client-state.js";
import { createEpoch, epochRecipients } from "./epoch.js";
import type { CreatedEpoch } from "./epoch.js";
import type { KeyLifecyclePorts } from "./ports.js";

export interface CreateVaultRequest {
  /** The verified state (§35.1: a trusted client's, with pins). Its registry decides E1's set. */
  readonly view: AccountView;
  readonly bundleId: Uint8Array;
  /** Step 2: a UUIDv7 that exists in neither `vaults` nor `retired_ids` (§35.1.1 step 0c). */
  readonly vaultId: Uint8Array;
  /** Step 3: the id of E1 itself (§23.2). */
  readonly epochId: Uint8Array;
  /** Step 1: the Signing handle of Root Unlock. No config is rewritten, so no `AccountConfigKey`. */
  readonly keys: Pick<SigningKeys, "signingKey">;
  readonly ports?: KeyLifecyclePorts;
}

export interface CreatedVault {
  readonly bundle: SecurityBundle;
  /** §35.1: persisted with its `bundle_id` until an answer arrives, so a lost one can be resent. */
  readonly serializedBundle: Uint8Array;
  readonly vaultId: Uint8Array;
  /** E1, with its Epoch Key ready — the creator never re-opens its own envelope (§31.1). */
  readonly epoch: CreatedEpoch;
  /**
   * What to pin once the bundle is applied (§32.1). Root, registry and config do not move, so the
   * only change is one more vault in `epochs`; the existing entries are carried over from `view`.
   */
  readonly pins: ClientPins;
}

/**
 * §35.10 steps 3–5. The descriptor has no predecessor (`previous_epoch_id = null`, §32.1) and
 * binds the `registry_version`/`registry_hash` of the verified registry, which is what makes the
 * "pending registry" of §36.2 and the set sealed in step 3 the same object.
 */
export async function createVault(request: CreateVaultRequest): Promise<CreatedVault> {
  const { view } = request;

  // Steps 3–4: E1 for ACCOUNT, RECOVERY and every ACTIVE recipient of the verified registry.
  const epoch = await createEpoch({
    vaultId: request.vaultId,
    epochId: request.epochId,
    previous: null,
    root: { generation: view.root.root_generation, hash: view.rootHash, cryptoVersion: view.root.crypto_version },
    registry: { version: view.registry.registry_version, hash: view.registryHash },
    recipients: await epochRecipients(view.root, view.registry),
    signingKey: request.keys.signingKey,
    ...(request.ports === undefined ? {} : { ports: request.ports }),
  });

  // Step 5: the bundle. Everything §35.1.1's row marks **—** is simply not supplied.
  const bundle = assembleBundle({
    operationType: "CREATE_VAULT",
    bundleId: request.bundleId,
    expected: expectedOf(view),
    epochs: [{ descriptor: epoch.descriptor, envelopes: [...epoch.envelopes] }],
  });

  return {
    bundle,
    serializedBundle: encodeRecord(SECURITY_BUNDLE, bundle),
    vaultId: request.vaultId,
    epoch,
    pins: {
      rootGeneration: view.root.root_generation,
      rootHash: view.rootHash,
      genesisRootHash: view.genesisRootHash,
      registryVersion: view.registry.registry_version,
      registryHash: view.registryHash,
      configVersion: view.configVersion,
      epochs: [
        ...view.vaults.flatMap((vault) =>
          vault.current === null
            ? []
            : [
                {
                  vaultId: vault.vaultId,
                  epochId: vault.current.epochId,
                  descriptorHash: vault.current.descriptorHash,
                },
              ],
        ),
        { vaultId: request.vaultId, epochId: request.epochId, descriptorHash: epoch.descriptorHash },
      ],
    },
  };
}
