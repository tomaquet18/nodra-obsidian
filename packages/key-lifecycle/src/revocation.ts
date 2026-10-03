// §35.5: revoking a browser or a plugin.
//
// A revocation is two facts that must travel in the same bundle, and the reason they must is the
// whole point of the operation: marking a recipient REVOKED in the Registry stops the Worker
// issuing it tokens and serving it envelopes (§35.5), but it takes away nothing it already holds.
// What actually removes its future access is the **new epoch in every vault**, whose envelope set
// no longer contains it (§36.1 step 2). A bundle that revoked without rotating would look correct
// and protect nothing; §35.1.1 step 7 rejects it with `VAULT_SET_STALE`, and the broken-variant
// test in `revocation.test.ts` is exactly that bundle.
//
// §35.5 also requires a *trusted client*: §35.1 says operations that create envelopes for other
// recipients must run on one, so that a server cannot use a stale config or registry to make a
// client issue envelopes to a recipient that was already revoked. This module cannot check that —
// it is a property of where the code runs and of the pins its caller verified — so it takes an
// {@link AccountView} that only a pinned client can honestly produce, and says so here.
import { SECURITY_BUNDLE, encodeRecord } from "@nodra/encoding/records";
import type { AccountSecurityConfig, Registry, SecurityBundle } from "@nodra/encoding/records";
import { assembleBundle } from "./bundle-build.js";
import type { AccountView, ClientPins, SigningKeys } from "./client-state.js";
import { expectedOf, sealNextConfig } from "./client-state.js";
import type { CreatedEpoch } from "./epoch.js";
import { registryHash, nextRegistry, signRegistry } from "./registry.js";
import { rotateLiveVaults } from "./rotation.js";

export interface RevokeClientRequest {
  /** The verified state, produced by a trusted client with pins (§35.1). */
  readonly view: AccountView;
  readonly bundleId: Uint8Array;
  /** The `recipient_id`s to move ACTIVE → REVOKED. §35.1.1: at least one, and none added. */
  readonly revoke: readonly Uint8Array[];
  /**
   * One fresh epoch id (UUIDv7) per vault that must rotate, keyed by the lowercase hex of its
   * `vault_id` ({@link idKey}). Every ACTIVE or DELETING_SCHEDULED vault needs one: §35.1.1 step 7
   * answers `VAULT_SET_STALE` for a missing one, so a key that is absent here is a caller error
   * and throws rather than silently producing a bundle that cannot be accepted.
   */
  readonly newEpochIds: ReadonlyMap<string, Uint8Array>;
  /** §35.5 step 1: the Signing handle of Root Unlock, plus the `AccountConfigKey` for step 5. */
  readonly keys: SigningKeys;
}

export interface RevokedClient {
  readonly bundle: SecurityBundle;
  readonly serializedBundle: Uint8Array;
  readonly registry: Registry;
  readonly registryHash: Uint8Array;
  /** The new epoch of every rotated vault, in `view.vaults` order, with its Epoch Key ready. */
  readonly epochs: readonly CreatedEpoch[];
  readonly config: AccountSecurityConfig;
  readonly configBlob: Uint8Array;
  readonly configVersion: number;
  /** What to pin once the bundle is applied: new registry, new config, new epoch per vault. */
  readonly pins: ClientPins;
}

/**
 * §35.5 steps 2–5. The registry is signed first because every new Epoch Descriptor binds the
 * **pending** registry's version and hash (§36.2), and its envelope set is exactly the recipients
 * that registry still lists as ACTIVE plus ACCOUNT and RECOVERY (§36.1 step 2) — which is how the
 * revoked recipient loses access rather than merely losing a label.
 */
export async function revokeClient(request: RevokeClientRequest): Promise<RevokedClient> {
  const { view, keys } = request;

  // Step 2: the registry that revokes. The root does not move, so neither does its generation.
  const registry = await signRegistry(
    await nextRegistry(view.registry, { revoke: request.revoke }),
    keys.signingKey,
  );
  const rHash = await registryHash(registry);

  // Steps 3–4: one new epoch per live vault, chained onto that vault's current descriptor.
  const rotation = await rotateLiveVaults({
    vaults: view.vaults,
    root: view.root,
    rootHash: view.rootHash,
    registry,
    registryHash: rHash,
    newEpochIds: request.newEpochIds,
    signingKey: keys.signingKey,
  });

  // Step 5: the config, rewritten for the new registry (§26).
  const sealed = await sealNextConfig(keys.configKey, {
    root: view.root,
    rootHash: view.rootHash,
    genesisRootHash: view.genesisRootHash,
    registryVersion: registry.registry_version,
    registryHash: rHash,
    configVersion: view.configVersion + 1,
  });

  const bundle = assembleBundle({
    operationType: "REVOKE_CLIENT",
    bundleId: request.bundleId,
    expected: expectedOf(view),
    registry,
    configBlob: sealed.blob,
    configVersion: sealed.configVersion,
    epochs: rotation.bundleEpochs,
  });

  return {
    bundle,
    serializedBundle: encodeRecord(SECURITY_BUNDLE, bundle),
    registry,
    registryHash: rHash,
    epochs: rotation.epochs,
    config: sealed.config,
    configBlob: sealed.blob,
    configVersion: sealed.configVersion,
    pins: {
      rootGeneration: view.root.root_generation,
      rootHash: view.rootHash,
      genesisRootHash: view.genesisRootHash,
      registryVersion: registry.registry_version,
      registryHash: rHash,
      configVersion: sealed.configVersion,
      epochs: rotation.pins,
    },
  };
}
