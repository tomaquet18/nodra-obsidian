// §35.5: revoking a browser or a plugin.
//
// The world here is an account with **two** trusted clients, because a revocation that leaves
// nobody behind cannot show the property that matters: the surviving client must still be able to
// open the epoch the revocation created, and the revoked one must have no envelope in it at all.
//
// Both broken variants are the ones §35.5 exists to prevent: a bundle that revokes in the Registry
// but keeps the old epoch (the revoked client keeps reading everything new), and a rotation whose
// envelope set still addresses the revoked recipient (the same, one level down).
import { describe, expect, it } from "vitest";
import { validateSecurityBundle } from "../src/bundle.js";
import type { BundleState } from "../src/bundle.js";
import { assembleBundle } from "../src/bundle-build.js";
import type { AccountView } from "../src/client-state.js";
import { expectedOf } from "../src/client-state.js";
import { createEpoch, deriveEpochCommitment, epochRecipients, idKey, openEpoch } from "../src/epoch.js";
import { enrollClient, prepareEnrollment } from "../src/enrollment.js";
import type { EnrollmentKeys } from "../src/enrollment.js";
import { KeyLifecycleError } from "../src/errors.js";
import { registryHash, verifyRegistryChain } from "../src/registry.js";
import { revokeClient } from "../src/revocation.js";
import { filled } from "./support.js";
import { envelopeFor, hasEnvelopeFor, operationWorld } from "./operations-support.js";

const BROWSER_ID = filled(16, 0x68);
const REVOKE_BUNDLE_ID = filled(16, 0x73);
const NEW_EPOCH_A = filled(16, 0x4a);
const NEW_EPOCH_B = filled(16, 0x4b);

interface TwoClientAccount {
  readonly view: AccountView;
  readonly state: BundleState;
  readonly browser: EnrollmentKeys;
  readonly pluginId: Uint8Array;
  readonly keys: Awaited<ReturnType<typeof operationWorld>>["keys"];
  readonly newEpochIds: ReadonlyMap<string, Uint8Array>;
}

/** The world after a §35.4 enrollment was applied: registry v2, config v2, same two epochs. */
async function twoClients(): Promise<TwoClientAccount> {
  const world = await operationWorld();
  const browser = await prepareEnrollment({ recipientId: BROWSER_ID, type: "TRUSTED_BROWSER", label: "browser" });
  const enrolled = await enrollClient({
    view: world.view,
    bundleId: filled(16, 0x74),
    recipient: browser.recipient,
    prover: browser.prover,
    keys: world.keys,
    sources: world.sources,
  });
  if (!enrolled.ok) throw new Error(`§35.4: ${enrolled.failure.code}`);

  const replay = await verifyRegistryChain([world.view.registry, enrolled.value.registry], {
    accountId: world.accountId,
    accountSigningKeys: new Map([[1, world.created.keyset.signing.publicKeySpki]]),
  });
  if (!replay.ok) throw new Error(`registry v2: ${replay.failure.code}`);

  return {
    view: {
      ...world.view,
      registry: enrolled.value.registry,
      registryHash: enrolled.value.registryHash,
      configVersion: enrolled.value.configVersion,
    },
    state: { ...world.state, registry: replay.value, configVersion: enrolled.value.configVersion },
    browser,
    pluginId: world.client.recipient.recipientId,
    keys: world.keys,
    newEpochIds: new Map([
      [idKey(world.view.vaults[0]!.vaultId), NEW_EPOCH_A],
      [idKey(world.view.vaults[1]!.vaultId), NEW_EPOCH_B],
    ]),
  };
}

describe("§35.5 the REVOKE_CLIENT bundle", () => {
  it("is accepted by §35.1.1, with one new epoch per live vault", async () => {
    const account = await twoClients();
    const revoked = await revokeClient({
      view: account.view,
      bundleId: REVOKE_BUNDLE_ID,
      revoke: [account.pluginId],
      newEpochIds: account.newEpochIds,
      keys: account.keys,
    });
    const decision = await validateSecurityBundle(revoked.bundle, account.state);
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    if (decision.value.kind !== "ACCEPT") return;
    expect(decision.value.accepted.epochs).toHaveLength(2);
    expect(decision.value.accepted.configVersion).toBe(account.view.configVersion + 1);
    expect(revoked.pins.registryVersion).toBe(account.view.registry.registry_version + 1);
    expect(revoked.pins.epochs.map((pin) => idKey(pin.epochId))).toEqual([idKey(NEW_EPOCH_A), idKey(NEW_EPOCH_B)]);
  });

  it("leaves the revoked recipient without an envelope and the survivor with one that opens", async () => {
    const account = await twoClients();
    const revoked = await revokeClient({
      view: account.view,
      bundleId: REVOKE_BUNDLE_ID,
      revoke: [account.pluginId],
      newEpochIds: account.newEpochIds,
      keys: account.keys,
    });

    const registry = revoked.registry.recipients.find((r) => idKey(r.recipient_id) === idKey(account.pluginId));
    expect(registry?.status).toBe("REVOKED");
    expect(registry?.revoked_version).toBe(revoked.registry.registry_version);

    for (const epoch of revoked.epochs) {
      expect(hasEnvelopeFor(epoch.envelopes, account.pluginId)).toBe(false);
      expect(epoch.envelopes.map((e) => e.recipient_type).sort()).toEqual(["ACCOUNT", "RECOVERY", "TRUSTED_BROWSER"]);

      const opened = await openEpoch({
        descriptor: epoch.descriptor,
        envelope: envelopeFor(epoch.envelopes, BROWSER_ID),
        recipient: { recipientId: BROWSER_ID, type: "TRUSTED_BROWSER" },
        privateKey: account.browser.privateKey,
      });
      expect(opened.ok).toBe(true);
      if (!opened.ok) return;
      const commitment = await deriveEpochCommitment(
        opened.value.key,
        epoch.descriptor.vault_id,
        epoch.descriptor.epoch_id,
      );
      expect(Array.from(commitment)).toEqual(Array.from(epoch.descriptor.epoch_commitment));
    }
  });

  it("chains each new descriptor onto the epoch in force (§32.1)", async () => {
    const account = await twoClients();
    const revoked = await revokeClient({
      view: account.view,
      bundleId: REVOKE_BUNDLE_ID,
      revoke: [account.pluginId],
      newEpochIds: account.newEpochIds,
      keys: account.keys,
    });
    for (const [i, epoch] of revoked.epochs.entries()) {
      const previous = account.view.vaults[i]!.current!;
      expect(idKey(epoch.descriptor.previous_epoch_id as Uint8Array)).toBe(idKey(previous.epochId));
      expect(Array.from(epoch.descriptor.previous_descriptor_hash as Uint8Array)).toEqual(
        Array.from(previous.descriptorHash),
      );
      expect(epoch.descriptor.registry_version).toBe(revoked.registry.registry_version);
      expect(Array.from(epoch.descriptor.registry_hash)).toEqual(Array.from(await registryHash(revoked.registry)));
    }
  });
});

describe("§35.5 broken variants", () => {
  it("is VAULT_SET_STALE when the registry revokes but no epoch rotates", async () => {
    const account = await twoClients();
    const revoked = await revokeClient({
      view: account.view,
      bundleId: REVOKE_BUNDLE_ID,
      revoke: [account.pluginId],
      newEpochIds: account.newEpochIds,
      keys: account.keys,
    });
    const withoutRotation = assembleBundle({
      operationType: "REVOKE_CLIENT",
      bundleId: REVOKE_BUNDLE_ID,
      expected: expectedOf(account.view),
      registry: revoked.registry,
      configBlob: revoked.configBlob,
      configVersion: revoked.configVersion,
      epochs: [],
    });
    const decision = await validateSecurityBundle(withoutRotation, account.state);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("VAULT_SET_STALE");
    expect(decision.failure.rule).toBe("epochs/every-live-vault");
    expect(decision.failure.retryable).toBe(true);
  });

  it("is INVALID_BUNDLE when the new epochs still address the revoked recipient", async () => {
    const account = await twoClients();
    const revoked = await revokeClient({
      view: account.view,
      bundleId: REVOKE_BUNDLE_ID,
      revoke: [account.pluginId],
      newEpochIds: account.newEpochIds,
      keys: account.keys,
    });
    // The mistake: rotate with the envelope set of the registry **before** the revocation.
    const stale = await epochRecipients(account.view.root, account.view.registry);
    const epochs = [];
    for (const [i, vault] of account.view.vaults.entries()) {
      const created = await createEpoch({
        vaultId: vault.vaultId,
        epochId: [NEW_EPOCH_A, NEW_EPOCH_B][i] as Uint8Array,
        previous: vault.current,
        root: { generation: account.view.root.root_generation, hash: account.view.rootHash, cryptoVersion: account.view.root.crypto_version },
        registry: { version: revoked.registry.registry_version, hash: revoked.registryHash },
        recipients: stale,
        signingKey: account.keys.signingKey,
      });
      epochs.push({ descriptor: created.descriptor, envelopes: [...created.envelopes] });
    }
    const forged = assembleBundle({
      operationType: "REVOKE_CLIENT",
      bundleId: REVOKE_BUNDLE_ID,
      expected: expectedOf(account.view),
      registry: revoked.registry,
      configBlob: revoked.configBlob,
      configVersion: revoked.configVersion,
      epochs,
    });
    const decision = await validateSecurityBundle(forged, account.state);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_BUNDLE");
    expect(decision.failure.rule).toBe("epoch/envelope-extra");
  });

  it("refuses to build when a live vault has no new epoch id", async () => {
    const account = await twoClients();
    await expect(
      revokeClient({
        view: account.view,
        bundleId: REVOKE_BUNDLE_ID,
        revoke: [account.pluginId],
        newEpochIds: new Map([[idKey(account.view.vaults[0]!.vaultId), NEW_EPOCH_A]]),
        keys: account.keys,
      }),
    ).rejects.toBeInstanceOf(KeyLifecycleError);
  });
});
