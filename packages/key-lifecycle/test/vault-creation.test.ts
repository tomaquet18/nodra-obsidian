// §35.10: creating an additional vault.
//
// The operation carries one epoch and nothing else, so the only thing a test can meaningfully
// check is that E1 is **reachable**: by ACCOUNT, by RECOVERY and by every ACTIVE recipient of the
// registry in force. The broken variant is therefore the vault that only its creator can open —
// which no later rule catches, because the epochs a bundle creates are excluded from the
// `RequiredEpochSet` it must cover (§35.1.1 step 7). If §35.1.1's envelope-set rule did not reject
// it at commit time, the account would silently acquire a vault its other installations could
// never read, and the user would find out when they opened the plugin on another machine.
import { describe, expect, it } from "vitest";
import { validateSecurityBundle } from "../src/bundle.js";
import { assembleBundle } from "../src/bundle-build.js";
import { expectedOf } from "../src/client-state.js";
import { createEpoch, deriveEpochCommitment, idKey, openEpoch } from "../src/epoch.js";
import { liveVaults } from "../src/rotation.js";
import { createVault } from "../src/vault-creation.js";
import { filled } from "./support.js";
import { envelopeFor, operationWorld, VAULT_A } from "./operations-support.js";

const VAULT_C = filled(16, 0x23);
const EPOCH_C1 = filled(16, 0x43);
const CREATE_VAULT_BUNDLE_ID = filled(16, 0x75);

async function build() {
  const world = await operationWorld();
  const created = await createVault({
    view: world.view,
    bundleId: CREATE_VAULT_BUNDLE_ID,
    vaultId: VAULT_C,
    epochId: EPOCH_C1,
    keys: { signingKey: world.keys.signingKey },
    ports: world.ports,
  });
  return { world, created };
}

describe("§35.10 the CREATE_VAULT bundle", () => {
  it("is accepted by §35.1.1, carrying one epoch and nothing else", async () => {
    const { world, created } = await build();
    // §35.1.1's row: every other part is **—**, so the assembled bundle must not have the fields.
    expect(created.bundle.registry).toBeUndefined();
    expect(created.bundle.root_transition).toBeUndefined();
    expect(created.bundle.profile).toBeUndefined();
    expect(created.bundle.config_blob).toBeUndefined();
    expect(created.bundle.coverage_envelopes).toBeUndefined();
    expect(created.bundle.deletion).toBeUndefined();

    const decision = await validateSecurityBundle(created.bundle, world.state);
    expect(decision.ok).toBe(true);
    if (!decision.ok || decision.value.kind !== "ACCEPT") return;
    expect(decision.value.accepted.epochs).toHaveLength(1);
    // Nothing moves but the vault set: the CAS triple is the one in force, unchanged.
    expect(decision.value.accepted.configVersion).toBe(world.view.configVersion);
    expect(decision.value.accepted.consumedNonce).toBeNull();
  });

  it("gives E1 no predecessor and binds the registry in force (§32.1, §36.2)", async () => {
    const { world, created } = await build();
    const descriptor = created.epoch.descriptor;
    expect(descriptor.previous_epoch_id).toBeNull();
    expect(descriptor.previous_descriptor_hash).toBeNull();
    expect(descriptor.root_generation).toBe(world.view.root.root_generation);
    expect(descriptor.registry_version).toBe(world.view.registry.registry_version);
    expect(Array.from(descriptor.registry_hash)).toEqual(Array.from(world.view.registryHash));
  });

  it("covers ACCOUNT, RECOVERY and every ACTIVE recipient, and the client's envelope opens", async () => {
    const { world, created } = await build();
    expect(created.epoch.envelopes.map((e) => e.recipient_type).sort()).toEqual([
      "ACCOUNT",
      "PLUGIN_INSTALLATION",
      "RECOVERY",
    ]);

    const clientId = world.client.recipient.recipientId;
    const opened = await openEpoch({
      descriptor: created.epoch.descriptor,
      envelope: envelopeFor(created.epoch.envelopes, clientId),
      recipient: { recipientId: clientId, type: "PLUGIN_INSTALLATION" },
      privateKey: world.client.privateKey,
    });
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    const commitment = await deriveEpochCommitment(opened.value.key, VAULT_C, EPOCH_C1);
    expect(Array.from(commitment)).toEqual(Array.from(created.epoch.descriptor.epoch_commitment));
  });

  it("pins the new vault alongside the ones already pinned (§32.1)", async () => {
    const { world, created } = await build();
    expect(created.pins.epochs.map((pin) => idKey(pin.vaultId))).toEqual([
      ...world.view.vaults.map((vault) => idKey(vault.vaultId)),
      idKey(VAULT_C),
    ]);
    expect(created.pins.registryVersion).toBe(world.view.registry.registry_version);
    expect(created.pins.configVersion).toBe(world.view.configVersion);
  });
});

describe("§35.10 broken variants", () => {
  it("is rejected when E1 is sealed only to the creating recipient", async () => {
    const world = await operationWorld();
    // The mistake: "my vault, my key". Nothing later catches it — a bundle's own epochs carry no
    // coverage (§35.1.1 step 7) — so the envelope-set rule is the only line of defence.
    const onlyMe = await createEpoch({
      vaultId: VAULT_C,
      epochId: EPOCH_C1,
      previous: null,
      root: { generation: world.view.root.root_generation, hash: world.view.rootHash, cryptoVersion: world.view.root.crypto_version },
      registry: { version: world.view.registry.registry_version, hash: world.view.registryHash },
      recipients: [
        {
          recipientId: world.client.recipient.recipientId,
          type: "PLUGIN_INSTALLATION",
          publicKey: world.client.recipient.publicKey,
        },
      ],
      signingKey: world.keys.signingKey,
      ports: world.ports,
    });
    const bundle = assembleBundle({
      operationType: "CREATE_VAULT",
      bundleId: CREATE_VAULT_BUNDLE_ID,
      expected: expectedOf(world.view),
      epochs: [{ descriptor: onlyMe.descriptor, envelopes: [...onlyMe.envelopes] }],
    });
    const decision = await validateSecurityBundle(bundle, world.state);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_BUNDLE");
    expect(decision.failure.retryable).toBe(false);
  });

  it("is INVALID_BUNDLE when a part marked — travels anyway", async () => {
    const { world, created } = await build();
    // §23.4: an applicable empty collection travels as `[]`, so `[]` is presence, not absence —
    // and `coverage_envelopes` is **—** for `CREATE_VAULT` (its own epoch needs no coverage).
    const withCoverage = assembleBundle({
      operationType: "CREATE_VAULT",
      bundleId: CREATE_VAULT_BUNDLE_ID,
      expected: expectedOf(world.view),
      epochs: created.bundle.epochs ?? [],
      coverageEnvelopes: [],
    });
    const decision = await validateSecurityBundle(withCoverage, world.state);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_BUNDLE");
    expect(decision.failure.step).toBe("7");
  });

  it("rejects a forbidden registry definitively, though not at step 7 (NOTES 226)", async () => {
    const { world, created } = await build();
    const withRegistry = assembleBundle({
      operationType: "CREATE_VAULT",
      bundleId: CREATE_VAULT_BUNDLE_ID,
      expected: expectedOf(world.view),
      epochs: created.bundle.epochs ?? [],
      registry: world.view.registry,
    });
    const decision = await validateSecurityBundle(withRegistry, world.state);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    // §35.1.1 numbers the registry at step 3 and the "partes marcadas — presentes" rule at step 7,
    // so a forbidden registry is validated *as a registry* first and answers `INVALID_REGISTRY`
    // (here: a re-sent v1 is not a permitted evolution). Both codes are definitive, so nothing is
    // weakened; which one the spec intends is question 226.
    expect(decision.failure.retryable).toBe(false);
    expect(decision.failure.code).toBe("INVALID_REGISTRY");
  });

  it("is INVALID_STATE when the vault_id is one the account already has", async () => {
    const world = await operationWorld();
    const clash = await createVault({
      view: world.view,
      bundleId: CREATE_VAULT_BUNDLE_ID,
      vaultId: VAULT_A,
      epochId: EPOCH_C1,
      keys: { signingKey: world.keys.signingKey },
      ports: world.ports,
    });
    const decision = await validateSecurityBundle(clash.bundle, world.state);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_STATE");
    expect(decision.failure.step).toBe("0c");
  });

  it("is INVALID_STATE when the vault_id was purged and retired (§35.12)", async () => {
    const { world, created } = await build();
    const decision = await validateSecurityBundle(created.bundle, {
      ...world.state,
      retiredVaultIds: [VAULT_C],
    });
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_STATE");
    expect(decision.failure.step).toBe("0c");
  });

  it("is SECURITY_STATE_STALE when the state moved under the prepared bundle (step 0d)", async () => {
    const { world, created } = await build();
    const decision = await validateSecurityBundle(created.bundle, {
      ...world.state,
      configVersion: world.state.configVersion + 1,
    });
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("SECURITY_STATE_STALE");
    expect(decision.failure.retryable).toBe(true);
  });

  it("is PLAN_LIMIT_EXCEEDED when the live vaults already fill the plan (§35.10 step 1)", async () => {
    const { world, created } = await build();
    // Step 1 counts ACTIVE and DELETING_SCHEDULED vaults; the world has two of them.
    expect(liveVaults(world.view.vaults)).toHaveLength(2);
    const decision = await validateSecurityBundle(created.bundle, { ...world.state, vaultLimit: 2 });
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("PLAN_LIMIT_EXCEEDED");
    expect(decision.failure.retryable).toBe(false);
  });

  it("scopes: §35.1.1 step 0 requires TRUSTED_SECURITY", async () => {
    const { world, created } = await build();
    const decision = await validateSecurityBundle(created.bundle, {
      ...world.state,
      authorization: { authenticated: true, emailConfirmed: true, token: { scopes: ["ACCOUNT_SECURITY"] } },
    });
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("SCOPE_REQUIRED");
  });
});
