// §35.2: account creation, end to end.
//
// The bundle is checked by the validator this package already owns, and the *account* is checked
// by using it: the client's own private key opens E1, the Recovery Kit opens E1, and the two
// secrets open the config. A test that only asserted on field values would pass for an account
// nobody could unlock.
import { describe, expect, it } from "vitest";
import { activeRecipients } from "../src/registry.js";
import type { BundleState } from "../src/bundle.js";
import { validateSecurityBundle } from "../src/bundle.js";
import { createAccount } from "../src/account-creation.js";
import { deriveEpochCommitment, idKey, openEpoch, rootRecipientId } from "../src/epoch.js";
import { prepareEnrollment } from "../src/enrollment.js";
import { proveEnvelope } from "../src/re-envelope.js";
import { verifyRecoveryKit } from "../src/recovery-kit.js";
import { unlockSession } from "../src/unlock.js";
import { filled, memoPorts } from "./support.js";
import {
  ACCOUNT_ID,
  CREATE_BUNDLE_ID,
  EPOCH_A1,
  FIRST_CLIENT_ID,
  PASSWORD,
  VAULT_A,
  envelopeFor,
  operationWorld,
  recoveryDecryptKey,
} from "./operations-support.js";

/** The account as the Worker sees it before GENESIS: no root, no registry, config version 0. */
function emptyAccount(): BundleState {
  return {
    authorization: { authenticated: true, emailConfirmed: true },
    accountId: ACCOUNT_ID,
    accountState: "ACTIVE",
    root: null,
    registry: null,
    configVersion: 0,
    vaults: [],
    escrow: null,
  };
}

describe("§35.2 the CREATE_ACCOUNT bundle", () => {
  it("is accepted by §35.1.1 on an account with no root", async () => {
    const world = await operationWorld();
    const decision = await validateSecurityBundle(world.created.bundle, emptyAccount());
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.value.kind).toBe("ACCEPT");
    if (decision.value.kind !== "ACCEPT") return;
    expect(decision.value.accepted.configVersion).toBe(1);
    expect(decision.value.accepted.epochs).toHaveLength(1);
  });

  it("carries GENESIS, registry v1 with exactly this client, and E1 of the first vault", async () => {
    const { created, client } = await operationWorld();
    expect(created.bundle.operation_type).toBe("CREATE_ACCOUNT");
    expect(created.bundle.root_transition?.transition_type).toBe("GENESIS");
    expect(created.bundle.expected).toEqual({ root_generation: 0, registry_version: 0, config_version: 0 });

    expect(created.registry.registry_version).toBe(1);
    expect(created.registry.previous_registry_hash).toBeNull();
    const active = activeRecipients(created.registry);
    expect(active).toHaveLength(1);
    expect(idKey(active[0]!.recipient_id)).toBe(idKey(client.recipient.recipientId));

    const epoch = created.bundle.epochs?.[0];
    expect(idKey(epoch!.descriptor.vault_id)).toBe(idKey(VAULT_A));
    expect(epoch!.descriptor.previous_epoch_id).toBeNull();
    expect(epoch!.descriptor.previous_descriptor_hash).toBeNull();
    // §36.1 step 2: ACCOUNT, RECOVERY and every ACTIVE recipient — here exactly three.
    expect(epoch!.envelopes.map((e) => e.recipient_type).sort()).toEqual([
      "ACCOUNT",
      "PLUGIN_INSTALLATION",
      "RECOVERY",
    ]);
  });

  it("pins what §35.2 step 17 says to pin", async () => {
    const { created } = await operationWorld();
    expect(created.pins).toMatchObject({
      rootGeneration: 1,
      registryVersion: 1,
      configVersion: 1,
    });
    expect(Array.from(created.pins.genesisRootHash)).toEqual(Array.from(created.pins.rootHash));
    expect(created.pins.epochs).toHaveLength(1);
    expect(idKey(created.pins.epochs[0]!.epochId)).toBe(idKey(EPOCH_A1));
    expect(Array.from(created.pins.epochs[0]!.descriptorHash)).toEqual(Array.from(created.epoch.descriptorHash));
  });

  it("persists the exact bytes and the recipient id §35.2 step 15 requires", async () => {
    const { created } = await operationWorld();
    expect(created.serializedBundle.length).toBeGreaterThan(0);
    expect(idKey(created.pendingRecipientId)).toBe(idKey(FIRST_CLIENT_ID));
  });
});

describe("§35.2 the account it produces is usable", () => {
  it("lets the creating client open E1 with its own non-extractable key (§33.1)", async () => {
    const world = await operationWorld();
    const opened = await openEpoch({
      descriptor: world.created.epoch.descriptor,
      envelope: envelopeFor(world.created.epoch.envelopes, world.client.recipient.recipientId),
      recipient: {
        recipientId: world.client.recipient.recipientId,
        type: world.client.recipient.type,
      },
      privateKey: world.client.privateKey,
    });
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    const commitment = await deriveEpochCommitment(opened.value.key, VAULT_A, EPOCH_A1);
    expect(Array.from(commitment)).toEqual(Array.from(world.created.epoch.descriptor.epoch_commitment));
  });

  it("lets the Recovery Kit open E1, and verifies against the root it was self-tested on", async () => {
    const world = await operationWorld();
    const recovery = world.created.epoch.envelopes.find((e) => e.recipient_type === "RECOVERY");
    const proved = await proveEnvelope(
      world.created.epoch.descriptor,
      recovery!,
      { recipientId: recovery!.recipient_id, type: "RECOVERY" },
      { kind: "DECRYPT", privateKey: await recoveryDecryptKey(world.recoveryKit) },
    );
    expect(proved.ok).toBe(true);

    const verified = await verifyRecoveryKit({
      serialized: world.created.recoveryKit.serialized,
      accountId: ACCOUNT_ID,
      genesisRootHash: world.created.rootHash,
      currentDescriptor: world.created.root,
      ports: world.ports,
    });
    expect(verified.ok).toBe(true);
  });

  it("lets the two secrets open the config, which names the root and registry just created", async () => {
    const world = await operationWorld();
    const unlocked = await unlockSession({
      accountId: ACCOUNT_ID,
      profile: world.created.profile,
      secrets: { password: PASSWORD, secretKey: world.created.setupKit.accountSecretKey },
      ports: world.ports,
    });
    expect(unlocked.ok).toBe(true);
    if (!unlocked.ok) return;
    const config = unlocked.value.config;
    expect(config.config_version).toBe(1);
    expect(Array.from(config.root_hash)).toEqual(Array.from(world.created.rootHash));
    expect(Array.from(config.genesis_root_hash)).toEqual(Array.from(world.created.rootHash));
    expect(Array.from(config.registry_hash)).toEqual(Array.from(world.created.registryHash));
    expect(Array.from(config.account_encryption_public_key_hash)).toEqual(
      Array.from(world.created.keyset.encryption.publicKeyHash),
    );
    // §26: the session key the config unlocks is the ACCOUNT recipient of every epoch (§30.1).
    expect(idKey(await rootRecipientId(world.created.root.account_encryption_public_key))).toBe(
      idKey(world.account.recipientId),
    );
  });
});

describe("§35.2 negatives", () => {
  it("is INVALID_STATE at step 0c when the account already has a root", async () => {
    const world = await operationWorld();
    const decision = await validateSecurityBundle(world.created.bundle, world.state);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_STATE");
    expect(decision.failure.step).toBe("0c");
  });

  it("rejects a Setup Kit secret that does not decode (§24), before any key is generated", async () => {
    const outcome = await createAccount({
      accountId: ACCOUNT_ID,
      password: PASSWORD,
      secretKey: "not-a-secret-key",
      bundleId: CREATE_BUNDLE_ID,
      vaultId: VAULT_A,
      epochId: EPOCH_A1,
      recipient: (await prepareEnrollment({ recipientId: filled(16, 0x39), type: "TRUSTED_BROWSER", label: "x" }))
        .recipient,
      ports: memoPorts(),
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.failure.code).toBe("BAD_SECRET_KEY_FORMAT");
    expect(outcome.failure.step).toBe(3);
  });
});
