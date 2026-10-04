// The ADR-021 builders end to end: each operation is built by the real code, validated by the real
// §35.1.1 validator, and then opened with real keys.
// §44.3: T1 (new account → Managed, escrow, no kits), T6 (the escrow slots open to what the account
// needs), T10/T11 (SWITCH_TO_MANAGED), T17 (SWITCH_TO_PRIVATE), T18 (RECOVERY_RESET in Managed).
// §44.5: after every operation, each new epoch is readable by the pending root's ACCOUNT and
// RECOVERY keys, and every activated key has an envelope for every epoch of the RequiredEpochSet.
import { beforeAll, describe, expect, it } from "vitest";
import { importEnvelopeDecryptKey } from "@nodra/crypto";
import type { EnvelopeOpeningKey } from "@nodra/crypto";
import type { EpochEnvelope, SecurityBundle } from "@nodra/encoding/records";
import { validateSecurityBundle } from "../src/bundle.js";
import type { AcceptedBundle, BundleState } from "../src/bundle.js";
import type { AccountView } from "../src/client-state.js";
import { requiredEpochSet } from "../src/coverage.js";
import { idKey } from "../src/epoch.js";
import type { CreatedEpoch } from "../src/epoch.js";
import { recoveryReset } from "../src/recovery-reset.js";
import { openEscrowedRecoveryKeys, verifyRecoveryKit } from "../src/recovery-kit.js";
import { verifyRootChain } from "../src/root-chain.js";
import { switchToManaged } from "../src/switch-to-managed.js";
import { switchToPrivate } from "../src/switch-to-private.js";
import { unlockForOperation, unlockSession } from "../src/unlock.js";
import { MANAGED_ACCOUNT_ID, escrowWorld, managedWorld, opensEpoch, unwrapSlot } from "./mode-support.js";
import type { ManagedWorld } from "./mode-support.js";
import { operationWorld, withMaturedRequest, withScopes } from "./operations-support.js";
import type { OperationWorld } from "./operations-support.js";
import { filled } from "./support.js";

let managed: ManagedWorld;
let priv: OperationWorld;

beforeAll(async () => {
  [managed, priv] = await Promise.all([managedWorld(), operationWorld()]);
}, 180_000);

async function accept(bundle: SecurityBundle, state: BundleState): Promise<AcceptedBundle> {
  const outcome = await validateSecurityBundle(bundle, state);
  if (!outcome.ok) throw new Error(`${outcome.failure.step} ${outcome.failure.code} ${outcome.failure.rule}: ${outcome.failure.message}`);
  if (outcome.value.kind !== "ACCEPT") throw new Error("expected ACCEPT");
  return outcome.value.accepted;
}

function newEpochIds(view: AccountView, tag: number): Map<string, Uint8Array> {
  return new Map(view.vaults.map((v, i) => [idKey(v.vaultId), filled(16, tag + i)]));
}

/** §44.5 "todo blob actual es descifrable por ACCOUNT y por RECOVERY", for the epochs just created. */
async function everyNewEpochReadableBy(epochs: readonly CreatedEpoch[], keys: readonly EnvelopeOpeningKey[]): Promise<boolean> {
  for (const epoch of epochs) for (const key of keys) if (!(await opensEpoch(epoch.envelopes, key))) return false;
  return true;
}

/**
 * §44.5 "ninguna clave que deba leer datos existentes se activa sin cobertura completa": every epoch
 * of the RequiredEpochSet has a coverage envelope that `key` actually opens.
 */
async function fullyCovered(view: AccountView, coverage: readonly EpochEnvelope[], key: EnvelopeOpeningKey): Promise<boolean> {
  for (const required of requiredEpochSet(view.vaults)) {
    const envelopes = coverage.filter((e) => idKey(e.vault_id) === idKey(required.vaultId) && idKey(e.epoch_id) === idKey(required.epochId));
    if (!(await opensEpoch(envelopes, key))) return false;
  }
  return true;
}

describe("T1: a new account is Managed, with escrow and without Setup Kit or Recovery Kit", () => {
  it("is accepted by §35.1.1 as a version-2 GENESIS carrying both slots", async () => {
    const created = managed.created;
    const empty: BundleState = { ...managed.state, authorization: { authenticated: true, emailConfirmed: true }, root: null, registry: null, configVersion: 0, vaults: [], escrow: null };
    const accepted = await accept(created.bundle, empty);
    expect(accepted.escrowChange).toEqual({ kind: "CREATE", escrow: created.escrow });
    expect(created.root.crypto_version).toBe(2);
    expect(created).not.toHaveProperty("setupKit");
    expect(created).not.toHaveProperty("recoveryKit");
    expect(created.profile).not.toHaveProperty("kdf_salt");
    expect(created.profile).not.toHaveProperty("argon2_params");
    const chain = await verifyRootChain([{ transition: created.rootTransition, descriptor: created.root }], { accountId: MANAGED_ACCOUNT_ID });
    expect(chain.ok && chain.value.mode).toBe("MANAGED");
  });

  it("zeroizes the RootUnlockKey bytes once derived and escrowed", () => {
    expect(managed.created.keyset.rootUnlockKey.every((b) => b === 0)).toBe(true);
  });

  it("E1 is readable by ACCOUNT and RECOVERY (§44.5)", async () => {
    const recovery = await importEnvelopeDecryptKey(managed.created.recoveryKeys.encryption.privateKeyPkcs8);
    expect(await everyNewEpochReadableBy([managed.created.epoch], [managed.created.keyset.encryption.privateKey, recovery])).toBe(true);
  });
});

describe("T6: the escrow of a Managed creation", () => {
  it("UNLOCK opens with the Escrow Key and yields keys that open the profile keyset and the config", async () => {
    const opened = await unwrapSlot(MANAGED_ACCOUNT_ID, managed.created.escrow.unlock!);
    if (opened.slot !== "UNLOCK") throw new Error("expected UNLOCK");
    const unlocked = await unlockForOperation({ accountId: MANAGED_ACCOUNT_ID, profile: managed.created.profile, rootUnlockKey: opened.rootUnlockBase });
    if (!unlocked.ok) throw new Error(unlocked.failure.code);
    expect(unlocked.value.config).toEqual(managed.created.config);
  });

  it("RECOVERY holds both Recovery privates of the root", async () => {
    const opened = await unwrapSlot(MANAGED_ACCOUNT_ID, managed.created.escrow.recovery!);
    if (opened.slot !== "RECOVERY") throw new Error("expected RECOVERY");
    const handles = await openEscrowedRecoveryKeys({ keys: opened.recoveryKeys, accountId: MANAGED_ACCOUNT_ID, currentDescriptor: managed.created.root });
    expect(handles.ok).toBe(true);
  });

  it("the Worker never receives a secret in clear: the bundle carries neither the RootUnlockKey nor a private", async () => {
    const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
    const bytes = hex(managed.created.serializedBundle);
    expect(bytes).not.toContain(hex(managed.created.recoveryKeys.authority.privateKeyPkcs8));
    expect(bytes).not.toContain(hex(managed.created.recoveryKeys.encryption.privateKeyPkcs8).slice(0, 200));
  });
});

describe("T18: RECOVERY_RESET in Managed", () => {
  it("replaces only the UNLOCK slot, keeps RECOVERY, and the new keys read the old epochs", async () => {
    const opened = await unwrapSlot(MANAGED_ACCOUNT_ID, managed.created.escrow.recovery!);
    if (opened.slot !== "RECOVERY") throw new Error("expected RECOVERY");
    const recovery = await openEscrowedRecoveryKeys({ keys: opened.recoveryKeys, accountId: MANAGED_ACCOUNT_ID, currentDescriptor: managed.view.root });
    if (!recovery.ok) throw new Error(recovery.failure.code);
    const { escrowKey } = await escrowWorld();
    const reset = await recoveryReset({
      view: managed.view,
      bundleId: filled(16, 0x81),
      recovery: recovery.value,
      escrowKey,
      newEpochIds: newEpochIds(managed.view, 0x82),
      sources: managed.recoverySources,
      ports: managed.ports,
    });
    if (!reset.ok) throw new Error(reset.failure.code);
    const r = reset.value;
    expect(r.epochs).toHaveLength(managed.view.vaults.length);
    expect(r.setupKit).toBeUndefined();
    expect(r.escrow?.unlock).toBeDefined();
    expect(r.escrow?.recovery).toBeUndefined();
    const accepted = await accept(r.bundle, withScopes(managed.state, ["RECOVERY_CONTROL"]));
    expect(accepted.escrowChange).toEqual({ kind: "REPLACE", escrow: r.escrow });

    // The new UNLOCK slot opens the new profile.
    const newUnlock = await unwrapSlot(MANAGED_ACCOUNT_ID, r.escrow!.unlock!);
    if (newUnlock.slot !== "UNLOCK") throw new Error("expected UNLOCK");
    expect((await unlockSession({ accountId: MANAGED_ACCOUNT_ID, profile: r.profile, rootUnlockKey: newUnlock.rootUnlockBase })).ok).toBe(true);
    // The kept RECOVERY slot still matches the new root (its keys did not change).
    expect((await openEscrowedRecoveryKeys({ keys: opened.recoveryKeys, accountId: MANAGED_ACCOUNT_ID, currentDescriptor: r.root })).ok).toBe(true);
    // Old blobs stay readable: the new ACCOUNT key opens a coverage envelope of every old epoch.
    expect(await fullyCovered(managed.view, r.coverageEnvelopes, r.keyset.encryption.privateKey)).toBe(true);
    // §44.5 over the new epochs.
    expect(await everyNewEpochReadableBy(r.epochs, [r.keyset.encryption.privateKey, recovery.value.encryptionKey])).toBe(true);
  });
});

describe("T17: SWITCH_TO_PRIVATE", () => {
  it("is accepted, deletes the escrow, and the old account private opens no envelope of the new epochs", async () => {
    const switched = await switchToPrivate({
      view: managed.view,
      bundleId: filled(16, 0x91),
      keys: { operationKey: managed.created.keyset.encryption.privateKey, signingKey: managed.created.keyset.signing.privateKey },
      password: "a new encryption password",
      newEpochIds: newEpochIds(managed.view, 0x92),
      sources: managed.sources,
      ports: managed.ports,
    });
    if (!switched.ok) throw new Error(switched.failure.code);
    const s = switched.value;
    expect(s.epochs).toHaveLength(managed.view.vaults.length);
    const accepted = await accept(s.bundle, managed.state);
    expect(accepted.escrowChange).toEqual({ kind: "DELETE" });

    const chain = await verifyRootChain([{ transition: s.rootTransition, descriptor: s.root }], { accountId: MANAGED_ACCOUNT_ID, from: managed.state.root! });
    expect(chain.ok && chain.value.mode).toBe("PRIVATE");

    const oldAccount = managed.created.keyset.encryption.privateKey;
    const oldRecovery = await importEnvelopeDecryptKey(managed.created.recoveryKeys.encryption.privateKeyPkcs8);
    for (const epoch of s.epochs) {
      expect(await opensEpoch(epoch.envelopes, oldAccount)).toBe(false);
      expect(await opensEpoch(epoch.envelopes, oldRecovery)).toBe(false);
    }
    // The new keys read everything: new epochs directly, old ones through the coverage (§44.5).
    const newRecovery = await importEnvelopeDecryptKey(s.recoveryKit.kit.recovery_encryption_private_key);
    expect(await everyNewEpochReadableBy(s.epochs, [s.keyset.encryption.privateKey, newRecovery])).toBe(true);
    expect(await fullyCovered(managed.view, s.coverageEnvelopes, s.keyset.encryption.privateKey)).toBe(true);
    expect(await fullyCovered(managed.view, s.coverageEnvelopes, newRecovery)).toBe(true);

    // The new secrets unlock the new Private profile, and the kit verifies against the new root.
    const unlocked = await unlockSession({
      accountId: MANAGED_ACCOUNT_ID,
      profile: s.profile,
      secrets: { password: "a new encryption password", secretKey: s.setupKit.accountSecretKey },
      ports: managed.ports,
    });
    expect(unlocked.ok).toBe(true);
    expect((await verifyRecoveryKit({ serialized: s.recoveryKit.serialized, accountId: MANAGED_ACCOUNT_ID, currentDescriptor: s.root })).ok).toBe(true);
  }, 120_000);
});

describe("T10/T11: SWITCH_TO_MANAGED", () => {
  it("keeps the account keys, installs new Recovery keys with full coverage, and takes the root to version 2", async () => {
    const { escrowKey } = await escrowWorld();
    const switched = await switchToManaged({
      view: priv.view,
      bundleId: filled(16, 0xa1),
      keys: { encryptionKey: priv.created.keyset.encryption.privateKey, signingKey: priv.created.keyset.signing.privateKey },
      escrowKey,
      newEpochIds: newEpochIds(priv.view, 0xa2),
      sources: priv.sources,
      ports: priv.ports,
    });
    if (!switched.ok) throw new Error(switched.failure.code);
    const s = switched.value;
    expect(s.epochs).toHaveLength(priv.view.vaults.length);
    const accepted = await accept(s.bundle, withMaturedRequest(priv.state, "SWITCH_TO_MANAGED"));
    expect(accepted.escrowChange).toEqual({ kind: "CREATE", escrow: s.escrow });

    expect(priv.view.root.crypto_version).toBe(1);
    expect(s.root.crypto_version).toBe(2);
    expect(Buffer.from(s.root.account_encryption_public_key).equals(Buffer.from(priv.view.root.account_encryption_public_key))).toBe(true);
    expect(Buffer.from(s.root.account_signing_public_key).equals(Buffer.from(priv.view.root.account_signing_public_key))).toBe(true);
    const chain = await verifyRootChain([{ transition: s.rootTransition, descriptor: s.root }], { accountId: priv.accountId, from: priv.state.root! });
    expect(chain.ok && chain.value.mode).toBe("MANAGED");

    // The new epochs are version 2 and readable by the ACCOUNT in force and the new RECOVERY (§44.5).
    expect(s.epochs.every((e) => e.descriptor.crypto_version === 2)).toBe(true);
    expect(await everyNewEpochReadableBy(s.epochs, [priv.created.keyset.encryption.privateKey, s.recoveryKeys.encryption.privateKey])).toBe(true);
    expect(await fullyCovered(priv.view, s.coverageEnvelopes, s.recoveryKeys.encryption.privateKey)).toBe(true);

    // T11: the old kit opens no envelope of the new epochs, and still opens the old ones.
    const oldKit = await importEnvelopeDecryptKey(priv.recoveryKit.recovery_encryption_private_key);
    for (const epoch of s.epochs) expect(await opensEpoch(epoch.envelopes, oldKit)).toBe(false);
    for (const source of priv.recoverySources) expect(await opensEpoch([source.envelope], oldKit)).toBe(true);
    // T10: the old kit no longer matches the root (it cannot sign role 3 of a future transition).
    const verified = await verifyRecoveryKit({ serialized: priv.created.recoveryKit.serialized, accountId: priv.accountId, currentDescriptor: s.root });
    expect(verified.ok).toBe(false);

    // The escrow opens the account: UNLOCK → the Managed profile; RECOVERY → the new Recovery keys.
    const unlock = await unwrapSlot(priv.accountId, s.escrow.unlock!);
    if (unlock.slot !== "UNLOCK") throw new Error("expected UNLOCK");
    expect((await unlockSession({ accountId: priv.accountId, profile: s.profile, rootUnlockKey: unlock.rootUnlockBase })).ok).toBe(true);
    const recovery = await unwrapSlot(priv.accountId, s.escrow.recovery!);
    if (recovery.slot !== "RECOVERY") throw new Error("expected RECOVERY");
    expect((await openEscrowedRecoveryKeys({ keys: recovery.recoveryKeys, accountId: priv.accountId, currentDescriptor: s.root })).ok).toBe(true);
    // The old secrets no longer open the new profile.
    const stale = await unlockSession({
      accountId: priv.accountId,
      profile: s.profile,
      secrets: { password: "correct horse battery staple", secretKey: priv.created.setupKit.accountSecretKey },
      ports: priv.ports,
    });
    expect(stale.ok).toBe(false);
  }, 120_000);
});
