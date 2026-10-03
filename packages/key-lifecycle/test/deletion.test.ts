// §35.11 and §35.12: scheduling a deletion, and cancelling one.
//
// Every test here is about one thing — that the two directions cannot be confused. A deletion and
// its cancel travel with the same shape, over the same endpoint, differing only in a string that
// is *inside* the signed Context. The broken variant is therefore the obvious implementation
// mistake: reusing the signature. If it were accepted, anyone who saw a `DELETE_VAULT` bundle
// could replay its signature as the cancel (and, worse, replay a captured cancel's as a deletion),
// and the 14-day grace period would protect nobody.
import { describe, expect, it } from "vitest";
import { validateSecurityBundle } from "../src/bundle.js";
import type { BundleState } from "../src/bundle.js";
import { assembleBundle } from "../src/bundle-build.js";
import { expectedOf } from "../src/client-state.js";
import {
  cancelDeleteAccount,
  cancelDeleteVault,
  deleteAccount,
  deleteVault,
  operationsAllowedWhileAccountDeleting,
} from "../src/deletion.js";
import { enrollClient, prepareEnrollment } from "../src/enrollment.js";
import { idKey } from "../src/epoch.js";
import { filled } from "./support.js";
import { operationWorld, VAULT_A, VAULT_B, withScopes } from "./operations-support.js";

const DELETE_BUNDLE_ID = filled(16, 0x76);
const CANCEL_BUNDLE_ID = filled(16, 0x77);
const NONCE_A = filled(16, 0x81);
const NONCE_B = filled(16, 0x82);

/** The same account with one vault moved to `DELETING_SCHEDULED`, as §35.11 step 4 leaves it. */
function withVaultScheduled(state: BundleState, vaultId: Uint8Array): BundleState {
  return {
    ...state,
    vaults: state.vaults.map((vault) =>
      idKey(vault.vaultId) === idKey(vaultId) ? { ...vault, state: "DELETING_SCHEDULED" as const } : vault,
    ),
  };
}

describe("§35.11 DELETE_VAULT and its cancel", () => {
  it("is accepted, consumes its nonce, and carries only the deletion block", async () => {
    const world = await operationWorld();
    const scheduled = await deleteVault({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      vaultId: VAULT_A,
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    expect(scheduled.bundle.epochs).toBeUndefined();
    expect(scheduled.bundle.registry).toBeUndefined();
    expect(scheduled.bundle.coverage_envelopes).toBeUndefined();
    expect(scheduled.bundle.config_blob).toBeUndefined();
    expect(idKey(scheduled.deletion.vault_id as Uint8Array)).toBe(idKey(VAULT_A));

    const decision = await validateSecurityBundle(scheduled.bundle, world.state);
    expect(decision.ok).toBe(true);
    if (!decision.ok || decision.value.kind !== "ACCEPT") return;
    expect(decision.value.accepted.consumedNonce).not.toBeNull();
    expect(Array.from(decision.value.accepted.consumedNonce as Uint8Array)).toEqual(Array.from(NONCE_A));
    expect(decision.value.accepted.epochs).toHaveLength(0);
    // A deletion installs no config (§35.1.1's row is **—**), so the version in force must not
    // move: a step 8 that bumped it would break every client's pin and the next `expected` CAS.
    expect(decision.value.accepted.configVersion).toBe(world.state.configVersion);
  });

  it("reports what the client must stop doing while the vault is DELETING_SCHEDULED", async () => {
    const world = await operationWorld();
    const scheduled = await deleteVault({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      vaultId: VAULT_A,
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    expect(scheduled.effects).toEqual({
      vaultId: VAULT_A,
      vaultState: "DELETING_SCHEDULED",
      writesRejected: true,
    });
  });

  it("cancels it, with a new nonce, and restores the prior state", async () => {
    const world = await operationWorld();
    const state = withVaultScheduled(world.state, VAULT_A);
    const cancelled = await cancelDeleteVault({
      view: world.view,
      bundleId: CANCEL_BUNDLE_ID,
      vaultId: VAULT_A,
      nonce: NONCE_B,
      keys: { signingKey: world.keys.signingKey },
    });
    expect(cancelled.effects).toEqual({ vaultId: VAULT_A, vaultState: "ACTIVE", writesRejected: false });

    const decision = await validateSecurityBundle(cancelled.bundle, state);
    expect(decision.ok).toBe(true);
  });

  it("is INVALID_STATE when the precondition of §35.12's table does not hold", async () => {
    const world = await operationWorld();
    // DELETE_VAULT requires ACTIVE; the vault is already scheduled.
    const again = await deleteVault({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      vaultId: VAULT_A,
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    const decision = await validateSecurityBundle(again.bundle, withVaultScheduled(world.state, VAULT_A));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_STATE");
    // Step 7 (a), and the nonce is consumed all the same (§35.1.1).
    expect(decision.failure.step).toBe("7");
    expect(decision.failure.consumesNonce).toBe(true);
  });

  it("is INVALID_STATE, with the nonce consumed, when the vault is not this account's", async () => {
    const world = await operationWorld();
    const foreign = await deleteVault({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      vaultId: filled(16, 0x2f),
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    const decision = await validateSecurityBundle(foreign.bundle, world.state);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_STATE");
    expect(decision.failure.step).toBe("0c");
    expect(decision.failure.consumesNonce).toBe(true);
  });

  it("is NONCE_REUSED when the nonce was already consumed by this account", async () => {
    const world = await operationWorld();
    const scheduled = await deleteVault({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      vaultId: VAULT_A,
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    const decision = await validateSecurityBundle(scheduled.bundle, {
      ...world.state,
      consumedNonces: [NONCE_A],
    });
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("NONCE_REUSED");
  });

  it("is SECURITY_STATE_STALE when the root moved under the prepared deletion (step 0d)", async () => {
    const world = await operationWorld();
    const scheduled = await deleteVault({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      vaultId: VAULT_A,
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    const decision = await validateSecurityBundle(scheduled.bundle, {
      ...world.state,
      configVersion: world.state.configVersion + 1,
    });
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("SECURITY_STATE_STALE");
    expect(decision.failure.retryable).toBe(true);
  });
});

describe("§35.11 broken variants", () => {
  it("cannot reuse the DELETE_VAULT signature as its own cancel", async () => {
    const world = await operationWorld();
    const scheduled = await deleteVault({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      vaultId: VAULT_A,
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    // The confusion this test exists for: same account, same vault, same root — a client that
    // signed only the subject rather than the `operation_type` would produce exactly this, and an
    // attacker replaying it could re-arm (or silently cancel) the user's deletion.
    const replayed = assembleBundle({
      operationType: "CANCEL_DELETE_VAULT",
      bundleId: CANCEL_BUNDLE_ID,
      expected: expectedOf(world.view),
      deletion: scheduled.deletion,
    });
    const decision = await validateSecurityBundle(replayed, withVaultScheduled(world.state, VAULT_A));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_SIGNATURE");
    expect(decision.failure.retryable).toBe(false);
  });

  it("cannot move a signature from one vault to another", async () => {
    const world = await operationWorld();
    const forB = await deleteVault({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      vaultId: VAULT_B,
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    const retargeted = assembleBundle({
      operationType: "DELETE_VAULT",
      bundleId: DELETE_BUNDLE_ID,
      expected: expectedOf(world.view),
      deletion: { ...forB.deletion, vault_id: VAULT_A },
    });
    const decision = await validateSecurityBundle(retargeted, world.state);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_SIGNATURE");
  });

  it("rejects a DELETE_VAULT with no deletion block, consuming no nonce (NOTES 227)", async () => {
    const world = await operationWorld();
    const empty = assembleBundle({
      operationType: "DELETE_VAULT",
      bundleId: DELETE_BUNDLE_ID,
      expected: expectedOf(world.view),
    });
    const decision = await validateSecurityBundle(empty, world.state);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    // §35.1.1 step 0c reads the target out of `deletion.vault_id` *before* step 7's "campo
    // aplicable ausente" rule, so a bundle with no block at all answers the same `INVALID_STATE`
    // as one naming a foreign vault — which is the non-oracle answer 0c exists to give. Both are
    // definitive; there is no nonce to consume. Question 227.
    expect(decision.failure.retryable).toBe(false);
    expect(decision.failure.code).toBe("INVALID_STATE");
    expect(decision.failure.consumesNonce).toBe(false);
  });

  it("rejects a CANCEL_DELETE_ACCOUNT with no deletion block at step 7", async () => {
    const world = await operationWorld();
    const empty = assembleBundle({
      operationType: "CANCEL_DELETE_ACCOUNT",
      bundleId: CANCEL_BUNDLE_ID,
      expected: expectedOf(world.view),
    });
    const decision = await validateSecurityBundle(empty, {
      ...world.state,
      accountState: "DELETING_SCHEDULED",
    });
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_BUNDLE");
    expect(decision.failure.step).toBe("7");
  });

  it("is INVALID_BUNDLE when a deletion travels on an operation that carries none", async () => {
    const world = await operationWorld();
    const scheduled = await deleteVault({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      vaultId: VAULT_A,
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    const extra = assembleBundle({
      operationType: "CHANGE_SECRETS",
      bundleId: DELETE_BUNDLE_ID,
      expected: expectedOf(world.view),
      deletion: scheduled.deletion,
    });
    const decision = await validateSecurityBundle(extra, withScopes(world.state, ["ACCOUNT_SECURITY"]));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_BUNDLE");
  });
});

describe("§35.12 DELETE_ACCOUNT and its cancel", () => {
  it("is accepted and names no vault", async () => {
    const world = await operationWorld();
    const scheduled = await deleteAccount({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    expect(scheduled.deletion.vault_id).toBeUndefined();
    expect(scheduled.effects).toEqual({ accountState: "DELETING_SCHEDULED", writesRejected: true });

    const decision = await validateSecurityBundle(scheduled.bundle, world.state);
    expect(decision.ok).toBe(true);
  });

  it("cancels from DELETING_SCHEDULED, and ACCOUNT_SECURITY is enough (§35.12)", async () => {
    const world = await operationWorld();
    const cancelled = await cancelDeleteAccount({
      view: world.view,
      bundleId: CANCEL_BUNDLE_ID,
      nonce: NONCE_B,
      keys: { signingKey: world.keys.signingKey },
    });
    expect(cancelled.effects).toEqual({ accountState: "ACTIVE", writesRejected: false });

    const deleting: BundleState = {
      ...withScopes(world.state, ["ACCOUNT_SECURITY"]),
      accountState: "DELETING_SCHEDULED",
    };
    const decision = await validateSecurityBundle(cancelled.bundle, deleting);
    expect(decision.ok).toBe(true);
  });

  it("names the operations a DELETING_SCHEDULED account still accepts (§35.12 step 4, §35.15)", async () => {
    expect([...operationsAllowedWhileAccountDeleting()].sort()).toEqual([
      "CANCEL_DELETE_ACCOUNT",
      "ENROLL_CLIENT",
      "RECOVERY_CANCEL",
      "RECOVERY_REQUEST",
      "RECOVERY_RESET",
      "RECOVERY_VETO",
    ]);
  });

  it("still accepts an ENROLL_CLIENT while the deletion is scheduled (§35.12 step 4)", async () => {
    const world = await operationWorld();
    const browser = await prepareEnrollment({
      recipientId: filled(16, 0x69),
      type: "TRUSTED_BROWSER",
      label: "rescue browser",
    });
    const enrolled = await enrollClient({
      view: world.view,
      bundleId: filled(16, 0x78),
      recipient: browser.recipient,
      prover: browser.prover,
      keys: world.keys,
      sources: world.sources,
    });
    expect(enrolled.ok).toBe(true);
    if (!enrolled.ok) return;
    const decision = await validateSecurityBundle(enrolled.value.bundle, {
      ...world.state,
      accountState: "DELETING_SCHEDULED",
    });
    expect(decision.ok).toBe(true);
  });

  it("refuses a second DELETE_ACCOUNT while one is already scheduled", async () => {
    const world = await operationWorld();
    const again = await deleteAccount({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    const decision = await validateSecurityBundle(again.bundle, {
      ...world.state,
      accountState: "DELETING_SCHEDULED",
    });
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_STATE");
    expect(decision.failure.step).toBe("0c");
  });

  it("refuses everything once the account is DELETING (§35.12 step 5: irreversible)", async () => {
    const world = await operationWorld();
    const cancelled = await cancelDeleteAccount({
      view: world.view,
      bundleId: CANCEL_BUNDLE_ID,
      nonce: NONCE_B,
      keys: { signingKey: world.keys.signingKey },
    });
    const decision = await validateSecurityBundle(cancelled.bundle, {
      ...world.state,
      accountState: "DELETING",
    });
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_STATE");
  });

  it("is INVALID_BUNDLE when an account deletion names a vault", async () => {
    const world = await operationWorld();
    const scheduled = await deleteAccount({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    const named = assembleBundle({
      operationType: "DELETE_ACCOUNT",
      bundleId: DELETE_BUNDLE_ID,
      expected: expectedOf(world.view),
      deletion: { ...scheduled.deletion, vault_id: VAULT_A },
    });
    const decision = await validateSecurityBundle(named, world.state);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_BUNDLE");
  });
});

describe("§35.12 broken variants", () => {
  it("cannot reuse the DELETE_ACCOUNT signature as its cancel", async () => {
    const world = await operationWorld();
    const scheduled = await deleteAccount({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    const replayed = assembleBundle({
      operationType: "CANCEL_DELETE_ACCOUNT",
      bundleId: CANCEL_BUNDLE_ID,
      expected: expectedOf(world.view),
      deletion: scheduled.deletion,
    });
    const decision = await validateSecurityBundle(replayed, {
      ...world.state,
      accountState: "DELETING_SCHEDULED",
    });
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_SIGNATURE");
  });

  it("cannot present an account deletion as a vault deletion", async () => {
    const world = await operationWorld();
    const scheduled = await deleteAccount({
      view: world.view,
      bundleId: DELETE_BUNDLE_ID,
      nonce: NONCE_A,
      keys: { signingKey: world.keys.signingKey },
    });
    const asVault = assembleBundle({
      operationType: "DELETE_VAULT",
      bundleId: DELETE_BUNDLE_ID,
      expected: expectedOf(world.view),
      deletion: { ...scheduled.deletion, vault_id: VAULT_A },
    });
    const decision = await validateSecurityBundle(asVault, world.state);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_SIGNATURE");
  });
});
