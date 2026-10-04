// Broken-variant proofs for §35.1.1.
//
// A rule is only worth its code if a *plausible* implementation without it gives a different, worse
// answer. Each variant below is a shortcut a competent implementer could reasonably take, written
// out here and run against the same inputs as `validateSecurityBundle`, so the difference is a
// value in a test rather than a claim in a comment.
import { beforeAll, describe, expect, it } from "vitest";
import type { SecurityBundle } from "@nodra/encoding/records";
import { REAUTH_WINDOW_SECONDS, validateSecurityBundle } from "../src/bundle.js";
import type { BundleState, StoredBundleResult } from "../src/bundle.js";
import { forbiddenFields, operationRules, requiredFields } from "../src/operations.js";
import type { OperationType } from "../src/operations.js";
import { signDeletion } from "../src/bundle-build.js";
import { checkCoverage, requiredEpochSet } from "../src/coverage.js";
import { rootRecipientId } from "../src/epoch.js";
import {
  VAULT_A,
  allScenarios,
  coverageFor,
  makeBundleWorld,
  makeEscrow,
  makeProfile,
  managedDeleteAccountScenario,
  managedRecoveryResetScenario,
  managedState,
  patch,
} from "./bundle-support.js";
import type { BundleWorld, Scenario } from "./bundle-support.js";
import { filled } from "./support.js";

let world: BundleWorld;
let scenarios: ReadonlyMap<OperationType, Scenario>;

beforeAll(async () => {
  world = await makeBundleWorld();
  scenarios = await allScenarios(world);
}, 120_000);

function scenario(type: OperationType): Scenario {
  const found = scenarios.get(type);
  if (found === undefined) throw new Error(`no scenario for ${type}`);
  return found;
}

// --- Variant (a): the steps evaluated out of order ------------------------------------------------

/**
 * **The idempotency shortcut.** "A replayed `bundle_id` already has an answer, so return it first
 * and skip the work." It looks strictly better — it is cheaper and it cannot be wrong about the
 * outcome, because the outcome is the one already computed. §35.1.1 puts the lookup at 0b, *after*
 * step 0, for one reason: the answer belongs to whoever had the scope for that operation.
 */
function storedResultFirst(bundle: SecurityBundle, state: BundleState): StoredBundleResult | null {
  const stored = state.storedResult;
  if (stored != null && stored.operationType === bundle.operation_type) return stored;
  return null;
}

/**
 * **The deletion block in the order a reader expects.** "Check the nonce first: it is the cheapest
 * and it is what makes the operation idempotent." §35.1.1 fixes the opposite order — state,
 * signature, nonce — and explains the consequence itself.
 */
function deletionNonceFirst(
  bundle: SecurityBundle,
  state: BundleState,
): "NONCE_REUSED" | "CONTINUE" {
  const nonce = bundle.deletion?.nonce;
  if (nonce === undefined) return "CONTINUE";
  return (state.consumedNonces ?? []).some((n) => n.every((b, i) => b === nonce[i])) ? "NONCE_REUSED" : "CONTINUE";
}

// --- Variant (b): a validator that checks only what must be there ----------------------------------

/**
 * **The "everything required is present" checker.** The applicability table reads as a list of
 * obligations, and checking obligations is the natural implementation: for each row, is every part
 * it names in the bundle? It is a complete reading of the "Contenido obligatorio" column and it
 * silently drops the column's other half — the **—** that says a part must *not* be there.
 */
function requiredOnly(bundle: SecurityBundle): boolean {
  const rules = operationRules(bundle.operation_type as OperationType);
  const record = bundle as unknown as Record<string, unknown>;
  return requiredFields(rules).every((name) => record[name] !== undefined);
}

describe("broken variant (a): a validator that evaluates the steps out of order", () => {
  it("leaks another session's stored result when the bundle_id lookup runs before the scope check", async () => {
    const { bundle, state } = scenario("REVOKE_CLIENT");
    // A session that holds only ACCOUNT_SECURITY: enough for ENROLL_CLIENT, never for REVOKE_CLIENT.
    const underScoped: BundleState = {
      ...state,
      authorization: { authenticated: true, emailConfirmed: true, token: { scopes: ["ACCOUNT_SECURITY"] } },
      storedResult: { operationType: "REVOKE_CLIENT", result: { revoked: "the other device" } },
    };

    // The shortcut hands the answer over.
    expect(storedResultFirst(bundle, underScoped)).toMatchObject({ result: { revoked: "the other device" } });

    // §35.1.1 stops at step 0 and never reads the stored row at all.
    const outcome = await validateSecurityBundle(bundle, underScoped);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.failure).toMatchObject({ step: "0", code: "SCOPE_REQUIRED" });
      // And because it is a step-0 code, nothing is stored and no nonce is spent: the same bundle
      // may legitimately be re-sent once the client obtains a token with the right scope.
      expect(outcome.failure.stored).toBe(false);
    }
  });

  it("spends the wrong answer when the deletion nonce is checked before the signature", async () => {
    const { bundle, state } = scenario("DELETE_VAULT");
    const nonce = bundle.deletion?.nonce as Uint8Array;
    const forged = patch(bundle, { deletion: { ...bundle.deletion, signature: filled(64, 0x00) } });
    const replayed: BundleState = { ...state, consumedNonces: [nonce] };

    // The shortcut answers NONCE_REUSED to a bundle whose signature is not even valid.
    expect(deletionNonceFirst(forged, replayed)).toBe("NONCE_REUSED");

    // §35.1.1 answers INVALID_SIGNATURE — its own worked example — so a forged bundle can never be
    // laundered into the benign-looking "you already did this" answer.
    const outcome = await validateSecurityBundle(forged, replayed);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.failure).toMatchObject({ code: "INVALID_SIGNATURE", rule: "deletion/signature" });
  });

  it("would answer a concurrency code where §35.1.1 answers a definitive one, and vice versa", async () => {
    // A bundle that is BOTH stale (CAS) and malformed (a forbidden sub-map). Checking the table
    // first would burn it definitively; §35.1.1's order gives the client the retryable answer,
    // because 0d comes before 7 and the client's own state is simply behind.
    const { bundle, state } = scenario("CREATE_VAULT");
    const both = patch(bundle, {
      expected: { ...bundle.expected, config_version: 99 },
      profile_signature: filled(64, 0x11),
    });
    const outcome = await validateSecurityBundle(both, state);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.failure).toMatchObject({ step: "0d", code: "SECURITY_STATE_STALE", retryable: true, stored: false });
    }
  });
});

describe("broken variant (b): a validator that accepts a sub-map the type forbids", () => {
  it("accepts a CREATE_VAULT carrying a signed deletion block", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    // A genuine, correctly signed DELETE_VAULT block smuggled into an operation whose row is "—"
    // for `deletion`. Nothing about it is forged: it would verify on its own.
    const smuggled = patch(bundle, {
      deletion: await signDeletion(world.as1.privateKey, {
        operationType: "DELETE_VAULT",
        accountId: world.accountId,
        vaultId: VAULT_A,
        rootGeneration: 1,
        nonce: filled(16, 0x91),
      }),
    });

    // The obligations-only checker sees every required part and waves it through.
    expect(requiredOnly(smuggled)).toBe(true);

    // §35.1.1 names the field it must not carry.
    const outcome = await validateSecurityBundle(smuggled, state);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.failure).toMatchObject({ step: "7", code: "INVALID_BUNDLE", rule: "applicability/forbidden:deletion" });
    }
  });

  it("accepts a bundle with the config in two places (§23.4, §44.3)", async () => {
    const { bundle, state } = scenario("CHANGE_SECRETS");
    // §23.4: with `profile` present, the config travels only inside it. A duplicate outside it
    // creates a second copy that `profile_signature` does not cover.
    const duplicated = patch(bundle, { config_blob: filled(64, 0x04), config_version: 2 });
    expect(requiredOnly(duplicated)).toBe(true);
    const outcome = await validateSecurityBundle(duplicated, state);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.failure.rule).toContain("forbidden:config_blob");
  });

  it("accepts a RECOVERY_RESET carrying a profile_signature it never had to produce", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    const extra = patch(bundle, { profile_signature: filled(64, 0x11) });
    expect(requiredOnly(extra)).toBe(true);
    const outcome = await validateSecurityBundle(extra, state);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.failure.rule).toContain("forbidden:profile_signature");
  });

  it("the two halves of the table really are different: every operation forbids something", () => {
    for (const type of scenarios.keys()) {
      const rules = operationRules(type);
      expect(forbiddenFields(rules).length, type).toBeGreaterThan(0);
      // And nothing is on both lists, which would make the table self-contradictory.
      const required = new Set(requiredFields(rules));
      for (const name of forbiddenFields(rules)) expect(required.has(name), `${type}/${name}`).toBe(false);
    }
  });

  it("a profile that is not the one the signature covers is rejected", async () => {
    const { bundle, state } = scenario("CHANGE_SECRETS");
    // Same shape, different bytes: the kdf_salt changed but the signature did not.
    const swapped = patch(bundle, { profile: { ...makeProfile(world.accountId, 2), kdf_salt: filled(16, 0x5b) } });
    expect(requiredOnly(swapped)).toBe(true);
    const outcome = await validateSecurityBundle(swapped, state);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.failure).toMatchObject({ code: "INVALID_SIGNATURE", rule: "profile-signature/invalid" });
  });
});

// --- Variant (c): ADR-021 shortcuts (§3.6, §35.1.1 steps 0c and 7) ---------------------------------

describe("broken variant (c): the protection mode, the escrow and the re-authentication", () => {
  let managedReset: Scenario;
  let managedDelete: Scenario;

  beforeAll(async () => {
    managedReset = await managedRecoveryResetScenario(world);
    managedDelete = await managedDeleteAccountScenario(world, REAUTH_WINDOW_SECONDS + 60);
  });

  async function failureOf(bundle: SecurityBundle, state: BundleState) {
    const outcome = await validateSecurityBundle(bundle, state);
    return outcome.ok ? null : outcome.failure;
  }

  it("taking the mode from the bundle (escrow present ⇒ Managed) lets a kit replacement through in Managed", async () => {
    const { bundle } = scenario("RECOVERY_KIT_REPLACEMENT");
    const state = managedState(world);
    // The shortcut: a kit replacement carries no escrow, so it must be a Private account.
    const modeFromBundle = bundle.escrow === undefined ? "PRIVATE" : "MANAGED";
    expect(modeFromBundle).toBe("PRIVATE");
    // §35.1.1 step 0c reads the mode from account_escrows.
    expect(await failureOf(bundle, state)).toMatchObject({ step: "0c", code: "NOT_APPLICABLE_IN_MANAGED" });
  });

  it("taking the mode from the root's crypto_version refuses a valid SWITCH_TO_PRIVATE", async () => {
    const { bundle, state } = scenario("SWITCH_TO_PRIVATE");
    // The shortcut: version 2 ⇔ Managed. This account has an escrow row on a version-1 root.
    const modeFromVersion = state.root?.descriptor.crypto_version === 2 ? "MANAGED" : "PRIVATE";
    expect(modeFromVersion).toBe("PRIVATE");
    expect(await failureOf(bundle, state)).toBeNull();
  });

  it("checking the re-authentication in the deletion block burns the nonce of a replay", async () => {
    const { bundle, state } = managedDelete;
    const replayed: BundleState = { ...state, consumedNonces: [bundle.deletion!.nonce] };
    // The shortcut would reach block (c) and answer NONCE_REUSED, which consumes and is stored.
    expect(deletionNonceFirst(bundle, replayed)).toBe("NONCE_REUSED");
    // §35.1: REAUTH_REQUIRED is retryable, not stored, and consumes nothing.
    expect(await failureOf(bundle, replayed)).toMatchObject({ code: "REAUTH_REQUIRED", retryable: true, stored: false, consumesNonce: false });
  });

  it("an escrow that is only *allowed* (not required) lets a Managed reset strand the new keyset", async () => {
    const { bundle, state } = managedReset;
    const withoutEscrow = patch(bundle, { escrow: undefined });
    // The shortcut: "escrow MAY travel on RECOVERY_RESET". Then the UNLOCK slot keeps the old
    // RootUnlockKey while the keyset is wrapped under the new one: nobody can unlock the account.
    const allowedOnly = operationRules("RECOVERY_RESET").escrow !== null || withoutEscrow.escrow === undefined;
    expect(allowedOnly).toBe(true);
    expect(await failureOf(withoutEscrow, state)).toMatchObject({ code: "INVALID_BUNDLE", rule: "escrow/presence" });
  });

  it("accepting any slot subset lets a Managed reset overwrite the RECOVERY slot", async () => {
    const { bundle, state } = managedReset;
    const both = patch(bundle, { escrow: makeEscrow(world.accountId, { unlock: true, recovery: true }) });
    const anySubset = both.escrow?.unlock !== undefined || both.escrow?.recovery !== undefined;
    expect(anySubset).toBe(true);
    expect(await failureOf(both, state)).toMatchObject({ code: "INVALID_BUNDLE", rule: "escrow/slots" });
  });

  it("requiring kdf_salt on every profile refuses SWITCH_TO_MANAGED; never checking it lets a Managed reset keep Private KDF fields", async () => {
    const managed = scenario("SWITCH_TO_MANAGED");
    const alwaysKdf = managed.bundle.profile?.kdf_salt !== undefined;
    expect(alwaysKdf).toBe(false); // the shortcut would reject this valid bundle
    expect(await failureOf(managed.bundle, managed.state)).toBeNull();

    const { bundle, state } = managedReset;
    const withKdf = patch(bundle, { profile: { ...bundle.profile!, kdf_salt: filled(16, 0x5a) } });
    expect(await failureOf(withKdf, state)).toMatchObject({ code: "INVALID_BUNDLE", rule: "profile/kdf-present" });
  });

  it("an operation table that forgets CHANGE_SECRETS in Managed lets it through with a Managed-shaped profile", async () => {
    const secrets = scenario("CHANGE_SECRETS");
    expect(operationRules("CHANGE_SECRETS").inManaged).toBe("NOT_APPLICABLE");
    expect(await failureOf(secrets.bundle, managedState(world, secrets.state))).toMatchObject({ step: "0c", code: "NOT_APPLICABLE_IN_MANAGED" });
  });

  it("one added reading key per operation lets SWITCH_TO_PRIVATE activate a RECOVERY key without coverage", async () => {
    const { bundle, state } = scenario("SWITCH_TO_PRIVATE");
    const accountOnly = coverageFor(world, await rootRecipientId(world.newAccountEncryption), "ACCOUNT");
    const partial = patch(bundle, { coverage_envelopes: accountOnly });
    // The shortcut covers the one key RECOVERY_RESET adds, and the partial set matches it exactly.
    const oneKey = checkCoverage({
      required: requiredEpochSet(state.vaults.map((v) => ({ vaultId: v.vaultId, state: v.state, epochs: v.epochs }))),
      recipients: [{ recipientId: await rootRecipientId(world.newAccountEncryption), type: "ACCOUNT" }],
      envelopes: accountOnly,
    });
    expect(oneKey.ok).toBe(true);
    expect(await failureOf(partial, state)).toMatchObject({ code: "COVERAGE_STALE" });
  });
});
