// §35.1.1 for the ADR-021 protection modes: the mode read in step 0c, the escrow and profile rules of
// step 7, the two switch rows and REAUTH_REQUIRED. Every negative starts from a bundle that passes.
// §44.3: T3 (switch from the wrong mode → INVALID_STATE), T4/T11 (a switch without a new epoch for a
// vault → VAULT_SET_STALE), T5 (escrow where it does not belong → INVALID_BUNDLE), T9 (kit replacement
// in Managed → NOT_APPLICABLE_IN_MANAGED) and T13 (DELETE_ACCOUNT in Managed without a recent
// re-authentication → REAUTH_REQUIRED, nonce not consumed).
import { beforeAll, describe, expect, it } from "vitest";
import type { SecurityBundle } from "@nodra/encoding/records";
import { REAUTH_WINDOW_SECONDS, validateSecurityBundle } from "../src/bundle.js";
import type { AcceptedBundle, BundleFailure, BundleState } from "../src/bundle.js";
import { signProfileUpdate } from "../src/bundle-build.js";
import { rootRecipientId } from "../src/epoch.js";
import { nextRegistry, registryHash, signRegistry } from "../src/registry.js";
import { rootHash } from "../src/root-chain.js";
import type { OperationType } from "../src/operations.js";
import {
  BROWSER_ID,
  allScenarios,
  coverageFor,
  makeBundleWorld,
  makeEscrow,
  makeManagedProfile,
  makeProfile,
  managedCreateAccountScenario,
  managedDeleteAccountScenario,
  managedRecoveryResetScenario,
  managedState,
  patch,
  rotateAll,
} from "./bundle-support.js";
import type { BundleWorld, Scenario } from "./bundle-support.js";
import { filled } from "./support.js";

let world: BundleWorld;
let scenarios: ReadonlyMap<OperationType, Scenario>;
let managedCreate: Scenario;
let managedReset: Scenario;

beforeAll(async () => {
  world = await makeBundleWorld();
  scenarios = await allScenarios(world);
  managedCreate = await managedCreateAccountScenario(world);
  managedReset = await managedRecoveryResetScenario(world);
}, 120_000);

function scenario(type: OperationType): Scenario {
  const found = scenarios.get(type);
  if (found === undefined) throw new Error(`no scenario for ${type}`);
  return found;
}

async function reject(bundle: SecurityBundle, state: BundleState): Promise<BundleFailure> {
  const outcome = await validateSecurityBundle(bundle, state);
  if (outcome.ok) throw new Error(`expected a rejection, got ${outcome.value.kind}`);
  return outcome.failure;
}

async function accept(bundle: SecurityBundle, state: BundleState): Promise<AcceptedBundle> {
  const outcome = await validateSecurityBundle(bundle, state);
  if (!outcome.ok) throw new Error(`${outcome.failure.step} ${outcome.failure.code} ${outcome.failure.rule}: ${outcome.failure.message}`);
  if (outcome.value.kind !== "ACCEPT") throw new Error("expected ACCEPT");
  return outcome.value.accepted;
}

const BOTH = () => makeEscrow(world.accountId, { unlock: true, recovery: true });
const UNLOCK = () => makeEscrow(world.accountId, { unlock: true });

describe("positives, and what step 8 must do to account_escrows", () => {
  it("SWITCH_TO_PRIVATE on a Managed account: the row is deleted", async () => {
    const { bundle, state } = scenario("SWITCH_TO_PRIVATE");
    expect((await accept(bundle, state)).escrowChange).toEqual({ kind: "DELETE" });
  });

  it("SWITCH_TO_MANAGED on a Private account: the row is created with both slots", async () => {
    const { bundle, state } = scenario("SWITCH_TO_MANAGED");
    expect((await accept(bundle, state)).escrowChange).toEqual({ kind: "CREATE", escrow: bundle.escrow });
  });

  it("CREATE_ACCOUNT in Managed (version-2 GENESIS): the row is created", async () => {
    const accepted = await accept(managedCreate.bundle, managedCreate.state);
    expect(accepted.escrowChange).toEqual({ kind: "CREATE", escrow: managedCreate.bundle.escrow });
  });

  it("RECOVERY_RESET in Managed: only the UNLOCK slot is replaced", async () => {
    const accepted = await accept(managedReset.bundle, managedReset.state);
    expect(accepted.escrowChange).toEqual({ kind: "REPLACE", escrow: managedReset.bundle.escrow });
    expect(managedReset.bundle.escrow?.recovery).toBeUndefined();
  });

  it("every other operation leaves the row alone", async () => {
    for (const [type, { bundle, state }] of scenarios) {
      if (type === "SWITCH_TO_PRIVATE" || type === "SWITCH_TO_MANAGED") continue;
      expect((await accept(bundle, state)).escrowChange, type).toBeNull();
    }
  });
});

describe("T3: step 0c — a switch from the wrong mode is INVALID_STATE", () => {
  it("SWITCH_TO_PRIVATE on an account without escrow", async () => {
    const { bundle } = scenario("SWITCH_TO_PRIVATE");
    const failure = await reject(bundle, world.state);
    expect(failure).toMatchObject({ step: "0c", code: "INVALID_STATE", rule: "mode/wrong-mode", stored: true, retryable: false, consumesNonce: false });
  });

  it("SWITCH_TO_MANAGED on an account with escrow", async () => {
    const { bundle, state } = scenario("SWITCH_TO_MANAGED");
    const failure = await reject(bundle, managedState(world, state));
    expect(failure).toMatchObject({ step: "0c", code: "INVALID_STATE", rule: "mode/wrong-mode", stored: true });
  });

  it("is decided before the CAS: a stale switch from the wrong mode is still INVALID_STATE", async () => {
    const { bundle } = scenario("SWITCH_TO_MANAGED");
    const failure = await reject(bundle, { ...managedState(world), configVersion: 7 });
    expect(failure.code).toBe("INVALID_STATE");
  });

  it("the switches need TRUSTED_SECURITY (step 0)", async () => {
    for (const type of ["SWITCH_TO_PRIVATE", "SWITCH_TO_MANAGED"] as const) {
      const { bundle, state } = scenario(type);
      const failure = await reject(bundle, { ...state, authorization: { authenticated: true, token: { scopes: ["ACCOUNT_SECURITY"] } } });
      expect(failure).toMatchObject({ step: "0", code: "SCOPE_REQUIRED" });
    }
  });
});

describe("§44.5: CREATE_ACCOUNT over a leftover account_escrows row", () => {
  it("is INVALID_STATE in both modes, so no account starts with an escrow its root does not justify", async () => {
    for (const { bundle, state } of [scenario("CREATE_ACCOUNT"), managedCreate]) {
      expect(await reject(bundle, managedState(world, state))).toMatchObject({ step: "0c", code: "INVALID_STATE", rule: "account/has-escrow" });
    }
  });
});

describe("T9: RECOVERY_KIT_REPLACEMENT on a Managed account", () => {
  it("is NOT_APPLICABLE_IN_MANAGED, definitive and stored, from step 0c", async () => {
    const { bundle, state } = scenario("RECOVERY_KIT_REPLACEMENT");
    const failure = await reject(bundle, managedState(world, state));
    expect(failure).toMatchObject({ step: "0c", code: "NOT_APPLICABLE_IN_MANAGED", retryable: false, stored: true, consumesNonce: false });
  });
});

describe("CHANGE_SECRETS on a Managed account (§35.1, §35.6)", () => {
  const NOT_APPLICABLE = { step: "0c", code: "NOT_APPLICABLE_IN_MANAGED", rule: "mode/not-applicable", retryable: false, stored: true, consumesNonce: false };

  it("is NOT_APPLICABLE_IN_MANAGED from step 0c, even with a Managed-shaped profile correctly signed", async () => {
    const { bundle, state } = scenario("CHANGE_SECRETS");
    // Without KDF fields, step 7 has nothing to object to: only the explicit rule can reject it.
    const profile = makeManagedProfile(world.accountId, 2);
    const profile_signature = await signProfileUpdate(world.as1.privateKey, world.accountId, 1, profile);
    const wellFormed = patch(bundle, { profile, profile_signature });
    expect(await reject(wellFormed, managedState(world, state))).toMatchObject(NOT_APPLICABLE);
  });

  it("the Private-shaped bundle gets the same code, decided before step 7", async () => {
    const { bundle, state } = scenario("CHANGE_SECRETS");
    expect(await reject(bundle, managedState(world, state))).toMatchObject(NOT_APPLICABLE);
  });

  it("a Private account keeps CHANGE_SECRETS as it was", async () => {
    const { bundle, state } = scenario("CHANGE_SECRETS");
    await accept(bundle, state);
  });
});

describe("T13: DELETE_ACCOUNT on a Managed account needs a re-authentication of at most 5 minutes", () => {
  it("accepts an authentication exactly 5 minutes old", async () => {
    const { bundle, state } = await managedDeleteAccountScenario(world, REAUTH_WINDOW_SECONDS);
    await accept(bundle, state);
  });

  it("answers REAUTH_REQUIRED, retryable, not stored, nonce not consumed, when older or unknown", async () => {
    for (const age of [REAUTH_WINDOW_SECONDS + 1, 86_400, undefined]) {
      const { bundle, state } = await managedDeleteAccountScenario(world, age);
      const failure = await reject(bundle, state);
      expect(failure).toMatchObject({ code: "REAUTH_REQUIRED", retryable: true, stored: false, consumesNonce: false });
    }
  });

  it("a Private account keeps §35.12 as it was: no age needed", async () => {
    const { bundle, state } = scenario("DELETE_ACCOUNT");
    expect(state.authorization.primaryAuthAgeSeconds).toBeUndefined();
    await accept(bundle, state);
  });

  it("only DELETE_ACCOUNT asks for it: CANCEL_DELETE_ACCOUNT in Managed does not", async () => {
    const { bundle, state } = scenario("CANCEL_DELETE_ACCOUNT");
    await accept(bundle, managedState(world, state));
  });
});

describe("T4/T11: a switch without a new epoch for a live vault is VAULT_SET_STALE", () => {
  it("holds for both switches", async () => {
    for (const type of ["SWITCH_TO_PRIVATE", "SWITCH_TO_MANAGED"] as const) {
      const { bundle, state } = scenario(type);
      const failure = await reject(patch(bundle, { epochs: (bundle.epochs ?? []).slice(1) }), state);
      expect(failure, type).toMatchObject({ step: "7", code: "VAULT_SET_STALE", retryable: true, stored: false });
    }
  });
});

describe("T5: step 7 — escrow only where §35.1.1 allows it", () => {
  it("any operation whose row has no escrow rejects it", async () => {
    for (const type of ["ENROLL_CLIENT", "CREATE_VAULT", "REVOKE_CLIENT", "CHANGE_SECRETS", "RECOVERY_KIT_REPLACEMENT", "DELETE_VAULT", "DELETE_ACCOUNT", "SWITCH_TO_PRIVATE"] as const) {
      const { bundle, state } = scenario(type);
      const failure = await reject(patch(bundle, { escrow: BOTH() }), state);
      expect(failure, type).toMatchObject({ step: "7", code: "INVALID_BUNDLE" });
    }
  });

  it("CREATE_ACCOUNT with a version-1 GENESIS (Private) and RECOVERY_RESET of a Private account reject it", async () => {
    const create = scenario("CREATE_ACCOUNT");
    expect(await reject(patch(create.bundle, { escrow: BOTH() }), create.state)).toMatchObject({ code: "INVALID_BUNDLE", rule: "escrow/presence" });
    const reset = scenario("RECOVERY_RESET");
    expect(await reject(patch(reset.bundle, { escrow: UNLOCK() }), reset.state)).toMatchObject({ code: "INVALID_BUNDLE", rule: "escrow/presence" });
  });

  it("the Managed rows require it", async () => {
    for (const { bundle, state } of [scenario("SWITCH_TO_MANAGED"), managedCreate, managedReset]) {
      const failure = await reject(patch(bundle, { escrow: undefined }), state);
      expect(failure).toMatchObject({ step: "7", code: "INVALID_BUNDLE" });
    }
  });

  it("CREATE_ACCOUNT and SWITCH_TO_MANAGED carry both slots; RECOVERY_RESET only UNLOCK", async () => {
    for (const { bundle, state } of [scenario("SWITCH_TO_MANAGED"), managedCreate]) {
      for (const escrow of [UNLOCK(), makeEscrow(world.accountId, { recovery: true }), makeEscrow(world.accountId, {})]) {
        expect(await reject(patch(bundle, { escrow }), state)).toMatchObject({ code: "INVALID_BUNDLE", rule: "escrow/slots" });
      }
    }
    for (const escrow of [BOTH(), makeEscrow(world.accountId, { recovery: true }), makeEscrow(world.accountId, {})]) {
      expect(await reject(patch(managedReset.bundle, { escrow }), managedReset.state)).toMatchObject({ code: "INVALID_BUNDLE", rule: "escrow/slots" });
    }
  });

  it("each slot names its own slot and carries payload_blob iff RECOVERY", async () => {
    const { bundle, state } = scenario("SWITCH_TO_MANAGED");
    const good = BOTH();
    const broken = [
      { ...good, unlock: { ...good.unlock!, slot: "RECOVERY" as const } },
      { ...good, recovery: { ...good.recovery!, slot: "UNLOCK" as const } },
      { ...good, unlock: { ...good.unlock!, payload_blob: filled(40, 1) } },
      { ...good, recovery: { slot: "RECOVERY" as const, key_id: good.recovery!.key_id, wrapped_key: good.recovery!.wrapped_key } },
    ];
    for (const escrow of broken) {
      expect(await reject(patch(bundle, { escrow }), state)).toMatchObject({ code: "INVALID_BUNDLE", rule: "escrow/slots" });
    }
  });
});

describe("step 7 — the profile has kdf_salt and argon2_params iff the account ends Private", () => {
  it("a Managed ending with a KDF field is rejected", async () => {
    const managedEndings: Scenario[] = [scenario("SWITCH_TO_MANAGED"), managedCreate, managedReset];
    for (const { bundle, state } of managedEndings) {
      const withKdf = { ...bundle.profile!, kdf_salt: filled(16, 0x5a) };
      expect(await reject(patch(bundle, { profile: withKdf }), state)).toMatchObject({ code: "INVALID_BUNDLE", rule: "profile/kdf-present" });
    }
  });

  it("a Private ending without them is rejected", async () => {
    const { bundle, state } = scenario("SWITCH_TO_PRIVATE");
    expect(await reject(patch(bundle, { profile: makeManagedProfile(world.accountId, 2) }), state)).toMatchObject({
      code: "INVALID_BUNDLE",
      rule: "profile/kdf-absent",
    });
  });

});

describe("step 7 — the rest of the two switch rows", () => {
  it("SWITCH_TO_PRIVATE needs coverage for both new keys (COVERAGE_STALE otherwise)", async () => {
    const { bundle, state } = scenario("SWITCH_TO_PRIVATE");
    const account = coverageFor(world, await rootRecipientId(world.newAccountEncryption), "ACCOUNT");
    const recovery = coverageFor(world, await rootRecipientId(world.newRecoveryEncryption), "RECOVERY");
    for (const partial of [account, recovery]) {
      expect(await reject(patch(bundle, { coverage_envelopes: partial }), state)).toMatchObject({ code: "COVERAGE_STALE", retryable: true });
    }
  });

  it("SWITCH_TO_MANAGED needs coverage for the new RECOVERY key only", async () => {
    const { bundle, state } = scenario("SWITCH_TO_MANAGED");
    const extra = [...(bundle.coverage_envelopes ?? []), ...coverageFor(world, await rootRecipientId(world.accountEncryption), "ACCOUNT")];
    expect(await reject(patch(bundle, { coverage_envelopes: extra }), state)).toMatchObject({ code: "COVERAGE_STALE" });
  });

  it("SWITCH_TO_MANAGED needs a valid profile_signature; SWITCH_TO_PRIVATE must not carry one", async () => {
    const managed = scenario("SWITCH_TO_MANAGED");
    expect(await reject(patch(managed.bundle, { profile_signature: undefined }), managed.state)).toMatchObject({ code: "INVALID_BUNDLE" });
    const stranger = await signProfileUpdate(world.stranger.privateKey, world.accountId, 1, managed.bundle.profile!);
    expect(await reject(patch(managed.bundle, { profile_signature: stranger }), managed.state)).toMatchObject({ code: "INVALID_SIGNATURE" });
    const toPrivate = scenario("SWITCH_TO_PRIVATE");
    expect(await reject(patch(toPrivate.bundle, { profile_signature: filled(64, 1) }), toPrivate.state)).toMatchObject({ code: "INVALID_BUNDLE" });
  });

  it("both switches keep the recipient list identical", async () => {
    for (const [type, signer] of [["SWITCH_TO_PRIVATE", world.as2], ["SWITCH_TO_MANAGED", world.as1]] as const) {
      const { bundle, state } = scenario(type);
      // Correctly signed for the pending root, but it revokes a recipient.
      const registry = await signRegistry(await nextRegistry(world.registry, { revoke: [BROWSER_ID], rootGeneration: 2 }), signer.privateKey);
      const root = bundle.root_descriptor!;
      const epochs = await rotateAll(world, { root, rootHash: await rootHash(root), registry, registryHash: await registryHash(registry), signer });
      const failure = await reject(patch(bundle, { registry, epochs }), state);
      expect(failure, `${type} ${failure.rule}`).toMatchObject({ step: "7", code: "INVALID_REGISTRY", rule: "registry/unchanged" });
    }
  });

  it("a profile for a Private ending still goes through the ADR-004 limits", async () => {
    const { bundle, state } = scenario("SWITCH_TO_PRIVATE");
    const weak = { ...makeProfile(world.accountId, 2), argon2_params: { ...makeProfile(world.accountId, 2).argon2_params!, memory_kib: 8 } };
    expect(await reject(patch(bundle, { profile: weak }), state)).toMatchObject({ code: "INVALID_BUNDLE", rule: "profile/KDF_PARAMS_REJECTED" });
  });
});
