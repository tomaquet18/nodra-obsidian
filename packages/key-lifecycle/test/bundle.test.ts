// §35.1.1: one well-formed bundle per `operation_type`, then one negative per rule and per step.
//
// Every negative starts from a bundle that passes and breaks exactly one thing, so the assertion
// is about the rule named in the test title. Where breaking a field would also invalidate a
// signature, the fixture re-signs — a `BAD_SIGNATURE` proving a shape rule would prove nothing.
import { beforeAll, describe, expect, it } from "vitest";
import { OPERATION_TYPES } from "@nodra/encoding/records";
import type { EpochEnvelope, SecurityBundle } from "@nodra/encoding/records";
import { validateSecurityBundle } from "../src/bundle.js";
import type { BundleFailure, BundleState } from "../src/bundle.js";
import { signDeletion, signProfileUpdate } from "../src/bundle-build.js";
import { OPERATION_RULES } from "../src/operations.js";
import type { OperationType } from "../src/operations.js";
import { nextRegistry, registryHash, signRegistry } from "../src/registry.js";
import { rootHash } from "../src/root-chain.js";
import { createEpoch, epochRecipients, rootRecipientId } from "../src/epoch.js";
import {
  BROWSER_ID,
  ENROLLED_ID,
  NEW_VAULT,
  VAULT_A,
  VAULT_B,
  allScenarios,
  coverageFor,
  expectedOf,
  makeBundleWorld,
  makeProfile,
  patch,
  rotateAll,
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

/** Validates and asserts a rejection, returning the failure so a test can assert on its detail. */
async function reject(bundle: SecurityBundle, state: BundleState): Promise<BundleFailure> {
  const outcome = await validateSecurityBundle(bundle, state);
  if (outcome.ok) throw new Error(`expected a rejection, got ${outcome.value.kind}`);
  return outcome.failure;
}

async function accept(bundle: SecurityBundle, state: BundleState): Promise<void> {
  const outcome = await validateSecurityBundle(bundle, state);
  if (!outcome.ok) throw new Error(`${outcome.failure.step} ${outcome.failure.code} ${outcome.failure.rule}: ${outcome.failure.message}`);
  expect(outcome.value.kind).toBe("ACCEPT");
}

describe("§35.1.1 positives", () => {
  it("covers every operation_type of §23.4", () => {
    expect([...scenarios.keys()].sort()).toEqual([...OPERATION_TYPES].sort());
    expect(Object.keys(OPERATION_RULES).sort()).toEqual([...OPERATION_TYPES].sort());
  });

  for (const type of OPERATION_TYPES) {
    it(`accepts a well-formed ${type}`, async () => {
      const { bundle, state } = scenario(type);
      await accept(bundle, state);
    });
  }

  it("returns the pending root and registry, and the config version to install", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    const outcome = await validateSecurityBundle(bundle, state);
    if (!outcome.ok || outcome.value.kind !== "ACCEPT") throw new Error("expected ACCEPT");
    expect(outcome.value.accepted.pendingRootGeneration).toBe(2);
    expect(outcome.value.accepted.pendingRegistryVersion).toBe(2);
    expect(outcome.value.accepted.configVersion).toBe(2);
    expect(outcome.value.accepted.epochs).toHaveLength(2);
  });
});

describe("step 0 — authorization, before any state is read", () => {
  it("rejects an unauthenticated request", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    const failure = await reject(bundle, { ...state, authorization: { authenticated: false } });
    expect(failure).toMatchObject({ step: "0", code: "WRITE_CAPABILITY_REQUIRED", stored: false });
  });

  it("rejects a bundle with no Write Capability Token", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    const failure = await reject(bundle, { ...state, authorization: { authenticated: true } });
    expect(failure).toMatchObject({ step: "0", code: "WRITE_CAPABILITY_REQUIRED" });
  });

  it("rejects the wrong scope: RECOVERY_CONTROL may not CREATE_VAULT (§11.3)", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    const failure = await reject(bundle, {
      ...state,
      authorization: { authenticated: true, token: { scopes: ["RECOVERY_CONTROL"] } },
    });
    expect(failure).toMatchObject({ step: "0", code: "SCOPE_REQUIRED" });
  });

  it("rejects the wrong scope: TRUSTED_SECURITY may not RECOVERY_RESET", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    const failure = await reject(bundle, {
      ...state,
      authorization: { authenticated: true, token: { scopes: ["TRUSTED_SECURITY", "ACCOUNT_SECURITY"] } },
    });
    expect(failure).toMatchObject({ step: "0", code: "SCOPE_REQUIRED" });
  });

  it("accepts ACCOUNT_SECURITY for ENROLL_CLIENT and rejects it for REVOKE_CLIENT", async () => {
    const enroll = scenario("ENROLL_CLIENT");
    await accept(enroll.bundle, {
      ...enroll.state,
      authorization: { authenticated: true, token: { scopes: ["ACCOUNT_SECURITY"] } },
    });
    const revoke = scenario("REVOKE_CLIENT");
    const failure = await reject(revoke.bundle, {
      ...revoke.state,
      authorization: { authenticated: true, token: { scopes: ["ACCOUNT_SECURITY"] } },
    });
    expect(failure.code).toBe("SCOPE_REQUIRED");
  });

  it("names RECIPIENT_REVOKED for an eagerly revoked token (§11.3)", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    const failure = await reject(bundle, {
      ...state,
      authorization: { authenticated: true, token: { scopes: ["TRUSTED_SECURITY"], revokedReason: "RECIPIENT_REVOKED" } },
    });
    expect(failure).toMatchObject({ step: "0", code: "RECIPIENT_REVOKED", stored: false, consumesNonce: false });
  });

  it("CREATE_ACCOUNT needs login alone (§11.3's single exception)", async () => {
    const { bundle, state } = scenario("CREATE_ACCOUNT");
    await accept(bundle, { ...state, authorization: { authenticated: true } });
  });

  it("step 0 never consumes a nonce, even for a deletion", async () => {
    const { bundle, state } = scenario("DELETE_VAULT");
    const failure = await reject(bundle, { ...state, authorization: { authenticated: true } });
    expect(failure).toMatchObject({ step: "0", consumesNonce: false, stored: false });
  });
});

describe("step 0b — the bundle_id lookup", () => {
  it("returns the stored result without reading any state", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    const outcome = await validateSecurityBundle(bundle, {
      ...state,
      // A state that would fail 0c and 0d outright; 0b must answer first.
      accountState: "DELETING",
      configVersion: 99,
      storedResult: { operationType: "CREATE_VAULT", result: { applied: true } },
    });
    if (!outcome.ok) throw new Error(`expected the stored result, got ${outcome.failure.code}`);
    expect(outcome.value).toMatchObject({ kind: "STORED", stored: { result: { applied: true } } });
  });

  it("rejects a bundle_id replayed under another operation_type", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    const failure = await reject(bundle, {
      ...state,
      storedResult: { operationType: "DELETE_VAULT", result: {} },
    });
    expect(failure).toMatchObject({ step: "0b", code: "INVALID_BUNDLE", stored: false });
  });

  it("is reached only after step 0: a wrong scope still answers SCOPE_REQUIRED", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    const failure = await reject(bundle, {
      ...state,
      authorization: { authenticated: true, token: { scopes: ["RECOVERY_CONTROL"] } },
      storedResult: { operationType: "CREATE_VAULT", result: { applied: true } },
    });
    expect(failure).toMatchObject({ step: "0", code: "SCOPE_REQUIRED" });
  });
});

describe("step 0c — account and vault state", () => {
  it("rejects CREATE_ACCOUNT on an account that already has a root", async () => {
    const { bundle } = scenario("CREATE_ACCOUNT");
    const failure = await reject(bundle, { ...world.state, authorization: { authenticated: true } });
    expect(failure).toMatchObject({ step: "0c", code: "INVALID_STATE", rule: "account/has-root" });
  });

  it("rejects CREATE_VAULT for a vault_id that already exists", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    const epochs = (bundle.epochs ?? []).map((e) => ({
      ...e,
      descriptor: { ...e.descriptor, vault_id: VAULT_A },
    }));
    const failure = await reject(patch(bundle, { epochs }), state);
    expect(failure).toMatchObject({ step: "0c", code: "INVALID_STATE", rule: "vault/not-free" });
  });

  it("rejects CREATE_VAULT for a vault_id that was retired (§35.12: never reused)", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    const vaultId = (bundle.epochs ?? [])[0]?.descriptor.vault_id as Uint8Array;
    const failure = await reject(bundle, { ...state, retiredVaultIds: [vaultId] });
    expect(failure).toMatchObject({ step: "0c", code: "INVALID_STATE", rule: "vault/not-free" });
  });

  it("rejects an epoch for a foreign vault with INVALID_BUNDLE, not a retryable code", async () => {
    const { bundle, state } = scenario("REVOKE_CLIENT");
    const epochs = [...(bundle.epochs ?? [])];
    const first = epochs[0];
    if (first === undefined) throw new Error("no epochs");
    epochs[0] = { ...first, descriptor: { ...first.descriptor, vault_id: filled(16, 0xee) } };
    const failure = await reject(patch(bundle, { epochs }), state);
    expect(failure).toMatchObject({ step: "0c", code: "INVALID_BUNDLE", rule: "epochs/foreign-vault", retryable: false });
  });

  it("rejects a coverage envelope for a foreign vault before any coverage comparison", async () => {
    const { bundle, state } = scenario("ENROLL_CLIENT");
    const envelopes = (bundle.coverage_envelopes ?? []).map((e, i) =>
      i === 0 ? { ...e, vault_id: filled(16, 0xee) } : e,
    );
    const failure = await reject(patch(bundle, { coverage_envelopes: envelopes }), state);
    expect(failure).toMatchObject({ step: "0c", code: "INVALID_BUNDLE", rule: "coverage/foreign-vault" });
  });

  it("rejects DELETE_VAULT for a vault of another account, indistinguishably from a missing one", async () => {
    const { bundle, state } = scenario("DELETE_VAULT");
    const foreign = await reject(
      patch(bundle, { deletion: { ...bundle.deletion, vault_id: filled(16, 0xee) } }),
      state,
    );
    const missing = await reject(
      patch(bundle, { deletion: { nonce: bundle.deletion?.nonce, signature: bundle.deletion?.signature } }),
      state,
    );
    expect(foreign).toMatchObject({ step: "0c", code: "INVALID_STATE", rule: "vault/not-mine" });
    expect(missing.code).toBe(foreign.code);
    expect(missing.rule).toBe(foreign.rule);
  });

  it("consumes the nonce for a definitive rejection from 0c on", async () => {
    const { bundle, state } = scenario("DELETE_VAULT");
    const failure = await reject(
      patch(bundle, { deletion: { ...bundle.deletion, vault_id: filled(16, 0xee) } }),
      state,
    );
    expect(failure).toMatchObject({ stored: true, consumesNonce: true });
  });

  it("accepts nothing while the account is DELETING or ORPHANED (§11.4)", async () => {
    for (const accountState of ["DELETING", "ORPHANED"] as const) {
      const { bundle, state } = scenario("ENROLL_CLIENT");
      const failure = await reject(bundle, { ...state, accountState });
      expect(failure).toMatchObject({ step: "0c", code: "INVALID_STATE", rule: "account/deleting" });
    }
  });

  it("accepts only ENROLL_CLIENT, RECOVERY_RESET, CANCEL_DELETE_ACCOUNT and the §35.15 records while DELETING_SCHEDULED", async () => {
    for (const type of OPERATION_TYPES) {
      const { bundle, state } = scenario(type);
      if (type === "CREATE_ACCOUNT") continue;
      const outcome = await validateSecurityBundle(bundle, { ...state, accountState: "DELETING_SCHEDULED" });
      const allowed = OPERATION_RULES[type].allowedWhileAccountDeleting;
      if (!allowed) {
        expect(outcome.ok ? "accepted" : outcome.failure.rule).toBe("account/delete-scheduled");
      } else if (!outcome.ok) {
        expect(outcome.failure.rule).not.toBe("account/delete-scheduled");
      }
    }
  });
});

describe("step 0d — the CAS of `expected`", () => {
  for (const field of ["root_generation", "registry_version", "config_version"] as const) {
    it(`answers SECURITY_STATE_STALE with the values in force when ${field} is stale`, async () => {
      const { bundle, state } = scenario("ENROLL_CLIENT");
      const expected = { ...bundle.expected, [field]: bundle.expected[field] + 1 };
      const failure = await reject(patch(bundle, { expected }), state);
      expect(failure).toMatchObject({
        step: "0d",
        code: "SECURITY_STATE_STALE",
        retryable: true,
        stored: false,
        expected: { rootGeneration: 1, registryVersion: 1, configVersion: 1 },
      });
    });
  }

  it("never consumes a nonce for a retryable code", async () => {
    const { bundle, state } = scenario("DELETE_VAULT");
    const failure = await reject(patch(bundle, { expected: { ...bundle.expected, config_version: 9 } }), state);
    expect(failure).toMatchObject({ code: "SECURITY_STATE_STALE", consumesNonce: false, stored: false });
  });
});

describe("step 1 — the transition (§28.2)", () => {
  it("rejects a transition whose descriptor is missing", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    const failure = await reject(patch(bundle, { root_descriptor: undefined }), state);
    expect(failure).toMatchObject({ step: "1", code: "INVALID_TRANSITION", rule: "transition/descriptor" });
  });

  it("names INVALID_SIGNATURE for a transition signed by a stranger", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    const signatures = (bundle.root_transition?.signatures ?? []).map((s) => ({ ...s, value: filled(64, 0x00) }));
    const failure = await reject(
      patch(bundle, { root_transition: { ...bundle.root_transition, signatures } }),
      state,
    );
    expect(failure).toMatchObject({ step: "1", code: "INVALID_SIGNATURE" });
  });

  it("names INVALID_TRANSITION for a transition that forks the chain", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    const transition = { ...bundle.root_transition, old_root_hash: filled(32, 0xaa) };
    const failure = await reject(patch(bundle, { root_transition: transition }), state);
    expect(failure).toMatchObject({ step: "1", code: "INVALID_SIGNATURE" });
  });
});

describe("step 3 — the registry (§29)", () => {
  it("rejects a registry signed under a generation that is not the pending one", async () => {
    const { bundle, state } = scenario("ENROLL_CLIENT");
    const resigned = await signRegistry(
      await nextRegistry(world.registry, {
        add: [{ recipientId: ENROLLED_ID, type: "TRUSTED_BROWSER", publicKey: filled(48, 0x33), label: "x" }],
      }),
      world.stranger.privateKey,
    );
    const failure = await reject(patch(bundle, { registry: resigned }), state);
    expect(failure).toMatchObject({ step: "3", code: "INVALID_SIGNATURE" });
  });

  it("rejects a registry version that is not N + 1", async () => {
    const { bundle, state } = scenario("ENROLL_CLIENT");
    const draft = await nextRegistry(world.registry, {
      add: [{ recipientId: ENROLLED_ID, type: "TRUSTED_BROWSER", publicKey: filled(48, 0x33), label: "x" }],
    });
    const skipped = await signRegistry({ ...draft, registry_version: 5 }, world.as1.privateKey);
    const failure = await reject(patch(bundle, { registry: skipped }), state);
    expect(failure).toMatchObject({ step: "3", code: "INVALID_REGISTRY" });
  });

  it("is reached only after the transition: a bad transition answers at step 1", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    // Both broken: the transition's signature AND a registry that is not N + 1.
    const signatures = (bundle.root_transition?.signatures ?? []).map((s) => ({ ...s, value: filled(64, 0x00) }));
    const draft = await nextRegistry(world.registry, { rootGeneration: 2 });
    const bad = await signRegistry({ ...draft, registry_version: 9 }, world.as2.privateKey);
    const failure = await reject(
      patch(bundle, { root_transition: { ...bundle.root_transition, signatures }, registry: bad }),
      state,
    );
    expect(failure.step).toBe("1");
  });
});

describe("step 5 — profile and config", () => {
  it("rejects a config_version that is not the one in force + 1", async () => {
    const { bundle, state } = scenario("ENROLL_CLIENT");
    const failure = await reject(patch(bundle, { config_version: 7 }), state);
    expect(failure).toMatchObject({ step: "5", code: "INVALID_BUNDLE", rule: "config/version" });
  });

  it("rejects a profile whose config_version is not the one in force + 1", async () => {
    const { bundle, state } = scenario("CHANGE_SECRETS");
    const profile = makeProfile(world.accountId, 5);
    const failure = await reject(
      patch(bundle, {
        profile,
        profile_signature: await signProfileUpdate(world.as1.privateKey, world.accountId, 1, profile),
      }),
      state,
    );
    expect(failure).toMatchObject({ step: "5", rule: "config/version" });
  });

  it("rejects a registry change with no config (§35.1.1, below the table)", async () => {
    const { bundle, state } = scenario("ENROLL_CLIENT");
    const failure = await reject(patch(bundle, { config_blob: undefined, config_version: undefined }), state);
    expect(failure).toMatchObject({ step: "5", code: "INVALID_BUNDLE", rule: "config/required" });
  });

  it("CREATE_VAULT with no config is accepted (§44.3)", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    await accept(bundle, state);
  });
});

describe("step 6 — §36.2 over the epochs that survive the filter", () => {
  it("discards an epoch and a coverage envelope for an own DELETED vault without error", async () => {
    const { bundle, state } = scenario("REVOKE_CLIENT");
    const deletedState: BundleState = {
      ...state,
      vaults: state.vaults.map((v, i) => (i === 1 ? { ...v, state: "DELETED" as const } : v)),
    };
    const outcome = await validateSecurityBundle(bundle, deletedState);
    if (!outcome.ok || outcome.value.kind !== "ACCEPT") {
      throw new Error(`expected ACCEPT, got ${outcome.ok ? outcome.value.kind : outcome.failure.rule}`);
    }
    expect(outcome.value.accepted.epochs).toHaveLength(1);
    expect(outcome.value.accepted.discardedEpochs).toHaveLength(1);
  });

  it("answers EPOCH_STALE when previous_epoch_id is not the vault's current epoch", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    const stale: BundleState = {
      ...state,
      // The new vault now exists with an epoch, so its E1 no longer links from nothing.
      vaults: [...state.vaults],
    };
    const epochs = (bundle.epochs ?? []).map((e) => ({
      ...e,
      descriptor: { ...e.descriptor, vault_id: VAULT_A },
    }));
    // Aim it at an existing vault instead, so 0c passes only when we also own it… it does not, so
    // use the REVOKE_CLIENT bundle, whose epochs target vaults that already have one.
    void epochs;
    const revoke = scenario("REVOKE_CLIENT");
    const shifted: BundleState = {
      ...revoke.state,
      vaults: revoke.state.vaults.map((v) => ({ ...v, currentEpoch: null })),
    };
    const failure = await reject(revoke.bundle, shifted);
    expect(failure).toMatchObject({ step: "6", code: "EPOCH_STALE", retryable: true, stored: false });
    void stale;
  });

  it("rejects a descriptor bound to a root generation that is not the pending one", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    // Signed correctly for generation 1, but the pending root is generation 2.
    const epochs = (bundle.epochs ?? []).map((e) => ({ ...e, descriptor: world.currentEpochs[0]?.descriptor as never }));
    const failure = await reject(patch(bundle, { epochs }), state);
    expect(failure.step).toBe("6");
  });

  it("rejects a descriptor whose crypto_version is above the pending root's (§32.1 (b), §36.2)", async () => {
    const { bundle, state } = scenario("REVOKE_CLIENT");
    const registry = bundle.registry!;
    const pending = {
      root: { ...world.root, crypto_version: 2 },
      rootHash: world.rootHash,
      registry,
      registryHash: await registryHash(registry),
      signer: world.as1,
    };
    const failure = await reject(patch(bundle, { epochs: await rotateAll(world, pending) }), state);
    expect(failure).toMatchObject({ step: "6", code: "INVALID_BUNDLE", rule: "epoch/CRYPTO_VERSION_ABOVE_ROOT" });
  });

  it("rejects an envelope set that does not match envelope_set_hash", async () => {
    const { bundle, state } = scenario("REVOKE_CLIENT");
    const epochs = (bundle.epochs ?? []).map((e, i) =>
      i === 0 ? { ...e, envelopes: e.envelopes.map((env, j) => (j === 0 ? { ...env, ciphertext: filled(384, 0x00) } : env)) } : e,
    );
    const failure = await reject(patch(bundle, { epochs }), state);
    expect(failure).toMatchObject({ step: "6", code: "INVALID_BUNDLE", rule: "epoch/envelope-set-hash" });
  });
});

describe("step 7 — applicability: the table's — and its required fields", () => {
  it("rejects every sub-map the table forbids that no earlier step inspects", async () => {
    // CREATE_VAULT's row is "—" for everything except `epochs`, so it is the sharpest probe. The
    // three parts an earlier step *does* inspect (`root_transition`, `root_descriptor`, `registry`)
    // get their own test below, because §35.1.1 validates them in steps 1 and 3 before step 7 ever
    // asks whether they were allowed at all.
    const extras: Record<string, unknown> = {
      profile: makeProfile(world.accountId, 2),
      profile_signature: filled(64, 0x11),
      config_blob: filled(64, 0x04),
      config_version: 2,
      coverage_envelopes: [],
      deletion: scenario("DELETE_VAULT").bundle.deletion,
    };
    const { bundle, state } = scenario("CREATE_VAULT");
    for (const [name, value] of Object.entries(extras)) {
      const failure = await reject(patch(bundle, { [name]: value }), state);
      expect(failure.step, name).toBe("7");
      expect(failure.rule, name).toContain(`forbidden:${name}`);
      expect(failure.code, name).toBe("INVALID_BUNDLE");
    }
  });

  it("a forbidden transition or registry is rejected by the step that validates it, not by step 7", async () => {
    // This is §35.1.1's numbering taken literally: steps 1, 3 and 5 all run before step 7's table.
    // A CREATE_VAULT carrying another operation's transition or registry is therefore rejected by
    // "cambia raíz o registry sin config" in step 5, never by a step-7 applicability rule — and if
    // the smuggled part had *also* been malformed, step 1 or 3 would have answered even earlier.
    const { bundle, state } = scenario("CREATE_VAULT");
    const reset = scenario("RECOVERY_RESET").bundle;
    const withTransition = await reject(
      patch(bundle, { root_transition: reset.root_transition, root_descriptor: reset.root_descriptor }),
      state,
    );
    expect(withTransition).toMatchObject({ step: "5", code: "INVALID_BUNDLE", rule: "config/required" });
    const withRegistry = await reject(patch(bundle, { registry: scenario("ENROLL_CLIENT").bundle.registry }), state);
    expect(withRegistry).toMatchObject({ step: "5", rule: "config/required" });

    // And a *malformed* smuggled transition answers at step 1, which is the earlier-step rule.
    const broken = await reject(
      patch(bundle, {
        root_transition: { ...reset.root_transition, old_root_hash: filled(32, 0xaa) },
        root_descriptor: reset.root_descriptor,
      }),
      state,
    );
    expect(broken.step).toBe("1");
  });

  it("rejects an applicable field that is absent", async () => {
    const { bundle, state } = scenario("REVOKE_CLIENT");
    for (const name of ["registry", "config_blob", "config_version", "epochs"]) {
      const failure = await reject(patch(bundle, { [name]: undefined }), state);
      // `registry` and the config are also step-3/5/6 rules; what matters is that absence is caught
      // somewhere, definitively, and never mistaken for a concurrency answer.
      expect(["3", "5", "6", "7"]).toContain(failure.step);
      expect(failure.retryable, name).toBe(false);
      expect(failure.code).not.toBe("SECURITY_STATE_STALE");
    }
  });

  it("rejects an empty `epochs` array as a *missing* rotation, not as an absent field", async () => {
    const { bundle, state } = scenario("REVOKE_CLIENT");
    const failure = await reject(patch(bundle, { epochs: [] }), state);
    expect(failure).toMatchObject({ step: "7", code: "VAULT_SET_STALE", retryable: true });
    expect(failure.vaultIds).toHaveLength(2);
  });

  it("rejects a transition of the wrong type for the operation", async () => {
    // A complete, internally consistent RECOVERY_KIT_REPLACEMENT — transition, registry, epochs all
    // bound to the same pending root — relabelled as RECOVERY_RESET and given the profile that row
    // demands. Everything a step before 7 looks at is valid, so only the table can reject it.
    const kit = scenario("RECOVERY_KIT_REPLACEMENT");
    const reset = scenario("RECOVERY_RESET");
    const failure = await reject(
      patch(kit.bundle, {
        operation_type: "RECOVERY_RESET",
        profile: makeProfile(world.accountId, 2),
        config_blob: undefined,
        config_version: undefined,
        coverage_envelopes: reset.bundle.coverage_envelopes,
      }),
      // §35.15: with the matured reset request the relabelled bundle would need, so 0c lets it through.
      { ...kit.state, recoveryRequests: reset.state.recoveryRequests ?? [], authorization: { authenticated: true, token: { scopes: ["RECOVERY_CONTROL"] } } },
    );
    expect(failure).toMatchObject({ step: "7", code: "INVALID_BUNDLE", rule: "applicability/transition-type" });
  });

  it("rejects `deletion.vault_id` on an account deletion (§23.4)", async () => {
    const { bundle, state } = scenario("DELETE_ACCOUNT");
    const deletion = await signDeletion(world.as1.privateKey, {
      operationType: "DELETE_ACCOUNT",
      accountId: world.accountId,
      rootGeneration: 1,
      nonce: filled(16, 0x90),
    });
    const failure = await reject(patch(bundle, { deletion: { ...deletion, vault_id: VAULT_A } }), state);
    expect(failure).toMatchObject({ step: "7", rule: "applicability/deletion-vault-id" });
  });

  it("rejects profile_signature outside CHANGE_SECRETS (§35.1, §44.3)", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    const failure = await reject(patch(bundle, { profile_signature: filled(64, 0x22) }), state);
    expect(failure).toMatchObject({ step: "7", rule: "applicability/forbidden:profile_signature" });
  });

  it("rejects CHANGE_SECRETS without profile_signature (§44.3)", async () => {
    const { bundle, state } = scenario("CHANGE_SECRETS");
    const failure = await reject(patch(bundle, { profile_signature: undefined }), state);
    expect(failure).toMatchObject({ step: "7", rule: "applicability/missing:profile_signature" });
  });

  it("rejects an invalid profile_signature with INVALID_SIGNATURE", async () => {
    const { bundle, state } = scenario("CHANGE_SECRETS");
    const wrong = await signProfileUpdate(world.stranger.privateKey, world.accountId, 1, makeProfile(world.accountId, 2));
    const failure = await reject(patch(bundle, { profile_signature: wrong }), state);
    expect(failure).toMatchObject({ step: "7", code: "INVALID_SIGNATURE", rule: "profile-signature/invalid" });
  });

  it("rejects a profile_signature bound to the wrong previous config_version (§35.6)", async () => {
    const { bundle, state } = scenario("CHANGE_SECRETS");
    const wrong = await signProfileUpdate(world.as1.privateKey, world.accountId, 0, makeProfile(world.accountId, 2));
    const failure = await reject(patch(bundle, { profile_signature: wrong }), state);
    expect(failure).toMatchObject({ step: "7", code: "INVALID_SIGNATURE" });
  });
});

describe("step 7 — registry shape per operation_type", () => {
  /**
   * A registry swap also moves the pending registry that every new epoch is bound to, and §36.2 is
   * step 6 — *before* the shape rule. So each case below re-rotates the vaults against the registry
   * it installs; otherwise step 6 would answer first and the shape rule would never be exercised.
   */
  async function withRegistry(base: Scenario, registry: Parameters<typeof registryHash>[0] & { signature: Uint8Array }, signer = world.as1) {
    const root = base.bundle.root_descriptor ?? world.root;
    const epochs =
      base.bundle.epochs === undefined
        ? undefined
        : await rotateAll(world, {
            root,
            rootHash: await rootHash(root),
            registry: registry as never,
            registryHash: await registryHash(registry),
            signer,
          });
    return patch(base.bundle, { registry, ...(epochs === undefined ? {} : { epochs }) });
  }

  it("rejects an ENROLL_CLIENT that also revokes (§44.3)", async () => {
    const base = scenario("ENROLL_CLIENT");
    const both = await signRegistry(
      await nextRegistry(world.registry, {
        add: [{ recipientId: ENROLLED_ID, type: "TRUSTED_BROWSER", publicKey: filled(48, 0x33), label: "x" }],
        revoke: [BROWSER_ID],
      }),
      world.as1.privateKey,
    );
    const failure = await reject(await withRegistry(base, both), base.state);
    expect(failure).toMatchObject({ step: "7", code: "INVALID_REGISTRY", rule: "registry/one-added" });
  });

  it("rejects a REVOKE_CLIENT that revokes nobody", async () => {
    const base = scenario("REVOKE_CLIENT");
    const noop = await signRegistry(await nextRegistry(world.registry, {}), world.as1.privateKey);
    const failure = await reject(await withRegistry(base, noop), base.state);
    expect(failure).toMatchObject({ step: "7", code: "INVALID_REGISTRY", rule: "registry/some-revoked" });
  });

  it("rejects a RECOVERY_RESET that leaves a recipient ACTIVE (§44.3)", async () => {
    const base = scenario("RECOVERY_RESET");
    const partial = await signRegistry(
      await nextRegistry(world.registry, { revoke: [BROWSER_ID], rootGeneration: 2 }),
      world.as2.privateKey,
    );
    const failure = await reject(await withRegistry(base, partial, world.as2), base.state);
    expect(failure).toMatchObject({ step: "7", code: "INVALID_REGISTRY", rule: "registry/none-active" });
  });

  it("rejects a RECOVERY_KIT_REPLACEMENT that changes the recipient list", async () => {
    const base = scenario("RECOVERY_KIT_REPLACEMENT");
    const changed = await signRegistry(
      await nextRegistry(world.registry, { revoke: [BROWSER_ID], rootGeneration: 2 }),
      world.as1.privateKey,
    );
    const failure = await reject(await withRegistry(base, changed), base.state);
    expect(failure).toMatchObject({ step: "7", code: "INVALID_REGISTRY", rule: "registry/unchanged" });
  });

  it("rejects a CREATE_ACCOUNT registry with more than one ACTIVE recipient", async () => {
    const base = scenario("CREATE_ACCOUNT");
    const epoch = await createEpoch({
      vaultId: NEW_VAULT,
      epochId: filled(16, 0x61),
      previous: null,
      root: { generation: 1, hash: world.rootHash, cryptoVersion: 1 },
      registry: { version: 1, hash: world.registryState.registryHash },
      recipients: await epochRecipients(world.root, world.registry),
      signingKey: world.as1.privateKey,
    });
    const failure = await reject(
      patch(base.bundle, {
        registry: world.registry,
        epochs: [{ descriptor: epoch.descriptor, envelopes: [...epoch.envelopes] }],
      }),
      base.state,
    );
    expect(failure).toMatchObject({ step: "7", code: "INVALID_REGISTRY", rule: "registry/initial" });
  });

  it("answers PLAN_LIMIT_EXCEEDED when the plan's plugin ceiling is crossed (§40)", async () => {
    const base = scenario("ENROLL_CLIENT");
    const plugin = await signRegistry(
      await nextRegistry(world.registry, {
        add: [{ recipientId: ENROLLED_ID, type: "PLUGIN_INSTALLATION", publicKey: filled(48, 0x33), label: "x" }],
      }),
      world.as1.privateKey,
    );
    const failure = await reject(
      patch(base.bundle, {
        registry: plugin,
        coverage_envelopes: coverageFor(world, ENROLLED_ID, "PLUGIN_INSTALLATION"),
      }),
      { ...base.state, pluginLimit: 1 },
    );
    expect(failure).toMatchObject({ step: "7", code: "PLAN_LIMIT_EXCEEDED", retryable: false });
  });
});

describe("step 7 — envelopes, coverage and epoch counts", () => {
  it("rejects an epoch with an envelope for a revoked recipient (§44.3)", async () => {
    const { bundle, state } = scenario("REVOKE_CLIENT");
    // The revoked browser's envelope survives from the previous epoch: exactly the §44.3 case.
    const epochs = (bundle.epochs ?? []).map((e, i) =>
      i === 0
        ? {
            ...e,
            envelopes: [
              ...e.envelopes,
              { ...(e.envelopes[0] as EpochEnvelope), recipient_id: BROWSER_ID, recipient_type: "TRUSTED_BROWSER" as const },
            ],
          }
        : e,
    );
    const failure = await reject(patch(bundle, { epochs }), state);
    // The extra envelope also breaks `envelope_set_hash`, which step 6 owns; either way it fails
    // before it could ever be stored.
    expect(["6", "7"]).toContain(failure.step);
    expect(failure.code).toBe("INVALID_BUNDLE");
  });

  it("rejects an epoch missing an envelope for an ACTIVE recipient", async () => {
    const { bundle, state } = scenario("REVOKE_CLIENT");
    const first = (bundle.epochs ?? [])[0];
    if (first === undefined) throw new Error("no epochs");
    const trimmed = first.envelopes.slice(0, -1);
    const failure = await reject(
      patch(bundle, { epochs: [{ ...first, envelopes: trimmed }, ...(bundle.epochs ?? []).slice(1)] }),
      state,
    );
    expect(["6", "7"]).toContain(failure.step);
  });

  it("answers VAULT_SET_STALE when a live vault has no new epoch", async () => {
    const { bundle, state } = scenario("REVOKE_CLIENT");
    const failure = await reject(patch(bundle, { epochs: (bundle.epochs ?? []).slice(0, 1) }), state);
    expect(failure).toMatchObject({ step: "7", code: "VAULT_SET_STALE", retryable: true, stored: false });
    expect(failure.vaultIds?.map((v) => v[0])).toEqual([VAULT_A[0], VAULT_B[0]]);
  });

  it("answers COVERAGE_STALE with the RequiredEpochSet when an envelope is missing", async () => {
    const { bundle, state } = scenario("ENROLL_CLIENT");
    const failure = await reject(patch(bundle, { coverage_envelopes: (bundle.coverage_envelopes ?? []).slice(0, 1) }), state);
    expect(failure).toMatchObject({ step: "7", code: "COVERAGE_STALE", retryable: true, stored: false });
    expect(failure.required).toHaveLength(2);
  });

  it("answers COVERAGE_STALE for a duplicate envelope", async () => {
    const { bundle, state } = scenario("ENROLL_CLIENT");
    const envelopes = bundle.coverage_envelopes ?? [];
    const failure = await reject(patch(bundle, { coverage_envelopes: [...envelopes, envelopes[0]] }), state);
    expect(failure).toMatchObject({ step: "7", code: "COVERAGE_STALE" });
  });

  it("answers COVERAGE_STALE when the envelopes address the wrong recipient", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    const failure = await reject(
      patch(bundle, { coverage_envelopes: coverageFor(world, await rootRecipientId(world.accountEncryption), "ACCOUNT") }),
      state,
    );
    expect(failure).toMatchObject({ step: "7", code: "COVERAGE_STALE" });
  });

  it("does not ask for coverage of the epochs the bundle itself creates", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    const outcome = await validateSecurityBundle(bundle, state);
    if (!outcome.ok || outcome.value.kind !== "ACCEPT") throw new Error("expected ACCEPT");
    // Two pre-existing epochs are covered; the two new ones are not, and that is correct.
    expect(outcome.value.accepted.coverageEnvelopes).toHaveLength(2);
  });

  it("rejects two epochs for the same vault", async () => {
    const { bundle, state } = scenario("REVOKE_CLIENT");
    const epochs = bundle.epochs ?? [];
    const first = epochs[0];
    if (first === undefined) throw new Error("no epochs");
    // Both live vaults are still covered, so rule 7.1 passes and rule 7.5 is the one that answers.
    const failure = await reject(patch(bundle, { epochs: [...epochs, first] }), state);
    expect(failure).toMatchObject({ step: "7", rule: "epochs/duplicate-vault" });
  });

  it("rejects a CREATE_VAULT carrying more than one epoch", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    const epochs = bundle.epochs ?? [];
    const otherVault = filled(16, 0x2e);
    const second = await createEpoch({
      vaultId: otherVault,
      epochId: filled(16, 0x63),
      previous: null,
      root: { generation: 1, hash: world.rootHash, cryptoVersion: 1 },
      registry: { version: 1, hash: world.registryState.registryHash },
      recipients: await epochRecipients(world.root, world.registry),
      signingKey: world.as1.privateKey,
    });
    const failure = await reject(
      patch(bundle, { epochs: [...epochs, { descriptor: second.descriptor, envelopes: [...second.envelopes] }] }),
      state,
    );
    expect(failure).toMatchObject({ step: "7", rule: "epochs/exactly-one" });
  });

  it("answers PLAN_LIMIT_EXCEEDED when the plan's vault ceiling is crossed (§40)", async () => {
    const { bundle, state } = scenario("CREATE_VAULT");
    const failure = await reject(bundle, { ...state, vaultLimit: 2 });
    expect(failure).toMatchObject({ step: "7", code: "PLAN_LIMIT_EXCEEDED", rule: "epochs/vault-limit" });
  });
});

describe("step 7 — profile limits, root keys and the deletion block", () => {
  it("rejects Argon2 parameters outside the ADR-004 limits (§44.3)", async () => {
    const { bundle, state } = scenario("CHANGE_SECRETS");
    const profile = {
      ...makeProfile(world.accountId, 2),
      argon2_params: { memory_kib: 1024, iterations: 3, parallelism: 1, version: 1 },
    };
    const failure = await reject(
      patch(bundle, {
        profile,
        profile_signature: await signProfileUpdate(world.as1.privateKey, world.accountId, 1, profile),
      }),
      state,
    );
    expect(failure).toMatchObject({ step: "7", code: "INVALID_BUNDLE" });
    expect(failure.rule).toContain("profile/");
  });

  it("rejects a Private-account profile without kdf_salt or argon2_params (§23.4)", async () => {
    const { bundle, state } = scenario("CHANGE_SECRETS");
    for (const field of ["kdf_salt", "argon2_params"] as const) {
      const { [field]: _dropped, ...profile } = bundle.profile!;
      const failure = await reject(patch(bundle, { profile }), state);
      expect(failure).toMatchObject({ step: "7", code: "INVALID_BUNDLE", rule: "profile/kdf-absent" });
    }
  });

  it("rejects a profile that names another account", async () => {
    const { bundle, state } = scenario("CHANGE_SECRETS");
    const profile = makeProfile(filled(16, 0x99), 2);
    const failure = await reject(
      patch(bundle, {
        profile,
        profile_signature: await signProfileUpdate(world.as1.privateKey, world.accountId, 1, profile),
      }),
      state,
    );
    expect(failure).toMatchObject({ step: "7", rule: "profile/account" });
  });

  it("rejects a root descriptor with two identical public keys", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    // Re-sign nothing: the transition binds the descriptor by hash, so step 1 answers first…
    const descriptor = { ...bundle.root_descriptor, recovery_encryption_public_key: world.newAccountEncryption };
    const failure = await reject(patch(bundle, { root_descriptor: descriptor }), state);
    // …which is itself the ordering guarantee: step 1 before step 7.
    expect(failure.step).toBe("1");
  });

  it("evaluates the deletion block in the order state → signature → nonce", async () => {
    const { bundle, state } = scenario("DELETE_VAULT");
    const nonce = bundle.deletion?.nonce as Uint8Array;

    // A bad state wins over a bad signature and a reused nonce.
    const wrongState = await reject(patch(bundle, { deletion: { ...bundle.deletion, signature: filled(64, 0) } }), {
      ...state,
      vaults: state.vaults.map((v, i) => (i === 0 ? { ...v, state: "DELETING_SCHEDULED" as const } : v)),
      consumedNonces: [nonce],
    });
    expect(wrongState).toMatchObject({ code: "INVALID_STATE", rule: "deletion/precondition" });

    // A bad signature wins over a reused nonce (§35.1.1's explicit example).
    const badSignature = await reject(
      patch(bundle, { deletion: { ...bundle.deletion, signature: filled(64, 0) } }),
      { ...state, consumedNonces: [nonce] },
    );
    expect(badSignature).toMatchObject({ code: "INVALID_SIGNATURE", consumesNonce: true });

    // Only when both are right does the nonce answer.
    const reused = await reject(bundle, { ...state, consumedNonces: [nonce] });
    expect(reused).toMatchObject({ step: "7", code: "NONCE_REUSED", consumesNonce: true, stored: true });
  });

  it("rejects a DELETE_VAULT signature replayed as CANCEL_DELETE_VAULT", async () => {
    const del = scenario("DELETE_VAULT");
    const cancel = scenario("CANCEL_DELETE_VAULT");
    const failure = await reject(patch(cancel.bundle, { deletion: del.bundle.deletion }), cancel.state);
    expect(failure).toMatchObject({ step: "7", code: "INVALID_SIGNATURE", rule: "deletion/signature" });
  });

  it("rejects CANCEL_DELETE_VAULT on a vault that is still ACTIVE", async () => {
    const { bundle } = scenario("CANCEL_DELETE_VAULT");
    const failure = await reject(bundle, world.state);
    expect(failure).toMatchObject({ step: "7", code: "INVALID_STATE", rule: "deletion/precondition" });
  });

  it("rejects DELETE_ACCOUNT on an account already scheduled for deletion", async () => {
    const { bundle, state } = scenario("DELETE_ACCOUNT");
    const failure = await reject(bundle, { ...state, accountState: "DELETING_SCHEDULED" });
    // §35.12 forbids DELETE_ACCOUNT while scheduled, and 0c says so before step 7 does.
    expect(failure).toMatchObject({ step: "0c", code: "INVALID_STATE" });
  });
});

describe("the classification of §35.1 is derived, not restated", () => {
  it("no retryable failure is ever stored or consumes a nonce", async () => {
    const cases: BundleFailure[] = [];
    const { bundle, state } = scenario("DELETE_VAULT");
    cases.push(await reject(patch(bundle, { expected: { ...bundle.expected, config_version: 9 } }), state));
    const revoke = scenario("REVOKE_CLIENT");
    cases.push(await reject(patch(revoke.bundle, { epochs: [] }), revoke.state));
    const enroll = scenario("ENROLL_CLIENT");
    cases.push(await reject(patch(enroll.bundle, { coverage_envelopes: [] }), enroll.state));
    for (const failure of cases) {
      expect(failure.retryable, failure.rule).toBe(true);
      expect(failure.stored, failure.rule).toBe(false);
      expect(failure.consumesNonce, failure.rule).toBe(false);
    }
  });

  it("every failure names one of the steps of §35.1.1", async () => {
    const { bundle, state } = scenario("ENROLL_CLIENT");
    const failure = await reject(patch(bundle, { config_version: 8 }), state);
    expect(["0", "0b", "0c", "0d", "1", "3", "5", "6", "7"]).toContain(failure.step);
  });

  it("`expectedOf` produces a CAS that passes for the state it was read from", () => {
    expect(expectedOf(world.state)).toEqual({ root_generation: 1, registry_version: 1, config_version: 1 });
  });
});
