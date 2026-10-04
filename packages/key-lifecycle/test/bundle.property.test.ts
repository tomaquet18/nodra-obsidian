// Property runs over §35.1.1.
//
// The shape of every property here is the same: take a bundle that passes, apply a random single
// mutation drawn from the ways a client or a server can get it wrong, and assert the **invariant**
// rather than a specific answer — either the validator rejects with a typed failure that names a
// step of §35.1.1 and classifies itself exactly as §35.1's table says, or it accepts and the bundle
// really does satisfy every rule of the applicability table, checked here a second time and
// independently of the implementation.
import fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";
import { OPERATION_TYPES } from "@nodra/encoding/records";
import type { SecurityBundle } from "@nodra/encoding/records";
import { BUNDLE_STEPS, validateSecurityBundle } from "../src/bundle.js";
import type { AcceptedBundle, BundleOutcome, BundleState } from "../src/bundle.js";
import { requiredEpochSet } from "../src/coverage.js";
import { idKey, rootRecipientId } from "../src/epoch.js";
import { forbiddenFields, operationRules, requiredFields } from "../src/operations.js";
import type { OperationType } from "../src/operations.js";
import {
  allScenarios,
  makeBundleWorld,
  makeEscrow,
  makeProfile,
  managedCreateAccountScenario,
  managedDeleteAccountScenario,
  managedRecoveryResetScenario,
  patch,
  storedRequest,
} from "./bundle-support.js";
import type { BundleWorld, Scenario } from "./bundle-support.js";
import { filled } from "./support.js";

let world: BundleWorld;
let scenarios: ReadonlyMap<OperationType, Scenario>;
/** Every valid scenario: one per operation type, plus the Managed forms of §35.2, §35.7 and §35.12. */
let pool: readonly (readonly [string, Scenario])[];

beforeAll(async () => {
  world = await makeBundleWorld();
  scenarios = await allScenarios(world);
  pool = [
    ...[...scenarios].map(([type, scenario]) => [type, scenario] as const),
    ["CREATE_ACCOUNT/managed", await managedCreateAccountScenario(world)],
    ["RECOVERY_RESET/managed", await managedRecoveryResetScenario(world)],
    ["DELETE_ACCOUNT/managed", await managedDeleteAccountScenario(world, 0)],
  ];
}, 120_000);

/**
 * §44.5, re-derived from an accepted bundle and the state it was validated against, independently of
 * the validator:
 *
 *   - "todo blob actual es descifrable por ACCOUNT y por RECOVERY": every new epoch addresses the
 *     pending root's ACCOUNT and RECOVERY recipients;
 *   - "ninguna clave que deba leer datos existentes se activa sin cobertura completa": every reading
 *     key the bundle activates (a new root ACCOUNT or RECOVERY key, a recipient added to the registry)
 *     has an envelope for every epoch of the RequiredEpochSet of the live vaults it had before;
 *   - "una cuenta Private no tiene escrow blob": the account has an escrow row after the bundle iff it
 *     is Managed after it (§3.6: the last mode-setting transition decides).
 */
async function invariantsHold(bundle: SecurityBundle, state: BundleState): Promise<string | null> {
  return invariantsHoldFor(bundle, state, await validateSecurityBundle(bundle, state));
}

async function invariantsHoldFor(bundle: SecurityBundle, state: BundleState, outcome: BundleOutcome): Promise<string | null> {
  if (!outcome.ok || outcome.value.kind !== "ACCEPT") return null;
  const accepted = outcome.value.accepted;
  const root = accepted.pendingRoot;
  const account = idKey(await rootRecipientId(root.account_encryption_public_key));
  const recovery = idKey(await rootRecipientId(root.recovery_encryption_public_key));
  for (const epoch of accepted.epochs) {
    const ids = new Set(epoch.envelopes.map((e) => idKey(e.recipient_id)));
    if (!ids.has(account) || !ids.has(recovery)) return "a new epoch is not readable by ACCOUNT and RECOVERY";
  }

  const activated: string[] = [];
  const before = state.root?.descriptor;
  if (before !== undefined) {
    if (idKey(await rootRecipientId(before.account_encryption_public_key)) !== account) activated.push(account);
    if (idKey(await rootRecipientId(before.recovery_encryption_public_key)) !== recovery) activated.push(recovery);
  }
  const known = new Set((state.registry?.registry.recipients ?? []).map((r) => idKey(r.recipient_id)));
  if (state.registry !== null) {
    for (const r of accepted.pendingRegistry.recipients) if (!known.has(idKey(r.recipient_id))) activated.push(idKey(r.recipient_id));
  }
  const required = requiredEpochSet(state.vaults.map((v) => ({ vaultId: v.vaultId, state: v.state, epochs: v.epochs })));
  for (const key of activated) {
    for (const epoch of required) {
      const covered = accepted.coverageEnvelopes.some(
        (e) => idKey(e.recipient_id) === key && idKey(e.vault_id) === idKey(epoch.vaultId) && idKey(e.epoch_id) === idKey(epoch.epochId),
      );
      if (!covered) return "a reading key was activated without full coverage";
    }
  }

  const escrowAfter =
    accepted.escrowChange === null ? state.escrow !== null : accepted.escrowChange.kind !== "DELETE";
  const type = bundle.root_transition?.transition_type;
  const managedAfter =
    type === "GENESIS" ? root.crypto_version === 2
    : type === "SWITCH_TO_MANAGED" ? true
    : type === "SWITCH_TO_PRIVATE" ? false
    : state.escrow !== null;
  if (escrowAfter !== managedAfter) return "the account's escrow does not match its mode";
  return null;
}

// §35.1: "reintentables, SECURITY_STATE_STALE, EPOCH_STALE, VAULT_SET_STALE, COVERAGE_STALE,
// REAUTH_REQUIRED, RECOVERY_NOT_MATURE y EMAIL_UNCONFIRMED".
const RETRYABLE = new Set([
  "SECURITY_STATE_STALE",
  "EPOCH_STALE",
  "VAULT_SET_STALE",
  "COVERAGE_STALE",
  "REAUTH_REQUIRED",
  "RECOVERY_NOT_MATURE",
  "EMAIL_UNCONFIRMED",
]);
const STEP_0_CODES = new Set(["WRITE_CAPABILITY_REQUIRED", "SCOPE_REQUIRED", "RECIPIENT_REVOKED"]);
// §35.1: "RECOVERY_REQUEST_REQUIRED (este último, excepción: ni se guarda ni consume nada)" (§35.15).
const DEFINITIVE_NOT_STORED = new Set(["RECOVERY_REQUEST_REQUIRED"]);

/**
 * §35.1's classification, re-derived here from the step and the code alone. If the implementation
 * ever restated it per call site instead of deriving it, this would catch the first divergence.
 */
function classificationHolds(outcome: BundleOutcome): boolean {
  if (outcome.ok) return true;
  const f = outcome.failure;
  if (!(BUNDLE_STEPS as readonly string[]).includes(f.step)) return false;
  if (f.retryable !== RETRYABLE.has(f.code)) return false;
  const shouldStore =
    !f.retryable && f.step !== "0" && f.step !== "0b" && !STEP_0_CODES.has(f.code) && !DEFINITIVE_NOT_STORED.has(f.code);
  if (f.stored !== shouldStore) return false;
  if (f.consumesNonce && !f.stored) return false;
  // Only a retryable code carries state back to the client.
  if (!f.retryable && (f.expected !== undefined || f.vaultIds !== undefined || f.required !== undefined)) return false;
  return true;
}

/** The applicability table, re-read independently of `validateSecurityBundle`. */
function applicabilityHolds(bundle: SecurityBundle, state: BundleState): boolean {
  const rules = operationRules(bundle.operation_type as OperationType);
  const record = bundle as unknown as Record<string, unknown>;
  for (const name of forbiddenFields(rules)) if (record[name] !== undefined) return false;
  for (const name of requiredFields(rules)) if (record[name] === undefined) return false;
  if (rules.transition !== null && bundle.root_transition?.transition_type !== rules.transition) return false;
  if (bundle.expected.root_generation !== (state.root?.rootGeneration ?? 0)) return false;
  if (bundle.expected.registry_version !== (state.registry?.registry.registry_version ?? 0)) return false;
  if (bundle.expected.config_version !== state.configVersion) return false;
  const next = state.configVersion + 1;
  if (bundle.profile !== undefined && bundle.profile.config_version !== next) return false;
  if (bundle.config_version !== undefined && bundle.config_version !== next) return false;
  return true;
}

/** Every mutation a case can suffer. Each is a pure function of a scenario. */
type Mutation = { readonly name: string; readonly apply: (s: Scenario) => Scenario };

function mutations(): Mutation[] {
  const dropField = (name: string): Mutation => ({
    name: `drop:${name}`,
    apply: (s) => ({ ...s, bundle: patch(s.bundle, { [name]: undefined }) }),
  });
  const addField = (name: string, value: unknown): Mutation => ({
    name: `add:${name}`,
    apply: (s) => ({ ...s, bundle: patch(s.bundle, { [name]: value }) }),
  });
  return [
    { name: "none", apply: (s) => s },
    ...[
      "root_transition",
      "root_descriptor",
      "registry",
      "profile",
      "profile_signature",
      "config_blob",
      "config_version",
      "epochs",
      "coverage_envelopes",
      "deletion",
      "escrow",
    ].map(dropField),
    addField("escrow", makeEscrow(filled(16, 0x11), { unlock: true, recovery: true })),
    { name: "add:escrow-unlock", apply: (s) => ({ ...s, bundle: patch(s.bundle, { escrow: makeEscrow(world.accountId, { unlock: true }) }) }) },
    { name: "state:managed", apply: (s) => ({ ...s, state: { ...s.state, escrow: makeEscrow(world.accountId, { unlock: true, recovery: true }) } }) },
    { name: "state:private", apply: (s) => ({ ...s, state: { ...s.state, escrow: null } }) },
    {
      name: "state:reauth-stale",
      apply: (s) => ({ ...s, state: { ...s.state, authorization: { ...s.state.authorization, primaryAuthAgeSeconds: 3_600 } } }),
    },
    addField("profile_signature", filled(64, 0x11)),
    addField("config_blob", filled(64, 0x04)),
    addField("config_version", 2),
    addField("coverage_envelopes", []),
    addField("epochs", []),
    {
      name: "add:profile",
      apply: (s) => ({ ...s, bundle: patch(s.bundle, { profile: makeProfile(world.accountId, 2) }) }),
    },
    {
      name: "bump:expected",
      apply: (s) => ({
        ...s,
        bundle: patch(s.bundle, { expected: { ...s.bundle.expected, config_version: s.bundle.expected.config_version + 1 } }),
      }),
    },
    {
      name: "shuffle:epochs",
      apply: (s) => ({ ...s, bundle: patch(s.bundle, { epochs: [...(s.bundle.epochs ?? [])].reverse() }) }),
    },
    {
      name: "shuffle:coverage",
      apply: (s) => ({
        ...s,
        bundle: patch(s.bundle, { coverage_envelopes: [...(s.bundle.coverage_envelopes ?? [])].reverse() }),
      }),
    },
    { name: "state:no-token", apply: (s) => ({ ...s, state: { ...s.state, authorization: { authenticated: true, emailConfirmed: true } } }) },
    {
      name: "state:recovery-only",
      apply: (s) => ({ ...s, state: { ...s.state, authorization: { authenticated: true, emailConfirmed: true, token: { scopes: ["RECOVERY_CONTROL"] } } } }),
    },
    { name: "state:account-scheduled", apply: (s) => ({ ...s, state: { ...s.state, accountState: "DELETING_SCHEDULED" } }) },
    { name: "state:config-ahead", apply: (s) => ({ ...s, state: { ...s.state, configVersion: s.state.configVersion + 1 } }) },
    {
      name: "state:vault-deleted",
      apply: (s) => ({
        ...s,
        state: { ...s.state, vaults: s.state.vaults.map((v, i) => (i === 1 ? { ...v, state: "DELETED" as const } : v)) },
      }),
    },
    {
      name: "state:vault-scheduled",
      apply: (s) => ({
        ...s,
        state: { ...s.state, vaults: s.state.vaults.map((v, i) => (i === 0 ? { ...v, state: "DELETING_SCHEDULED" as const } : v)) },
      }),
    },
    {
      name: "state:nonce-consumed",
      apply: (s) => ({
        ...s,
        state: { ...s.state, consumedNonces: s.bundle.deletion === undefined ? [] : [s.bundle.deletion.nonce] },
      }),
    },
    { name: "state:plugin-limit", apply: (s) => ({ ...s, state: { ...s.state, pluginLimit: 0 } }) },
    { name: "state:vault-limit", apply: (s) => ({ ...s, state: { ...s.state, vaultLimit: 1 } }) },
    {
      name: "state:stored-result",
      apply: (s) => ({
        ...s,
        state: { ...s.state, storedResult: { operationType: s.bundle.operation_type as OperationType, result: { applied: true } } },
      }),
    },
  ];
}

describe("§44.5 key invariants over every accepted bundle", () => {
  it("no key without full coverage, every new epoch readable by ACCOUNT and RECOVERY, escrow iff Managed", async () => {
    await fc.assert(
      fc.asyncProperty(fc.nat({ max: 1_000 }), fc.constantFrom(...mutations()), async (index, mutation) => {
        const [type, base] = pool[index % pool.length]!;
        const { bundle, state } = mutation.apply(base);
        expect(await invariantsHold(bundle, state), `${type}/${mutation.name}`).toBeNull();
      }),
      { numRuns: 400 },
    );
  });

  it("every scenario of the pool is accepted, so the invariants are checked on real acceptances", async () => {
    for (const [name, { bundle, state }] of pool) {
      const outcome = await validateSecurityBundle(bundle, state);
      expect(outcome.ok && outcome.value.kind, name).toBe("ACCEPT");
    }
  });

  it("the invariants detect what they claim to (broken inputs fed straight to the oracle)", async () => {
    // A SWITCH_TO_PRIVATE whose coverage omits the new RECOVERY key, judged as if it had been accepted.
    const { bundle, state } = scenarios.get("SWITCH_TO_PRIVATE")!;
    const newRecovery = idKey(await rootRecipientId(bundle.root_descriptor!.recovery_encryption_public_key));
    const partial = (bundle.coverage_envelopes ?? []).filter((e) => idKey(e.recipient_id) !== newRecovery);
    expect(await invariantsOf(bundle, state, { coverageEnvelopes: partial })).toBe("a reading key was activated without full coverage");
    // An epoch without its RECOVERY envelope.
    const epochs = (bundle.epochs ?? []).map((e, i) => (i === 0 ? { ...e, envelopes: e.envelopes.filter((x) => idKey(x.recipient_id) !== newRecovery) } : e));
    expect(await invariantsOf(bundle, state, { epochs })).toBe("a new epoch is not readable by ACCOUNT and RECOVERY");
    // A switch to Private that keeps the escrow row.
    expect(await invariantsOf(bundle, state, { escrowChange: null })).toBe("the account's escrow does not match its mode");
  });
});

/**
 * The oracle of {@link invariantsHold} over an accepted bundle whose `AcceptedBundle` is replaced in
 * part — a validator that let a broken bundle through would hand the oracle exactly this.
 */
async function invariantsOf(bundle: SecurityBundle, state: BundleState, override: Partial<AcceptedBundle>): Promise<string | null> {
  const outcome = await validateSecurityBundle(bundle, state);
  if (!outcome.ok || outcome.value.kind !== "ACCEPT") throw new Error("the base must be accepted");
  const forged: BundleOutcome = { ok: true, value: { kind: "ACCEPT", accepted: { ...outcome.value.accepted, ...override } } };
  return invariantsHoldFor(bundle, state, forged);
}

describe("§35.1.1 properties", () => {
  it("every mutated bundle either carries a typed step failure or genuinely satisfies the table", async () => {
    const ops = fc.nat({ max: 1_000 });
    const muts = fc.constantFrom(...mutations());
    await fc.assert(
      fc.asyncProperty(ops, muts, async (index, mutation) => {
        const [type, base] = pool[index % pool.length]!;
        const { bundle, state } = mutation.apply(base);
        const outcome = await validateSecurityBundle(bundle, state);
        expect(classificationHolds(outcome), `${type}/${mutation.name}`).toBe(true);
        if (outcome.ok && outcome.value.kind === "ACCEPT") {
          expect(applicabilityHolds(bundle, state), `${type}/${mutation.name}`).toBe(true);
        }
      }),
      { numRuns: 400 },
    );
  });

  // Regression: fast-check seed 699267598, path "156" — RECOVERY_RESET/managed/state:private. A
  // Managed reset replayed on a Private account without a matured request is rejected at step 0c
  // with RECOVERY_REQUEST_REQUIRED, which §35.1 makes definitive but **not** stored (ADR-022).
  it("the classification oracle follows §35.1 for the §35.15 codes (seed 699267598)", async () => {
    const managed = pool.find(([name]) => name === "RECOVERY_RESET/managed")![1];
    const required = await validateSecurityBundle(managed.bundle, { ...managed.state, escrow: null });
    expect(!required.ok && required.failure.code).toBe("RECOVERY_REQUEST_REQUIRED");
    expect(classificationHolds(required)).toBe(true);

    const reset = scenarios.get("RECOVERY_RESET")!;
    const immature = await validateSecurityBundle(reset.bundle, {
      ...reset.state,
      recoveryRequests: [storedRequest("RECOVERY_RESET", { ageMs: 1 })],
    });
    expect(!immature.ok && immature.failure.code).toBe("RECOVERY_NOT_MATURE");
    expect(classificationHolds(immature)).toBe(true);

    // The oracle still catches a validator that stored them, or failed to mark the wait retryable.
    if (required.ok || immature.ok) throw new Error("both must be rejections");
    expect(classificationHolds({ ok: false, failure: { ...required.failure, stored: true } })).toBe(false);
    expect(classificationHolds({ ok: false, failure: { ...immature.failure, retryable: false } })).toBe(false);
  });

  it("replays the seed that found it", async () => {
    await fc.assert(
      fc.asyncProperty(fc.nat({ max: 1_000 }), fc.constantFrom(...mutations()), async (index, mutation) => {
        const [type, base] = pool[index % pool.length]!;
        const { bundle, state } = mutation.apply(base);
        expect(classificationHolds(await validateSecurityBundle(bundle, state)), `${type}/${mutation.name}`).toBe(true);
      }),
      { seed: 699267598, path: "156", endOnFailure: true },
    );
  });

  it("is deterministic: the same bundle and state always get the same answer", async () => {
    const ops = fc.constantFrom(...OPERATION_TYPES);
    const muts = fc.constantFrom(...mutations());
    await fc.assert(
      fc.asyncProperty(ops, muts, async (type, mutation) => {
        const base = scenarios.get(type);
        if (base === undefined) throw new Error(`no scenario for ${type}`);
        const { bundle, state } = mutation.apply(base);
        const a = await validateSecurityBundle(bundle, state);
        const b = await validateSecurityBundle(bundle, state);
        expect(summarize(a)).toEqual(summarize(b));
      }),
      { numRuns: 120 },
    );
  });

  it("dropping any applicable field is always rejected, definitively", async () => {
    const cases: { type: OperationType; field: string }[] = [];
    for (const type of OPERATION_TYPES) {
      for (const field of requiredFields(operationRules(type))) cases.push({ type, field });
    }
    expect(cases.length).toBeGreaterThan(15);
    for (const { type, field } of cases) {
      const base = scenarios.get(type);
      if (base === undefined) throw new Error(`no scenario for ${type}`);
      const outcome = await validateSecurityBundle(patch(base.bundle, { [field]: undefined }), base.state);
      expect(outcome.ok, `${type}/${field}`).toBe(false);
      if (!outcome.ok) expect(outcome.failure.retryable, `${type}/${field}`).toBe(false);
    }
  });

  it("adding any field the table forbids is always rejected", async () => {
    const values: Record<string, unknown> = {
      root_transition: scenarios.get("RECOVERY_RESET")?.bundle.root_transition,
      root_descriptor: scenarios.get("RECOVERY_RESET")?.bundle.root_descriptor,
      registry: scenarios.get("ENROLL_CLIENT")?.bundle.registry,
      profile: makeProfile(world.accountId, 2),
      profile_signature: filled(64, 0x11),
      config_blob: filled(64, 0x04),
      config_version: 2,
      epochs: [],
      coverage_envelopes: [],
      deletion: scenarios.get("DELETE_VAULT")?.bundle.deletion,
      escrow: makeEscrow(world.accountId, { unlock: true, recovery: true }),
      recovery: scenarios.get("RECOVERY_VETO")?.bundle.recovery,
    };
    for (const type of OPERATION_TYPES) {
      const base = scenarios.get(type);
      if (base === undefined) throw new Error(`no scenario for ${type}`);
      for (const field of forbiddenFields(operationRules(type))) {
        const outcome = await validateSecurityBundle(patch(base.bundle, { [field]: values[field] }), base.state);
        expect(outcome.ok, `${type}/${field}`).toBe(false);
      }
    }
  });

  it("reordering an epoch or a coverage envelope never changes the answer", async () => {
    for (const type of ["REVOKE_CLIENT", "RECOVERY_RESET", "ENROLL_CLIENT"] as const) {
      const base = scenarios.get(type);
      if (base === undefined) throw new Error(`no scenario for ${type}`);
      const reversed = patch(base.bundle, {
        ...(base.bundle.epochs === undefined ? {} : { epochs: [...base.bundle.epochs].reverse() }),
        ...(base.bundle.coverage_envelopes === undefined
          ? {}
          : { coverage_envelopes: [...base.bundle.coverage_envelopes].reverse() }),
      });
      const outcome = await validateSecurityBundle(reversed, base.state);
      expect(outcome.ok, type).toBe(true);
    }
  });
});

function summarize(outcome: BundleOutcome): unknown {
  return outcome.ok
    ? { kind: outcome.value.kind }
    : { code: outcome.failure.code, step: outcome.failure.step, rule: outcome.failure.rule };
}
