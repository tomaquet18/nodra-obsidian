// §44.5, the four ADR-022 invariants, over random sequences of requests, vetoes, cancellations,
// phase-2 bundles, clock ticks and scheduled deletions:
//
//   ningún RECOVERY_RESET, RECOVERY_KIT_REPLACEMENT ni SWITCH_TO_MANAGED se aplica en una cuenta
//     Private sin una solicitud madura, viva, no vetada ni cancelada, del mismo tipo y de la misma
//     generación, que ese mismo commit consume
//   una solicitud vetada, cancelada, caducada o invalidada nunca madura ni se consume
//   una cuenta nunca tiene más de una solicitud de recovery viva, y tras una transición de raíz no
//     queda ninguna PENDING de la generación anterior
//
// The decisions are the real `validateSecurityBundle`; step 8 is a model of what the Worker writes
// (the SQL of `nodra_apply_bundle` is held to the same rules in workers/api). Each invariant is also
// run against a broken variant — a validator without the 0c gate, a veto that only hides the
// request, a step 8 without the invalidation rule — and the property MUST find the violation.
import fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";
import type { SecurityBundle } from "@nodra/encoding/records";
import { validateSecurityBundle } from "../src/bundle.js";
import type { BundleOutcome, BundleState } from "../src/bundle.js";
import { assembleBundle, signRecoveryRecord } from "../src/bundle-build.js";
import { idKey } from "../src/epoch.js";
import { RECOVERY_RECORD_SIGNERS } from "../src/operations.js";
import type { OperationType, RecoveryRecordOperation, RecoveryRequestKind } from "../src/operations.js";
import { isLive, isMature } from "../src/recovery-request-state.js";
import type { RecoveryRequestState, StoredRecoveryRequest } from "../src/recovery-request-state.js";
import { BUNDLE_ID, DELAY_MS, NOW, TTL_MS, allScenarios, expectedOf, makeBundleWorld } from "./bundle-support.js";
import type { BundleWorld, Scenario } from "./bundle-support.js";
import { filled } from "./support.js";

const KINDS: readonly RecoveryRequestKind[] = ["RECOVERY_RESET", "RECOVERY_KIT_REPLACEMENT", "SWITCH_TO_MANAGED"];
const RECORD_OPS: readonly RecoveryRecordOperation[] = ["RECOVERY_REQUEST", "RECOVERY_VETO", "RECOVERY_CANCEL"];
/** A small pool, so the generator reuses request_ids (NONCE_REUSED) and names the live one often. */
const IDS = [0xa1, 0xa2, 0xa3, 0xa4].map((b) => filled(16, b));

let world: BundleWorld;
let scenarios: ReadonlyMap<OperationType, Scenario>;
/** Every record the generator can send, signed once: by (op, kind, id index, correct signer?). */
const records = new Map<string, SecurityBundle>();

beforeAll(async () => {
  world = await makeBundleWorld();
  scenarios = await allScenarios(world);
  for (const op of RECORD_OPS) {
    for (const kind of KINDS) {
      for (const [i, requestId] of IDS.entries()) {
        for (const correct of [true, false]) {
          const role = RECOVERY_RECORD_SIGNERS[op][kind].role;
          // The wrong signer is the *other* authority of the account: the shortcut a veto must not allow.
          const signer = (role === 1) === correct ? world.as1 : world.ra1;
          const recovery = await signRecoveryRecord(signer.privateKey, {
            operationType: op,
            accountId: world.accountId,
            requestId,
            kind,
            rootGeneration: 1,
            rootHash: world.rootHash,
          });
          records.set(`${op}/${kind}/${i}/${correct}`, assembleBundle({ operationType: op, bundleId: BUNDLE_ID, expected: expectedOf(world.state), recovery }));
        }
      }
    }
  }
}, 120_000);

// --- The model ---------------------------------------------------------------------------------------

interface Row {
  readonly requestId: Uint8Array;
  readonly kind: RecoveryRequestKind;
  readonly rootGeneration: number;
  state: RecoveryRequestState;
  readonly maturesAt: number;
  readonly expiresAt: number;
}

interface Model {
  now: number;
  generation: number;
  accountState: "ACTIVE" | "DELETING_SCHEDULED";
  rows: Row[];
  /** Ids a VETO or CANCEL was *accepted* for, or that left PENDING: they must never be consumed. */
  ended: Set<string>;
  /** Set when a root transition applied; the validator's world only has generation 1. */
  transitioned: boolean;
}

type Action =
  | { readonly t: "tick"; readonly to: "maturity" | "maturity-1" | "expiry" | "expiry-1" | "delta"; readonly delta: number }
  /** `aim`: name the live request's own id and kind, so vetoes and cancels are not almost always unknown. */
  | { readonly t: "record"; readonly op: RecoveryRecordOperation; readonly kind: RecoveryRequestKind; readonly id: number; readonly correct: boolean; readonly aim: boolean }
  | { readonly t: "phase2"; readonly kind: RecoveryRequestKind }
  | { readonly t: "schedule-delete" }
  /** A root transition that consumes nothing, applied straight to step 8 (a future A.3 rotation). */
  | { readonly t: "inject" };

const arbAction: fc.Arbitrary<Action> = fc.oneof(
  { weight: 3, arbitrary: fc.record({ t: fc.constant("tick" as const), to: fc.constantFrom("maturity", "maturity-1", "expiry", "expiry-1", "delta" as const), delta: fc.integer({ min: 1, max: TTL_MS }) }) },
  { weight: 5, arbitrary: fc.record({ t: fc.constant("record" as const), op: fc.constantFrom(...RECORD_OPS), kind: fc.constantFrom(...KINDS), id: fc.integer({ min: 0, max: IDS.length - 1 }), correct: fc.constantFrom(true, true, true, false), aim: fc.boolean() }) },
  { weight: 3, arbitrary: fc.record({ t: fc.constant("phase2" as const), kind: fc.constantFrom(...KINDS) }) },
  { weight: 1, arbitrary: fc.constant({ t: "schedule-delete" as const }) },
  { weight: 1, arbitrary: fc.constant({ t: "inject" as const }) },
);

type Validator = (bundle: SecurityBundle, state: BundleState) => Promise<BundleOutcome>;

interface Step8 {
  /** VETO/CANCEL: set the row's final state. The broken variant only hides it. */
  readonly endsOnVeto: boolean;
  /** Every root transition sets every other PENDING request to INVALIDATED. */
  readonly invalidates: boolean;
}

const REAL_STEP8: Step8 = { endsOnVeto: true, invalidates: true };

/** `nodra_security_state`'s lazy expiry, under the account lock, before anything reads the rows. */
function expire(model: Model): void {
  for (const row of model.rows) {
    if (row.state === "PENDING" && row.expiresAt <= model.now) {
      row.state = "EXPIRED";
      model.ended.add(idKey(row.requestId));
    }
  }
}

function stateFor(model: Model, base: BundleState): BundleState {
  return {
    ...base,
    accountState: model.accountState,
    now: model.now,
    recoveryRequests: model.rows.map((r): StoredRecoveryRequest => ({ ...r })),
  };
}

function rootTransition(model: Model, step8: Step8, consumed: string | null): void {
  model.generation += 1;
  model.transitioned = true;
  if (!step8.invalidates) return;
  for (const row of model.rows) {
    if (row.state === "PENDING" && idKey(row.requestId) !== consumed) {
      row.state = "INVALIDATED";
      model.ended.add(idKey(row.requestId));
    }
  }
}

/** One action under the account lock; returns a violation message, or null. */
async function step(model: Model, action: Action, validate: Validator, step8: Step8): Promise<string | null> {
  if (action.t === "tick") {
    const live = model.rows.find((r) => isLive(r, model.now));
    const target =
      live === undefined || action.to === "delta"
        ? model.now + action.delta
        : { maturity: live.maturesAt, "maturity-1": live.maturesAt - 1, expiry: live.expiresAt, "expiry-1": live.expiresAt - 1 }[action.to];
    model.now = Math.max(model.now, target);
    return null;
  }
  if (action.t === "schedule-delete") {
    model.accountState = "DELETING_SCHEDULED";
    return null;
  }
  if (action.t === "inject") {
    rootTransition(model, step8, null);
    return null;
  }

  expire(model);
  const before = model.rows.map((r) => ({ ...r }));
  if (action.t === "record") {
    const live = action.aim ? model.rows.find((r) => isLive(r, model.now)) : undefined;
    const kind = live?.kind ?? action.kind;
    const id = live === undefined ? action.id : IDS.findIndex((x) => idKey(x) === idKey(live.requestId));
    const bundle = records.get(`${action.op}/${kind}/${id}/${action.correct}`)!;
    const scopes = RECOVERY_RECORD_SIGNERS[action.op][kind].scopes;
    const outcome = await validate(bundle, stateFor(model, { ...world.state, authorization: { authenticated: true, token: { scopes } } }));
    if (!outcome.ok || outcome.value.kind !== "ACCEPT") return null;
    const change = outcome.value.accepted.recoveryChange;
    if (change?.kind === "REQUEST") {
      model.rows.push({
        requestId: change.requestId,
        kind: change.requestKind,
        rootGeneration: change.rootGeneration,
        state: "PENDING",
        maturesAt: model.now + DELAY_MS,
        expiresAt: model.now + DELAY_MS + TTL_MS,
      });
    } else if (change?.kind === "VETO" || change?.kind === "CANCEL") {
      model.ended.add(idKey(change.requestId));
      const row = model.rows.find((r) => idKey(r.requestId) === idKey(change.requestId) && r.state === "PENDING");
      if (step8.endsOnVeto && row !== undefined) row.state = change.kind === "VETO" ? "VETOED" : "CANCELLED";
    }
  } else {
    const { bundle, state } = scenarios.get(action.kind)!;
    const outcome = await validate(bundle, stateFor(model, state));
    if (!outcome.ok || outcome.value.kind !== "ACCEPT") return null;
    // Invariant 1: a delayed operation applied only with a matured, live, same-kind, same-generation request…
    const authorizing = before.find(
      (r) => r.kind === action.kind && r.rootGeneration === model.generation && isMature(r, model.now) && !model.ended.has(idKey(r.requestId)),
    );
    const change = outcome.value.accepted.recoveryChange;
    if (authorizing === undefined) return `${action.kind} applied without a matured live request of its kind`;
    // …which that same commit consumes.
    if (change?.kind !== "CONSUME") return `${action.kind} applied without consuming its request`;
    const consumed = idKey(change.requestId);
    // Invariant 2: never an ended (vetoed, cancelled, expired, invalidated) one.
    if (model.ended.has(consumed)) return `${action.kind} consumed an ended request`;
    const row = model.rows.find((r) => idKey(r.requestId) === consumed)!;
    row.state = "CONSUMED";
    model.ended.add(consumed);
    rootTransition(model, step8, consumed);
  }
  return null;
}

/** Invariant 3, checked after every step. */
function structural(model: Model): string | null {
  const live = model.rows.filter((r) => isLive(r, model.now));
  if (live.length > 1) return `${live.length} live requests`;
  if (model.transitioned && model.rows.some((r) => r.state === "PENDING" && r.rootGeneration < model.generation)) {
    return "a PENDING request of an earlier generation survived a root transition";
  }
  // Invariant 2 again, on the rows: an ended request is never mature.
  for (const row of model.rows) {
    if (model.ended.has(idKey(row.requestId)) && row.state !== "CONSUMED" && isMature(row, model.now)) {
      return "an ended request matured";
    }
  }
  return null;
}

async function run(actions: readonly Action[], validate: Validator, step8: Step8): Promise<string | null> {
  const model: Model = { now: NOW, generation: 1, accountState: "ACTIVE", rows: [], ended: new Set(), transitioned: false };
  for (const action of actions) {
    // The validator's world is generation 1; after a root transition the account is another one.
    if (model.transitioned) break;
    const violation = (await step(model, action, validate, step8)) ?? structural(model);
    if (violation !== null) return violation;
  }
  return null;
}

const arbSequence = fc.array(arbAction, { minLength: 1, maxLength: 14 });

function property(validate: Validator, step8: Step8) {
  return fc.asyncProperty(arbSequence, async (actions) => {
    const violation = await run(actions, validate, step8);
    if (violation !== null) throw new Error(violation);
  });
}

describe("§44.5 ADR-022 invariants", () => {
  it("hold for the real validator and step 8 on random sequences", async () => {
    await fc.assert(property(validateSecurityBundle, REAL_STEP8), { numRuns: 500 });
  }, 600_000);

  it("are reached: the generator applies phase-2 bundles, vetoes, expiries and same-instant boundaries", async () => {
    // A property that never applies a phase 2 would hold vacuously; this pins the generator's reach.
    const seen = new Set<string>();
    await fc.assert(
      fc.asyncProperty(arbSequence, async (actions) => {
        const model: Model = { now: NOW, generation: 1, accountState: "ACTIVE", rows: [], ended: new Set(), transitioned: false };
        for (const action of actions) {
          if (model.transitioned) break;
          const consumedBefore = model.rows.filter((r) => r.state === "CONSUMED").length;
          await step(model, action, validateSecurityBundle, REAL_STEP8);
          if (model.rows.filter((r) => r.state === "CONSUMED").length > consumedBefore) seen.add("phase2");
          for (const r of model.rows) seen.add(r.state);
          if (model.rows.some((r) => r.maturesAt === model.now)) seen.add("at-maturity");
          if (model.rows.some((r) => r.expiresAt === model.now)) seen.add("at-expiry");
          if (model.accountState === "DELETING_SCHEDULED" && model.rows.some((r) => r.kind === "RECOVERY_RESET")) seen.add("request-while-deleting");
        }
      }),
      { numRuns: 300, seed: 22 },
    );
    for (const reached of ["phase2", "PENDING", "VETOED", "CANCELLED", "CONSUMED", "EXPIRED", "at-maturity", "at-expiry", "request-while-deleting"]) {
      expect(seen, reached).toContain(reached);
    }
  }, 600_000);
});

describe("§44.5 ADR-022 invariants catch the broken variants", () => {
  /** The violation the property finds, or null: the message pins *which* invariant caught it. */
  async function finds(validate: Validator, step8: Step8): Promise<string | null> {
    const result = await fc.check(property(validate, step8), { numRuns: 400, seed: 7 });
    return result.failed ? String((result.errorInstance as Error | undefined)?.message) : null;
  }

  it("a validator without the step-0c gate [sin la comprobación de 0c]", async () => {
    // The gate removed: the validator is shown a matured request of the bundle's kind whatever exists.
    const gateless: Validator = (bundle, state) => {
      const kind = bundle.operation_type as RecoveryRequestKind;
      if (!KINDS.includes(kind) || bundle.recovery !== undefined) return validateSecurityBundle(bundle, state);
      const fake: StoredRecoveryRequest = { requestId: filled(16, 0xee), kind, rootGeneration: 1, state: "PENDING", maturesAt: 0, expiresAt: Number.MAX_SAFE_INTEGER };
      return validateSecurityBundle(bundle, { ...state, recoveryRequests: [...(state.recoveryRequests ?? []), fake] });
    };
    expect(await finds(gateless, REAL_STEP8)).toMatch(/applied without a matured live request/);
  }, 600_000);

  it("a veto or cancel that only hides the request [veto que solo oculta la solicitud]", async () => {
    expect(await finds(validateSecurityBundle, { ...REAL_STEP8, endsOnVeto: false })).toMatch(/ended request|live requests/);
  }, 600_000);

  it("a step 8 without the invalidation rule, through an injected transition that consumes nothing", async () => {
    // In the MVP every Private transition consumes the only live request, so this rule can only fail
    // through a transition that does not — which is why the generator has `inject`.
    expect(await finds(validateSecurityBundle, { ...REAL_STEP8, invalidates: false })).toMatch(/earlier generation survived/);
  }, 600_000);
});
