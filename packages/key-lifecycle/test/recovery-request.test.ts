// §35.15 (ADR-022): delay and veto of the three operations that change an authority with only one of
// the two of §28.2, as §35.1.1 decides them, and the §44.4 "Delay y veto" list line by line.
//
// Every line of §44.4 names, in brackets, the shortcut its test must catch. Those shortcuts are
// written out at the bottom as broken variants and run against the same inputs, so "this test would
// fail without the check" is a value in an assertion, not a claim in a comment.
import { beforeAll, describe, expect, it } from "vitest";
import type { RecoveryRecord, SecurityBundle } from "@nodra/encoding/records";
import { importVerifyingKey, verifyContext } from "@nodra/crypto";
import { validateSecurityBundle } from "../src/bundle.js";
import type { BundleFailure, BundleState, RecoveryChange } from "../src/bundle.js";
import { assembleBundle, signDeletion, signRecoveryRecord } from "../src/bundle-build.js";
import { recoveryRequestContext } from "../src/contexts.js";
import { OPERATION_RULES, RECOVERY_RECORD_SIGNERS, vetoRole } from "../src/operations.js";
import type { OperationType, RecoveryRecordOperation, RecoveryRequestKind, Scope } from "../src/operations.js";
import { isLive, isMature, recoveryRequestPhase } from "../src/recovery-request-state.js";
import type { StoredRecoveryRequest } from "../src/recovery-request-state.js";
import { cancelRecovery, requestRecovery, verifyRecoveryRequest, vetoRecovery } from "../src/recovery-request.js";
import type { RecoveryRecordView } from "../src/recovery-request.js";
import {
  BUNDLE_ID,
  DELAY_MS,
  NOW,
  REQUEST_ID,
  TTL_MS,
  VAULT_A,
  allScenarios,
  deletionScenario,
  expectedOf,
  makeBundleWorld,
  managedRecoveryResetScenario,
  managedState,
  patch,
  storedRequest,
} from "./bundle-support.js";
import type { BundleWorld, Scenario } from "./bundle-support.js";
import type { Signer } from "./chain-support.js";
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

async function reject(bundle: SecurityBundle, state: BundleState): Promise<BundleFailure> {
  const outcome = await validateSecurityBundle(bundle, state);
  if (outcome.ok) throw new Error(`expected a rejection, got ${outcome.value.kind}`);
  return outcome.failure;
}

async function accepted(bundle: SecurityBundle, state: BundleState): Promise<RecoveryChange | null> {
  const outcome = await validateSecurityBundle(bundle, state);
  if (!outcome.ok) throw new Error(`${outcome.failure.step} ${outcome.failure.code} ${outcome.failure.rule}: ${outcome.failure.message}`);
  if (outcome.value.kind !== "ACCEPT") throw new Error("expected ACCEPT");
  return outcome.value.accepted.recoveryChange;
}

const DELAYED: readonly RecoveryRequestKind[] = ["RECOVERY_RESET", "RECOVERY_KIT_REPLACEMENT", "SWITCH_TO_MANAGED"];
const RECORDS: readonly RecoveryRecordOperation[] = ["RECOVERY_REQUEST", "RECOVERY_VETO", "RECOVERY_CANCEL"];

function withRequests(state: BundleState, requests: readonly StoredRecoveryRequest[], now = NOW): BundleState {
  return { ...state, now, recoveryRequests: requests };
}

function withScopes(state: BundleState, scopes: readonly Scope[]): BundleState {
  return { ...state, authorization: { authenticated: true, emailConfirmed: true, token: { scopes } } };
}

/** A record bundle over the world's root, signed by `signer`, with any field of the record overridden. */
async function recordBundle(
  operationType: RecoveryRecordOperation,
  kind: RecoveryRequestKind,
  signer: Signer,
  signed: Partial<{ operationType: string; accountId: Uint8Array; requestId: Uint8Array; kind: RecoveryRequestKind; rootGeneration: number; rootHash: Uint8Array }> = {},
  sent: Partial<RecoveryRecord> = {},
): Promise<SecurityBundle> {
  const record = await signRecoveryRecord(signer.privateKey, {
    operationType: (signed.operationType ?? operationType) as RecoveryRecordOperation,
    accountId: signed.accountId ?? world.accountId,
    requestId: signed.requestId ?? REQUEST_ID,
    kind: signed.kind ?? kind,
    rootGeneration: signed.rootGeneration ?? 1,
    rootHash: signed.rootHash ?? world.rootHash,
  });
  return assembleBundle({
    operationType,
    bundleId: BUNDLE_ID,
    expected: expectedOf(world.state),
    // What travels is the canonical record; only the signature comes from the (possibly altered) signed fields.
    recovery: { request_id: REQUEST_ID, kind, root_generation: 1, root_hash: world.rootHash, signature: record.signature, ...sent },
  });
}

/** The signer and scope §35.15 assigns to (operation_type, kind), from the world's generation 1. */
function signerFor(operationType: RecoveryRecordOperation, kind: RecoveryRequestKind): { signer: Signer; scopes: readonly Scope[] } {
  const row = RECOVERY_RECORD_SIGNERS[operationType][kind];
  return { signer: row.role === 1 ? world.as1 : world.ra1, scopes: row.scopes };
}

// --- The tables, transcribed again from §35.15 ------------------------------------------------------

describe("§35.15 tables", () => {
  // | operation_type | kind = RECOVERY_RESET | kind = RECOVERY_KIT_REPLACEMENT o SWITCH_TO_MANAGED |
  const SPEC: Record<RecoveryRecordOperation, { reset: [1 | 3, Scope[]]; other: [1 | 3, Scope[]] }> = {
    RECOVERY_REQUEST: { reset: [3, ["RECOVERY_CONTROL"]], other: [1, ["TRUSTED_SECURITY"]] },
    RECOVERY_CANCEL: { reset: [3, ["RECOVERY_CONTROL"]], other: [1, ["TRUSTED_SECURITY", "ACCOUNT_SECURITY"]] },
    RECOVERY_VETO: { reset: [1, ["TRUSTED_SECURITY", "ACCOUNT_SECURITY"]], other: [3, ["RECOVERY_CONTROL"]] },
  };

  for (const operationType of RECORDS) {
    for (const kind of DELAYED) {
      it(`${operationType} of ${kind}: role and scopes`, () => {
        const [role, scopes] = kind === "RECOVERY_RESET" ? SPEC[operationType].reset : SPEC[operationType].other;
        expect(RECOVERY_RECORD_SIGNERS[operationType][kind].role).toBe(role);
        expect([...RECOVERY_RECORD_SIGNERS[operationType][kind].scopes].sort()).toEqual([...scopes].sort());
      });
    }
  }

  it("the veto is cross: always the role that does not request", () => {
    for (const kind of DELAYED) {
      expect(vetoRole(kind)).not.toBe(RECOVERY_RECORD_SIGNERS.RECOVERY_REQUEST[kind].role);
    }
  });

  it("exactly the three operations of §35.15 are delayed, and the three records carry key 15", () => {
    const delayed = (Object.keys(OPERATION_RULES) as OperationType[]).filter((t) => OPERATION_RULES[t].delayed);
    expect(delayed.sort()).toEqual([...DELAYED].sort());
    const records = (Object.keys(OPERATION_RULES) as OperationType[]).filter((t) => OPERATION_RULES[t].recovery);
    expect(records.sort()).toEqual([...RECORDS].sort());
  });

  it("matured at matures_at, expired at expires_at; nothing is live without a clock", () => {
    const r = storedRequest("RECOVERY_RESET", { ageMs: 0 });
    expect(isMature(r, r.maturesAt - 1)).toBe(false);
    expect(isMature(r, r.maturesAt)).toBe(true);
    expect(isLive(r, r.expiresAt - 1)).toBe(true);
    expect(isLive(r, r.expiresAt)).toBe(false);
    expect(isLive(r, undefined)).toBe(false);
    expect(recoveryRequestPhase(r, r.maturesAt - 1)).toBe("WAITING");
    expect(recoveryRequestPhase(r, r.maturesAt)).toBe("MATURE");
    expect(recoveryRequestPhase(r, r.expiresAt)).toBe("EXPIRED");
    expect(recoveryRequestPhase({ ...r, state: "VETOED" }, r.maturesAt)).toBe("VETOED");
  });
});

// --- Phase 2: the gate of step 0c ------------------------------------------------------------------

describe("step 0c: a delayed operation needs a matured request (§44.4)", () => {
  for (const kind of DELAYED) {
    it(`${kind} in Private without a live request → RECOVERY_REQUEST_REQUIRED, definitive but not stored`, async () => {
      const { bundle, state } = scenario(kind);
      const failure = await reject(bundle, withRequests(state, []));
      expect(failure).toMatchObject({ step: "0c", code: "RECOVERY_REQUEST_REQUIRED", retryable: false, stored: false, consumesNonce: false });
    });

    it(`${kind} with a request that has not matured → RECOVERY_NOT_MATURE with matures_at, retryable, not stored`, async () => {
      const { bundle, state } = scenario(kind);
      const young = storedRequest(kind, { ageMs: DELAY_MS - 1 });
      const failure = await reject(bundle, withRequests(state, [young]));
      expect(failure).toMatchObject({ step: "0c", code: "RECOVERY_NOT_MATURE", retryable: true, stored: false, maturesAt: young.maturesAt });
    });

    it(`${kind}: a matured request of another kind, or of another generation → RECOVERY_REQUEST_REQUIRED`, async () => {
      const { bundle, state } = scenario(kind);
      for (const other of DELAYED.filter((k) => k !== kind)) {
        expect((await reject(bundle, withRequests(state, [storedRequest(other)]))).code).toBe("RECOVERY_REQUEST_REQUIRED");
      }
      expect((await reject(bundle, withRequests(state, [storedRequest(kind, { rootGeneration: 0 })]))).code).toBe("RECOVERY_REQUEST_REQUIRED");
    });

    it(`${kind}: a vetoed, cancelled, consumed, invalidated or expired request never authorizes it`, async () => {
      const { bundle, state } = scenario(kind);
      for (const terminal of ["VETOED", "CANCELLED", "CONSUMED", "INVALIDATED", "EXPIRED"] as const) {
        const failure = await reject(bundle, withRequests(state, [storedRequest(kind, { state: terminal })]));
        expect(failure.code, terminal).toBe("RECOVERY_REQUEST_REQUIRED");
      }
    });

    it(`${kind}: applied, it consumes exactly the request that authorized it`, async () => {
      const { bundle, state } = scenario(kind);
      expect(await accepted(bundle, state)).toEqual({ kind: "CONSUME", requestId: REQUEST_ID });
    });
  }

  it("exactly at matures_at → mature; exactly at expires_at → expired, so RECOVERY_REQUEST_REQUIRED", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    const r = storedRequest("RECOVERY_RESET", { ageMs: 0 });
    expect(await accepted(bundle, withRequests(state, [r], r.maturesAt))).toMatchObject({ kind: "CONSUME" });
    expect(await accepted(bundle, withRequests(state, [r], r.expiresAt - 1))).toMatchObject({ kind: "CONSUME" });
    expect((await reject(bundle, withRequests(state, [r], r.maturesAt - 1))).code).toBe("RECOVERY_NOT_MATURE");
    expect((await reject(bundle, withRequests(state, [r], r.expiresAt))).code).toBe("RECOVERY_REQUEST_REQUIRED");
  });

  it("without the database clock nothing is mature: the gate fails closed", async () => {
    const { bundle, state } = scenario("RECOVERY_RESET");
    const { now: _now, ...clockless } = state;
    expect((await reject(bundle, clockless)).code).toBe("RECOVERY_REQUEST_REQUIRED");
  });

  it("a second phase-2 bundle with another bundle_id after the consumption → RECOVERY_REQUEST_REQUIRED; the same bundle_id → the stored result", async () => {
    const { bundle, state } = scenario("RECOVERY_KIT_REPLACEMENT");
    const consumed = withRequests(state, [storedRequest("RECOVERY_KIT_REPLACEMENT", { state: "CONSUMED" })]);
    expect((await reject(patch(bundle, { bundle_id: filled(16, 0x7c) }), consumed)).code).toBe("RECOVERY_REQUEST_REQUIRED");
    const replay = await validateSecurityBundle(bundle, { ...consumed, storedResult: { operationType: "RECOVERY_KIT_REPLACEMENT", result: { ok: true } } });
    expect(replay).toEqual({ ok: true, value: { kind: "STORED", stored: { operationType: "RECOVERY_KIT_REPLACEMENT", result: { ok: true } } } });
  });

  it("Managed: a RECOVERY_RESET without any request is accepted at once and consumes nothing", async () => {
    const managed = await managedRecoveryResetScenario(world);
    expect(await accepted(managed.bundle, withRequests(managed.state, []))).toBeNull();
  });

  it("the gate comes after the mode check: a Managed RECOVERY_KIT_REPLACEMENT is still NOT_APPLICABLE_IN_MANAGED", async () => {
    const { bundle, state } = scenario("RECOVERY_KIT_REPLACEMENT");
    expect((await reject(bundle, { ...managedState(world, state), recoveryRequests: [] })).code).toBe("NOT_APPLICABLE_IN_MANAGED");
  });
});

// --- Phase 1: the records --------------------------------------------------------------------------

describe("step 0: the scope of a record follows from operation_type and recovery.kind", () => {
  const ALL: readonly Scope[] = ["TRUSTED_SECURITY", "ACCOUNT_SECURITY", "RECOVERY_CONTROL"];

  for (const operationType of RECORDS) {
    for (const kind of DELAYED) {
      it(`${operationType}/${kind}: only its scopes pass step 0`, async () => {
        const { signer, scopes } = signerFor(operationType, kind);
        const bundle = await recordBundle(operationType, kind, signer);
        for (const scope of ALL) {
          const outcome = await validateSecurityBundle(bundle, withScopes(world.state, [scope]));
          const step0 = !outcome.ok && outcome.failure.step === "0";
          expect(step0, `${scope}`).toBe(!scopes.includes(scope));
          if (step0 && !outcome.ok) expect(outcome.failure.code).toBe("SCOPE_REQUIRED");
        }
      });
    }
  }

  it("without a recovery record the scope cannot be deduced: INVALID_BUNDLE at step 0, not stored", async () => {
    const { bundle, state } = scenario("RECOVERY_VETO");
    const failure = await reject(patch(bundle, { recovery: undefined }), state);
    expect(failure).toMatchObject({ step: "0", code: "INVALID_BUNDLE", stored: false });
  });

  it("a step-0 refusal answers before the stored result, so a stranger's scope never reads it", async () => {
    const { bundle, state } = scenario("RECOVERY_CANCEL");
    const failure = await reject(bundle, { ...withScopes(state, ["TRUSTED_SECURITY"]), storedResult: { operationType: "RECOVERY_CANCEL", result: {} } });
    expect(failure.code).toBe("SCOPE_REQUIRED");
  });
});

describe("step 7: the recovery block (§35.1.1)", () => {
  it("each record yields the change step 8 makes", async () => {
    expect(await accepted(scenario("RECOVERY_REQUEST").bundle, scenario("RECOVERY_REQUEST").state)).toMatchObject({
      kind: "REQUEST",
      requestId: REQUEST_ID,
      requestKind: "RECOVERY_KIT_REPLACEMENT",
      rootGeneration: 1,
      signerRole: 1,
    });
    expect(await accepted(scenario("RECOVERY_VETO").bundle, scenario("RECOVERY_VETO").state)).toMatchObject({ kind: "VETO", requestId: REQUEST_ID });
    expect(await accepted(scenario("RECOVERY_CANCEL").bundle, scenario("RECOVERY_CANCEL").state)).toMatchObject({ kind: "CANCEL", requestId: REQUEST_ID });
  });

  it("a reset is requested with the kit (role 3) and RECOVERY_CONTROL", async () => {
    const bundle = await recordBundle("RECOVERY_REQUEST", "RECOVERY_RESET", world.ra1);
    expect(await accepted(bundle, withScopes(world.state, ["RECOVERY_CONTROL"]))).toMatchObject({ kind: "REQUEST", signerRole: 3 });
  });

  it("(a) a record that does not name the root in force → INVALID_BUNDLE, stored", async () => {
    const bundle = await recordBundle("RECOVERY_REQUEST", "SWITCH_TO_MANAGED", world.as1, { rootHash: filled(32, 0x01) }, { root_hash: filled(32, 0x01) });
    expect(await reject(bundle, world.state)).toMatchObject({ step: "7", code: "INVALID_BUNDLE", rule: "recovery/root", stored: true });
    const otherGeneration = await recordBundle("RECOVERY_REQUEST", "SWITCH_TO_MANAGED", world.as1, { rootGeneration: 2 }, { root_generation: 2 });
    expect((await reject(otherGeneration, world.state)).rule).toBe("recovery/root");
  });

  it("(b) a request while another is live → RECOVERY_REQUEST_EXISTS with its kind and dates, stored", async () => {
    const live = storedRequest("RECOVERY_RESET", { requestId: filled(16, 0x01), ageMs: 5 });
    const failure = await reject(scenario("RECOVERY_REQUEST").bundle, withRequests(world.state, [live]));
    expect(failure).toMatchObject({
      step: "7",
      code: "RECOVERY_REQUEST_EXISTS",
      stored: true,
      liveRequest: { kind: "RECOVERY_RESET", maturesAt: live.maturesAt, expiresAt: live.expiresAt },
    });
  });

  it("(b) right at expires_at the old one is dead, so a new request is accepted", async () => {
    const old = storedRequest("RECOVERY_RESET", { requestId: filled(16, 0x01), ageMs: DELAY_MS + TTL_MS });
    expect(old.expiresAt).toBe(NOW);
    expect(await accepted(scenario("RECOVERY_REQUEST").bundle, withRequests(world.state, [old]))).toMatchObject({ kind: "REQUEST" });
  });

  it("(b) a new request right after a veto is accepted, and starts a new delay", async () => {
    const vetoed = storedRequest("RECOVERY_KIT_REPLACEMENT", { requestId: filled(16, 0x01), state: "VETOED", ageMs: 1 });
    expect(await accepted(scenario("RECOVERY_REQUEST").bundle, withRequests(world.state, [vetoed]))).toMatchObject({ kind: "REQUEST" });
  });

  it("(b) a veto or cancel of an unknown, finished or other-kind request → INVALID_STATE, stored, never telling them apart", async () => {
    for (const op of ["RECOVERY_VETO", "RECOVERY_CANCEL"] as const) {
      const { bundle, state } = scenario(op);
      const cases: readonly (readonly StoredRecoveryRequest[])[] = [
        [],
        [storedRequest("RECOVERY_RESET", { requestId: filled(16, 0x01), ageMs: 1 })],
        [storedRequest("RECOVERY_RESET", { state: "VETOED", ageMs: 1 })],
        [storedRequest("RECOVERY_RESET", { state: "CANCELLED", ageMs: 1 })],
        [storedRequest("RECOVERY_RESET", { ageMs: DELAY_MS + TTL_MS })],
        [storedRequest("SWITCH_TO_MANAGED", { ageMs: 1 })],
      ];
      for (const requests of cases) {
        const failure = await reject(bundle, withRequests(state, requests));
        expect(failure).toMatchObject({ step: "7", code: "INVALID_STATE", rule: "recovery/not-live", stored: true });
      }
    }
  });

  it("(b) veto and cancel are accepted on a matured request too", async () => {
    for (const op of ["RECOVERY_VETO", "RECOVERY_CANCEL"] as const) {
      const { bundle, state } = scenario(op);
      expect(await accepted(bundle, withRequests(state, [storedRequest("RECOVERY_RESET")]))).toMatchObject({ requestId: REQUEST_ID });
    }
  });

  it("(c) a veto with the role that does not correspond → INVALID_SIGNATURE (reset vetoed by the kit, kit replacement by the root)", async () => {
    const resetByKit = await recordBundle("RECOVERY_VETO", "RECOVERY_RESET", world.ra1);
    const liveReset = withRequests(withScopes(world.state, ["ACCOUNT_SECURITY"]), [storedRequest("RECOVERY_RESET", { ageMs: 1 })]);
    expect(await reject(resetByKit, liveReset)).toMatchObject({ step: "7", code: "INVALID_SIGNATURE", rule: "recovery/signature" });
    const kitByRoot = await recordBundle("RECOVERY_VETO", "RECOVERY_KIT_REPLACEMENT", world.as1);
    const liveKit = withRequests(withScopes(world.state, ["RECOVERY_CONTROL"]), [storedRequest("RECOVERY_KIT_REPLACEMENT", { ageMs: 1 })]);
    expect(await reject(kitByRoot, liveKit)).toMatchObject({ code: "INVALID_SIGNATURE" });
  });

  it("(c) a request signature reused as a veto or a cancel, or over another request_id, kind, account or root → INVALID_SIGNATURE", async () => {
    const live = withRequests(withScopes(world.state, ["RECOVERY_CONTROL"]), [storedRequest("RECOVERY_RESET", { ageMs: 1 })]);
    const variants = [
      { signed: { operationType: "RECOVERY_REQUEST" } },
      { signed: { operationType: "RECOVERY_VETO" } },
      { signed: { requestId: filled(16, 0x02) } },
      { signed: { kind: "SWITCH_TO_MANAGED" as const } },
      { signed: { accountId: filled(16, 0x12) } },
      { signed: { rootHash: filled(32, 0x03) } },
    ];
    for (const { signed } of variants) {
      const bundle = await recordBundle("RECOVERY_CANCEL", "RECOVERY_RESET", world.ra1, signed);
      expect((await reject(bundle, live)).code, JSON.stringify(signed)).toBe("INVALID_SIGNATURE");
    }
    const stranger = await recordBundle("RECOVERY_CANCEL", "RECOVERY_RESET", world.stranger);
    expect((await reject(stranger, live)).code).toBe("INVALID_SIGNATURE");
  });

  it("(d) a request_id already used in this account, whatever its fate → NONCE_REUSED, stored", async () => {
    const used = storedRequest("SWITCH_TO_MANAGED", { state: "CANCELLED", ageMs: 1 });
    expect(await reject(scenario("RECOVERY_REQUEST").bundle, withRequests(world.state, [used]))).toMatchObject({
      step: "7",
      code: "NONCE_REUSED",
      stored: true,
      consumesNonce: false,
    });
  });

  it("the order is fixed: an existing live request answers before a bad signature, a bad signature before a reused id", async () => {
    const live = storedRequest("RECOVERY_RESET", { ageMs: 1 });
    const forged = await recordBundle("RECOVERY_REQUEST", "RECOVERY_KIT_REPLACEMENT", world.stranger);
    expect((await reject(forged, withRequests(world.state, [live]))).code).toBe("RECOVERY_REQUEST_EXISTS");
    expect((await reject(forged, withRequests(world.state, [{ ...live, state: "VETOED" }]))).code).toBe("INVALID_SIGNATURE");
  });

  it("Managed: the three records → NOT_APPLICABLE_IN_MANAGED, stored", async () => {
    for (const op of RECORDS) {
      const { bundle, state } = scenario(op);
      expect(await reject(bundle, managedState(world, state))).toMatchObject({ step: "0c", code: "NOT_APPLICABLE_IN_MANAGED", stored: true });
    }
  });

  it("DELETING_SCHEDULED: a reset request is accepted, a kit-replacement request is INVALID_STATE, a veto of any kind is accepted", async () => {
    const deleting = (s: BundleState): BundleState => ({ ...s, accountState: "DELETING_SCHEDULED" });
    const reset = await recordBundle("RECOVERY_REQUEST", "RECOVERY_RESET", world.ra1);
    expect(await accepted(reset, deleting(withScopes(world.state, ["RECOVERY_CONTROL"])))).toMatchObject({ kind: "REQUEST" });
    expect(await reject(scenario("RECOVERY_REQUEST").bundle, deleting(scenario("RECOVERY_REQUEST").state))).toMatchObject({
      code: "INVALID_STATE",
      rule: "recovery/delete-scheduled",
    });
    const kitVeto = await recordBundle("RECOVERY_VETO", "RECOVERY_KIT_REPLACEMENT", world.ra1);
    const liveKit = withRequests(withScopes(world.state, ["RECOVERY_CONTROL"]), [storedRequest("RECOVERY_KIT_REPLACEMENT", { ageMs: 1 })]);
    expect(await accepted(kitVeto, deleting(liveKit))).toMatchObject({ kind: "VETO" });
  });

  it("DELETING and ORPHANED accept no record", async () => {
    for (const accountState of ["DELETING", "ORPHANED"] as const) {
      const { bundle, state } = scenario("RECOVERY_VETO");
      expect((await reject(bundle, { ...state, accountState })).rule).toBe("account/deleting");
    }
  });
});

// --- ADR-022 section 13: the kit always cancels a scheduled deletion --------------------------------

describe("kit-signed CANCEL_DELETE_ACCOUNT and CANCEL_DELETE_VAULT (§35.11, §35.12)", () => {
  async function kitCancel(type: "CANCEL_DELETE_ACCOUNT" | "CANCEL_DELETE_VAULT", signer: Signer): Promise<Scenario> {
    const base = await deletionScenario(world, type);
    const deletion = await signDeletion(signer.privateKey, {
      operationType: type,
      accountId: world.accountId,
      ...(type === "CANCEL_DELETE_VAULT" ? { vaultId: VAULT_A } : {}),
      rootGeneration: 1,
      nonce: filled(16, 0x91),
    });
    return { bundle: patch(base.bundle, { deletion }), state: withScopes(base.state, ["RECOVERY_CONTROL"]) };
  }

  for (const type of ["CANCEL_DELETE_ACCOUNT", "CANCEL_DELETE_VAULT"] as const) {
    it(`${type} with RECOVERY_CONTROL and the Recovery Authority in force → accepted, no request and no delay`, async () => {
      const { bundle, state } = await kitCancel(type, world.ra1);
      const outcome = await validateSecurityBundle(bundle, withRequests(state, []));
      expect(outcome.ok && outcome.value.kind === "ACCEPT" && outcome.value.accepted.recoveryChange).toBe(null);
    });

    it(`${type}: a role-3 signature under a role-1 scope, a role-1 signature under RECOVERY_CONTROL, or an old Recovery Authority → INVALID_SIGNATURE`, async () => {
      const kit = await kitCancel(type, world.ra1);
      for (const scope of type === "CANCEL_DELETE_ACCOUNT" ? (["ACCOUNT_SECURITY", "TRUSTED_SECURITY"] as const) : (["TRUSTED_SECURITY"] as const)) {
        expect((await reject(kit.bundle, withScopes(kit.state, [scope]))).code, scope).toBe("INVALID_SIGNATURE");
      }
      const root = await kitCancel(type, world.as1);
      expect((await reject(root.bundle, root.state)).code).toBe("INVALID_SIGNATURE");
      // `ra2` is the Recovery Authority a kit replacement would install: not the one in force.
      const other = await kitCancel(type, world.ra2);
      expect((await reject(other.bundle, other.state)).code).toBe("INVALID_SIGNATURE");
    });
  }

  it("the kit can cancel, never schedule: DELETE_ACCOUNT and DELETE_VAULT under RECOVERY_CONTROL → SCOPE_REQUIRED", async () => {
    for (const type of ["DELETE_ACCOUNT", "DELETE_VAULT"] as const) {
      const { bundle, state } = scenario(type);
      expect((await reject(bundle, withScopes(state, ["RECOVERY_CONTROL"]))).code).toBe("SCOPE_REQUIRED");
    }
  });
});

// --- The client side -----------------------------------------------------------------------------------

describe("builders and the client's check of a pending request", () => {
  const view = (): RecoveryRecordView => ({
    accountId: world.accountId,
    root: world.root,
    rootHash: world.rootHash,
    registry: world.registry,
    configVersion: 1,
  });

  it("requestRecovery, vetoRecovery and cancelRecovery build bundles §35.1.1 accepts", async () => {
    const request = await requestRecovery({ view: view(), bundleId: BUNDLE_ID, requestId: REQUEST_ID, kind: "RECOVERY_RESET", signingKey: world.ra1.privateKey });
    expect(await accepted(request.bundle, withScopes(world.state, ["RECOVERY_CONTROL"]))).toMatchObject({ kind: "REQUEST" });
    const live = [storedRequest("RECOVERY_RESET", { ageMs: 1 })];
    const veto = await vetoRecovery({ view: view(), bundleId: BUNDLE_ID, requestId: REQUEST_ID, kind: "RECOVERY_RESET", signingKey: world.as1.privateKey });
    expect(await accepted(veto.bundle, withRequests(withScopes(world.state, ["ACCOUNT_SECURITY"]), live))).toMatchObject({ kind: "VETO" });
    const cancel = await cancelRecovery({ view: view(), bundleId: BUNDLE_ID, requestId: REQUEST_ID, kind: "RECOVERY_RESET", signingKey: world.ra1.privateKey });
    expect(await accepted(cancel.bundle, withRequests(withScopes(world.state, ["RECOVERY_CONTROL"]), live))).toMatchObject({ kind: "CANCEL" });
  });

  it("verifyRecoveryRequest accepts the requester's signature over the pinned root, and nothing else", async () => {
    const request = await requestRecovery({ view: view(), bundleId: BUNDLE_ID, requestId: REQUEST_ID, kind: "RECOVERY_KIT_REPLACEMENT", signingKey: world.as1.privateKey });
    const shown = {
      requestId: REQUEST_ID,
      kind: "RECOVERY_KIT_REPLACEMENT" as const,
      rootGeneration: 1,
      rootHash: world.rootHash,
      signature: request.record.signature,
    };
    expect(await verifyRecoveryRequest(world.accountId, world.root, world.rootHash, shown)).toBe(true);
    expect(await verifyRecoveryRequest(world.accountId, world.root, world.rootHash, { ...shown, kind: "SWITCH_TO_MANAGED" })).toBe(false);
    expect(await verifyRecoveryRequest(world.accountId, world.root, world.rootHash, { ...shown, requestId: filled(16, 0x01) })).toBe(false);
    expect(await verifyRecoveryRequest(filled(16, 0x12), world.root, world.rootHash, shown)).toBe(false);
    expect(await verifyRecoveryRequest(world.accountId, world.root, filled(32, 0x01), { ...shown, rootHash: filled(32, 0x01) })).toBe(false);
    // A veto signature is not a request.
    const veto = await vetoRecovery({ view: view(), bundleId: BUNDLE_ID, requestId: REQUEST_ID, kind: "RECOVERY_KIT_REPLACEMENT", signingKey: world.ra1.privateKey });
    expect(await verifyRecoveryRequest(world.accountId, world.root, world.rootHash, { ...shown, signature: veto.record.signature })).toBe(false);
  });
});

// --- Broken variants: each bracket of §44.4 ---------------------------------------------------------

describe("broken variants the §44.4 lines must catch", () => {
  /** [comprobación que no compara kind o generación]: "any matured live request will do". */
  function gateIgnoringKindAndGeneration(state: BundleState): boolean {
    return (state.recoveryRequests ?? []).some((r) => isMature(r, state.now));
  }

  it("a gate that does not compare kind or generation would apply what the real one refuses", async () => {
    for (const kind of DELAYED) {
      const { bundle, state } = scenario(kind);
      const other = DELAYED.find((k) => k !== kind)!;
      for (const request of [storedRequest(other), storedRequest(kind, { rootGeneration: 0 })]) {
        const s = withRequests(state, [request]);
        expect(gateIgnoringKindAndGeneration(s)).toBe(true);
        expect((await reject(bundle, s)).code).toBe("RECOVERY_REQUEST_REQUIRED");
      }
    }
  });

  /** [verificación con cualquier clave de la raíz]: accept a record signed by any key of the root. */
  async function verifiesUnderAnyRootKey(bundle: SecurityBundle): Promise<boolean> {
    const record = bundle.recovery!;
    const ctx = recoveryRequestContext(bundle.operation_type, world.accountId, record.request_id, record.kind, record.root_generation, record.root_hash);
    for (const spki of [world.root.account_signing_public_key, world.root.recovery_authority_public_key]) {
      if (await verifyContext(await importVerifyingKey(spki), ctx, record.signature)) return true;
    }
    return false;
  }

  it("verification with any root key would accept a reset vetoed by the kit itself", async () => {
    const resetByKit = await recordBundle("RECOVERY_VETO", "RECOVERY_RESET", world.ra1);
    expect(await verifiesUnderAnyRootKey(resetByKit)).toBe(true);
    const live = withRequests(withScopes(world.state, ["ACCOUNT_SECURITY"]), [storedRequest("RECOVERY_RESET", { ageMs: 1 })]);
    expect((await reject(resetByKit, live)).code).toBe("INVALID_SIGNATURE");
  });

  /** [verificación con la Account Signing sea cual sea el scope]: the pre-ADR deletion check. */
  it("verifying deletion.signature with the Account Signing whatever the scope would refuse the kit's cancel", async () => {
    const base = await deletionScenario(world, "CANCEL_DELETE_ACCOUNT");
    const deletion = await signDeletion(world.ra1.privateKey, {
      operationType: "CANCEL_DELETE_ACCOUNT",
      accountId: world.accountId,
      rootGeneration: 1,
      nonce: filled(16, 0x92),
    });
    const { deleteAccountContext } = await import("../src/contexts.js");
    const ctx = deleteAccountContext("CANCEL_DELETE_ACCOUNT", world.accountId, 1, deletion.nonce);
    expect(await verifyContext(await importVerifyingKey(world.root.account_signing_public_key), ctx, deletion.signature)).toBe(false);
    const outcome = await validateSecurityBundle(patch(base.bundle, { deletion }), withScopes(base.state, ["RECOVERY_CONTROL"]));
    expect(outcome.ok).toBe(true);
  });

  /** [rechazo del scope RECOVERY_CONTROL en el paso 0]: the pre-ADR scope rows. */
  it("the pre-ADR scope rows would refuse RECOVERY_CONTROL at step 0", () => {
    const before: Record<string, readonly Scope[]> = {
      CANCEL_DELETE_ACCOUNT: ["TRUSTED_SECURITY", "ACCOUNT_SECURITY"],
      CANCEL_DELETE_VAULT: ["TRUSTED_SECURITY"],
    };
    for (const type of ["CANCEL_DELETE_ACCOUNT", "CANCEL_DELETE_VAULT"] as const) {
      expect(before[type]!.includes("RECOVERY_CONTROL")).toBe(false);
      expect(OPERATION_RULES[type].scopes).toContain("RECOVERY_CONTROL");
    }
  });
});
