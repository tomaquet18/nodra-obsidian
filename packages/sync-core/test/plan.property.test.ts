import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { plan } from "../src/plan.js";
import type { Action, ActionKind, LocalEntry, PlanInput, RevisionEntry } from "../src/types.js";
import { OBJECT_IDS, type ObjectTrees, buildInput, hashArb, pathArb, reorder, treeArb } from "./arbitraries.js";

type Planner = (input: PlanInput) => Action[];
const RUNS = { numRuns: 3000 };

/** Asserts the property holds for `plan` and that it catches a deliberately broken planner. */
function holdsAndDetects<T extends [unknown, ...unknown[]]>(property: (p: Planner) => fc.IPropertyWithHooks<T>, broken: Planner) {
  fc.assert(property(plan), RUNS);
  expect(() => fc.assert(property(broken), RUNS)).toThrow();
}

// ---------------------------------------------------------------------------
// (a) Determinism (§44.5): same inputs → same actions, whatever the iteration order.
const determinism = (p: Planner) =>
  fc.property(treeArb, fc.shuffledSubarray([...OBJECT_IDS], { minLength: OBJECT_IDS.length }), ({ input }, order) => {
    const first = p(input);
    expect(p(input)).toEqual(first);
    expect(p(reorder(input, order))).toEqual(first);
  });

/** Broken on purpose: emits actions in Map insertion order instead of a canonical order. */
const insertionOrderPlanner: Planner = (input) => {
  const order = [...new Set([...input.local.keys(), ...input.remote.keys(), ...input.synced.keys()])];
  return plan(input).sort((x, y) => order.indexOf(x.objectId) - order.indexOf(y.objectId));
};

// ---------------------------------------------------------------------------
// (b) §44.1: the five base cases with random L, R and S → the table action.
type Row = "none" | "upload" | "apply" | "advance" | "resolveOrCopy" | "rule3a";

const liveKnown = (revisionId: string, sequence: number) =>
  fc.record({
    revisionId: fc.constant(revisionId),
    sequence: fc.constant(sequence),
    path: pathArb,
    localCompareHash: hashArb as fc.Arbitrary<string | null>,
    deleted: fc.constant(false),
    createdSequence: fc.constant(1),
  });

const baseCaseArb = (id: string) =>
  fc
    .record({
      s: liveKnown(`${id}-s`, 1),
      lSameAsS: fc.boolean(),
      lPath: pathArb,
      lHash: hashArb,
      rSameRevision: fc.boolean(),
      rNew: liveKnown(`${id}-r`, 2),
    })
    .map(({ s, lSameAsS, lPath, lHash, rSameRevision, rNew }): ObjectTrees => ({
      s,
      r: rSameRevision ? s : rNew,
      l: lSameAsS
        ? { kind: "PRESENT", path: s.path, physicalPath: s.path, recordedPhysicalPath: s.path, localCompareHash: s.localCompareHash! }
        : { kind: "PRESENT", path: lPath, physicalPath: lPath, recordedPhysicalPath: lPath, localCompareHash: lHash },
    }));

const baseTreesArb = fc
  .uniqueArray(fc.constantFrom(...OBJECT_IDS), { minLength: 1 })
  .chain((ids) => fc.tuple(...ids.map((id) => baseCaseArb(id).map((t) => [id, t] as const))))
  .map((entries) => new Map(entries));

function tableRow(t: ObjectTrees): Row {
  const s = t.s!;
  const r = t.r!;
  const l = t.l as Extract<LocalEntry, { kind: "PRESENT" }>;
  const eq = (e: RevisionEntry) => l.path === e.path && l.localCompareHash === e.localCompareHash;
  const rEqualsS = r.path === s.path && r.localCompareHash === s.localCompareHash;
  if (r.revisionId === s.revisionId) return eq(s) ? "none" : "upload";
  if (rEqualsS) return "rule3a";
  if (eq(s)) return "apply";
  return eq(r) ? "advance" : "resolveOrCopy";
}

const expectedKinds: Record<Row, ActionKind[]> = {
  none: [],
  upload: ["upload"],
  apply: ["applyRemote"],
  advance: ["advanceSynced"],
  rule3a: ["advanceSynced"],
  resolveOrCopy: ["resolve", "conflictCopy"],
};

const PHYSICAL = new Set<ActionKind>(["movePhysical", "removePhysical"]);
const rowsSeen = new Set<Row>();
const baseTable = (p: Planner) =>
  fc.property(baseTreesArb, (trees) => {
    const actions = p(buildInput(trees));
    for (const [id, t] of trees) {
      const row = tableRow(t);
      rowsSeen.add(row);
      const mine = actions.filter((a) => a.objectId === id && !PHYSICAL.has(a.kind));
      if (row === "none") {
        expect(mine).toEqual([]);
        continue;
      }
      expect(mine).toHaveLength(1);
      const action = mine[0]!;
      expect(expectedKinds[row]).toContain(action.kind);
      if (action.kind === "upload") expect(action.expectedHeadRevisionId).toBe(t.s!.revisionId);
      if (action.kind === "applyRemote" || action.kind === "advanceSynced") expect(action.revisionId).toBe(t.r!.revisionId);
    }
  });

/** Broken on purpose: ignores the base tree S (compares against R only). */
const ignoresSyncedPlanner: Planner = (input) => plan({ ...input, synced: input.remote });

// ---------------------------------------------------------------------------
// (c) Rule 9: no object in the outbox ever receives an action.
let inFlightWithWouldBeAction = 0;
const outboxQuiet = (p: Planner) =>
  fc.property(treeArb, ({ input }) => {
    const inFlight = new Set(input.outbox.flatMap((e) => e.objects.map((o) => o.objectId)));
    if (plan({ ...input, outbox: [] }).some((a) => inFlight.has(a.objectId))) inFlightWithWouldBeAction++;
    for (const a of p(input)) expect(inFlight.has(a.objectId)).toBe(false);
  });
const ignoresOutboxPlanner: Planner = (input) => plan({ ...input, outbox: [] });

// ---------------------------------------------------------------------------
// (d) Rule 2 / rule 6: an object that is not materialized, or ABSENT without ever
// having been confirmed (no S), never produces a delete upload.
let notMaterializedSeen = 0;
const neverDeletesUnmaterialized = (p: Planner) =>
  fc.property(treeArb, ({ trees, input }) => {
    for (const a of p(input)) {
      if (a.kind !== "upload" || !a.deleted) continue;
      const t = trees.get(a.objectId)!;
      const l = t.l?.kind ?? "UNBOUND";
      expect(l === "UNBOUND" || l === "NOT_MATERIALIZED").toBe(false);
      expect(l === "ABSENT" && t.s === undefined).toBe(false);
    }
    for (const t of trees.values()) {
      const l = t.l?.kind ?? "UNBOUND";
      if (t.s && !t.s.deleted && (l === "UNBOUND" || l === "NOT_MATERIALIZED")) notMaterializedSeen++;
    }
  });
/** Broken on purpose: reads "not on disk" as a local delete. */
const unboundAsAbsentPlanner: Planner = (input) =>
  plan({
    ...input,
    local: new Map(
      [...new Set([...input.local.keys(), ...input.synced.keys(), ...input.remote.keys()])].map((id) => {
        const l = input.local.get(id);
        return [id, l && l.kind !== "UNBOUND" && l.kind !== "NOT_MATERIALIZED" ? l : ({ kind: "ABSENT" } as const)];
      }),
    ),
  });

// ---------------------------------------------------------------------------
// (e) Rule 8: no upload is planned for blocked content.
let blockedWouldUpload = 0;
const noUploadOfBlocked = (p: Planner) =>
  fc.property(treeArb, ({ input }) => {
    const isBlocked = (id: string) => {
      const l = input.local.get(id);
      return l?.kind === "PRESENT" && input.blocked.some((b) => b.objectId === id && b.localCompareHash === l.localCompareHash);
    };
    if (plan({ ...input, blocked: [] }).some((a) => a.kind === "upload" && !a.deleted && isBlocked(a.objectId))) blockedWouldUpload++;
    for (const a of p(input)) if (a.kind === "upload" && !a.deleted) expect(isBlocked(a.objectId)).toBe(false);
  });
const ignoresBlockedPlanner: Planner = (input) => plan({ ...input, blocked: [] });

// ---------------------------------------------------------------------------
// (f) Liveness (§20.1, §10.6): a fetch of a pruned revision can never succeed, so the
// planner must never plan one; otherwise the object stalls forever.
let prunedUnknownSeen = 0;
const neverFetchesPruned = (p: Planner) =>
  fc.property(treeArb, ({ input }) => {
    for (const s of input.synced.values()) if (s.localCompareHash === null && input.prunedRevisions.has(s.revisionId)) prunedUnknownSeen++;
    for (const a of p(input)) if (a.kind === "fetchContent") expect(input.prunedRevisions.has(a.revisionId)).toBe(false);
  });
/** Broken on purpose: the old behavior, which does not know which revisions are pruned when fetching. */
const fetchesPrunedPlanner: Planner = (input) => plan({ ...input, prunedRevisions: new Set() });

// ---------------------------------------------------------------------------
describe("planner properties", () => {
  it("(f) liveness: no fetchContent ever targets a pruned revision", () => {
    holdsAndDetects(neverFetchesPruned, fetchesPrunedPlanner);
    expect(prunedUnknownSeen).toBeGreaterThan(100);
  });

  it("(a) is deterministic and independent of iteration order", () => {
    holdsAndDetects(determinism, insertionOrderPlanner);
  });

  it("(b) §44.1 base table: random L, R, S → the table action", () => {
    holdsAndDetects(baseTable, ignoresSyncedPlanner);
    // Evidence: the generator reaches every row of the table, plus rule 3a.
    expect([...rowsSeen].sort()).toEqual(["advance", "apply", "none", "resolveOrCopy", "rule3a", "upload"]);
  });

  it("(c) rule 9: no in-flight object receives an action", () => {
    holdsAndDetects(outboxQuiet, ignoresOutboxPlanner);
    expect(inFlightWithWouldBeAction).toBeGreaterThan(100);
  });

  it("(d) rule 2 / rule 6: not-materialized or never-confirmed objects never produce a delete upload", () => {
    holdsAndDetects(neverDeletesUnmaterialized, unboundAsAbsentPlanner);
    expect(notMaterializedSeen).toBeGreaterThan(100);
  });

  it("(e) rule 8: no upload of blocked content", () => {
    holdsAndDetects(noUploadOfBlocked, ignoresBlockedPlanner);
    expect(blockedWouldUpload).toBeGreaterThan(50);
  });

  it("every object gets at most one logical action and the generator covers every action kind", () => {
    const kinds = new Set<ActionKind>();
    fc.assert(
      fc.property(treeArb, ({ input }) => {
        const actions = plan(input);
        for (const a of actions) kinds.add(a.kind);
        const logical = actions.filter((a) => !PHYSICAL.has(a.kind));
        expect(new Set(logical.map((a) => a.objectId)).size).toBe(logical.length);
      }),
      RUNS,
    );
    expect([...kinds].sort()).toEqual(
      ["advanceSynced", "applyRemote", "conflictCopy", "discardLocalRename", "fetchContent", "forgetUnconfirmedCreate", "movePhysical", "resolve", "upload"].sort(),
    );
  });
});
