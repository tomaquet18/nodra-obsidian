import { comparisonKey } from "@nodra/path-projection";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { plan } from "../../src/plan.js";
import type { Action, PlanInput } from "../../src/types.js";
import { SIM, brokenRuns, runs } from "./budget.js";
import { LONG, NFC_NAME, NFD_NAME, type Scenario, build, scenarioArb } from "./scenario.js";
import { type Planner, type Variant, hash, observe, restingProjection, run } from "./simulator.js";

const RUNS = { numRuns: runs(25, 250) };
const MAX_STEPS = 300;

/** The property holds for `plan` and catches a deliberately broken planner. */
function holdsAndDetects(property: (p: Planner | Variant) => fc.IPropertyWithHooks<[Scenario]>, broken: Planner | Variant) {
  fc.assert(property(plan), RUNS);
  expect(() => fc.assert(property(broken), brokenRuns(250, 250))).toThrow();
}

// ---------------------------------------------------------------------------
// (a) Convergence (§44.5): with no new changes, the loop reaches an empty plan within a bound
// and L = R = S for every object (NOT_MATERIALIZED: S = R and nothing on disk).
const converges = (p: Planner | Variant) =>
  fc.property(scenarioArb, (s) => {
    const { world: w } = build(s);
    expect(run(w, p, MAX_STEPS)).not.toBeNull();
    const projection = restingProjection(w);
    for (const [id, head] of w.server.heads) {
      expect(w.facts.synced.get(id)?.revisionId).toBe(head.revisionId);
      const file = w.bound.get(id);
      if (head.deleted || projection.files.get(id)?.notMaterialized) {
        expect(file).toBeUndefined();
        continue;
      }
      expect(file).toBeDefined();
      expect(w.files.get(file!)!.content).toBe(head.content);
      expect(w.recorded.get(id)!.logicalPath).toBe(head.path);
    }
    for (const id of w.bound.keys()) expect(w.server.heads.has(id)).toBe(true); // every local file confirmed
  });
/** Broken on purpose: never advances S without writing or uploading. */
const noAdvancePlanner: Planner = (i) => plan(i).filter((a) => a.kind !== "advanceSynced");

// (b) At rest, the disk matches the projection, except NOT_MATERIALIZED objects.
const diskIsProjection = (p: Planner | Variant) =>
  fc.property(scenarioArb, (s) => {
    const { world: w } = build(s);
    expect(run(w, p, MAX_STEPS)).not.toBeNull();
    const projection = restingProjection(w);
    for (const [id, f] of projection.files) {
      if (f.notMaterialized !== null) expect(w.bound.get(id)).toBeUndefined();
      else expect(w.bound.get(id)).toBe(f.physicalPath);
    }
  });
/** Broken on purpose: ignores the physical renames of the projection. */
const noMovesPlanner: Planner = (i) => plan(i).filter((a) => a.kind !== "movePhysical");

// (c) No step ever writes onto an occupied path (the simulator throws on any overwrite), and the
// planner never even plans one: with nobody else acting, the executor's last-moment re-check of the
// destination (§16.7 rule 4) never has to cancel.
const neverOverwrites = (p: Planner | Variant) =>
  fc.property(scenarioArb, (s) => {
    const { world: w } = build(s);
    run(w, p, MAX_STEPS);
    expect(w.log.occupiedCancels).toBe(0);
  });
/** Broken on purpose: does not see untracked files (and they are kept untracked, so they matter). */
const blindToUntrackedPlanner: Planner = (i) => plan({ ...i, untrackedFiles: [] });

// (d) A NOT_MATERIALIZED or never-applied object never produces a delete upload: the only
// delete uploads are for objects the user deleted.
const deletesOnlyUserDeletes = (p: Planner | Variant) =>
  fc.property(scenarioArb, (s) => {
    const { world: w, userDeleted } = build(s);
    run(w, p, MAX_STEPS);
    for (const u of w.log.uploads) {
      if (!u.deleted) continue;
      expect(u.localKind).toBe("ABSENT");
      expect(userDeleted.has(u.objectId)).toBe(true);
    }
  });
/** Broken on purpose: reads "not on disk" (UNBOUND / NOT_MATERIALIZED) as a local delete. */
const notOnDiskAsDeletePlanner: Planner = (i) => {
  const ids = new Set([...i.local.keys(), ...i.synced.keys()]);
  const local = new Map(i.local);
  for (const id of ids) {
    const l = i.local.get(id);
    if (l === undefined || l.kind === "NOT_MATERIALIZED") local.set(id, { kind: "ABSENT" });
  }
  return plan({ ...i, local });
};

// (e) No local edit disappears: every local content present at the start ends in a confirmed
// revision, in a file on disk (conflict copies included), or merged into a resolved result.
const noLocalEditLost = (p: Planner | Variant) =>
  fc.property(scenarioArb, (s) => {
    const { world: w, initialLocal } = build(s);
    run(w, p, MAX_STEPS);
    const confirmed = new Set([...w.server.revisions.values()].filter((r) => !r.deleted).map((r) => hash(r.content)));
    const onDisk = new Set([...w.files.values()].map((f) => hash(f.content)));
    for (const h of initialLocal) {
      expect(confirmed.has(h) || onDisk.has(h) || w.log.mergedLocal.has(h)).toBe(true);
    }
  });
/** Broken on purpose: remote wins instead of a conflict copy (the local content is overwritten). */
const remoteWinsPlanner: Planner = (i: PlanInput) =>
  plan(i).map((a): Action => {
    const l = i.local.get(a.objectId);
    return a.kind === "conflictCopy" && l?.kind === "PRESENT"
      ? { kind: "applyRemote", objectId: a.objectId, revisionId: a.remoteRevisionId, physicalPath: l.physicalPath }
      : a;
  });

// ---------------------------------------------------------------------------
describe("single-replica simulation (§44.5 seed)", () => {
  it("(a) convergence: empty plan within the bound and L = R = S", () => {
    holdsAndDetects(converges, noAdvancePlanner);
  }, 300_000);

  it("(b) at rest the disk matches the projection, except NOT_MATERIALIZED", () => {
    holdsAndDetects(diskIsProjection, noMovesPlanner);
  }, 300_000);

  it("(c) no step writes onto an occupied path", () => {
    holdsAndDetects(neverOverwrites, { planner: blindToUntrackedPlanner, noImport: true });
  }, 300_000);

  it("(d) no delete upload for NOT_MATERIALIZED or never-applied objects", () => {
    holdsAndDetects(deletesOnlyUserDeletes, notOnDiskAsDeletePlanner);
  }, 300_000);

  it("(e) no local edit disappears", () => {
    holdsAndDetects(noLocalEditLost, remoteWinsPlanner);
  }, 300_000);

  it("generator coverage: collisions, NFC/NFD, long paths, folder/file, swaps, copies, merges, moves", () => {
    const seen = { caseTwin: 0, nfcNfd: 0, long: 0, folderFile: 0, parked: 0, copies: 0, merges: 0, moved: 0, reserved: 0 };
    fc.assert(
      fc.property(scenarioArb, (s) => {
        const { world: w, userMoved } = build(s);
        const names = [...w.server.heads.values()].map((h) => h.path).concat([...w.files.keys()]);
        const keys = new Map<string, Set<string>>();
        for (const n of names) (keys.get(comparisonKey(n)) ?? keys.set(comparisonKey(n), new Set()).get(comparisonKey(n))!).add(n);
        if ([...keys.values()].some((v) => v.size > 1)) seen.caseTwin++;
        if (names.includes(NFD_NAME) && names.includes(NFC_NAME)) seen.nfcNfd++;
        if (names.includes(LONG)) seen.long++;
        if (names.includes("foo") && names.some((n) => comparisonKey(n).startsWith("foo/"))) seen.folderFile++;
        if (names.some((n) => n.startsWith("a:b") || n === "CON.md")) seen.reserved++;
        if (userMoved.size > 0) seen.moved++;
        run(w, plan, MAX_STEPS);
        if (w.log.parked > 0) seen.parked++;
        if (w.log.conflictCopies > 0) seen.copies++;
        if (w.log.merges > 0) seen.merges++;
      }),
      // Fixed seed: coverage counts are measured on a reproducible sample.
      { numRuns: runs(150, 500), seed: 20260921 },
    );
    for (const [k, v] of Object.entries(seen)) expect(v, k).toBeGreaterThan(SIM ? 5 : 1);
  }, 300_000);

  it("a run is deterministic: same scenario, same final world", () => {
    fc.assert(
      fc.property(scenarioArb, (s) => {
        const a = build(s).world;
        const b = build(s).world;
        run(a);
        run(b);
        expect([...a.files]).toEqual([...b.files]);
        expect(observe(a)).toEqual(observe(b));
      }),
      { numRuns: runs(10, 50) },
    );
  }, 300_000);
});
