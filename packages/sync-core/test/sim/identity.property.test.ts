import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { type Attribution, attributeFiles } from "../../src/observe.js";
import { plan } from "../../src/plan.js";
import { SIM, brokenRuns, runs } from "./budget.js";
import { buildCluster, clusterArb, runCluster } from "./multi.js";
import { DEFAULT_SERVER, build, scenarioArb } from "./scenario.js";
import { type Faults, type Variant, type World, hash, run } from "./simulator.js";

// File identity, rename pairing after a restart and import of untracked files (§12.2 rules 10-11,
// §15, §18.4, §44.1, §44.5). Every property also runs against a broken variant.

const FAULTS: Faults = {
  drop: 0.05,
  lose: 0.05,
  crash: 0.3,
  putTimeout: 0,
  remoteWrite: 0.03,
  rotateEpoch: 0,
  expireRows: 0,
  userEdit: 0.05,
  fileCrash: 0.02,
  tmpTouch: 0,
  userMove: 0.12,
  prune: 0,
  skipPoll: 0,
  userCreate: 0.12,
  reload: 0.08,
  activeUntil: 120,
};
const MAX_STEPS = 3000;
const REAL: Variant = { planner: plan };
const worldArb = fc.record({ scenario: scenarioArb, seed: fc.integer() });
type Spec = typeof worldArb extends fc.Arbitrary<infer T> ? T : never;

interface Outcome {
  world: World;
  steps: number | null;
  shared: string[];
}

/** Runs one world; after every step no two objects share a file or an identity (§44.5). */
function simulate(spec: Spec, v: Variant = REAL): Outcome {
  const { world } = build(spec.scenario, FAULTS, spec.seed, DEFAULT_SERVER);
  const shared: string[] = [];
  const steps = run(world, v, MAX_STEPS, (w) => {
    const paths = [...w.bound.values()];
    if (new Set(paths).size !== paths.length) shared.push(`two objects share a path at step ${w.step}`);
    const fids = [...w.identity.values()];
    if (new Set(fids).size !== fids.length) shared.push(`two objects share an identity at step ${w.step}`);
    return shared.length > 0;
  });
  return { world, steps, shared };
}

const violations = (w: World, tag: string) => w.log.identityViolations.filter((x) => x.startsWith(tag));

// (u) No object ever gets two identities or two paths, no two objects share one, and a file is only
// ever registered as the state of the object it really is (or of a rule-11 rename).
const identityIsSound = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    const { world, shared } = simulate(spec, v);
    expect(shared).toEqual([]);
    expect(violations(world, "(u)")).toEqual([]);
  });
/** Broken: ignores the in-memory identities (a delayed rename or delete is read by path). */
const pathOnly: Variant = { planner: plan, attribute: (recorded, disk) => attributeFiles(recorded, disk, new Map()) };

// (v) A rename is paired after a restart only on the exact hash of the last observation and a match
// unique in both directions.
const pairingIsExactAndUnique = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    expect(violations(simulate(spec, v).world, "(v)")).toEqual([]);
  });
/** Broken: pairs every absent object with the first untracked file of the same hash, ambiguous or not. */
const pairFirstMatch: Variant = {
  planner: plan,
  attribute: (recorded, disk, identities): Attribution => {
    const a = attributeFiles(recorded, disk, identities);
    const byObject = new Map(a.byObject);
    const paired = [...a.paired];
    const free = [...a.untracked];
    for (const o of a.absent) {
      const h = recorded.find((r) => r.objectId === o)?.localCompareHash;
      const i = free.findIndex((p) => disk.find((d) => d.path === p)?.localCompareHash === h);
      if (h === null || h === undefined || i < 0 || identities.has(o)) continue;
      byObject.set(o, free[i]!);
      paired.push({ objectId: o, path: free[i]! });
      free.splice(i, 1);
    }
    return { byObject, paired, untracked: free, absent: a.absent.filter((o) => !byObject.has(o)) };
  },
};

// (w) No spurious objects: an imported object always comes from a file the user made or touched.
const noSpuriousObjects = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    expect(violations(simulate(spec, v).world, "(w)")).toEqual([]);
  });
/** Broken: forgets every attribution after a restart (no scan by path, no pairing): re-imports its own files. */
const forgetsEverything: Variant = {
  planner: plan,
  attribute: (recorded, disk, identities) =>
    identities.size === 0
      ? { byObject: new Map(), paired: [], untracked: disk.map((d) => d.path).sort(), absent: recorded.map((r) => r.objectId).sort() }
      : attributeFiles(recorded, disk, identities),
};

// (x) An untracked user file is never lost and eventually syncs: at rest nothing is left untracked and
// every file on disk holds a confirmed content.
const untrackedSyncs = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    const { world: w, steps } = simulate(spec, v);
    expect(steps).not.toBeNull();
    expect([...w.files].filter(([, f]) => f.owner === null).map(([p]) => p)).toEqual([]);
    const live = new Set([...w.server.heads.values()].filter((h) => !h.deleted).map((h) => hash(h.content)));
    const blocked = new Set(w.facts.blocked.map((b) => b.localCompareHash));
    for (const [p, f] of w.files) expect(live.has(hash(f.content)) || blocked.has(hash(f.content)), `${p} not synced`).toBe(true);
  });

function holdsAndDetects(property: (v: Variant) => fc.IPropertyWithHooks<[Spec]>, broken: Variant) {
  fc.assert(property(REAL), { numRuns: runs(8, 120) });
  expect(() => fc.assert(property(broken), brokenRuns(80, 150))).toThrow();
}

describe("file identity and untracked files (§12.2 rules 10-11, §15, §44.5)", () => {
  const T = 1_200_000;
  it("(u) one file per object, one object per file, and only its own file", () => {
    holdsAndDetects(identityIsSound, pathOnly);
  }, T);

  it("(v) rename pairing only on the exact hash and a unique match", () => {
    holdsAndDetects(pairingIsExactAndUnique, pairFirstMatch);
  }, T);

  it("(w) no spurious objects", () => {
    holdsAndDetects(noSpuriousObjects, forgetsEverything);
  }, T);

  it("(x) untracked user files are never lost and eventually sync", () => {
    holdsAndDetects(untrackedSyncs, { planner: plan, noImport: true });
  }, T);

  it("(x) across replicas: a file one replica's user created reaches every replica", () => {
    fc.assert(
      fc.property(clusterArb, (spec) => {
        const c = buildCluster(spec, { ...FAULTS, activeUntil: 60 }, DEFAULT_SERVER);
        expect(runCluster(c, REAL, 1500)).not.toBeNull();
        const live = [...c.server.heads.values()].filter((h) => !h.deleted);
        for (const w of c.replicas) {
          expect([...w.files].filter(([, f]) => f.owner === null).map(([p]) => p), w.replica).toEqual([]);
          expect(w.log.identityViolations, w.replica).toEqual([]);
          for (const h of live) if (!w.facts.blocked.some((b) => b.objectId === h.objectId)) expect(w.bound.has(h.objectId) || w.notMaterialized.has(h.objectId), `${w.replica} ${h.objectId}`).toBe(true);
        }
      }),
      { numRuns: runs(3, 40) },
    );
  }, T);

  it("generator coverage: reloads, pairings, ambiguity, pastes, creations, imports, moves", () => {
    const seen = { reloads: 0, pairings: 0, ambiguous: 0, pastes: 0, userCreates: 0, imports: 0, userMoves: 0 };
    fc.assert(
      fc.property(worldArb, (spec) => {
        const { world: w } = simulate(spec);
        for (const k of Object.keys(seen) as Array<keyof typeof seen>) if (w.log[k] > 0) seen[k]++;
      }),
      { numRuns: runs(20, 200), seed: 20260921 },
    );
    for (const [k, v] of Object.entries(seen)) expect(v, k).toBeGreaterThan(SIM ? 3 : 0);
  }, T);
});
