import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { type CanonicalPath, canonicalizePath, comparisonKey, utf8Length } from "../src/paths.js";
import { type MovedFile, physicalToLogical } from "../src/physical-to-logical.js";
import { type Projection, type ProjectionInput, type ProjectionObject, project } from "../src/project.js";
import { type PhysicalAction, type RenamePlan, type RenamePlanInput, planRenames } from "../src/rename-plan.js";
import { oid, simulate } from "./helpers.js";

const RUNS = { numRuns: 1500 };

/** The property holds for the real implementation and catches a deliberately broken one. */
function holdsAndDetects<T extends [unknown, ...unknown[]]>(
  property: (impl: never) => fc.IPropertyWithHooks<T>,
  real: unknown,
  broken: unknown,
) {
  fc.assert(property(real as never), RUNS);
  expect(() => fc.assert(property(broken as never), RUNS)).toThrow();
}

// ---------------------------------------------------------------------------
// Generators. Awkward on purpose: case-only and NFC/NFD twins, non-portable names,
// file/folder collisions (foo vs foo/...), long multibyte names, shared labels and
// same-sequence ("same minute") creations.
const LONG_MULTIBYTE = "ñ".repeat(130); // 260 bytes
const LONG_CJK = "日本".repeat(45); // 270 bytes
const segmentArb = fc.constantFrom(
  "foo",
  "Foo",
  "FOO",
  "café",
  "café",
  "a:b",
  "a?b",
  "CON",
  "notes.",
  "what?",
  LONG_MULTIBYTE,
  LONG_CJK,
);
const fileNameArb = fc.tuple(segmentArb, fc.constantFrom("", ".md", ".MD")).map(([s, e]) => s + e);
const randomPathArb = fc
  .tuple(fc.array(segmentArb, { maxLength: 2 }), fileNameArb)
  .map(([dirs, name]) => [...dirs, name].join("/"));
/** A tiny pool so exact, case-only, NFC/NFD and file-vs-folder collisions are frequent. */
const twinPathArb = fc.constantFrom("foo", "Foo.md", "foo.md", "FOO.md", "café.md", "café.md", "foo/x.md", "Foo/X.md");
const logicalPathArb = fc.oneof(randomPathArb, twinPathArb);

const objectsArb: fc.Arbitrary<ProjectionObject[]> = fc
  .uniqueArray(fc.integer({ min: 1, max: 40 }), { minLength: 1, maxLength: 7 })
  .chain((ns) =>
    fc.tuple(
      ...ns.map((n) =>
        fc.record({
          objectId: fc.constantFrom("aaaaaaaa", "bbbbbbbb", "0000abcd").map((label) => oid(n, label)),
          logicalPath: logicalPathArb,
          createdSequence: fc.option(fc.integer({ min: 1, max: 3 }), { nil: null, freq: 5 }),
        }),
      ),
    ),
  );

const projectionInputArb: fc.Arbitrary<ProjectionInput> = fc.record({
  objects: objectsArb,
  untrackedFiles: fc.array(logicalPathArb, { maxLength: 2 }),
});

// ---------------------------------------------------------------------------
// (a) Projection is identical for every permutation of arrival order (§16.3, §44.5).
type Projector = (input: ProjectionInput) => Projection;
const snapshot = (p: Projection) => ({
  files: [...p.files].sort(([a], [b]) => (a < b ? -1 : 1)),
  folders: [...p.folders].sort(([a], [b]) => (a < b ? -1 : 1)),
});
const orderIndependent = (impl: Projector) =>
  fc.property(
    projectionInputArb.chain((input) =>
      fc.tuple(fc.constant(input), fc.shuffledSubarray([...input.objects], { minLength: input.objects.length })),
    ),
    ([input, shuffled]) => {
      expect(snapshot(impl({ ...input, objects: shuffled }))).toEqual(snapshot(impl(input)));
    },
  );
/** Broken on purpose: first come, first served (priority by arrival instead of created_sequence). */
const arrivalOrderProjector: Projector = (input) =>
  project({ ...input, objects: input.objects.map((o, i) => ({ ...o, createdSequence: i })) });

// ---------------------------------------------------------------------------
// (b) No two objects share a physical path under the §16.2 key (case fold, NFC, sanitized),
// no file sits on a folder or inside another file, and every segment is ≤ 255 bytes.
let caseOrNfcTwins = 0;
const noSharedPaths = (impl: Projector) =>
  fc.property(projectionInputArb, (input) => {
    const keys = input.objects.map((o) => comparisonKey(o.logicalPath));
    if (new Set(keys).size < new Set(input.objects.map((o) => o.logicalPath)).size) caseOrNfcTwins++;
    const p = impl(input);
    const fileKeys = [...p.files.values()].map((f) => comparisonKey(f.physicalPath));
    expect(new Set(fileKeys).size).toBe(fileKeys.length);
    const folderKeys = new Set([...p.folders.keys()].map(comparisonKey));
    const untracked = new Set(input.untrackedFiles.map(comparisonKey));
    for (const k of fileKeys) {
      expect(folderKeys.has(k)).toBe(false);
      expect(untracked.has(k)).toBe(false);
      for (const other of fileKeys) expect(other.startsWith(`${k}/`)).toBe(false);
    }
    for (const f of p.files.values()) {
      for (const seg of f.physicalPath.split("/")) expect(utf8Length(seg)).toBeLessThanOrEqual(255);
    }
  });
/** Broken on purpose: compares exact strings instead of the §16.2 key. */
const exactKeyProjector: Projector = (input) => project(input, (s) => s);

// ---------------------------------------------------------------------------
// (c) The rename plan never writes onto an occupied path at any step, and every object
// that is not blocked or in flight ends at its projected path.
const POOL = ["1.md", "2.md", "3.md", "N.md", "n.md", "d/1.md", "d/2.md", "D/3.md", "x", "x/y.md"];
const consistent = (paths: readonly string[]) => {
  const keys = paths.map(comparisonKey);
  return new Set(keys).size === keys.length && keys.every((k) => keys.every((o) => !o.startsWith(`${k}/`)));
};
const IDS = ["a", "b", "c", "d", "e"];
const renameInputArb: fc.Arbitrary<RenamePlanInput> = fc
  .record({
    current: fc.shuffledSubarray(POOL, { maxLength: IDS.length }),
    desired: fc.oneof(fc.shuffledSubarray(POOL, { maxLength: IDS.length }), fc.constant(null)),
    nulls: fc.subarray(IDS, { maxLength: 1 }),
    untracked: fc.subarray(POOL, { maxLength: 2 }),
    inFlight: fc.subarray(IDS, { maxLength: 1 }),
    pending: fc.subarray(IDS, { maxLength: 2 }),
  })
  .chain((g) =>
    // null: desired is a permutation of the current slots, which produces swaps and cycles.
    g.desired === null
      ? fc.shuffledSubarray(g.current, { minLength: g.current.length }).map((d) => ({ ...g, desired: d }))
      : fc.constant({ ...g, desired: g.desired }),
  )
  .filter((g) => consistent(g.current) && consistent(g.desired) && consistent([...g.current, ...g.untracked]))
  .map((g) => ({
    current: new Map(g.current.map((p, i) => [IDS[i]!, p])),
    desired: new Map<string, string | null>(
      g.desired.map((p, i) => [IDS[i]!, g.nulls.includes(IDS[i]!) ? null : p]),
    ),
    untrackedFiles: g.untracked.filter((u) => !g.current.includes(u)),
    inFlight: new Set(g.inFlight),
    pending: new Set(g.pending),
    tmpHex: ["00000001", "00000002", "00000003", "00000004"],
  }));

type Planner = (input: RenamePlanInput) => RenamePlan;
let plansWithParking = 0;
const neverOverwrites = (impl: Planner) =>
  fc.property(renameInputArb, (input) => {
    const plan = impl(input);
    if (plan.actions.some((a) => a.kind === "rename" && a.to.includes("nodra-tmp-"))) plansWithParking++;
    const final = simulate(input, plan.actions); // throws on any overwrite
    for (const [id, to] of input.desired) {
      if (typeof to !== "string" || input.inFlight.has(id) || plan.blocked.includes(id)) continue;
      expect(final.get(id)).toBe(to);
    }
  });
/** Broken on purpose: no parking; a parked object jumps straight from its source to its target. */
const noParkingPlanner: Planner = (input) => {
  const plan = planRenames(input);
  const origin = new Map<string, string>();
  const actions: PhysicalAction[] = [];
  for (const a of plan.actions) {
    if (a.kind === "rename" && a.to.includes("nodra-tmp-")) {
      origin.set(a.objectId, a.from);
      continue;
    }
    if (a.kind === "rename" && origin.has(a.objectId)) actions.push({ ...a, from: origin.get(a.objectId)! });
    else actions.push(a);
  }
  return { ...plan, actions };
};

// ---------------------------------------------------------------------------
// (d) Physical → logical round trip for moved files: moving object o into the projected
// folder of object q, keeping its physical name, yields q's logical folder + o's logical name.
type P2L = (file: MovedFile, folders: ReadonlyMap<string, string>) => CanonicalPath;
const dirOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
const nameOf = (p: string) => p.slice(p.lastIndexOf("/") + 1);
let sanitizedOrSuffixedMoves = 0;
const roundTrip = (impl: P2L) =>
  fc.property(projectionInputArb, (input) => {
    const p = project(input);
    const logical = new Map(input.objects.map((o) => [o.objectId, canonicalizePath(o.logicalPath)] as const));
    for (const [o, fo] of p.files) {
      for (const fq of p.files.values()) {
        const folder = dirOf(fq.physicalPath);
        const lo = logical.get(o)!;
        if (!lo.ok) continue;
        const newPhysicalPath = folder === "" ? nameOf(fo.physicalPath) : `${folder}/${nameOf(fo.physicalPath)}`;
        const logicalFolder = folder === "" ? "" : p.folders.get(folder)!;
        const expected = logicalFolder === "" ? nameOf(lo.path) : `${logicalFolder}/${nameOf(lo.path)}`;
        if (newPhysicalPath !== expected) sanitizedOrSuffixedMoves++;
        const r = impl({ objectId: o, currentLogicalPath: lo.path, currentPhysicalPath: fo.physicalPath, newPhysicalPath }, p.folders);
        expect(r).toEqual({ ok: true, path: expected });
      }
    }
  });
/** Broken on purpose: takes the physical path literally. */
const literalP2L: P2L = (file) => canonicalizePath(file.newPhysicalPath);

// ---------------------------------------------------------------------------
describe("path-projection properties", () => {
  it("(a) projection is identical for every permutation of arrival order", () => {
    holdsAndDetects(orderIndependent, project, arrivalOrderProjector);
  });

  it("(b) no two objects share a physical path (case fold, NFC, sanitization, hierarchy)", () => {
    holdsAndDetects(noSharedPaths, project, exactKeyProjector);
    expect(caseOrNfcTwins).toBeGreaterThan(100);
  });

  it("(c) the rename plan never writes onto an occupied path at any step", () => {
    holdsAndDetects(neverOverwrites, planRenames, noParkingPlanner);
    expect(plansWithParking).toBeGreaterThan(50);
  });

  it("(d) physical → logical round trip for moved files", () => {
    holdsAndDetects(roundTrip, physicalToLogical, literalP2L);
    expect(sanitizedOrSuffixedMoves).toBeGreaterThan(100);
  });

  it("generator coverage: hierarchy collisions, escalation to full id, too-long paths", () => {
    let folderBeatsFile = 0;
    let fullId = 0;
    fc.assert(
      fc.property(projectionInputArb, (input) => {
        const p = project(input);
        for (const [id, f] of p.files) {
          if (f.physicalPath.includes(`(Nodra conflict ${id})`)) fullId++;
          if (/^(foo|Foo|FOO)( \(Nodra conflict [^)]+\))?(\.md|\.MD)?$/.test(f.physicalPath) && p.folders.size > 0) {
            if ([...p.folders.keys()].some((k) => comparisonKey(k) === comparisonKey(f.physicalPath.split(" (")[0]!))) {
              folderBeatsFile++;
            }
          }
        }
      }),
      RUNS,
    );
    expect(folderBeatsFile).toBeGreaterThan(10);
    expect(fullId).toBeGreaterThan(10);
  });
});
