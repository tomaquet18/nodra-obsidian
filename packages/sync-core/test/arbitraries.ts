import { comparisonKey } from "@nodra/path-projection";
import fc from "fast-check";
import type { BlockedContent, LocalEntry, PlanInput, RevisionEntry } from "../src/types.js";

// Small alphabets on purpose: they force identical content across objects, path
// collisions, empty content ("hEmpty" stands for the hash of the empty file) and
// same-state-different-revision (rule 3a).
export const OBJECT_IDS = ["a", "b", "c", "d", "e"] as const;
export const hashArb = fc.constantFrom("h1", "h2", "hEmpty");
export const pathArb = fc.constantFrom("n.md", "m.md", "dir/n.md");
const maybeHashArb = fc.option(hashArb, { nil: null, freq: 4 }); // unknown hashes too

export interface ObjectTrees {
  l: LocalEntry | undefined;
  s: RevisionEntry | undefined;
  r: RevisionEntry | undefined;
}

const liveOrDeleted = (revisionId: string, sequence: number): fc.Arbitrary<RevisionEntry> =>
  fc.record({
    revisionId: fc.constant(revisionId),
    sequence: fc.constant(sequence),
    path: pathArb,
    localCompareHash: maybeHashArb,
    deleted: fc.constantFrom(false, false, false, true),
    createdSequence: fc.integer({ min: 1, max: 3 }),
  });

export const localArb: fc.Arbitrary<LocalEntry> = fc.oneof(
  {
    weight: 5,
    arbitrary: fc
      .record({ path: pathArb, localCompareHash: hashArb })
      .map((p) => ({ kind: "PRESENT" as const, ...p, physicalPath: p.path, recordedPhysicalPath: p.path })),
  },
  { weight: 2, arbitrary: fc.constant({ kind: "ABSENT" } as const) },
  { weight: 1, arbitrary: fc.constant({ kind: "UNBOUND" } as const) },
  {
    weight: 1,
    arbitrary: fc.constantFrom(
      { kind: "NOT_MATERIALIZED", reason: "LOCAL_PATH_TOO_LONG" } as const,
      { kind: "NOT_MATERIALIZED", reason: "LOCAL_FS_REJECTED" } as const,
    ),
  },
);

/** Arbitrary per-object trees. R is either absent, S itself, or a newer revision. */
export const objectTreesArb = (id: string): fc.Arbitrary<ObjectTrees> =>
  fc
    .record({
      l: fc.option(localArb, { nil: undefined, freq: 6 }),
      s: fc.option(liveOrDeleted(`${id}-s`, 1), { nil: undefined, freq: 4 }),
      rKind: fc.constantFrom("none", "sameAsS", "newer"),
      rNew: liveOrDeleted(`${id}-r`, 2),
    })
    .map(({ l, s, rKind, rNew }) => ({
      l,
      s,
      r: rKind === "none" ? undefined : rKind === "sameAsS" ? s : rNew,
    }));

export const treeArb: fc.Arbitrary<{ trees: Map<string, ObjectTrees>; input: PlanInput }> = fc
  .record({
    objects: fc.uniqueArray(fc.constantFrom(...OBJECT_IDS), { minLength: 1, maxLength: OBJECT_IDS.length }),
    inFlight: fc.subarray([...OBJECT_IDS]),
    blocked: fc.array(
      fc.record({
        objectId: fc.constantFrom(...OBJECT_IDS),
        localCompareHash: hashArb,
        reason: fc.constantFrom("BLOB_TOO_LARGE", "UPLOAD_TIMEOUT_MAX", "INVALID_BATCH_REPEATED"),
      }),
      { maxLength: 3 },
    ),
    text: fc.subarray([...OBJECT_IDS]),
    prunedS: fc.subarray([...OBJECT_IDS]),
  })
  .chain((base) =>
    fc.tuple(fc.constant(base), fc.tuple(...base.objects.map((id) => objectTreesArb(id)))),
  )
  .map(([base, treeList]) => {
    const trees = new Map(base.objects.map((id, i) => [id, treeList[i]!]));
    return { trees, input: buildInput(trees, base.inFlight, base.blocked as BlockedContent[], base.text, base.prunedS) };
  });

export function buildInput(
  trees: ReadonlyMap<string, ObjectTrees>,
  inFlight: readonly string[] = [],
  blocked: readonly BlockedContent[] = [],
  text: readonly string[] = [...OBJECT_IDS],
  prunedS: readonly string[] = [],
): PlanInput {
  const local = new Map<string, LocalEntry>();
  const synced = new Map<string, RevisionEntry>();
  const remote = new Map<string, RevisionEntry>();
  const onDisk = new Set<string>();
  for (const [id, t] of trees) {
    if (t.l?.kind === "PRESENT") {
      // One file per physical path: a second object with the same path sits in its own folder.
      const physicalPath = onDisk.has(comparisonKey(t.l.path)) ? `${id}/${t.l.path}` : t.l.path;
      onDisk.add(comparisonKey(physicalPath));
      local.set(id, { ...t.l, physicalPath, recordedPhysicalPath: physicalPath });
    } else if (t.l) local.set(id, t.l);
    if (t.s) synced.set(id, t.s);
    if (t.r) remote.set(id, t.r);
  }
  const outbox: PlanInput["outbox"][number][] = inFlight
    .filter((id) => trees.has(id))
    .map((id) => ({ mutationId: `m-${id}`, objects: [{ objectId: id, revisionId: `${id}-out`, expectedHeadRevisionId: null }] }));
  return {
    local,
    synced,
    remote,
    outbox,
    blocked,
    textObjects: new Set(text),
    prunedRevisions: new Set(prunedS.map((id) => `${id}-s`)),
    untrackedFiles: [],
    tmpHex: ["0000000a", "0000000b"],
  };
}

/** Same content, different Map insertion order and outbox/blocked order. */
export function reorder(input: PlanInput, order: readonly string[]): PlanInput {
  const pick = <V>(m: ReadonlyMap<string, V>) =>
    new Map(order.filter((id) => m.has(id)).map((id) => [id, m.get(id)!] as const));
  return {
    ...input,
    local: pick(input.local),
    synced: pick(input.synced),
    remote: pick(input.remote),
    outbox: [...input.outbox].reverse(),
    blocked: [...input.blocked].reverse(),
    textObjects: new Set([...input.textObjects].reverse()),
    prunedRevisions: new Set([...input.prunedRevisions].reverse()),
  };
}
