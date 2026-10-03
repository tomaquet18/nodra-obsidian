import { comparisonKey, project } from "@nodra/path-projection";
import fc from "fast-check";
import { emptyFacts } from "../../src/outbox.js";
import { type Server, type ServerConfig, type ServerRevision, appendEvent, newServer } from "./server.js";
import { type Faults, NO_FAULTS, type World, canonical, hash, newFile } from "./simulator.js";

export const DEFAULT_SERVER: ServerConfig = { pendingBudgetBytes: 20000, maxBlobBytes: 5000, uploadWindow: 40 };

// Awkward inputs on purpose: case-only and NFC/NFD twins, non-portable and reserved names,
// file/folder collisions (foo vs foo/x.md), a path too long to materialize, identical and
// empty contents, remote swaps, untracked files on projected paths.
const NL = String.fromCharCode(10);
export const NFC_NAME = `caf${String.fromCodePoint(0xe9)}.md`;
export const NFD_NAME = `cafe${String.fromCodePoint(0x301)}.md`;
export const LONG = `${Array.from({ length: 12 }, (_, i) => `${"d".repeat(90)}${i}`).join("/")}/n.md`;
const PATHS = ["n.md", "N.md", NFC_NAME, NFD_NAME, "a:b.md", "CON.md", "foo", "foo/x.md", "Foo/y.md", "d/1.md", "d/2.md", LONG];
const MOVE_TARGETS = ["moved.md", "sub/moved.md", NFD_NAME, "N.md", "foo", "a_b.md"];
const FIVE = ["a", "b", "c", "d", "e"];
// The last three differ from the third in far-apart lines, so a merge of two of them resolves.
const CONTENTS = [
  "",
  "a",
  ["x", "y", "z"].join(NL),
  FIVE.join(NL),
  ["A", ...FIVE.slice(1)].join(NL),
  [...FIVE.slice(0, 4), "E"].join(NL),
];

const pathArb = fc.constantFrom(...PATHS);
const contentArb = fc.constantFrom(...CONTENTS);

const objectArb = fc.record({
  path: pathArb,
  content: contentArb,
  second: fc.option(fc.record({ path: pathArb, content: contentArb, deleted: fc.constantFrom(false, false, false, true) }), {
    nil: null,
  }),
  replica: fc.constantFrom("unseen", "rev1", "rev1", "head", "head"),
  mod: fc.constantFrom("none", "none", "edit", "move", "delete"),
  editContent: contentArb,
  moveTarget: fc.constantFrom(...MOVE_TARGETS),
});

export const scenarioArb = fc.record({
  objects: fc.array(objectArb, { minLength: 1, maxLength: 5 }),
  localCreates: fc.array(fc.record({ path: pathArb, content: contentArb }), { maxLength: 2 }),
  untracked: fc.array(fc.record({ path: fc.constantFrom(...PATHS, ...MOVE_TARGETS, NFD_NAME, NFD_NAME), content: contentArb }), { maxLength: 2 }),
  swap: fc.boolean(),
  merge: fc.boolean(),
});
export type Scenario = typeof scenarioArb extends fc.Arbitrary<infer T> ? T : never;

const occupied = (w: World, path: string) => {
  const k = comparisonKey(path);
  for (const p of w.files.keys()) {
    const fk = comparisonKey(p);
    if (fk === k || fk.startsWith(`${k}/`) || k.startsWith(`${fk}/`)) return true;
  }
  return false;
};

export interface Built {
  world: World;
  /** local_compare_hashes of every local content at the start (tracked and untracked files). */
  initialLocal: Set<string>;
  /** Objects the user deleted locally at the start (the only legitimate delete uploads). */
  userDeleted: Set<string>;
  /** Objects moved by the user at the start (rule 12). */
  userMoved: Set<string>;
}

const copy = (s: Scenario): Scenario => ({ ...s, objects: s.objects.map((o) => ({ ...o })) });

/**
 * Builds one replica. The first replica creates the server history from the scenario; further
 * replicas (`shared`) join that server and only lay out their own local state.
 */
export function build(
  scenario: Scenario,
  faults: Faults = NO_FAULTS,
  seed = 1,
  server: ServerConfig = DEFAULT_SERVER,
  shared?: { readonly server: Server; readonly index: number },
): Built {
  const index = shared?.index ?? 0;
  const prefix = index === 0 ? "" : `r${index}-`;
  // A swap scenario forces a real rename cycle: two synced files whose remote paths swap.
  const s: Scenario = copy(
    scenario.swap && scenario.objects.length >= 2
      ? {
          ...scenario,
          objects: scenario.objects.map((o, i) =>
            i < 2 ? { ...o, path: i === 0 ? "d/1.md" : "d/2.md", replica: "rev1" as const, mod: "none" as const } : o,
          ),
        }
      : scenario,
  );
  // A merge scenario forces a clean three-way merge on the last object (outside the swap pair).
  const last = s.objects.length - 1;
  if (s.merge && !(s.swap && last < 2)) {
    const five = CONTENTS[3]!;
    s.objects[last] = {
      ...s.objects[last]!,
      content: five,
      second: { path: s.objects[last]!.path, content: CONTENTS[5]!, deleted: false },
      replica: "rev1",
      mod: "edit",
      editContent: CONTENTS[4]!,
    };
  }
  const w: World = {
    server: shared?.server ?? newServer(server),
    replica: `replica-${index + 1}`,
    prefix,
    userDeletedBase: new Map(),
    files: new Map(),
    bound: new Map(),
    recorded: new Map(),
    gone: new Set(),
    notMaterialized: new Set(),
    known: new Set(),
    facts: emptyFacts("vault", `replica-${index + 1}`, shared?.server.epoch ?? "e1"),
    journal: null,
    identity: new Map(),
    fids: 0,
    forcedCrashes: new Set(),
    userMoved: new Set(),
    recoveryNotes: new Map(),
    memory: { putDone: new Set(), scanned: true },
    faults,
    rng: seed,
    ids: 0,
    copies: 0,
    step: 0,
    log: {
      uploads: [],
      parked: 0,
      conflictCopies: 0,
      merges: 0,
      mergedLocal: new Set(),
      crashes: 0,
      lostResponses: 0,
      expiredRetired: 0,
      statusQueries: 0,
      rejections: new Map(),
      userContents: new Map(),
      wholeContents: new Set(),
      deletions: [],
      pathMisreads: [],
      journalReplays: 0,
      journalCancels: 0,
      partialWrites: 0,
      recoveries: 0,
      tmpTouches: 0,
      deleteUploads: [],
      reconciliations: 0,
      seen: new Map(),
      userMoves: 0,
      userDeletes: 0,
      applies: [],
      imports: 0,
      adoptions: 0,
      pairings: 0,
      ambiguous: 0,
      identityViolations: [],
      reloads: 0,
      userCreates: 0,
      pastes: 0,
      occupiedCancels: 0,
    },
  };
  const id = (i: number) => `0190a1b2-000${i}-7000-8000-00000000000${i}`;
  const put = (r: ServerRevision, parent: string | null) => {
    w.server.heads.set(r.objectId, r);
    w.server.revisions.set(r.revisionId, r);
    appendEvent(w.server, r, parent, `seed-${r.sequence}`, 0, 1);
  };
  const rev1 = new Map<string, ServerRevision>();
  if (shared) {
    // The first revision of each scenario object already exists on the shared server.
    for (const r of [...w.server.revisions.values()].sort((a, b) => a.sequence - b.sequence)) if (!rev1.has(r.objectId)) rev1.set(r.objectId, r);
  } else {
    s.objects.forEach((o, i) => {
      w.server.seq++;
      const r = { revisionId: `${id(i)}@${w.server.seq}`, objectId: id(i), sequence: w.server.seq, createdSequence: w.server.seq, path: canonical(o.path), content: o.content, deleted: false };
      rev1.set(r.objectId, r);
      put(r, null);
    });
    s.objects.forEach((o, i) => {
      let second = o.second;
      if (s.swap && s.objects.length >= 2 && i < 2) {
        second = { path: s.objects[1 - i]!.path, content: o.content, deleted: false };
      }
      if (second === null) return;
      w.server.seq++;
      const first = rev1.get(id(i))!;
      put({ ...first, revisionId: `${id(i)}@${w.server.seq}`, sequence: w.server.seq, path: canonical(second.path), content: second.content, deleted: second.deleted }, first.revisionId);
    });
  }

  // The replica's synced base, laid out on disk at its projection (a replica at rest).
  const base = new Map<string, ServerRevision>();
  s.objects.forEach((o, i) => {
    if (o.replica === "unseen") return;
    const first = rev1.get(id(i));
    if (!first) return;
    const r = o.replica === "rev1" ? first : w.server.heads.get(id(i))!;
    base.set(r.objectId, r);
    if (!r.deleted) (w.log.seen.get(r.objectId) ?? w.log.seen.set(r.objectId, new Set()).get(r.objectId)!).add(r.content);
    w.facts = { ...w.facts, synced: new Map(w.facts.synced).set(r.objectId, { revisionId: r.revisionId, sequence: r.sequence, path: r.path, localCompareHash: null, deleted: r.deleted, createdSequence: r.createdSequence }) };
    w.known.add(r.revisionId);
  });
  const layout = project({
    objects: [...base.values()].filter((r) => !r.deleted).map((r) => ({ objectId: r.objectId, logicalPath: r.path, createdSequence: r.createdSequence })),
    untrackedFiles: [],
  });
  for (const [oid, f] of layout.files) {
    if (f.notMaterialized !== null) {
      w.notMaterialized.add(oid);
      continue;
    }
    w.files.set(f.physicalPath, newFile(w, oid, base.get(oid)!.content, "client"));
    w.identity.set(oid, w.fids);
    w.bound.set(oid, f.physicalPath);
    w.recorded.set(oid, { logicalPath: base.get(oid)!.path, physicalPath: f.physicalPath, hash: hash(base.get(oid)!.content) });
  }

  for (const u of s.untracked) if (!occupied(w, u.path)) w.files.set(u.path, newFile(w, null, u.content, "user"));
  s.localCreates.forEach((c, n) => {
    if (occupied(w, c.path)) return;
    const lid = `0190a1b2-0${index}f${n}-7000-8000-000000000${index}f${n}`;
    w.files.set(c.path, newFile(w, lid, c.content, "user"));
    w.identity.set(lid, w.fids);
    w.bound.set(lid, c.path);
    w.recorded.set(lid, { logicalPath: canonical(c.path), physicalPath: c.path, hash: hash(c.content) });
  });

  // Local changes the user made before this run.
  const userDeleted = new Set<string>();
  const userMoved = new Set<string>();
  s.objects.forEach((o, i) => {
    const p = w.bound.get(id(i));
    if (p === undefined) return;
    // Edits are unique per object (except the forced merge), so a lost edit cannot hide behind an
    // identical content confirmed by another object.
    const forcedMerge = s.merge && i === last && !(s.swap && last < 2);
    if (o.mod === "edit") {
      w.files.get(p)!.content = forcedMerge ? o.editContent : `local-${i}${NL}${o.editContent}`;
      w.files.get(p)!.touched = true;
    }
    w.log.seen.get(id(i))?.add(w.files.get(p)!.content);
    if (o.mod === "delete") {
      w.userDeletedBase.set(id(i), { base: w.facts.synced.get(id(i))?.revisionId, content: w.files.get(p)!.content });
      w.files.delete(p);
      w.bound.delete(id(i));
      w.gone.add(id(i));
      userDeleted.add(id(i));
    }
    if (o.mod === "move" && !occupied(w, o.moveTarget)) {
      const f = w.files.get(p)!;
      w.files.delete(p);
      w.files.set(o.moveTarget, f);
      w.bound.set(id(i), o.moveTarget);
      userMoved.add(id(i));
    }
  });

  const initialLocal = new Set([...w.files.values()].map((f) => hash(f.content)));
  for (const [p, f] of w.files) w.log.userContents.set(f.owner ?? p, hash(f.content));
  for (const f of w.files.values()) w.log.wholeContents.add(f.content);
  for (const id of userMoved) w.userMoved.add(id);
  return { world: w, initialLocal, userDeleted, userMoved };
}
