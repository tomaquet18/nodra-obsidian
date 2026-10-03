import { describe, expect, it } from "vitest";
import { plan } from "../../src/plan.js";
import { type Cluster, type ClusterSpec, buildCluster, restingViolations, runCluster } from "./multi.js";
import { DEFAULT_SERVER, type Scenario } from "./scenario.js";
import { prune, revisionStatus } from "./server.js";
import { nextOutboxStep } from "../../src/outbox.js";
import { NO_FAULTS, type World, hash, newFile, tick } from "./simulator.js";

// Deterministic §44.1 multi-replica cases, driven replica by replica (no faults).

const NL = String.fromCharCode(10);
const FIVE = ["a", "b", "c", "d", "e"].join(NL);
const REAL = { planner: plan };
type Obj = Scenario["objects"][number];
const obj = (path: string, content = FIVE): Obj => ({ path, content, second: null, replica: "head", mod: "none", editContent: "", moveTarget: "moved.md" });

/** A cluster of `n` replicas, all synced at the head of every object. */
function cluster(
  objects: Obj[],
  n = 2,
  localCreates: Array<ClusterSpec["replicas"][number]["localCreate"]> = [],
  unseenBy: number[] = [],
): Cluster {
  const spec: ClusterSpec = {
    base: { objects, localCreates: [], untracked: [], swap: false, merge: false },
    replicas: Array.from({ length: n }, (_, i) => ({
      perObject: objects.map(() => ({ replica: unseenBy.includes(i) ? ("unseen" as const) : ("head" as const), mod: "none" as const, editContent: "" })),
      localCreate: localCreates[i] ?? null,
    })),
    seed: 1,
  };
  const c = buildCluster(spec, NO_FAULTS, DEFAULT_SERVER);
  for (const w of c.replicas) settleOne(w); // everyone has read the events of the initial history
  return c;
}

const ID0 = "0190a1b2-0000-7000-8000-000000000000";
const ID1 = "0190a1b2-0001-7000-8000-000000000001";
const settleOne = (w: World) => {
  for (let i = 0; i < 200 && tick(w, REAL); i++);
};
const settle = (c: Cluster) => expect(runCluster(c, REAL, 500)).not.toBeNull();
/** Ticks `w` without reading events until its next outbox step is the commit. */
const untilCommitReady = (w: World) => {
  w.faults = { ...NO_FAULTS, skipPoll: 1, activeUntil: 1e9 };
  for (let i = 0; i < 100 && nextOutboxStep(w.facts, w.server.now, w.memory.putDone)?.kind !== "commit"; i++) tick(w, REAL);
  expect(nextOutboxStep(w.facts, w.server.now, w.memory.putDone)?.kind).toBe("commit");
};
/** One tick whose response is lost (and no events are read), then faults off again. */
const withLostResponse = (w: World) => {
  w.faults = { ...NO_FAULTS, lose: 1, skipPoll: 1, activeUntil: 1e9 };
  tick(w, REAL);
  w.faults = NO_FAULTS;
};
const file = (w: World, id: string) => {
  const p = w.bound.get(id);
  return p === undefined ? undefined : { path: p, content: w.files.get(p)!.content };
};
const edit = (w: World, id: string, content: string) => {
  w.files.get(w.bound.get(id)!)!.content = content;
};
const move = (w: World, id: string, to: string) => {
  const from = w.bound.get(id)!;
  const f = w.files.get(from)!;
  w.files.delete(from);
  w.files.set(to, f);
  w.bound.set(id, to);
  w.userMoved.add(id);
};
const remove = (w: World, id: string) => {
  w.files.delete(w.bound.get(id)!);
  w.bound.delete(id);
  w.gone.add(id);
};
const liveHeads = (c: Cluster) => [...c.server.heads.values()].filter((h) => !h.deleted);
const allContents = (c: Cluster) => [...c.server.revisions.values()].map((r) => r.content).concat(c.replicas.flatMap((w) => [...w.files.values()].map((f) => f.content)));

describe("§44.1 multi-replica: concurrent edits", () => {
  it("modify/modify, different hunks → merged, no copy", () => {
    const c = cluster([obj("n.md")]);
    const [a, b] = c.replicas as [World, World];
    edit(a, ID0, ["A", "b", "c", "d", "e"].join(NL));
    edit(b, ID0, ["a", "b", "c", "d", "E"].join(NL));
    settleOne(a);
    settle(c);
    expect(liveHeads(c).map((h) => h.content)).toEqual([["A", "b", "c", "d", "E"].join(NL)]);
    for (const w of c.replicas) expect(file(w, ID0)?.content).toBe(["A", "b", "c", "d", "E"].join(NL));
  });

  it("two replicas edit the same hunk → conflict copy, never conflict markers", () => {
    const c = cluster([obj("n.md")]);
    const [a, b] = c.replicas as [World, World];
    edit(a, ID0, ["A1", "b", "c", "d", "e"].join(NL));
    edit(b, ID0, ["A2", "b", "c", "d", "e"].join(NL));
    settleOne(a);
    settle(c);
    const contents = liveHeads(c).map((h) => h.content).sort();
    expect(contents).toEqual([["A1", "b", "c", "d", "e"].join(NL), ["A2", "b", "c", "d", "e"].join(NL)]);
    expect(allContents(c).some((x) => /^(<<<<<<<|=======|>>>>>>>)/m.test(x))).toBe(false);
    expect(c.server.heads.get(ID0)?.content).toBe(["A1", "b", "c", "d", "e"].join(NL)); // the original keeps R
  });

  it("commit R1 and R2 before the next poll: CONFLICT with head R1, the second replica merges and uploads R3 over it", () => {
    const c = cluster([obj("n.md")]);
    const [a, b] = c.replicas as [World, World];
    edit(a, ID0, ["A", "b", "c", "d", "e"].join(NL));
    edit(b, ID0, ["a", "b", "c", "d", "E"].join(NL));
    untilCommitReady(b); // B's upload over R0 is ready, B has not seen R1
    settleOne(a); // R1 committed
    b.faults = NO_FAULTS;
    settleOne(b); // CONFLICT (head R1) → merge → R3 over R1
    settle(c);
    const revisions = [...c.server.revisions.values()].filter((r) => r.objectId === ID0).sort((x, y) => x.sequence - y.sequence);
    expect(revisions.at(-1)?.content).toBe(["A", "b", "c", "d", "E"].join(NL));
    expect(b.log.rejections.get("CONFLICT") ?? 0).toBeGreaterThan(0);
  });

  it("own-commit echo is a no-op: the author never re-applies its own revision", () => {
    const c = cluster([obj("n.md")]);
    const [a] = c.replicas as [World, World];
    edit(a, ID0, "mine");
    settle(c);
    expect(a.log.applies.filter((id) => id === ID0)).toEqual([]);
    expect(file(a, ID0)?.content).toBe("mine");
  });
});

describe("§44.1 multi-replica: renames", () => {
  it("rename/rename → the path confirmed first wins, the other rename is discarded, no duplicate", () => {
    const c = cluster([obj("n.md")]);
    const [a, b] = c.replicas as [World, World];
    move(a, ID0, "from-a.md");
    move(b, ID0, "from-b.md");
    settleOne(a);
    settle(c);
    expect(liveHeads(c).map((h) => h.path)).toEqual(["from-a.md"]);
    for (const w of c.replicas) expect(file(w, ID0)?.path).toBe("from-a.md");
  });

  it("folder rename on one replica and a file rename on the other converge per object", () => {
    const c = cluster([obj("d/1.md", "one"), obj("d/2.md", "two")]);
    const [a, b] = c.replicas as [World, World];
    move(a, ID0, "e/1.md");
    move(a, ID1, "e/2.md");
    move(b, ID0, "x.md");
    settleOne(a);
    settle(c);
    expect(Object.fromEntries(liveHeads(c).map((h) => [h.content, h.path]))).toEqual({ one: "e/1.md", two: "e/2.md" });
    for (const w of c.replicas) expect(file(w, ID0)?.path).toBe("e/1.md");
  });
});

describe("§44.1 / §18.2 multi-replica: delete vs modify", () => {
  it("delete confirmed first, then a modification → the edit comes back as a new object", () => {
    const c = cluster([obj("n.md")]);
    const [a, b] = c.replicas as [World, World];
    remove(a, ID0);
    edit(b, ID0, "edited on b");
    settleOne(a);
    settle(c);
    expect(c.server.heads.get(ID0)?.deleted).toBe(true);
    expect(liveHeads(c).map((h) => h.content)).toEqual(["edited on b"]);
    for (const w of c.replicas) expect([...w.files.values()].map((f) => f.content)).toEqual(["edited on b"]);
  });

  it("modification confirmed first, then a delete → the delete is not sent; the content is materialized again", () => {
    const c = cluster([obj("n.md")]);
    const [a, b] = c.replicas as [World, World];
    edit(b, ID0, "edited on b");
    remove(a, ID0);
    settleOne(b);
    settle(c);
    expect(c.server.heads.get(ID0)?.deleted).toBe(false);
    for (const w of c.replicas) expect(file(w, ID0)?.content).toBe("edited on b");
  });

  it("delete vs rename: rename confirmed first → the delete is sent over it (5d); delete first → the rename is discarded (5b)", () => {
    const c1 = cluster([obj("n.md")]);
    const [a1, b1] = c1.replicas as [World, World];
    move(b1, ID0, "renamed.md");
    remove(a1, ID0);
    settleOne(b1);
    settle(c1);
    expect(c1.server.heads.get(ID0)?.deleted).toBe(true);

    const c2 = cluster([obj("n.md")]);
    const [a2, b2] = c2.replicas as [World, World];
    remove(a2, ID0);
    move(b2, ID0, "renamed.md");
    settleOne(a2);
    settle(c2);
    expect(c2.server.heads.get(ID0)?.deleted).toBe(true);
    for (const w of c2.replicas) expect(w.files.size).toBe(0);
  });
});

describe("§44.1 multi-replica: creations", () => {
  it("same path, independent creations → two objects; the one confirmed first keeps the name on every replica", () => {
    const c = cluster([], 2, ["n.md", "n.md"]);
    const [a, b] = c.replicas as [World, World];
    settleOne(a);
    settle(c);
    const heads = liveHeads(c).sort((x, y) => x.createdSequence - y.createdSequence);
    expect(heads).toHaveLength(2);
    const winner = heads[0]!.objectId;
    for (const w of [a, b]) expect(file(w, winner)?.path).toBe("n.md");
  });

  it("a file created offline that syncs late never displaces the established winner", () => {
    const c = cluster([obj("n.md", "established")], 2, [null, "n.md"], [1]);
    const [a, b] = c.replicas as [World, World];
    settle(c);
    for (const w of [a, b]) expect(file(w, ID0)?.path).toBe("n.md");
    const late = liveHeads(c).find((h) => h.objectId !== ID0)!;
    expect(file(b, late.objectId)?.path).toMatch(/^n \(Nodra conflict .+\)\.md$/);
  });
});

describe("§44.1 / §18.4 stale replicas and full reconciliation", () => {
  it("a stale replica after pruning (CURSOR_EXPIRED) reconciles; deleted objects stay deleted, its edit becomes a new object", () => {
    const c = cluster([obj("n.md"), obj("m.md", "keep")], 3);
    const [a, b, stale] = c.replicas as [World, World, World];
    edit(stale, ID0, "edited while stale");
    remove(a, ID0);
    edit(b, ID1, "newer");
    settleOne(a);
    settleOne(b);
    edit(b, ID1, "newest");
    settleOne(b);
    prune(c.server); // "newer" is pruned: the floor passes the stale cursor
    settle(c);
    expect(stale.log.reconciliations).toBeGreaterThan(0);
    expect(c.server.heads.get(ID0)?.deleted).toBe(true);
    expect([...c.server.revisions.values()].filter((r) => r.objectId === ID0 && !r.deleted && r.sequence > c.server.heads.get(ID0)!.sequence)).toEqual([]);
    for (const w of c.replicas) expect([...w.files.values()].map((f) => f.content).sort()).toEqual(["edited while stale", "newest"]);
  });

  it("reconciliation with a pending outbox entry (commit applied, response lost) → settled by getRevisionStatus, no duplicate copy", () => {
    const c = cluster([obj("n.md")]);
    const [a, b] = c.replicas as [World, World];
    edit(a, ID0, "sent, response lost");
    untilCommitReady(a);
    withLostResponse(a); // the server applies the commit; A never hears back
    const entry = a.facts.outbox[0]!;
    expect(entry.commitSent).toBe(true);
    expect(c.server.heads.get(ID0)?.content).toBe("sent, response lost");
    settleOne(b); // B takes R1…
    edit(b, ID0, ["x", "y"].join(NL));
    settleOne(b); // …and supersedes it with R2
    prune(c.server); // R1 is pruned: A's cursor is now below the floor
    expect(revisionStatus(c.server, entry.objects.map((o) => o.revisionId))[0]?.exists).toBeDefined();
    settle(c);
    const copies = liveHeads(c).filter((h) => h.objectId.includes("~copy"));
    expect(copies.length).toBeLessThanOrEqual(1);
    expect(new Set(liveHeads(c).map((h) => h.content)).size).toBe(liveHeads(c).length); // no duplicated content
    expect(a.log.reconciliations).toBeGreaterThan(0);
  });
});

describe("§12.2 rule 8 at rest: a new object whose content is blocked (question 336)", () => {
  /** B creates a file offline and every PUT of it times out until UPLOAD_TIMEOUT_MAX blocks its content. */
  const blockedCreate = () => {
    const c = cluster([obj("n.md")]);
    const b = c.replicas[1]!;
    b.files.set("new.md", newFile(b, null, "made offline", "user"));
    b.faults = { ...NO_FAULTS, putTimeout: 1, activeUntil: 1e9 };
    const created = () => [...b.bound.keys()].find((id) => !c.server.heads.has(id));
    for (let i = 0; i < 200 && !b.facts.blocked.some((x) => x.objectId === created()); i++) tick(b, REAL);
    b.faults = NO_FAULTS;
    const id = created()!;
    expect(b.facts.blocked).toEqual([{ objectId: id, localCompareHash: hash("made offline"), reason: "UPLOAD_TIMEOUT_MAX" }]);
    return { c, b, id };
  };

  it("the blocked content stays on disk, unconfirmed, and (m) accepts that resting state", () => {
    const { c, b, id } = blockedCreate();
    settle(c);
    expect(c.server.heads.has(id)).toBe(false); // rule 8: no upload while L carries the blocked content
    expect(file(b, id)).toEqual({ path: "new.md", content: "made offline" });
    expect(restingViolations(c)).toEqual([]);
  });

  it("(m) still reports an unconfirmed new object whose content is not the blocked one", () => {
    const { c, b, id } = blockedCreate();
    edit(b, id, "edited after the block"); // the block no longer applies (rule 8)
    expect(restingViolations(c)).toContain(`${b.replica} ${id} never confirmed`);
    settle(c);
    expect(c.server.heads.get(id)?.content).toBe("edited after the block");
    expect(restingViolations(c)).toEqual([]);
  });

  it("(m) reports an unconfirmed new object that was never blocked", () => {
    const c = cluster([obj("n.md")]);
    const b = c.replicas[1]!;
    b.files.set("new.md", newFile(b, null, "made offline", "user"));
    tick(b, REAL); // imported as a new object, not uploaded yet
    const id = [...b.bound.keys()].find((x) => !c.server.heads.has(x))!;
    expect(restingViolations(c)).toContain(`${b.replica} ${id} never confirmed`);
  });
});
