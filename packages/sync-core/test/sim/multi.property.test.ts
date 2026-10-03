import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { plan } from "../../src/plan.js";
import type { Action } from "../../src/types.js";
import { SIM, brokenRuns, runs } from "./budget.js";
import { type Cluster, type ClusterSpec, buildCluster, clusterArb, restingViolations, runCluster } from "./multi.js";
import { DEFAULT_SERVER } from "./scenario.js";
import { type ServerConfig, pendingOf } from "./server.js";
import { type Faults, type Variant, type World, hash } from "./simulator.js";

// Several replicas on one server (§13, §18, §44.5). Every property also runs against a broken variant.

const FAULTS: Faults = {
  drop: 0.05,
  lose: 0.1,
  crash: 0.4,
  putTimeout: 0.02,
  remoteWrite: 0,
  rotateEpoch: 0.01,
  expireRows: 0.02,
  userEdit: 0.08,
  fileCrash: 0.05,
  tmpTouch: 0.02,
  userMove: 0.05,
  prune: 0.03,
  skipPoll: 0.2,
  activeUntil: 60,
};
const MAX_ROUNDS = 1500;
const SERVER: ServerConfig = { ...DEFAULT_SERVER, uploadWindow: 40 };
const REAL: Variant = { planner: plan };

interface Outcome {
  cluster: Cluster;
  rounds: number | null;
  violations: string[];
}

/** Runs a cluster, checking per-step invariants for every replica: (b), (c), (f), (i), (q). */
function simulate(spec: ClusterSpec, variant: Variant = REAL, server: ServerConfig = SERVER): Outcome {
  const cluster = buildCluster(spec, FAULTS, server);
  const violations: string[] = [];
  const rounds = runCluster(cluster, variant, MAX_ROUNDS, (c, w) => {
    const inFlight = w.facts.outbox.flatMap((e) => e.objects.map((o) => o.objectId));
    if (new Set(inFlight).size !== inFlight.length) violations.push(`(b) ${w.replica}`);
    for (const [id, s] of w.facts.synced) {
      const r = c.server.revisions.get(s.revisionId);
      if (!r || r.objectId !== id || r.deleted !== s.deleted) violations.push(`(c) ${w.replica} S of ${id}`);
    }
    const known = new Set([...w.facts.attempts.flatMap((a) => a.blobs.map((b) => b.blobId)), ...w.facts.cleanup.map((x) => x.blobId)]);
    for (const b of pendingOf(c.server, w.replica)) if (!known.has(b)) violations.push(`(f) ${w.replica} ${b}`);
    // (q) the cursor never stops inside a batch: a client never applies a partial batch.
    if (!c.server.batchEnds.has(w.facts.cursor)) violations.push(`(q) ${w.replica} cursor ${w.facts.cursor} inside a batch`);
    return violations.length > 0;
  });
  return { cluster, rounds, violations };
}

// (m) Global convergence: every replica reaches L = R = S for every object, with the same heads,
// and the same content for every object materialized on two replicas; each disk matches its projection.
const converges = (v: Variant) =>
  fc.property(clusterArb, (spec) => {
    const { cluster: c, rounds, violations } = simulate(spec, v);
    expect(violations).toEqual([]);
    expect(rounds).not.toBeNull();
    expect(restingViolations(c)).toEqual([]);
  });
/** Broken: never applies remote changes. */
const neverApplies: Variant = { planner: (i) => plan(i).filter((a) => a.kind !== "applyRemote") };

// (n) Confirmed content never disappears silently: a delete only removes a content the deleting
// replica had on disk or as S (rule 5c: a remote content change it never saw wins over the delete).
const deletesOnlySeenContent = (v: Variant) =>
  fc.property(clusterArb, (spec) => {
    const { cluster: c } = simulate(spec, v);
    for (const w of c.replicas) {
      for (const d of w.log.deleteUploads) {
        if (d.expected === null || d.deleted === undefined) continue;
        const deleted = c.server.revisions.get(d.expected);
        // What the server loses must be a content this replica had (on its disk or as S), never an unseen one.
        const ok = deleted === undefined || w.log.seen.get(d.objectId)?.has(deleted.content) === true;
        expect(ok, `${w.replica} deleted ${d.objectId} over unseen content`).toBe(true);
      }
    }
  });
/** Broken: rule 5c ignored — a local delete is sent over a remote content change. */
const deleteOverRemoteChange: Variant = {
  planner: (i) =>
    plan(i).map((a): Action => {
      const l = i.local.get(a.objectId);
      const s = i.synced.get(a.objectId);
      const r = i.remote.get(a.objectId);
      return a.kind === "applyRemote" && l?.kind === "ABSENT" && s && r && !r.deleted
        ? { kind: "upload", objectId: a.objectId, expectedHeadRevisionId: r.revisionId, deleted: true }
        : a;
    }),
};

// (o) No local edit is lost across replicas: each replica's latest user content is confirmed, on its
// disk (conflict copies included), merged, or blocked with notice.
const noEditLost = (v: Variant) =>
  fc.property(clusterArb, (spec) => {
    const { cluster: c } = simulate(spec, v);
    const confirmed = new Set([...c.server.revisions.values()].filter((r) => !r.deleted).map((r) => hash(r.content)));
    for (const w of c.replicas) {
      const onDisk = new Set([...w.files.values()].map((f) => hash(f.content)));
      const blocked = new Set(w.facts.blocked.map((b) => b.localCompareHash));
      for (const h of w.log.userContents.values()) {
        expect(confirmed.has(h) || onDisk.has(h) || w.log.mergedLocal.has(h) || blocked.has(h), `${w.replica} lost ${h.slice(0, 40)}`).toBe(true);
      }
    }
  });
/** Broken: the remote side wins instead of a conflict copy. */
const remoteWins: Variant = {
  planner: (i) =>
    plan(i).map((a): Action => {
      const l = i.local.get(a.objectId);
      return a.kind === "conflictCopy" && l?.kind === "PRESENT"
        ? { kind: "applyRemote", objectId: a.objectId, revisionId: a.remoteRevisionId, physicalPath: l.physicalPath }
        : a;
    }),
};

// (p) A deleted object never gets new revisions, and graveyard objects never resurrect.
const deletedIsTerminal = (v: Variant, server: ServerConfig) =>
  fc.property(clusterArb, (spec) => {
    const { cluster: c } = simulate(spec, v, server);
    const byObject = new Map<string, Array<{ sequence: number; deleted: boolean }>>();
    for (const r of c.server.revisions.values()) (byObject.get(r.objectId) ?? byObject.set(r.objectId, []).get(r.objectId)!).push(r);
    for (const [id, revs] of byObject) {
      const sorted = revs.sort((a, b) => a.sequence - b.sequence);
      const firstDelete = sorted.findIndex((r) => r.deleted);
      if (firstDelete >= 0) expect(sorted.length - 1, `${id} got revisions after its delete`).toBe(firstDelete);
    }
  });
/** Broken: local content of a remotely deleted object is uploaded over the delete (server lets it through). */
const resurrects: Variant = {
  planner: (i) =>
    plan(i).map((a): Action =>
      a.kind === "conflictCopy" && a.reason === "remoteDeleted" && i.local.get(a.objectId)?.kind === "PRESENT"
        ? { kind: "upload", objectId: a.objectId, expectedHeadRevisionId: a.remoteRevisionId, deleted: false }
        : a,
    ),
};

// (q) A client never applies a partial batch (checked after every step in `simulate`).
const noPartialBatch = (v: Variant, server: ServerConfig) =>
  fc.property(clusterArb, (spec) => {
    expect(simulate(spec, v, server).violations.filter((x) => x.startsWith("(q)"))).toEqual([]);
  });

function holdsAndDetects(property: fc.IPropertyWithHooks<[ClusterSpec]>, broken: fc.IPropertyWithHooks<[ClusterSpec]>, brokenBudget = 60) {
  fc.assert(property, { numRuns: runs(4, 40) });
  expect(() => fc.assert(broken, brokenRuns(brokenBudget, brokenBudget))).toThrow();
}

describe("multi-replica simulation (§13, §18, §44.5)", () => {
  const T = 1_200_000;
  it("(m) global convergence: L = R = S everywhere, same heads, same contents, disk = projection", () => {
    holdsAndDetects(converges(REAL), converges(neverApplies));
  }, T);

  it("(n) confirmed content never disappears silently (a delete removes only what the deleter had seen)", () => {
    holdsAndDetects(deletesOnlySeenContent(REAL), deletesOnlySeenContent(deleteOverRemoteChange), 150);
  }, T);

  it("(o) no local edit is lost across replicas", () => {
    holdsAndDetects(noEditLost(REAL), noEditLost(remoteWins), 150);
  }, T);

  it("(p) a deleted object never gets new revisions (no resurrection)", () => {
    holdsAndDetects(deletedIsTerminal(REAL, SERVER), deletedIsTerminal(resurrects, { ...SERVER, brokenAllowResurrection: true }), 150);
  }, T);

  it("(q) a client never applies a partial batch", () => {
    holdsAndDetects(noPartialBatch(REAL, SERVER), noPartialBatch({ planner: plan, acceptPartialPages: true }, { ...SERVER, brokenSplitPages: true }));
  }, T);

  it("generator coverage: conflicts, copies, merges, deletes, moves, folders, reconciliation, pruning", () => {
    const seen = { copies: 0, merges: 0, reconciliations: 0, userMoves: 0, userDeletes: 0, conflicts: 0, objectDeleted: 0, crashes: 0, multiPage: 0 };
    fc.assert(
      fc.property(clusterArb, (spec) => {
        const { cluster: c } = simulate(spec);
        const any = (f: (w: World) => boolean) => c.replicas.some(f);
        if (any((w) => w.log.conflictCopies > 0)) seen.copies++;
        if (any((w) => w.log.merges > 0)) seen.merges++;
        if (any((w) => w.log.reconciliations > 0)) seen.reconciliations++;
        if (any((w) => w.log.userMoves > 0)) seen.userMoves++;
        if (any((w) => w.log.userDeletes > 0)) seen.userDeletes++;
        if (any((w) => (w.log.rejections.get("CONFLICT") ?? 0) > 0)) seen.conflicts++;
        if (any((w) => (w.log.rejections.get("OBJECT_DELETED") ?? 0) > 0)) seen.objectDeleted++;
        if (any((w) => w.log.crashes > 0)) seen.crashes++;
        if (c.server.events.length > 3) seen.multiPage++;
      }),
      { numRuns: runs(12, 80), seed: 20260921 },
    );
    for (const [k, v] of Object.entries(seen)) expect(v, k).toBeGreaterThan(SIM ? 3 : 0);
  }, T);
});
