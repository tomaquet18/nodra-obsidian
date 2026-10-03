import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { enqueueUploads } from "../../src/outbox.js";
import { plan } from "../../src/plan.js";
import type { Action, PlanInput } from "../../src/types.js";
import { SIM, brokenRuns, runs } from "./budget.js";
import { DEFAULT_SERVER, build, scenarioArb } from "./scenario.js";
import { type ServerConfig, pendingOf } from "./server.js";
import { type Faults, type Variant, type World, hash, run } from "./simulator.js";

// Outbox, mutations and crashes under faults (§12.1-§12.6, §44.1, §44.5). Every property also runs
// against a deliberately broken variant that must be caught.

const FAULTS: Faults = {
  drop: 0.1,
  lose: 0.2,
  crash: 0.5,
  putTimeout: 0.1,
  remoteWrite: 0.08,
  rotateEpoch: 0.06,
  expireRows: 0.1,
  userEdit: 0.05,
  fileCrash: 0.08,
  tmpTouch: 0.05,
  userMove: 0,
  prune: 0,
  skipPoll: 0.6,
  activeUntil: 150,
};
const MAX_STEPS = 3000;
const RUNS = { numRuns: runs(6, 60) };
const BIG = "x".repeat(6000); // over maxBlobBytes: the server answers BLOB_TOO_LARGE (§11.1)

const REAL: Variant = { planner: plan };
/** A short upload window so local expiry (§12.1) happens under faults. */
const SERVER: ServerConfig = { ...DEFAULT_SERVER, uploadWindow: 25 };

const worldArb = fc.record({ scenario: scenarioArb, seed: fc.integer(), big: fc.boolean() });
type WorldSpec = typeof worldArb extends fc.Arbitrary<infer T> ? T : never;

interface Outcome {
  world: World;
  steps: number | null;
  /** Server time at which each (object, content) was blocked. */
  blockedAt: Map<string, number>;
  violations: string[];
}

/** Runs one faulty world, checking the per-step invariants (b), (c), (f). */
function simulate(spec: WorldSpec, variant: Variant = REAL, server: ServerConfig = SERVER, faults: Faults = FAULTS): Outcome {
  const scenario = spec.big
    ? { ...spec.scenario, localCreates: [...spec.scenario.localCreates, { path: "big.md", content: BIG }] }
    : spec.scenario;
  const { world } = build(scenario, faults, spec.seed, server);
  const blockedAt = new Map<string, number>();
  const violations: string[] = [];
  const steps = run(world, variant, MAX_STEPS, (w) => {
    // (b) at most one in-flight outbox entry per object.
    const inFlight = w.facts.outbox.flatMap((e) => e.objects.map((o) => o.objectId));
    if (new Set(inFlight).size !== inFlight.length) violations.push(`(b) duplicate in-flight object at step ${w.step}`);
    // (c) S is always a real server revision.
    for (const [id, s] of w.facts.synced) {
      const r = w.server.revisions.get(s.revisionId);
      if (!r || r.objectId !== id || r.path !== s.path || r.deleted !== s.deleted) violations.push(`(c) S of ${id} is not a server revision`);
    }
    // (f) every PENDING upload of this replica is known to the client (attempt or cleanup queue).
    const known = new Set([...w.facts.attempts.flatMap((a) => a.blobs.map((b) => b.blobId)), ...w.facts.cleanup.map((c) => c.blobId)]);
    for (const b of pendingOf(w.server, w.replica)) if (!known.has(b)) violations.push(`(f) leaked PENDING ${b}`);
    for (const b of w.facts.blocked) {
      const k = `${b.objectId}|${b.localCompareHash}`;
      if (!blockedAt.has(k)) blockedAt.set(k, w.server.now);
    }
    return violations.length > 0;
  });
  return { world, steps, blockedAt, violations };
}

const isBlocked = (w: World, id: string) => {
  const p = w.bound.get(id);
  return p !== undefined && w.facts.blocked.some((b) => b.objectId === id && b.localCompareHash === hash(w.files.get(p)!.content));
};

// ---------------------------------------------------------------------------
// (a) A mutation_id is confirmed at most once.
const atMostOnce = (v: Variant, server: ServerConfig) =>
  fc.property(worldArb, (spec) => {
    const { world } = simulate(spec, v, server);
    for (const [m, n] of world.server.log.applied) expect(n, m).toBeLessThanOrEqual(1);
  });

// (b) An object never has more than one in-flight outbox entry.
const oneInFlight = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    expect(simulate(spec, v).violations.filter((x) => x.startsWith("(b)"))).toEqual([]);
  });
/** Broken: forgets the outbox when planning and enqueues without the in-flight guard. */
const duplicatesInFlight: Variant = {
  planner: (i: PlanInput) => plan({ ...i, outbox: [] }),
  enqueue: (f, uploads, limits, ids) => {
    const fresh = enqueueUploads({ ...f, outbox: [] }, uploads, limits, ids);
    return { ...fresh, outbox: [...f.outbox, ...fresh.outbox] };
  },
};

// (c) No edit is marked synced without confirmation: S is always a real server revision.
const sIsReal = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    expect(simulate(spec, v).violations.filter((x) => x.startsWith("(c)"))).toEqual([]);
  });

// (d) After faults, remote writes and user edits stop: plan empty, L = R = S, outbox and cleanup empty.
const converges = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    const { world: w, steps } = simulate(spec, v);
    expect(steps).not.toBeNull();
    expect(w.facts.outbox).toEqual([]);
    expect(w.facts.attempts).toEqual([]);
    expect(w.facts.cleanup).toEqual([]);
    for (const [id, head] of w.server.heads) {
      if (isBlocked(w, id)) continue; // blocked with notice (rule 8): L ≠ S is kept on purpose
      expect(w.facts.synced.get(id)?.revisionId, id).toBe(head.revisionId);
      // No cached R means R = S (NOTES 7): an event at or below S's sequence is a no-op.
      expect((w.facts.remote.get(id) ?? w.facts.synced.get(id))?.revisionId, id).toBe(head.revisionId);
      const p = w.bound.get(id);
      if (head.deleted || w.notMaterialized.has(id)) {
        expect(p).toBeUndefined();
        continue;
      }
      expect(w.files.get(p!)?.content, id).toBe(head.content);
      expect(w.recorded.get(id)?.logicalPath, id).toBe(head.path);
    }
  });

// (e) No local edit is lost: confirmed, on disk (conflict copies included), merged, or blocked with notice.
const noEditLost = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    const { world: w } = simulate(spec, v);
    const confirmed = new Set([...w.server.revisions.values()].filter((r) => !r.deleted).map((r) => hash(r.content)));
    const onDisk = new Set([...w.files.values()].map((f) => hash(f.content)));
    const blocked = new Set(w.facts.blocked.map((b) => b.localCompareHash));
    for (const h of w.log.userContents.values()) {
      expect(confirmed.has(h) || onDisk.has(h) || w.log.mergedLocal.has(h) || blocked.has(h), h.slice(0, 40)).toBe(true);
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

// (f) PENDING uploads of this replica are always known to the client and none remain at the end.
const noLeakedPending = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    const { world, violations, steps } = simulate(spec, v);
    expect(violations.filter((x) => x.startsWith("(f)"))).toEqual([]);
    if (steps !== null) expect(pendingOf(world.server, world.replica)).toEqual([]);
  });

// (g) A retry of an already confirmed mutation (lost response, epoch rotation, expired row) always
// gets the original COMMITTED result, never EPOCH_STALE or CONFLICT.
/** Stress for (g): an epoch rotation races every lost commit response. */
const RETRY_STRESS: Faults = { ...FAULTS, rotateOnLostCommit: 1 };
const retriesGetCommitted = (v: Variant, server: ServerConfig) =>
  fc.property(worldArb, (spec) => {
    const { world } = simulate(spec, v, server, RETRY_STRESS);
    for (const r of world.server.log.retriesOfCommitted) expect(r.response, r.mutationId).toBe("COMMITTED");
  });

// (h) Blocked content is never uploaded again and never overwritten locally (writeFile throws).
const blockedNotUploaded = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    const { world, blockedAt } = simulate(spec, v);
    for (const p of world.server.log.contentPrepares) {
      const at = blockedAt.get(`${p.objectId}|${hash(p.payload)}`);
      expect(at === undefined || p.at < at, `${p.objectId} re-uploaded blocked content`).toBe(true);
    }
  });
/** Broken: ignores blocked content when planning. */
const ignoresBlocked: Variant = { planner: (i) => plan({ ...i, blocked: [] }) };

function holdsAndDetects(property: fc.IPropertyWithHooks<[WorldSpec]>, broken: fc.IPropertyWithHooks<[WorldSpec]>, brokenBudget = 60) {
  fc.assert(property, RUNS);
  expect(() => fc.assert(broken, brokenRuns(brokenBudget, brokenBudget))).toThrow();
}

describe("outbox, mutations and crashes under faults (§12, §44.5)", () => {
  const T = 600_000;
  it("(a) a mutation_id is confirmed at most once", () => {
    holdsAndDetects(atMostOnce(REAL, SERVER), atMostOnce(REAL, { ...SERVER, brokenNoIdempotency: true }));
  }, T);

  it("(b) an object never has more than one in-flight outbox entry", () => {
    holdsAndDetects(oneInFlight(REAL), oneInFlight(duplicatesInFlight));
  }, T);

  it("(c) S is always a real server revision (no edit marked synced without confirmation)", () => {
    holdsAndDetects(sIsReal(REAL), sIsReal({ planner: plan, assumeCommittedWhenUnknown: true }));
  }, T);

  it("(d) convergence after faults: plan empty, L = R = S, outbox and cleanup queue empty", () => {
    holdsAndDetects(converges(REAL), converges({ planner: plan, skipRelease: true }));
  }, T);

  it("(e) no local edit is lost", () => {
    holdsAndDetects(noEditLost(REAL), noEditLost(remoteWins));
  }, T);

  it("(f) PENDING uploads never leak (write-ahead attempts) and none remain after convergence", () => {
    holdsAndDetects(noLeakedPending(REAL), noLeakedPending({ planner: plan, prepareBeforePersist: true }));
  }, T);

  it("(g) a retry of a confirmed mutation gets its COMMITTED result, even after an epoch rotation", () => {
    holdsAndDetects(
      retriesGetCommitted(REAL, SERVER),
      retriesGetCommitted(REAL, { ...SERVER, brokenEpochCheckOnRetry: true }),
    );
  }, T);

  it("(h) blocked content is never uploaded again", () => {
    holdsAndDetects(blockedNotUploaded(REAL), blockedNotUploaded(ignoresBlocked));
  }, T);

  it("generator coverage: crashes, lost responses, rejections, retries, expiry, blocking", () => {
    const seen = {
      crashes: 0,
      lost: 0,
      retriesOfCommitted: 0,
      reconstructed: 0,
      expiredRetired: 0,
      epochStale: 0,
      conflict: 0,
      objectDeleted: 0,
      blobTooLarge: 0,
      uploadTimeoutMax: 0,
      releases: 0,
    };
    fc.assert(
      fc.property(worldArb, (spec) => {
        const { world: w } = simulate(spec);
        const r = (c: string) => (w.log.rejections.get(c) ?? 0) > 0;
        if (w.log.crashes > 0) seen.crashes++;
        if (w.log.lostResponses > 0) seen.lost++;
        if (w.server.log.retriesOfCommitted.length > 0) seen.retriesOfCommitted++;
        if (w.server.log.reconstructed > 0) seen.reconstructed++;
        if (w.log.expiredRetired > 0) seen.expiredRetired++;
        if (r("EPOCH_STALE")) seen.epochStale++;
        if (r("CONFLICT")) seen.conflict++;
        if (r("OBJECT_DELETED")) seen.objectDeleted++;
        if (r("BLOB_TOO_LARGE")) seen.blobTooLarge++;
        if (w.facts.blocked.some((b) => b.reason === "UPLOAD_TIMEOUT_MAX")) seen.uploadTimeoutMax++;
        if ([...w.server.blobs.values()].some((b) => b.state === "DELETING")) seen.releases++;
      }),
      { numRuns: runs(30, 150), seed: 20260921 },
    );
    for (const [k, v] of Object.entries(seen)) expect(v, k).toBeGreaterThan(SIM ? 3 : 0);
  }, T);
});
