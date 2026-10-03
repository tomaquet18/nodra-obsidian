import fc from "fast-check";
import { inject } from "vitest";
import { describe, expect, it } from "vitest";
import { isRecoveryName } from "@nodra/sync-core";
import { fromModel, isBinaryModel } from "../support/bytes.js";
import { ATTACHMENT_FAULTS, type Broken, type DiskMtime, type E2EFaults, QUOTA_FAULTS, type Run, e2eSpecArb, convergenceProblems, intentDelivery, lostEdits, runToRest, startRun, unknownContents } from "./e2e.js";
import { SPEC_WINDOWS } from "./windows.js";

// End-to-end fault runs of the real shell (runner + Dexie + in-memory disk + server model). Each
// property also runs against a deliberately broken adapter and must fail there.

declare module "vitest" {
  export interface ProvidedContext {
    /** True under vitest.sim.config.ts (`pnpm test:sim`). */
    nodraSim: boolean;
  }
}

const SIM = inject("nodraSim") === true;
const runs = (fast: number, full: number) => (SIM ? full : fast);
const BROKEN_SEED = 20260921;

/**
 * Every property runs with attachments in the mix (binary user and remote writes, §2.1), and with followers
 * that edit like the web editor, on the view they loaded before their own previous intent (Q414).
 */
const FAULTS: E2EFaults = { ...ATTACHMENT_FAULTS, editorView: 0.5 };
const MAX_TICKS = 2500;
const specArb = e2eSpecArb;
type Spec = typeof specArb extends fc.Arbitrary<infer T> ? T : never;

/**
 * Every run's disk has a modification marker, so the observation cache (question 146) is in every long
 * run: an exact counter, or a coarse clock where same-size edits keep size and mtime equal.
 */
const diskMtime = (spec: Spec): DiskMtime => (spec.seed % 2 === 0 ? "coarse" : "counter");

async function simulate(spec: Spec, broken: Broken = {}, mtime: DiskMtime = diskMtime(spec), faults: E2EFaults = FAULTS): Promise<{ run: Run; ticks: number | null; delivery: string[] }> {
  const run = await startRun(spec.scenario, faults, spec.seed, broken, SPEC_WINDOWS, mtime);
  try {
    const ticks = await runToRest(run, MAX_TICKS);
    return { run, ticks, delivery: await intentDelivery(run) }; // reads the store: before it is closed
  } finally {
    run.close();
  }
}

type Property = (broken: Broken) => fc.IAsyncPropertyWithHooks<[Spec]>;

async function holdsAndDetects(property: Property, broken: Broken) {
  await fc.assert(property({}), { numRuns: runs(4, 60) });
  await expect(fc.assert(property(broken), { numRuns: runs(30, 60), endOnFailure: true, seed: BROKEN_SEED })).rejects.toThrow();
}

// (E1) Convergence: quiescent within the bound, L = R = S, the disk is the projection of the server heads.
const converges: Property = (broken) =>
  fc.asyncProperty(specArb, async (spec) => {
    const { run, ticks } = await simulate(spec, broken);
    expect(ticks).not.toBeNull();
    expect(convergenceProblems(run)).toEqual([]);
  });

// (E2) No local edit is lost: confirmed, on disk (copies and recovery notes included), or merged.
const noLostEdit: Property = (broken) =>
  fc.asyncProperty(specArb, async (spec) => {
    expect(lostEdits((await simulate(spec, broken)).run)).toEqual([]);
  });

// (E3) No overwrite and no truncated destination: a replace only destroys confirmed or merged content
// (outside the §13.4 window) and only ever places a whole content.
const safeReplaces: Property = (broken) =>
  fc.asyncProperty(specArb, async (spec) => {
    expect((await simulate(spec, broken)).run.log.violations).toEqual([]);
  });

// (E4) Write-ahead (rule 13): every blob is prepared only after its attempt is committed in IndexedDB.
const writeAhead: Property = (broken) =>
  fc.asyncProperty(specArb, async (spec) => {
    expect((await simulate(spec, broken)).run.writeAheadViolations()).toEqual([]);
  });

// (E5) §20.2 relay: no write of a deposed leader commits after the new leader's leader_epoch increment.
const noStaleWrites: Property = (broken) =>
  fc.asyncProperty(specArb, async (spec) => {
    expect((await simulate(spec, broken)).run.log.staleWrites).toEqual([]);
  });

// (E6) §20.2 delivery: every intent written to pending_intents is processed exactly once; none is left.
const intentsOnce: Property = (broken) =>
  fc.asyncProperty(specArb, async (spec) => {
    expect((await simulate(spec, broken)).delivery).toEqual([]);
  });

// (E7) §20.2 currency: an intent is applied only on the state its follower saw, or on its own chain.
const knownStateOnly: Property = (broken) =>
  fc.asyncProperty(specArb, async (spec) => {
    expect((await simulate(spec, broken)).run.log.unknownStateApplies).toEqual([]);
  });

// (E8) Byte exactness: every content on the server and on disk is one some actor wrote, byte for byte
// (attachments included); an adapter that reads through a string is caught.
const byteExact: Property = (broken) =>
  fc.asyncProperty(specArb, async (spec) => {
    expect(unknownContents((await simulate(spec, broken)).run)).toEqual([]);
  });

// (E9) The observation cache never hides an edit (question 146): on a coarse-mtime disk, every run still
// converges (a hidden edit stays on disk and never reaches the server) and loses no edit.
const cacheHidesNothing: Property = (broken) =>
  fc.asyncProperty(specArb, async (spec) => {
    const { run, ticks } = await simulate(spec, broken, "coarse");
    expect(ticks).not.toBeNull();
    expect(convergenceProblems(run)).toEqual([]);
    expect(lostEdits(run)).toEqual([]);
  });

/** FAULTS with an adapter that rewrites the destination and can die before removing the temporary (§15). */
const REWRITING_FAULTS: E2EFaults = { ...FAULTS, rewritingReplace: 0.3 };

// (E11) §20.2 at run time (NOTES question 419): the check is on in every run, and without another tool no
// pause is ever unexplained: this replica's own writes (crashes between writing a file and fixing its base
// included, on an adapter that rewrites the destination), its commits' echoes, merges, copies and renames
// are never taken for another tool. Only the user making exactly a remote edit (non-empty) may pause, as
// §20.2 says. A client that forgets its own writes pauses on them.
const noFalsePause: Property = (broken) =>
  fc.asyncProperty(specArb, async (spec) => {
    const { run } = await simulate(spec, broken, diskMtime(spec), REWRITING_FAULTS);
    expect(run.log.otherTool.violations).toEqual([]);
  });

/**
 * The fault mix with another tool on the folder, and coincidental identical edits (empty ones included): more
 * remote edits for them to carry, and fewer local edits (a file edited here is not in sync, so nothing carries).
 */
// Replaces stay atomic here: a rewriting adapter's crash during a follower intent's write is question 420.
const OTHER_TOOL_FAULTS: E2EFaults = { ...FAULTS, user: 0.02, followerEdit: 0.05, remoteWrite: 0.15, otherTool: 0.5, coincidence: 0.5 };

describe("end-to-end fault runs (runner + Dexie + in-memory disk + server model)", () => {
  const T = 1_800_000;
  it("(E1) convergence", async () => holdsAndDetects(converges, { noEvents: true }), T);
  it("(E2) no local edit is lost", async () => holdsAndDetects(noLostEdit, { constantHash: true }), T);
  it("(E3) replaces never destroy unconfirmed content nor place a truncated one", async () => holdsAndDetects(safeReplaces, { constantHash: true, truncatingWrites: true }), T);
  it("(E4) write-ahead of upload attempts", async () => {
    await fc.assert(writeAhead({}), { numRuns: runs(4, 60) });
  }, T);

  it("(E5) a deposed leader writes nothing", async () => holdsAndDetects(noStaleWrites, { staleAdoptsEpoch: true }), T);
  it("(E6) every intent is processed exactly once", async () => holdsAndDetects(intentsOnce, { followerResends: true }), T);
  it("(E7) intents are applied only on a state their follower knew", async () => holdsAndDetects(knownStateOnly, { followerFreshView: true }), T);
  it("(E8) contents stay byte-exact (attachments included)", async () => holdsAndDetects(byteExact, { lossyText: true }), T);
  it("(E9) the observation cache never hides an edit (coarse mtime)", async () => holdsAndDetects(cacheHidesNothing, { naiveStatCache: true }), T);
  it("(E11) no false pause for another sync tool, crashes of a rewriting adapter included", async () => {
    await holdsAndDetects(noFalsePause, { forgetsOwnWrites: true });
    // The crash the property is about happens (a rewriting replace dying before removing the temporary).
    let crashes = 0;
    for (const spec of fc.sample(specArb, { numRuns: 6, seed: BROKEN_SEED })) crashes += (await simulate(spec, {}, diskMtime(spec), REWRITING_FAULTS)).run.log.otherTool.rewriteCrashes;
    expect(crashes).toBeGreaterThan(0);
  }, T);

  // (E12) §20.2 with another tool on the folder: every pause is explained by what that tool (or a
  // coincidence) put on this disk, never by empty content; after the user resumes, the run still converges
  // and loses no edit. Over the runs, the tool's content is detected, and its empty writes never pause.
  it("(E12) another tool on the folder: detected, never on empty content, never a false positive; resume converges", async () => {
    const total = { carried: 0, carriedEmpty: 0, carriedRenames: 0, coincidences: 0, coincidencesEmpty: 0, contentPauses: 0, renamePauses: 0 };
    await fc.assert(
      fc.asyncProperty(specArb, async (spec) => {
        const { run, ticks } = await simulate(spec, {}, diskMtime(spec), OTHER_TOOL_FAULTS);
        const t = run.log.otherTool;
        expect(t.violations).toEqual([]);
        expect(ticks).not.toBeNull();
        expect(convergenceProblems(run)).toEqual([]);
        expect(lostEdits(run)).toEqual([]);
        total.carried += t.carried;
        total.carriedEmpty += t.carriedEmpty;
        total.carriedRenames += t.carriedRenames;
        total.coincidences += t.coincidences;
        total.coincidencesEmpty += t.coincidencesEmpty;
        total.contentPauses += t.pauses.filter((x) => x.arrivals.length > 0).length;
        total.renamePauses += t.pauses.filter((x) => x.arrivals.length === 0).length;
      }),
      { numRuns: runs(12, 80), seed: BROKEN_SEED },
    );
    const why = JSON.stringify(total);
    expect(total.contentPauses, why).toBeGreaterThan(0);
    expect(total.carriedEmpty, why).toBeGreaterThan(0);
    expect(total.coincidencesEmpty, why).toBeGreaterThan(0);
    expect(total.carriedRenames, why).toBeGreaterThan(0);
  }, T);

  // (E10) §12.6, §40.1: with the quota full now and then (and the delete allowance spent now and then),
  // every run still converges once there is space and the user syncs, and loses no edit; and deletes the
  // client makes after a QUOTA_EXCEEDED still commit while the quota is full. A client that holds deletes
  // with the rest commits none of those.
  it("(E10) quota refusals: convergence and no lost edit; deletes go on over the quota", async () => {
    const quotaRuns = async (broken: Broken) => {
      const total = { refusals: 0, deletesOverQuota: 0 };
      await fc.assert(
        fc.asyncProperty(specArb, async (spec) => {
          const { run, ticks } = await simulate(spec, broken, diskMtime(spec), QUOTA_FAULTS);
          expect(ticks).not.toBeNull();
          expect(convergenceProblems(run)).toEqual([]);
          expect(lostEdits(run)).toEqual([]);
          total.refusals += run.quota().refusals;
          total.deletesOverQuota += run.quota().deletesOverQuota;
        }),
        { numRuns: runs(12, 80), seed: BROKEN_SEED },
      );
      return total;
    };
    const ok = await quotaRuns({});
    expect(ok.refusals).toBeGreaterThan(0);
    expect(ok.deletesOverQuota, JSON.stringify(ok)).toBeGreaterThan(0);
    expect((await quotaRuns({ quotaHoldsDeletes: true })).deletesOverQuota).toBe(0);
  }, T);

  it("generator coverage: crashes, reloads, user actions, merges, copies, imports, cancels, recovery notes, reconciliations, handovers, intents (editor-style views too), attachments", async () => {
    const seen = {
      crashes: 0,
      reloads: 0,
      userActions: 0,
      merge: 0,
      conflictCopy: 0,
      import: 0,
      cancel: 0,
      recovery: 0,
      reconcile: 0,
      uploads: 0,
      handovers: 0,
      staleStopped: 0,
      intentApplied: 0,
      intentCopied: 0,
      intentDiscarded: 0,
      intentChained: 0,
      binaryRevisions: 0,
      invalidUtf8Markdown: 0,
      sharedBinary: 0,
      binaryCopies: 0,
      cacheHit: 0,
      editorView: 0,
    };
    await fc.assert(
      fc.asyncProperty(specArb, async (spec) => {
        const { run } = await simulate(spec);
        const l = run.log;
        const live = [...run.server.revisions.values()].filter((r) => !r.deleted && fromModel(r.content).length > 0);
        const counts: Record<keyof typeof seen, number> = {
          crashes: l.crashes,
          reloads: l.reloads,
          userActions: l.userActions,
          merge: l.events.get("merge") ?? 0,
          conflictCopy: l.events.get("conflictCopy") ?? 0,
          import: l.events.get("import") ?? 0,
          cancel: l.events.get("cancel") ?? 0,
          recovery: [...run.disk.files.keys()].filter(isRecoveryName).length,
          reconcile: l.events.get("reconcile") ?? 0,
          uploads: run.server.log.applied.size,
          handovers: l.handovers,
          staleStopped: l.staleStopped,
          intentApplied: [...l.processed.values()].filter((o) => o.includes("APPLY")).length,
          intentCopied: [...l.processed.values()].filter((o) => o.includes("CONFLICT_COPY")).length,
          intentDiscarded: [...l.processed.values()].filter((o) => o.includes("DISCARD")).length,
          intentChained: [...l.sent.values()].filter((s) => s.intent.afterIntentId !== null && l.processed.get(s.intent.intentId)?.includes("APPLY")).length,
          binaryRevisions: live.filter((r) => isBinaryModel(r.content)).length,
          invalidUtf8Markdown: live.filter((r) => isBinaryModel(r.content) && /\.md$/i.test(r.path)).length,
          sharedBinary: [...run.disk.files.values()].filter((f, _, all) => isBinaryModel(f.content) && all.filter((g) => g.content === f.content).length > 1).length,
          binaryCopies: l.binaryCopies,
          cacheHit: l.events.get("cache-hit") ?? 0,
          editorView: l.events.get("editorView") ?? 0,
        };
        for (const k of Object.keys(seen) as Array<keyof typeof seen>) if (counts[k] > 0) seen[k]++;
      }),
      { numRuns: runs(12, 80), seed: BROKEN_SEED },
    );
    for (const [k, v] of Object.entries(seen)) expect(v, `${k} in ${JSON.stringify(seen)}`).toBeGreaterThan(0);
  }, T);
});
