import fc from "fast-check";
import { describe, expect, inject, it } from "vitest";
import { ATTACHMENT_FAULTS, type Broken, type DiskMtime, type E2EFaults, type Run, convergenceProblems, e2eSpecArb, lostEdits, reencryptionProblems, runToRest, startRun } from "./e2e.js";
import { SPEC_WINDOWS } from "./windows.js";

// §35.13 in the end-to-end fault runs: a SWITCH_TO_PRIVATE at a random step, then re-encryption passes
// mixed with the user's edits, remote writes, syncs, lost requests and responses, crashes and reloads
// (inside the passes too), pruning and further epoch rotations. After EVERY step the §44.5 server
// invariants hold and no revision is lost or duplicated; at rest the list is empty and, once collected,
// no current or historical blob of the vault is in a pre-switch epoch. Each oracle has a broken variant.

const SIM = inject("nodraSim") === true;
const runs = (fast: number, full: number) => (SIM ? full : fast);
const BROKEN_SEED = 20260924;
const MAX_TICKS = 2500;
const FAULTS: E2EFaults = { ...ATTACHMENT_FAULTS, reencrypt: 0.3 };

type Spec = typeof e2eSpecArb extends fc.Arbitrary<infer T> ? T : never;
const diskMtime = (spec: Spec): DiskMtime => (spec.seed % 2 === 0 ? "coarse" : "counter");

async function simulate(spec: Spec, broken: Broken = {}, maxTicks = MAX_TICKS): Promise<{ run: Run; ticks: number | null; end: string[] }> {
  const run = await startRun(spec.scenario, FAULTS, spec.seed, broken, SPEC_WINDOWS, diskMtime(spec));
  try {
    const ticks = await runToRest(run, maxTicks);
    return { run, ticks, end: reencryptionProblems(run) };
  } finally {
    run.close();
  }
}

const property = (broken: Broken, maxTicks = MAX_TICKS) =>
  fc.asyncProperty(e2eSpecArb, async (spec) => {
    const { run, ticks, end } = await simulate(spec, broken, maxTicks);
    expect(end).toEqual([]);
    expect(ticks).not.toBeNull();
    expect(convergenceProblems(run)).toEqual([]);
    expect(lostEdits(run)).toEqual([]);
    expect(run.log.violations).toEqual([]);
    expect(run.writeAheadViolations()).toEqual([]);
  });

/**
 * A broken variant must fail the property. Its runs stop at 600 ticks: a correct run is at rest long before
 * (the active phase is 100), and a variant that never rests fails there as it would at MAX_TICKS.
 */
const detects = (broken: Broken) => expect(fc.assert(property(broken, 600), { numRuns: runs(20, 60), endOnFailure: true, seed: BROKEN_SEED })).rejects.toThrow();

describe("§35.13 re-encryption in the end-to-end fault runs", () => {
  const T = 1_800_000;
  it("(R1) §44.5 after every step; at rest nothing listed, no pre-switch blob stored, nothing lost or duplicated, converged", async () => {
    await fc.assert(property({}), { numRuns: runs(3, 60) });
  }, T);

  it("(R1) detects an adapter that answers every swap without sending it (the old blobs stay: never at rest)", async () => detects({ reencryptLies: true }), T);
  it("(R1) detects a list whose manifests open to the wrong path (a revision's manifest no longer says its path)", async () => detects({ reencryptWrongPath: true }), T);
  it("(R1) detects a server that keeps the old blobs referenced (refcounts, and pre-switch blobs at the end)", async () => detects({ server: { brokenReencryptKeepsOld: true } }), T);
  it("(R1) detects a server that leaves the old blobs stored after the swap (a pre-switch blob at the end)", async () => detects({ server: { brokenReencryptLeavesOld: true } }), T);
  it("(R1) detects a server that re-commits the revision instead of swapping it (a revision changed: lost or duplicated)", async () => detects({ server: { brokenReencryptNewSequence: true } }), T);

  it("generator coverage: switches, swaps, crashes, rotations after the switch, pruning, attachments and empty files", async () => {
    const seen = { switched: 0, swapped: 0, crashes: 0, passCrashes: 0, rotatedAfter: 0, pruned: 0, empty: 0, binary: 0, sharedContent: 0 };
    await fc.assert(
      fc.asyncProperty(e2eSpecArb, async (spec) => {
        const { run } = await simulate(spec);
        const s = run.server;
        if (run.log.switchedAt !== null) seen.switched++;
        if (run.log.reencrypted > 0) seen.swapped++;
        if (run.log.crashes > 0) seen.crashes++;
        if (run.log.passCrashes > 0) seen.passCrashes++;
        if (run.log.switchedAt !== null && s.privateSince !== null && Number(s.epoch.slice(1)) > Number(s.privateSince.slice(1))) seen.rotatedAfter++;
        if (s.pruned.size > 0) seen.pruned++;
        if ([...s.revisions.values()].some((r) => !r.deleted && r.content === "")) seen.empty++;
        if ([...s.revisions.values()].some((r) => r.content.startsWith("\0b64:"))) seen.binary++;
        // Two live revisions on one content blob (a rename keeps it, §7): one new content blob must serve both.
        const contents = [...s.revisions.values()].filter((r) => !s.pruned.has(r.revisionId) && r.contentBlobId != null).map((r) => r.contentBlobId);
        if (new Set(contents).size < contents.length) seen.sharedContent++;
      }),
      { numRuns: runs(8, 40), seed: BROKEN_SEED },
    );
    for (const [k, v] of Object.entries(seen)) expect(v, `${k} in ${JSON.stringify(seen)}`).toBeGreaterThan(0);
  }, T);
});
