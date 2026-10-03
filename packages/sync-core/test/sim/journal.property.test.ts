import fc from "fast-check";
import { describe, expect, it } from "vitest";
import type { JournalEntry } from "../../src/journal.js";
import { plan } from "../../src/plan.js";
import { SIM, brokenRuns, runs } from "./budget.js";
import { DEFAULT_SERVER, build, scenarioArb } from "./scenario.js";
import { type Faults, type Variant, type World, hash, run } from "./simulator.js";
import { text } from "../utf8.js";

// Apply journal and temporary files under crashes in the middle of physical operations (§15,
// §44.1, §44.5). Every property also runs against a deliberately broken variant.

const FAULTS: Faults = {
  drop: 0.05,
  lose: 0.1,
  crash: 0.5,
  putTimeout: 0.02,
  remoteWrite: 0.12,
  rotateEpoch: 0.02,
  expireRows: 0.02,
  userEdit: 0.06,
  fileCrash: 0.15,
  tmpTouch: 0.12,
  userMove: 0,
  prune: 0,
  skipPoll: 0,
  activeUntil: 150,
};
const MAX_STEPS = 3000;
const REAL: Variant = { planner: plan };
const worldArb = fc.record({ scenario: scenarioArb, seed: fc.integer() });
type Spec = typeof worldArb extends fc.Arbitrary<infer T> ? T : never;

const serverContents = (w: World) => new Set([...w.server.revisions.values()].filter((r) => !r.deleted).map((r) => r.content));

interface Outcome {
  world: World;
  truncated: string[];
}

/** Runs one world; checks (i) after every step: no bound file ever holds a truncated write. */
function simulate(spec: Spec, variant: Variant = REAL): Outcome {
  const { world } = build(spec.scenario, FAULTS, spec.seed, { ...DEFAULT_SERVER, uploadWindow: 25 });
  const truncated: string[] = [];
  run(world, variant, MAX_STEPS, (w) => {
    const confirmed = serverContents(w);
    for (const [id, p] of w.bound) {
      if (w.recoveryNotes.has(id)) continue; // a recovery note may legitimately hold a partial temporary
      const c = w.files.get(p)?.content;
      if (c !== undefined && !w.log.wholeContents.has(c) && !confirmed.has(c)) truncated.push(`${id} at ${p}`);
    }
    return truncated.length > 0;
  });
  return { world, truncated };
}

/** Independent check of §15 "demostrablemente nuestro" for a deleted temporary. */
const provablyOurs = (content: string, e: JournalEntry | null) =>
  e !== null && e.content !== null && (content === text(e.content) || (e.tmpCreated && text(e.content).startsWith(content)));

// (i) A crash mid-apply never leaves a truncated destination (nor loses user bytes: see (j) and §44.5 (e)).
const noTruncatedDestination = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    expect(simulate(spec, v).truncated).toEqual([]);
  });

// (j) The client never deletes bytes it cannot prove its own: confirmed, preserved elsewhere, empty,
// merged into what replaced them (rule 4), or its own temporary (exact, or own prefix with tmp_created).
const onlyOwnBytesDeleted = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    const { world: w } = simulate(spec, v);
    const confirmed = serverContents(w);
    const onDisk = new Set([...w.files.values()].map((f) => f.content));
    for (const d of w.log.deletions) {
      const merged = d.reason === "replace" && w.log.mergedLocal.has(hash(d.content));
      const ok = d.content === "" || confirmed.has(d.content) || onDisk.has(d.content) || merged || (d.reason === "tmp" && provablyOurs(d.content, d.entry));
      expect(ok, `${d.reason}: ${JSON.stringify(d.content.slice(0, 60))}`).toBe(true);
    }
  });

// (k) No spurious objects: a recovery note the user has not edited is never empty and never comes
// from a temporary the client could prove its own (those are deleted, not imported).
const noSpuriousRecoveryNotes = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    const { world: w } = simulate(spec, v);
    for (const [id, note] of w.recoveryNotes) {
      const p = w.bound.get(id);
      if (p === undefined || w.files.get(p)?.content !== note.content) continue; // edited or gone since
      expect(note.content.length, id).toBeGreaterThan(0);
      expect(note.provable, `${id} rescued from a provably own temporary`).toBe(false);
    }
  });

// (l) A projection rename (including parking) is never read as a user move after a crash.
const noMisreadRenames = (v: Variant) =>
  fc.property(worldArb, (spec) => {
    expect(simulate(spec, v).world.log.pathMisreads).toEqual([]);
  });

function holdsAndDetects(property: (v: Variant) => fc.IPropertyWithHooks<[Spec]>, broken: Variant) {
  fc.assert(property(REAL), { numRuns: runs(10, 80) });
  expect(() => fc.assert(property(broken), brokenRuns(80, 150))).toThrow();
}

describe("apply journal and temporary files under crashes (§15, §44.5)", () => {
  const T = 600_000;
  it("(i) a crash mid-apply never leaves a truncated destination", () => {
    holdsAndDetects(noTruncatedDestination, { planner: plan, writeInPlace: true });
  }, T);

  it("(j) the client never deletes bytes it cannot prove its own", () => {
    holdsAndDetects(onlyOwnBytesDeleted, { planner: plan, cancelDeletesTmp: true });
  }, T);

  it("(k) no spurious recovery notes: never empty, never from a provably own temporary", () => {
    holdsAndDetects(noSpuriousRecoveryNotes, { planner: plan, cancelKeepsTmp: true });
  }, T);

  it("(l) a projection rename after a crash is never read as a user move", () => {
    holdsAndDetects(noMisreadRenames, { planner: plan, renameWithoutJournal: true });
  }, T);

  it("generator coverage: replays, cancels, partial writes, user tmp edits, recovery notes, parking", () => {
    const seen = { replays: 0, cancels: 0, partialWrites: 0, tmpTouches: 0, recoveries: 0, tmpDeleted: 0, parked: 0, merges: 0 };
    fc.assert(
      fc.property(worldArb, (spec) => {
        const { world: w } = simulate(spec);
        if (w.log.journalReplays > 0) seen.replays++;
        if (w.log.journalCancels > 0) seen.cancels++;
        if (w.log.partialWrites > 0) seen.partialWrites++;
        if (w.log.tmpTouches > 0) seen.tmpTouches++;
        if (w.log.recoveries > 0) seen.recoveries++;
        if (w.log.deletions.some((d) => d.reason === "tmp")) seen.tmpDeleted++;
        if (w.log.parked > 0) seen.parked++;
        if (w.log.merges > 0) seen.merges++;
      }),
      { numRuns: runs(20, 200), seed: 20260921 },
    );
    for (const [k, v] of Object.entries(seen)) expect(v, k).toBeGreaterThan(SIM ? 3 : 0);
  }, T);
});
