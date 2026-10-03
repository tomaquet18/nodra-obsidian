import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { SIM, brokenRuns, runs } from "./budget.js";
import { type LeaderFaults, type LeaderVariant, newTabs, runTabs } from "./leader.js";

// Multi-tab leader (§20.2, §44.1 "dos pestañas / dos ventanas / recarga del plugin", "líder congelado y
// robo del lock"). Every property also runs against a broken variant.

const FAULTS: LeaderFaults = {
  lostMessage: 0.3,
  freeze: 0.05,
  wake: 0.2,
  reload: 0.02,
  steal: 0.3,
  followerEdit: 0.5,
  leaderEdit: 0.1,
  activeUntil: 200,
};
const MAX_STEPS = 5000;
const specArb = fc.record({ seed: fc.integer(), contexts: fc.integer({ min: 2, max: 4 }) });
type Spec = typeof specArb extends fc.Arbitrary<infer T> ? T : never;

const simulate = (spec: Spec, v: LeaderVariant = {}) => {
  const t = newTabs(spec.seed, FAULTS, spec.contexts);
  const steps = runTabs(t, v, MAX_STEPS);
  return { t, steps };
};

// (r) One writer per vault: each leader_epoch belongs to one context, and writers never interleave —
// once a newer leader has written, no context with an older epoch writes again.
const oneWriter = (v: LeaderVariant) =>
  fc.property(specArb, (spec) => {
    const { t } = simulate(spec, v);
    const writers = new Map<number, Set<string>>();
    let newest = 0;
    for (const c of t.log.commits) {
      (writers.get(c.epoch) ?? writers.set(c.epoch, new Set()).get(c.epoch)!).add(c.contextId);
      expect(c.epoch, `${c.contextId} (epoch ${c.epoch}) wrote after epoch ${newest}`).toBeGreaterThanOrEqual(newest);
      newest = Math.max(newest, c.epoch);
    }
    for (const [epoch, set] of writers) expect(set.size, `epoch ${epoch}`).toBe(1);
  });

// (s) No write of an old leader is confirmed after the new leader's leader_epoch increment.
const noStaleWrite = (v: LeaderVariant) =>
  fc.property(specArb, (spec) => {
    const { t } = simulate(spec, v);
    for (const c of t.log.commits) expect(c.epoch, `${c.contextId} wrote with epoch ${c.epoch} after ${c.metaEpoch}`).toBe(c.metaEpoch);
  });

// (t) Intents are neither lost nor applied twice, and never applied over a state their follower did not know.
const intentsExactlyOnce = (v: LeaderVariant) =>
  fc.property(specArb, (spec) => {
    const { t, steps } = simulate(spec, v);
    expect(steps).not.toBeNull();
    expect(t.db.pending).toEqual([]);
    for (const id of t.log.created) expect(t.log.processed.get(id), id).toBe(1);
    expect(t.log.unknownStateApplies).toEqual([]);
  });

const holdsAndDetects = (property: fc.IPropertyWithHooks<[Spec]>, broken: fc.IPropertyWithHooks<[Spec]>) => {
  fc.assert(property, { numRuns: runs(15, 150) });
  expect(() => fc.assert(broken, brokenRuns(80, 150))).toThrow();
};

describe("multi-tab leader (§20.2)", () => {
  it("(r) one writer per vault", () => {
    holdsAndDetects(oneWriter({}), oneWriter({ noFencing: true }));
  });

  it("(s) no write of an old leader is confirmed after the new leader_epoch", () => {
    holdsAndDetects(noStaleWrite({}), noStaleWrite({ noFencing: true }));
  });

  it("(t) intents are neither lost nor applied twice (row deleted in the same transition)", () => {
    holdsAndDetects(intentsExactlyOnce({}), intentsExactlyOnce({ keepRows: true }));
  });

  it("(t) intents are never applied over a state their follower did not know", () => {
    holdsAndDetects(intentsExactlyOnce({}), intentsExactlyOnce({ ignoreCurrency: true }));
  });

  it("generator coverage: steals, fenced aborts, copies, discards, chains on copies, lost messages, reloads", () => {
    const seen = { steals: 0, fencedAborts: 0, copies: 0, discards: 0, chainedOnCopy: 0, lostMessages: 0, reloads: 0 };
    fc.assert(
      fc.property(specArb, (spec) => {
        const { t } = simulate(spec);
        for (const k of Object.keys(seen) as Array<keyof typeof seen>) if (t.log[k] > 0) seen[k]++;
      }),
      { numRuns: runs(40, 200), seed: 20260921 },
    );
    for (const [k, v] of Object.entries(seen)) expect(v, k).toBeGreaterThan(SIM ? 3 : 0);
  });
});
