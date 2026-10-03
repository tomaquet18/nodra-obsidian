import { describe, expect, it } from "vitest";
import { type LeaderFaults, acquire, followerEdit, newTabs, sweepOne, write } from "./leader.js";

// Deterministic §44.1 lines for the multi-tab leader (§20.2).

const QUIET: LeaderFaults = { lostMessage: 0, freeze: 0, wake: 0, reload: 0, steal: 0, followerEdit: 0, leaderEdit: 0, activeUntil: 0 };

describe("§44.1 frozen leader and stolen lock", () => {
  it("no write of the old leader is confirmed after the new leader's leader_epoch increment", () => {
    const t = newTabs(1, QUIET, 2);
    const [a, b] = t.contexts as [(typeof t.contexts)[0], (typeof t.contexts)[0]];
    acquire(t, a);
    expect(write(t, a, {}, () => undefined)).toBe(true);
    a.frozen = true;
    acquire(t, b); // { steal: true }: B's first transaction increments leader_epoch
    a.frozen = false; // A wakes up still believing it leads
    expect(write(t, a, {}, () => undefined)).toBe(false); // fenced: aborts and degrades to follower
    expect(a.epoch).toBeNull();
    expect(write(t, b, {}, () => undefined)).toBe(true);
    expect(t.log.commits.map((c) => c.contextId)).toEqual([a.id, b.id]);
  });

  it("an intent written by a follower survives the leader change and is processed exactly once", () => {
    const t = newTabs(3, QUIET, 3);
    const [a, b, c] = t.contexts as [(typeof t.contexts)[0], (typeof t.contexts)[0], (typeof t.contexts)[0]];
    acquire(t, a);
    followerEdit(t, c); // written to pending_intents; the channel message may be lost
    a.frozen = true;
    acquire(t, b);
    expect(sweepOne(t, b, {})).toBe(true); // the new leader sweeps pending_intents
    a.frozen = false;
    expect(sweepOne(t, a, {})).toBe(false); // the old leader finds nothing (and could not write anyway)
    expect(t.db.pending).toEqual([]);
    expect([...t.log.processed.values()]).toEqual([1]);
  });
});
