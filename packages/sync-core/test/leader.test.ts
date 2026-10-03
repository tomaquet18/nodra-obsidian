import { describe, expect, it } from "vitest";
import {
  type Intent,
  type IntentState,
  bumpLocalVersion,
  decideIntent,
  emptyIntentState,
  fencedWriteAllowed,
  nextIntents,
  processIntent,
  takeLeadership,
  viewFingerprint,
} from "../src/leader.js";
import { text, utf8 } from "./utf8.js";

const intent = (over: Partial<Intent> = {}): Intent => ({
  intentId: "i1",
  contextId: "ctx-a",
  intentSeq: 1,
  objectId: "o",
  viewVersion: 0,
  viewFp: "fp0",
  afterIntentId: null,
  change: { kind: "CONTENT", path: "o.md", content: utf8("edit") },
  ...over,
});
const fpOf = (fp: string) => () => fp;

describe("§20.2 fencing: leader_epoch", () => {
  it("the new leader's first transaction increments leader_epoch and remembers it", () => {
    expect(takeLeadership({ leaderEpoch: 4 })).toEqual({ meta: { leaderEpoch: 5 }, epoch: 5 });
  });

  it("a write is allowed only with the current epoch: a deposed leader's write aborts", () => {
    expect(fencedWriteAllowed({ leaderEpoch: 5 }, 5)).toBe(true);
    expect(fencedWriteAllowed({ leaderEpoch: 5 }, 4)).toBe(false);
  });
});

describe("§20.2 intent order", () => {
  it("per context, only the lowest intent_seq is next; contexts in any order (sorted for determinism)", () => {
    const rows = [
      intent({ intentId: "b2", contextId: "b", intentSeq: 2 }),
      intent({ intentId: "a1", contextId: "a", intentSeq: 1 }),
      intent({ intentId: "b1", contextId: "b", intentSeq: 1 }),
      intent({ intentId: "a2", contextId: "a", intentSeq: 2 }),
    ];
    expect(nextIntents(rows).map((i) => i.intentId)).toEqual(["a1", "b1"]);
  });
});

describe("§20.2 when an intent is current", () => {
  it("view_version equal to local_version → apply", () => {
    const st = bumpLocalVersion(emptyIntentState(), "o");
    expect(decideIntent(intent({ viewVersion: 1 }), st, fpOf("other"))).toEqual({ kind: "APPLY", target: "o" });
  });

  it("a follower that saw exactly the current content with an old local_version (own COMMITTED) → current by view_fp", () => {
    const st = bumpLocalVersion(bumpLocalVersion(emptyIntentState(), "o"), "o");
    expect(decideIntent(intent({ viewVersion: 1, viewFp: "fp-now" }), st, fpOf("fp-now"))).toEqual({ kind: "APPLY", target: "o" });
  });

  it("an edit chained on the context's previous intent, with nothing in between → apply without waiting for the echo", () => {
    let st: IntentState = emptyIntentState();
    st = processIntent(st, [intent()], intent(), { kind: "APPLY", target: "o" }).state;
    const next = intent({ intentId: "i2", intentSeq: 2, viewVersion: 0, afterIntentId: "i1" });
    expect(decideIntent(next, st, fpOf("unrelated"))).toEqual({ kind: "APPLY", target: "o" });
  });

  it("a superseded content change → conflict copy; a superseded path change or delete → discarded", () => {
    const st = bumpLocalVersion(emptyIntentState(), "o");
    expect(decideIntent(intent(), st, fpOf("changed"))).toEqual({ kind: "CONFLICT_COPY", base: "o" });
    expect(decideIntent(intent({ change: { kind: "PATH", path: "p.md", content: null } }), st, fpOf("changed"))).toEqual({ kind: "DISCARD" });
    expect(decideIntent(intent({ change: { kind: "DELETE", path: "o.md", content: null } }), st, fpOf("changed"))).toEqual({ kind: "DISCARD" });
  });
});

describe("§20.2 processing: the row is deleted in the same transition", () => {
  it("processing removes exactly that row and bumps local_version of the target", () => {
    const rows = [intent(), intent({ intentId: "i2", intentSeq: 2 })];
    const r = processIntent(emptyIntentState(), rows, rows[0]!, { kind: "APPLY", target: "o" });
    expect(r.pending.map((x) => x.intentId)).toEqual(["i2"]);
    expect(r.state.localVersion.get("o")).toBe(1);
    expect(r.state.lastIntent.get("o")).toEqual({ intentId: "i1", version: 1 });
  });

  it("an intent whose row is gone cannot be processed again (never applied twice)", () => {
    const r = processIntent(emptyIntentState(), [intent()], intent(), { kind: "APPLY", target: "o" });
    expect(() => processIntent(r.state, r.pending, intent(), { kind: "APPLY", target: "o" })).toThrow();
  });
});

describe("§20.2 chains over a conflict copy", () => {
  const superseded = () => {
    const st = bumpLocalVersion(emptyIntentState(), "o");
    return processIntent(st, [intent()], intent(), { kind: "CONFLICT_COPY", base: "o" }, "copy-1").state;
  };

  it("the next intent of the chain applies to the copy while the copy is unchanged", () => {
    const next = intent({ intentId: "i2", intentSeq: 2, afterIntentId: "i1" });
    expect(decideIntent(next, superseded(), fpOf("x"))).toEqual({ kind: "APPLY", target: "copy-1" });
  });

  it("§44.1: the leader edited the copy in between → the next content change creates another copy", () => {
    const st = bumpLocalVersion(superseded(), "copy-1");
    const next = intent({ intentId: "i2", intentSeq: 2, afterIntentId: "i1" });
    expect(decideIntent(next, st, fpOf("x"))).toEqual({ kind: "CONFLICT_COPY", base: "copy-1" });
    expect(decideIntent({ ...next, change: { kind: "PATH", path: "q.md", content: null } }, st, fpOf("x"))).toEqual({ kind: "DISCARD" });
  });

  it("at most one link per context: any later intent of that context replaces it", () => {
    const st = processIntent(superseded(), [intent({ intentId: "i9", intentSeq: 2, objectId: "other", viewVersion: 0 })], intent({ intentId: "i9", intentSeq: 2, objectId: "other" }), { kind: "APPLY", target: "other" }).state;
    expect(st.copyLinks.get("ctx-a")).toBeUndefined();
  });
});

describe("§20.1 / §20.2 view_fp", () => {
  it("summarizes path, deleted and local_compare_hash; the content of a deleted object does not count", () => {
    const fp = viewFingerprint({ path: "a.md", deleted: false, localCompareHash: "h1" });
    expect(fp).toBe(viewFingerprint({ path: "a.md", deleted: false, localCompareHash: "h1" }));
    expect(fp).not.toBe(viewFingerprint({ path: "b.md", deleted: false, localCompareHash: "h1" }));
    expect(fp).not.toBe(viewFingerprint({ path: "a.md", deleted: false, localCompareHash: "h2" }));
    expect(fp).not.toBe(viewFingerprint({ path: "a.md", deleted: true, localCompareHash: null }));
    expect(viewFingerprint({ path: "a.md", deleted: true, localCompareHash: "h1" })).toBe(viewFingerprint({ path: "a.md", deleted: true, localCompareHash: null }));
    expect(viewFingerprint(null)).toBe("absent");
  });

  it("an unknown hash gives an unknown summary, and an unknown summary never makes an intent current", () => {
    expect(viewFingerprint({ path: "a.md", deleted: false, localCompareHash: null })).toBeNull();
    const st = bumpLocalVersion(emptyIntentState(), "o");
    // Neither side known: null never equals null.
    expect(decideIntent(intent({ viewVersion: 0, viewFp: null }), st, () => null)).toEqual({ kind: "CONFLICT_COPY", base: "o" });
    // Only the leader's side unknown.
    expect(decideIntent(intent({ viewVersion: 0, viewFp: "fp0" }), st, () => null)).toEqual({ kind: "CONFLICT_COPY", base: "o" });
    // view_version still proves currency (§20.1).
    expect(decideIntent(intent({ viewVersion: 1, viewFp: null }), st, () => null)).toEqual({ kind: "APPLY", target: "o" });
  });
});
