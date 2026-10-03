import { describe, expect, it } from "vitest";
import {
  EMPTY_OTHER_SYNC_FACTS,
  PROJECTION_RENAME_ARRIVALS_TO_PAUSE,
  contentArrivals,
  explainWrite,
  expectedProjectionMoves,
  projectionRenameArrivals,
  pruneOtherSyncFacts,
  renameArrivals,
} from "../src/other-sync.js";
import type { PlanInput } from "../src/types.js";
import { ABSENT, inFlight, input1, present, rev } from "./fixtures.js";

// §20.2 "Nodra es el único sincronizador de la carpeta", runtime half (NOTES question 417).

const S = rev("r1", 1, "n.md", "h1");
const R = rev("r2", 2, "n.md", "h2");
const EMPTY = "h:";
const facts = EMPTY_OTHER_SYNC_FACTS;

describe("content arrivals: the disk already holds exactly the remote revision's content", () => {
  it("L = R ≠ S with nothing of this replica explaining it → an arrival of (object, remote revision)", () => {
    expect(contentArrivals(input1({ l: present("n.md", "h2"), s: S, r: R }), facts, EMPTY)).toEqual([{ objectId: "o", revisionId: "r2" }]);
  });

  it("the path does not take part: a moved file holding the remote content is an arrival too", () => {
    expect(contentArrivals(input1({ l: present("n.md", "h2", "x.md", "n.md"), s: S, r: rev("r2", 2, "y.md", "h2") }), facts, EMPTY)).toEqual([
      { objectId: "o", revisionId: "r2" },
    ]);
  });

  it("a journal entry of this replica that wrote that content explains it (§15): no arrival", () => {
    expect(contentArrivals(input1({ l: present("n.md", "h2"), s: S, r: R }), explainWrite(facts, "o", "h2"), EMPTY)).toEqual([]);
  });

  it("a journal entry that wrote other content explains nothing", () => {
    expect(contentArrivals(input1({ l: present("n.md", "h2"), s: S, r: R }), explainWrite(facts, "o", "h9"), EMPTY)).toHaveLength(1);
  });

  it("empty content is exempt (the likeliest coincidence, no evidence of another tool)", () => {
    expect(contentArrivals(input1({ l: present("n.md", EMPTY), s: S, r: rev("r2", 2, "n.md", EMPTY) }), facts, EMPTY)).toEqual([]);
  });

  it("an acknowledged (object, revision) is not reported again; another revision of it is (detection re-arms)", () => {
    const acked = { ...facts, acknowledged: new Map([["o", "r2"]]) };
    expect(contentArrivals(input1({ l: present("n.md", "h2"), s: S, r: R }), acked, EMPTY)).toEqual([]);
    expect(contentArrivals(input1({ l: present("n.md", "h3"), s: S, r: rev("r3", 3, "n.md", "h3") }), acked, EMPTY)).toEqual([{ objectId: "o", revisionId: "r3" }]);
  });

  it("no arrival: a different local edit (a conflict, not another tool), L = S, R = S, an in-flight object", () => {
    expect(contentArrivals(input1({ l: present("n.md", "hL"), s: S, r: R }), facts, EMPTY)).toEqual([]);
    expect(contentArrivals(input1({ l: present("n.md", "h1"), s: S, r: R }), facts, EMPTY)).toEqual([]);
    expect(contentArrivals(input1({ l: present("n.md", "h2"), s: S, r: S }), facts, EMPTY)).toEqual([]);
    expect(contentArrivals(input1({ l: present("n.md", "h2"), s: S, r: R }, { outbox: [inFlight("o")] }), facts, EMPTY)).toEqual([]);
  });

  it("own commit echo (§44): the event of the revision that is already the base is no arrival", () => {
    const own = rev("r2", 2, "n.md", "h2");
    expect(contentArrivals(input1({ l: present("n.md", "h2"), s: own, r: own }), facts, EMPTY)).toEqual([]);
  });

  it("no arrival without the hashes it needs (they are fetched first), nor for deletes or objects without a base", () => {
    expect(contentArrivals(input1({ l: present("n.md", "h2"), s: S, r: rev("r2", 2, "n.md", null) }), facts, EMPTY)).toEqual([]);
    expect(contentArrivals(input1({ l: present("n.md", "h2"), s: rev("r1", 1, "n.md", null), r: R }), facts, EMPTY)).toEqual([]);
    expect(contentArrivals(input1({ l: ABSENT, s: S, r: rev("r2", 2, "n.md", null, true) }), facts, EMPTY)).toEqual([]);
    expect(contentArrivals(input1({ l: present("n.md", "h2"), r: R }), facts, EMPTY)).toEqual([]);
  });
});

describe("pruning the facts: they live only while they can matter", () => {
  it("an explained write goes once the base holds that content; an acknowledgement once S reaches it or R moves on", () => {
    const f = { explainedWrites: new Map([["o", "h2"], ["p", "h7"]]), acknowledged: new Map([["o", "r2"], ["p", "r5"], ["q", "r8"]]) };
    const synced = new Map([["o", rev("r2", 2, "n.md", "h2")], ["p", rev("r4", 4, "p.md", "h4")], ["q", rev("r7", 7, "q.md", "h7")]]);
    const remote = new Map([["p", rev("r5", 5, "p.md", "h5")], ["q", rev("r9", 9, "q.md", "h9")]]);
    const pruned = pruneOtherSyncFacts(f, synced, remote);
    expect([...pruned.explainedWrites]).toEqual([["p", "h7"]]);
    expect([...pruned.acknowledged]).toEqual([["p", "r5"]]);
  });

  it("returns the same value when nothing goes (no needless write)", () => {
    const f = { explainedWrites: new Map([["o", "h9"]]), acknowledged: new Map([["o", "r2"]]) };
    expect(pruneOtherSyncFacts(f, new Map([["o", S]]), new Map([["o", R]]))).toBe(f);
  });
});

/** Two objects whose logical names collide (N.md / n.md): the projection gives the later one a suffix. */
function collision(localB: PlanInput["local"] extends ReadonlyMap<string, infer L> ? L : never): PlanInput {
  const a = rev("ra", 1, "N.md", "hA", false, 1);
  const b = rev("rb", 2, "n.md", "hB", false, 2);
  return {
    ...input1({}),
    local: new Map([["a", present("N.md", "hA")], ["b", localB]]),
    synced: new Map([["a", a], ["b", b]]),
    remote: new Map([["a", a], ["b", b]]),
    textObjects: new Set(["a", "b"]),
  };
}

describe("projection renames (§16.7) of another replica appearing on disk before they are applied", () => {
  const before = collision(present("n.md", "hB"));
  const move = expectedProjectionMoves(before).get("b");

  it("the projection wants b moved off its colliding path", () => {
    expect(move).toBeDefined();
    expect(move!.from).toBe("n.md");
    expect(move!.to).not.toBe("n.md");
  });

  it("the file left its path and sits, unchanged, exactly where the projection was taking it → an arrival", () => {
    const disk = new Map([["N.md", "hA"], [move!.to, "hB"]]);
    expect(projectionRenameArrivals(before, disk)).toEqual(["b"]);
  });

  it("not an arrival: the file is still at its path, it moved elsewhere, or it changed on the way", () => {
    expect(projectionRenameArrivals(before, new Map([["N.md", "hA"], ["n.md", "hB"]]))).toEqual([]);
    expect(projectionRenameArrivals(before, new Map([["N.md", "hA"], ["elsewhere.md", "hB"]]))).toEqual([]);
    expect(projectionRenameArrivals(before, new Map([["N.md", "hA"], [move!.to, "hX"]]))).toEqual([]);
  });

  it("parking under nodra-tmp-* (a cycle) is never taken for another replica's rename", () => {
    for (const m of expectedProjectionMoves(before).values()) expect(m.to.includes("nodra-tmp-")).toBe(false);
  });

  it("the threshold is three in a row", () => {
    expect(PROJECTION_RENAME_ARRIVALS_TO_PAUSE).toBe(3);
  });
});

describe("remote renames already on disk (the other device's §16.7 rename, carried by another tool)", () => {
  const S2 = rev("r1", 1, "a.md", "h1");
  const moved = rev("r2", 2, "b.md", "h1");

  it("the file sits at R's path with R's content, and this replica did not move it → an arrival", () => {
    expect(renameArrivals(input1({ l: present("b.md", "h1", "b.md", "a.md"), s: S2, r: moved }))).toEqual([{ objectId: "o", revisionId: "r2" }]);
  });

  it("not an arrival: still at S's path (not applied yet), moved elsewhere, other content, in flight, or R did not rename", () => {
    expect(renameArrivals(input1({ l: present("a.md", "h1"), s: S2, r: moved }))).toEqual([]);
    expect(renameArrivals(input1({ l: present("c.md", "h1"), s: S2, r: moved }))).toEqual([]);
    expect(renameArrivals(input1({ l: present("b.md", "hX"), s: S2, r: moved }))).toEqual([]);
    expect(renameArrivals(input1({ l: present("b.md", "h1"), s: S2, r: moved }, { outbox: [inFlight("o")] }))).toEqual([]);
    expect(renameArrivals(input1({ l: present("b.md", "h2"), s: S2, r: rev("r2", 2, "a.md", "h2") }))).toEqual([]);
  });
});
