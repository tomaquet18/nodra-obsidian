import { describe, expect, it } from "vitest";
import { plan } from "../src/plan.js";
import { recordRemoteHead } from "../src/remote.js";
import { ABSENT, NOT_MATERIALIZED, UNBOUND, del, inFlight, input1, present, rev } from "./fixtures.js";

const S = rev("r1", 1, "n.md", "h1");

describe("§12.2 base table", () => {
  it("L = S, R = S → nothing", () => {
    expect(plan(input1({ l: present("n.md", "h1"), s: S, r: S }))).toEqual([]);
  });

  it("L ≠ S, R = S → upload with expected_head_revision_id = S", () => {
    expect(plan(input1({ l: present("n.md", "h2"), s: S, r: S }))).toEqual([
      { kind: "upload", objectId: "o", expectedHeadRevisionId: "r1", deleted: false },
    ]);
  });

  it("L ≠ S, no S → upload as a create (expected = null)", () => {
    expect(plan(input1({ l: present("n.md", "h1") }))).toEqual([
      { kind: "upload", objectId: "o", expectedHeadRevisionId: null, deleted: false },
    ]);
  });

  it("L = S, R ≠ S → apply remote (§13.4)", () => {
    expect(plan(input1({ l: present("n.md", "h1"), s: S, r: rev("r2", 2, "n.md", "h2") }))).toEqual([
      { kind: "applyRemote", objectId: "o", revisionId: "r2", physicalPath: "n.md" },
    ]);
  });

  it("L ≠ S, R ≠ S, L = R → advance S := R without writing or uploading", () => {
    expect(plan(input1({ l: present("n.md", "h2"), s: S, r: rev("r2", 2, "n.md", "h2") }))).toEqual([
      { kind: "advanceSynced", objectId: "o", revisionId: "r2" },
    ]);
  });

  it("L ≠ S, R ≠ S, L ≠ R (both content, text, base available) → resolve by merge", () => {
    expect(plan(input1({ l: present("n.md", "hL"), s: S, r: rev("r2", 2, "n.md", "hR") }))).toEqual([
      {
        kind: "resolve",
        objectId: "o",
        baseRevisionId: "r1",
        remoteRevisionId: "r2",
        content: "merge",
        path: "remote",
        localRenameDiscarded: false,
      },
    ]);
  });
});

describe("§12.2 rule 3a: same state, different revision", () => {
  it("advances S := R first, even with a pending local edit", () => {
    expect(plan(input1({ l: present("n.md", "h2"), s: S, r: rev("r9", 9, "n.md", "h1") }))).toEqual([
      { kind: "advanceSynced", objectId: "o", revisionId: "r9" },
    ]);
  });
});

describe("§12.2 rule 4 / §17.1: merge or conflict copy", () => {
  const both = { l: present("n.md", "hL"), s: S, r: rev("r2", 2, "n.md", "hR") };

  it("content not text → conflict copy", () => {
    expect(plan(input1(both, { textObjects: new Set() }))).toEqual([
      { kind: "conflictCopy", objectId: "o", remoteRevisionId: "r2", reason: "unmergeable" },
    ]);
  });

  it("base S pruned → conflict copy", () => {
    expect(plan(input1(both, { prunedRevisions: new Set(["r1"]) }))).toEqual([
      { kind: "conflictCopy", objectId: "o", remoteRevisionId: "r2", reason: "unmergeable" },
    ]);
  });

  it("no common ancestor (no S) and L ≠ R → conflict copy", () => {
    expect(plan(input1({ l: present("n.md", "hL"), r: rev("r2", 2, "n.md", "hR") }))).toEqual([
      { kind: "conflictCopy", objectId: "o", remoteRevisionId: "r2", reason: "noCommonAncestor" },
    ]);
  });

  it("rename/modify combines both changes without a copy (local path, remote content)", () => {
    expect(plan(input1({ l: present("m.md", "h1"), s: S, r: rev("r2", 2, "n.md", "hR") }))).toEqual([
      expect.objectContaining({ kind: "resolve", content: "remote", path: "local", localRenameDiscarded: false }),
    ]);
  });

  it("modify/rename combines both changes (local content, remote path)", () => {
    expect(plan(input1({ l: present("n.md", "hL"), s: S, r: rev("r2", 2, "p.md", "h1") }))).toEqual([
      expect.objectContaining({ kind: "resolve", content: "local", path: "remote", localRenameDiscarded: false }),
    ]);
  });

  it("rename/rename keeps the remote path and reports the discarded local rename", () => {
    expect(plan(input1({ l: present("m.md", "h1"), s: S, r: rev("r2", 2, "p.md", "h1") }))).toEqual([
      expect.objectContaining({ kind: "resolve", content: "remote", path: "remote", localRenameDiscarded: true }),
    ]);
  });

  it("same content change on both sides but different paths → no merge needed", () => {
    expect(plan(input1({ l: present("m.md", "h2"), s: S, r: rev("r2", 2, "p.md", "h2") }))).toEqual([
      expect.objectContaining({ kind: "resolve", content: "remote", path: "remote", localRenameDiscarded: true }),
    ]);
  });
});

describe("§12.2 rule 5 / §18.2: delete vs modify", () => {
  it("5a: remote delete vs local content change → local content becomes a new object", () => {
    expect(plan(input1({ l: present("n.md", "h2"), s: S, r: del("r2", 2) }))).toEqual([
      { kind: "conflictCopy", objectId: "o", remoteRevisionId: "r2", reason: "remoteDeleted" },
    ]);
  });

  it("5a: remote delete vs local content change with rename → new object too", () => {
    expect(plan(input1({ l: present("m.md", "h2"), s: S, r: del("r2", 2) }))).toEqual([
      { kind: "conflictCopy", objectId: "o", remoteRevisionId: "r2", reason: "remoteDeleted" },
    ]);
  });

  it("5b: remote delete vs local rename without content change → delete wins, rename discarded", () => {
    expect(plan(input1({ l: present("m.md", "h1"), s: S, r: del("r2", 2) }))).toEqual([
      { kind: "discardLocalRename", objectId: "o", remoteRevisionId: "r2" },
    ]);
  });

  it("5c: local delete vs remote content change → delete not sent, R materialized", () => {
    expect(plan(input1({ l: ABSENT, s: S, r: rev("r2", 2, "n.md", "h2") }))).toEqual([
      { kind: "applyRemote", objectId: "o", revisionId: "r2", physicalPath: "n.md" },
    ]);
  });

  it("5d: local delete vs remote path-only change → delete sent with expected = R", () => {
    expect(plan(input1({ l: ABSENT, s: S, r: rev("r2", 2, "p.md", "h1") }))).toEqual([
      { kind: "upload", objectId: "o", expectedHeadRevisionId: "r2", deleted: true },
    ]);
  });

  it("local delete with R = S → delete upload with expected = S", () => {
    expect(plan(input1({ l: ABSENT, s: S, r: S }))).toEqual([
      { kind: "upload", objectId: "o", expectedHeadRevisionId: "r1", deleted: true },
    ]);
  });

  it("delete/delete → S advances to the remote delete", () => {
    expect(plan(input1({ l: ABSENT, s: S, r: del("r2", 2) }))).toEqual([
      { kind: "advanceSynced", objectId: "o", revisionId: "r2" },
    ]);
  });

  it("L = S, R deleted → apply the remote delete", () => {
    expect(plan(input1({ l: present("n.md", "h1"), s: S, r: del("r2", 2) }))).toEqual([
      { kind: "applyRemote", objectId: "o", revisionId: "r2", physicalPath: "n.md" },
    ]);
  });
});

describe("§12.2 rule 6: discarded creates", () => {
  it("no S, no R, L ABSENT → forgotten without sending anything", () => {
    expect(plan(input1({ l: ABSENT }))).toEqual([{ kind: "forgetUnconfirmedCreate", objectId: "o" }]);
  });
});

describe("§12.2 rule 8: blocked content", () => {
  const blocked = [{ objectId: "o", localCompareHash: "h2", reason: "BLOB_TOO_LARGE" as const }];

  it("no upload while L carries the blocked hash", () => {
    expect(plan(input1({ l: present("n.md", "h2"), s: S, r: S }, { blocked }))).toEqual([]);
  });

  it("upload again once the local content changes", () => {
    expect(plan(input1({ l: present("n.md", "h3"), s: S, r: S }, { blocked }))).toHaveLength(1);
  });

  it("other rules still apply and never overwrite local content (L ≠ S, R ≠ S → resolve, not apply)", () => {
    expect(plan(input1({ l: present("n.md", "h2"), s: S, r: rev("r2", 2, "n.md", "h9") }, { blocked }))).toEqual([
      expect.objectContaining({ kind: "resolve" }),
    ]);
  });
});

describe("§12.2 rule 9: in flight", () => {
  it("an object with an outbox entry receives no action, even with a new edit and a remote event", () => {
    const i = input1({ l: present("n.md", "h3"), s: S, r: rev("r2", 2, "n.md", "h2") }, { outbox: [inFlight("o")] });
    expect(plan(i)).toEqual([]);
  });
});

describe("§12.2 rule 2: not materialized", () => {
  it("UNBOUND with a live R → materialize R, never a delete", () => {
    expect(plan(input1({ l: UNBOUND, s: S, r: S }))).toEqual([{ kind: "applyRemote", objectId: "o", revisionId: "r1", physicalPath: "n.md" }]);
  });

  it("missing local entry is treated as UNBOUND (remote object not applied yet)", () => {
    expect(plan(input1({ r: rev("r2", 2, "n.md", null) }))).toEqual([
      { kind: "applyRemote", objectId: "o", revisionId: "r2", physicalPath: "n.md" },
    ]);
  });

  it("NOT_MATERIALIZED → never written or deleted; S follows R (no local content)", () => {
    expect(plan(input1({ l: NOT_MATERIALIZED, s: S, r: rev("r2", 2, "n.md", "h2") }))).toEqual([
      { kind: "advanceSynced", objectId: "o", revisionId: "r2" },
    ]);
  });
});

describe("§12.2 missing local_compare_hash", () => {
  it("R hash unknown and needed → first action downloads R", () => {
    expect(plan(input1({ l: present("n.md", "h1"), s: S, r: rev("r2", 2, "n.md", null) }))).toEqual([
      { kind: "fetchContent", objectId: "o", revisionId: "r2" },
    ]);
  });

  it("S hash unknown and needed → download S", () => {
    expect(plan(input1({ l: present("n.md", "h1"), s: rev("r1", 1, "n.md", null), r: rev("r1", 1, "n.md", null) }))).toEqual([
      { kind: "fetchContent", objectId: "o", revisionId: "r1" },
    ]);
  });

  it("same revision on S and R needs no hash when there is nothing local to compare", () => {
    expect(plan(input1({ l: ABSENT, s: rev("r1", 1, "n.md", null), r: rev("r1", 1, "n.md", null) }))).toEqual([
      { kind: "upload", objectId: "o", expectedHeadRevisionId: "r1", deleted: true },
    ]);
  });
});

describe("whole tree", () => {
  it("returns actions sorted by object id, independent of map insertion order", () => {
    const a = plan({
      ...input1({}),
      local: new Map([
        ["b", present("b.md", "h")],
        ["a", present("a.md", "h")],
      ]),
    });
    expect(a.map((x) => x.objectId)).toEqual(["a", "b"]);
  });
});

describe("§12.2 rule 3: R never regresses", () => {
  it("ignores heads with sequence ≤ the recorded one", () => {
    const r0 = new Map([["o", rev("r5", 5, "n.md", "h")]]);
    expect(recordRemoteHead(r0, "o", rev("r4", 4, "n.md", "x"))).toBe(r0);
    expect(recordRemoteHead(r0, "o", rev("r5b", 5, "n.md", "x"))).toBe(r0);
    const r1 = recordRemoteHead(r0, "o", rev("r6", 6, "n.md", "x"));
    expect(r1.get("o")?.revisionId).toBe("r6");
    expect(r0.get("o")?.revisionId).toBe("r5");
  });

  it("records the first head of an unknown object", () => {
    expect(recordRemoteHead(new Map(), "o", rev("r1", 1, "n.md", "h")).get("o")?.revisionId).toBe("r1");
  });
});

describe("§20.1 LocalCompareKey loss: S hash unknown and S pruned (§44.1)", () => {
  const sUnknown = rev("r1", 1, "n.md", null);
  const pruned = { prunedRevisions: new Set(["r1"]) };

  it("R = S by revision, L present → upload L over S (maybe redundant, never a loss)", () => {
    expect(plan(input1({ l: present("n.md", "h1"), s: sUnknown, r: sUnknown }, pruned))).toEqual([
      { kind: "upload", objectId: "o", expectedHeadRevisionId: "r1", deleted: false },
    ]);
  });

  it("R = S by revision, L present but blocked → no upload and no fetch", () => {
    const blocked = [{ objectId: "o", localCompareHash: "h1", reason: "BLOB_TOO_LARGE" as const }];
    expect(plan(input1({ l: present("n.md", "h1"), s: sUnknown, r: sUnknown }, { ...pruned, blocked }))).toEqual([]);
  });

  it("R ≠ S, L present and different from R → conflict copy (no base bytes)", () => {
    expect(plan(input1({ l: present("n.md", "h1"), s: sUnknown, r: rev("r2", 2, "n.md", "h2") }, pruned))).toEqual([
      { kind: "conflictCopy", objectId: "o", remoteRevisionId: "r2", reason: "unmergeable" },
    ]);
  });

  it("R ≠ S, L equal to R (both hashes known) → advance S := R", () => {
    expect(plan(input1({ l: present("n.md", "h2"), s: sUnknown, r: rev("r2", 2, "n.md", "h2") }, pruned))).toEqual([
      { kind: "advanceSynced", objectId: "o", revisionId: "r2" },
    ]);
  });

  it("R ≠ S with the same path: never assumed equal to S (no rule 3a advance on an unknown hash)", () => {
    const actions = plan(input1({ l: ABSENT, s: sUnknown, r: rev("r2", 2, "n.md", "h1") }, pruned));
    expect(actions).toEqual([{ kind: "applyRemote", objectId: "o", revisionId: "r2", physicalPath: "n.md" }]);
  });

  it("R deleted, L present → local content kept as a new object (content change cannot be ruled out)", () => {
    expect(plan(input1({ l: present("n.md", "h1"), s: sUnknown, r: del("r2", 2) }, pruned))).toEqual([
      { kind: "conflictCopy", objectId: "o", remoteRevisionId: "r2", reason: "remoteDeleted" },
    ]);
  });

  it("L ABSENT, R ≠ S live → R is materialized again, the delete is not sent (5c, conservative)", () => {
    expect(plan(input1({ l: ABSENT, s: sUnknown, r: rev("r2", 2, "p.md", "h2") }, pruned))).toEqual([
      { kind: "applyRemote", objectId: "o", revisionId: "r2", physicalPath: "p.md" },
    ]);
  });

  it("L ABSENT, R = S → delete uploaded over S (no hash needed)", () => {
    expect(plan(input1({ l: ABSENT, s: sUnknown, r: sUnknown }, pruned))).toEqual([
      { kind: "upload", objectId: "o", expectedHeadRevisionId: "r1", deleted: true },
    ]);
  });

  it("L ABSENT, R deleted → advance to the delete", () => {
    expect(plan(input1({ l: ABSENT, s: sUnknown, r: del("r2", 2) }, pruned))).toEqual([
      { kind: "advanceSynced", objectId: "o", revisionId: "r2" },
    ]);
  });

  it("UNBOUND, R ≠ S live → materialize R", () => {
    expect(plan(input1({ l: UNBOUND, s: sUnknown, r: rev("r2", 2, "n.md", "h2") }, pruned))).toEqual([
      { kind: "applyRemote", objectId: "o", revisionId: "r2", physicalPath: "n.md" },
    ]);
  });

  it("S hash unknown but NOT pruned → still fetches S first", () => {
    expect(plan(input1({ l: present("n.md", "h1"), s: sUnknown, r: sUnknown }))).toEqual([
      { kind: "fetchContent", objectId: "o", revisionId: "r1" },
    ]);
  });
});
