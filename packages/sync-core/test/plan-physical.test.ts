import { describe, expect, it } from "vitest";
import { plan, resolveLocalPaths } from "../src/plan.js";
import type { LocalEntry, PlanInput, RevisionEntry } from "../src/types.js";
import { UNBOUND, inFlight, present, rev } from "./fixtures.js";

/** Multi-object input; every object is text, nothing pruned. */
function tree(objects: Record<string, { l?: LocalEntry; s?: RevisionEntry; r?: RevisionEntry }>, extra: Partial<PlanInput> = {}): PlanInput {
  const pick = (k: "l" | "s" | "r") =>
    new Map(Object.entries(objects).flatMap(([id, o]) => (o[k] ? [[id, o[k]!] as [string, never]] : [])));
  return {
    local: pick("l") as Map<string, LocalEntry>,
    synced: pick("s") as Map<string, RevisionEntry>,
    remote: pick("r") as Map<string, RevisionEntry>,
    outbox: [],
    blocked: [],
    textObjects: new Set(Object.keys(objects)),
    prunedRevisions: new Set(),
    untrackedFiles: [],
    tmpHex: ["0000000a", "0000000b", "0000000c"],
    ...extra,
  };
}

const ID_A = "0190a1b2-0001-7000-8000-0000aaaaaaaa";
const ID_B = "0190a1b2-0002-7000-8000-0000bbbbbbbb";

describe("§12.2 rule 12 / §16.4: only a file that moved changes its logical path", () => {
  it("a moved file takes its logical path from the physical → logical rule and is uploaded", () => {
    const s = rev("r1", 1, "n.md", "h1");
    const i = tree({ [ID_A]: { l: present("n.md", "h1", "sub/n.md", "n.md"), s, r: s } });
    expect(resolveLocalPaths(i).get(ID_A)).toMatchObject({ path: "sub/n.md" });
    expect(plan(i)).toEqual([{ kind: "upload", objectId: ID_A, expectedHeadRevisionId: "r1", deleted: false }]);
  });

  it("moving into a sanitized projected folder uses the folder's logical path", () => {
    const sa = rev("ra", 1, "a:b/x.md", "hx", false, 1);
    const sb = rev("rb", 2, "n.md", "hn", false, 2);
    const i = tree({
      [ID_A]: { l: present("a:b/x.md", "hx", "a_b/x.md"), s: sa, r: sa },
      [ID_B]: { l: present("n.md", "hn", "a_b/n.md", "n.md"), s: sb, r: sb },
    });
    expect(resolveLocalPaths(i).get(ID_B)).toMatchObject({ path: "a:b/n.md" });
  });

  it("a file that did not move keeps its logical path even at a stale physical path; the projection moves it", () => {
    const s = rev("r1", 1, "a:b.md", "h1");
    const i = tree({ [ID_A]: { l: present("a:b.md", "h1", "old.md"), s, r: s } });
    expect(resolveLocalPaths(i).get(ID_A)).toMatchObject({ path: "a:b.md" });
    expect(plan(i)).toEqual([{ kind: "movePhysical", objectId: ID_A, from: "old.md", to: "a_b.md" }]);
  });
});

describe("§12.2 rule 7 / §16.3 / §16.7: physical actions from the whole-tree projection", () => {
  it("case-only collision: the later object is moved to its suffixed physical name", () => {
    const sa = rev("ra", 1, "n.md", "h1", false, 1);
    const sb = rev("rb", 2, "N.md", "h2", false, 2);
    const i = tree({
      [ID_A]: { l: present("n.md", "h1"), s: sa, r: sa },
      [ID_B]: { l: present("N.md", "h2", "other.md"), s: sb, r: sb },
    });
    expect(plan(i)).toEqual([
      { kind: "movePhysical", objectId: ID_B, from: "other.md", to: "N (Nodra conflict bbbbbbbb).md" },
    ]);
  });

  it("a remote object is materialized at its projected path, avoiding an untracked file", () => {
    const r = rev("r1", 1, "n.md", "h1");
    const i = tree({ [ID_A]: { l: UNBOUND, r } }, { untrackedFiles: ["n.md"] });
    expect(plan(i)).toEqual([
      { kind: "applyRemote", objectId: ID_A, revisionId: "r1", physicalPath: "n (Nodra conflict aaaaaaaa).md" },
    ]);
  });

  it("a remote content change is applied in place, at the object's current file", () => {
    const s = rev("r1", 1, "n.md", "h1");
    const i = tree({ [ID_A]: { l: present("n.md", "h1"), s, r: rev("r2", 2, "n.md", "h2") } });
    expect(plan(i)).toEqual([{ kind: "applyRemote", objectId: ID_A, revisionId: "r2", physicalPath: "n.md" }]);
  });

  it("a remote swap of two paths is applied through a nodra-tmp-* parking step, never an overwrite", () => {
    const sa = rev("ra1", 1, "1.md", "ha", false, 1);
    const sb = rev("rb1", 2, "2.md", "hb", false, 2);
    const i = tree({
      [ID_A]: { l: present("1.md", "ha"), s: sa, r: rev("ra2", 3, "2.md", "ha", false, 1) },
      [ID_B]: { l: present("2.md", "hb"), s: sb, r: rev("rb2", 4, "1.md", "hb", false, 2) },
    });
    const actions = plan(i);
    const moves = actions.filter((a) => a.kind === "movePhysical");
    expect(moves[0]).toEqual({ kind: "movePhysical", objectId: ID_A, from: "1.md", to: "nodra-tmp-0000000a" });
  });

  it("bug (Q74/Q75): a remote rename that makes the file its own ancestor or descendant is parked first", () => {
    // `g` → `g/f.md`: no single rename can do it (the folder `g/` needs the file `g` gone).
    const s = rev("r1", 1, "g", "h1");
    const into = tree({ [ID_A]: { l: present("g", "h1"), s, r: rev("r2", 2, "g/f.md", "h1") } });
    expect(plan(into)[0]).toEqual({ kind: "movePhysical", objectId: ID_A, from: "g", to: "nodra-tmp-0000000a" });
    // `Foo/y.md` → `foo`: parked outside `Foo/`, at the target's folder.
    const s2 = rev("r1", 1, "Foo/y.md", "h1");
    const onto = tree({ [ID_A]: { l: present("Foo/y.md", "h1"), s: s2, r: rev("r2", 2, "foo", "h1") } });
    expect(plan(onto)[0]).toEqual({ kind: "movePhysical", objectId: ID_A, from: "Foo/y.md", to: "nodra-tmp-0000000a" });
  });

  it("an in-flight object gets no physical action (rule 9)", () => {
    const s = rev("r1", 1, "a:b.md", "h1");
    const i = tree({ [ID_A]: { l: present("a:b.md", "h1", "old.md"), s, r: s } }, { outbox: [inFlight(ID_A)] });
    expect(plan(i)).toEqual([]);
  });
});

describe("§16.2 NOT_MATERIALIZED (projected path too long)", () => {
  const long = Array.from({ length: 12 }, (_, i) => `${"d".repeat(90)}${i}`).join("/");

  it("a remote object whose projected path is too long is never materialized: it is marked, S := R", () => {
    const i = tree({ [ID_A]: { l: UNBOUND, r: rev("r1", 1, `${long}/n.md`, "h1") } });
    expect(plan(i)).toEqual([{ kind: "markNotMaterialized", objectId: ID_A, revisionId: "r1" }]);
  });

  it("once marked with S = R nothing is planned, and its absence never produces a delete", () => {
    const r = rev("r1", 1, `${long}/n.md`, "h1");
    expect(plan(tree({ [ID_A]: { l: UNBOUND, s: r, r } }))).toEqual([{ kind: "markNotMaterialized", objectId: ID_A, revisionId: "r1" }]);
    expect(plan(tree({ [ID_A]: { l: { kind: "NOT_MATERIALIZED", reason: "LOCAL_PATH_TOO_LONG" }, s: r, r } }))).toEqual([]);
  });

  it("bug (simulation (b)): a LOCAL_PATH_TOO_LONG object whose path becomes short is materialized again", () => {
    const s = rev("r1", 1, `${long}/n.md`, "h1");
    const i = tree({ [ID_A]: { l: { kind: "NOT_MATERIALIZED", reason: "LOCAL_PATH_TOO_LONG" }, s, r: rev("r2", 2, "n.md", "h1") } });
    expect(plan(i)).toEqual([{ kind: "applyRemote", objectId: ID_A, revisionId: "r2", physicalPath: "n.md" }]);
  });

  it("bug (simulation (a)): 5c with a too-long remote path marks the object NOT_MATERIALIZED, never a delete", () => {
    const s = rev("r1", 1, "n.md", "h1");
    const i = tree({ [ID_A]: { l: { kind: "ABSENT" }, s, r: rev("r2", 2, `${long}/n.md`, "h2") } });
    expect(plan(i)).toEqual([{ kind: "markNotMaterialized", objectId: ID_A, revisionId: "r2" }]);
  });

  it("a LOCAL_FS_REJECTED object is never written here; S follows R", () => {
    const s = rev("r1", 1, "n.md", "h1");
    const i = tree({ [ID_A]: { l: { kind: "NOT_MATERIALIZED", reason: "LOCAL_FS_REJECTED" }, s, r: rev("r2", 2, "m.md", "h1") } });
    expect(plan(i)).toEqual([{ kind: "advanceSynced", objectId: ID_A, revisionId: "r2" }]);
  });

  it("a file already on disk leaves it only when nothing is pending", () => {
    const r = rev("r1", 1, `${long}/n.md`, "h1");
    expect(plan(tree({ [ID_A]: { l: present(`${long}/n.md`, "h1", "short.md"), s: r, r } }))).toEqual([
      { kind: "removePhysical", objectId: ID_A, from: "short.md" },
    ]);
    const pending = plan(tree({ [ID_A]: { l: present(`${long}/n.md`, "h2", "short.md"), s: r, r } }));
    expect(pending.map((a) => a.kind)).toEqual(["upload"]);
  });
});

describe("action priority (NOTES.md)", () => {
  it("fetch, then S-only, then local resolution, then upload, then physical plan, then in-place apply", () => {
    const i = tree({
      a: { l: present("a.md", "h1"), s: rev("a1", 1, "a.md", "h1"), r: rev("a2", 2, "a.md", "h9") }, // apply in place
      b: { l: present("b.md", "h2"), s: rev("b1", 1, "b.md", "h1"), r: rev("b1", 1, "b.md", "h1") }, // upload
      c: { l: present("c.md", "h1"), s: rev("c1", 1, "c.md", "h1"), r: rev("c2", 2, "c.md", null) }, // fetch
      d: { l: present("d.md", "h5"), s: rev("d1", 1, "d.md", "h1"), r: rev("d2", 2, "d.md", "h5") }, // advance
      e: { l: present("e.md", "h1", "old-e.md"), s: rev("e1", 1, "e.md", "h1"), r: rev("e1", 1, "e.md", "h1") }, // move
      f: { l: present("f.md", "h2"), s: rev("f1", 1, "f.md", "h1"), r: rev("f2", 2, "f.md", "h3") }, // resolve
    });
    expect(plan(i).map((a) => `${a.kind}:${a.objectId}`)).toEqual([
      "fetchContent:c",
      "advanceSynced:d",
      "resolve:f",
      "upload:b",
      "movePhysical:e",
      "applyRemote:a",
    ]);
  });
});
