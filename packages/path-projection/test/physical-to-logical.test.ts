import { describe, expect, it } from "vitest";
import { observedLogicalPath, physicalToLogical } from "../src/physical-to-logical.js";
import { project } from "../src/project.js";
import { obj, oid } from "./helpers.js";

const ID = oid(1, "3fa9c21b");
const folders = new Map([
  ["a_b", "a:b"],
  ["otra", "otra"],
  ["Foo (Nodra conflict 3fa9c21b)", "foo"],
]);
const moved = (currentLogicalPath: string, currentPhysicalPath: string, newPhysicalPath: string) =>
  physicalToLogical({ objectId: ID, currentLogicalPath, currentPhysicalPath, newPhysicalPath }, folders);

describe("§16.4 physical → logical (spec examples, Annex B.1 Físico → lógico)", () => {
  it("rename inside a sanitized folder keeps the logical folder spelling", () => {
    expect(moved("a:b/x.md", "a_b/x.md", "a_b/y.md")).toEqual({ ok: true, path: "a:b/y.md" });
  });

  it("moving into a sanitized projected folder uses its logical path", () => {
    expect(moved("otra/x.md", "otra/x.md", "a_b/x.md")).toEqual({ ok: true, path: "a:b/x.md" });
  });

  it("moving into a suffixed projected folder uses its logical path", () => {
    expect(moved("n.md", "n.md", "Foo (Nodra conflict 3fa9c21b)/n.md")).toEqual({ ok: true, path: "foo/n.md" });
  });

  it("a new folder under a projected parent is taken literally", () => {
    expect(moved("a:b/x.md", "a_b/x.md", "a_b/nueva/x.md")).toEqual({ ok: true, path: "a:b/nueva/x.md" });
  });

  it("an unchanged physical name keeps the logical name (no sanitization or suffix leaks)", () => {
    expect(moved("what?.md", "what_.md", "otra/what_.md")).toEqual({ ok: true, path: "otra/what?.md" });
    expect(moved("n.md", "n (Nodra conflict 3fa9c21b).md", "otra/n (Nodra conflict 3fa9c21b).md")).toEqual({
      ok: true,
      path: "otra/n.md",
    });
  });

  it("a renamed file drops a final projection suffix only if it is this object's label or full id", () => {
    expect(moved("n.md", "n.md", "m (Nodra conflict 3fa9c21b).md")).toEqual({ ok: true, path: "m.md" });
    expect(moved("n.md", "n.md", `m (Nodra conflict ${ID}).md`)).toEqual({ ok: true, path: "m.md" });
    expect(moved("n.md", "n.md", "m (Nodra conflict deadbeef).md")).toEqual({
      ok: true,
      path: "m (Nodra conflict deadbeef).md",
    });
    expect(moved("n.md", "n.md", "m (Nodra conflict 3fa9c21b) v2.md")).toEqual({
      ok: true,
      path: "m (Nodra conflict 3fa9c21b) v2.md",
    });
  });

  it("a case-only change of a segment changes the logical path", () => {
    expect(moved("otra/x.md", "otra/x.md", "otra/X.md")).toEqual({ ok: true, path: "otra/X.md" });
  });

  it("folder prefixes are matched on exact bytes, not comparison keys", () => {
    expect(moved("n.md", "n.md", "A_B/n.md")).toEqual({ ok: true, path: "A_B/n.md" });
  });

  it("works with a real projection table", () => {
    const A = oid(1, "aaaaaaaa");
    const B = oid(2, "bbbbbbbb");
    const p = project({ objects: [obj(A, "a:b/x.md", 1), obj(B, "a?b/y.md", 2)], untrackedFiles: [] });
    const r = physicalToLogical(
      {
        objectId: A,
        currentLogicalPath: "a:b/x.md",
        currentPhysicalPath: "a_b/x.md",
        newPhysicalPath: "a_b (Nodra conflict bbbbbbbb)/x.md",
      },
      p.folders,
    );
    expect(r).toEqual({ ok: true, path: "a?b/x.md" });
  });
});

describe("§12.2 rule 12: only a file that moved changes its logical path", () => {
  it("a file that did not move keeps its logical path even with a stale physical path", () => {
    const r = observedLogicalPath(
      {
        objectId: ID,
        currentLogicalPath: "foo/n.md",
        currentPhysicalPath: "Foo/n.md",
        newPhysicalPath: "old/n.md",
        previousObservedPhysicalPath: "old/n.md",
      },
      folders,
    );
    expect(r).toEqual({ ok: true, path: "foo/n.md" });
  });

  it("a file that moved goes through the physical → logical rule", () => {
    const r = observedLogicalPath(
      {
        objectId: ID,
        currentLogicalPath: "otra/x.md",
        currentPhysicalPath: "otra/x.md",
        newPhysicalPath: "a_b/x.md",
        previousObservedPhysicalPath: "otra/x.md",
      },
      folders,
    );
    expect(r).toEqual({ ok: true, path: "a:b/x.md" });
  });
});
