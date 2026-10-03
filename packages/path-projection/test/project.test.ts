import { describe, expect, it } from "vitest";
import { MAX_PORTABLE_PHYSICAL_PATH_BYTES, utf8Length } from "../src/paths.js";
import { type ProjectionObject, project } from "../src/project.js";
import { obj, oid } from "./helpers.js";

const A = oid(1, "aaaaaaaa");
const B = oid(2, "bbbbbbbb");
const C = oid(3, "cccccccc");

const paths = (objects: ProjectionObject[], untrackedFiles: string[] = []) => {
  const p = project({ objects, untrackedFiles });
  return Object.fromEntries([...p.files].map(([id, f]) => [id, f.physicalPath]));
};

describe("§16.3 projection (§44.1 path cases, Annex B.1 Proyección)", () => {
  it("exact collision: the object confirmed first wins", () => {
    expect(paths([obj(B, "n.md", 2), obj(A, "n.md", 1)])).toEqual({
      [A]: "n.md",
      [B]: "n (Nodra conflict bbbbbbbb).md",
    });
  });

  it("priority is created_sequence, not object_id: a late-syncing file never displaces the established one", () => {
    expect(paths([obj(A, "n.md", 9), obj(B, "n.md", 3)])).toEqual({
      [B]: "n.md",
      [A]: "n (Nodra conflict aaaaaaaa).md",
    });
  });

  it("unconfirmed local creates go behind every confirmed object", () => {
    expect(paths([obj(A, "n.md", null), obj(B, "n.md", 100)])).toEqual({
      [B]: "n.md",
      [A]: "n (Nodra conflict aaaaaaaa).md",
    });
  });

  it("case-only collision", () => {
    expect(paths([obj(A, "Notes.md", 1), obj(B, "notes.md", 2)])[B]).toBe("notes (Nodra conflict bbbbbbbb).md");
  });

  it("Unicode-equivalent collision (NFC vs NFD)", () => {
    expect(paths([obj(A, "café.md", 1), obj(B, "café.md", 2)])[B]).toBe(
      "café (Nodra conflict bbbbbbbb).md",
    );
  });

  it("hierarchical collision: file foo vs foo/bar.md → the folder wins", () => {
    expect(paths([obj(A, "foo", 1), obj(B, "foo/bar.md", 2)])).toEqual({
      [A]: "foo (Nodra conflict aaaaaaaa)",
      [B]: "foo/bar.md",
    });
  });

  it("hierarchical collision by case only: file Foo vs foo/bar.md → the folder wins", () => {
    expect(paths([obj(A, "Foo", 1), obj(B, "foo/bar.md", 2)])).toEqual({
      [A]: "Foo (Nodra conflict aaaaaaaa)",
      [B]: "foo/bar.md",
    });
  });

  it("three objects created in the same minute with the same path → three distinct physical names", () => {
    expect(paths([obj(C, "daily.md", 7), obj(A, "daily.md", 5), obj(B, "daily.md", 6)])).toEqual({
      [A]: "daily.md",
      [B]: "daily (Nodra conflict bbbbbbbb).md",
      [C]: "daily (Nodra conflict cccccccc).md",
    });
  });

  it("two objects sharing a label: the second escalates to the full id", () => {
    const X = oid(4, "12345678");
    const Y = oid(5, "12345678");
    expect(paths([obj(A, "n.md", 1), obj(X, "n.md", 2), obj(Y, "n.md", 3)])[Y]).toBe(`n (Nodra conflict ${Y}).md`);
  });

  it("projected name occupied by an existing file → escalates to the full id", () => {
    expect(paths([obj(A, "n.md", 1)], ["n.md", "N (Nodra conflict aaaaaaaa).md"])[A]).toBe(
      `n (Nodra conflict ${A}).md`,
    );
  });

  it("untracked local files count as occupied", () => {
    expect(paths([obj(A, "n.md", 1)], ["N.md"])[A]).toBe("n (Nodra conflict aaaaaaaa).md");
  });

  it("an untracked file inside a folder blocks a file with the folder's name", () => {
    expect(paths([obj(A, "foo", 1)], ["foo/x.md"])[A]).toBe("foo (Nodra conflict aaaaaaaa)");
  });

  it("folders Foo/ and foo/ → one physical folder, spelled by the highest-priority object", () => {
    const p = project({ objects: [obj(B, "foo/b.md", 2), obj(A, "Foo/a.md", 1)], untrackedFiles: [] });
    expect(p.files.get(A)?.physicalPath).toBe("Foo/a.md");
    expect(p.files.get(B)?.physicalPath).toBe("Foo/b.md");
    expect([...p.folders]).toEqual([["Foo", "Foo"]]);
  });

  it("subfolders inherit the physical spelling of their parent", () => {
    expect(paths([obj(A, "Foo/Sub/a.md", 1), obj(B, "foo/sub/b.md", 2), obj(C, "FOO/new/c.md", 3)])).toEqual({
      [A]: "Foo/Sub/a.md",
      [B]: "Foo/Sub/b.md",
      [C]: "Foo/new/c.md",
    });
  });

  it("non-portable names get the same sanitization everywhere", () => {
    expect(paths([obj(A, "what?.md", 1), obj(B, "dir./notes.", 2), obj(C, "CON.md", 3)])).toEqual({
      [A]: "what_.md",
      [B]: "dir._/notes._",
      [C]: "_CON.md",
    });
  });

  it("folders that collide after sanitization get a suffix, escalating to the full id if occupied", () => {
    expect(paths([obj(A, "a:b/x.md", 1), obj(B, "a?b/y.md", 2)])).toEqual({
      [A]: "a_b/x.md",
      [B]: "a_b (Nodra conflict bbbbbbbb)/y.md",
    });
    expect(paths([obj(A, "a:b/x.md", 1), obj(B, "a?b/y.md", 2)], ["a_b (Nodra conflict bbbbbbbb)"])[B]).toBe(
      `a_b (Nodra conflict ${B})/y.md`,
    );
  });

  it("the folder suffix label comes from the highest-priority object inside it", () => {
    expect(paths([obj(C, "foo/z.md", 3), obj(B, "foo/y.md", 2)], ["foo"])).toEqual({
      [B]: "foo (Nodra conflict bbbbbbbb)/y.md",
      [C]: "foo (Nodra conflict bbbbbbbb)/z.md",
    });
  });

  it("segments stay ≤ 255 UTF-8 bytes with multibyte names", () => {
    const long = "ñ".repeat(200);
    const p = paths([obj(A, `${long}/${long}.md`, 1), obj(B, `${long}/${long}.md`, 2)]);
    for (const path of Object.values(p)) {
      for (const seg of path.split("/")) expect(utf8Length(seg)).toBeLessThanOrEqual(255);
    }
    expect(p[A]).not.toBe(p[B]);
  });

  it("a physical path over MAX_PORTABLE_PHYSICAL_PATH_BYTES is NOT_MATERIALIZED but keeps its reservation", () => {
    const deep = Array.from({ length: 12 }, (_, i) => `${"d".repeat(90)}${i}`).join("/");
    const p = project({ objects: [obj(A, `${deep}/n.md`, 1), obj(B, `${deep}/n.md`, 2)], untrackedFiles: [] });
    const a = p.files.get(A)!;
    expect(utf8Length(a.physicalPath)).toBeGreaterThan(MAX_PORTABLE_PHYSICAL_PATH_BYTES);
    expect(a.notMaterialized).toBe("LOCAL_PATH_TOO_LONG");
    expect(p.files.get(B)!.physicalPath.endsWith("n (Nodra conflict bbbbbbbb).md")).toBe(true);
  });

  it("invalid logical paths are rejected, not projected", () => {
    const p = project({ objects: [obj(A, "../x.md", 1)], untrackedFiles: [] });
    expect(p.files.size).toBe(0);
    expect(p.rejected.get(A)).toBe("DOT_DOT_SEGMENT");
  });

  it("projection is identical for any arrival order", () => {
    const objects = [obj(A, "Foo/n.md", 1), obj(B, "foo/N.md", 2), obj(C, "foo", 3)];
    const first = project({ objects, untrackedFiles: [] });
    const again = project({ objects: [...objects].reverse(), untrackedFiles: [] });
    expect([...again.files].sort()).toEqual([...first.files].sort());
    expect([...again.folders].sort()).toEqual([...first.folders].sort());
  });
});
