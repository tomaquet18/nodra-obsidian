import { describe, expect, it } from "vitest";
import { type DiskFile, type RecordedFile, attributeFiles } from "../src/observe.js";

const rec = (objectId: string, physicalPath: string | null, localCompareHash: string | null = `h-${objectId}`): RecordedFile => ({ objectId, physicalPath, localCompareHash });
const file = (path: string, localCompareHash: string | null, identity: string): DiskFile => ({ path, localCompareHash, identity });
const ids = (entries: Array<[string, string]>) => new Map(entries);
const summary = (a: ReturnType<typeof attributeFiles>) => ({
  byObject: Object.fromEntries([...a.byObject].sort()),
  paired: a.paired.map((p) => `${p.objectId}@${p.path}`),
  untracked: a.untracked,
  absent: a.absent,
});

describe("§12.2 rule 10: within an instance the identity keeps the object_id", () => {
  it("a renamed file is attributed by identity at its new path", () => {
    const a = attributeFiles([rec("A", "old.md")], [file("new.md", "h-A", "f1")], ids([["A", "f1"]]));
    expect(summary(a)).toEqual({ byObject: { A: "new.md" }, paired: [], untracked: [], absent: [] });
  });

  it("§44.1 delayed rename event after a new file is created at the old path → attributed by identity; the new file keeps its content (untracked)", () => {
    const a = attributeFiles([rec("A", "p.md")], [file("q.md", "h-A", "f1"), file("p.md", "h-new", "f2")], ids([["A", "f1"]]));
    expect(summary(a)).toEqual({ byObject: { A: "q.md" }, paired: [], untracked: ["p.md"], absent: [] });
  });

  it("§44.1 delayed delete after another file was moved to that path → the right object is absent", () => {
    // A was deleted; B was moved onto A's old path.
    const a = attributeFiles([rec("A", "p.md"), rec("B", "b.md")], [file("p.md", "h-B", "fB")], ids([["A", "fA"], ["B", "fB"]]));
    expect(summary(a)).toEqual({ byObject: { B: "p.md" }, paired: [], untracked: [], absent: ["A"] });
  });

  it("§44.1 a note pasted with the same bytes while the instance is alive is decided by identity: a new file, not the object", () => {
    const a = attributeFiles([rec("A", "p.md")], [file("p.md", "h-A", "f1"), file("copy.md", "h-A", "f2")], ids([["A", "f1"]]));
    expect(summary(a)).toEqual({ byObject: { A: "p.md" }, paired: [], untracked: ["copy.md"], absent: [] });
  });

  it("an object whose known identity left the disk is absent and never paired, even with an identical file", () => {
    const a = attributeFiles([rec("A", "p.md")], [file("elsewhere.md", "h-A", "f2")], ids([["A", "f1"]]));
    expect(summary(a)).toEqual({ byObject: {}, paired: [], untracked: ["elsewhere.md"], absent: ["A"] });
  });
});

describe("bug (identity simulation (u)): the path scan and pairing happen only at startup", () => {
  it("within a running instance, an object without identity never takes a new file at its recorded path", () => {
    const a = attributeFiles([rec("A", "p.md")], [file("p.md", "h-new", "f9")], new Map(), { startup: false });
    expect(summary(a)).toEqual({ byObject: {}, paired: [], untracked: ["p.md"], absent: ["A"] });
  });

  it("within a running instance, no rule-11 pairing either", () => {
    const a = attributeFiles([rec("A", "p.md")], [file("moved.md", "h-A", "f9")], new Map(), { startup: false });
    expect(summary(a).paired).toEqual([]);
  });
});

describe("§12.2 rule 11 / §15: after a restart there are no identities", () => {
  it("the startup scan attributes files at their recorded paths", () => {
    const a = attributeFiles([rec("A", "p.md")], [file("p.md", "h-edited", "f1")], new Map());
    expect(summary(a)).toEqual({ byObject: { A: "p.md" }, paired: [], untracked: [], absent: [] });
  });

  it("an absent object and a new file with the exact hash of its last observation, unique both ways → rename with the same object_id", () => {
    const a = attributeFiles([rec("A", "p.md")], [file("moved.md", "h-A", "f1")], new Map());
    expect(summary(a)).toEqual({ byObject: { A: "moved.md" }, paired: ["A@moved.md"], untracked: [], absent: [] });
  });

  it("ambiguous: two new files with that hash → delete + create, no pairing", () => {
    const a = attributeFiles([rec("A", "p.md")], [file("x.md", "h-A", "f1"), file("y.md", "h-A", "f2")], new Map());
    expect(summary(a)).toEqual({ byObject: {}, paired: [], untracked: ["x.md", "y.md"], absent: ["A"] });
  });

  it("ambiguous: two absent objects with that hash → no pairing", () => {
    const a = attributeFiles([rec("A", "p.md", "h"), rec("B", "q.md", "h")], [file("x.md", "h", "f1")], new Map());
    expect(summary(a)).toEqual({ byObject: {}, paired: [], untracked: ["x.md"], absent: ["A", "B"] });
  });

  it("a hash that differs from the last observation never pairs", () => {
    const a = attributeFiles([rec("A", "p.md")], [file("x.md", "h-other", "f1")], new Map());
    expect(summary(a).paired).toEqual([]);
  });

  it("an unknown hash (LocalCompareKey lost) never pairs", () => {
    expect(summary(attributeFiles([rec("A", "p.md", null)], [file("x.md", null, "f1")], new Map())).paired).toEqual([]);
    expect(summary(attributeFiles([rec("A", "p.md")], [file("x.md", null, "f1")], new Map())).paired).toEqual([]);
  });

  it("the scan never leaves two objects with one file: a path recorded by two objects goes to neither by path", () => {
    const a = attributeFiles([rec("A", "p.md"), rec("B", "p.md")], [file("p.md", "h-A", "f1")], new Map());
    expect(Object.keys(summary(a).byObject).length).toBeLessThanOrEqual(1);
  });

  it("a record whose last observation was an absence claims no path: another record keeps its file", () => {
    const a = attributeFiles([rec("A", null, null), rec("B", "p.md")], [file("p.md", "h-B", "f1")], new Map());
    expect(summary(a)).toEqual({ byObject: { B: "p.md" }, paired: [], untracked: [], absent: ["A"] });
  });

  it("files already attributed by identity are not taken again by path or pairing", () => {
    const a = attributeFiles([rec("A", "p.md"), rec("B", "q.md", "h-A")], [file("p.md", "h-A", "f1")], ids([["A", "f1"]]));
    expect(summary(a)).toEqual({ byObject: { A: "p.md" }, paired: [], untracked: [], absent: ["B"] });
  });
});
