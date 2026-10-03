import { describe, expect, it } from "vitest";
import { deleteEntry, readIfExists, removeVacatedFolders, renameEntry, replayOpenEntry, runEntry, writeEntry } from "../src/executor.js";
import type { VaultState } from "../src/state.js";
import { Crash } from "./support/memfs.js";
import { rig, rev } from "./support/shell.js";
import { utf8 } from "./support/bytes.js";

// The disk executor: one journaled physical operation (§15, §13.4, §16.7) through the FileSystem port.

const present = (logicalPath: string, physicalPath: string, content: string) => ({ kind: "PRESENT" as const, logicalPath, physicalPath, hash: `h:${content}` });
const withObject = (id: string, path: string, content: string) => (s: VaultState): VaultState => ({
  ...s,
  observations: new Map(s.observations).set(id, present(path, path, content)),
  facts: { ...s.facts, synced: new Map(s.facts.synced).set(id, rev("r1", path, content)) },
});

describe("WRITE (§15 atomic write, §13.4 conservative apply)", () => {
  it("writes through a temporary, replaces, and closes with S := new_synced and the observation", async () => {
    const r = await rig();
    const e = await writeEntry(r.shell, { objectId: "o1", dest: "d/n.md", expectedPrevFp: "ABSENT", content: utf8("remote"), newSynced: rev("r2", "d/n.md", "remote"), logicalPath: "d/n.md" });
    expect(await runEntry(r.shell, e)).toBe("COMPLETE");
    expect(r.disk.files.get("d/n.md")?.content).toBe("remote");
    expect([...r.disk.files.keys()]).toEqual(["d/n.md"]);
    const s = await r.persisted();
    expect(s.journal).toBeNull();
    expect(s.facts.synced.get("o1")?.revisionId).toBe("r2");
    expect(s.observations.get("o1")).toEqual(present("d/n.md", "d/n.md", "remote"));
    expect(r.shell.identities.get("o1")).toBe(r.disk.fs.identityOf("d/n.md"));
  });

  it("the entry is persisted before the disk is touched, and tmp_created in its own transaction", async () => {
    const r = await rig();
    const seen: Array<{ op: string; journal: boolean; tmpCreated: boolean }> = [];
    const e = await writeEntry(r.shell, { objectId: "o1", dest: "n.md", expectedPrevFp: "ABSENT", content: utf8("x"), newSynced: rev("r2", "n.md", "x"), logicalPath: "n.md" });
    r.disk.beforeOp = (op) => {
      if (op === "write" || op === "replace") seen.push({ op, journal: r.shell.state.journal !== null, tmpCreated: r.shell.state.journal?.tmpCreated ?? false });
    };
    await runEntry(r.shell, e);
    expect(seen).toEqual([
      { op: "write", journal: true, tmpCreated: false },
      { op: "replace", journal: true, tmpCreated: true },
    ]);
  });

  it("§13.4 step 5: the user edited the destination after the plan → no replace; the temporary (provably ours) is deleted", async () => {
    const r = await rig(withObject("o1", "n.md", "old"));
    r.disk.userWrite("n.md", "old");
    const e = await writeEntry(r.shell, { objectId: "o1", dest: "n.md", expectedPrevFp: "h:old", content: utf8("remote"), newSynced: rev("r2", "n.md", "remote"), logicalPath: "n.md" });
    r.disk.beforeOp = (op) => {
      if (op === "replace") throw new Error("must not replace");
      if (op === "stat" && r.shell.state.journal?.tmpCreated) r.disk.userWrite("n.md", "user edit");
    };
    expect(await runEntry(r.shell, e)).toBe("CANCEL");
    expect(r.disk.files.get("n.md")?.content).toBe("user edit");
    expect([...r.disk.files.keys()]).toEqual(["n.md"]);
    expect((await r.persisted()).journal).toBeNull();
  });

  it("bug (Q65): rewriting an object's own file in place is not blocked by another file whose name differs only by case", async () => {
    // Both names coexist, so the disk is case-sensitive and they are two files: the replace targets the
    // exact path, verified by its hash. (On a case-insensitive disk they could not coexist.)
    const r = await rig(withObject("o1", "a.md", "old"));
    r.disk.userWrite("a.md", "old");
    r.disk.userWrite("A.md", "someone else");
    const e = await writeEntry(r.shell, { objectId: "o1", dest: "a.md", expectedPrevFp: "h:old", content: utf8("new"), newSynced: rev("r2", "a.md", "new"), logicalPath: "a.md" });
    expect(await runEntry(r.shell, e)).toBe("COMPLETE");
    expect(r.disk.files.get("a.md")?.content).toBe("new");
    expect(r.disk.files.get("A.md")?.content).toBe("someone else");
  });

  it("Q65 keeps Q41: a materialization (nothing expected at the destination) is still blocked by a case variant", async () => {
    const r = await rig();
    r.disk.userWrite("A.md", "someone else");
    const e = await writeEntry(r.shell, { objectId: "o1", dest: "a.md", expectedPrevFp: "ABSENT", content: utf8("new"), newSynced: rev("r2", "a.md", "new"), logicalPath: "a.md" });
    expect(await runEntry(r.shell, e)).toBe("CANCEL");
    expect([...r.disk.files.keys()]).toEqual(["A.md"]);
  });

  it("bug (Q41 b): a folder that appeared at the destination cancels the replace", async () => {
    const r = await rig();
    const e = await writeEntry(r.shell, { objectId: "o1", dest: "n.md", expectedPrevFp: "ABSENT", content: utf8("remote"), newSynced: rev("r2", "n.md", "remote"), logicalPath: "n.md" });
    r.disk.beforeOp = (op) => {
      if (op === "stat" && r.shell.state.journal?.tmpCreated && !r.disk.folders.has("n.md")) r.disk.userWrite("n.md/inside.md", "user");
    };
    expect(await runEntry(r.shell, e)).toBe("CANCEL");
    expect(r.disk.files.get("n.md/inside.md")?.content).toBe("user");
    expect(r.disk.replaced).toEqual([]);
  });

  it("bug (Q41 c): a file that appeared at an ancestor path cancels the operation", async () => {
    const r = await rig(withObject("o1", "a.md", "A"));
    r.disk.userWrite("a.md", "A");
    const e = await renameEntry(r.shell, { objectId: "o1", from: "a.md", to: "x/n.md" });
    r.disk.beforeOp = (op) => {
      if (op === "stat" && !r.disk.files.has("x")) r.disk.userWrite("x", "a file named like the folder");
    };
    expect(await runEntry(r.shell, e)).toBe("CANCEL");
    expect(r.disk.files.get("a.md")?.content).toBe("A");
    expect(r.disk.files.get("x")?.content).toBe("a file named like the folder");
  });
});

describe("RENAME and DELETE (§16.7 rule 4)", () => {
  it("renames when the source still holds the observed content and the destination is free", async () => {
    const r = await rig(withObject("o1", "a.md", "A"));
    r.disk.userWrite("a.md", "A");
    const e = await renameEntry(r.shell, { objectId: "o1", from: "a.md", to: "sub/b.md" });
    expect(await runEntry(r.shell, e)).toBe("COMPLETE");
    expect(r.disk.files.get("sub/b.md")?.content).toBe("A");
    const s = await r.persisted();
    expect(s.observations.get("o1")).toEqual(present("a.md", "sub/b.md", "A"));
  });

  it("bug (e2e livelock): a rename to a case or normalization variant of its own path is not blocked by itself", async () => {
    const nfd = `cafe${String.fromCodePoint(0x301)}.md`;
    const nfc = `caf${String.fromCodePoint(0xe9)}.md`;
    const r = await rig(withObject("o1", nfd, "A"));
    r.disk.userWrite(nfd, "A");
    expect(await runEntry(r.shell, await renameEntry(r.shell, { objectId: "o1", from: nfd, to: nfc }))).toBe("COMPLETE");
    expect([...r.disk.files.keys()]).toEqual([nfc]);
  });

  it("does not rename when the source changed or the destination is taken", async () => {
    const r = await rig(withObject("o1", "a.md", "A"));
    r.disk.userWrite("a.md", "A");
    const e = await renameEntry(r.shell, { objectId: "o1", from: "a.md", to: "b.md" });
    r.disk.userWrite("b.md", "user");
    expect(await runEntry(r.shell, e)).toBe("CANCEL");
    expect(r.disk.files.get("b.md")?.content).toBe("user");
    expect(r.disk.files.get("a.md")?.content).toBe("A");
  });

  it("deletes only the exact expected bytes", async () => {
    const r = await rig(withObject("o1", "a.md", "A"));
    r.disk.userWrite("a.md", "edited");
    const e = deleteEntry({ objectId: "o1", dest: "a.md", expectedPrevFp: "h:A", newSynced: { ...rev("r2", "a.md", ""), deleted: true, localCompareHash: null }, marksNotMaterialized: false });
    expect(await runEntry(r.shell, e)).toBe("CANCEL");
    expect(r.disk.files.get("a.md")?.content).toBe("edited");
  });
});

describe("crash and replay (§15 table) with the database closed and reopened", () => {
  it("a crash after the replace completes on replay: S = new_synced", async () => {
    const r = await rig();
    const e = await writeEntry(r.shell, { objectId: "o1", dest: "n.md", expectedPrevFp: "ABSENT", content: utf8("remote"), newSynced: rev("r2", "n.md", "remote"), logicalPath: "n.md" });
    r.disk.afterOp = (op) => {
      if (op === "replace") r.disk.crash("after replace");
    };
    await expect(runEntry(r.shell, e)).rejects.toThrow(Crash);
    r.disk.afterOp = null;
    await r.restart();
    expect(r.shell.state.journal?.objectId).toBe("o1");
    expect(await replayOpenEntry(r.shell)).toBe("COMPLETE");
    const s = await r.persisted();
    expect(s.journal).toBeNull();
    expect(s.facts.synced.get("o1")?.revisionId).toBe("r2");
  });

  it("a partial temporary written after tmp_created is provably ours: deleted on cancel", async () => {
    const r = await rig();
    r.disk.userWrite("n.md", "user");
    const e = await writeEntry(r.shell, { objectId: "o1", dest: "n.md", expectedPrevFp: "h:user", content: utf8("remote content"), newSynced: rev("r2", "n.md", "remote content"), logicalPath: "n.md" });
    // tmp_created is recorded right after the write; crash at the re-check, then the user edits.
    r.disk.beforeOp = (op) => {
      if (op === "stat" && r.shell.state.journal?.tmpCreated) r.disk.crash("before re-check");
    };
    await expect(runEntry(r.shell, e)).rejects.toThrow(Crash);
    r.disk.beforeOp = null;
    const tmp = [...r.disk.files.keys()].find((p) => p.startsWith("nodra-tmp-"))!;
    r.disk.files.get(tmp)!.content = "remote";
    await r.restart();
    expect(await replayOpenEntry(r.shell)).toBe("CANCEL");
    expect([...r.disk.files.keys()]).toEqual(["n.md"]);
    expect(r.disk.files.get("n.md")?.content).toBe("user");
  });

  it("a partial write before tmp_created is not provably ours: kept as a recovery note", async () => {
    const r = await rig();
    const e = await writeEntry(r.shell, { objectId: "o1", dest: "n.md", expectedPrevFp: "ABSENT", content: utf8("remote content"), newSynced: rev("r2", "n.md", "remote content"), logicalPath: "n.md" });
    r.disk.partialWrite = 3;
    await expect(runEntry(r.shell, e)).rejects.toThrow(Crash);
    await r.restart();
    expect(await replayOpenEntry(r.shell)).toBe("CANCEL");
    const notes = [...r.disk.files.keys()].filter((p) => p.startsWith("nodra-recuperado-"));
    expect(notes).toHaveLength(1);
    expect(r.disk.files.get(notes[0]!)?.content).toBe("rem");
    const s = await r.persisted();
    expect([...s.observations.values()]).toContainEqual(expect.objectContaining({ kind: "PRESENT", physicalPath: notes[0] }));
  });
});

describe("bug (e2e seed 4): a crash while cancelling must not turn our own temporary into a recovery note", () => {
  it("the temporary is disposed of before the entry is cleared, so a replay finishes the job", async () => {
    const r = await rig(withObject("o1", "n.md", "old"));
    r.disk.userWrite("n.md", "old");
    const e = await writeEntry(r.shell, { objectId: "o1", dest: "n.md", expectedPrevFp: "h:old", content: utf8("remote"), newSynced: rev("r2", "n.md", "remote"), logicalPath: "n.md" });
    r.disk.beforeOp = (op) => {
      if (op === "stat" && r.shell.state.journal?.tmpCreated) r.disk.userWrite("n.md", "user edit");
      if (op === "remove") r.disk.crash("while deleting our temporary");
    };
    await expect(runEntry(r.shell, e)).rejects.toThrow(Crash);
    r.disk.beforeOp = null;
    await r.restart();
    await replayOpenEntry(r.shell);
    expect([...r.disk.files.keys()]).toEqual(["n.md"]);
    expect(r.disk.files.get("n.md")?.content).toBe("user edit");
    expect((await r.persisted()).journal).toBeNull();
  });
});

describe("bug (e2e): the user acting in the window after the re-check never crashes the executor", () => {
  it("the source vanishes right before the rename → cancelled, the entry is not left open", async () => {
    const r = await rig(withObject("o1", "a.md", "A"));
    r.disk.userWrite("a.md", "A");
    const e = await renameEntry(r.shell, { objectId: "o1", from: "a.md", to: "b.md" });
    r.disk.beforeOp = (op) => {
      if (op === "rename") r.disk.files.delete("a.md");
    };
    expect(await runEntry(r.shell, e)).toBe("CANCEL");
    expect((await r.persisted()).journal).toBeNull();
  });

  it("the file to delete vanishes right before it is parked → cancelled", async () => {
    const r = await rig(withObject("o1", "a.md", "A"));
    r.disk.userWrite("a.md", "A");
    r.disk.beforeOp = (op, path) => {
      if (op === "rename" && path === "a.md") r.disk.files.delete("a.md");
    };
    expect(await runEntry(r.shell, deleteEntry({ objectId: "o1", dest: "a.md", expectedPrevFp: "h:A", newSynced: null, marksNotMaterialized: false }))).toBe("CANCEL");
  });

  it("our temporary vanishes right before the replace → cancelled, the destination untouched", async () => {
    const r = await rig();
    r.disk.userWrite("n.md", "user");
    const e = await writeEntry(r.shell, { objectId: "o1", dest: "n.md", expectedPrevFp: "h:user", content: utf8("remote"), newSynced: null, logicalPath: "n.md" });
    r.disk.beforeOp = (op, path) => {
      if (op === "replace") r.disk.files.delete(path);
    };
    expect(await runEntry(r.shell, e)).toBe("CANCEL");
    expect(r.disk.files.get("n.md")?.content).toBe("user");
  });
});

describe("bug (Q60): a remove never destroys bytes written after the final re-read (§44.5)", () => {
  it("the user writes the file right before the remove → the user bytes survive", async () => {
    const r = await rig(withObject("o1", "a.md", "A"));
    r.disk.userWrite("a.md", "A");
    r.disk.beforeOp = (op, path) => {
      if (op === "remove" && path === "a.md") r.disk.userWrite("a.md", "user late");
      if (op === "rename" && path === "a.md") r.disk.userWrite("a.md", "user late");
    };
    const e = deleteEntry({ objectId: "o1", dest: "a.md", expectedPrevFp: "h:A", newSynced: null, marksNotMaterialized: false });
    expect(await runEntry(r.shell, e)).toBe("CANCEL");
    expect([...r.disk.files.values()].map((f) => f.content)).toEqual(["user late"]);
    expect(r.disk.files.get("a.md")?.content).toBe("user late");
    expect((await r.persisted()).journal).toBeNull();
  });
});

describe("park → verify → delete (§44.5) across crashes", () => {
  const del = () => deleteEntry({ objectId: "o1", dest: "a.md", expectedPrevFp: "h:A", newSynced: null, marksNotMaterialized: false });

  it("a crash right after parking: the replay verifies the parked bytes and deletes them", async () => {
    const r = await rig(withObject("o1", "a.md", "A"));
    r.disk.userWrite("a.md", "A");
    r.disk.afterOp = (op) => {
      if (op === "rename") r.disk.crash("after parking");
    };
    await expect(runEntry(r.shell, del())).rejects.toThrow(Crash);
    r.disk.afterOp = null;
    await r.restart();
    expect(await replayOpenEntry(r.shell)).toBe("COMPLETE");
    expect([...r.disk.files.keys()]).toEqual([]);
  });

  it("a crash after parking, then the user edits the parked file: restored to its path, never deleted", async () => {
    const r = await rig(withObject("o1", "a.md", "A"));
    r.disk.userWrite("a.md", "A");
    r.disk.afterOp = (op) => {
      if (op === "rename") r.disk.crash("after parking");
    };
    await expect(runEntry(r.shell, del())).rejects.toThrow(Crash);
    r.disk.afterOp = null;
    const parked = [...r.disk.files.keys()].find((p) => p.startsWith("nodra-tmp-"))!;
    r.disk.files.get(parked)!.content = "user edit";
    await r.restart();
    expect(await replayOpenEntry(r.shell)).toBe("CANCEL");
    expect(r.disk.files.get("a.md")?.content).toBe("user edit");
    expect([...r.disk.files.keys()]).toEqual(["a.md"]);
  });

  it("the parked bytes differ and the path was taken meanwhile: kept as a recovery note", async () => {
    const r = await rig(withObject("o1", "a.md", "A"));
    r.disk.userWrite("a.md", "A");
    r.disk.afterOp = (op, path) => {
      if (op === "rename" && path === "a.md") {
        const parked = [...r.disk.files.keys()].find((p) => p.startsWith("nodra-tmp-"))!;
        r.disk.files.get(parked)!.content = "user edit";
        r.disk.userWrite("a.md", "new file");
      }
    };
    expect(await runEntry(r.shell, del())).toBe("CANCEL");
    expect(r.disk.files.get("a.md")?.content).toBe("new file");
    const notes = [...r.disk.files.keys()].filter((p) => p.startsWith("nodra-recuperado-"));
    expect(notes.map((p) => r.disk.files.get(p)!.content)).toEqual(["user edit"]);
  });
});

describe("temporaries and folders", () => {
  it("§15 step 2: a temporary name that exists anywhere in the vault is never reused", async () => {
    const r = await rig();
    r.disk.userWrite("other/nodra-tmp-00000001", "user");
    const e = await writeEntry(r.shell, { objectId: "o1", dest: "n.md", expectedPrevFp: "ABSENT", content: utf8("x"), newSynced: null, logicalPath: "n.md" });
    expect(e.tmpName).not.toBe("nodra-tmp-00000001");
  });

  it("bug (e2e livelock, Q33): an EMPTY folder whose name collides with the target (case variant) is removed; a non-empty one blocks", async () => {
    const r = await rig(withObject("o1", "a.md", "A"));
    r.disk.userWrite("a.md", "A");
    r.disk.folders.add("Foo");
    r.disk.folders.add("Foo/empty-too");
    expect(await runEntry(r.shell, await renameEntry(r.shell, { objectId: "o1", from: "a.md", to: "foo" }))).toBe("COMPLETE");
    expect(r.disk.files.get("foo")?.content).toBe("A");
    expect([...r.disk.folders]).toEqual([]);
    r.disk.userWrite("Bar/keep.md", "user");
    expect(await runEntry(r.shell, await renameEntry(r.shell, { objectId: "o1", from: "foo", to: "bar" }))).toBe("CANCEL");
    expect(r.disk.files.get("Bar/keep.md")?.content).toBe("user");
  });

  it("Q33: a folder this instance created and a projection move emptied is removed; a user's empty folder is not", async () => {
    const r = await rig(withObject("o1", "a.md", "A"));
    r.disk.userWrite("a.md", "A");
    r.disk.folders.add("user-empty");
    expect(await runEntry(r.shell, await renameEntry(r.shell, { objectId: "o1", from: "a.md", to: "made/b.md" }))).toBe("COMPLETE");
    expect(r.disk.folders.has("made")).toBe(true);
    expect(await runEntry(r.shell, await renameEntry(r.shell, { objectId: "o1", from: "made/b.md", to: "c.md" }))).toBe("COMPLETE");
    expect(r.disk.folders.has("made")).toBe(false);
    expect(r.disk.folders.has("user-empty")).toBe(true);
    await removeVacatedFolders(r.shell, "user-empty/x.md");
    expect(r.disk.folders.has("user-empty")).toBe(true);
  });
});

describe("readIfExists", () => {
  it("bug (e2e, question 146): a file created between the failed read and the stat that explains it is read, not an error", async () => {
    const r = await rig();
    r.disk.beforeOp = (op, path) => {
      if (op === "stat" && path === "n.md" && !r.disk.files.has(path)) r.disk.userWrite(path, "created now");
    };
    expect(await readIfExists(r.disk.fs, "n.md")).toEqual(utf8("created now"));
  });

  it("a read that keeps failing on a file is an error (an adapter fault, not a race)", async () => {
    const r = await rig();
    r.disk.userWrite("n.md", "x");
    const fs = { ...r.disk.fs, read: async () => Promise.reject(new Error("EACCES")) };
    await expect(readIfExists(fs, "n.md")).rejects.toThrow("EACCES");
  });
});
