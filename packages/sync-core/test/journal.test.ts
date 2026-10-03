import { describe, expect, it } from "vitest";
import {
  type JournalEntry,
  isRecoveryName,
  isTmpName,
  openEntry,
  parkedDisposition,
  recoveryName,
  replaceAllowed,
  replay,
  strayDisposition,
  tmpDisposition,
  tmpPath,
} from "../src/journal.js";
import { rev } from "./fixtures.js";
import { text, utf8 } from "./utf8.js";

const h = (s: string) => `h:${s}`;
const write = (over: Partial<JournalEntry> = {}): JournalEntry => ({
  objectId: "o",
  kind: "WRITE",
  sourcePath: null,
  destPath: "dir/n.md",
  tmpName: "nodra-tmp-0000abcd",
  expectedPrevFp: h("old"),
  finalFp: h("new content"),
  newSynced: rev("r2", 2, "n.md", h("new content")),
  recordedLogicalPath: "n.md",
  tmpCreated: true,
  content: utf8("new content"),
  marksNotMaterialized: false,
  ...over,
});

describe("§15 journal: one open entry, written before touching the disk", () => {
  it("opens an entry only when none is open", () => {
    expect(openEntry(null, write())).toEqual(write());
    expect(() => openEntry(write(), write({ objectId: "p" }))).toThrow();
  });

  it("the temporary lives in the destination folder", () => {
    expect(tmpPath(write())).toBe("dir/nodra-tmp-0000abcd");
    expect(tmpPath(write({ destPath: "n.md" }))).toBe("nodra-tmp-0000abcd");
    expect(isTmpName("dir/nodra-tmp-0000abcd")).toBe(true);
    expect(isTmpName("dir/nodra-tmp-notes.md")).toBe(false);
    expect(isRecoveryName("dir/nodra-recuperado-1f.md")).toBe(true);
  });
});

describe("§15 step 4 / §13.4: re-check the destination before replacing", () => {
  it("replaces only if the destination still holds the expected previous content (or is absent for a create)", () => {
    expect(replaceAllowed(write(), h("old"))).toBe(true);
    expect(replaceAllowed(write(), h("user edit"))).toBe(false);
    expect(replaceAllowed(write(), "ABSENT")).toBe(false);
    expect(replaceAllowed(write({ expectedPrevFp: "ABSENT" }), "ABSENT")).toBe(true);
    expect(replaceAllowed(write({ expectedPrevFp: "ABSENT" }), h("x"))).toBe(false);
  });
});

describe("§15 replay after a crash", () => {
  it("WRITE: temporary gone and destination holds final_fp → complete; anything else → cancel", () => {
    expect(replay(write(), { tmpExists: false, destFp: h("new content"), sourceExists: false })).toBe("COMPLETE");
    expect(replay(write(), { tmpExists: true, destFp: h("new content"), sourceExists: false })).toBe("CANCEL");
    expect(replay(write(), { tmpExists: false, destFp: h("old"), sourceExists: false })).toBe("CANCEL");
    expect(replay(write(), { tmpExists: false, destFp: "ABSENT", sourceExists: false })).toBe("CANCEL");
  });

  it("DELETE with a parked file still present → not complete yet (it is verified first)", () => {
    const del = write({ kind: "DELETE", finalFp: null, content: null, tmpName: "nodra-tmp-0000beef" });
    expect(replay(del, { tmpExists: true, destFp: "ABSENT", sourceExists: false })).toBe("CANCEL");
    expect(replay(del, { tmpExists: false, destFp: "ABSENT", sourceExists: false })).toBe("COMPLETE");
  });

  it("park → verify → delete (§44.5): only the exact expected bytes are deleted", () => {
    const del = write({ kind: "DELETE", finalFp: null, content: null, expectedPrevFp: h("old"), tmpName: "nodra-tmp-0000beef" });
    expect(parkedDisposition(del, h("old"))).toBe("DELETE");
    expect(parkedDisposition(del, h("user edit"))).toBe("RESTORE");
    expect(parkedDisposition(write(), h("old"))).toBe("RESTORE");
  });

  it("DELETE: destination already gone → complete; still there → cancel", () => {
    const del = write({ kind: "DELETE", finalFp: null, content: null, tmpName: null });
    expect(replay(del, { tmpExists: false, destFp: "ABSENT", sourceExists: false })).toBe("COMPLETE");
    expect(replay(del, { tmpExists: false, destFp: h("old"), sourceExists: false })).toBe("CANCEL");
  });

  it("RENAME (projection or parking): the file left the source and is at the destination → complete, even if edited since", () => {
    const ren = write({ kind: "RENAME", sourcePath: "a.md", tmpName: null, content: null, newSynced: null, finalFp: h("x") });
    expect(replay(ren, { tmpExists: false, destFp: h("x"), sourceExists: false })).toBe("COMPLETE");
    expect(replay(ren, { tmpExists: false, destFp: h("x edited"), sourceExists: false })).toBe("COMPLETE");
    expect(replay(ren, { tmpExists: false, destFp: "ABSENT", sourceExists: true })).toBe("CANCEL");
  });
});

describe("§15 cancellation: the temporary is deleted only if it is provably ours", () => {
  const disp = (entry: JournalEntry, content: string) => tmpDisposition(entry, utf8(content), (b) => h(text(b)));

  it("exact final content → delete", () => {
    expect(disp(write(), "new content")).toBe("DELETE");
  });
  it("zero bytes → delete, always (never an empty recovery note)", () => {
    expect(disp(write({ tmpCreated: false }), "")).toBe("DELETE");
  });
  it("own prefix with tmp_created → delete", () => {
    expect(disp(write(), "new con")).toBe("DELETE");
  });
  it("prefix WITHOUT tmp_created → kept as a recovery note (the prefix proof needs tmp_created)", () => {
    expect(disp(write({ tmpCreated: false }), "new con")).toBe("RECOVER");
  });
  it("a temporary the user edited → kept as a recovery note", () => {
    expect(disp(write(), "new content + user line")).toBe("RECOVER");
    expect(disp(write(), "user text")).toBe("RECOVER");
  });
});

describe("§15 cancellation over bytes (attachments)", () => {
  const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0xfe, 0xc3, 0x28]);
  const entry = write({ content: png, finalFp: "h:png" });
  const hash = (c: Uint8Array) => (c.join() === png.join() ? "h:png" : `h:${c.join()}`);
  it("a byte prefix of the content (cut anywhere, even inside a UTF-8 sequence) is ours with tmp_created", () => {
    for (let n = 1; n <= png.length; n++) expect(tmpDisposition(entry, png.slice(0, n), hash)).toBe("DELETE");
  });
  it("bytes that differ anywhere, or extend the content, are kept as a recovery note", () => {
    expect(tmpDisposition(entry, Uint8Array.from([0x89, 0x50, 0x4e, 0x48]), hash)).toBe("RECOVER");
    expect(tmpDisposition(entry, Uint8Array.from([...png, 0]), hash)).toBe("RECOVER");
    expect(tmpDisposition(write({ content: png, tmpCreated: false }), png.slice(0, 3), hash)).toBe("RECOVER");
  });
});

describe("§15: stray nodra-tmp-* files (not bound, not the open entry's temporary)", () => {
  it("non-empty → imported as a recovery note; empty → deleted (no bytes lost, no empty note)", () => {
    expect(strayDisposition(utf8("some bytes"))).toBe("RECOVER");
    expect(strayDisposition(utf8(""))).toBe("DELETE");
  });

  it("recovery name: nodra-recuperado-<hex>.md in the same folder, another hex when occupied", () => {
    expect(recoveryName("dir/nodra-tmp-0000abcd", ["1f", "2e"], () => false)).toBe("dir/nodra-recuperado-1f.md");
    expect(recoveryName("dir/nodra-tmp-0000abcd", ["1f", "2e"], (p) => p === "dir/nodra-recuperado-1f.md")).toBe("dir/nodra-recuperado-2e.md");
    expect(recoveryName("x", ["1f"], (p) => p === "nodra-recuperado-1f.md")).toBeNull();
  });
});
