import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { merge3 } from "@nodra/sync-core";
import type { Scenario } from "@nodra/sync-core/test-support/scenario";
import { decodeText, encodeText, mergeContent } from "../src/content.js";
import { textObjects } from "../src/runner.js";
import { QUIET, convergenceProblems, lostEdits, runToRest, startRun, unknownContents } from "./sim/e2e.js";
import { fromModel, toModel, utf8 } from "./support/bytes.js";

// Attachments (§2.1): content is bytes end to end; only Markdown that is valid UTF-8 on all three sides
// is merged (§17 "ambas ramas son texto", NOTES question 140). Everything else concurrent → conflict copy.

const BASE = "a\nb\nc\nd\ne";
const NOT_UTF8 = Uint8Array.from([...utf8("a\n"), 0xff, 0xfe, ...utf8("\nc\nd\ne")]); // BASE with line 2 not UTF-8

/** A merge that decodes leniently (U+FFFD): the shape mergeContent must never take. */
function lossyMerge(base: Uint8Array, local: Uint8Array, remote: Uint8Array) {
  const d = new TextDecoder();
  const m = merge3(d.decode(base), d.decode(local), d.decode(remote));
  return m.kind === "conflict" ? m : { kind: "resolved" as const, content: encodeText(m.text) };
}

describe("mergeContent (§17 over bytes)", () => {
  it("merges UTF-8 text as merge3 does", () => {
    expect(mergeContent(utf8(BASE), utf8("a\nX\nc\nd\ne"), utf8("a\nb\nc\nY\ne"))).toEqual({ kind: "resolved", content: utf8("a\nX\nc\nY\ne") });
    expect(mergeContent(utf8(BASE), utf8("a\nX\nc\nd\ne"), utf8("a\nY\nc\nd\ne"))).toEqual({ kind: "conflict" });
  });

  it("keeps a BOM, NUL and CR LF byte for byte", () => {
    const bom = (s: string) => Uint8Array.from([0xef, 0xbb, 0xbf, ...utf8(s)]);
    expect(mergeContent(bom("a\r\nb\r\nc\0"), bom("A\r\nb\r\nc\0"), bom("a\r\nb\r\nC\0"))).toEqual({ kind: "resolved", content: bom("A\r\nb\r\nC\0") });
  });

  it.each([
    ["local", utf8(BASE), NOT_UTF8, utf8("a\nb\nc\nd\nE")],
    ["remote", utf8(BASE), utf8("A\nb\nc\nd\ne"), NOT_UTF8],
    ["base", NOT_UTF8, utf8("A\nb\nc\nd\ne"), utf8("a\nb\nc\nd\nE")],
  ])("bytes that are not UTF-8 on the %s side → conflict, never a merge", (_side, base, local, remote) => {
    expect(mergeContent(base, local, remote)).toEqual({ kind: "conflict" });
  });

  it("broken variant: a lenient decoder merges the local case above and writes U+FFFD over the user's bytes", () => {
    const r = lossyMerge(utf8(BASE), NOT_UTF8, utf8("a\nb\nc\nd\nE"));
    expect(r.kind).toBe("resolved");
    if (r.kind === "resolved") expect(r.content.includes(0xff)).toBe(false); // 0xff became U+FFFD
  });

  it("property: a resolved merge only ever comes from three UTF-8 texts, and is merge3 of them", () => {
    const side = fc.oneof(fc.uint8Array({ maxLength: 12 }), fc.array(fc.constantFrom("a", "b", "\n", "é", "\r", "\0"), { maxLength: 8 }).map((cs) => utf8(cs.join(""))));
    fc.assert(
      fc.property(side, side, side, (b, l, r) => {
        const m = mergeContent(b, l, r);
        const texts = [b, l, r].map(decodeText);
        if (texts.some((t) => t === null)) return m.kind === "conflict";
        const expected = merge3(texts[0]!, texts[1]!, texts[2]!);
        return expected.kind === "conflict" ? m.kind === "conflict" : m.kind === "resolved" && encodeText(expected.text).join() === m.content.join();
      }),
      { numRuns: 3000 },
    );
  });

  it("property: decodeText is exact (encoding its text gives the same bytes) or refuses", () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 64 }), (b) => {
      const t = decodeText(b);
      return t === null || encodeText(t).join() === b.join();
    }), { numRuns: 3000 });
  });
});

describe("textObjects (§17 'ambas ramas son texto')", () => {
  const rev = (path: string, deleted = false) => ({ revisionId: "r", sequence: 1, path, localCompareHash: null, deleted, createdSequence: 1 });
  const present = (path: string) => ({ kind: "PRESENT" as const, path, physicalPath: path, recordedPhysicalPath: path, localCompareHash: "h" });
  it("text only when every known path is Markdown", () => {
    const local = new Map([["md", present("a.md")], ["png", present("a.png")], ["renamed", present("a.md")], ["upper", present("B.MD")]]);
    const remote = new Map([["md", rev("a.md")], ["renamed", rev("a.png")], ["deleted", rev("x.png", true)]]);
    const synced = new Map([["md", rev("a.md")], ["pdf", rev("doc.pdf")]]);
    expect([...textObjects(local, remote, synced)].sort()).toEqual(["md", "upper"]);
  });
});

// ---------------------------------------------------------------------------
// End to end: the real runner, Dexie, the in-memory disk and the server model.

const scenario = (path: string, base: string, remote: string): Scenario => ({
  objects: [{ path, content: base, second: { path, content: remote, deleted: false }, replica: "rev1", mod: "none", editContent: "", moveTarget: "moved.md" }],
  localCreates: [],
  untracked: [],
  swap: false,
  merge: false,
});

/** The object's base on disk, a remote edit on the server, and a concurrent local edit written by the user. */
async function concurrent(path: string, base: Uint8Array, remote: Uint8Array, local: Uint8Array) {
  const run = await startRun(scenario(path, toModel(base), toModel(remote)), QUIET, 3);
  const file = run.disk.files.get(path)!;
  file.content = toModel(local);
  run.log.userContents.set(String(file.id), file.content);
  run.log.authored.add(file.content);
  const ticks = await runToRest(run, 400);
  run.close();
  const heads = [...run.server.heads.values()].filter((h) => !h.deleted);
  return {
    run,
    ticks,
    heads: heads.map((h) => fromModel(h.content)),
    disk: [...run.disk.files.values()].map((f) => fromModel(f.content)),
    checks: { convergence: convergenceProblems(run), lost: lostEdits(run), unknown: unknownContents(run), violations: run.log.violations },
  };
}
const CLEAN = { convergence: [], lost: [], unknown: [], violations: [] };
const noise = (n: number, seed: number) => Uint8Array.from({ length: n }, (_, i) => (i * 97 + seed * 31 + (i >> 3)) & 0xff);

describe("concurrent edits end to end", () => {
  it("a binary edited on both sides → conflict copy with both versions byte for byte, never a merge", async () => {
    const [base, remote, local] = [noise(300, 1), noise(310, 2), noise(290, 3)];
    const r = await concurrent("img.png", base, remote, local);
    expect(r.ticks).not.toBeNull();
    expect(r.checks).toEqual(CLEAN);
    expect(r.run.log.events.get("merge") ?? 0).toBe(0);
    expect(r.run.log.events.get("conflictCopy")).toBe(1);
    expect(r.heads).toHaveLength(2);
    expect(r.heads).toEqual(expect.arrayContaining([remote, local]));
    expect(r.disk).toEqual(expect.arrayContaining([remote, local]));
  }, 60_000);

  it("a Markdown file whose local bytes are not UTF-8 → conflict copy, not a lossy merge", async () => {
    const r = await concurrent("bad.md", utf8(BASE), utf8("a\nb\nc\nd\nE"), NOT_UTF8);
    expect(r.checks).toEqual(CLEAN);
    expect(r.run.log.events.get("merge") ?? 0).toBe(0);
    expect(r.heads).toEqual(expect.arrayContaining([utf8("a\nb\nc\nd\nE"), NOT_UTF8]));
  }, 60_000);

  it("Markdown edited in different lines on both sides still merges (§17)", async () => {
    const r = await concurrent("notes.md", utf8(BASE), utf8("a\nb\nc\nY\ne"), utf8("a\nX\nc\nd\ne"));
    expect(r.checks).toEqual(CLEAN);
    expect(r.run.log.events.get("merge")).toBe(1);
    expect(r.heads).toEqual([utf8("a\nX\nc\nY\ne")]);
    expect(r.disk).toEqual([utf8("a\nX\nc\nY\ne")]);
  }, 60_000);

  it("identical binaries in several files and an empty file sync byte for byte", async () => {
    const shared = noise(64, 9);
    const s: Scenario = {
      objects: [
        { path: "a.png", content: toModel(shared), second: null, replica: "unseen", mod: "none", editContent: "", moveTarget: "moved.md" },
        { path: "d/b.png", content: toModel(shared), second: null, replica: "unseen", mod: "none", editContent: "", moveTarget: "moved.md" },
        { path: "empty.bin", content: "", second: null, replica: "unseen", mod: "none", editContent: "", moveTarget: "moved.md" },
      ],
      localCreates: [],
      untracked: [{ path: "mine.pdf", content: toModel(noise(1000, 4)) }],
      swap: false,
      merge: false,
    };
    const run = await startRun(s, QUIET, 5);
    expect(await runToRest(run, 400)).not.toBeNull();
    run.close();
    expect(convergenceProblems(run)).toEqual([]);
    expect(unknownContents(run)).toEqual([]);
    const disk = new Map([...run.disk.files].map(([p, f]) => [p, fromModel(f.content)]));
    expect(disk.get("a.png")).toEqual(shared);
    expect(disk.get("d/b.png")).toEqual(shared);
    expect(disk.get("empty.bin")).toEqual(new Uint8Array());
    expect([...run.server.heads.values()].map((h) => fromModel(h.content))).toEqual(expect.arrayContaining([noise(1000, 4)]));
  }, 60_000);
});
