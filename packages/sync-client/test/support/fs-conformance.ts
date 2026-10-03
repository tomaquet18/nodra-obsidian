import type { FileSystem } from "../../src/ports.js";
import { expect } from "vitest";
import { utf8 } from "./bytes.js";

// The FileSystem port's semantics as the executor relies on them (ports.ts): one suite that every
// implementation runs (memfs, the Obsidian adapter, the web's IndexedDB note store).

export interface FsCase {
  readonly name: string;
  run(fs: FileSystem): Promise<void>;
}

/** Bytes that no text round trip preserves: invalid UTF-8, a lone continuation byte, NUL, a BOM, CR LF. */
const AWKWARD = Uint8Array.from([0xef, 0xbb, 0xbf, 0x00, 0xff, 0xfe, 0x80, 0xc3, 0x28, 0x0d, 0x0a, 0xed, 0xa0, 0x80, 0xf8, 0x00]);

/** Deterministic pseudo-random bytes (a PNG-like attachment), without a random source. */
function noise(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);
  let x = seed >>> 0 || 1;
  for (let i = 0; i < length; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out[i] = x & 0xff;
  }
  return out;
}

/** Byte for byte, with a readable failure (no 1 MiB diff). */
async function expectExact(fs: FileSystem, path: string, bytes: Uint8Array): Promise<void> {
  const read = await fs.read(path);
  expect(read).toBeInstanceOf(Uint8Array);
  expect(read.length).toBe(bytes.length);
  const first = read.findIndex((b, i) => b !== bytes[i]);
  expect(first).toBe(-1);
  expect((await fs.stat(path))?.size).toBe(bytes.length);
}

/** NOTES question 146: a `counter` marker moves at every content write and is never given back. */
export const CHANGE_MARKER_CASE = "change marker: a counter moves at every write, same size too, and never comes back after a remove";

export const FS_CONFORMANCE_CASES: readonly FsCase[] = [
  { name: "binary: bytes round-trip exactly (invalid UTF-8, NUL, BOM, CR LF), the size is the byte length", run: async (fs: FileSystem) => {
    await fs.write("img.png", AWKWARD);
    await expectExact(fs, "img.png", AWKWARD);
    await fs.write("bad.md", AWKWARD); // a Markdown name with bytes that are not UTF-8
    await expectExact(fs, "bad.md", AWKWARD);
  } },

  { name: "binary: an empty file and a large one (1 MiB) round-trip exactly", run: async (fs: FileSystem) => {
    await fs.write("empty.bin", new Uint8Array());
    await expectExact(fs, "empty.bin", new Uint8Array());
    const big = noise(1 << 20, 7);
    await fs.write("big.pdf", big);
    await expectExact(fs, "big.pdf", big);
  } },

  { name: "binary: a rename or a replace carries the bytes unchanged", run: async (fs: FileSystem) => {
    const a = noise(4096, 1);
    await fs.write("a.png", a);
    await fs.rename("a.png", "b.png");
    await expectExact(fs, "b.png", a);
    await fs.write("nodra-tmp-0000abcd", AWKWARD);
    await fs.replace("nodra-tmp-0000abcd", "b.png");
    await expectExact(fs, "b.png", AWKWARD);
  } },

  { name: "stat: null when missing, then file or folder", run: async (fs: FileSystem) => {
    expect(await fs.stat("a.md")).toBeNull();
    await fs.write("a.md", utf8("abc"));
    expect(await fs.stat("a.md")).toMatchObject({ type: "file" });
    await fs.mkdir("d");
    expect(await fs.stat("d")).toMatchObject({ type: "folder" });
  } },

  { name: CHANGE_MARKER_CASE, run: async (fs: FileSystem) => {
    const marker = fs.changeMarker;
    if (marker === undefined) return; // no marker: the observation cache is off
    await fs.write("a.md", utf8("one"));
    const first = (await fs.stat("a.md"))?.mtime;
    expect(typeof first).toBe("number");
    if (marker.kind !== "counter") return; // a clock mtime: precision is the adapter's (stat-cache.ts)
    await fs.write("a.md", utf8("two")); // same size
    const second = (await fs.stat("a.md"))?.mtime;
    expect(second).not.toBe(first);
    await fs.remove("a.md");
    await fs.write("a.md", utf8("six")); // same path, same size, after a remove
    expect([first, second]).not.toContain((await fs.stat("a.md"))?.mtime);
  } },

  { name: "write creates and overwrites; read returns the last content", run: async (fs: FileSystem) => {
    await fs.write("a.md", utf8("one"));
    await fs.write("a.md", utf8("two"));
    expect(await fs.read("a.md")).toEqual(utf8("two"));
  } },

  { name: "write into a missing folder, or onto a folder, rejects", run: async (fs: FileSystem) => {
    await expect(fs.write("missing/a.md", utf8("x"))).rejects.toThrow();
    await fs.mkdir("d");
    await expect(fs.write("d", utf8("x"))).rejects.toThrow();
    expect(await fs.stat("missing/a.md")).toBeNull();
  } },

  { name: "read of a missing file rejects", run: async (fs: FileSystem) => {
    await expect(fs.read("nope.md")).rejects.toThrow();
  } },

  { name: "mkdir creates missing ancestors and is a no-op on an existing folder; under a file it rejects", run: async (fs: FileSystem) => {
    await fs.mkdir("a/b/c");
    await fs.mkdir("a/b");
    expect(await fs.stat("a/b/c")).toMatchObject({ type: "folder" });
    await fs.write("f.md", utf8("x"));
    await expect(fs.mkdir("f.md/sub")).rejects.toThrow();
  } },

  { name: "list: direct children as vault-relative paths; the root is the empty string", run: async (fs: FileSystem) => {
    await fs.mkdir("d/e");
    await fs.write("a.md", utf8("x"));
    await fs.write("d/b.md", utf8("y"));
    expect(await fs.list("")).toEqual({ files: ["a.md"], folders: ["d"] });
    expect(await fs.list("d")).toEqual({ files: ["d/b.md"], folders: ["d/e"] });
  } },

  { name: "rename to a free path moves the content and the identity", run: async (fs: FileSystem) => {
    await fs.mkdir("d");
    await fs.write("a.md", utf8("x"));
    const id = fs.identityOf("a.md");
    expect(id).not.toBeNull();
    await fs.rename("a.md", "d/b.md");
    expect(await fs.stat("a.md")).toBeNull();
    expect(await fs.read("d/b.md")).toEqual(utf8("x"));
    expect(fs.identityOf("d/b.md")).toBe(id);
    expect(fs.identityOf("a.md")).toBeNull();
  } },

  { name: "rename onto an existing file rejects and changes nothing", run: async (fs: FileSystem) => {
    await fs.write("a.md", utf8("a"));
    await fs.write("b.md", utf8("b"));
    await expect(fs.rename("a.md", "b.md")).rejects.toThrow();
    expect([await fs.read("a.md"), await fs.read("b.md")]).toEqual([utf8("a"), utf8("b")]);
  } },

  { name: "rename of a missing file, or into a missing folder, rejects", run: async (fs: FileSystem) => {
    await expect(fs.rename("nope.md", "b.md")).rejects.toThrow();
    await fs.write("a.md", utf8("a"));
    await expect(fs.rename("a.md", "missing/a.md")).rejects.toThrow();
    expect(await fs.read("a.md")).toEqual(utf8("a"));
  } },

  { name: "replace moves the temporary over an existing destination (§15 step 4), and onto a free one", run: async (fs: FileSystem) => {
    await fs.write("a.md", utf8("old"));
    await fs.write("nodra-tmp-0000000a", utf8("new"));
    await fs.replace("nodra-tmp-0000000a", "a.md");
    expect(await fs.read("a.md")).toEqual(utf8("new"));
    expect(await fs.stat("nodra-tmp-0000000a")).toBeNull();
    await fs.write("nodra-tmp-0000000b", utf8("fresh"));
    await fs.replace("nodra-tmp-0000000b", "b.md");
    expect(await fs.read("b.md")).toEqual(utf8("fresh"));
  } },

  { name: "replace onto a folder rejects and keeps the temporary", run: async (fs: FileSystem) => {
    await fs.mkdir("d");
    await fs.write("nodra-tmp-0000000a", utf8("x"));
    await expect(fs.replace("nodra-tmp-0000000a", "d")).rejects.toThrow();
    expect(await fs.read("nodra-tmp-0000000a")).toEqual(utf8("x"));
  } },

  { name: "remove deletes a file; a missing one rejects", run: async (fs: FileSystem) => {
    await fs.write("a.md", utf8("x"));
    await fs.remove("a.md");
    expect(await fs.stat("a.md")).toBeNull();
    await expect(fs.remove("a.md")).rejects.toThrow();
  } },

  { name: "rmdir removes an empty folder only, never recursively", run: async (fs: FileSystem) => {
    await fs.mkdir("d/e");
    await fs.write("d/e/a.md", utf8("x"));
    await expect(fs.rmdir("d/e")).rejects.toThrow();
    expect(await fs.read("d/e/a.md")).toEqual(utf8("x"));
    await fs.remove("d/e/a.md");
    await fs.rmdir("d/e");
    expect(await fs.stat("d/e")).toBeNull();
    await expect(fs.rmdir("d/e")).rejects.toThrow();
  } },

  { name: "identity: null for a missing path; a new file gets a new one", run: async (fs: FileSystem) => {
    expect(fs.identityOf("a.md")).toBeNull();
    await fs.write("a.md", utf8("x"));
    const first = fs.identityOf("a.md");
    await fs.remove("a.md");
    await fs.write("a.md", utf8("x"));
    expect(fs.identityOf("a.md")).not.toBe(first);
  } },
];
