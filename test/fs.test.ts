import type { FileSystem } from "@nodra/sync-client";
import { FS_CONFORMANCE_CASES as CASES } from "@nodra/sync-client/test-support/fs-conformance";
import { memFs } from "@nodra/sync-client/test-support/memfs";
import { describe, expect, it } from "vitest";
import { failurePolicy, isPersistentError, isSyncedFile, obsidianFileSystem } from "../src/fs.js";
import { type FakeOptions, fakeObsidianVault } from "./support/fake-obsidian.js";

const utf8 = (s: string) => new TextEncoder().encode(s);

// The FileSystem port's semantics, as the executor relies on them (sync-client ports.ts), run against
// the in-memory memfs the sync tests use AND the Obsidian adapter over a fake DataAdapter. Then the
// Obsidian-only assumptions (NOTES questions 115–120), each pinned by its own test.

const obsidian = (o: FakeOptions = {}) => {
  const v = fakeObsidianVault(o);
  return { vault: v, fs: obsidianFileSystem(v.adapter, (p) => v.fileOf(p), v.nodeRename) };
};

const IMPLEMENTATIONS: ReadonlyArray<readonly [string, () => FileSystem]> = [
  ["memfs", () => memFs().fs],
  ["Obsidian DataAdapter (fake, case-sensitive)", () => obsidian().fs],
  ["Obsidian DataAdapter (fake, case-insensitive)", () => obsidian({ caseInsensitive: true }).fs],
];

describe.each(IMPLEMENTATIONS)("FileSystem port conformance: %s", (_, make) => {
  it.each(CASES.map((c) => [c.name, c] as const))("%s", async (_, c) => c.run(make()));
});

describe("the conformance suite catches a broken adapter", () => {
  it("a pass-through of DataAdapter (no port checks) fails cases the executor relies on", async () => {
    const failed: string[] = [];
    for (const c of CASES) {
      // An adapter whose rename replaces (Node's fs.rename): passed through, it must still fail the suite.
      const v = fakeObsidianVault({ renameOntoExisting: "replace" });
      const a = v.adapter;
      const naive: FileSystem = {
        stat: async (p) => a.stat(p),
        read: async (p) => new Uint8Array(await a.readBinary(p)),
        write: (p, d) => a.writeBinary(p, d.slice().buffer),
        rename: (f, t) => a.rename(f, t),
        replace: (f, t) => a.rename(f, t),
        remove: (p) => a.remove(p),
        list: (p) => a.list(p),
        mkdir: (p) => a.mkdir(p),
        rmdir: (p) => a.rmdir(p, false),
        identityOf: (p) => (v.fileOf(p) ? p : null),
      };
      await c.run(naive).catch(() => failed.push(c.name));
    }
    expect(failed).toEqual(
      expect.arrayContaining([
        "rename onto an existing file rejects and changes nothing",
        "mkdir creates missing ancestors and is a no-op on an existing folder; under a file it rejects",
        "rename to a free path moves the content and the identity",
      ]),
    );
  });
});

describe("the conformance suite catches an adapter that carries content as text", () => {
  it("DataAdapter.read/write (a string round trip) fails the binary cases", async () => {
    const failed: string[] = [];
    for (const c of CASES) {
      const v = fakeObsidianVault();
      const port = obsidianFileSystem(v.adapter, (p) => v.fileOf(p), v.nodeRename);
      const textual: FileSystem = {
        ...port,
        read: async (p) => new TextEncoder().encode(await v.adapter.read(p)),
        write: async (p, d) => v.adapter.write(p, new TextDecoder().decode(d)),
      };
      await c.run(textual).catch(() => failed.push(c.name));
    }
    const binary = CASES.filter((c) => c.name.startsWith("binary:")).map((c) => c.name);
    expect(binary.length).toBeGreaterThan(0);
    expect(failed).toEqual(binary); // every binary case, and only those
  });
});

describe("Obsidian adapter: what the plugin sees (Q116)", () => {
  it("hidden paths (.obsidian, .trash, dot files) are invisible; Markdown, attachments, temporaries and recovery notes are listed", async () => {
    const { vault, fs } = obsidian();
    for (const p of [".obsidian/app.json", ".trash/old.md", ".hidden.md", "img.png", "doc.pdf", "a.md", "B.MD", "nodra-tmp-0123abcd", "nodra-recuperado-00ff.md", "nodra-tmp-xyz"]) vault.userWrite(p, "x");
    expect(await fs.list("")).toEqual({ files: ["B.MD", "a.md", "doc.pdf", "img.png", "nodra-recuperado-00ff.md", "nodra-tmp-0123abcd", "nodra-tmp-xyz"], folders: [] });
    expect(isSyncedFile("notes/nodra-tmp-0123abcd")).toBe(true);
    expect(isSyncedFile(".obsidian/workspace.json")).toBe(false);
  });

  it("the `.nodra/` folder is the one dot path that syncs (the vault's published settings, §20.3); dot paths inside it do not", async () => {
    const { vault, fs } = obsidian();
    for (const p of [".nodra/vault-settings.json", ".nodra/nodra-tmp-0123abcd", ".nodra/.hidden", ".obsidian/app.json", "x/.nodra/y.md"]) vault.userWrite(p, "x");
    expect(await fs.list("")).toEqual({ files: [], folders: [".nodra", "x"] });
    expect(await fs.list(".nodra")).toEqual({ files: [".nodra/nodra-tmp-0123abcd", ".nodra/vault-settings.json"], folders: [] });
    expect(await fs.list("x")).toEqual({ files: [], folders: [] });
    expect([".nodra/vault-settings.json", ".nodra/.hidden", ".obsidian/app.json", "x/.nodra/y.md"].map(isSyncedFile)).toEqual([true, false, false, false]);
  });

  it("an attachment is read and written through readBinary/writeBinary, byte for byte", async () => {
    const { vault, fs } = obsidian();
    const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff, 0xfe, 0x80]);
    vault.userWrite("img.png", png);
    expect(await fs.read("img.png")).toEqual(png);
    await fs.write("nodra-tmp-0000000b", png.subarray(8)); // a view into a larger buffer: only its bytes are written
    expect(vault.bytes("nodra-tmp-0000000b")).toEqual(png.subarray(8));
    expect(vault.calls.filter((c) => c === "read" || c === "write")).toEqual(["read", "write"]);
  });

  it("an adapter that lists with a leading slash is read as vault-relative", async () => {
    const { vault } = obsidian();
    vault.userWrite("d/a.md", "x");
    const slashed = obsidianFileSystem({ ...vault.adapter, list: async (p) => {
      const l = await vault.adapter.list(p);
      return { files: l.files.map((f) => `/${f}`), folders: l.folders.map((f) => `/${f}`) };
    } }, (p) => vault.fileOf(p));
    expect(await slashed.list("d")).toEqual({ files: ["d/a.md"], folders: [] });
  });

  it("mkdir creates one level at a time, whether or not the adapter's mkdir is recursive", async () => {
    const { vault, fs } = obsidian();
    await fs.mkdir("a/b/c");
    expect([...vault.folders].sort()).toEqual(["a", "a/b", "a/b/c"]);
  });
});

describe("Obsidian adapter: rename onto an existing file (Q115)", () => {
  it("bug (Q115, Phase 0 demo): DataAdapter.rename refuses an existing destination, so replace uses the desktop Node rename", async () => {
    const { vault, fs } = obsidian();
    vault.userWrite("a.md", "old");
    await fs.write("nodra-tmp-0000000a", utf8("new"));
    await fs.replace("nodra-tmp-0000000a", "a.md");
    expect(vault.snapshot()).toEqual({ "a.md": "new" });
  });

  it("without a replacing rename (no desktop fs), replace rejects and nothing is lost (the controller pauses, Q55)", async () => {
    const vault = fakeObsidianVault();
    const fs = obsidianFileSystem(vault.adapter, (p) => vault.fileOf(p));
    vault.userWrite("a.md", "old");
    await fs.write("nodra-tmp-0000000a", utf8("new"));
    await expect(fs.replace("nodra-tmp-0000000a", "a.md")).rejects.toThrow();
    expect(await fs.read("a.md")).toEqual(utf8("old"));
    expect(await fs.read("nodra-tmp-0000000a")).toEqual(utf8("new"));
  });

  it("rename never relies on the adapter to refuse: a taken destination is refused before the call", async () => {
    const { vault, fs } = obsidian({ renameOntoExisting: "replace" });
    vault.userWrite("a.md", "a");
    vault.userWrite("b.md", "b");
    const before = vault.calls.filter((c) => c === "rename").length;
    await expect(fs.rename("a.md", "b.md")).rejects.toMatchObject({ code: "EEXIST" });
    expect(vault.calls.filter((c) => c === "rename").length).toBe(before);
    expect(vault.snapshot()).toEqual({ "a.md": "a", "b.md": "b" });
  });
});

describe("Obsidian adapter: case-insensitive disks (Q117)", () => {
  it("a rename onto a case variant of ANOTHER file is refused and destroys nothing", async () => {
    const { vault, fs } = obsidian({ caseInsensitive: true });
    vault.userWrite("a.md", "a");
    vault.userWrite("B.md", "b");
    await expect(fs.rename("a.md", "b.md")).rejects.toMatchObject({ code: "EEXIST" });
    expect(vault.snapshot()).toEqual({ "B.md": "b", "a.md": "a" });
  });

  it("the same refusal on a case-sensitive disk (conservative, as the executor's comparison key, Q41)", async () => {
    const { vault, fs } = obsidian();
    vault.userWrite("a.md", "a");
    vault.userWrite("B.md", "b");
    await expect(fs.rename("a.md", "b.md")).rejects.toMatchObject({ code: "EEXIST" });
  });

  it("a case-only rename of the file itself goes through", async () => {
    const { vault, fs } = obsidian({ caseInsensitive: true });
    vault.userWrite("a.md", "a");
    await fs.rename("a.md", "A.md");
    expect(vault.snapshot()).toEqual({ "A.md": "a" });
  });
});

describe("Obsidian adapter: identity is the vault index's TFile, a hint only (Q118)", () => {
  it("follows a user rename; a stale index entry (another path) gives no identity", async () => {
    const { vault } = obsidian();
    vault.userWrite("a.md", "x");
    let stale = false;
    const fs = obsidianFileSystem(vault.adapter, (p) => (stale ? { path: "elsewhere.md" } : vault.fileOf(p)));
    const id = fs.identityOf("a.md");
    vault.userRename("a.md", "b.md");
    expect(fs.identityOf("b.md")).toBe(id);
    stale = true;
    expect(fs.identityOf("b.md")).toBeNull();
  });
});

describe("adapter errors (Q55)", () => {
  const codeError = (code: string) => Object.assign(new Error(`${code}: permission denied, open 'x.md'`), { code });
  const o = { backoffMs: 100, maxFailures: 3 };

  it.each(["EACCES", "EPERM", "ENOSPC", "EROFS", "EDQUOT"])("%s is persistent: pause at once", (code) => {
    expect(failurePolicy(codeError(code), 1, o)).toMatchObject({ kind: "pause" });
  });

  it("recognized by message too (the mobile adapter's errors carry no code), and through a wrapper's `inner`", () => {
    expect(isPersistentError(new Error("Error: ENOSPC: no space left on device"))).toBe(true);
    expect(isPersistentError({ name: "DexieError", inner: { name: "QuotaExceededError" } })).toBe(true);
    expect(isPersistentError(Object.assign(new Error("UNAUTHENTICATED"), { name: "SyncBackendError", status: 401 }))).toBe(true);
  });

  it("anything else is retried with doubling backoff, then paused after maxFailures in a row", () => {
    const e = new Error("EBUSY: resource busy");
    expect(failurePolicy(e, 1, o)).toEqual({ kind: "retry", delayMs: 100 });
    expect(failurePolicy(e, 2, o)).toEqual({ kind: "retry", delayMs: 200 });
    expect(failurePolicy(e, 3, o)).toMatchObject({ kind: "pause" });
  });
});
