import type { DataAdapter } from "obsidian";
import type { AdapterPort, IndexedFile } from "../../src/fs.js";

// A fake of Obsidian's DataAdapter (`app.vault.adapter`) and of the vault's file index
// (`getAbstractFileByPath`). It follows obsidian.d.ts where it documents something and Node's fs (what
// the desktop adapter calls) where it does not. Every such assumption is a knob here, pinned by a test
// in fs.test.ts and listed in NOTES.md (questions 115 onwards):
//   - `renameOntoExisting`: "fail" (the default: Obsidian's desktop adapter throws "Destination file already
//     exists!", confirmed in the Phase 0 demo, NOTES question 115) or "replace";
//   - `nodeRename`: Node's fs.rename on the vault paths (desktop), which replaces an existing file;
//   - `caseInsensitive`: Windows and macOS default disks (a case variant is the same file);
//   - `list("")` lists the vault root with vault-relative paths, hidden entries included;
//   - `mkdir` is NOT recursive here (the strictest reading), `rmdir(p, false)` needs an empty folder;
//   - the index follows every change at once (the real one lags; see identityOf).

export interface FakeOptions {
  readonly caseInsensitive?: boolean;
  readonly renameOntoExisting?: "replace" | "fail";
  /** `stat().mtime` (ms): the clock at the last content write, truncated to this granularity (default 1 ms). */
  readonly mtimeGranularityMs?: number;
  /** The disk's clock (default Date.now). */
  readonly clock?: () => number;
}

type Op = "stat" | "list" | "read" | "write" | "rename" | "remove" | "mkdir" | "rmdir";

/** The fake adapter also has DataAdapter's text methods (UTF-8, lossy on bytes that are not UTF-8), for broken variants. */
export type FakeAdapter = AdapterPort & Pick<DataAdapter, "read" | "write">;

const encode = (s: string) => new TextEncoder().encode(s);
export type VaultEvent = "create" | "modify" | "delete" | "rename";

const parentOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
const err = (code: string, path: string) => Object.assign(new Error(`${code}: ${path}`), { code });

/** A file on the fake disk: its bytes, the index's file object, and the modification time of its bytes (renames keep it). */
export interface FakeFile {
  content: Uint8Array;
  readonly file: { path: string };
  mtime: number;
}

export interface FakeVault {
  readonly adapter: FakeAdapter;
  fileOf(path: string): IndexedFile | null;
  /** Actual paths → content (the names as stored on disk). */
  readonly files: Map<string, FakeFile>;
  readonly folders: Set<string>;
  /** Runs before each adapter operation; may throw (an injected adapter error). */
  fault: ((op: Op, path: string) => void) | null;
  /** Adapter operations performed, by name. */
  readonly calls: Op[];
  /** Vault events (only hints for the plugin). */
  onEvent: ((e: VaultEvent, path: string) => void) | null;
  /** Node's fs.rename on the files behind the adapter: replaces an existing destination (desktop). */
  nodeRename(from: string, to: string): Promise<void>;
  /** A user write: text is stored as its UTF-8 bytes. */
  userWrite(path: string, content: string | Uint8Array): void;
  userRename(from: string, to: string): void;
  userDelete(path: string): void;
  /** Synced-looking view: visible files → content as text (UTF-8). */
  snapshot(): Record<string, string>;
  /** The exact bytes of a file, or undefined. */
  bytes(path: string): Uint8Array | undefined;
}

export function fakeObsidianVault(o: FakeOptions = {}): FakeVault {
  const files = new Map<string, FakeFile>();
  const granularity = o.mtimeGranularityMs ?? 1;
  const now = () => Math.floor((o.clock ?? Date.now)() / granularity) * granularity;
  /** Stores bytes at an existing or new file (a write moves the modification time). */
  const put = (at: string | null, path: string, content: Uint8Array) => {
    if (at !== null) Object.assign(files.get(at)!, { content, mtime: now() });
    else files.set(path, { content, file: { path }, mtime: now() });
  };
  const folders = new Set<string>();
  const key = (p: string) => (o.caseInsensitive ? p.toLowerCase() : p);
  const findFile = (p: string) => [...files.keys()].find((k) => key(k) === key(p)) ?? null;
  const findFolder = (p: string) => (p === "" ? "" : ([...folders].find((k) => key(k) === key(p)) ?? null));
  const requireParent = (p: string) => {
    if (findFolder(parentOf(p)) === null) throw err("ENOENT", parentOf(p));
  };
  const ensureFolders = (p: string) => {
    for (let q = parentOf(p); q !== ""; q = parentOf(q)) folders.add(q);
  };
  const v: FakeVault = {
    files,
    folders,
    fault: null,
    calls: [],
    onEvent: null,
    fileOf(path) {
      const f = files.get(path);
      return f ? f.file : null;
    },
    async nodeRename(from, to) {
      hook("rename", from);
      const src = findFile(from);
      if (src === null) throw err("ENOENT", from);
      requireParent(to);
      if (findFolder(to) !== null) throw err("EISDIR", to);
      const dest = findFile(to);
      if (dest !== null && dest !== src) files.delete(dest);
      const f = files.get(src)!;
      files.delete(src);
      f.file.path = to;
      files.set(to, f);
      v.onEvent?.("rename", to);
    },
    userWrite(path, text) {
      const content = typeof text === "string" ? encode(text) : text.slice();
      ensureFolders(path);
      const at = findFile(path);
      put(at, path, content);
      v.onEvent?.(at !== null ? "modify" : "create", path);
    },
    userRename(from, to) {
      const f = files.get(from)!;
      files.delete(from);
      ensureFolders(to);
      f.file.path = to;
      files.set(to, f);
      v.onEvent?.("rename", to);
    },
    userDelete(path) {
      files.delete(path);
      v.onEvent?.("delete", path);
    },
    snapshot() {
      return Object.fromEntries([...files].filter(([p]) => !p.split("/").some((s) => s.startsWith("."))).map(([p, f]) => [p, new TextDecoder().decode(f.content)]).sort(([a], [b]) => (a! < b! ? -1 : 1)));
    },
    bytes(path) {
      return files.get(path)?.content.slice();
    },
    adapter: null as unknown as FakeAdapter,
  };
  const hook = (op: Op, path: string) => {
    v.calls.push(op);
    v.fault?.(op, path);
  };
  const store = (path: string, data: Uint8Array) => {
    requireParent(path);
    if (findFolder(path) !== null) throw err("EISDIR", path);
    const at = findFile(path);
    put(at, path, data);
  };
  const adapter: FakeAdapter = {
    async stat(path) {
      hook("stat", path);
      const f = findFile(path);
      if (f !== null) return { type: "file", size: files.get(f)!.content.byteLength, ctime: 0, mtime: files.get(f)!.mtime };
      return findFolder(path) !== null ? { type: "folder", size: 0, ctime: 0, mtime: 0 } : null;
    },
    async list(path) {
      hook("list", path);
      const folder = path === "/" ? "" : path;
      if (findFolder(folder) === null) throw err("ENOENT", path);
      const under = (p: string) => key(parentOf(p)) === key(folder);
      return { files: [...files.keys()].filter(under), folders: [...folders].filter(under) };
    },
    async read(path) {
      hook("read", path);
      const f = findFile(path);
      if (f === null) throw err("ENOENT", path);
      return new TextDecoder().decode(files.get(f)!.content);
    },
    async readBinary(path) {
      hook("read", path);
      const f = findFile(path);
      if (f === null) throw err("ENOENT", path);
      return files.get(f)!.content.slice().buffer;
    },
    async write(path, data) {
      hook("write", path);
      store(path, encode(data));
    },
    async writeBinary(path, data) {
      hook("write", path);
      store(path, new Uint8Array(data.slice(0)));
    },
    async rename(from, to) {
      hook("rename", from);
      const src = findFile(from);
      if (src === null) throw err("ENOENT", from);
      requireParent(to);
      if (findFolder(to) !== null) throw err("EISDIR", to);
      const dest = findFile(to);
      if (dest !== null && dest !== src) {
        if (o.renameOntoExisting !== "replace") throw new Error("Destination file already exists!");
        files.delete(dest);
      }
      const f = files.get(src)!;
      files.delete(src);
      f.file.path = to;
      files.set(to, f);
    },
    async remove(path) {
      hook("remove", path);
      const f = findFile(path);
      if (f === null) throw err("ENOENT", path);
      files.delete(f);
    },
    async mkdir(path) {
      hook("mkdir", path);
      requireParent(path);
      if (findFile(path) !== null || findFolder(path) !== null) throw err("EEXIST", path);
      folders.add(path);
    },
    async rmdir(path, recursive) {
      hook("rmdir", path);
      const f = findFolder(path);
      if (f === null || f === "") throw err("ENOENT", path);
      const inside = [...files.keys(), ...folders].some((p) => key(p).startsWith(`${key(f)}/`));
      if (inside && !recursive) throw err("ENOTEMPTY", path);
      folders.delete(f);
    },
  };
  (v as { adapter: FakeAdapter }).adapter = adapter;
  return v;
}
