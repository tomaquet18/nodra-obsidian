import type { FileSystem } from "@nodra/sync-client";
import type { DataAdapter } from "obsidian";

// The FileSystem port (sync-client ports.ts) over Obsidian's DataAdapter (`app.vault.adapter`). The
// port's semantics are stricter than the adapter's documentation, so every precondition the executor
// relies on is checked here before the adapter call (the conformance suite in test/fs-conformance.ts
// runs the same cases against the in-memory memfs). What cannot be checked is an assumption about
// Obsidian, pinned as a test over the fake adapter and as a question in NOTES.md (115 onwards).

/** The part of DataAdapter this module uses (the real one satisfies it; tests pass a fake). */
/** Content goes through `readBinary`/`writeBinary` only: the text methods would decode and re-encode attachments (§2.1). */
export type AdapterPort = Pick<DataAdapter, "stat" | "list" | "readBinary" | "writeBinary" | "rename" | "remove" | "mkdir" | "rmdir">;

/** Obsidian's in-memory file object (`TFile`): only its identity and current path are used (§15). */
export interface IndexedFile {
  readonly path: string;
}

const parentOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
const strip = (p: string) => p.replace(/^\/+/, "");
/** Case- and normalization-insensitive name (Windows and macOS disks, NOTES question 117). */
const foldKey = (p: string) => p.normalize("NFC").toLowerCase();

/** Obsidian does not track dot paths (§15), and `.obsidian/` is not synced (§20.3). */
const isHidden = (p: string) => p.split("/").some((s) => s.startsWith("."));

/**
 * The files the plugin syncs: every file that is not hidden, Markdown and attachments alike (§2.1), the
 * executor's `nodra-tmp-*` temporaries (§15) included. The port carries bytes (NOTES questions 52 and 116).
 */
export const isSyncedFile = (p: string): boolean => !isHidden(p);

/** The exact bytes of a view, as the ArrayBuffer `writeBinary` takes. */
const bufferOf = (data: Uint8Array): ArrayBuffer => data.slice().buffer as ArrayBuffer;

/**
 * Obsidian's `stat().mtime` is the disk's modification time in ms (NOTES question 146). Its precision
 * depends on the disk: 2 s on FAT, 10 ms on exFAT, 1 s on HFS+, finer on NTFS, APFS and ext4. 2 s is the
 * coarsest a vault may sit on, so it is the granularity the observation cache assumes (stat-cache.ts).
 */
export const OBSIDIAN_MTIME_GRANULARITY_MS = 2000;

const fail = (code: string, path: string) => Object.assign(new Error(`${code}: ${path}`), { code });

/**
 * `fileOf(path)`: the vault's in-memory file at `path` (`vault.getAbstractFileByPath`), whose object
 * identity is the §15 hint that follows a user's rename. Never persisted.
 *
 * `replacingRename(tmp, dest)`: a rename that replaces an existing destination (§15 step 4). Obsidian's
 * `DataAdapter.rename` refuses one ("Destination file already exists!", NOTES question 115), so the desktop
 * plugin passes Node's `fs.rename` on the vault paths. Without it, replace falls back to the adapter and
 * rejects with both files intact.
 */
export function obsidianFileSystem(
  adapter: AdapterPort,
  fileOf: (path: string) => IndexedFile | null,
  replacingRename?: (tmp: string, dest: string) => Promise<void>,
): FileSystem {
  const identities = new WeakMap<IndexedFile, string>();
  let next = 0;
  const kind = async (p: string) => (p === "" ? "folder" : ((await adapter.stat(p))?.type ?? null));
  const requireFolder = async (p: string) => {
    if ((await kind(p)) !== "folder") throw fail("ENOENT", p);
  };
  /** Another entry in `to`'s folder with the same folded name: on a case-insensitive disk it IS `to`. */
  const occupied = async (to: string, except: string | null) => {
    const { files, folders } = await adapter.list(parentOf(to));
    return [...files, ...folders].map(strip).some((p) => foldKey(p) === foldKey(to) && p !== except);
  };
  return {
    async stat(path) {
      const s = await adapter.stat(path);
      if (s === null) return null;
      return s.type === "file" && Number.isFinite(s.mtime) ? { type: s.type, size: s.size, mtime: s.mtime } : { type: s.type, size: s.size };
    },
    read: async (path) => new Uint8Array(await adapter.readBinary(path)),
    async write(path, data) {
      await requireFolder(parentOf(path));
      if ((await kind(path)) === "folder") throw fail("EISDIR", path);
      await adapter.writeBinary(path, bufferOf(data));
    },
    async rename(from, to) {
      if ((await kind(from)) !== "file") throw fail("ENOENT", from);
      await requireFolder(parentOf(to));
      if (await occupied(to, from)) throw fail("EEXIST", to);
      await adapter.rename(from, to);
    },
    async replace(tmp, dest) {
      // NOTES question 115: DataAdapter.rename refuses an existing destination; see replacingRename.
      if ((await kind(tmp)) !== "file") throw fail("ENOENT", tmp);
      await requireFolder(parentOf(dest));
      if ((await kind(dest)) === "folder") throw fail("EISDIR", dest);
      await (replacingRename ?? adapter.rename.bind(adapter))(tmp, dest);
    },
    async remove(path) {
      if ((await kind(path)) !== "file") throw fail("ENOENT", path);
      await adapter.remove(path);
    },
    async list(folder) {
      const l = await adapter.list(folder);
      return { files: l.files.map(strip).filter(isSyncedFile).sort(), folders: l.folders.map(strip).filter((p) => !isHidden(p)).sort() };
    },
    async mkdir(path) {
      // One level at a time: no assumption about whether the adapter's mkdir is recursive.
      const levels = path.split("/").map((_, i, parts) => parts.slice(0, i + 1).join("/"));
      for (const p of levels) {
        const k = await kind(p);
        if (k === "file") throw fail("ENOTDIR", p);
        if (k === null) await adapter.mkdir(p);
      }
    },
    async rmdir(path) {
      if ((await kind(path)) !== "folder") throw fail("ENOENT", path);
      await adapter.rmdir(path, false); // never recursive: fails on anything inside, hidden files included
    },
    identityOf(path) {
      const f = fileOf(path);
      // The vault's index follows the disk asynchronously: an entry for another path is stale (NOTES question 118).
      if (f === null || f.path !== path) return null;
      let id = identities.get(f);
      if (id === undefined) identities.set(f, (id = `tfile:${++next}`));
      return id;
    },
    changeMarker: { kind: "clock", granularityMs: OBSIDIAN_MTIME_GRANULARITY_MS },
  };
}

// Adapter errors (NOTES question 55) are handled by the shared controller's policy (sync-client).
export { type FailureDecision, describeError, failurePolicy, isPersistentError } from "@nodra/sync-client";
