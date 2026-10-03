import { type Content, type ObjectId, fencedWriteAllowed } from "@nodra/sync-core";
import type { DeviceLocalCrypto, FileSystem } from "./ports.js";
import type { Observation } from "./state.js";
import { FencedOut, type MetaRow, type VaultStore } from "./store.js";

// The web replica's notes (§20.1, §20.2): there is no file system, so the FileSystem port is a table of
// the vault's own IndexedDB database. Two differences from a disk:
// - every write is FENCED like the leader's state writes (§20.2 "Fencing"): one readwrite transaction
//   over `meta` and `files` that reads leader_epoch first and aborts when it is not this leader's. That is
//   what makes the web's forced takeover safe ("En web no hay escrituras fuera de IndexedDB");
// - content is sealed with the Device Local Key (§20.1: no plaintext notes at rest). Sealing happens
//   before the transaction opens and opening after the read transaction closes (CLAUDE.md "Persistencia").
// Paths are stored as is (exact, case-sensitive): only the executor writes here, through the projection.

interface FileRow {
  readonly path: string;
  readonly parent: string;
  readonly type: "file" | "folder";
  /** UTF-8 bytes of the plaintext. */
  readonly size: number;
  readonly sealed: Uint8Array | null;
  /**
   * The `counter` change marker (NOTES question 146): the store-wide `fileSeq` value of the write that
   * stored these bytes. Moves keep it. Absent on rows written before schema version 4 (never cached).
   */
  readonly mtime?: number;
}

const parentOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
const fail = (code: string, path: string) => Object.assign(new Error(`${code}: ${path}`), { code });

const filesOf = (store: VaultStore) => store.db.table<FileRow, string>("files");
const SEQ = "seq";

/**
 * The note store as the leader holding `leaderEpoch` writes it. `leaderEpoch` null: read-only (a
 * follower's view); every write is fenced out. Identities (§15) are this instance's, in memory only.
 */
export function indexedDbFileSystem(store: VaultStore, dlc: DeviceLocalCrypto, leaderEpoch: number | null): FileSystem {
  const files = filesOf(store);
  const meta = store.db.table<MetaRow, string>("meta");
  const seq = store.db.table<{ id: string; value: number }, string>("fileSeq");
  const identities = new Map<string, string>();
  let next = 0;

  /** One fenced readwrite transaction; `body` only makes IndexedDB calls. */
  const fenced = (body: () => Promise<void>) =>
    store.db.transaction("rw", [meta, files, seq], async () => {
      const m = await meta.get("meta");
      if (leaderEpoch === null || m === undefined || !fencedWriteAllowed({ leaderEpoch: m.leaderEpoch }, leaderEpoch)) {
        throw new FencedOut(`fenced: leader_epoch is ${m?.leaderEpoch ?? "missing"}, this writer holds ${leaderEpoch ?? "none"}`);
      }
      await body();
    });
  const kind = async (p: string) => (p === "" ? "folder" : ((await files.get(p))?.type ?? null));
  const requireFolder = async (p: string) => {
    if ((await kind(p)) !== "folder") throw fail("ENOENT", p);
  };
  const move = async (from: string, to: string) => {
    const row = (await files.get(from))!;
    await files.delete(from);
    await files.put({ ...row, path: to, parent: parentOf(to) });
  };
  const moveIdentity = (from: string, to: string) => {
    const id = identities.get(from);
    identities.delete(from);
    if (id === undefined) identities.delete(to);
    else identities.set(to, id);
  };
  const readRow = (p: string) => store.db.transaction("r", files, () => files.get(p));

  return {
    async stat(path) {
      if (path === "") return { type: "folder", size: 0 };
      const row = await readRow(path);
      if (row === undefined) return null;
      return row.mtime === undefined ? { type: row.type, size: row.size } : { type: row.type, size: row.size, mtime: row.mtime };
    },
    async read(path) {
      const row = await readRow(path);
      if (row?.type !== "file" || row.sealed === null) throw fail("ENOENT", path);
      return dlc.decrypt(row.sealed);
    },
    async write(path, data) {
      const sealed = await dlc.encrypt(data);
      await fenced(async () => {
        await requireFolder(parentOf(path));
        if ((await kind(path)) === "folder") throw fail("EISDIR", path);
        const mtime = ((await seq.get(SEQ))?.value ?? 0) + 1;
        await seq.put({ id: SEQ, value: mtime });
        await files.put({ path, parent: parentOf(path), type: "file", size: data.byteLength, sealed, mtime });
      });
      if (!identities.has(path)) identities.set(path, `idb:${++next}`);
    },
    async rename(from, to) {
      await fenced(async () => {
        if ((await kind(from)) !== "file") throw fail("ENOENT", from);
        await requireFolder(parentOf(to));
        if ((await kind(to)) !== null) throw fail("EEXIST", to);
        await move(from, to);
      });
      moveIdentity(from, to);
    },
    async replace(tmp, dest) {
      await fenced(async () => {
        if ((await kind(tmp)) !== "file") throw fail("ENOENT", tmp);
        await requireFolder(parentOf(dest));
        if ((await kind(dest)) === "folder") throw fail("EISDIR", dest);
        await move(tmp, dest);
      });
      moveIdentity(tmp, dest);
    },
    async remove(path) {
      await fenced(async () => {
        if ((await kind(path)) !== "file") throw fail("ENOENT", path);
        await files.delete(path);
      });
      identities.delete(path);
    },
    async list(folder) {
      const rows = await store.db.transaction("r", files, () => files.where("parent").equals(folder).toArray());
      const of = (t: FileRow["type"]) => rows.filter((r) => r.type === t && r.path !== "").map((r) => r.path).sort();
      const listed = of("file");
      // A file this instance sees for the first time (it was there before a reload) gets its identity
      // here, as Obsidian gives every file a TFile at load: without one, rule 10 could never attribute
      // it after the startup scan, and it would be imported as a new object on every tick.
      for (const path of listed) if (!identities.has(path)) identities.set(path, `idb:${++next}`);
      return { files: listed, folders: of("folder") };
    },
    async mkdir(path) {
      const levels = path.split("/").map((_, i, parts) => parts.slice(0, i + 1).join("/"));
      await fenced(async () => {
        for (const p of levels) {
          const k = await kind(p);
          if (k === "file") throw fail("ENOTDIR", p);
          if (k === null) await files.put({ path: p, parent: parentOf(p), type: "folder", size: 0, sealed: null });
        }
      });
    },
    async rmdir(path) {
      await fenced(async () => {
        if ((await kind(path)) !== "folder") throw fail("ENOENT", path);
        if ((await files.where("parent").equals(path).count()) > 0) throw fail("ENOTEMPTY", path);
        await files.delete(path);
      });
    },
    identityOf: (path) => identities.get(path) ?? null,
    changeMarker: { kind: "counter" },
  };
}

/** A note as the editor shows it. */
export interface NoteView {
  readonly objectId: ObjectId;
  readonly path: string;
  /** The note's exact bytes; the editor shows it as text only if it is Markdown and valid UTF-8. */
  readonly content: Content;
  /** What the editor edited on (§20.2 `view_version`, `view_fp`), for the intent it will send. */
  readonly version: number;
  readonly observation: Observation;
}

/**
 * Every note present in the leader's last observation with its content, read in ONE read transaction
 * (observations, local versions and the note store together), then opened outside it.
 */
export async function readNotes(store: VaultStore, dlc: DeviceLocalCrypto): Promise<NoteView[]> {
  const tables = [store.db.table("observations"), store.db.table("intentObjects"), filesOf(store)] as const;
  const [obs, versions, rows] = await store.db.transaction("r", [...tables], async () => [
    (await tables[0].toArray()) as Array<Observation & { objectId: ObjectId }>,
    (await tables[1].toArray()) as Array<{ objectId: ObjectId; localVersion: number | null }>,
    await tables[2].toArray(),
  ] as const);
  const byPath = new Map(rows.map((r) => [r.path, r]));
  const version = new Map(versions.map((v) => [v.objectId, v.localVersion ?? 0]));
  const notes: NoteView[] = [];
  for (const o of obs) {
    if (o.kind !== "PRESENT") continue;
    const row = byPath.get(o.physicalPath);
    if (row?.sealed == null) continue; // observed, then removed before this read: the next state message refreshes
    const { objectId, ...observation } = o;
    notes.push({ objectId, path: o.logicalPath, content: await dlc.decrypt(row.sealed), version: version.get(objectId) ?? 0, observation: observation as Observation });
  }
  return notes.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}
