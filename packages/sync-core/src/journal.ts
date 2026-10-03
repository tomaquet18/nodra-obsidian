import { bytesStartWith } from "./bytes.js";
import type { Content, LocalCompareHash, LogicalPath, ObjectId, PhysicalPath, SyncedEntry } from "./types.js";

// Apply journal and temporary files (§15). The journal exists only to make physical writes safe
// against crashes; it is not the sync state. Every physical write, rename or delete opens an entry
// BEFORE touching the disk, and at most one entry is open. After a crash the entry is completed or
// cancelled from what is observed, and the planner decides the rest (§12.2). Pure decisions only:
// the executor performs the file operations and re-reads the disk before each one.

export type JournalKind = "WRITE" | "RENAME" | "DELETE";

/** A journal entry (§15 fields, plus what this model needs to record the observation on close). */
export interface JournalEntry {
  readonly objectId: ObjectId;
  readonly kind: JournalKind;
  /** RENAME only: the file being moved (not in the §15 field list; a rename needs its source). */
  readonly sourcePath: PhysicalPath | null;
  readonly destPath: PhysicalPath;
  /**
   * WRITE: the temporary, `nodra-tmp-<8 hex>` in the destination folder. DELETE: the name the file is
   * parked under (renamed atomically) before it is verified and deleted, so a user edit after the final
   * re-read is never destroyed (§44.5). Null when unused.
   */
  readonly tmpName: string | null;
  /** local_compare_hash expected at the destination before the replace, or "ABSENT". */
  readonly expectedPrevFp: LocalCompareHash | "ABSENT";
  /** local_compare_hash of what ends at the destination (the moved file for RENAME); null for DELETE. */
  readonly finalFp: LocalCompareHash | null;
  /** The S recorded when the entry closes (the applied R, or the R a merge descends from, rule 4). */
  readonly newSynced: SyncedEntry | null;
  /** Logical path of the object's observation after the close (§12.2 table); null keeps it. */
  readonly recordedLogicalPath: LogicalPath | null;
  /** The entry's temporary was created on disk (recorded in its own transaction, §15 step 3). */
  readonly tmpCreated: boolean;
  /** WRITE only: the content written (encrypted with the Device Local Key at rest, rule 16). */
  readonly content: Content | null;
  /** DELETE of a NOT_MATERIALIZED object's file (§16.2): the close marks it NOT_MATERIALIZED. */
  readonly marksNotMaterialized: boolean;
}

const TMP = /(^|\/)nodra-tmp-[0-9a-f]{8}$/;
const RECOVERY = /(^|\/)nodra-recuperado-[0-9a-f]+\.md$/;

export const isTmpName = (path: PhysicalPath): boolean => TMP.test(path);
export const isRecoveryName = (path: PhysicalPath): boolean => RECOVERY.test(path);

const dirOf = (path: PhysicalPath) => path.slice(0, path.lastIndexOf("/") + 1);

export function tmpPath(entry: JournalEntry): PhysicalPath {
  if (entry.tmpName === null) throw new Error("entry has no temporary");
  return dirOf(entry.destPath) + entry.tmpName;
}

/** At most one open entry (§15). */
export function openEntry(open: JournalEntry | null, entry: JournalEntry): JournalEntry {
  if (open !== null) throw new Error(`journal entry already open for ${open.objectId}`);
  return entry;
}

/** §15 step 4 / §13.4 step 4: the destination must still be exactly what the entry expects. */
export function replaceAllowed(entry: JournalEntry, destFp: LocalCompareHash | "ABSENT"): boolean {
  return destFp === entry.expectedPrevFp;
}

export interface ReplayObservation {
  readonly tmpExists: boolean;
  readonly destFp: LocalCompareHash | "ABSENT";
  /** RENAME only: whether the source file is still there. */
  readonly sourceExists: boolean;
}

/**
 * Replay after a crash (§15 table). WRITE: temporary gone and destination with exactly final_fp →
 * COMPLETE (S = new_synced); otherwise CANCEL. DELETE: destination gone → COMPLETE. RENAME: the file
 * left the source and is at the destination → COMPLETE even if the user edited it since (the entry
 * proves the move was ours; cancelling would read it as a delete plus an untracked file).
 */
export function replay(entry: JournalEntry, obs: ReplayObservation): "COMPLETE" | "CANCEL" {
  switch (entry.kind) {
    case "WRITE":
      return !obs.tmpExists && obs.destFp === entry.finalFp ? "COMPLETE" : "CANCEL";
    case "DELETE":
      // A parked file still present is verified first (parkedDisposition); only then can it complete.
      return !obs.tmpExists && obs.destFp === "ABSENT" ? "COMPLETE" : "CANCEL";
    case "RENAME":
      return !obs.sourceExists && obs.destFp !== "ABSENT" ? "COMPLETE" : "CANCEL";
  }
}

/**
 * On cancel, the entry's temporary is deleted only if it is provably ours: exactly final_fp, zero
 * bytes, or an own prefix of the content AND tmp_created was recorded. Otherwise it is kept and
 * imported as a recovery note. The executor re-reads the file right before deleting.
 */
export function tmpDisposition(
  entry: JournalEntry,
  tmpContent: Content,
  hash: (content: Content) => LocalCompareHash,
): "DELETE" | "RECOVER" {
  if (tmpContent.length === 0) return "DELETE";
  if (hash(tmpContent) === entry.finalFp) return "DELETE";
  if (entry.tmpCreated && entry.content !== null && bytesStartWith(entry.content, tmpContent)) return "DELETE";
  return "RECOVER";
}

/**
 * DELETE by park → verify → delete: the parked file is deleted only if it holds exactly the content the
 * entry expected (bytes provably ours to delete, §44.5); otherwise it goes back to its path, or becomes
 * a recovery note if the path was taken.
 */
export function parkedDisposition(entry: JournalEntry, parkedFp: LocalCompareHash): "DELETE" | "RESTORE" {
  return entry.kind === "DELETE" && parkedFp === entry.expectedPrevFp ? "DELETE" : "RESTORE";
}

/** A nodra-tmp-* file bound to no object and to no open entry: kept as a recovery note unless empty. */
export function strayDisposition(content: Content): "DELETE" | "RECOVER" {
  return content.length === 0 ? "DELETE" : "RECOVER";
}

/** `nodra-recuperado-<hex>.md` in the same folder; `hexes` are inputs (randomness). Null if all are taken. */
export function recoveryName(path: PhysicalPath, hexes: readonly string[], occupied: (path: PhysicalPath) => boolean): PhysicalPath | null {
  for (const hex of hexes) {
    const candidate = `${dirOf(path)}nodra-recuperado-${hex}.md`;
    if (!occupied(candidate)) return candidate;
  }
  return null;
}
