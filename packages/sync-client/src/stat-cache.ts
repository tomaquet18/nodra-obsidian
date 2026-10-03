import type { Content, LocalCompareHash, PhysicalPath } from "@nodra/sync-core";
import type { ChangeMarker, Stat } from "./ports.js";

// The observation cache (NOTES questions 57, 146). §12.2 rule 2: L is obtained by observing, and every
// change of the disk must be re-read with local_compare_hash. Hashing every file at every tick is the
// cost; this cache skips the hash of a file only when its stat PROVES the bytes are the ones hashed.
//
// Persisted as a fact (CLAUDE.md "persistir hechos"): "at `readAt` the file at this path had this size and
// modification marker, and bytes whose local_compare_hash is `hash`". Never a step of an algorithm.
//
// The rule (`cachedHash`):
// - same size and same marker as the entry, always;
// - `counter` marker: that is enough (the adapter changes it on every write and never reuses it);
// - `clock` marker: the entry must also be OLD ENOUGH: mtime + granularity + CLOCK_SLACK_MS ≤ readAt,
//   where readAt is the device's wall clock taken before the stat that preceded the read. A write after
//   readAt then gets an mtime of at least readAt − granularity − slack > mtime, so it changes the marker.
//   A file modified within that margin of its hash (the "racy" case: an edit in the same mtime granule
//   keeps size and mtime) is hashed again at every observation until it is old enough.
//   A wall clock behind the entry's readAt (the clock went back) trusts nothing.
// - the entry's (size, mtime) pair is not DISPLACED: no other cached entry with the same pair lost its own
//   file since (its path is gone or shows another stat). A rename keeps size and mtime, so a file moved
//   over this path (while no instance was observing, or between two observations) could otherwise match
//   the pair cached here; with a displaced pair the file is hashed again.
// What no stat-based rule can see, and this one does not claim to: a tool that writes a file and then
// sets its mtime back to the old value with the same size (`touch -r`, a copy preserving mtime onto the
// same path). git, rsync and Unison's fastcheck make the same assumption.

/** Allowed disagreement between the device clock and the file system's timestamps (network disks, FAT local time rounding). */
export const CLOCK_SLACK_MS = 2000;

/** Total bytes of this observation's freshly read contents kept for the enqueue that follows it (in memory only). */
export const OBSERVED_BYTES_BUDGET = 64 * 1024 * 1024;

/** The last hash of the file at a path (the `fileStats` table). */
export interface FileStatEntry {
  readonly size: number;
  readonly mtime: number;
  readonly hash: LocalCompareHash;
  /** Wall clock (ms since the epoch) taken before the stat that preceded the read; null for a `counter` marker. */
  readonly readAt: number | null;
}

const pair = (size: number, mtime: number | undefined) => `${size}:${mtime}`;

/**
 * The (size, mtime) pairs of cached entries whose own path no longer shows them (gone, a folder, or
 * another stat): the files they described may have moved over another path (`stats`: this observation).
 */
export function displacedPairs(prior: ReadonlyMap<PhysicalPath, FileStatEntry>, stats: ReadonlyMap<PhysicalPath, Stat>): Set<string> {
  const out = new Set<string>();
  for (const [path, e] of prior) {
    const st = stats.get(path);
    if (st?.type !== "file" || st.size !== e.size || st.mtime !== e.mtime) out.add(pair(e.size, e.mtime));
  }
  return out;
}

/** The entry's hash if `stat` proves the file still holds the bytes it was computed from; null means: read and hash. */
export function cachedHash(
  entry: FileStatEntry | undefined,
  stat: Stat,
  marker: ChangeMarker | undefined,
  wallNow: number | null,
  displaced: ReadonlySet<string>,
): LocalCompareHash | null {
  if (entry === undefined || marker === undefined || stat.type !== "file" || stat.mtime === undefined) return null;
  if (stat.size !== entry.size || stat.mtime !== entry.mtime || displaced.has(pair(entry.size, entry.mtime))) return null;
  if (marker.kind === "counter") return entry.hash;
  if (entry.readAt === null || wallNow === null || wallNow < entry.readAt) return null;
  return entry.mtime + marker.granularityMs + CLOCK_SLACK_MS <= entry.readAt ? entry.hash : null;
}

/**
 * The entry for bytes just read after `stat` (itself taken after `readAt`), or null when there is none to
 * record: no usable marker, or the bytes do not have the stat's size (a write landed between the two).
 */
export function statEntry(stat: Stat, content: Content, hash: LocalCompareHash, marker: ChangeMarker | undefined, readAt: number | null): FileStatEntry | null {
  if (marker === undefined || stat.type !== "file" || stat.mtime === undefined || content.byteLength !== stat.size) return null;
  if (marker.kind === "clock" && readAt === null) return null;
  return { size: stat.size, mtime: stat.mtime, hash, readAt: marker.kind === "clock" ? readAt : null };
}
