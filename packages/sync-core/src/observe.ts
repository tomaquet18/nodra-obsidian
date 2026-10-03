import type { LocalCompareHash, ObjectId, PhysicalPath } from "./types.js";

// Attributing files on disk to objects (§12.2 rules 10-11, §15 "Identidad y ecos"). Pure: the
// observation step re-reads the disk and calls this; the planner then works on the result.

/** The persisted last observation of an object (§12.2 table): its file and that file's hash. */
export interface RecordedFile {
  readonly objectId: ObjectId;
  /** null once the last observation found the file absent: it claims no path and never pairs. */
  readonly physicalPath: PhysicalPath | null;
  /** local_compare_hash of the last observation; null if unknown (LocalCompareKey lost, §20.1). */
  readonly localCompareHash: LocalCompareHash | null;
}

/** A file on disk now, with the adapter's in-memory identity (Obsidian's TFile; never persisted). */
export interface DiskFile {
  readonly path: PhysicalPath;
  readonly localCompareHash: LocalCompareHash | null;
  readonly identity: string;
}

export interface Attribution {
  /** Each object's file (one file per object, one object per file). */
  readonly byObject: ReadonlyMap<ObjectId, PhysicalPath>;
  /** Rule 11 renames found after a restart. */
  readonly paired: ReadonlyArray<{ readonly objectId: ObjectId; readonly path: PhysicalPath }>;
  /** Files attributed to no object, sorted. */
  readonly untracked: readonly PhysicalPath[];
  /** Objects with a recorded file that is not on disk (ABSENT), sorted. */
  readonly absent: readonly ObjectId[];
}

const byPath = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * 1. Rule 10: an object whose identity the instance knows is where that identity is (or absent);
 *    it is never attributed by path or paired.
 * 2. Startup scan (§15), only on the first observation of an instance: an object without a known
 *    identity takes the file at its recorded path, unless that file belongs to another object's identity
 *    or several objects record that path.
 * 3. Rule 11, also only at startup ("tras un reinicio"): an absent object without identity and an
 *    untracked file pair as a rename only on the exact local_compare_hash of the object's last
 *    observation, unique in both directions. Anything ambiguous or unknown stays delete + create:
 *    history may be lost, never content.
 * Within a running instance, attribution is by identity only: an object whose delete was registered
 * stays without identity and never takes a new file (§44.1).
 */
export function attributeFiles(
  recorded: readonly RecordedFile[],
  disk: readonly DiskFile[],
  identities: ReadonlyMap<ObjectId, string>,
  options: { readonly startup: boolean } = { startup: true },
): Attribution {
  const byObject = new Map<ObjectId, PhysicalPath>();
  const taken = new Set<PhysicalPath>();
  const byIdentity = new Map(disk.map((f) => [f.identity, f]));
  const claimed = new Set(identities.values());

  for (const r of recorded) {
    const identity = identities.get(r.objectId);
    if (identity === undefined) continue;
    const f = byIdentity.get(identity);
    if (f && !taken.has(f.path)) {
      byObject.set(r.objectId, f.path);
      taken.add(f.path);
    }
  }

  const recordedPaths = new Map<PhysicalPath, number>();
  for (const r of recorded) if (r.physicalPath !== null) recordedPaths.set(r.physicalPath, (recordedPaths.get(r.physicalPath) ?? 0) + 1);
  const atPath = new Map(disk.map((f) => [f.path, f]));
  for (const r of recorded) {
    if (!options.startup || identities.has(r.objectId) || r.physicalPath === null) continue;
    const f = atPath.get(r.physicalPath);
    if (!f || taken.has(f.path) || claimed.has(f.identity) || recordedPaths.get(r.physicalPath)! > 1) continue;
    byObject.set(r.objectId, f.path);
    taken.add(f.path);
  }

  const candidates = options.startup ? recorded.filter((r) => !identities.has(r.objectId) && !byObject.has(r.objectId) && r.localCompareHash !== null) : [];
  const free = disk.filter((f) => !taken.has(f.path) && !claimed.has(f.identity) && f.localCompareHash !== null);
  const paired: Array<{ objectId: ObjectId; path: PhysicalPath }> = [];
  for (const r of candidates) {
    const objects = candidates.filter((x) => x.localCompareHash === r.localCompareHash);
    const files = free.filter((f) => f.localCompareHash === r.localCompareHash);
    if (objects.length !== 1 || files.length !== 1) continue;
    const f = files[0]!;
    byObject.set(r.objectId, f.path);
    taken.add(f.path);
    paired.push({ objectId: r.objectId, path: f.path });
  }

  return {
    byObject,
    paired: paired.sort((a, b) => byPath(a.objectId, b.objectId)),
    untracked: disk.filter((f) => !taken.has(f.path)).map((f) => f.path).sort(byPath),
    absent: recorded.filter((r) => !byObject.has(r.objectId)).map((r) => r.objectId).sort(byPath),
  };
}
