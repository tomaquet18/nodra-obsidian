import {
  type CanonicalPath,
  type KeyFn,
  MAX_PORTABLE_PHYSICAL_PATH_BYTES,
  type ObjectId,
  canonicalizePath,
  comparisonKey,
  conflictSuffix,
  fitSegment,
  objectLabel,
  sanitizeSegment,
  splitExtension,
  utf8Length,
} from "./paths.js";

// §16.3 projection: logical view of all objects → physical paths. Pure and deterministic.

export interface ProjectionObject {
  readonly objectId: ObjectId;
  /** Logical path of the local view (L when L ≠ S, R otherwise; §16.3). Chosen by the caller. */
  readonly logicalPath: string;
  /** Sequence of the commit that created the object; null for a local create not yet confirmed. */
  readonly createdSequence: number | null;
}

export interface ProjectionInput {
  readonly objects: readonly ProjectionObject[];
  /** Physical paths of untracked files on this replica's disk: they count as occupied. */
  readonly untrackedFiles: readonly string[];
}

export interface ProjectedFile {
  readonly physicalPath: string;
  /** §16.2: the path is still reserved, but it is not written to disk. */
  readonly notMaterialized: "LOCAL_PATH_TOO_LONG" | null;
}

export interface Projection {
  readonly files: ReadonlyMap<ObjectId, ProjectedFile>;
  /** Projected folder table: physical folder path → logical folder path (used by §16.4). */
  readonly folders: ReadonlyMap<string, string>;
  /** Objects whose logical path cannot be canonicalized (§16.2): not projected. */
  readonly rejected: ReadonlyMap<ObjectId, Extract<CanonicalPath, { ok: false }>["reason"]>;
}

interface Entry {
  readonly objectId: ObjectId;
  readonly segments: readonly string[];
  readonly createdSequence: number | null;
}

interface Folder {
  readonly key: string;
  readonly parentKey: string | null;
  readonly depth: number;
  /** Priority index of the highest-priority object under this folder. */
  readonly rank: number;
  readonly owner: ObjectId;
  readonly logicalPath: string;
  readonly segment: string;
}

/** Priority: confirmed first by created_sequence, then object_id; unconfirmed creates last (§16.3). */
function byPriority(a: Entry, b: Entry): number {
  if (a.createdSequence !== b.createdSequence) {
    if (a.createdSequence === null) return 1;
    if (b.createdSequence === null) return -1;
    return a.createdSequence - b.createdSequence;
  }
  return a.objectId < b.objectId ? -1 : a.objectId > b.objectId ? 1 : 0;
}

const join = (parent: string, segment: string) => (parent === "" ? segment : `${parent}/${segment}`);

/** `key` is the §16.2 comparison key (pinned Unicode tables); a parameter so tests can inject a broken one. */
export function project(input: ProjectionInput, key: KeyFn = comparisonKey): Projection {
  const rejected = new Map<ObjectId, Extract<CanonicalPath, { ok: false }>["reason"]>();
  const entries: Entry[] = [];
  for (const o of input.objects) {
    const c = canonicalizePath(o.logicalPath);
    if (c.ok) entries.push({ objectId: o.objectId, segments: c.path.split("/"), createdSequence: o.createdSequence });
    else rejected.set(o.objectId, c.reason);
  }
  entries.sort(byPriority);

  // Logical folders, keyed by comparison key; the first (highest-priority) object fixes the spelling.
  const folders = new Map<string, Folder>();
  entries.forEach((e, rank) => {
    for (let depth = 1; depth < e.segments.length; depth++) {
      const logicalPath = e.segments.slice(0, depth).join("/");
      const k = key(logicalPath);
      if (folders.has(k)) continue;
      folders.set(k, {
        key: k,
        parentKey: depth === 1 ? null : key(e.segments.slice(0, depth - 1).join("/")),
        depth,
        rank,
        owner: e.objectId,
        logicalPath,
        segment: e.segments[depth - 1]!,
      });
    }
  });

  // Local occupation (§16.3): untracked files, and the folders that contain them.
  const untrackedFileKeys = new Set<string>();
  const untrackedDirKeys = new Set<string>();
  for (const p of input.untrackedFiles) {
    const segs = p.split("/");
    untrackedFileKeys.add(key(p));
    for (let i = 1; i < segs.length; i++) untrackedDirKeys.add(key(segs.slice(0, i).join("/")));
  }

  // Folders, top-down, by level then by the priority of their first object.
  const folderPhysical = new Map<string, string>(); // logical folder key → physical path
  const placedFolderKeys = new Map<string, string>(); // physical key → logical folder key
  const folderTable = new Map<string, string>(); // physical → logical
  const orderedFolders = [...folders.values()].sort((a, b) => a.depth - b.depth || a.rank - b.rank);
  for (const f of orderedFolders) {
    const parent = f.parentKey === null ? "" : folderPhysical.get(f.parentKey)!;
    const base = sanitizeSegment(f.segment);
    const candidates = [
      fitSegment(base, "", ""),
      fitSegment(base, conflictSuffix(objectLabel(f.owner)), ""),
      fitSegment(base, conflictSuffix(f.owner), ""),
    ].map((s) => join(parent, s));
    const free = (p: string) => {
      const k = key(p);
      const other = placedFolderKeys.get(k);
      return !untrackedFileKeys.has(k) && (other === undefined || other === f.key);
    };
    // Candidate (c) is unique by construction; if even it is occupied, it is kept anyway
    // and the physical plan (§16.7) never writes onto the occupied path.
    const physical = candidates.find(free) ?? candidates[2]!;
    folderPhysical.set(f.key, physical);
    placedFolderKeys.set(key(physical), f.key);
    folderTable.set(physical, f.logicalPath);
  }

  // Files, in priority order. A folder always wins over a file (folders are placed first).
  const placedFileKeys = new Set<string>();
  const files = new Map<ObjectId, ProjectedFile>();
  for (const e of entries) {
    const parentKey = e.segments.length > 1 ? key(e.segments.slice(0, -1).join("/")) : null;
    const parent = parentKey === null ? "" : folderPhysical.get(parentKey)!;
    const [base, ext] = splitExtension(sanitizeSegment(e.segments[e.segments.length - 1]!));
    const candidates = [
      fitSegment(base, "", ext),
      fitSegment(base, conflictSuffix(objectLabel(e.objectId)), ext),
      fitSegment(base, conflictSuffix(e.objectId), ext),
    ].map((s) => join(parent, s));
    const free = (p: string) => {
      const k = key(p);
      return !untrackedFileKeys.has(k) && !untrackedDirKeys.has(k) && !placedFileKeys.has(k) && !placedFolderKeys.has(k);
    };
    const physical = candidates.find(free) ?? candidates[2]!;
    placedFileKeys.add(key(physical));
    files.set(e.objectId, {
      physicalPath: physical,
      notMaterialized: utf8Length(physical) > MAX_PORTABLE_PHYSICAL_PATH_BYTES ? "LOCAL_PATH_TOO_LONG" : null,
    });
  }

  return { files, folders: folderTable, rejected };
}
