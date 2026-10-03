import { isTmpName } from "./journal.js";
import { plan } from "./plan.js";
import type { LocalCompareHash, ObjectId, PhysicalPath, PlanInput, RemoteEntry, RevisionId, SyncedEntry } from "./types.js";

// §20.2 "Nodra es el único sincronizador de la carpeta", the runtime half (NOTES questions 417, 419).
// Another tool syncing the vault folder carries the files Nodra wrote on another device to this one
// without this replica's journal (§15): the disk ends up holding a remote revision before this replica
// applies it. Pure detection over the facts the planner already has, plus two small facts of this
// replica: which content its own journal wrote per object, and which arrivals the user accepted.

/**
 * - `explainedWrites`: per object, the `final_fp` (a local_compare_hash) of the last WRITE of this
 *   replica's journal that closed, or that was cancelled after its replace may have happened (a replay,
 *   or a failed replace). It explains that content on disk (§15 "ninguna entrada de su journal, pendiente o
 *   completada, lo explica"): an adapter that rewrites the destination can crash with the new content in
 *   place and the temporary still there, and the replay then cancels (§15 table). Dropped once S holds it.
 * - `acknowledged`: per object, the remote revision the user accepted ("I removed the other tool,
 *   resume"): its arrival no longer pauses. Dropped once S reaches it or R moves on (detection re-arms).
 */
export interface OtherSyncFacts {
  readonly explainedWrites: ReadonlyMap<ObjectId, LocalCompareHash>;
  readonly acknowledged: ReadonlyMap<ObjectId, RevisionId>;
}

export const EMPTY_OTHER_SYNC_FACTS: OtherSyncFacts = { explainedWrites: new Map(), acknowledged: new Map() };

/** A remote revision whose exact content was on disk before this replica wrote it. */
export interface ContentArrival {
  readonly objectId: ObjectId;
  readonly revisionId: RevisionId;
}

/** "Varias veces seguidas" (§20.2): projection renames of another replica seen in a row before sync pauses. */
export const PROJECTION_RENAME_ARRIVALS_TO_PAUSE = 3;

/** This replica's journal wrote `hash` for the object (a close, or a cancel after a possible replace). */
export function explainWrite(f: OtherSyncFacts, objectId: ObjectId, hash: LocalCompareHash): OtherSyncFacts {
  if (f.explainedWrites.get(objectId) === hash) return f;
  return { ...f, explainedWrites: new Map(f.explainedWrites).set(objectId, hash) };
}

/** The user accepted these arrivals. */
export function acknowledgeArrivals(f: OtherSyncFacts, arrivals: readonly ContentArrival[]): OtherSyncFacts {
  if (arrivals.every((a) => f.acknowledged.get(a.objectId) === a.revisionId)) return f;
  const acknowledged = new Map(f.acknowledged);
  for (const a of arrivals) acknowledged.set(a.objectId, a.revisionId);
  return { ...f, acknowledged };
}

/**
 * §20.2: the objects whose file already holds exactly the content of the remote revision this replica is
 * about to apply (same local_compare_hash, computed on that revision's downloaded content), with a base
 * that holds other content (so this replica did not write it as S), no in-flight entry (§12.2 rule 14: an
 * own commit is not another tool), no journal entry of this replica explaining that content, and not
 * accepted by the user. Empty content is exempt: two devices emptying a file is a coincidence, not evidence.
 * A different local content is a conflict (§17), never an arrival. `input.local` is the current observation.
 */
export function contentArrivals(input: PlanInput, facts: OtherSyncFacts, emptyHash: LocalCompareHash): ContentArrival[] {
  const inFlight = new Set<ObjectId>();
  for (const entry of input.outbox) for (const o of entry.objects) inFlight.add(o.objectId);
  const out: ContentArrival[] = [];
  for (const [objectId, l] of input.local) {
    if (l.kind !== "PRESENT" || inFlight.has(objectId)) continue;
    const s = input.synced.get(objectId);
    const r = input.remote.get(objectId);
    if (s === undefined || s.deleted || s.localCompareHash === null) continue;
    if (r === undefined || r.deleted || r.localCompareHash === null || r.revisionId === s.revisionId) continue;
    const hash = l.localCompareHash;
    if (hash !== r.localCompareHash || hash === s.localCompareHash || hash === emptyHash) continue;
    if (facts.explainedWrites.get(objectId) === hash || facts.acknowledged.get(objectId) === r.revisionId) continue;
    out.push({ objectId, revisionId: r.revisionId });
  }
  return out.sort((a, b) => (a.objectId < b.objectId ? -1 : a.objectId > b.objectId ? 1 : 0));
}

/**
 * §20.2 renames of another replica on disk before this replica applies them, read from the facts: a remote
 * revision that renamed the object (R's path ≠ S's) whose file already sits, with R's content, at R's
 * path (the observation's logical path, §16.4) although this replica did not move it (L = R ≠ S). Another
 * tool carried the physical rename (§16.7) the other device made. One coincidence proves nothing: the
 * caller counts each (object, revision) once and pauses at PROJECTION_RENAME_ARRIVALS_TO_PAUSE in a row.
 */
export function renameArrivals(input: PlanInput): ContentArrival[] {
  const inFlight = new Set<ObjectId>();
  for (const entry of input.outbox) for (const o of entry.objects) inFlight.add(o.objectId);
  const out: ContentArrival[] = [];
  for (const [objectId, l] of input.local) {
    if (l.kind !== "PRESENT" || inFlight.has(objectId)) continue;
    const s = input.synced.get(objectId);
    const r = input.remote.get(objectId);
    if (s === undefined || s.deleted || r === undefined || r.deleted || r.revisionId === s.revisionId) continue;
    if (r.path === s.path || l.path !== r.path || r.localCompareHash === null || l.localCompareHash !== r.localCompareHash) continue;
    out.push({ objectId, revisionId: r.revisionId });
  }
  return out.sort((a, b) => (a.objectId < b.objectId ? -1 : a.objectId > b.objectId ? 1 : 0));
}

/** Drops the facts that can no longer matter; the same value when none goes (no needless write). */
export function pruneOtherSyncFacts(f: OtherSyncFacts, synced: ReadonlyMap<ObjectId, SyncedEntry>, remote: ReadonlyMap<ObjectId, RemoteEntry>): OtherSyncFacts {
  const explained = [...f.explainedWrites].filter(([id, hash]) => synced.get(id)?.localCompareHash !== hash);
  const acknowledged = [...f.acknowledged].filter(([id, revisionId]) => synced.get(id)?.revisionId !== revisionId && (remote.get(id) ?? synced.get(id))?.revisionId === revisionId);
  if (explained.length === f.explainedWrites.size && acknowledged.length === f.acknowledged.size) return f;
  return { explainedWrites: new Map(explained), acknowledged: new Map(acknowledged) };
}

/** The projection's physical moves (§16.7) the planner wants from `input`, parking excluded, by object. */
export function expectedProjectionMoves(input: PlanInput): ReadonlyMap<ObjectId, { readonly from: PhysicalPath; readonly to: PhysicalPath }> {
  const moves = new Map<ObjectId, { from: PhysicalPath; to: PhysicalPath }>();
  for (const a of plan(input)) if (a.kind === "movePhysical" && !isTmpName(a.to)) moves.set(a.objectId, { from: a.from, to: a.to });
  return moves;
}

/**
 * §20.2 "renames de proyección (§16.7) hechos por otra réplica apareciendo en disco antes de aplicarlos":
 * the objects whose planned physical move (from the last observation, `before`) is already done on the
 * disk now, without this replica: the file left its path and the destination holds exactly its content.
 * The caller counts them; PROJECTION_RENAME_ARRIVALS_TO_PAUSE in a row pause sync. `disk`: path → hash.
 */
export function projectionRenameArrivals(before: PlanInput, disk: ReadonlyMap<PhysicalPath, LocalCompareHash>): ObjectId[] {
  const out: ObjectId[] = [];
  for (const [objectId, m] of expectedProjectionMoves(before)) {
    const l = before.local.get(objectId);
    if (l?.kind !== "PRESENT" || disk.has(m.from)) continue;
    if (disk.get(m.to) === l.localCompareHash) out.push(objectId);
  }
  return out.sort();
}
