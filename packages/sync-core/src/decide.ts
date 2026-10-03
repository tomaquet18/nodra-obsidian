import { match } from "ts-pattern";
import type { Action, LocalEntry, ObjectId, PlanInput, RemoteEntry, RevisionEntry, Side, SyncedEntry } from "./types.js";

// Per-object logical decisions (§12.2 base table and rules 2-6, 8). Physical placement
// (rule 7, §16.7) is decided afterwards by plan() over the whole tree.

/**
 * A logical decision. `applyRemote` has no physical path yet: plan() applies it in place
 * (object on disk) or materializes it at its projected path (object not on disk).
 */
export type Decision =
  | Exclude<Action, { kind: "applyRemote" | "movePhysical" | "removePhysical" | "markNotMaterialized" }>
  | { readonly kind: "applyRemote"; readonly objectId: ObjectId; readonly revisionId: string };

type Present = Extract<LocalEntry, { kind: "PRESENT" }>;

/** `local` must already carry the rule-12 logical paths. */
export function decideObject(id: ObjectId, input: PlanInput): Decision | null {
  const s = input.synced.get(id);
  // R is the known head; with no cached head, nothing is known to have changed remotely.
  const r = input.remote.get(id) ?? s;
  const l: LocalEntry = input.local.get(id) ?? { kind: "UNBOUND" };

  // Hashes are inputs: if a needed one is missing, the first action is to download it (§12.2).
  const missing = missingHash(l, s, r, input.prunedRevisions);
  if (missing) return { kind: "fetchContent", objectId: id, revisionId: missing.revisionId };

  const remoteChanged = r !== undefined && (s === undefined || r.revisionId !== s.revisionId);
  // Rule 3a: different revision, same state → advance S := R before anything else.
  if (s && r && remoteChanged && sameState(s, r)) {
    return { kind: "advanceSynced", objectId: id, revisionId: r.revisionId };
  }

  return match(l)
    // LOCAL_PATH_TOO_LONG depends only on the projection, which plan() re-evaluates: like UNBOUND.
    .with({ kind: "NOT_MATERIALIZED", reason: "LOCAL_PATH_TOO_LONG" }, () => planUnbound(id, r, remoteChanged))
    .with({ kind: "NOT_MATERIALIZED", reason: "LOCAL_FS_REJECTED" }, () => planNotMaterialized(id, r, remoteChanged))
    .with({ kind: "UNBOUND" }, () => planUnbound(id, r, remoteChanged))
    .with({ kind: "ABSENT" }, () => planAbsent(id, s, r, remoteChanged))
    .with({ kind: "PRESENT" }, (present) => planPresent(id, present, s, r, remoteChanged, input))
    .exhaustive();
}

/**
 * Returns the first revision whose hash the decision needs but is unknown (R first: its bytes always exist).
 * A pruned revision is never returned: its bytes cannot be downloaded, so its hash stays unknown
 * and the rules below act conservatively on it (§20.1 LocalCompareKey loss, §44.1).
 */
function missingHash(
  l: LocalEntry,
  s: SyncedEntry | undefined,
  r: RemoteEntry | undefined,
  pruned: ReadonlySet<string>,
): RevisionEntry | null {
  const sLive = s !== undefined && !s.deleted;
  const rLive = r !== undefined && !r.deleted;
  const rDiffers = r !== undefined && r.revisionId !== s?.revisionId;
  const lPresent = l.kind === "PRESENT";
  if (rLive && rDiffers && (lPresent || sLive) && r.localCompareHash === null && !pruned.has(r.revisionId)) return r;
  if (sLive && (lPresent || (rDiffers && rLive)) && s.localCompareHash === null && !pruned.has(s.revisionId)) return s;
  return null;
}

/**
 * Entry equality: content, logical path and deleted state (§12.2). mtime never participates.
 * An unknown hash is never equal to anything (§20.1).
 */
function sameState(a: RevisionEntry, b: RevisionEntry): boolean {
  if (a.deleted || b.deleted) return a.deleted === b.deleted;
  return a.path === b.path && sameContent(a.localCompareHash, b.localCompareHash);
}

function sameContent(a: string | null, b: string | null): boolean {
  return a !== null && a === b;
}

/** L ≠ S: the object has a local change pending (unknown hashes count as a change). */
export function hasLocalChange(l: LocalEntry | undefined, s: SyncedEntry | undefined): boolean {
  if (l === undefined || l.kind === "UNBOUND" || l.kind === "NOT_MATERIALIZED") return false;
  if (l.kind === "ABSENT") return s !== undefined && !s.deleted;
  return s === undefined || !equalsLocal(l, s);
}

// Rule 2 / §16.2: an object this replica cannot write (LOCAL_FS_REJECTED) never produces a
// delete and is never written; it has no local content, so S may follow R.
function planNotMaterialized(id: ObjectId, r: RemoteEntry | undefined, remoteChanged: boolean): Decision | null {
  return r !== undefined && remoteChanged ? { kind: "advanceSynced", objectId: id, revisionId: r.revisionId } : null;
}

// Rule 2: a not-materialized object never produces a delete; it is materialized from R.
function planUnbound(id: ObjectId, r: RemoteEntry | undefined, remoteChanged: boolean): Decision | null {
  if (r === undefined) return null;
  if (r.deleted) return remoteChanged ? { kind: "advanceSynced", objectId: id, revisionId: r.revisionId } : null;
  return { kind: "applyRemote", objectId: id, revisionId: r.revisionId };
}

function planAbsent(
  id: ObjectId,
  s: SyncedEntry | undefined,
  r: RemoteEntry | undefined,
  remoteChanged: boolean,
): Decision | null {
  if (s === undefined) {
    // Rule 6: created and deleted before being confirmed.
    if (r === undefined) return { kind: "forgetUnconfirmedCreate", objectId: id };
    // No base: never send a delete. Conservative: take R (nothing local to lose).
    return r.deleted
      ? { kind: "advanceSynced", objectId: id, revisionId: r.revisionId }
      : { kind: "applyRemote", objectId: id, revisionId: r.revisionId };
  }
  if (s.deleted) return null; // L = S: the deletion is already reflected locally.
  // Local delete of a live object.
  if (!remoteChanged || r === undefined) {
    return { kind: "upload", objectId: id, expectedHeadRevisionId: s.revisionId, deleted: true };
  }
  if (r.deleted) return { kind: "advanceSynced", objectId: id, revisionId: r.revisionId }; // delete/delete
  // Rule 5c: remote content change wins; the delete is not sent and R is materialized again.
  if (!sameContent(r.localCompareHash, s.localCompareHash)) {
    return { kind: "applyRemote", objectId: id, revisionId: r.revisionId };
  }
  // Rule 5d: remote path-only change → send the delete on top of R.
  return { kind: "upload", objectId: id, expectedHeadRevisionId: r.revisionId, deleted: true };
}

function planPresent(
  id: ObjectId,
  l: Present,
  s: SyncedEntry | undefined,
  r: RemoteEntry | undefined,
  remoteChanged: boolean,
  input: PlanInput,
): Decision | null {
  const upload = (expected: string | null): Decision | null =>
    isBlocked(id, l.localCompareHash, input)
      ? null // Rule 8: no upload while L carries the blocked content.
      : { kind: "upload", objectId: id, expectedHeadRevisionId: expected, deleted: false };

  if (s === undefined) {
    if (r === undefined) return upload(null); // local create
    if (r.deleted) return { kind: "conflictCopy", objectId: id, remoteRevisionId: r.revisionId, reason: "remoteDeleted" };
    if (equalsLocal(l, r)) return { kind: "advanceSynced", objectId: id, revisionId: r.revisionId };
    return { kind: "conflictCopy", objectId: id, remoteRevisionId: r.revisionId, reason: "noCommonAncestor" };
  }
  if (s.deleted) {
    // A deleted object is terminal (§18.1): local content can only come back as a new object.
    return { kind: "conflictCopy", objectId: id, remoteRevisionId: (r ?? s).revisionId, reason: "remoteDeleted" };
  }

  const localChanged = !equalsLocal(l, s);
  if (!remoteChanged || r === undefined) return localChanged ? upload(s.revisionId) : null;
  if (!localChanged) return { kind: "applyRemote", objectId: id, revisionId: r.revisionId };

  // Both sides changed.
  const localContentChanged = !sameContent(l.localCompareHash, s.localCompareHash);
  if (r.deleted) {
    // Rule 5a / 5b.
    return localContentChanged
      ? { kind: "conflictCopy", objectId: id, remoteRevisionId: r.revisionId, reason: "remoteDeleted" }
      : { kind: "discardLocalRename", objectId: id, remoteRevisionId: r.revisionId };
  }
  if (equalsLocal(l, r)) return { kind: "advanceSynced", objectId: id, revisionId: r.revisionId };

  // Field-wise resolution against S (§17.1).
  const remoteContentChanged = !sameContent(r.localCompareHash, s.localCompareHash);
  const content: Side | "merge" =
    localContentChanged && remoteContentChanged && !sameContent(l.localCompareHash, r.localCompareHash)
      ? "merge"
      : localContentChanged && !remoteContentChanged
        ? "local"
        : "remote";
  if (content === "merge" && !(input.textObjects.has(id) && !input.prunedRevisions.has(s.revisionId))) {
    return { kind: "conflictCopy", objectId: id, remoteRevisionId: r.revisionId, reason: "unmergeable" };
  }
  const localPathChanged = l.path !== s.path;
  const remotePathChanged = r.path !== s.path;
  const path: Side = localPathChanged && !remotePathChanged ? "local" : "remote";
  return {
    kind: "resolve",
    objectId: id,
    baseRevisionId: s.revisionId,
    remoteRevisionId: r.revisionId,
    content,
    path,
    localRenameDiscarded: localPathChanged && remotePathChanged && l.path !== r.path,
  };
}

function equalsLocal(l: Present, e: RevisionEntry): boolean {
  return !e.deleted && l.path === e.path && sameContent(l.localCompareHash, e.localCompareHash);
}

function isBlocked(id: ObjectId, hash: string, input: PlanInput): boolean {
  return input.blocked.some((b) => b.objectId === id && b.localCompareHash === hash);
}
