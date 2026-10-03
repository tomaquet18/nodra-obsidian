import { recordRemoteHead } from "./remote.js";
import type {
  BlockedContent,
  Content,
  ContentRef,
  LocalCompareHash,
  LogicalPath,
  MutationId,
  ObjectId,
  RemoteEntry,
  RevisionEntry,
  RevisionId,
  SyncedEntry,
} from "./types.js";

// Outbox, upload attempts and cleanup queue (§12.1, §12.2 rules 13-16, §12.6).
// Only FACTS are persisted, never "which step we were at". Every function below is one
// persisted transition: what the spec requires in a single IndexedDB transaction happens
// in a single call, so the atomicity is structural. No I/O, no clock (time is an input:
// monotonic readings), no randomness (ids are inputs).

export type BlobId = string;
export type BlobKind = "CONTENT" | "MANIFEST";

/** Initial value of §12.6. */
export const UPLOAD_TIMEOUT_MAX = 3;
/** §12.1: a mutation has 1 to 500 revisions. */
export const MAX_REVISIONS_PER_MUTATION = 500;

/** One revision of an outbox entry: the exact immutable snapshot that is sent (rule 13). */
export interface OutboxRevision {
  readonly objectId: ObjectId;
  readonly revisionId: RevisionId;
  readonly expectedHeadRevisionId: RevisionId | null;
  readonly path: LogicalPath;
  readonly deleted: boolean;
  /** Content identity of the snapshot; null for a delete. */
  readonly localCompareHash: LocalCompareHash | null;
  /** Plaintext of the new content (encrypted with the Device Local Key at rest, rule 16); null for a delete. */
  readonly plaintext: Content | null;
  /**
   * `mtime_ms` of the §8 manifest, as the shell observed it. A plain fact about the file, carried
   * so the manifest built at seal time does not have to re-stat a file that may already be gone;
   * absent on an entry persisted before this field existed.
   */
  readonly mtimeMs?: number;
  /** Declared bytes of the new blobs of this revision (content + manifest), for §12.1 sizing. */
  readonly newBlobBytes: number;
}

export interface OutboxEntry {
  readonly mutationId: MutationId;
  readonly objects: readonly OutboxRevision[];
  /** Fact: a commit request for this entry may have reached the server (outcome unknown until a response). */
  readonly commitSent: boolean;
}

export interface AttemptBlob {
  readonly blobId: BlobId;
  readonly kind: BlobKind;
  readonly objectId: ObjectId;
  readonly declaredSize: number;
  readonly ciphertextSha256: string;
  /** The exact ciphertext (rule 13): a retry resends these bytes, never re-encrypts within an attempt. */
  readonly ciphertext: Uint8Array;
  readonly forDelete: boolean;
  /** Conservative local deadline (monotonic), known once the prepare response arrives (§12.1). */
  readonly expiresAt: number | null;
}

/** Write-ahead record of an upload attempt (rule 13), persisted before any network request. */
export interface UploadAttempt {
  readonly attemptId: string;
  /** The outbox entry it uploads for; for a re-encryption, {@link reencryptKey} of its revision. */
  readonly mutationId: MutationId;
  readonly replicaId: string;
  readonly epochId: string;
  readonly blobs: readonly AttemptBlob[];
  /** §35.13: present when the blobs re-encrypt an existing revision instead of carrying a new one. */
  readonly reencrypt?: ReencryptTarget;
}

/**
 * The fact a re-encryption attempt records (§35.13): which revision its blobs replace, what the server
 * said the revision's manifest was when it was listed, and the exact reencryptRevision to send. Nothing
 * about how far it got: prepare and PUT are idempotent, and the swap itself is (step 2).
 */
export interface ReencryptTarget {
  readonly revisionId: RevisionId;
  readonly expectedManifestBlobId: BlobId;
  readonly newManifestBlobId: BlobId;
  /** One of the attempt's blobs, or a CONFIRMED one an earlier swap already put in for the same old content. */
  readonly newContentBlobId: BlobId | null;
}

/**
 * The key of a re-encryption attempt in the attempts table. It never names an outbox entry, so no
 * outbox transition (retire, confirm, a new attempt) ever touches it, and one revision has at most one.
 */
export const reencryptKey = (revisionId: RevisionId): MutationId => `reencrypt:${revisionId}`;

/**
 * Persists a re-encryption attempt before any request (rule 13, §35.13 "con el intento persistido
 * antes"). A previous attempt for the same revision has its blobs moved to the cleanup queue in the
 * same transition.
 */
export function recordReencryptAttempt(f: ClientFacts, attempt: UploadAttempt): ClientFacts {
  const target = attempt.reencrypt;
  if (target === undefined || attempt.mutationId !== reencryptKey(target.revisionId)) throw new Error(`${attempt.attemptId} is not a re-encryption attempt`);
  const previous = f.attempts.find((a) => a.mutationId === attempt.mutationId);
  return {
    ...f,
    attempts: [...f.attempts.filter((a) => a.mutationId !== attempt.mutationId), attempt],
    cleanup: previous ? withCleanup(f.cleanup, f, previous) : f.cleanup,
  };
}

/**
 * §35.13: the attempt is over. `swapped`: reencryptRevision answered success, so its blobs are the
 * revision's now and nothing is released. Otherwise (REVISION_PRUNED, REVISION_CHANGED, a refused or
 * expired upload...) its blobs go to the cleanup queue in the same transition.
 */
export function endReencryptAttempt(f: ClientFacts, revisionId: RevisionId, swapped: boolean): ClientFacts {
  const key = reencryptKey(revisionId);
  const attempt = f.attempts.find((a) => a.mutationId === key);
  if (attempt === undefined) return f;
  return {
    ...f,
    attempts: f.attempts.filter((a) => a.mutationId !== key),
    cleanup: swapped ? f.cleanup : withCleanup(f.cleanup, f, attempt),
  };
}

/** pending_upload_cleanup record (rule 13). */
export interface CleanupRecord {
  readonly vaultId: string;
  readonly replicaId: string;
  readonly blobId: BlobId;
}

/** Everything the client persists about sync (besides the local observation). */
export interface ClientFacts {
  readonly vaultId: string;
  readonly replicaId: string;
  /** Current write epoch as last learned from the server. */
  readonly epochId: string;
  readonly synced: ReadonlyMap<ObjectId, SyncedEntry>;
  readonly remote: ReadonlyMap<ObjectId, RemoteEntry>;
  readonly outbox: readonly OutboxEntry[];
  /** At most one attempt per outbox entry. */
  readonly attempts: readonly UploadAttempt[];
  readonly cleanup: readonly CleanupRecord[];
  readonly blocked: readonly BlockedContent[];
  /** INVALID_BATCH counter per (object, content), rule 8. Key: `${objectId}|${hash}`. */
  readonly invalidBatchCounts: ReadonlyMap<string, number>;
  /** Failed upload attempts attributable to the object, per (object, content), §12.6. */
  readonly uploadFailures: ReadonlyMap<string, number>;
  /** §12.1: after an expiry, mutations containing the object carry at most this many new bytes. */
  readonly byteCaps: ReadonlyMap<ObjectId, number>;
  /** Last event sequence applied to R (§13.2); 0 before the first page. */
  readonly cursor: number;
}

export function emptyFacts(vaultId: string, replicaId: string, epochId: string): ClientFacts {
  return {
    vaultId,
    replicaId,
    epochId,
    synced: new Map(),
    remote: new Map(),
    outbox: [],
    attempts: [],
    cleanup: [],
    blocked: [],
    invalidBatchCounts: new Map(),
    uploadFailures: new Map(),
    byteCaps: new Map(),
    cursor: 0,
  };
}

const key = (objectId: ObjectId, hash: LocalCompareHash | null) => `${objectId}|${hash ?? "deleted"}`;

/** Rule 8: the fact "the server refuses this content for this object" (idempotent; a deleted content blocks nothing). */
export function blockContent(f: ClientFacts, objectId: ObjectId, hash: LocalCompareHash | null, reason: BlockedContent["reason"]): ClientFacts {
  if (hash === null || f.blocked.some((b) => b.objectId === objectId && b.localCompareHash === hash)) return f;
  return { ...f, blocked: [...f.blocked, { objectId, localCompareHash: hash, reason }] };
}

function entryOf(f: ClientFacts, mutationId: MutationId): OutboxEntry {
  const e = f.outbox.find((x) => x.mutationId === mutationId);
  if (e === undefined) throw new Error(`no outbox entry ${mutationId}`);
  return e;
}

/** Removes the entry and moves every blob of its attempt to the cleanup queue (same transition). */
function retire(f: ClientFacts, mutationId: MutationId): ClientFacts {
  const attempt = f.attempts.find((a) => a.mutationId === mutationId);
  return {
    ...f,
    outbox: f.outbox.filter((e) => e.mutationId !== mutationId),
    attempts: f.attempts.filter((a) => a.mutationId !== mutationId),
    cleanup: attempt ? withCleanup(f.cleanup, f, attempt) : f.cleanup,
  };
}

function withCleanup(cleanup: readonly CleanupRecord[], f: ClientFacts, attempt: UploadAttempt): CleanupRecord[] {
  const out = [...cleanup];
  // §12.2 rule 13: an attempt of a previous replica_id (before a re-enrollment) owns blobs this
  // replica cannot release; its records are discarded locally rather than filed.
  if (attempt.replicaId !== f.replicaId) return out;
  for (const b of attempt.blobs) {
    if (!out.some((c) => c.blobId === b.blobId)) out.push({ vaultId: f.vaultId, replicaId: attempt.replicaId, blobId: b.blobId });
  }
  return out;
}

// ---------------------------------------------------------------------------
// §12.1: planner uploads → outbox entries.

/** What the planner decided to upload for one object, with the observed snapshot. */
export interface UploadRequest {
  readonly objectId: ObjectId;
  readonly expectedHeadRevisionId: RevisionId | null;
  readonly path: LogicalPath;
  readonly deleted: boolean;
  readonly localCompareHash: LocalCompareHash | null;
  readonly plaintext: Content | null;
  /** `mtime_ms` of the §8 manifest (see {@link OutboxRevision}); 0 when the shell has no clock. */
  readonly mtimeMs?: number;
  readonly newBlobBytes: number;
}

export interface BatchLimits {
  /** `pending_budget_bytes` from getRootState (§22, §40.1). */
  readonly pendingBudgetBytes: number;
}

/**
 * Splits uploads into mutations (1-500 revisions; new blob bytes ≤ pending_budget_bytes and ≤ the
 * halved caps of their objects) and appends them to the outbox. A single revision over the budget is
 * BLOB_TOO_LARGE (blocked, rule 8). An object already in the outbox is skipped (at most one in-flight
 * entry per object). `ids` supplies mutation_ids and revision_ids in order.
 */
export function enqueueUploads(
  f: ClientFacts,
  uploads: readonly UploadRequest[],
  limits: BatchLimits,
  ids: readonly string[],
): ClientFacts {
  const inFlight = new Set(f.outbox.flatMap((e) => e.objects.map((o) => o.objectId)));
  let next = 0;
  const id = () => {
    const v = ids[next++];
    if (v === undefined) throw new Error("not enough ids");
    return v;
  };
  let facts = f;
  const batches: UploadRequest[][] = [];
  let current: UploadRequest[] = [];
  let bytes = 0;
  let cap = limits.pendingBudgetBytes;
  for (const u of uploads) {
    if (inFlight.has(u.objectId)) continue;
    inFlight.add(u.objectId);
    if (!u.deleted && u.newBlobBytes > limits.pendingBudgetBytes) {
      facts = blockContent(facts, u.objectId, u.localCompareHash, "BLOB_TOO_LARGE");
      continue;
    }
    const ownCap = Math.min(limits.pendingBudgetBytes, f.byteCaps.get(u.objectId) ?? Infinity);
    const full = current.length >= MAX_REVISIONS_PER_MUTATION || bytes + u.newBlobBytes > Math.min(cap, ownCap);
    if (current.length > 0 && full) {
      batches.push(current);
      current = [];
      bytes = 0;
      cap = limits.pendingBudgetBytes;
    }
    current.push(u);
    bytes += u.newBlobBytes;
    cap = Math.min(cap, ownCap);
  }
  if (current.length > 0) batches.push(current);

  const entries: OutboxEntry[] = batches.map((batch) => ({
    mutationId: id(),
    commitSent: false,
    objects: batch.map((u) => ({
      objectId: u.objectId,
      revisionId: id(),
      expectedHeadRevisionId: u.expectedHeadRevisionId,
      path: u.path,
      deleted: u.deleted,
      localCompareHash: u.deleted ? null : u.localCompareHash,
      plaintext: u.deleted ? null : u.plaintext,
      mtimeMs: u.mtimeMs ?? 0,
      newBlobBytes: u.newBlobBytes,
    })),
  }));
  return { ...facts, outbox: [...facts.outbox, ...entries] };
}

// ---------------------------------------------------------------------------
// Rule 13: attempts.

/**
 * Persists a new attempt before any network request (write-ahead). The previous attempt of the same
 * entry, if any, has its blobs moved to the cleanup queue in the same transition. An entry whose
 * commit was already sent must first learn its outcome with getRevisionStatus (§12.1 table).
 */
export function recordAttempt(f: ClientFacts, attempt: UploadAttempt): ClientFacts {
  const entry = entryOf(f, attempt.mutationId);
  if (entry.commitSent) throw new Error(`entry ${entry.mutationId} was sent: getRevisionStatus before re-encrypting`);
  const previous = f.attempts.find((a) => a.mutationId === attempt.mutationId);
  return {
    ...f,
    attempts: [...f.attempts.filter((a) => a.mutationId !== attempt.mutationId), attempt],
    cleanup: previous ? withCleanup(f.cleanup, f, previous) : f.cleanup,
  };
}

/** Records the prepare response of a blob as a conservative local deadline. */
export function recordPrepared(f: ClientFacts, blobId: BlobId, expiresAt: number): ClientFacts {
  return {
    ...f,
    attempts: f.attempts.map((a) => ({
      ...a,
      blobs: a.blobs.map((b) => (b.blobId === blobId ? { ...b, expiresAt } : b)),
    })),
  };
}

/** Persisted before the commit request leaves (write-ahead). */
export function markCommitSent(f: ClientFacts, mutationId: MutationId): ClientFacts {
  entryOf(f, mutationId);
  return { ...f, outbox: f.outbox.map((e) => (e.mutationId === mutationId ? { ...e, commitSent: true } : e)) };
}

export type OutboxStep =
  | { readonly kind: "release"; readonly blobId: BlobId }
  | { readonly kind: "revisionStatus"; readonly mutationId: MutationId }
  | { readonly kind: "encrypt"; readonly mutationId: MutationId }
  | { readonly kind: "retireExpired"; readonly mutationId: MutationId }
  | { readonly kind: "prepare"; readonly mutationId: MutationId; readonly blobId: BlobId }
  | { readonly kind: "put"; readonly mutationId: MutationId; readonly blobId: BlobId }
  | { readonly kind: "commit"; readonly mutationId: MutationId };

/**
 * An entry whose revisions all delete: its only new blobs are for_delete manifests (§11.1, §40.1). An
 * entry that mixes deletes with other revisions is not one: it is immutable (rule 13) and §12.6 lets no
 * `QUOTA_EXCEEDED` retire it, so it waits whole.
 */
export function isDeleteOnly(e: OutboxEntry): boolean {
  return e.objects.every((o) => o.deleted);
}

/**
 * The next network step for the outbox, derived from facts only (plus the in-memory set of blobs
 * whose PUT completed in this instance, rule 13). The cleanup queue goes first.
 *
 * `deletesOnly` (the client holds what needs quota after a `QUOTA_EXCEEDED`, §12.6): the first
 * delete-only entry instead of the first entry. Entries never share an object (rule 9) and the server
 * checks each mutation against its own objects' heads (§12.5), so a delete may overtake a held entry.
 */
export function nextOutboxStep(f: ClientFacts, now: number, putDone: ReadonlySet<BlobId>, o: { readonly deletesOnly?: boolean } = {}): OutboxStep | null {
  const record = f.cleanup[0];
  if (record) return { kind: "release", blobId: record.blobId };
  const entry = o.deletesOnly ? f.outbox.find(isDeleteOnly) : f.outbox[0];
  if (entry === undefined) return null;
  const { mutationId } = entry;
  const attempt = f.attempts.find((a) => a.mutationId === mutationId);
  // An entry that may have reached the server is resent to learn its outcome, never retired locally.
  if (entry.commitSent) return attempt ? { kind: "commit", mutationId } : { kind: "revisionStatus", mutationId };
  if (attempt === undefined) return { kind: "encrypt", mutationId };
  if (attempt.blobs.some((b) => b.expiresAt !== null && b.expiresAt <= now)) return { kind: "retireExpired", mutationId };
  const unprepared = attempt.blobs.find((b) => b.expiresAt === null);
  if (unprepared) return { kind: "prepare", mutationId, blobId: unprepared.blobId };
  const unput = attempt.blobs.find((b) => !putDone.has(b.blobId));
  if (unput) return { kind: "put", mutationId, blobId: unput.blobId };
  return { kind: "commit", mutationId };
}

/**
 * §12.1: a never-sent entry with an expired blob is retired without confirming anything. Its objects
 * are re-planned in mutations of at most half the bytes; an object that travelled alone counts a
 * failed attempt (§12.6).
 */
export function retireExpired(f: ClientFacts, mutationId: MutationId, now: number): ClientFacts {
  const entry = entryOf(f, mutationId);
  if (entry.commitSent) throw new Error(`entry ${mutationId} was sent: it is resent, never retired for local expiry`);
  const attempt = f.attempts.find((a) => a.mutationId === mutationId);
  if (!attempt?.blobs.some((b) => b.expiresAt !== null && b.expiresAt <= now)) throw new Error(`entry ${mutationId} has not expired`);
  let facts = halveCaps(retire(f, mutationId), entry);
  if (entry.objects.length === 1) facts = recordPutFailure(facts, entry.objects[0]!.objectId, entry.objects[0]!.localCompareHash);
  return facts;
}

function halveCaps(f: ClientFacts, entry: OutboxEntry): ClientFacts {
  const half = Math.floor(entry.objects.reduce((s, o) => s + o.newBlobBytes, 0) / 2);
  const byteCaps = new Map(f.byteCaps);
  for (const o of entry.objects) byteCaps.set(o.objectId, Math.min(half, byteCaps.get(o.objectId) ?? Infinity));
  return { ...f, byteCaps };
}

/**
 * A failed upload attempt attributable to the object (§12.6). At UPLOAD_TIMEOUT_MAX the content is
 * blocked (rule 8) and a never-sent entry carrying it is retired in the same transition.
 */
export function recordPutFailure(f: ClientFacts, objectId: ObjectId, hash: LocalCompareHash | null): ClientFacts {
  const k = key(objectId, hash);
  const n = (f.uploadFailures.get(k) ?? 0) + 1;
  const facts = { ...f, uploadFailures: new Map(f.uploadFailures).set(k, n) };
  if (n < UPLOAD_TIMEOUT_MAX) return facts;
  const entry = facts.outbox.find((e) => !e.commitSent && e.objects.some((o) => o.objectId === objectId && o.localCompareHash === hash));
  return blockContent(entry ? retire(facts, entry.mutationId) : facts, objectId, hash, "UPLOAD_TIMEOUT_MAX");
}

// ---------------------------------------------------------------------------
// Commit results (§12.3, §12.5, rules 14-15).

export type DefinitiveRejection =
  | "CONFLICT"
  | "OBJECT_DELETED"
  | "BLOB_UNAVAILABLE"
  | "EPOCH_STALE"
  | "INVALID_BATCH"
  | "BLOB_ID_CONFLICT";

export interface ConfirmedRevision {
  readonly objectId: ObjectId;
  readonly revisionId: RevisionId;
  readonly sequence: number;
  readonly createdSequence: number;
}

export type CommitResult =
  | { readonly kind: "COMMITTED"; readonly revisions: readonly ConfirmedRevision[] }
  | {
      readonly kind: "REJECTED";
      readonly code: DefinitiveRejection;
      /** Heads the response carries (recorded in R). */
      readonly heads: ReadonlyArray<{ readonly objectId: ObjectId; readonly head: RemoteEntry }>;
      /** INVALID_BATCH: the listed entries; null when the response lists none. */
      readonly invalidObjects: readonly ObjectId[] | null;
    };

/**
 * Applies a commit response to the outbox. COMMITTED (rule 14) must match the entry exactly
 * (§12.3: the client checks the stored result); otherwise nothing is applied and `ok` is false.
 * `now` lets a BLOB_UNAVAILABLE caused by expired blobs halve the caps (§12.1).
 */
export function applyCommitResult(
  f: ClientFacts,
  mutationId: MutationId,
  result: CommitResult,
  now: number | null = null,
): { readonly ok: boolean; readonly facts: ClientFacts } {
  const entry = entryOf(f, mutationId);
  if (result.kind === "COMMITTED") {
    const matches =
      result.revisions.length === entry.objects.length &&
      entry.objects.every((o) => result.revisions.some((r) => r.objectId === o.objectId && r.revisionId === o.revisionId));
    return matches ? { ok: true, facts: confirm(f, entry, result.revisions) } : { ok: false, facts: f };
  }
  const attempt = f.attempts.find((a) => a.mutationId === mutationId);
  let facts = retire(f, mutationId);
  let remote = facts.remote;
  for (const { objectId, head } of result.heads) remote = recordRemoteHead(remote, objectId, head);
  facts = { ...facts, remote };
  if (result.code === "INVALID_BATCH") {
    const listed = new Set(result.invalidObjects ?? entry.objects.map((o) => o.objectId));
    const counts = new Map(facts.invalidBatchCounts);
    for (const o of entry.objects.filter((x) => listed.has(x.objectId))) {
      const k = key(o.objectId, o.localCompareHash);
      const n = (counts.get(k) ?? 0) + 1;
      counts.set(k, n);
      if (n >= 2) facts = blockContent(facts, o.objectId, o.localCompareHash, "INVALID_BATCH_REPEATED");
    }
    facts = { ...facts, invalidBatchCounts: counts };
  }
  if (result.code === "BLOB_UNAVAILABLE" && now !== null && attempt?.blobs.some((b) => b.expiresAt !== null && b.expiresAt <= now)) {
    facts = halveCaps(facts, entry);
  }
  return { ok: true, facts };
}

/** An event page carrying every revision of an own in-flight entry equals COMMITTED for it (§13.4). */
export function confirmByEcho(f: ClientFacts, mutationId: MutationId, revisions: readonly ConfirmedRevision[]): ClientFacts {
  return confirm(f, entryOf(f, mutationId), revisions);
}

/** Rule 14: S of each object := the confirmed revision; the entry and its attempt leave together. */
function confirm(f: ClientFacts, entry: OutboxEntry, revisions: readonly ConfirmedRevision[]): ClientFacts {
  const synced = new Map(f.synced);
  let remote = f.remote;
  const clear = new Set(entry.objects.map((o) => o.objectId));
  // The content blob this replica uploaded for the revision (§13.1): kept in S so that it can be read
  // again after a restart, when it is no longer a head.
  const attempt = f.attempts.find((a) => a.mutationId === entry.mutationId);
  const contentOf = (o: OutboxRevision): { content?: ContentRef | null } => {
    if (o.deleted) return { content: null };
    const blob = attempt?.blobs.find((b) => b.kind === "CONTENT" && b.objectId === o.objectId);
    return blob === undefined ? {} : { content: { blobId: blob.blobId, epochId: attempt!.epochId } };
  };
  for (const o of entry.objects) {
    const r = revisions.find((x) => x.objectId === o.objectId)!;
    const s: RevisionEntry = {
      revisionId: r.revisionId,
      sequence: r.sequence,
      path: o.path,
      localCompareHash: o.localCompareHash,
      deleted: o.deleted,
      createdSequence: r.createdSequence,
      ...contentOf(o),
    };
    synced.set(o.objectId, s);
    remote = recordRemoteHead(remote, o.objectId, s);
  }
  const keep = <V>(m: ReadonlyMap<string, V>) => new Map([...m].filter(([k]) => !clear.has(k.split("|")[0]!)));
  return {
    ...f,
    synced,
    remote,
    outbox: f.outbox.filter((e) => e.mutationId !== entry.mutationId),
    attempts: f.attempts.filter((a) => a.mutationId !== entry.mutationId),
    invalidBatchCounts: keep(f.invalidBatchCounts),
    uploadFailures: keep(f.uploadFailures),
    byteCaps: keep(f.byteCaps),
  };
}

export interface RevisionStatus {
  readonly revisionId: RevisionId;
  readonly exists: boolean;
  readonly objectId?: ObjectId;
  readonly sequence?: number;
}

/**
 * getRevisionStatus for an entry whose outcome is unknown (§12.1 table, §18.4). A revision exists only
 * if it belongs to the same object. All exist → COMMITTED; none → the entry may be re-encrypted;
 * some → impossible for an atomic commit: the entry is retired (diagnostic) and re-planned.
 */
export function applyRevisionStatus(f: ClientFacts, mutationId: MutationId, statuses: readonly RevisionStatus[]): ClientFacts {
  const entry = entryOf(f, mutationId);
  const found = entry.objects.map((o) =>
    statuses.find((st) => st.revisionId === o.revisionId && st.exists && st.objectId === o.objectId && st.sequence !== undefined),
  );
  if (found.every((x) => x !== undefined)) {
    const revisions = entry.objects.map((o, i) => {
      const sequence = found[i]!.sequence!;
      const createdSequence =
        o.expectedHeadRevisionId === null ? sequence : (f.synced.get(o.objectId) ?? f.remote.get(o.objectId))?.createdSequence ?? sequence;
      return { objectId: o.objectId, revisionId: o.revisionId, sequence, createdSequence };
    });
    return confirm(f, entry, revisions);
  }
  if (found.every((x) => x === undefined)) {
    return { ...f, outbox: f.outbox.map((e) => (e.mutationId === mutationId ? { ...e, commitSent: false } : e)) };
  }
  return retire(f, mutationId);
}

export type PrepareRejection = "BLOB_TOO_LARGE" | "EPOCH_STALE" | "BLOB_ID_CONFLICT" | "BLOB_UNAVAILABLE" | "BLOB_ALREADY_EXISTS" | "BLOB_CORRUPT";

/**
 * Prepare/PUT rejections (§11.1, §12.6). BLOB_TOO_LARGE: the server refuses this content (rule 8):
 * the entry, which never reached commit, is retired. EPOCH_STALE on a never-sent entry: retired
 * without risk. The others need new blob_ids: the attempt is dropped (its blobs to cleanup) and the
 * entry stays. An upload error never retires an entry by itself (rule 15).
 */
export function applyPrepareRejection(f: ClientFacts, mutationId: MutationId, blobId: BlobId, code: PrepareRejection): ClientFacts {
  const entry = entryOf(f, mutationId);
  const attempt = f.attempts.find((a) => a.mutationId === mutationId);
  if (code === "BLOB_TOO_LARGE") {
    const objectId = attempt?.blobs.find((b) => b.blobId === blobId)?.objectId;
    const o = entry.objects.find((x) => x.objectId === objectId);
    const facts = retire(f, mutationId);
    return o ? blockContent(facts, o.objectId, o.localCompareHash, "BLOB_TOO_LARGE") : facts;
  }
  if (code === "EPOCH_STALE") {
    if (entry.commitSent) throw new Error(`entry ${mutationId} was sent: getRevisionStatus first`);
    return retire(f, mutationId);
  }
  return {
    ...f,
    attempts: f.attempts.filter((a) => a.mutationId !== mutationId),
    cleanup: attempt ? withCleanup(f.cleanup, f, attempt) : f.cleanup,
  };
}

export type ReleaseResponse = "OK" | "VAULT_NOT_FOUND" | "BLOB_IN_USE" | "BLOB_ID_CONFLICT" | "UPLOAD_IN_PROGRESS" | "VAULT_DELETING";

/** Rule 13: which releaseUpload responses delete the cleanup record. None keeps it forever. */
export function applyRelease(f: ClientFacts, blobId: BlobId, response: ReleaseResponse): ClientFacts {
  const keep = response === "UPLOAD_IN_PROGRESS" || response === "VAULT_DELETING";
  return keep ? f : { ...f, cleanup: f.cleanup.filter((c) => c.blobId !== blobId) };
}

/** Re-enrollment (§18.3): records of a previous replica_id are discarded locally, never released. */
export function discardForeignCleanup(f: ClientFacts): ClientFacts {
  return { ...f, cleanup: f.cleanup.filter((c) => c.replicaId === f.replicaId) };
}

/**
 * §6: a trusted client's `replica_id` is its `recipient_id`, so a re-enrollment (§35.8, §18.3) changes
 * it. The vault's facts follow the replica that now leads: its id, and (§12.2 rule 13) no cleanup
 * record of the previous one, which the server would answer BLOB_ID_CONFLICT. Outbox and attempts
 * are kept (§18.3: "Revocar una réplica NO DEBE borrar su outbox"). Same id: the facts unchanged.
 */
export function adoptReplicaId(f: ClientFacts, replicaId: string): ClientFacts {
  return f.replicaId === replicaId ? f : discardForeignCleanup({ ...f, replicaId });
}

/** Records the current write epoch learned from the server (after EPOCH_STALE, §12.6). */
export function setWriteEpoch(f: ClientFacts, epochId: string): ClientFacts {
  return { ...f, epochId };
}

/** Records remote heads (events, commit responses); R never regresses (rule 3). */
export function recordRemoteHeads(f: ClientFacts, heads: ReadonlyArray<{ readonly objectId: ObjectId; readonly head: RemoteEntry }>): ClientFacts {
  let remote = f.remote;
  for (const { objectId, head } of heads) remote = recordRemoteHead(remote, objectId, head);
  return remote === f.remote ? f : { ...f, remote };
}
