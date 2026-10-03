// In-memory server, faithful to the client-visible contract of §10.3 (release), §11.1 (prepare),
// §11.2 (PUT), §12.3 and §12.5 (commit order and priorities), §10.5–10.6 (GC, pruning) and §18.4
// (getRevisionStatus). packages/control-plane runs the same contract and a differential test against
// the SQL implementation. Test harness only. Fake crypto: a blob's ciphertext carries its plaintext payload.

import type { CommitResult, ConfirmedRevision, DefinitiveRejection, PrepareRejection, ReleaseResponse, RevisionStatus } from "../../src/outbox.js";
import type { SyncEvent, VaultState } from "../../src/events.js";
import type { RemoteEntry } from "../../src/types.js";
import { text } from "../utf8.js";

export interface ServerRevision {
  readonly revisionId: string;
  readonly objectId: string;
  readonly sequence: number;
  readonly createdSequence: number;
  readonly path: string;
  readonly content: string;
  readonly deleted: boolean;
  /** Blobs the revision references (blob_refs, §10.6); absent for the revisions a scenario seeds. */
  readonly manifestBlobId?: string;
  readonly contentBlobId?: string | null;
}

export interface ServerBlob {
  readonly blobId: string;
  readonly owner: string;
  readonly epochId: string;
  readonly kind: "CONTENT" | "MANIFEST";
  readonly declaredSize: number;
  readonly sha: string;
  readonly forDelete: boolean;
  /** §35.13: the revision the blob was prepared to re-encrypt (`for_reencrypt`), or null. */
  readonly forReencrypt: string | null;
  state: "PENDING" | "CONFIRMED" | "GARBAGE_CANDIDATE" | "DELETING" | "DELETED";
  /** Revisions that reference it (§10.6); only pruning decrements it. */
  refcount: number;
  stateChangedAt: number;
  /** Ciphertext registered by a completed PUT (r2_etag not null). */
  payload: string | null;
  readonly expiresAt: number;
}

export interface CommitRequest {
  readonly mutationId: string;
  readonly epochId: string;
  readonly revisions: ReadonlyArray<{
    readonly objectId: string;
    readonly revisionId: string;
    readonly expectedHeadRevisionId: string | null;
    readonly deleted: boolean;
    readonly manifestBlobId: string;
    readonly contentBlobId: string | null;
  }>;
}

export interface ServerConfig {
  readonly pendingBudgetBytes: number;
  readonly maxBlobBytes: number;
  /** expires_in of a new PENDING upload (time units of the simulation). */
  readonly uploadWindow: number;
  /** §10.3 GC grace (24 h in the spec), in time units; default 86 400. */
  readonly gcGrace?: number;
  /** Broken variants for evidence tests. */
  readonly brokenNoIdempotency?: boolean;
  readonly brokenEpochCheckOnRetry?: boolean;
  /** Broken: pages are cut at the limit even inside a batch (§13.2 forbids it). */
  readonly brokenSplitPages?: boolean;
  /** Broken: commits over a deleted head are accepted (resurrection, §18.1). */
  readonly brokenAllowResurrection?: boolean;
  /** listEvents page size (the spec uses 500-1000; small here to exercise pagination). */
  readonly pageLimit?: number;
  /** Broken: reencryptRevision keeps the old blobs referenced and never deletes them (evidence tests, §35.13). */
  readonly brokenReencryptKeepsOld?: boolean;
  /** Broken: reencryptRevision accepts new blobs of any epoch (§35.13 step 4, EPOCH_STALE). */
  readonly brokenReencryptAnyEpoch?: boolean;
  /** Broken: an old blob the swap leaves unreferenced stays CONFIRMED instead of going to DELETING (§35.13 step 5). */
  readonly brokenReencryptLeavesOld?: boolean;
  /** Broken: reencryptRevision re-commits the revision at a new sequence instead of swapping it in place (§35.13 step 6). */
  readonly brokenReencryptNewSequence?: boolean;
}

export interface Server {
  now: number;
  seq: number;
  epoch: string;
  epochs: number;
  readonly heads: Map<string, ServerRevision>;
  readonly revisions: Map<string, ServerRevision>;
  readonly revisionMutation: Map<string, string>;
  readonly blobs: Map<string, ServerBlob>;
  /** Stored results of COMMITTED mutations (rows may expire, §18.4). */
  readonly mutations: Map<string, ConfirmedRevision[]>;
  /** sync_events (§13.1); events at or below cursor_floor may be gone (§13.6). */
  events: SyncEvent[];
  /** §10.6 step 7 and §13.3. */
  minApplicableSequence: number;
  /** Pruned revisions (§10.6): their content can no longer be downloaded. */
  readonly pruned: Set<string>;
  /** Every sequence that ends a batch (a valid cursor position, §13.2). */
  readonly batchEnds: Set<number>;
  /** §35.13: `vault.private_since_epoch_id`, set by a SWITCH_TO_PRIVATE; null for a vault never switched. */
  privateSince: string | null;
  /** §3.6: the account has an escrow row (Managed); the model starts Private, like an account without one. */
  managed: boolean;
  readonly config: ServerConfig;
  readonly log: {
    /** How many times each mutation_id was applied (must be ≤ 1). */
    readonly applied: Map<string, number>;
    /** Commit calls for a mutation that was already applied, with their response kind. */
    readonly retriesOfCommitted: Array<{ mutationId: string; response: string }>;
    /** Prepares of CONTENT blobs: object and plaintext hash, in order. */
    readonly contentPrepares: Array<{ objectId: string; payload: string; at: number }>;
    /** COMMITTED results rebuilt from object_revisions after the mutations row expired (§12.3 step 5). */
    reconstructed: number;
  };
}

export function newServer(config: ServerConfig): Server {
  return {
    now: 0,
    seq: 0,
    epoch: "e1",
    epochs: 1,
    heads: new Map(),
    revisions: new Map(),
    revisionMutation: new Map(),
    blobs: new Map(),
    mutations: new Map(),
    events: [],
    minApplicableSequence: 0,
    pruned: new Set(),
    batchEnds: new Set([0]),
    privateSince: null,
    managed: false,
    config,
    log: { applied: new Map(), retriesOfCommitted: [], contentPrepares: [], reconstructed: 0 },
  };
}

export const headEntry = (r: ServerRevision): RemoteEntry => ({
  revisionId: r.revisionId,
  sequence: r.sequence,
  path: r.path,
  localCompareHash: null,
  deleted: r.deleted,
  createdSequence: r.createdSequence,
});

const pendingBytes = (s: Server) =>
  [...s.blobs.values()].filter((b) => b.state === "PENDING" && !b.forDelete && b.forReencrypt === null && b.expiresAt > s.now).reduce((n, b) => n + b.declaredSize, 0);

/** §35.13 REENCRYPT_IN_FLIGHT (initial value). */
export const REENCRYPT_IN_FLIGHT = 4;

/** §11.1: a for_delete manifest is capped at 16 KiB, whatever the plan limit. */
export const FOR_DELETE_MAX_BYTES = 16_384;
/**
 * §31.3 framing of a sealed blob: a 12-byte nonce and a 16-byte tag. `maxBlobBytes` limits the FILE (§40,
 * control-plane NOTES question 381), so a CONTENT blob may be that many plaintext bytes sealed; a manifest
 * keeps `maxBlobBytes` on its ciphertext (SQL: nodra_ciphertext_size).
 */
export const CONTENT_FRAMING_BYTES = 28;

export interface PrepareRequest {
  readonly blobId: string;
  readonly epochId: string;
  readonly kind: "CONTENT" | "MANIFEST";
  readonly declaredSize: number;
  readonly sha: string;
  readonly forDelete: boolean;
  /** §35.13: the revision this blob re-encrypts; absent or null otherwise. */
  readonly forReencrypt?: string | null;
  /** Test log only: which object and plaintext the blob carries. */
  readonly objectId: string;
  readonly plaintext: string | null;
}

export type PrepareResponse = { readonly ok: true; readonly expiresIn: number } | { readonly ok: false; readonly code: PrepareRejection | "PENDING_BUDGET_EXCEEDED" };

/** §11.1 prepare. */
export function prepare(s: Server, replica: string, req: PrepareRequest): PrepareResponse {
  const forReencrypt = req.forReencrypt ?? null;
  const row = s.blobs.get(req.blobId);
  if (row) {
    if (row.owner !== replica) return { ok: false, code: "BLOB_ID_CONFLICT" };
    const same =
      row.epochId === req.epochId &&
      row.kind === req.kind &&
      row.forDelete === req.forDelete &&
      row.declaredSize === req.declaredSize &&
      row.sha === req.sha &&
      row.forReencrypt === forReencrypt;
    const live = row.state === "PENDING" && row.expiresAt > s.now;
    if (same && live) return { ok: true, expiresIn: row.expiresAt - s.now };
    // §11.1 table order: a row no longer live answers BLOB_UNAVAILABLE even with other parameters.
    return { ok: false, code: live ? "BLOB_ID_CONFLICT" : "BLOB_UNAVAILABLE" };
  }
  if (req.kind === "CONTENT") s.log.contentPrepares.push({ objectId: req.objectId, payload: req.plaintext ?? "", at: s.now });
  if (req.forDelete && req.kind === "CONTENT") return { ok: false, code: "BLOB_TOO_LARGE" };
  const maxSize = req.forDelete ? FOR_DELETE_MAX_BYTES : req.kind === "CONTENT" ? s.config.maxBlobBytes + CONTENT_FRAMING_BYTES : s.config.maxBlobBytes;
  if (req.declaredSize > maxSize) return { ok: false, code: "BLOB_TOO_LARGE" };
  if (forReencrypt !== null) {
    // §35.13: exempt from the general budget, capped at REENCRYPT_IN_FLIGHT revisions with PENDING blobs.
    const inFlight = new Set([...s.blobs.values()].filter((b) => b.state === "PENDING" && b.forReencrypt !== null && b.forReencrypt !== forReencrypt).map((b) => b.forReencrypt));
    if (inFlight.size >= REENCRYPT_IN_FLIGHT) return { ok: false, code: "PENDING_BUDGET_EXCEEDED" };
  }
  // for_delete manifests are exempt from the general budget (their own caps of §40.1 are not modelled).
  else if (!req.forDelete && pendingBytes(s) + req.declaredSize > s.config.pendingBudgetBytes) return { ok: false, code: "PENDING_BUDGET_EXCEEDED" };
  if (req.epochId !== s.epoch) return { ok: false, code: "EPOCH_STALE" };
  s.blobs.set(req.blobId, {
    blobId: req.blobId,
    owner: replica,
    epochId: req.epochId,
    kind: req.kind,
    declaredSize: req.declaredSize,
    sha: req.sha,
    forDelete: req.forDelete,
    forReencrypt,
    state: "PENDING",
    payload: null,
    refcount: 0,
    stateChangedAt: s.now,
    expiresAt: s.now + s.config.uploadWindow,
  });
  return { ok: true, expiresIn: s.config.uploadWindow };
}

/** §11.2 PUT (the lease is not modelled: one client, sequential requests). */
export function put(s: Server, replica: string, blobId: string, ciphertext: Uint8Array): { ok: true } | { ok: false; code: PrepareRejection } {
  const row = s.blobs.get(blobId);
  if (!row) return { ok: false, code: "BLOB_UNAVAILABLE" };
  if (row.owner !== replica) return { ok: false, code: "BLOB_ID_CONFLICT" };
  if (row.payload !== null && row.state !== "DELETING") return { ok: true };
  if (row.state !== "PENDING" || row.expiresAt <= s.now) return { ok: false, code: "BLOB_UNAVAILABLE" };
  row.payload = text(ciphertext);
  return { ok: true };
}

/** §10.3 releaseUpload responses. */
export function release(s: Server, replica: string, blobId: string): ReleaseResponse {
  const row = s.blobs.get(blobId);
  if (row && row.owner !== replica) return "BLOB_ID_CONFLICT";
  if (!row || row.state === "DELETING" || row.state === "DELETED") return "OK";
  if (row.state !== "PENDING") return "BLOB_IN_USE";
  row.state = "DELETING";
  return "OK";
}

/** §18.4 getRevisionStatus. */
export function revisionStatus(s: Server, revisionIds: readonly string[]): RevisionStatus[] {
  return revisionIds.map((revisionId) => {
    const r = s.revisions.get(revisionId);
    return r ? { revisionId, exists: true, objectId: r.objectId, sequence: r.sequence } : { revisionId, exists: false };
  });
}

const PRIORITY: DefinitiveRejection[] = ["INVALID_BATCH", "EPOCH_STALE", "BLOB_UNAVAILABLE", "OBJECT_DELETED", "CONFLICT"];

/** §12.3 + §12.5 commit, including the stored result and its reconstruction. */
export function commit(s: Server, replica: string, req: CommitRequest): CommitResult {
  const stored = s.config.brokenNoIdempotency ? undefined : s.mutations.get(req.mutationId);
  const alreadyApplied = (s.log.applied.get(req.mutationId) ?? 0) > 0;
  const respond = (r: CommitResult): CommitResult => {
    if (alreadyApplied) s.log.retriesOfCommitted.push({ mutationId: req.mutationId, response: r.kind === "COMMITTED" ? "COMMITTED" : r.code });
    return r;
  };
  if (stored && !(s.config.brokenEpochCheckOnRetry && req.epochId !== s.epoch)) return respond({ kind: "COMMITTED", revisions: stored });
  if (s.config.brokenEpochCheckOnRetry && stored) return respond({ kind: "REJECTED", code: "EPOCH_STALE", heads: [], invalidObjects: null });

  // Blob ownership (§12.5 step 2), before the re-lookup of step 3.
  for (const r of req.revisions) {
    for (const id of [r.manifestBlobId, r.contentBlobId]) {
      const b = id === null ? undefined : s.blobs.get(id);
      if (b && b.state === "PENDING" && b.owner !== replica) return respond({ kind: "REJECTED", code: "BLOB_ID_CONFLICT", heads: [], invalidObjects: null });
    }
  }

  // §12.3 step 5: the mutations row expired but revision_ids exist.
  if (!s.config.brokenNoIdempotency) {
    const existing = req.revisions.filter((r) => s.revisions.has(r.revisionId));
    if (existing.length > 0) {
      const all =
        existing.length === req.revisions.length && req.revisions.every((r) => s.revisions.get(r.revisionId)!.objectId === r.objectId);
      if (!all) return respond({ kind: "REJECTED", code: "INVALID_BATCH", heads: [], invalidObjects: existing.map((r) => r.objectId) });
      s.log.reconstructed++;
      return respond({
        kind: "COMMITTED",
        revisions: req.revisions.map((r) => {
          const rev = s.revisions.get(r.revisionId)!;
          return { objectId: r.objectId, revisionId: r.revisionId, sequence: rev.sequence, createdSequence: rev.createdSequence };
        }),
      });
    }
  }

  // Shape.
  const invalid = (objects: string[] | null): CommitResult => ({ kind: "REJECTED", code: "INVALID_BATCH", heads: [], invalidObjects: objects });
  if (req.revisions.length === 0 || req.revisions.length > 500) return respond(invalid(null));
  const dup = (f: (r: CommitRequest["revisions"][number]) => string) =>
    req.revisions.filter((r, i) => req.revisions.findIndex((x) => f(x) === f(r)) !== i).map((r) => r.objectId);
  const dups = [...dup((r) => r.objectId), ...dup((r) => r.revisionId), ...dup((r) => r.manifestBlobId)];
  if (dups.length > 0) return respond(invalid(dups));

  const codes = new Set<DefinitiveRejection>();
  const invalidObjects: string[] = [];
  const affected = new Set<string>();
  if (req.epochId !== s.epoch) codes.add("EPOCH_STALE");
  for (const r of req.revisions) {
    const head = s.heads.get(r.objectId);
    if (r.expectedHeadRevisionId === null && r.deleted) {
      codes.add("INVALID_BATCH");
      invalidObjects.push(r.objectId);
    }
    const checkHeads = !s.config.brokenNoIdempotency;
    const deletedOk = s.config.brokenAllowResurrection && head?.deleted && head.revisionId === r.expectedHeadRevisionId;
    if (checkHeads && head && !deletedOk && (r.expectedHeadRevisionId === null || head.deleted || head.revisionId !== r.expectedHeadRevisionId)) {
      codes.add(head.deleted ? "OBJECT_DELETED" : "CONFLICT");
      affected.add(r.objectId);
    }
    if (checkHeads && !head && r.expectedHeadRevisionId !== null) {
      codes.add("CONFLICT");
      affected.add(r.objectId);
    }
    if (r.deleted !== (r.contentBlobId === null)) {
      codes.add("INVALID_BATCH");
      invalidObjects.push(r.objectId);
    }
    for (const [id, manifest] of [
      [r.manifestBlobId, true],
      [r.contentBlobId, false],
    ] as const) {
      if (id === null) continue;
      const b = s.blobs.get(id);
      if (!b || b.state === "DELETING" || b.state === "DELETED") {
        codes.add("BLOB_UNAVAILABLE");
        continue;
      }
      // A manifest is specific to its revision (§8): it must be a PENDING manifest; a content blob a CONTENT one.
      // The role comes from the field, not the id: the same blob may be named in both.
      if (b.kind !== (manifest ? "MANIFEST" : "CONTENT") || (manifest && b.state !== "PENDING")) {
        codes.add("INVALID_BATCH");
        invalidObjects.push(r.objectId);
      }
      // Every condition is noted (§12.5): an expired blob of an old epoch is both.
      if (b.state === "PENDING" && (b.expiresAt <= s.now || b.payload === null)) codes.add("BLOB_UNAVAILABLE");
      if (b.state === "PENDING" && b.epochId !== s.epoch) codes.add("EPOCH_STALE");
    }
  }
  // Broken variant: no idempotency and no validation at all (every request is applied).
  const top = s.config.brokenNoIdempotency ? undefined : PRIORITY.find((c) => codes.has(c));
  if (top) {
    // An expected head on an object that does not exist is a CONFLICT with no head to carry.
    const heads = [...affected].flatMap((objectId) => {
      const h = s.heads.get(objectId);
      return h ? [{ objectId, head: headEntry(h) }] : [];
    });
    return respond({ kind: "REJECTED", code: top, heads, invalidObjects: top === "INVALID_BATCH" ? invalidObjects : null });
  }

  const revisions: ConfirmedRevision[] = [];
  for (const [batchIndex, r] of req.revisions.entries()) {
    s.seq++;
    const prev = s.heads.get(r.objectId);
    const manifest = JSON.parse(s.blobs.get(r.manifestBlobId)!.payload!.split("|").slice(1).join("|")) as { path: string };
    const rev: ServerRevision = {
      revisionId: r.revisionId,
      objectId: r.objectId,
      sequence: s.seq,
      createdSequence: prev?.createdSequence ?? s.seq,
      path: manifest.path,
      content: r.contentBlobId === null ? "" : s.blobs.get(r.contentBlobId)!.payload!.split("|").slice(1).join("|"),
      deleted: r.deleted,
      manifestBlobId: r.manifestBlobId,
      contentBlobId: r.contentBlobId,
    };
    s.heads.set(r.objectId, rev);
    s.revisions.set(rev.revisionId, rev);
    s.revisionMutation.set(rev.revisionId, req.mutationId);
    appendEvent(s, rev, prev?.revisionId ?? null, req.mutationId, batchIndex, req.revisions.length);
    for (const id of [r.manifestBlobId, r.contentBlobId]) {
      if (id === null) continue;
      const b = s.blobs.get(id)!;
      if (b.state !== "CONFIRMED") b.stateChangedAt = s.now;
      b.state = "CONFIRMED";
      b.refcount++;
    }
    revisions.push({ objectId: r.objectId, revisionId: r.revisionId, sequence: rev.sequence, createdSequence: rev.createdSequence });
  }
  s.mutations.set(req.mutationId, revisions);
  s.log.applied.set(req.mutationId, (s.log.applied.get(req.mutationId) ?? 0) + 1);
  return respond({ kind: "COMMITTED", revisions });
}

// ---------------------------------------------------------------------------
// The remote writer: stands in for other replicas (true multi-replica is the next slice).

export function remoteCommit(s: Server, objectId: string, change: { path: string; content: string; deleted: boolean }): ServerRevision {
  s.seq++;
  const prev = s.heads.get(objectId);
  const revisionId = `${objectId}@${s.seq}`;
  // Its blobs, as the other replica uploaded them in the write epoch; a rename keeps the content blob (§7).
  const reuse = !change.deleted && prev !== undefined && !prev.deleted && prev.content === change.content && prev.contentBlobId ? prev.contentBlobId : null;
  const blobs = storedBlobs(s, revisionId, { objectId, parentRevisionId: prev?.revisionId ?? null, ...change }, reuse);
  const rev: ServerRevision = {
    revisionId,
    objectId,
    sequence: s.seq,
    createdSequence: prev?.createdSequence ?? s.seq,
    ...change,
    ...blobs,
  };
  s.heads.set(objectId, rev);
  s.revisions.set(rev.revisionId, rev);
  appendEvent(s, rev, prev?.revisionId ?? null, `remote-${rev.sequence}`, 0, 1);
  return rev;
}

/** The manifest payload a replica seals for a revision (the dev codec: JSON with at least `path`). */
export const manifestPayload = (m: { objectId: string; revisionId: string; parentRevisionId: string | null; path: string; deleted: boolean }) =>
  JSON.stringify({ objectId: m.objectId, revisionId: m.revisionId, parentRevisionId: m.parentRevisionId, path: m.path, mtimeMs: 0, deleted: m.deleted });

/**
 * CONFIRMED blobs in the write epoch for a revision another replica committed (fake crypto: the
 * ciphertext is `<blobId>|<payload>`), counted in their refcounts. `reuse`: a content blob it keeps.
 */
function storedBlobs(
  s: Server,
  revisionId: string,
  r: { objectId: string; parentRevisionId: string | null; path: string; content: string; deleted: boolean },
  reuse: string | null,
): { manifestBlobId: string; contentBlobId: string | null } {
  const store = (blobId: string, kind: ServerBlob["kind"], payload: string) => {
    s.blobs.set(blobId, {
      blobId,
      owner: "remote",
      epochId: s.epoch,
      kind,
      declaredSize: payload.length,
      sha: `sha(${blobId})`,
      forDelete: false,
      forReencrypt: null,
      state: "CONFIRMED",
      refcount: 1,
      stateChangedAt: s.now,
      payload: `${blobId}|${payload}`,
      expiresAt: s.now,
    });
  };
  const manifestBlobId = `rb-${revisionId}-m`;
  store(manifestBlobId, "MANIFEST", manifestPayload({ ...r, revisionId }));
  if (r.deleted) return { manifestBlobId, contentBlobId: null };
  if (reuse !== null && s.blobs.get(reuse)?.state === "CONFIRMED") {
    s.blobs.get(reuse)!.refcount++;
    return { manifestBlobId, contentBlobId: reuse };
  }
  const contentBlobId = `rb-${revisionId}-c`;
  store(contentBlobId, "CONTENT", r.content);
  return { manifestBlobId, contentBlobId };
}

/**
 * Gives every revision without blobs (the ones a scenario seeds) its manifest and content blobs in the
 * write epoch, so that each revision on the server lives in some epoch (§35.13 lists by epoch).
 */
export function attachBlobs(s: Server): void {
  for (const r of [...s.revisions.values()].sort((a, b) => a.sequence - b.sequence)) {
    if (r.manifestBlobId !== undefined) continue;
    // A revision with its parent's bytes (a rename, §7) keeps its parent's content blob, as a replica does.
    const parentId = parentOf(s, r);
    const parent = parentId === null ? undefined : s.revisions.get(parentId);
    const reuse = !r.deleted && parent !== undefined && !parent.deleted && parent.content === r.content ? (parent.contentBlobId ?? null) : null;
    replaceRevision(s, { ...r, ...storedBlobs(s, r.revisionId, { ...r, parentRevisionId: parentId }, reuse) });
  }
}

/** A revision row changed in place (its blobs): the same object in `revisions` and, if head, `heads`. */
function replaceRevision(s: Server, r: ServerRevision): void {
  s.revisions.set(r.revisionId, r);
  if (s.heads.get(r.objectId)?.revisionId === r.revisionId) s.heads.set(r.objectId, r);
}

// ---------------------------------------------------------------------------
// §35.13 history re-encryption.

/** Position of a model epoch (`e<n>`) in the vault's chain. */
export const epochIndex = (epochId: string): number => Number(epochId.slice(1));

/** SWITCH_TO_PRIVATE as the sync path sees it (§35.13 steps 9 and 11): a new epoch, and private_since = it. */
export function switchToPrivate(s: Server): void {
  rotateEpoch(s);
  s.privateSince = s.epoch;
  s.managed = false;
}

export interface RevisionToReencrypt {
  readonly revisionId: string;
  readonly objectId: string;
  readonly parentRevisionId: string | null;
  readonly deleted: boolean;
  readonly manifestBlobId: string;
  readonly manifestEpochId: string;
  readonly contentBlobId: string | null;
  readonly contentEpochId: string | null;
}

export type ReencryptPage =
  | { readonly kind: "PAGE"; readonly revisions: readonly RevisionToReencrypt[]; readonly next: string | null }
  | { readonly kind: "INVALID_STATE" };

/** The parent of a revision (§13.1 `parent_revision_id`): the object's previous revision. */
function parentOf(s: Server, r: ServerRevision): string | null {
  let parent: ServerRevision | undefined;
  for (const x of s.revisions.values()) if (x.objectId === r.objectId && x.sequence < r.sequence && (parent === undefined || x.sequence > parent.sequence)) parent = x;
  return parent?.revisionId ?? null;
}

type Key = readonly [number, string, string];
const keyOf = (contentBlobId: string | null, revisionId: string): Key => [contentBlobId === null ? 1 : 0, contentBlobId ?? "", revisionId];
const str = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const cmpKey = (a: Key, b: Key) => a[0] - b[0] || str(a[1], b[1]) || str(a[2], b[2]);

/** §35.13 listRevisionsToReencrypt, with the SQL's order (old content, then revision; deletes last) and cursor. */
export function listToReencrypt(s: Server, after: string | null, limit: number): ReencryptPage {
  if (s.managed) return { kind: "INVALID_STATE" };
  if (s.privateSince === null) return { kind: "PAGE", revisions: [], next: null };
  const since = epochIndex(s.privateSince);
  const old = (blobId: string | null | undefined) => blobId != null && s.blobs.has(blobId) && epochIndex(s.blobs.get(blobId)!.epochId) < since;
  const [c, r] = after === null ? [null, null] : after.split("/");
  const from = after === null ? null : keyOf(c === "-" ? null : c!, r!);
  const rows = [...s.revisions.values()]
    .filter((x) => !s.pruned.has(x.revisionId) && x.manifestBlobId !== undefined && (old(x.manifestBlobId) || old(x.contentBlobId)))
    .map((x) => ({ x, k: keyOf(x.contentBlobId ?? null, x.revisionId) }))
    .filter(({ k }) => from === null || cmpKey(k, from) > 0)
    .sort((a, b) => cmpKey(a.k, b.k));
  const page = rows.slice(0, limit).map(({ x }) => ({
    revisionId: x.revisionId,
    objectId: x.objectId,
    parentRevisionId: parentOf(s, x),
    deleted: x.deleted,
    manifestBlobId: x.manifestBlobId!,
    manifestEpochId: s.blobs.get(x.manifestBlobId!)!.epochId,
    contentBlobId: x.contentBlobId ?? null,
    contentEpochId: x.contentBlobId == null ? null : s.blobs.get(x.contentBlobId)!.epochId,
  }));
  const last = page[page.length - 1];
  return { kind: "PAGE", revisions: page, next: rows.length > limit && last ? `${last.contentBlobId ?? "-"}/${last.revisionId}` : null };
}

export interface ReencryptRequest {
  readonly revisionId: string;
  readonly expectedManifestBlobId: string;
  readonly newManifestBlobId: string;
  readonly newContentBlobId: string | null;
}

export type ReencryptCode = "INVALID_STATE" | "REVISION_NOT_FOUND" | "REVISION_PRUNED" | "REVISION_CHANGED" | "EPOCH_STALE" | "INVALID_BATCH";
export type ReencryptResult = { readonly ok: true } | { readonly ok: false; readonly code: ReencryptCode };

/** §35.13 reencryptRevision (steps 1–6), with the SQL's order of answers. */
export function reencrypt(s: Server, replica: string, req: ReencryptRequest): ReencryptResult {
  if (s.managed) return { ok: false, code: "INVALID_STATE" };
  const r = s.revisions.get(req.revisionId);
  if (!r) return { ok: false, code: "REVISION_NOT_FOUND" };
  if (s.pruned.has(r.revisionId)) return { ok: false, code: "REVISION_PRUNED" };
  if (r.manifestBlobId === req.newManifestBlobId && (r.contentBlobId ?? null) === req.newContentBlobId) return { ok: true };
  if (r.manifestBlobId !== req.expectedManifestBlobId) return { ok: false, code: "REVISION_CHANGED" };
  let invalid = r.deleted !== (req.newContentBlobId === null);
  let stale = false;
  for (const [id, kind] of [
    [req.newManifestBlobId, "MANIFEST"],
    [req.newContentBlobId, "CONTENT"],
  ] as const) {
    if (id === null) continue;
    const b = s.blobs.get(id);
    if (!b || b.kind !== kind) {
      invalid = true;
      continue;
    }
    if (b.state === "PENDING") {
      if (b.owner !== replica || b.forReencrypt !== r.revisionId || b.payload === null || b.expiresAt <= s.now) invalid = true;
    } else if (!(kind === "CONTENT" && b.state === "CONFIRMED")) invalid = true;
    if (b.epochId !== s.epoch && !s.config.brokenReencryptAnyEpoch) stale = true;
  }
  if (invalid) return { ok: false, code: "INVALID_BATCH" };
  if (stale) return { ok: false, code: "EPOCH_STALE" };
  for (const id of [req.newManifestBlobId, req.newContentBlobId]) {
    if (id === null) continue;
    const b = s.blobs.get(id)!;
    if (b.state !== "CONFIRMED") b.stateChangedAt = s.now;
    b.state = "CONFIRMED";
    b.refcount++;
  }
  if (!s.config.brokenReencryptKeepsOld) {
    for (const id of [r.manifestBlobId, r.contentBlobId]) {
      const b = id == null ? undefined : s.blobs.get(id);
      if (!b) continue;
      b.refcount--;
      // §35.13 step 5: an old blob nobody references goes to DELETING in the same call.
      if (b.refcount === 0 && !s.config.brokenReencryptLeavesOld) {
        b.state = "DELETING";
        b.stateChangedAt = s.now;
      }
    }
  }
  const sequence = s.config.brokenReencryptNewSequence ? ++s.seq : r.sequence;
  replaceRevision(s, { ...r, sequence, manifestBlobId: req.newManifestBlobId, contentBlobId: req.newContentBlobId });
  return { ok: true };
}

/** Epoch rotation (§34): a new current write epoch. */
export function rotateEpoch(s: Server): void {
  s.epochs++;
  s.epoch = `e${s.epochs}`;
  s.seq++;
  s.events.push({ kind: "EPOCH_ROTATED", sequence: s.seq, epochId: s.epoch, batchIndex: 0, batchSize: 1 });
  s.batchEnds.add(s.seq);
}

/** The mutations rows expire (§18.4 keeps them ≥ 180 days; the test shortens it). */
export function expireMutationRows(s: Server): void {
  s.mutations.clear();
}

/** PENDING uploads of a replica (§10.3), for property (f). */
export function pendingOf(s: Server, replica: string): string[] {
  return [...s.blobs.values()].filter((b) => b.owner === replica && b.state === "PENDING").map((b) => b.blobId);
}

// ---------------------------------------------------------------------------
// Events (§13), pruning (§10.6) and getVaultState (§18.4).

/** Appends the REVISION event of a revision already inserted with sequence `rev.sequence`. */
export function appendEvent(s: Server, rev: ServerRevision, parentRevisionId: string | null, mutationId: string, batchIndex: number, batchSize: number): void {
  s.events.push({
    kind: "REVISION",
    sequence: rev.sequence,
    objectId: rev.objectId,
    revisionId: rev.revisionId,
    parentRevisionId,
    path: rev.path,
    deleted: rev.deleted,
    createdSequence: rev.createdSequence,
    mutationId,
    batchIndex,
    batchSize,
  });
  if (batchIndex === batchSize - 1) s.batchEnds.add(rev.sequence);
}

/** §13.3: cursor_floor (min_event_sequence is not modelled apart: pruning drives the floor). */
export const cursorFloor = (s: Server) => s.minApplicableSequence;

/** §13.2 listEvents: CURSOR_EXPIRED below the floor; a page never splits a batch. */
export function listEvents(s: Server, after: number): { kind: "PAGE"; events: SyncEvent[] } | { kind: "CURSOR_EXPIRED" } {
  if (after < cursorFloor(s)) return { kind: "CURSOR_EXPIRED" };
  const limit = s.config.pageLimit ?? 3;
  const pending = s.events.filter((e) => e.sequence > after);
  const page: SyncEvent[] = [];
  for (let i = 0; i < pending.length; ) {
    const size = pending[i]!.batchSize - pending[i]!.batchIndex;
    const batch = pending.slice(i, i + size);
    if (s.config.brokenSplitPages) {
      page.push(...batch.slice(0, limit - page.length));
      if (page.length >= limit) break;
    } else {
      if (page.length > 0 && page.length + batch.length > limit) break;
      page.push(...batch);
    }
    i += size;
  }
  return { kind: "PAGE", events: page };
}

/** §10.6: prune every revision that is no longer head; the floor moves to the end of their batches. */
export function prune(s: Server): void {
  const heads = new Set([...s.heads.values()].map((h) => h.revisionId));
  for (const r of s.revisions.values()) {
    if (heads.has(r.revisionId) || s.pruned.has(r.revisionId)) continue;
    s.pruned.add(r.revisionId);
    // §10.6 step 6: drop its references; a blob nobody references becomes a GC candidate.
    for (const id of [r.manifestBlobId, r.contentBlobId]) {
      const b = id === undefined || id === null ? undefined : s.blobs.get(id);
      if (!b) continue;
      b.refcount--;
      if (b.refcount === 0 && b.state === "CONFIRMED") {
        b.state = "GARBAGE_CANDIDATE";
        b.stateChangedAt = s.now;
      }
    }
    const e = s.events.find((x) => x.sequence === r.sequence);
    const batchEnd = e ? e.sequence + (e.batchSize - 1 - e.batchIndex) : r.sequence;
    s.minApplicableSequence = Math.max(s.minApplicableSequence, batchEnd);
  }
  // §13.6: events at or below the floor may be deleted.
  s.events = s.events.filter((e) => e.sequence > cursorFloor(s));
}

/**
 * §10.5 GC pass: expired PENDING (plus the grace) and GARBAGE_CANDIDATE past the grace go to
 * DELETING; every DELETING blob is then deleted from storage and becomes DELETED (no PUT leases here).
 */
export function gc(s: Server): void {
  const grace = s.config.gcGrace ?? 86_400;
  for (const b of s.blobs.values()) {
    const expired = b.state === "PENDING" && b.expiresAt + grace <= s.now;
    const garbage = b.state === "GARBAGE_CANDIDATE" && b.stateChangedAt + grace <= s.now;
    if (b.refcount === 0 && (expired || garbage)) {
      b.state = "DELETING";
      b.stateChangedAt = s.now;
    }
  }
  for (const b of s.blobs.values()) {
    if (b.state !== "DELETING") continue;
    b.state = "DELETED";
    b.payload = null;
    b.stateChangedAt = s.now;
  }
}

/** §18.4 getVaultState: every head (graveyard included) consistent at N = latest sequence. */
export function vaultState(s: Server): VaultState {
  return { sequence: s.seq, epochId: s.epoch, heads: [...s.heads.values()].map((h) => ({ objectId: h.objectId, head: headEntry(h) })) };
}

// ---------------------------------------------------------------------------
// §44.5 invariants of the model's rows, checked after every step of a run.

/**
 * Violations of the server-side §44.5 invariants the model can state, with `ledger` remembering the
 * first payload of each CONFIRMED blob across calls:
 *   - un blob CONFIRMED nunca cambia de contenido;
 *   - una revisión nunca referencia un blob PENDING ajeno, DELETING o DELETED (nor a missing one);
 *   - un blob con refcount > 0 nunca pasa a DELETING;
 *   - refcount = número de blob_refs de revisiones no podadas;
 *   - a revision's blobs carry its own plaintext and path (§35.13: a re-encryption changes neither).
 */
export function modelInvariants(s: Server, ledger: Map<string, string>): string[] {
  const out: string[] = [];
  const refs = new Map<string, number>();
  for (const r of s.revisions.values()) {
    if (s.pruned.has(r.revisionId) || r.manifestBlobId === undefined) continue;
    for (const [id, kind] of [
      [r.manifestBlobId, "MANIFEST"],
      [r.contentBlobId ?? null, "CONTENT"],
    ] as const) {
      if (id === null) continue;
      refs.set(id, (refs.get(id) ?? 0) + 1);
      const b = s.blobs.get(id);
      if (b === undefined || b.state === "DELETING" || b.state === "DELETED" || b.state === "PENDING") {
        out.push(`references: ${r.revisionId} → ${id} ${b?.state ?? "missing"}`);
        continue;
      }
      if (b.kind !== kind) out.push(`references: ${r.revisionId} → ${id} is a ${b.kind}`);
      const payload = b.payload === null ? null : b.payload.slice(b.payload.indexOf("|") + 1);
      if (kind === "CONTENT" && payload !== r.content) out.push(`plaintext: ${r.revisionId} reads ${JSON.stringify(payload)}, not ${JSON.stringify(r.content)}`);
      if (kind === "MANIFEST" && payload !== null) {
        let path: string | undefined;
        try {
          path = (JSON.parse(payload) as { path?: string }).path;
        } catch {
          path = `<not a manifest: ${payload.slice(0, 20)}>`;
        }
        if (path !== r.path) out.push(`path: ${r.revisionId} manifest says ${JSON.stringify(path)}, not ${JSON.stringify(r.path)}`);
      }
    }
    if ((r.contentBlobId ?? null) === null && !r.deleted) out.push(`references: live ${r.revisionId} has no content blob`);
  }
  for (const b of s.blobs.values()) {
    if (b.refcount !== (refs.get(b.blobId) ?? 0)) out.push(`refcount: ${b.blobId} ${b.state} refcount ${b.refcount}, refs ${refs.get(b.blobId) ?? 0}`);
    if (b.refcount > 0 && (b.state === "DELETING" || b.state === "DELETED")) out.push(`refcount: ${b.blobId} is ${b.state} with refcount ${b.refcount}`);
    if (b.state === "CONFIRMED" || b.state === "GARBAGE_CANDIDATE") {
      const first = ledger.get(b.blobId);
      if (first === undefined && b.payload !== null) ledger.set(b.blobId, b.payload);
      else if (first !== b.payload) out.push(`immutable: ${b.blobId} changed from ${JSON.stringify(first)} to ${JSON.stringify(b.payload)}`);
    }
  }
  return out;
}

/** §35.13 "Fin": the blobs still stored (not DELETED) in an epoch before the vault's first Private one. */
export function preSwitchBlobs(s: Server): string[] {
  if (s.privateSince === null) return [];
  const since = epochIndex(s.privateSince);
  return [...s.blobs.values()].filter((b) => b.state !== "DELETED" && epochIndex(b.epochId) < since).map((b) => `${b.blobId} (${b.epochId}, ${b.state})`);
}
