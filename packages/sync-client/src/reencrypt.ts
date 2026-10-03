import {
  type AttemptBlob,
  type ClientFacts,
  type UploadAttempt,
  applyRelease,
  endReencryptAttempt,
  recordPrepared,
  recordReencryptAttempt,
  reencryptKey,
  setWriteEpoch,
} from "@nodra/sync-core";
import PQueue from "p-queue";
import { commit } from "./executor.js";
import type { ManifestInput } from "./manifest.js";
import type { RevisionToReencrypt } from "./ports.js";
import type { Client } from "./runner.js";

// §35.13 "Re-cifrado del historial": after a SWITCH_TO_PRIVATE, the trusted client that switched lists
// the revisions still in a pre-switch epoch, reads each one with its old epoch, seals it again under the
// write epoch and swaps it in with reencryptRevision, one revision per call.
//
// Only facts are persisted, never "which revision we were at":
//   - the server's list is the progress: a pass walks it, and what is left is what the next pass sees;
//   - each revision's upload is the ordinary write-ahead attempt of rule 13 (`UploadAttempt` with a
//     `reencrypt` target), committed before its first request, and its blobs go to the ordinary
//     `pending_upload_cleanup` queue when the swap is refused. The runner's tick releases them.
// After a crash a new pass resumes the persisted attempts (prepare, PUT and the swap are all idempotent,
// §11.1, §11.2, §35.13 step 2) and then lists again.
//
// At most REENCRYPT_IN_FLIGHT revisions are in flight (p-queue), which is the server's own cap on
// revisions with `for_reencrypt` blobs in PENDING; revisions that share an old content blob go one after
// another, so that the first one's new content blob serves the rest (the list gives them in a row).

/** §35.13 REENCRYPT_IN_FLIGHT (initial value, ADR-014). */
export const REENCRYPT_IN_FLIGHT = 4;
/** Revisions asked per page of listRevisionsToReencrypt. */
export const REENCRYPT_PAGE = 100;

export interface ReencryptPassOptions {
  readonly inFlight?: number;
  readonly pageSize?: number;
}

export interface ReencryptPassResult {
  /** Revisions the server listed during this pass: the visible progress (§35.13 "Crash y reanudación"). */
  readonly listed: number;
  /** Revisions swapped by this pass (a repeated swap counts: it is the same success). */
  readonly swapped: number;
  /** INVALID_STATE: the account is not Private, so there is nothing to re-encrypt. */
  readonly notPrivate: boolean;
  /**
   * The first request or store error, or null. It ends the pass (no new revision starts); the attempts
   * it leaves are facts, and the next pass resumes them. The caller decides when that is.
   */
  readonly error: unknown;
}

/** The new content blob a swap put in for an old one: the manifests of the revisions sharing it name it (§8). */
interface NewContent {
  readonly blobId: string;
  readonly epochId: string;
  readonly fingerprint: string;
  readonly plaintextSize: number;
}

type Outcome = "SWAPPED" | "RELEASED" | "WAIT" | "NOT_PRIVATE";

/** State transitions of one pass, one at a time, each against the state as it is when it runs. */
function serializer(c: Client) {
  let tail: Promise<unknown> = Promise.resolve();
  return (fn: (f: ClientFacts) => ClientFacts): Promise<void> => {
    const next = tail.then(async () => {
      const facts = fn(c.shell.state.facts);
      if (facts !== c.shell.state.facts) await commit(c.shell, { ...c.shell.state, facts });
    });
    tail = next.catch(() => undefined);
    return next;
  };
}

/**
 * One pass: resume every persisted re-encryption attempt, then walk the list once, page by page, with at
 * most `inFlight` revisions at a time. Nothing is persisted about the pass itself.
 */
export async function reencryptPass(c: Client, options: ReencryptPassOptions = {}): Promise<ReencryptPassResult> {
  const queue = new PQueue({ concurrency: options.inFlight ?? REENCRYPT_IN_FLIGHT });
  const update = serializer(c);
  const replaced = new Map<string, NewContent>();
  const tails = new Map<string, Promise<unknown>>();
  let listed = 0;
  let swapped = 0;
  let notPrivate = false;
  let error: unknown = null;
  let failed = false;
  const stopped = () => failed || notPrivate;

  const settle = (outcome: Outcome) => {
    if (outcome === "SWAPPED") swapped++;
    if (outcome === "NOT_PRIVATE") notPrivate = true;
  };
  const enqueue = (work: () => Promise<Outcome>): Promise<void> =>
    queue.add(async () => {
      if (stopped()) return;
      try {
        settle(await work());
      } catch (e) {
        if (!failed) error = e;
        failed = true;
      }
    });

  // 1. The attempts a previous instance left: each is resumed where the server has it.
  const pending = c.shell.state.facts.attempts.filter((a) => a.reencrypt !== undefined);
  const resumed = new Set(pending.map((a) => a.reencrypt!.revisionId));
  const resumptions = pending.map((a) => enqueue(() => drive(c, update, a)));
  await Promise.all(resumptions);

  // 2. The list, walked once. A revision that shares its old content with the previous ones waits for them.
  for (let after: string | null = null; !stopped(); ) {
    await queue.onSizeLessThan(1);
    let page;
    try {
      page = await c.backend.listRevisionsToReencrypt(after, options.pageSize ?? REENCRYPT_PAGE);
    } catch (e) {
      error = e;
      failed = true;
      break;
    }
    if (page.kind === "INVALID_STATE") {
      notPrivate = true;
      break;
    }
    listed += page.revisions.length;
    for (const t of page.revisions) {
      if (resumed.has(t.revisionId)) continue; // already driven above in this pass
      const old = t.content?.blobId ?? null;
      const one = () => enqueue(() => reencryptOne(c, update, t, old === null ? null : (replaced.get(old) ?? null), replaced));
      if (old === null) {
        void one();
        continue;
      }
      const tail = (tails.get(old) ?? Promise.resolve()).then(one);
      tails.set(old, tail);
    }
    if (page.next === null) break;
    after = page.next;
  }
  await Promise.all(tails.values());
  await queue.onIdle();
  return { listed, swapped, notPrivate, error };
}

/** Reads, seals and records the attempt of one listed revision, then drives it (§35.13 "Cliente"). */
async function reencryptOne(
  c: Client,
  update: (fn: (f: ClientFacts) => ClientFacts) => Promise<void>,
  t: RevisionToReencrypt,
  reuse: NewContent | null,
  replaced: Map<string, NewContent>,
): Promise<Outcome> {
  const f = c.shell.state.facts;
  const epochId = f.epochId;
  const blobs: AttemptBlob[] = [];
  let content: NewContent | null = null;
  if (t.content !== null) {
    if (reuse !== null) content = reuse;
    else {
      // §33.1 and §9: the old content, opened with its own epoch and checked against the old manifest.
      const read = await c.backend.readRevision(t.revisionId, t.content);
      // Pruned meanwhile: the server no longer lists it; nothing to replace.
      if (read.kind === "PRUNED") return "RELEASED";
      const blobId = c.shell.newId("b-");
      const sealed = await c.blobs.encryptBlob({ epochId, blobId, kind: "CONTENT", payload: read.plaintext });
      blobs.push({ blobId, kind: "CONTENT", objectId: t.objectId, declaredSize: sealed.declaredSize, ciphertextSha256: sealed.ciphertextSha256, ciphertext: sealed.ciphertext, forDelete: false, expiresAt: null });
      // §31.4: the fingerprint is taken with the dedup key of the new epoch.
      content = { blobId, epochId, fingerprint: sealed.fingerprint ?? "", plaintextSize: read.plaintext.byteLength };
    }
  }
  // §35.13: a new manifest with the same fields but content_blob_id, content_fingerprint and content_epoch_id.
  const binding = { objectId: t.objectId, revisionId: t.revisionId, parentRevisionId: t.parentRevisionId };
  const manifest: ManifestInput = {
    ...binding,
    path: t.manifest.path,
    mtimeMs: t.manifest.mtimeMs,
    deleted: t.deleted,
    ...(content === null ? {} : { content: { blobId: content.blobId, epochId: content.epochId, fingerprint: content.fingerprint, plaintextSize: content.plaintextSize } }),
  };
  const manifestBlobId = c.shell.newId("b-");
  const sealed = await c.blobs.encryptBlob({ epochId, blobId: manifestBlobId, kind: "MANIFEST", payload: c.blobs.encodeManifest(manifest), binding });
  blobs.unshift({ blobId: manifestBlobId, kind: "MANIFEST", objectId: t.objectId, declaredSize: sealed.declaredSize, ciphertextSha256: sealed.ciphertextSha256, ciphertext: sealed.ciphertext, forDelete: false, expiresAt: null });
  const attempt: UploadAttempt = {
    attemptId: c.shell.newId("a-"),
    mutationId: reencryptKey(t.revisionId),
    replicaId: f.replicaId,
    epochId,
    blobs,
    reencrypt: { revisionId: t.revisionId, expectedManifestBlobId: t.manifestBlobId, newManifestBlobId: manifestBlobId, newContentBlobId: content?.blobId ?? null },
  };
  // Rule 13: encrypted and hashed first; the one transaction that follows only writes.
  await update((facts) => recordReencryptAttempt(facts, attempt));
  const outcome = await drive(c, update, attempt);
  if (t.content !== null && content !== null) {
    if (outcome === "SWAPPED") replaced.set(t.content.blobId, content);
    // A refused swap may be the reused blob's fault (gone meanwhile): the next revision uploads its own.
    else if (reuse !== null) replaced.delete(t.content.blobId);
  }
  return outcome;
}

/**
 * Prepare, PUT and swap of one attempt, each only as far as the facts say it is needed: an attempt left
 * by a crash goes through the same steps, which the server answers idempotently.
 */
async function drive(c: Client, update: (fn: (f: ClientFacts) => ClientFacts) => Promise<void>, attempt: UploadAttempt): Promise<Outcome> {
  const target = attempt.reencrypt!;
  // The blobs go to pending_upload_cleanup first (a fact), then are released at once: left PENDING, they
  // would keep counting against REENCRYPT_IN_FLIGHT until the tick got to them.
  const release = async (): Promise<Outcome> => {
    await update((f) => endReencryptAttempt(f, target.revisionId, false));
    for (const b of attempt.blobs) {
      if (!c.shell.state.facts.cleanup.some((x) => x.blobId === b.blobId)) continue;
      const r = await c.backend.releaseUpload(b.blobId);
      await update((f) => applyRelease(f, b.blobId, r));
    }
    return "RELEASED";
  };
  const learnEpoch = async () => {
    const state = await c.backend.getVaultState();
    await update((f) => setWriteEpoch(f, state.epochId));
  };
  // An upload window that ended locally (§12.1): the server would refuse the swap (step 4).
  if (attempt.blobs.some((b) => b.expiresAt !== null && b.expiresAt <= c.now())) return release();
  for (const b of attempt.blobs) {
    const current = c.shell.state.facts.attempts.find((a) => a.attemptId === attempt.attemptId)?.blobs.find((x) => x.blobId === b.blobId);
    if (current?.expiresAt != null) continue;
    const sentAt = c.now();
    const r = await c.backend.prepareUpload({
      blobId: b.blobId,
      epochId: attempt.epochId,
      kind: b.kind,
      declaredSize: b.declaredSize,
      ciphertextSha256: b.ciphertextSha256,
      forDelete: false,
      objectId: b.objectId,
      forReencrypt: target.revisionId,
    });
    if (r.ok) await update((f) => recordPrepared(f, b.blobId, sentAt + r.expiresInSeconds));
    // §35.13: REENCRYPT_IN_FLIGHT revisions of this account are in flight elsewhere; kept for a later pass.
    else if (r.code === "PENDING_BUDGET_EXCEEDED") return "WAIT";
    else {
      if (r.code === "EPOCH_STALE") await learnEpoch();
      return release();
    }
  }
  for (const b of attempt.blobs) {
    if (c.memory.putDone.has(b.blobId)) continue;
    const r = await c.backend.uploadBlob(b.blobId, b.ciphertext);
    if (!r.ok) return release();
    c.memory.putDone.add(b.blobId);
  }
  const r = await c.backend.reencryptRevision({
    revisionId: target.revisionId,
    expectedManifestBlobId: target.expectedManifestBlobId,
    newManifestBlobId: target.newManifestBlobId,
    newContentBlobId: target.newContentBlobId,
  });
  if (r.ok) {
    // The blobs are the revision's now: nothing to release.
    await update((f) => endReencryptAttempt(f, target.revisionId, true));
    return "SWAPPED";
  }
  if (r.code === "EPOCH_STALE") await learnEpoch();
  await release();
  return r.code === "INVALID_STATE" ? "NOT_PRIVATE" : "RELEASED";
}
