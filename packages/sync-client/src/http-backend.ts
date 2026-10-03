import * as P from "@nodra/protocol";
import type { CommitResult, ContentRef, ObjectId, PrepareRejection, RemoteEntry, RevisionId, RevisionStatus, SyncEvent } from "@nodra/sync-core";
import type { z } from "zod";
import { type ManifestBinding, type ManifestCodec, type OpenBlobInput, type ReencryptRejection, type RevisionToReencrypt, type SyncBackend, UPLOAD_TIMEOUT } from "./ports.js";
import type { ManifestInput } from "./manifest.js";

// SyncBackend (§22) over the Worker's HTTP API (@nodra/protocol), for one vault. It also opens the
// manifests the runner needs as paths (§13.1: events and heads carry blob ids, not paths) and reads a
// revision's content through getBlob.
//
// A rejected promise means "outcome unknown" to the runner, which then keeps its facts and tries again
// later (ports.ts). Answers the runner cannot act on yet are therefore thrown as a SyncBackendError with
// their code, so that nothing is retired or inferred from them (§12.6; packages/control-plane/NOTES.md, questions 88 and 98):
//   VAULT_DELETING, VAULT_NOT_FOUND (except releaseUpload, whose port carries it), QUOTA_EXCEEDED,
//   RATE_LIMITED, the auth refusals, UPLOAD_IN_PROGRESS, BLOB_CORRUPT_RETRYABLE and BAD_UPLOAD_LENGTH (after
//   one immediate retry of the PUT, §12.6), and BAD_RESPONSE (a body that does not parse). UPLOAD_TIMEOUT
//   is thrown as the port's UPLOAD_TIMEOUT. The runner decides the reaction to each code (retry.ts); a
//   server-given wait travels as `retryAfterSeconds`: the PUT's `retryAfterSeconds` (UPLOAD_IN_PROGRESS,
//   §12.6) or an HTTP `Retry-After` header in seconds on any answer.

/** Opens a blob's ciphertext into its plaintext (the decrypt half of VaultCrypto, §22). */
export interface BlobOpener extends Pick<ManifestCodec, "decodeManifest"> {
  open(input: OpenBlobInput): Promise<Uint8Array>;
}

export class SyncBackendError extends Error {
  constructor(
    readonly code: string,
    readonly status?: number,
    /** A wait the server asked for (retry-after, a lease's end), in seconds. */
    readonly retryAfterSeconds?: number,
  ) {
    super(code);
    this.name = "SyncBackendError";
  }
}

export interface HttpBackendOptions {
  /** Origin of the Worker, e.g. "https://api.nodra.app" (no trailing slash). */
  readonly baseUrl: string;
  readonly vaultId: string;
  readonly fetch: typeof fetch;
  /** Headers of every request: the session and, for writes, the capability (§11.3). */
  readonly headers: () => Record<string, string> | Promise<Record<string, string>>;
  /**
   * §11.3: a write refused for an authentication reason. Returning true means a fresh proof of
   * possession succeeded and the request is worth sending once more; false leaves the refusal to
   * the runner, which keeps its facts and tries again later. `capabilitySession` supplies it.
   */
  readonly onAuthRefusal?: (code: string) => Promise<boolean>;
  readonly opener: BlobOpener;
  /** listEvents page size (§13.2). */
  readonly pageLimit?: number;
}

const PREPARE_REJECTIONS: ReadonlySet<string> = new Set<PrepareRejection | "PENDING_BUDGET_EXCEEDED">([
  "BLOB_TOO_LARGE",
  "EPOCH_STALE",
  "BLOB_ID_CONFLICT",
  "BLOB_UNAVAILABLE",
  "BLOB_ALREADY_EXISTS",
  "BLOB_CORRUPT",
  "PENDING_BUDGET_EXCEEDED",
]);

/** content_blob_id and content_epoch_id of an event or head (§13.1): null for a delete. */
function contentRef(blobId: string | null | undefined, epochId: string | null | undefined): ContentRef | null {
  return blobId == null || epochId == null ? null : { blobId, epochId };
}

export function httpSyncBackend(o: HttpBackendOptions): SyncBackend {
  const v = o.vaultId;
  const manifests = new Map<string, ManifestInput>(); // manifest blob id → §8 manifest (blobs are immutable)
  const byRevision = new Map<RevisionId, ManifestInput>(); // the same, reachable by the revision it belongs to
  const contents = new Map<RevisionId, ContentRef | null>(); // learned by this instance

  /** The gateway's own refusals of §11.3, the only ones a fresh capability can change. */
  const AUTH_REFUSALS: ReadonlySet<string> = new Set(["WRITE_CAPABILITY_REQUIRED", "SCOPE_REQUIRED", "UNAUTHENTICATED"]);

  async function send1(method: string, path: string, body?: unknown): Promise<Response> {
    const headers = { ...(await o.headers()) };
    let payload: BodyInit | undefined;
    if (body instanceof Uint8Array) {
      headers["content-type"] = "application/octet-stream";
      payload = body as Uint8Array<ArrayBuffer>;
    } else if (body !== undefined) {
      headers["content-type"] = "application/json";
      payload = JSON.stringify(body);
    }
    return o.fetch(`${o.baseUrl}${path}`, { method, headers, ...(payload === undefined ? {} : { body: payload }) });
  }

  /**
   * §11.3: a capability lives 30 minutes and dies the moment its recipient is revoked or the root
   * moves, so a refusal is ordinary, not exceptional. One fresh proof, one resend, and no more: a
   * second refusal is a real one and travels to the runner as a `SyncBackendError`.
   */
  async function send(method: string, path: string, body?: unknown): Promise<Response> {
    const res = await send1(method, path, body);
    if (res.ok || o.onAuthRefusal === undefined) return res;
    const error = P.ErrorBody.safeParse(await res.clone().json().catch(() => null));
    if (!error.success || !AUTH_REFUSALS.has(error.data.error)) return res;
    return (await o.onAuthRefusal(error.data.error)) ? send1(method, path, body) : res;
  }

  /** HTTP `Retry-After` in delta-seconds (the HTTP-date form is not used by the Worker). */
  function retryAfter(res: Response): number | undefined {
    const h = res.headers.get("retry-after");
    return h !== null && /^\d+$/.test(h.trim()) ? Number(h.trim()) : undefined;
  }

  async function call<S extends z.ZodType>(schema: S, method: string, path: string, body?: unknown): Promise<z.output<S> & { retryAfterHeader?: number }> {
    const res = await send(method, path, body);
    let value: unknown;
    try {
      value = JSON.parse(await res.text());
    } catch {
      throw new SyncBackendError("BAD_RESPONSE", res.status, retryAfter(res));
    }
    if (!res.ok) {
      const error = P.ErrorBody.safeParse(value);
      throw new SyncBackendError(error.success ? error.data.error : "BAD_RESPONSE", res.status, retryAfter(res));
    }
    const parsed = schema.safeParse(value);
    if (!parsed.success) throw new SyncBackendError("BAD_RESPONSE", res.status);
    const wait = retryAfter(res);
    return (wait === undefined ? parsed.data : Object.assign(parsed.data as object, { retryAfterHeader: wait })) as z.output<S> & { retryAfterHeader?: number };
  }

  /** getBlob (§22): the exact bytes, or null when they are not stored (BLOB_NOT_FOUND). */
  async function getBlob(blobId: string): Promise<Uint8Array | null> {
    const res = await send("GET", P.routes.blob(v, blobId));
    if (res.ok) return new Uint8Array(await res.arrayBuffer());
    const error = P.ErrorBody.safeParse(await res.json().catch(() => null));
    if (error.success && error.data.error === "BLOB_NOT_FOUND") return null;
    throw new SyncBackendError(error.success ? error.data.error : "BAD_RESPONSE", res.status);
  }

  /**
   * The manifest of a revision (§8), opened once per blob id and kept: blobs are immutable, and the
   * §9 check on the way down needs the manifest's `content_epoch_id` and `content_fingerprint`,
   * which only this open can produce.
   *
   * `binding` is the AAD of §31.3. It comes from the event or head that named the manifest — §13.1
   * carries `parent_revision_id` for exactly this reason — so a manifest replayed under another
   * revision does not open at all, and the "path" it claims never reaches the planner.
   */
  async function manifestOf(manifestBlobId: string, epochId: string, binding: ManifestBinding): Promise<ManifestInput> {
    const known = manifests.get(manifestBlobId);
    if (known !== undefined) {
      byRevision.set(binding.revisionId, known);
      return known;
    }
    const ciphertext = await getBlob(manifestBlobId);
    // A manifest that an event or head still names is never collected (§10.6, §13.3): its absence is
    // a race with pruning, and the next listEvents answers CURSOR_EXPIRED.
    if (ciphertext === null) throw new SyncBackendError("BLOB_NOT_FOUND");
    const plaintext = await o.opener.open({ epochId, blobId: manifestBlobId, kind: "MANIFEST", ciphertext, binding });
    let manifest: ManifestInput;
    try {
      manifest = o.opener.decodeManifest(plaintext);
    } catch {
      throw new SyncBackendError("CORRUPTION_OR_MISBINDING");
    }
    // §8 binds identity to content, so a manifest whose ids are not the revision's is misbinding.
    // The §31.3 AAD already makes that unreachable for a real manifest; this is the same statement
    // in the clear. A Phase 0 manifest that declares no identity (the dev codec, §22) has nothing
    // to compare, and its AAD is still what bound it.
    if ((manifest.objectId !== "" && manifest.objectId !== binding.objectId) || (manifest.revisionId !== "" && manifest.revisionId !== binding.revisionId)) {
      throw new SyncBackendError("CORRUPTION_OR_MISBINDING");
    }
    manifests.set(manifestBlobId, manifest);
    byRevision.set(binding.revisionId, manifest);
    return manifest;
  }

  const pathOf = async (manifestBlobId: string, epochId: string, binding: ManifestBinding): Promise<string> =>
    (await manifestOf(manifestBlobId, epochId, binding)).path;

  async function remoteEntry(objectId: ObjectId, h: P.Head): Promise<RemoteEntry> {
    const content = contentRef(h.contentBlobId, h.contentEpochId);
    contents.set(h.revisionId, content);
    let path = "";
    if (h.manifestBlobId !== null && h.manifestEpochId !== null) {
      path = await pathOf(h.manifestBlobId, h.manifestEpochId, { objectId, revisionId: h.revisionId, parentRevisionId: h.parentRevisionId });
    }
    // Only a deleted head loses its manifest to pruning (§8, §10.6); its path takes no part in equality.
    else if (!h.deleted) throw new SyncBackendError("BAD_RESPONSE");
    return { revisionId: h.revisionId, sequence: h.sequence, path, localCompareHash: null, deleted: h.deleted, createdSequence: h.createdSequence, content };
  }

  async function event(e: P.EventRow): Promise<SyncEvent> {
    switch (e.eventType) {
      case "REVISION": {
        const content = contentRef(e.contentBlobId, e.contentEpochId);
        contents.set(e.revisionId, content);
        return {
          kind: "REVISION",
          sequence: e.sequence,
          objectId: e.objectId,
          revisionId: e.revisionId,
          parentRevisionId: e.parentRevisionId ?? null,
          path: await pathOf(e.manifestBlobId, e.manifestEpochId, { objectId: e.objectId, revisionId: e.revisionId, parentRevisionId: e.parentRevisionId ?? null }),
          deleted: e.deleted,
          createdSequence: e.createdSequence,
          mutationId: e.mutationId,
          batchIndex: e.batchIndex,
          batchSize: e.batchSize,
          content,
        };
      }
      case "EPOCH_ROTATED":
        if (e.batchIndex !== 0 || e.batchSize !== 1) throw new SyncBackendError("BAD_RESPONSE");
        return { kind: "EPOCH_ROTATED", sequence: e.sequence, epochId: e.epochId, batchIndex: 0, batchSize: 1 };
      case "SECURITY":
        // §37: the event only says the security log moved; sync-core takes the cursor past it. Reading
        // and acknowledging the event itself is §37's slice (control-plane NOTES question 98).
        if (e.batchIndex !== 0 || e.batchSize !== 1) throw new SyncBackendError("BAD_RESPONSE");
        return { kind: "SECURITY", sequence: e.sequence, securityEventId: e.securityEventId, batchIndex: 0, batchSize: 1 };
    }
  }

  /**
   * §9 steps 1 and 2 for a content blob whose manifest this instance has. Without the manifest
   * (a revision learned before this process started) there is nothing to compare against, and the
   * AAD of §31.3 is still what stops the wrong blob opening at all.
   */
  function expectedOf(revisionId: RevisionId, ref: ContentRef): { expectFingerprint?: string } {
    const manifest = byRevision.get(revisionId);
    if (manifest === undefined) return {};
    const content = manifest.deleted ? undefined : manifest.content;
    // A Phase 0 manifest with no content section makes no claim about the blob; there is nothing to
    // check. A real one (§8) always has it, and a mismatch is §9's refusal.
    if (content === undefined) return {};
    if (content.blobId !== ref.blobId || content.epochId !== ref.epochId) throw new SyncBackendError("CORRUPTION_OR_MISBINDING");
    return content.fingerprint === "" ? {} : { expectFingerprint: content.fingerprint };
  }

  /**
   * The revision's current content ref as the server has it now (§35.13): from the heads, or from its own
   * REVISION event when it is not a head and its sequence is known (the events carry the current blob
   * ids). null: the server no longer has it to give (pruned, or its event below the cursor floor).
   */
  async function currentRef(revisionId: RevisionId, sequence: number | undefined): Promise<ContentRef | null> {
    contents.delete(revisionId);
    await backend.getVaultState();
    if (!contents.has(revisionId) && sequence !== undefined && sequence > 0) await backend.listEvents(sequence - 1);
    return contents.get(revisionId) ?? null;
  }

  const backend: SyncBackend = {
    async listEvents(afterSequence) {
      const r = await call(P.ListEventsResponse, "GET", P.routes.listEvents(v, afterSequence, o.pageLimit ?? P.PAGE_LIMIT.max));
      if (r.kind === "CURSOR_EXPIRED") return r;
      const events: SyncEvent[] = [];
      for (const e of r.events) events.push(await event(e));
      return { kind: "PAGE", events };
    },

    async getVaultState() {
      const r = await call(P.VaultStateResponse, "GET", P.routes.vaultState(v));
      const heads = [];
      for (const h of r.heads) heads.push({ objectId: h.objectId, head: await remoteEntry(h.objectId, h.head) });
      return { sequence: r.sequence, epochId: r.epochId, heads };
    },

    async prepareUpload(input) {
      const r = await call(P.PrepareResponse, "POST", P.routes.prepareUpload(v), {
        blobId: input.blobId,
        epochId: input.epochId,
        kind: input.kind,
        declaredSize: input.declaredSize,
        ciphertextSha256: input.ciphertextSha256,
        forDelete: input.forDelete,
        fingerprint: null,
        ...(input.forReencrypt === undefined ? {} : { forReencrypt: input.forReencrypt }),
      } satisfies P.PrepareRequest);
      if (r.ok) return { ok: true, expiresInSeconds: r.expiresInSeconds };
      if (PREPARE_REJECTIONS.has(r.code)) return { ok: false, code: r.code as PrepareRejection | "PENDING_BUDGET_EXCEEDED" };
      throw new SyncBackendError(r.code, undefined, r.retryAfterHeader);
    },

    async uploadBlob(blobId, ciphertext) {
      const body = ciphertext;
      let r = await call(P.PutResponse, "PUT", P.routes.blob(v, blobId), body);
      // §12.6: the bytes or their length went wrong on the way; the same PUT goes again at once, once.
      // A second failure is thrown like the other codes below, and the runner retries on a later tick.
      if (!r.ok && (r.code === "BLOB_CORRUPT_RETRYABLE" || r.code === "BAD_UPLOAD_LENGTH")) r = await call(P.PutResponse, "PUT", P.routes.blob(v, blobId), body);
      if (r.ok) return r;
      if (r.code === "UPLOAD_TIMEOUT") {
        const e = new SyncBackendError(r.code);
        e.name = UPLOAD_TIMEOUT;
        throw e;
      }
      if (PREPARE_REJECTIONS.has(r.code)) return { ok: false, code: r.code as PrepareRejection };
      throw new SyncBackendError(r.code, undefined, r.retryAfterSeconds ?? r.retryAfterHeader);
    },

    async releaseUpload(blobId) {
      try {
        return (await call(P.ReleaseResponse, "POST", P.routes.releaseUpload(v, blobId))).result;
      } catch (e) {
        // The port carries it: the cleanup record goes (§44.1), the vault is gone.
        if (e instanceof SyncBackendError && e.code === "VAULT_NOT_FOUND") return "VAULT_NOT_FOUND";
        throw e;
      }
    },

    async listRevisionsToReencrypt(after, limit) {
      const r = await call(P.ReencryptListResponse, "GET", P.routes.revisionsToReencrypt(v, after, limit));
      if (r.kind === "INVALID_STATE") return r;
      const revisions: RevisionToReencrypt[] = [];
      for (const x of r.revisions) {
        const binding = { objectId: x.objectId, revisionId: x.revisionId, parentRevisionId: x.parentRevisionId };
        // Opened under its old epoch, with its own binding (§31.3), like every manifest an event names.
        const manifest = await manifestOf(x.manifestBlobId, x.manifestEpochId, binding);
        revisions.push({
          revisionId: x.revisionId,
          objectId: x.objectId,
          parentRevisionId: x.parentRevisionId,
          deleted: x.deleted,
          manifestBlobId: x.manifestBlobId,
          manifestEpochId: x.manifestEpochId,
          content: contentRef(x.contentBlobId, x.contentEpochId),
          manifest,
        });
      }
      return { kind: "PAGE", revisions, next: r.next };
    },

    async reencryptRevision(input) {
      const r = await call(P.ReencryptResponse, "POST", P.routes.reencryptRevision(v), {
        revisionId: input.revisionId,
        expectedManifestBlobId: input.expectedManifestBlobId,
        newManifestBlobId: input.newManifestBlobId,
        newContentBlobId: input.newContentBlobId,
      } satisfies P.ReencryptRequest);
      if (r.ok) return r;
      // VAULT_DELETING keeps everything, like every other write (§11.4): not a definitive answer.
      if (r.code === "VAULT_DELETING") throw new SyncBackendError(r.code, undefined, r.retryAfterHeader);
      return { ok: false, code: r.code as ReencryptRejection };
    },

    async getRevisionStatus(revisionIds) {
      const r = await call(P.RevisionStatusResponse, "POST", P.routes.revisionStatus(v), { revisionIds: [...revisionIds] } satisfies P.RevisionStatusRequest);
      return r.revisions.map(
        (x): RevisionStatus =>
          x.exists && x.objectId !== undefined && x.sequence !== undefined ? { revisionId: x.revisionId, exists: true, objectId: x.objectId, sequence: x.sequence } : { revisionId: x.revisionId, exists: false },
      );
    },

    async commitMutation(input) {
      const r = await call(P.CommitResponse, "POST", P.routes.commitMutation(v), {
        mutationId: input.mutationId,
        epochId: input.epochId,
        revisions: input.revisions.map((x) => ({ ...x })),
      } satisfies P.CommitRequest);
      if (r.kind === "COMMITTED") {
        return { kind: "COMMITTED", revisions: r.revisions.map((x) => ({ objectId: x.objectId, revisionId: x.revisionId, sequence: x.sequence, createdSequence: x.createdSequence })) };
      }
      // VAULT_DELETING and QUOTA_EXCEEDED keep the outbox (§12.6): not definitive rejections.
      if (!("heads" in r) || r.code === "QUOTA_EXCEEDED") throw new SyncBackendError(r.code, undefined, r.retryAfterHeader);
      const heads: Array<{ objectId: string; head: RemoteEntry }> = [];
      for (const h of r.heads) if (h.head !== null) heads.push({ objectId: h.objectId, head: await remoteEntry(h.objectId, h.head) });
      const result: CommitResult = { kind: "REJECTED", code: r.code, heads, invalidObjects: r.invalid === null ? null : r.invalid.map((x) => x.objectId) };
      return result;
    },

    async readRevision(revisionId, recorded, sequence) {
      // The ref recorded with the revision in S or R comes first (NOTES question 99). Without one (an
      // entry persisted before refs were recorded): what this instance learned, then the heads, since
      // after a restart the refs of earlier events are gone and the heads cover every live revision.
      if (recorded === undefined && !contents.has(revisionId)) await backend.getVaultState();
      let ref = recorded === undefined ? contents.get(revisionId) : recorded;
      // Still unknown (a non-head revision of an old entry) or no content: unavailable, like pruned bytes.
      if (ref === undefined || ref === null) return { kind: "PRUNED" };
      let ciphertext = await getBlob(ref.blobId);
      if (ciphertext === null) {
        // §35.13 "Otras réplicas": BLOB_NOT_FOUND is not proof of pruning, and not CORRUPTION_OR_MISBINDING.
        // A re-encryption may have replaced the blob: read the revision again and try its current one, once.
        const fresh = await currentRef(revisionId, sequence);
        if (fresh === null) return { kind: "PRUNED" };
        ref = fresh;
        ciphertext = await getBlob(ref.blobId);
        if (ciphertext === null) return { kind: "PRUNED" };
      }
      // §9 on download, whenever this instance opened the revision's manifest: the content blob's
      // epoch must be the manifest's `content_epoch_id`, and its fingerprint must be recomputed with
      // the dedup key of THAT epoch. Both checks refuse before any byte reaches the executor.
      const open: OpenBlobInput = { epochId: ref.epochId, blobId: ref.blobId, kind: "CONTENT", ciphertext, ...expectedOf(revisionId, ref) };
      return { kind: "CONTENT", plaintext: await o.opener.open(open) };
    },
  };
  return backend;
}
