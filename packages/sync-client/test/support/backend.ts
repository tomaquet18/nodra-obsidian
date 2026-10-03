import {
  type Server,
  commit,
  listEvents,
  listToReencrypt,
  prepare,
  put,
  reencrypt,
  release,
  revisionStatus,
  vaultState,
} from "@nodra/sync-core/test-support/server";
import { SyncBackendError } from "../../src/http-backend.js";
import { type BlobCrypto, type RevisionToReencrypt, type SyncBackend, UPLOAD_TIMEOUT } from "../../src/ports.js";
import { devManifestCodec } from "../../src/dev-crypto.js";
import { fromModel, toModel, utf8 } from "./bytes.js";

// SyncBackend over sync-core's in-memory server model (test-support), with network faults. Fake
// crypto: a blob's "ciphertext" is the UTF-8 of `<blobId>|<payload>`, the payload in the model encoding
// (bytes.ts, so binary content survives byte for byte); the server model reads payloads from it.

export interface NetFaults {
  /** The request is lost before reaching the server. */
  drop: number;
  /** The server applies the request and the response is lost. */
  lose: number;
  /** A lost response comes with a crash of the client. */
  crash: number;
  /** A PUT times out (§12.6). */
  putTimeout: number;
}

export const NO_NET_FAULTS: NetFaults = { drop: 0, lose: 0, crash: 0, putTimeout: 0 };

const MANIFEST_OVERHEAD = 28;

/** 64 hex characters from four seeded FNV-1a passes: deterministic and synchronous, not a real hash. */
function modelFingerprint(model: string): string {
  let out = "";
  for (let seed = 0; seed < 4; seed++) {
    let h = 0x811c9dc5 ^ seed;
    for (let i = 0; i < model.length; i++) h = Math.imul(h ^ model.charCodeAt(i), 0x01000193);
    let l = 0xcbf29ce4 ^ (seed * 0x9e3779b9);
    for (let i = model.length - 1; i >= 0; i--) l = Math.imul(l ^ model.charCodeAt(i), 0x01000193);
    out += (h >>> 0).toString(16).padStart(8, "0") + (l >>> 0).toString(16).padStart(8, "0");
  }
  return out;
}

/** DevVaultCrypto-like blob crypto (§22: development only). */
export function devBlobCrypto(): BlobCrypto & { readonly payloads: Map<string, string> } {
  const payloads = new Map<string, string>();
  return {
    ...devManifestCodec,
    payloads,
    declaredSize: (payload) => payload.byteLength + MANIFEST_OVERHEAD,
    async encryptBlob({ blobId, kind, payload }) {
      const model = toModel(payload);
      payloads.set(blobId, model);
      const ciphertext = `${blobId}|${model}`;
      return {
        ciphertext: utf8(ciphertext),
        ciphertextSha256: `sha(${ciphertext})`,
        declaredSize: payload.byteLength + MANIFEST_OVERHEAD,
        // §31.4 in the model: the same bytes under the same epoch give the same fingerprint, 64 hex
        // characters like the real HMAC-SHA-256, so a manifest is as large as the real one (§8).
        ...(kind === "CONTENT" ? { fingerprint: modelFingerprint(model) } : {}),
      };
    },
  };
}

/**
 * The account against its plan quota (§11.1, §40.1), which the server model does not carry: "full" refuses
 * every prepare that needs quota with QUOTA_EXCEEDED and lets for_delete manifests through (within
 * DELETE_MANIFEST_ALLOWANCE); "spent" refuses those too (the allowance is used up). Re-encryption blobs
 * follow their own rule (§35.13) and always pass.
 */
export type QuotaState = "free" | "full" | "spent";

export interface MemBackend {
  readonly backend: SyncBackend;
  faults: NetFaults;
  quota: QuotaState;
  /**
   * Prepares refused with QUOTA_EXCEEDED; `contentRefused`: a prepare that needs quota was refused since the
   * harness last set `quota` (it resets the flag); `deletesOverQuota`: delete-only mutations committed while
   * the quota was "full" after such a refusal, i.e. deletes that went on past a known QUOTA_EXCEEDED.
   */
  readonly quotaLog: { refusals: number; contentRefused: boolean; deletesOverQuota: number };
  /** Oracle (write-ahead, rule 13): every prepared blob id was persisted before its prepare. */
  readonly writeAheadViolations: string[];
}

export function memBackend(
  server: Server,
  replica: string,
  crypto: ReturnType<typeof devBlobCrypto>,
  random: () => number,
  persistedBlobIds: () => Promise<ReadonlySet<string>>,
  crash: (where: string) => never,
): MemBackend {
  const m: MemBackend = { backend: null as unknown as SyncBackend, faults: NO_NET_FAULTS, quota: "free", quotaLog: { refusals: 0, contentRefused: false, deletesOverQuota: 0 }, writeAheadViolations: [] };
  const deliver = <T>(f: () => T): T => {
    if (random() < m.faults.drop) throw new Error("request lost");
    const out = f();
    if (random() < m.faults.lose) {
      if (random() < m.faults.crash) crash("lost response");
      throw new Error("response lost");
    }
    return out;
  };
  (m as { backend: SyncBackend }).backend = {
    async listEvents(after) {
      return deliver(() => listEvents(server, after));
    },
    async getVaultState() {
      return deliver(() => vaultState(server));
    },
    async prepareUpload(input) {
      if (!(await persistedBlobIds()).has(input.blobId)) m.writeAheadViolations.push(input.blobId);
      if (input.forReencrypt === undefined && (m.quota === "spent" || (m.quota === "full" && !input.forDelete))) {
        m.quotaLog.refusals++;
        if (!input.forDelete) m.quotaLog.contentRefused = true;
        throw new SyncBackendError("QUOTA_EXCEEDED");
      }
      const payload = crypto.payloads.get(input.blobId) ?? null;
      const r = deliver(() =>
        prepare(server, replica, {
          blobId: input.blobId,
          epochId: input.epochId,
          kind: input.kind,
          declaredSize: input.declaredSize,
          sha: input.ciphertextSha256,
          forDelete: input.forDelete,
          forReencrypt: input.forReencrypt ?? null,
          objectId: input.objectId,
          plaintext: input.kind === "CONTENT" ? payload : null,
        }),
      );
      return r.ok ? { ok: true, expiresInSeconds: r.expiresIn } : r;
    },
    async uploadBlob(blobId, ciphertext) {
      if (random() < m.faults.putTimeout) {
        const e = new Error("PUT timed out");
        e.name = UPLOAD_TIMEOUT;
        throw e;
      }
      return deliver(() => put(server, replica, blobId, ciphertext));
    },
    async releaseUpload(blobId) {
      return deliver(() => release(server, replica, blobId));
    },
    async getRevisionStatus(ids) {
      return deliver(() => revisionStatus(server, ids));
    },
    async commitMutation(input) {
      const overQuota = m.quota === "full" && m.quotaLog.contentRefused;
      const r = deliver(() => commit(server, replica, input));
      if (r.kind === "COMMITTED" && overQuota && input.revisions.every((x) => x.deleted)) m.quotaLog.deletesOverQuota++;
      return r;
    },
    async readRevision(revisionId, recorded) {
      return deliver(() => {
        const r = server.revisions.get(revisionId);
        if (!r || server.pruned.has(revisionId)) return { kind: "PRUNED" as const };
        // A revision a scenario seeded carries no blobs: its plaintext is the model's.
        if (r.contentBlobId === undefined) return { kind: "CONTENT" as const, plaintext: fromModel(r.content) };
        // getBlob of the recorded ref; gone (§35.13 re-encryption) → the revision read again, its current blob.
        const stored = (blobId: string | null | undefined) => {
          const b = blobId == null ? undefined : server.blobs.get(blobId);
          return b !== undefined && b.payload !== null && b.state !== "DELETING" && b.state !== "DELETED" ? b.payload : null;
        };
        const payload = stored(recorded?.blobId) ?? stored(r.contentBlobId);
        if (payload === null) return { kind: "PRUNED" as const };
        return { kind: "CONTENT" as const, plaintext: fromModel(payload.slice(payload.indexOf("|") + 1)) };
      });
    },
    async listRevisionsToReencrypt(after, limit) {
      return deliver(() => {
        const page = listToReencrypt(server, after, limit);
        if (page.kind === "INVALID_STATE") return page;
        const revisions = page.revisions.map((x): RevisionToReencrypt => {
          const payload = server.blobs.get(x.manifestBlobId)!.payload!;
          return {
            revisionId: x.revisionId,
            objectId: x.objectId,
            parentRevisionId: x.parentRevisionId,
            deleted: x.deleted,
            manifestBlobId: x.manifestBlobId,
            manifestEpochId: x.manifestEpochId,
            content: x.contentBlobId === null ? null : { blobId: x.contentBlobId, epochId: x.contentEpochId! },
            manifest: crypto.decodeManifest(fromModel(payload.slice(payload.indexOf("|") + 1))),
          };
        });
        return { kind: "PAGE" as const, revisions, next: page.next };
      });
    },
    async reencryptRevision(input) {
      return deliver(() => reencrypt(server, replica, input));
    },
  };
  return m;
}
