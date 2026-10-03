import { describe, expect, it } from "vitest";
import {
  type ClientFacts,
  type OutboxEntry,
  type UploadAttempt,
  type UploadRequest,
  UPLOAD_TIMEOUT_MAX,
  applyCommitResult,
  applyPrepareRejection,
  applyRelease,
  adoptReplicaId,
  applyRevisionStatus,
  discardForeignCleanup,
  emptyFacts,
  enqueueUploads,
  isDeleteOnly,
  markCommitSent,
  nextOutboxStep,
  recordAttempt,
  recordPrepared,
  recordPutFailure,
  retireExpired,
} from "../src/outbox.js";
import { rev } from "./fixtures.js";
import { text, utf8 } from "./utf8.js";

const ids = (n: number) => Array.from({ length: n }, (_, i) => `id${String(i).padStart(4, "0")}`);
const facts = (over: Partial<ClientFacts> = {}): ClientFacts => ({ ...emptyFacts("vault", "replica-1", "e1"), ...over });
const up = (objectId: string, bytes: number, over: Partial<UploadRequest> = {}): UploadRequest => ({
  objectId,
  expectedHeadRevisionId: null,
  path: `${objectId}.md`,
  deleted: false,
  localCompareHash: `h-${objectId}`,
  plaintext: utf8(`content ${objectId}`),
  newBlobBytes: bytes,
  ...over,
});
const LIMITS = { pendingBudgetBytes: 100 };

function attemptFor(entry: OutboxEntry, attemptId: string, epochId = "e1"): UploadAttempt {
  return {
    attemptId,
    mutationId: entry.mutationId,
    replicaId: "replica-1",
    epochId,
    blobs: entry.objects.map((o) => ({
      blobId: `${attemptId}-${o.objectId}`,
      kind: "CONTENT" as const,
      objectId: o.objectId,
      declaredSize: 10,
      ciphertextSha256: `sha-${attemptId}-${o.objectId}`,
      ciphertext: utf8(`ct-${attemptId}-${o.objectId}`),
      forDelete: false,
      expiresAt: null,
    })),
  };
}

/** One entry for object "a", with an attempt whose blobs are prepared (deadline 100). */
function prepared(): ClientFacts {
  let f = enqueueUploads(facts(), [up("a", 10)], LIMITS, ids(10));
  f = recordAttempt(f, attemptFor(f.outbox[0]!, "att1"));
  return recordPrepared(f, "att1-a", 100);
}

describe("§12.1 batching into mutations", () => {
  it("packs uploads into one mutation with fresh mutation_id and revision_ids (inputs, not random)", () => {
    const f = enqueueUploads(facts(), [up("a", 10), up("b", 10, { expectedHeadRevisionId: "rb" })], LIMITS, ids(10));
    expect(f.outbox).toHaveLength(1);
    expect(f.outbox[0]).toMatchObject({
      mutationId: "id0000",
      commitSent: false,
      objects: [
        { objectId: "a", revisionId: "id0001", expectedHeadRevisionId: null },
        { objectId: "b", revisionId: "id0002", expectedHeadRevisionId: "rb" },
      ],
    });
  });

  it("never more than 500 revisions per mutation", () => {
    const many = Array.from({ length: 501 }, (_, i) => up(`o${String(i).padStart(3, "0")}`, 0));
    const f = enqueueUploads(facts(), many, { pendingBudgetBytes: 1e9 }, ids(2000));
    expect(f.outbox.map((e) => e.objects.length)).toEqual([500, 1]);
  });

  it("the new blob bytes of a mutation never exceed pending_budget_bytes", () => {
    const f = enqueueUploads(facts(), [up("a", 40), up("b", 40), up("c", 40)], LIMITS, ids(10));
    expect(f.outbox.map((e) => e.objects.map((o) => o.objectId))).toEqual([["a", "b"], ["c"]]);
  });

  it("a single revision over the budget is BLOB_TOO_LARGE: blocked, not enqueued (rule 8)", () => {
    const f = enqueueUploads(facts(), [up("a", 101)], LIMITS, ids(10));
    expect(f.outbox).toEqual([]);
    expect(f.blocked).toEqual([{ objectId: "a", localCompareHash: "h-a", reason: "BLOB_TOO_LARGE" }]);
  });

  it("after an expiry the object's mutations carry at most half the bytes, down to one object", () => {
    const f0 = facts({ byteCaps: new Map([["a", 30]]) });
    const f = enqueueUploads(f0, [up("a", 20), up("b", 20)], LIMITS, ids(10));
    expect(f.outbox.map((e) => e.objects.map((o) => o.objectId))).toEqual([["a"], ["b"]]);
    const single = enqueueUploads(facts({ byteCaps: new Map([["a", 5]]) }), [up("a", 20)], LIMITS, ids(10));
    expect(single.outbox.map((e) => e.objects.length)).toEqual([1]);
  });

  it("delete-only entries (§11.1, §40.1): only deletes; an entry mixing a delete with an edit is not one", () => {
    const del = (id: string) => up(id, 5, { deleted: true, localCompareHash: null, plaintext: null, expectedHeadRevisionId: `r${id}` });
    expect(enqueueUploads(facts(), [del("b"), del("d")], LIMITS, ids(10)).outbox.map(isDeleteOnly)).toEqual([true]);
    expect(enqueueUploads(facts(), [up("a", 10), del("b")], LIMITS, ids(10)).outbox.map(isDeleteOnly)).toEqual([false]);
  });

  it("an object already in the outbox is never enqueued twice (at most one in-flight entry)", () => {
    const f1 = enqueueUploads(facts(), [up("a", 10)], LIMITS, ids(10));
    const f2 = enqueueUploads(f1, [up("a", 10)], LIMITS, ids(10).map((i) => `x${i}`));
    expect(f2.outbox).toHaveLength(1);
  });
});

describe("§12.2 rule 13: upload attempts (write-ahead) and next step", () => {
  it("next step: cleanup first, then encrypt, prepare, PUT, commit", () => {
    let f = enqueueUploads(facts(), [up("a", 10)], LIMITS, ids(10));
    expect(nextOutboxStep(f, 0, new Set())).toEqual({ kind: "encrypt", mutationId: "id0000" });
    f = recordAttempt(f, attemptFor(f.outbox[0]!, "att1"));
    expect(nextOutboxStep(f, 0, new Set())).toEqual({ kind: "prepare", mutationId: "id0000", blobId: "att1-a" });
    f = recordPrepared(f, "att1-a", 100);
    expect(nextOutboxStep(f, 0, new Set())).toEqual({ kind: "put", mutationId: "id0000", blobId: "att1-a" });
    expect(nextOutboxStep(f, 0, new Set(["att1-a"]))).toEqual({ kind: "commit", mutationId: "id0000" });
    const withCleanup = { ...f, cleanup: [{ vaultId: "vault", replicaId: "replica-1", blobId: "old" }] };
    expect(nextOutboxStep(withCleanup, 0, new Set())).toEqual({ kind: "release", blobId: "old" });
  });

  it("deletesOnly (a QUOTA_EXCEEDED hold, §12.6): the first delete-only entry goes; cleanup still first; null without one", () => {
    const del = up("d", 5, { deleted: true, localCompareHash: null, plaintext: null, expectedHeadRevisionId: "rd" });
    let f = enqueueUploads(facts(), [up("a", 10)], LIMITS, ids(10));
    expect(nextOutboxStep(f, 0, new Set(), { deletesOnly: true })).toBeNull();
    f = enqueueUploads(f, [del], LIMITS, ids(10).map((i) => `x${i}`));
    expect(f.outbox.map(isDeleteOnly)).toEqual([false, true]);
    expect(nextOutboxStep(f, 0, new Set())).toEqual({ kind: "encrypt", mutationId: "id0000" });
    expect(nextOutboxStep(f, 0, new Set(), { deletesOnly: true })).toEqual({ kind: "encrypt", mutationId: "xid0000" });
    const withCleanup = { ...f, cleanup: [{ vaultId: "vault", replicaId: "replica-1", blobId: "old" }] };
    expect(nextOutboxStep(withCleanup, 0, new Set(), { deletesOnly: true })).toEqual({ kind: "release", blobId: "old" });
  });

  it("a new attempt for the same entry moves the old attempt's blobs to cleanup in the same transition", () => {
    const f = recordAttempt(prepared(), attemptFor(prepared().outbox[0]!, "att2"));
    expect(f.attempts.map((a) => a.attemptId)).toEqual(["att2"]);
    expect(f.cleanup).toEqual([{ vaultId: "vault", replicaId: "replica-1", blobId: "att1-a" }]);
  });

  it("an entry whose commit was sent is never re-encrypted without getRevisionStatus (§12.1 table)", () => {
    const f = markCommitSent(prepared(), "id0000");
    expect(() => recordAttempt(f, attemptFor(f.outbox[0]!, "att2"))).toThrow();
    const noAttempt = { ...f, attempts: [] };
    expect(nextOutboxStep(noAttempt, 0, new Set())).toEqual({ kind: "revisionStatus", mutationId: "id0000" });
  });

  it("an expired, never-sent entry is retired locally: blobs to cleanup, caps halved, single-object failure counted", () => {
    const f = prepared();
    expect(nextOutboxStep(f, 100, new Set(["att1-a"]))).toEqual({ kind: "retireExpired", mutationId: "id0000" });
    const r = retireExpired(f, "id0000", 100);
    expect(r.outbox).toEqual([]);
    expect(r.attempts).toEqual([]);
    expect(r.cleanup.map((c) => c.blobId)).toEqual(["att1-a"]);
    expect(r.byteCaps.get("a")).toBe(5);
    expect(r.uploadFailures.get("a|h-a")).toBe(1);
  });

  it("an entry already sent with unknown outcome is never retired for local expiry: it is resent", () => {
    const f = markCommitSent(prepared(), "id0000");
    expect(nextOutboxStep(f, 1000, new Set())).toEqual({ kind: "commit", mutationId: "id0000" });
    expect(() => retireExpired(f, "id0000", 1000)).toThrow();
  });

  it("UPLOAD_TIMEOUT_MAX failures of the same content block it; new content starts a new count", () => {
    let f = prepared();
    for (let i = 0; i < UPLOAD_TIMEOUT_MAX - 1; i++) f = recordPutFailure(f, "a", "h-a");
    expect(f.blocked).toEqual([]);
    f = recordPutFailure(f, "a", "h-a");
    expect(f.blocked).toEqual([{ objectId: "a", localCompareHash: "h-a", reason: "UPLOAD_TIMEOUT_MAX" }]);
    expect(f.outbox).toEqual([]); // the never-sent entry carrying it is retired, its blobs queued for cleanup
    expect(f.cleanup.map((c) => c.blobId)).toEqual(["att1-a"]);
    expect(recordPutFailure(prepared(), "a", "h-other").blocked).toEqual([]);
  });
});

describe("§12.2 rules 14-15, §12.3: commit results", () => {
  it("COMMITTED: S := the confirmed revisions (with sequence and the attempt's content blob), entry and attempt leave in one transition", () => {
    const f = applyCommitResult(prepared(), "id0000", {
      kind: "COMMITTED",
      revisions: [{ objectId: "a", revisionId: "id0001", sequence: 7, createdSequence: 7 }],
    });
    expect(f.ok).toBe(true);
    expect(f.facts.outbox).toEqual([]);
    expect(f.facts.attempts).toEqual([]);
    expect(f.facts.cleanup).toEqual([]); // used blobs are confirmed, nothing to release
    // The content ref is a fact of S (control-plane NOTES question 99): the revision stays readable after a restart.
    expect(f.facts.synced.get("a")).toEqual({ ...rev("id0001", 7, "a.md", "h-a", false, 7), content: { blobId: "att1-a", epochId: "e1" } });
    expect(f.facts.remote.get("a")).toEqual(f.facts.synced.get("a"));
  });

  it("a stored result that does not match the outbox is not applied (§12.3: the client must check)", () => {
    const f = prepared();
    const r = applyCommitResult(f, "id0000", {
      kind: "COMMITTED",
      revisions: [{ objectId: "a", revisionId: "other", sequence: 7, createdSequence: 7 }],
    });
    expect(r.ok).toBe(false);
    expect(r.facts).toBe(f);
  });

  it("a definitive rejection retires the entry, records heads in R without regression and queues the blobs for cleanup", () => {
    const f0 = { ...prepared(), remote: new Map([["b", rev("rb9", 9, "b.md", null)]]) };
    const r = applyCommitResult(f0, "id0000", {
      kind: "REJECTED",
      code: "CONFLICT",
      heads: [
        { objectId: "a", head: rev("ra5", 5, "a.md", null) },
        { objectId: "b", head: rev("rb3", 3, "b.md", null) },
      ],
      invalidObjects: null,
    });
    expect(r.facts.outbox).toEqual([]);
    expect(r.facts.attempts).toEqual([]);
    expect(r.facts.cleanup.map((c) => c.blobId)).toEqual(["att1-a"]);
    expect(r.facts.remote.get("a")?.revisionId).toBe("ra5");
    expect(r.facts.remote.get("b")?.revisionId).toBe("rb9");
  });

  it("a second consecutive INVALID_BATCH on the same object and content blocks it (rule 8)", () => {
    const reject = (f: ClientFacts) =>
      applyCommitResult(f, f.outbox[0]!.mutationId, { kind: "REJECTED", code: "INVALID_BATCH", heads: [], invalidObjects: ["a"] }).facts;
    const once = reject(prepared());
    expect(once.blocked).toEqual([]);
    const again = reject(enqueueUploads(once, [up("a", 10)], LIMITS, ids(10).map((i) => `y${i}`)));
    expect(again.blocked).toEqual([{ objectId: "a", localCompareHash: "h-a", reason: "INVALID_BATCH_REPEATED" }]);
  });

  it("INVALID_BATCH without a list counts every entry of the batch", () => {
    const f = enqueueUploads(facts({ invalidBatchCounts: new Map([["b|h-b", 1]]) }), [up("a", 10), up("b", 10)], LIMITS, ids(10));
    const r = applyCommitResult(f, "id0000", { kind: "REJECTED", code: "INVALID_BATCH", heads: [], invalidObjects: null });
    expect(r.facts.invalidBatchCounts.get("a|h-a")).toBe(1);
    expect(r.facts.blocked.map((b) => b.objectId)).toEqual(["b"]);
  });
});

describe("getRevisionStatus (§12.1 table, §18.4)", () => {
  it("all revisions exist → equivalent to COMMITTED", () => {
    const f = markCommitSent(prepared(), "id0000");
    const r = applyRevisionStatus(f, "id0000", [{ revisionId: "id0001", exists: true, objectId: "a", sequence: 4 }]);
    expect(r.outbox).toEqual([]);
    expect(r.synced.get("a")?.revisionId).toBe("id0001");
  });

  it("no revision exists → the entry may be re-encrypted (same mutation_id and revision_ids)", () => {
    const f = markCommitSent(prepared(), "id0000");
    const r = applyRevisionStatus(f, "id0000", [{ revisionId: "id0001", exists: false }]);
    expect(r.outbox[0]).toMatchObject({ mutationId: "id0000", commitSent: false });
    expect(() => recordAttempt(r, attemptFor(r.outbox[0]!, "att2"))).not.toThrow();
  });

  it("a revision_id owned by another object counts as not existing", () => {
    const f = markCommitSent(prepared(), "id0000");
    const r = applyRevisionStatus(f, "id0000", [{ revisionId: "id0001", exists: true, objectId: "zzz", sequence: 4 }]);
    expect(r.outbox[0]?.commitSent).toBe(false);
  });
});

describe("prepare rejections (§11.1, §12.6)", () => {
  it("BLOB_TOO_LARGE: entry retired (never reached commit), content blocked, blobs to cleanup", () => {
    const r = applyPrepareRejection(prepared(), "id0000", "att1-a", "BLOB_TOO_LARGE");
    expect(r.outbox).toEqual([]);
    expect(r.blocked).toEqual([{ objectId: "a", localCompareHash: "h-a", reason: "BLOB_TOO_LARGE" }]);
    expect(r.cleanup.map((c) => c.blobId)).toEqual(["att1-a"]);
  });

  it("EPOCH_STALE on prepare of a never-sent entry: retired without risk", () => {
    const r = applyPrepareRejection(prepared(), "id0000", "att1-a", "EPOCH_STALE");
    expect(r.outbox).toEqual([]);
    expect(r.cleanup.map((c) => c.blobId)).toEqual(["att1-a"]);
  });

  it("BLOB_ID_CONFLICT / BLOB_UNAVAILABLE on prepare: new blob_ids (new attempt), the entry stays", () => {
    for (const code of ["BLOB_ID_CONFLICT", "BLOB_UNAVAILABLE"] as const) {
      const r = applyPrepareRejection(prepared(), "id0000", "att1-a", code);
      expect(r.outbox).toHaveLength(1);
      expect(r.attempts).toEqual([]);
      expect(r.cleanup.map((c) => c.blobId)).toEqual(["att1-a"]);
    }
  });
});

describe("§12.2 rule 13: releaseUpload responses and the cleanup queue", () => {
  const withRecord = () => facts({ cleanup: [{ vaultId: "vault", replicaId: "replica-1", blobId: "b1" }] });
  it.each(["OK", "VAULT_NOT_FOUND", "BLOB_IN_USE", "BLOB_ID_CONFLICT"] as const)("%s deletes the record", (res) => {
    expect(applyRelease(withRecord(), "b1", res).cleanup).toEqual([]);
  });
  it.each(["UPLOAD_IN_PROGRESS", "VAULT_DELETING"] as const)("%s keeps the record", (res) => {
    expect(applyRelease(withRecord(), "b1", res).cleanup).toHaveLength(1);
  });
  it("after re-enrollment, records of the previous replica_id are discarded locally", () => {
    const f = facts({
      cleanup: [
        { vaultId: "vault", replicaId: "replica-0", blobId: "old" },
        { vaultId: "vault", replicaId: "replica-1", blobId: "mine" },
      ],
    });
    expect(discardForeignCleanup(f).cleanup.map((c) => c.blobId)).toEqual(["mine"]);
  });
  it("adoptReplicaId (§6, §35.8): the new replica id, its own cleanup only; outbox and attempts kept; same id changes nothing", () => {
    const f = { ...prepared(), cleanup: [{ vaultId: "vault", replicaId: "replica-1", blobId: "old" }] };
    const adopted = adoptReplicaId(f, "replica-2");
    expect(adopted.replicaId).toBe("replica-2");
    expect(adopted.cleanup).toEqual([]);
    expect(adopted.outbox).toEqual(f.outbox);
    expect(adopted.attempts).toEqual(f.attempts);
    expect(adoptReplicaId(f, "replica-1")).toBe(f);
  });
  it("an attempt of the previous replica id, retired after a re-enrollment, files no cleanup record (§12.2 rule 13)", () => {
    const adopted = adoptReplicaId(prepared(), "replica-2");
    const r = retireExpired(adopted, "id0000", 100);
    expect(r.outbox).toEqual([]);
    expect(r.cleanup).toEqual([]);
    // Broken variant: filing it under the old id would send a release the server answers BLOB_ID_CONFLICT.
    expect(retireExpired(prepared(), "id0000", 100).cleanup.map((c) => c.replicaId)).toEqual(["replica-1"]);
  });
});
