import { describe, expect, it } from "vitest";
import {
  type ClientFacts,
  type UploadAttempt,
  adoptReplicaId,
  applyPrepareRejection,
  emptyFacts,
  endReencryptAttempt,
  enqueueUploads,
  nextOutboxStep,
  recordAttempt,
  recordPrepared,
  recordReencryptAttempt,
  reencryptKey,
} from "../src/outbox.js";
import { utf8 } from "./utf8.js";

// §35.13: a re-encryption's upload is the ordinary write-ahead attempt of rule 13, keyed by its revision,
// and a refused one releases its blobs through the ordinary pending_upload_cleanup queue.

const facts = (over: Partial<ClientFacts> = {}): ClientFacts => ({ ...emptyFacts("vault", "replica-1", "e2"), ...over });
const blob = (blobId: string, kind: "CONTENT" | "MANIFEST" = "MANIFEST") => ({ blobId, kind, objectId: "o", declaredSize: 10, ciphertextSha256: `sha-${blobId}`, ciphertext: utf8(blobId), forDelete: false, expiresAt: null });
const attempt = (revisionId: string, attemptId: string, blobs = [blob(`${attemptId}-m`), blob(`${attemptId}-c`, "CONTENT")], replicaId = "replica-1"): UploadAttempt => ({
  attemptId,
  mutationId: reencryptKey(revisionId),
  replicaId,
  epochId: "e2",
  blobs,
  reencrypt: { revisionId, expectedManifestBlobId: "old-m", newManifestBlobId: `${attemptId}-m`, newContentBlobId: `${attemptId}-c` },
});
const cleaned = (f: ClientFacts) => f.cleanup.map((c) => c.blobId);

describe("§35.13 re-encryption attempts", () => {
  it("one per revision: a new attempt for the same revision sends the previous one's blobs to the cleanup queue", () => {
    let f = recordReencryptAttempt(facts(), attempt("r1", "a1"));
    f = recordReencryptAttempt(f, attempt("r2", "a2"));
    expect(f.attempts.map((a) => a.attemptId)).toEqual(["a1", "a2"]);
    expect(f.cleanup).toEqual([]);
    f = recordReencryptAttempt(f, attempt("r1", "a3"));
    expect(f.attempts.map((a) => a.attemptId)).toEqual(["a2", "a3"]);
    expect(cleaned(f)).toEqual(["a1-m", "a1-c"]);
  });

  it("a swap that succeeded leaves nothing to release; a refused one releases every blob of the attempt", () => {
    const f = recordReencryptAttempt(recordReencryptAttempt(facts(), attempt("r1", "a1")), attempt("r2", "a2"));
    const swapped = endReencryptAttempt(f, "r1", true);
    expect(swapped.attempts.map((a) => a.attemptId)).toEqual(["a2"]);
    expect(swapped.cleanup).toEqual([]);
    const refused = endReencryptAttempt(f, "r2", false);
    expect(refused.attempts.map((a) => a.attemptId)).toEqual(["a1"]);
    expect(cleaned(refused)).toEqual(["a2-m", "a2-c"]);
    // A reused content blob is not the attempt's (it is not in its blobs): it is never released.
    const reused = recordReencryptAttempt(facts(), { ...attempt("r3", "a4", [blob("a4-m")]), reencrypt: { revisionId: "r3", expectedManifestBlobId: "old", newManifestBlobId: "a4-m", newContentBlobId: "shared-new" } });
    expect(cleaned(endReencryptAttempt(reused, "r3", false))).toEqual(["a4-m"]);
    // Ending an attempt that is not there changes nothing.
    expect(endReencryptAttempt(f, "r9", false)).toBe(f);
  });

  it("an attempt of a previous replica_id (a re-enrollment, §18.3) is dropped without releasing what this replica does not own", () => {
    const f = adoptReplicaId(recordReencryptAttempt(facts(), attempt("r1", "a1")), "replica-2");
    expect(cleaned(endReencryptAttempt(f, "r1", false))).toEqual([]);
  });

  it("the outbox never touches them: its entries, attempts and rejections leave re-encryption attempts alone", () => {
    let f = recordReencryptAttempt(facts(), attempt("r1", "a1"));
    f = enqueueUploads(f, [{ objectId: "x", expectedHeadRevisionId: null, path: "x.md", deleted: false, localCompareHash: "h", plaintext: utf8("x"), newBlobBytes: 5 }], { pendingBudgetBytes: 100 }, ["m1", "r-x"]);
    f = recordAttempt(f, { attemptId: "o1", mutationId: "m1", replicaId: "replica-1", epochId: "e2", blobs: [blob("o1-m")] });
    expect(nextOutboxStep(f, 0, new Set())).toEqual({ kind: "prepare", mutationId: "m1", blobId: "o1-m" });
    f = applyPrepareRejection(f, "m1", "o1-m", "BLOB_UNAVAILABLE");
    expect(f.attempts.map((a) => a.attemptId)).toEqual(["a1"]);
    // Its prepare deadlines are facts like any attempt's.
    expect(recordPrepared(f, "a1-m", 40).attempts[0]!.blobs[0]!.expiresAt).toBe(40);
  });

  it("refuses an attempt that is not a re-encryption's", () => {
    expect(() => recordReencryptAttempt(facts(), { ...attempt("r1", "a1"), mutationId: "m1" })).toThrow();
    const { reencrypt: _, ...plain } = attempt("r1", "a1");
    expect(() => recordReencryptAttempt(facts(), plain)).toThrow();
  });
});
