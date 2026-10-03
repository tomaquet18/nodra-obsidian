import { describe, expect, it } from "vitest";
import {
  type ClientFacts,
  type UploadAttempt,
  applyCommitResult,
  applyPrepareRejection,
  emptyFacts,
  enqueueUploads,
  markCommitSent,
  recordAttempt,
  recordPrepared,
  setWriteEpoch,
} from "../../src/outbox.js";
import { DEFAULT_SERVER } from "./scenario.js";
import { type CommitRequest, type Server, commit, expireMutationRows, newServer, prepare, put, remoteCommit, rotateEpoch } from "./server.js";
import { text, utf8 } from "../utf8.js";

// Deterministic §44.1 cases for the outbox against the server model.

const R = "replica-1";
let counter = 0;
const ids = () => Array.from({ length: 8 }, () => `id${counter++}`);

function upload(f: ClientFacts, objectId: string, content: string, expected: string | null = null): ClientFacts {
  return enqueueUploads(
    f,
    [{ objectId, expectedHeadRevisionId: expected, path: `${objectId}.md`, deleted: false, localCompareHash: `h:${content}`, plaintext: utf8(content), newBlobBytes: 100 }],
    { pendingBudgetBytes: 10_000 },
    ids(),
  );
}

/** Encrypts (write-ahead), prepares and PUTs every blob of the last entry; returns the commit request. */
function uploadBlobs(s: Server, f0: ClientFacts, mutationId: string): { facts: ClientFacts; request: CommitRequest; prepareCodes: string[] } {
  const entry = f0.outbox.find((e) => e.mutationId === mutationId)!;
  const attempt: UploadAttempt = {
    attemptId: `att-${counter++}`,
    mutationId,
    replicaId: R,
    epochId: f0.epochId,
    blobs: entry.objects.flatMap((o) => [
      { blobId: `man-${o.revisionId}-${counter++}`, kind: "MANIFEST" as const, objectId: o.objectId, declaredSize: 50, ciphertextSha256: `s${counter}`, ciphertext: utf8(`x|${JSON.stringify({ path: o.path, deleted: false })}`), forDelete: false, expiresAt: null },
      { blobId: `con-${o.revisionId}-${counter++}`, kind: "CONTENT" as const, objectId: o.objectId, declaredSize: 50, ciphertextSha256: `s${counter}`, ciphertext: utf8(`x|${text(o.plaintext!)}`), forDelete: false, expiresAt: null },
    ]),
  };
  let facts = recordAttempt(f0, attempt);
  const prepareCodes: string[] = [];
  for (const b of attempt.blobs) {
    const res = prepare(s, R, { blobId: b.blobId, epochId: attempt.epochId, kind: b.kind, declaredSize: b.declaredSize, sha: b.ciphertextSha256, forDelete: false, objectId: b.objectId, plaintext: null });
    prepareCodes.push(res.ok ? "OK" : res.code);
    if (res.ok) {
      facts = recordPrepared(facts, b.blobId, s.now + res.expiresIn);
      put(s, R, b.blobId, b.ciphertext);
    }
  }
  const request: CommitRequest = {
    mutationId,
    epochId: attempt.epochId,
    revisions: entry.objects.map((o) => ({
      objectId: o.objectId,
      revisionId: o.revisionId,
      expectedHeadRevisionId: o.expectedHeadRevisionId,
      deleted: false,
      manifestBlobId: attempt.blobs.find((b) => b.objectId === o.objectId && b.kind === "MANIFEST")!.blobId,
      contentBlobId: attempt.blobs.find((b) => b.objectId === o.objectId && b.kind === "CONTENT")!.blobId,
    })),
  };
  return { facts: markCommitSent(facts, mutationId), request, prepareCodes };
}

const fresh = () => ({ s: newServer(DEFAULT_SERVER), f: emptyFacts("vault", R, "e1") });

describe("§44.1: commit, lost responses and retries", () => {
  it("commit OK + lost response + retry → the stored result; applied once", () => {
    const { s, f } = fresh();
    const f1 = upload(f, "a", "one");
    const { facts, request } = uploadBlobs(s, f1, f1.outbox[0]!.mutationId);
    const first = commit(s, R, request); // response lost
    const retry = commit(s, R, request);
    expect(retry).toEqual(first);
    expect(s.log.applied.get(request.mutationId)).toBe(1);
    expect(applyCommitResult(facts, request.mutationId, retry).facts.outbox).toEqual([]);
  });

  it("committed mutation retry after an epoch rotation → original result, never EPOCH_STALE", () => {
    const { s, f } = fresh();
    const f1 = upload(f, "a", "one");
    const { request } = uploadBlobs(s, f1, f1.outbox[0]!.mutationId);
    const first = commit(s, R, request);
    rotateEpoch(s);
    expect(commit(s, R, request)).toEqual(first);
  });

  it("retry after the mutations row expired → COMMITTED reconstructed from object_revisions (§12.3 step 5)", () => {
    const { s, f } = fresh();
    const f1 = upload(f, "a", "one");
    const { facts, request } = uploadBlobs(s, f1, f1.outbox[0]!.mutationId);
    const first = commit(s, R, request);
    expireMutationRows(s);
    rotateEpoch(s);
    const retry = commit(s, R, request);
    expect(retry).toEqual(first);
    expect(s.log.reconstructed).toBe(1);
    expect(applyCommitResult(facts, request.mutationId, retry).ok).toBe(true);
  });

  it("some revision_ids of the batch already exist → INVALID_BATCH (a mutation commits whole or not at all)", () => {
    const { s, f } = fresh();
    const f1 = upload(f, "a", "one");
    const { request } = uploadBlobs(s, f1, f1.outbox[0]!.mutationId);
    commit(s, R, request);
    expireMutationRows(s);
    const tampered = { ...request, revisions: [...request.revisions, { ...request.revisions[0]!, objectId: "b", revisionId: "new-rev" }] };
    expect(commit(s, R, tampered)).toMatchObject({ kind: "REJECTED", code: "INVALID_BATCH" });
  });

  it("commit OK + lost response + the user keeps editing + EPOCH_STALE → the later edit goes in a new mutation and is not lost", () => {
    const { s, f } = fresh();
    const f1 = upload(f, "a", "one");
    const m1 = f1.outbox[0]!.mutationId;
    const sent = uploadBlobs(s, f1, m1);
    commit(s, R, sent.request); // applied, response lost
    rotateEpoch(s);
    // Resend: the stored result, even under the new epoch.
    let facts = applyCommitResult(sent.facts, m1, commit(s, R, sent.request)).facts;
    expect(facts.synced.get("a")?.revisionId).toBe(sent.request.revisions[0]!.revisionId);
    // The later edit: a new entry with a new mutation_id; its stale-epoch prepare is retired without risk.
    facts = upload(facts, "a", "two", facts.synced.get("a")!.revisionId);
    const m2 = facts.outbox[0]!.mutationId;
    expect(m2).not.toBe(m1);
    const stale = uploadBlobs(s, { ...facts }, m2);
    expect(stale.prepareCodes[0]).toBe("EPOCH_STALE");
    facts = setWriteEpoch(applyPrepareRejection({ ...stale.facts, outbox: stale.facts.outbox.map((e) => ({ ...e, commitSent: false })) }, m2, stale.request.revisions[0]!.manifestBlobId, "EPOCH_STALE"), s.epoch);
    expect(facts.outbox).toEqual([]);
    facts = upload(facts, "a", "two", facts.synced.get("a")!.revisionId);
    const ok = uploadBlobs(s, facts, facts.outbox[0]!.mutationId);
    const result = commit(s, R, ok.request);
    expect(result.kind).toBe("COMMITTED");
    expect(s.heads.get("a")?.content).toBe("two");
  });

  it("uncommitted stale attempt → EPOCH_STALE → entry retired; the next upload has a new mutation_id", () => {
    const { s, f } = fresh();
    const f1 = upload(f, "a", "one");
    const m1 = f1.outbox[0]!.mutationId;
    const { facts, request } = uploadBlobs(s, f1, m1);
    rotateEpoch(s);
    const r = commit(s, R, request);
    expect(r).toMatchObject({ kind: "REJECTED", code: "EPOCH_STALE" });
    const after = applyCommitResult(facts, m1, r).facts;
    expect(after.outbox).toEqual([]);
    expect(after.cleanup.length).toBe(2); // its blobs go to the cleanup queue in the same transition
    expect(upload(after, "a", "one").outbox[0]!.mutationId).not.toBe(m1);
  });

  it("prepare with an obsolete epoch → EPOCH_STALE", () => {
    const { s, f } = fresh();
    rotateEpoch(s);
    const f1 = upload(f, "a", "one");
    expect(uploadBlobs(s, f1, f1.outbox[0]!.mutationId).prepareCodes).toEqual(["EPOCH_STALE", "EPOCH_STALE"]);
  });

  it("a batch with one object in CONFLICT is rejected whole; nothing is applied", () => {
    const { s, f } = fresh();
    remoteCommit(s, "b", { path: "b.md", content: "remote", deleted: false });
    let f1 = upload(f, "a", "one");
    f1 = enqueueUploads(
      { ...f1, outbox: [] },
      [
        { objectId: "a", expectedHeadRevisionId: null, path: "a.md", deleted: false, localCompareHash: "h:one", plaintext: utf8("one"), newBlobBytes: 10 },
        { objectId: "b", expectedHeadRevisionId: "stale", path: "b.md", deleted: false, localCompareHash: "h:mine", plaintext: utf8("mine"), newBlobBytes: 10 },
      ],
      { pendingBudgetBytes: 10_000 },
      ids(),
    );
    const { request } = uploadBlobs(s, f1, f1.outbox[0]!.mutationId);
    const r = commit(s, R, request);
    expect(r).toMatchObject({ kind: "REJECTED", code: "CONFLICT", heads: [{ objectId: "b" }] });
    expect(s.heads.has("a")).toBe(false);
  });

  it("OBJECT_DELETED has priority over CONFLICT (§12.5 order)", () => {
    const { s, f } = fresh();
    remoteCommit(s, "a", { path: "a.md", content: "x", deleted: false });
    remoteCommit(s, "a", { path: "a.md", content: "", deleted: true });
    const f1 = upload(f, "a", "one", "stale");
    const { request } = uploadBlobs(s, f1, f1.outbox[0]!.mutationId);
    expect(commit(s, R, request)).toMatchObject({ kind: "REJECTED", code: "OBJECT_DELETED" });
  });

  it("upload OK + commit lost before the server → the same entry is resent with the same mutation_id", () => {
    const { s, f } = fresh();
    const f1 = upload(f, "a", "one");
    const { facts, request } = uploadBlobs(s, f1, f1.outbox[0]!.mutationId);
    // (the first commit never arrived)
    expect(facts.outbox[0]).toMatchObject({ mutationId: request.mutationId, commitSent: true });
    expect(commit(s, R, request).kind).toBe("COMMITTED");
  });
});
