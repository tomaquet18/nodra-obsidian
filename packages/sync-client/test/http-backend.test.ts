import { routes } from "@nodra/protocol";
import { describe, expect, it } from "vitest";
import { type BlobOpener, SyncBackendError, httpSyncBackend } from "../src/http-backend.js";
import { UPLOAD_TIMEOUT } from "../src/ports.js";
import { devManifestCodec } from "../src/dev-crypto.js";
import { utf8 } from "./support/bytes.js";

// The adapter against a scripted server: what it sends, and how every answer maps onto the port.
// The real Worker and SQL are exercised end to end in tests/integration.

const id = (n: number) => `0190a1b2-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const V = id(100);
const E = id(101);
const sha = "cd".repeat(32);

type Reply = [status: number, body: unknown];

/** A server as a table "METHOD path" → reply (or a function of the request body). */
function scripted(table: Record<string, Reply | ((body: unknown) => Reply)>) {
  const seen: Array<{ method: string; path: string; body: unknown; auth: string | null }> = [];
  /** The exact bytes of every binary request body, in order. */
  const binaryBodies: Uint8Array[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const path = url.pathname + url.search;
    const method = init?.method ?? "GET";
    const raw = init?.body;
    const body = raw instanceof Uint8Array ? new TextDecoder().decode(raw) : typeof raw === "string" ? JSON.parse(raw) : undefined;
    if (raw instanceof Uint8Array) binaryBodies.push(raw);
    seen.push({ method, path, body, auth: new Headers(init?.headers).get("authorization") });
    const entry = table[`${method} ${path}`];
    if (entry === undefined) return new Response(JSON.stringify({ error: "NOT_FOUND" }), { status: 404 });
    const [status, reply] = typeof entry === "function" ? entry(body) : entry;
    return new Response(reply instanceof Uint8Array ? (reply as Uint8Array<ArrayBuffer>) : typeof reply === "string" ? reply : JSON.stringify(reply), { status });
  };
  return { fetch: fetchImpl, seen, binaryBodies };
}

/**
 * The §8 manifest of revision `n`, in the Phase 0 format the fake crypto uses. Its ids must be the
 * revision's: the adapter now checks them against the event or head that named the manifest (§8).
 */
const manifestFor = (n: number, path: string, objectId: string, over: Record<string, unknown> = {}) =>
  devManifestCodec.encodeManifest({
    objectId,
    revisionId: id(n),
    parentRevisionId: null,
    path,
    mtimeMs: 0,
    deleted: false,
    content: { blobId: id(n + 20), epochId: E, fingerprint: "", plaintextSize: 0 },
    ...over,
  } as Parameters<typeof devManifestCodec.encodeManifest>[0]);

/** Fake crypto: the ciphertext is the bytes of `<blobId>|` followed by the plaintext bytes. */
const opener: BlobOpener = {
  ...devManifestCodec,
  async open({ blobId, ciphertext }) {
    const prefix = utf8(`${blobId}|`);
    if (!prefix.every((b, i) => ciphertext[i] === b)) throw new Error("misbound blob");
    return ciphertext.slice(prefix.length);
  },
};
const sealed = (blobId: string, plaintext: string | Uint8Array): Reply => {
  const body = typeof plaintext === "string" ? utf8(plaintext) : plaintext;
  const prefix = utf8(`${blobId}|`);
  const out = new Uint8Array(prefix.length + body.length);
  out.set(prefix);
  out.set(body, prefix.length);
  return [200, out];
};

const backendOver = (server: ReturnType<typeof scripted>) =>
  httpSyncBackend({ baseUrl: "https://api.test", vaultId: V, fetch: server.fetch, headers: () => ({ authorization: "Bearer dev" }), opener, pageLimit: 500 });

const head = (n: number, over: Record<string, unknown> = {}) => ({
  revisionId: id(n),
  sequence: n,
  deleted: false,
  createdSequence: 1,
  parentRevisionId: null,
  pruned: false,
  manifestBlobId: id(n + 10),
  manifestEpochId: E,
  contentBlobId: id(n + 20),
  contentEpochId: E,
  ...over,
});
const revisionEvent = (n: number) => ({
  sequence: n,
  eventType: "REVISION",
  objectId: id(n + 30),
  revisionId: id(n),
  deleted: false,
  createdSequence: n,
  mutationId: id(n + 40),
  manifestBlobId: id(n + 10),
  manifestEpochId: E,
  contentBlobId: id(n + 20),
  contentEpochId: E,
  batchIndex: 0,
  batchSize: 1,
});
const prepareInput = { blobId: id(1), epochId: E, kind: "CONTENT" as const, declaredSize: 10, ciphertextSha256: sha, forDelete: false, objectId: id(2) };
const rejected = async (p: Promise<unknown>) => {
  const e = await p.then(
    () => null,
    (x: unknown) => x,
  );
  expect(e).toBeInstanceOf(SyncBackendError);
  return e as SyncBackendError;
};

describe("requests", () => {
  it("each operation goes to its route with the auth headers and the protocol body", async () => {
    const server = scripted({
      [`POST ${routes.prepareUpload(V)}`]: [200, { ok: true, expiresInSeconds: 3600 }],
      [`PUT ${routes.blob(V, id(1))}`]: [200, { ok: true }],
      [`POST ${routes.releaseUpload(V, id(1))}`]: [200, { result: "OK" }],
      [`POST ${routes.revisionStatus(V)}`]: [200, { kind: "STATUS", revisions: [{ revisionId: id(5), exists: true, objectId: id(4), sequence: 3 }, { revisionId: id(6), exists: false }] }],
      [`POST ${routes.commitMutation(V)}`]: [200, { kind: "COMMITTED", revisions: [{ objectId: id(4), revisionId: id(5), sequence: 3, createdSequence: 3, contentFingerprint: null }] }],
    });
    const b = backendOver(server);
    expect(await b.prepareUpload(prepareInput)).toEqual({ ok: true, expiresInSeconds: 3600 });
    expect(await b.uploadBlob(id(1), utf8("cipher ✓"))).toEqual({ ok: true });
    expect(await b.releaseUpload(id(1))).toBe("OK");
    expect(await b.getRevisionStatus([id(5), id(6)])).toEqual([{ revisionId: id(5), exists: true, objectId: id(4), sequence: 3 }, { revisionId: id(6), exists: false }]);
    const revisions = [{ objectId: id(4), revisionId: id(5), expectedHeadRevisionId: null, deleted: false, manifestBlobId: id(7), contentBlobId: id(1) }];
    expect(await b.commitMutation({ mutationId: id(8), epochId: E, revisions })).toEqual({ kind: "COMMITTED", revisions: [{ objectId: id(4), revisionId: id(5), sequence: 3, createdSequence: 3 }] });
    expect(server.seen).toEqual([
      { method: "POST", path: routes.prepareUpload(V), auth: "Bearer dev", body: { blobId: id(1), epochId: E, kind: "CONTENT", declaredSize: 10, ciphertextSha256: sha, forDelete: false, fingerprint: null } },
      { method: "PUT", path: routes.blob(V, id(1)), auth: "Bearer dev", body: "cipher ✓" },
      { method: "POST", path: routes.releaseUpload(V, id(1)), auth: "Bearer dev", body: undefined },
      { method: "POST", path: routes.revisionStatus(V), auth: "Bearer dev", body: { revisionIds: [id(5), id(6)] } },
      { method: "POST", path: routes.commitMutation(V), auth: "Bearer dev", body: { mutationId: id(8), epochId: E, revisions } },
    ]);
  });
});

describe("events, heads and content: manifests are opened into paths", () => {
  it("a page becomes SyncEvents with paths; a manifest is fetched once", async () => {
    const server = scripted({
      [`GET ${routes.listEvents(V, 0, 500)}`]: [200, { kind: "PAGE", events: [revisionEvent(1), { sequence: 2, eventType: "EPOCH_ROTATED", epochId: id(99), batchIndex: 0, batchSize: 1 }] }],
      [`GET ${routes.listEvents(V, 2, 500)}`]: [200, { kind: "PAGE", events: [{ ...revisionEvent(1), sequence: 3, revisionId: id(3), parentRevisionId: id(1) }] }],
      [`GET ${routes.blob(V, id(11))}`]: sealed(id(11), manifestFor(1, "notes/a.md", id(31))),
    });
    const b = backendOver(server);
    expect(await b.listEvents(0)).toEqual({
      kind: "PAGE",
      events: [
        { kind: "REVISION", sequence: 1, objectId: id(31), revisionId: id(1), parentRevisionId: null, path: "notes/a.md", deleted: false, createdSequence: 1, mutationId: id(41), batchIndex: 0, batchSize: 1, content: { blobId: id(21), epochId: E } },
        { kind: "EPOCH_ROTATED", sequence: 2, epochId: id(99), batchIndex: 0, batchSize: 1 },
      ],
    });
    expect(await b.listEvents(2)).toMatchObject({ kind: "PAGE", events: [{ revisionId: id(3), parentRevisionId: id(1), path: "notes/a.md" }] });
    expect(server.seen.filter((s) => s.path === routes.blob(V, id(11)))).toHaveLength(1);
  });

  it("a SECURITY event (§37) becomes a SyncEvent that only carries its sequence and id", async () => {
    const b = backendOver(
      scripted({ [`GET ${routes.listEvents(V, 0, 500)}`]: [200, { kind: "PAGE", events: [{ sequence: 1, eventType: "SECURITY", securityEventId: 4, batchIndex: 0, batchSize: 1 }] }] }),
    );
    expect(await b.listEvents(0)).toEqual({ kind: "PAGE", events: [{ kind: "SECURITY", sequence: 1, securityEventId: 4, batchIndex: 0, batchSize: 1 }] });
  });

  it("readRevision reads the content an event named; bytes gone → PRUNED", async () => {
    const server = scripted({
      [`GET ${routes.listEvents(V, 0, 500)}`]: [200, { kind: "PAGE", events: [revisionEvent(1), revisionEvent(2)] }],
      [`GET ${routes.blob(V, id(11))}`]: sealed(id(11), manifestFor(1, "a.md", id(31))),
      [`GET ${routes.blob(V, id(12))}`]: sealed(id(12), manifestFor(2, "b.md", id(32))),
      [`GET ${routes.blob(V, id(21))}`]: sealed(id(21), "hello"),
      [`GET ${routes.blob(V, id(22))}`]: [404, { error: "BLOB_NOT_FOUND" }],
      // Read again (§35.13 "Otras réplicas"): not a head any more, and no sequence to find its event by.
      [`GET ${routes.vaultState(V)}`]: [200, { kind: "STATE", sequence: 2, epochId: E, heads: [] }],
    });
    const b = backendOver(server);
    await b.listEvents(0);
    expect(await b.readRevision(id(1))).toEqual({ kind: "CONTENT", plaintext: utf8("hello") });
    expect(await b.readRevision(id(2))).toEqual({ kind: "PRUNED" });
  });

  it("§35.13 listRevisionsToReencrypt opens each old manifest with its revision's binding; reencryptRevision maps its answers", async () => {
    const listed = { revisionId: id(5), objectId: id(31), parentRevisionId: id(4), deleted: false, manifestBlobId: id(15), manifestEpochId: E, contentBlobId: id(25), contentEpochId: E };
    const opened: unknown[] = [];
    const server = scripted({
      [`GET ${routes.revisionsToReencrypt(V, null, 2)}`]: [200, { kind: "PAGE", revisions: [listed], next: `${id(25)}/${id(5)}` }],
      [`GET ${routes.revisionsToReencrypt(V, `${id(25)}/${id(5)}`, 2)}`]: [200, { kind: "INVALID_STATE" }],
      [`GET ${routes.blob(V, id(15))}`]: sealed(id(15), manifestFor(5, "a.md", id(31), { parentRevisionId: id(4) })),
      [`POST ${routes.reencryptRevision(V)}`]: (body) => [200, (body as { revisionId: string }).revisionId === id(5) ? { ok: true } : (body as { revisionId: string }).revisionId === id(6) ? { ok: false, code: "REVISION_CHANGED" } : { ok: false, code: "VAULT_DELETING" }],
    });
    const b = httpSyncBackend({ baseUrl: "https://api.test", vaultId: V, fetch: server.fetch, headers: () => ({}), opener: { ...opener, open: async (x) => (opened.push(x.binding), opener.open(x)) } });
    const page = await b.listRevisionsToReencrypt(null, 2);
    expect(page).toMatchObject({ kind: "PAGE", next: `${id(25)}/${id(5)}`, revisions: [{ revisionId: id(5), content: { blobId: id(25), epochId: E }, manifest: { path: "a.md", parentRevisionId: id(4) } }] });
    expect(opened).toEqual([{ objectId: id(31), revisionId: id(5), parentRevisionId: id(4) }]);
    expect(await b.listRevisionsToReencrypt(`${id(25)}/${id(5)}`, 2)).toEqual({ kind: "INVALID_STATE" });
    const req = { revisionId: id(5), expectedManifestBlobId: id(15), newManifestBlobId: id(45), newContentBlobId: id(55) };
    expect(await b.reencryptRevision(req)).toEqual({ ok: true });
    expect(await b.reencryptRevision({ ...req, revisionId: id(6) })).toEqual({ ok: false, code: "REVISION_CHANGED" });
    // VAULT_DELETING keeps everything: thrown, like every other write (§11.4).
    expect((await rejected(b.reencryptRevision({ ...req, revisionId: id(7) }))).code).toBe("VAULT_DELETING");
    expect(server.seen.find((s) => s.method === "POST")?.body).toEqual(req);
  });

  it("prepareUpload sends forReencrypt only when the blob re-encrypts a revision", async () => {
    const server = scripted({ [`POST ${routes.prepareUpload(V)}`]: [200, { ok: true, expiresInSeconds: 3600 }] });
    const b = backendOver(server);
    await b.prepareUpload(prepareInput);
    await b.prepareUpload({ ...prepareInput, forReencrypt: id(5) });
    expect(server.seen.map((s) => (s.body as { forReencrypt?: string }).forReencrypt)).toEqual([undefined, id(5)]);
    expect("forReencrypt" in (server.seen[0]!.body as object)).toBe(false);
  });

  describe("§44.3 T21: a replica holding a blob_id that a re-encryption replaced (§35.13)", () => {
    const E2 = id(102);
    /** Revision 5's blobs after the swap: manifest 45 and content 55, in the new epoch. */
    const swapped = (over: Record<string, unknown> = {}) => head(5, { manifestBlobId: id(45), manifestEpochId: E2, contentBlobId: id(55), contentEpochId: E2, ...over });
    const newManifest = sealed(id(45), manifestFor(5, "a.md", id(31), { content: { blobId: id(55), epochId: E2, fingerprint: "", plaintextSize: 0 } }));

    it("BLOB_NOT_FOUND on the recorded ref: the head is read again and its new blob downloaded; the plaintext is the same", async () => {
      const server = scripted({
        [`GET ${routes.blob(V, id(25))}`]: [404, { error: "BLOB_NOT_FOUND" }],
        [`GET ${routes.vaultState(V)}`]: [200, { kind: "STATE", sequence: 5, epochId: E2, heads: [{ objectId: id(31), head: swapped() }] }],
        [`GET ${routes.blob(V, id(45))}`]: newManifest,
        [`GET ${routes.blob(V, id(55))}`]: sealed(id(55), "unchanged"),
      });
      const b = backendOver(server);
      expect(await b.readRevision(id(5), { blobId: id(25), epochId: E }, 5)).toEqual({ kind: "CONTENT", plaintext: utf8("unchanged") });
      expect(server.seen.map((s) => s.path)).toEqual([routes.blob(V, id(25)), routes.vaultState(V), routes.blob(V, id(45)), routes.blob(V, id(55))]);
    });

    it("a revision that is no longer a head is read again from its own REVISION event (listEvents from its sequence)", async () => {
      const server = scripted({
        [`GET ${routes.blob(V, id(22))}`]: [404, { error: "BLOB_NOT_FOUND" }],
        [`GET ${routes.vaultState(V)}`]: [200, { kind: "STATE", sequence: 9, epochId: E2, heads: [] }],
        [`GET ${routes.listEvents(V, 1, 500)}`]: [200, { kind: "PAGE", events: [{ ...revisionEvent(2), manifestBlobId: id(42), manifestEpochId: E2, contentBlobId: id(52), contentEpochId: E2 }] }],
        [`GET ${routes.blob(V, id(42))}`]: sealed(id(42), manifestFor(2, "b.md", id(32), { content: { blobId: id(52), epochId: E2, fingerprint: "", plaintextSize: 0 } })),
        [`GET ${routes.blob(V, id(52))}`]: sealed(id(52), "old but live"),
      });
      const b = backendOver(server);
      expect(await b.readRevision(id(2), { blobId: id(22), epochId: E }, 2)).toEqual({ kind: "CONTENT", plaintext: utf8("old but live") });
    });

    it("read again, its new blob gone too → PRUNED, once: no loop, and never CORRUPTION_OR_MISBINDING", async () => {
      const server = scripted({
        [`GET ${routes.blob(V, id(25))}`]: [404, { error: "BLOB_NOT_FOUND" }],
        [`GET ${routes.blob(V, id(55))}`]: [404, { error: "BLOB_NOT_FOUND" }],
        [`GET ${routes.vaultState(V)}`]: [200, { kind: "STATE", sequence: 5, epochId: E2, heads: [{ objectId: id(31), head: swapped() }] }],
        [`GET ${routes.blob(V, id(45))}`]: newManifest,
      });
      const b = backendOver(server);
      expect(await b.readRevision(id(5), { blobId: id(25), epochId: E }, 5)).toEqual({ kind: "PRUNED" });
      expect(server.seen.filter((s) => s.path === routes.vaultState(V))).toHaveLength(1);
    });
  });

  it("binary content goes both ways byte for byte: the PUT body is the ciphertext, readRevision the exact plaintext", async () => {
    // Invalid UTF-8, NUL, a BOM and every byte value: any text decoding on the way would change them.
    const binary = Uint8Array.from([0xef, 0xbb, 0xbf, 0, 0xff, 0xc3, 0x28, ...Array.from({ length: 256 }, (_, i) => i)]);
    const server = scripted({
      [`GET ${routes.listEvents(V, 0, 500)}`]: [200, { kind: "PAGE", events: [revisionEvent(1)] }],
      [`GET ${routes.blob(V, id(11))}`]: sealed(id(11), manifestFor(1, "img.png", id(31))),
      [`GET ${routes.blob(V, id(21))}`]: sealed(id(21), binary),
      [`PUT ${routes.blob(V, id(1))}`]: [200, { ok: true }],
    });
    const b = backendOver(server);
    await b.listEvents(0);
    expect(await b.readRevision(id(1))).toEqual({ kind: "CONTENT", plaintext: binary });
    expect(await b.uploadBlob(id(1), binary)).toEqual({ ok: true });
    expect(server.binaryBodies).toEqual([binary]);
  });

  it("without a recorded ref, after a restart readRevision finds a head through getVaultState; an unknown non-head revision is unavailable (PRUNED)", async () => {
    const server = scripted({
      [`GET ${routes.vaultState(V)}`]: [200, { kind: "STATE", sequence: 5, epochId: E, heads: [{ objectId: id(31), head: head(5) }, { objectId: id(32), head: head(6, { deleted: true, pruned: true, manifestBlobId: null, manifestEpochId: null, contentBlobId: null, contentEpochId: null }) }] }],
      [`GET ${routes.blob(V, id(15))}`]: sealed(id(15), manifestFor(5, "a.md", id(31))),
      [`GET ${routes.blob(V, id(25))}`]: sealed(id(25), "head content"),
    });
    const b = backendOver(server);
    expect(await b.readRevision(id(5))).toEqual({ kind: "CONTENT", plaintext: utf8("head content") });
    expect(await b.readRevision(id(4))).toEqual({ kind: "PRUNED" });
    expect((await b.getVaultState()).heads).toEqual([
      { objectId: id(31), head: { revisionId: id(5), sequence: 5, path: "a.md", localCompareHash: null, deleted: false, createdSequence: 1, content: { blobId: id(25), epochId: E } } },
      { objectId: id(32), head: { revisionId: id(6), sequence: 6, path: "", localCompareHash: null, deleted: true, createdSequence: 1, content: null } },
    ]);
  });

  it("after a restart readRevision reads a non-head revision through the ref recorded in S or R (NOTES question 99)", async () => {
    const server = scripted({ [`GET ${routes.blob(V, id(24))}`]: sealed(id(24), "merge base") });
    const b = backendOver(server); // a fresh instance: it has learned nothing
    expect(await b.readRevision(id(4), { blobId: id(24), epochId: E })).toEqual({ kind: "CONTENT", plaintext: utf8("merge base") });
    expect(await b.readRevision(id(6), null)).toEqual({ kind: "PRUNED" }); // a delete has no content
    expect(server.seen.map((s) => s.path)).toEqual([routes.blob(V, id(24))]); // no getVaultState
  });

  it("a blob bound to another id fails to open (the opener's check reaches the caller)", async () => {
    const server = scripted({
      [`GET ${routes.listEvents(V, 0, 500)}`]: [200, { kind: "PAGE", events: [revisionEvent(1)] }],
      [`GET ${routes.blob(V, id(11))}`]: sealed(id(12), manifestFor(1, "a.md", id(31))),
    });
    await expect(backendOver(server).listEvents(0)).rejects.toThrow(/misbound/);
  });

  it("CONFLICT: heads come back as RemoteEntries; a null head is dropped; INVALID_BATCH lists its objects", async () => {
    let reply: unknown;
    const server = scripted({
      [`POST ${routes.commitMutation(V)}`]: () => [200, reply],
      [`GET ${routes.blob(V, id(15))}`]: sealed(id(15), manifestFor(5, "theirs.md", id(31))),
    });
    const b = backendOver(server);
    const input = { mutationId: id(8), epochId: E, revisions: [] };
    reply = { kind: "REJECTED", code: "CONFLICT", heads: [{ objectId: id(31), code: "CONFLICT", head: head(5) }, { objectId: id(33), code: "CONFLICT", head: null }], blobs: [], invalid: null };
    expect(await b.commitMutation(input)).toEqual({
      kind: "REJECTED",
      code: "CONFLICT",
      heads: [{ objectId: id(31), head: { revisionId: id(5), sequence: 5, path: "theirs.md", localCompareHash: null, deleted: false, createdSequence: 1, content: { blobId: id(25), epochId: E } } }],
      invalidObjects: null,
    });
    reply = { kind: "REJECTED", code: "INVALID_BATCH", heads: [], blobs: [], invalid: [{ index: 0, objectId: id(31) }] };
    expect(await b.commitMutation(input)).toEqual({ kind: "REJECTED", code: "INVALID_BATCH", heads: [], invalidObjects: [id(31)] });
  });
});

describe("answers the runner cannot act on are thrown as typed errors (outcome kept unknown)", () => {
  it.each<[string, Record<string, Reply>, (b: ReturnType<typeof backendOver>) => Promise<unknown>, string]>([
    ["prepare VAULT_DELETING", { [`POST ${routes.prepareUpload(V)}`]: [200, { ok: false, code: "VAULT_DELETING" }] }, (b) => b.prepareUpload(prepareInput), "VAULT_DELETING"],
    ["prepare QUOTA_EXCEEDED", { [`POST ${routes.prepareUpload(V)}`]: [200, { ok: false, code: "QUOTA_EXCEEDED" }] }, (b) => b.prepareUpload(prepareInput), "QUOTA_EXCEEDED"],
    ["prepare RATE_LIMITED", { [`POST ${routes.prepareUpload(V)}`]: [200, { ok: false, code: "RATE_LIMITED" }] }, (b) => b.prepareUpload(prepareInput), "RATE_LIMITED"],
    ["PUT UPLOAD_IN_PROGRESS", { [`PUT ${routes.blob(V, id(1))}`]: [200, { ok: false, code: "UPLOAD_IN_PROGRESS" }] }, (b) => b.uploadBlob(id(1), utf8("x")), "UPLOAD_IN_PROGRESS"],
    ["PUT BAD_UPLOAD_LENGTH", { [`PUT ${routes.blob(V, id(1))}`]: [200, { ok: false, code: "BAD_UPLOAD_LENGTH" }] }, (b) => b.uploadBlob(id(1), utf8("x")), "BAD_UPLOAD_LENGTH"],
    ["commit VAULT_DELETING", { [`POST ${routes.commitMutation(V)}`]: [200, { kind: "REJECTED", code: "VAULT_DELETING" }] }, (b) => b.commitMutation({ mutationId: id(8), epochId: E, revisions: [] }), "VAULT_DELETING"],
    [
      "commit QUOTA_EXCEEDED",
      { [`POST ${routes.commitMutation(V)}`]: [200, { kind: "REJECTED", code: "QUOTA_EXCEEDED", heads: [], blobs: [{ blobId: id(1), code: "QUOTA_EXCEEDED" }], invalid: null }] },
      (b) => b.commitMutation({ mutationId: id(8), epochId: E, revisions: [] }),
      "QUOTA_EXCEEDED",
    ],
    ["listEvents VAULT_NOT_FOUND", { [`GET ${routes.listEvents(V, 0, 500)}`]: [404, { error: "VAULT_NOT_FOUND" }] }, (b) => b.listEvents(0), "VAULT_NOT_FOUND"],
    ["getVaultState WRITE_CAPABILITY_REQUIRED", { [`GET ${routes.vaultState(V)}`]: [403, { error: "WRITE_CAPABILITY_REQUIRED" }] }, (b) => b.getVaultState(), "WRITE_CAPABILITY_REQUIRED"],
    ["a SECURITY event that claims a batch", { [`GET ${routes.listEvents(V, 0, 500)}`]: [200, { kind: "PAGE", events: [{ sequence: 1, eventType: "SECURITY", securityEventId: 4, batchIndex: 0, batchSize: 2 }] }] }, (b) => b.listEvents(0), "BAD_RESPONSE"],
    ["a body that does not parse", { [`GET ${routes.vaultState(V)}`]: [200, { kind: "STATE", sequence: -1 }] }, (b) => b.getVaultState(), "BAD_RESPONSE"],
    ["a gateway page that is not JSON", { [`GET ${routes.vaultState(V)}`]: [502, "<html>bad gateway</html>"] }, (b) => b.getVaultState(), "BAD_RESPONSE"],
  ])("%s", async (_, table, op, code) => {
    expect((await rejected(op(backendOver(scripted(table))))).code).toBe(code);
  });

  it.each(["BLOB_CORRUPT_RETRYABLE", "BAD_UPLOAD_LENGTH"])("PUT %s: re-sent once at once with the same blob_id (§12.6); a second one is thrown", async (code) => {
    const replies: Reply[] = [
      [200, { ok: false, code }],
      [200, { ok: true }],
    ];
    const server = scripted({ [`PUT ${routes.blob(V, id(1))}`]: () => replies.shift() ?? [200, { ok: false, code }] });
    expect(await backendOver(server).uploadBlob(id(1), utf8("x"))).toEqual({ ok: true });
    expect(server.seen.map((s) => [s.method, s.body])).toEqual([
      ["PUT", "x"],
      ["PUT", "x"],
    ]);
    const failing = scripted({ [`PUT ${routes.blob(V, id(1))}`]: [200, { ok: false, code }] });
    expect((await rejected(backendOver(failing).uploadBlob(id(1), utf8("x")))).code).toBe(code);
    expect(failing.seen.length).toBe(2);
  });

  it("PUT UPLOAD_TIMEOUT is the port's UPLOAD_TIMEOUT (a failed attempt of the object, §12.6)", async () => {
    const b = backendOver(scripted({ [`PUT ${routes.blob(V, id(1))}`]: [200, { ok: false, code: "UPLOAD_TIMEOUT" }] }));
    expect((await rejected(b.uploadBlob(id(1), utf8("x")))).name).toBe(UPLOAD_TIMEOUT);
  });

  it("port-level answers stay answers: release VAULT_NOT_FOUND (the cleanup record goes), prepare/PUT rejections", async () => {
    const b = backendOver(
      scripted({
        [`POST ${routes.releaseUpload(V, id(1))}`]: [404, { error: "VAULT_NOT_FOUND" }],
        [`POST ${routes.prepareUpload(V)}`]: [200, { ok: false, code: "PENDING_BUDGET_EXCEEDED", limit: "GENERAL" }],
        [`PUT ${routes.blob(V, id(1))}`]: [200, { ok: false, code: "BLOB_CORRUPT" }],
      }),
    );
    expect(await b.releaseUpload(id(1))).toBe("VAULT_NOT_FOUND");
    expect(await b.prepareUpload(prepareInput)).toEqual({ ok: false, code: "PENDING_BUDGET_EXCEEDED" });
    expect(await b.uploadBlob(id(1), utf8("x"))).toEqual({ ok: false, code: "BLOB_CORRUPT" });
  });

  it("a server-given wait travels with the error: the PUT's retryAfterSeconds, or an HTTP Retry-After in seconds", async () => {
    const put = backendOver(scripted({ [`PUT ${routes.blob(V, id(1))}`]: [200, { ok: false, code: "UPLOAD_IN_PROGRESS", retryAfterSeconds: 42 }] }));
    expect(await rejected(put.uploadBlob(id(1), utf8("x")))).toMatchObject({ code: "UPLOAD_IN_PROGRESS", retryAfterSeconds: 42 });
    const withHeader = (status: number, body: unknown, retryAfter: string): typeof fetch => async () => new Response(JSON.stringify(body), { status, headers: { "retry-after": retryAfter } });
    const over = (f: typeof fetch) => httpSyncBackend({ baseUrl: "https://api.test", vaultId: V, fetch: f, headers: () => ({}), opener });
    expect(await rejected(over(withHeader(200, { ok: false, code: "RATE_LIMITED" }, "120")).prepareUpload(prepareInput))).toMatchObject({ code: "RATE_LIMITED", retryAfterSeconds: 120 });
    expect(await rejected(over(withHeader(503, { error: "INTERNAL" }, "7")).getVaultState())).toMatchObject({ code: "INTERNAL", status: 503, retryAfterSeconds: 7 });
    expect(await rejected(over(withHeader(502, "<html>", "30")).getVaultState())).toMatchObject({ code: "BAD_RESPONSE", retryAfterSeconds: 30 });
    // The HTTP-date form is not a number of seconds: ignored (the client's own backoff applies).
    expect((await rejected(over(withHeader(200, { ok: false, code: "RATE_LIMITED" }, "Wed, 21 Oct 2026 07:28:00 GMT")).prepareUpload(prepareInput))).retryAfterSeconds).toBeUndefined();
  });

  it("a lost request is a rejected promise, never an answer", async () => {
    const b = httpSyncBackend({ baseUrl: "https://api.test", vaultId: V, fetch: async () => Promise.reject(new TypeError("fetch failed")), headers: () => ({}), opener });
    await expect(b.commitMutation({ mutationId: id(8), epochId: E, revisions: [] })).rejects.toThrow("fetch failed");
  });
});
