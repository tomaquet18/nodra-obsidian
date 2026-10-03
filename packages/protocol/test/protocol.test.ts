import { describe, expect, it } from "vitest";
import * as P from "../src/index.js";
import type { z } from "zod";
import {
  CommitRequest,
  CommitResponse,
  ErrorBody,
  ListEventsQuery,
  ListEventsResponse,
  PrepareRequest,
  PrepareResponse,
  PutResponse,
  ReleaseResponse,
  RevisionStatusRequest,
  RevisionStatusResponse,
  VaultStateResponse,
  routes,
} from "../src/index.js";

const id = (n: number) => `0190a1b2-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const hex = "ab".repeat(32);

const prepare: PrepareRequest = { blobId: id(1), epochId: id(2), kind: "MANIFEST", declaredSize: 120, ciphertextSha256: hex, forDelete: true, fingerprint: null };
const commit: CommitRequest = {
  mutationId: id(3),
  epochId: id(2),
  revisions: [
    { objectId: id(4), revisionId: id(5), expectedHeadRevisionId: null, deleted: false, manifestBlobId: id(6), contentBlobId: id(7) },
    { objectId: id(8), revisionId: id(9), expectedHeadRevisionId: id(10), deleted: true, manifestBlobId: id(11), contentBlobId: null },
  ],
};
const head = {
  revisionId: id(5),
  sequence: 3,
  deleted: false,
  createdSequence: 1,
  parentRevisionId: null,
  pruned: false,
  manifestBlobId: id(6),
  manifestEpochId: id(2),
  contentBlobId: id(7),
  contentEpochId: id(2),
};

/** Through JSON and back: what a peer sends is what the other side reads. */
const roundTrip = <S extends z.ZodType>(schema: S, value: z.input<S>) => schema.parse(JSON.parse(JSON.stringify(value)));

describe("round trips", () => {
  it.each<[string, z.ZodType, unknown]>([
    ["prepare request", PrepareRequest, prepare],
    ["prepare ok", PrepareResponse, { ok: true, expiresInSeconds: 3600 }],
    ["prepare rejected with limit", PrepareResponse, { ok: false, code: "PENDING_BUDGET_EXCEEDED", limit: "FOR_DELETE" }],
    ["put ok", PutResponse, { ok: true }],
    ["put rejected", PutResponse, { ok: false, code: "BLOB_CORRUPT" }],
    ["release", ReleaseResponse, { result: "BLOB_IN_USE" }],
    ["commit request", CommitRequest, commit],
    ["commit request with attempt", CommitRequest, { ...commit, attemptId: id(12) }],
    ["committed", CommitResponse, { kind: "COMMITTED", revisions: [{ objectId: id(4), revisionId: id(5), sequence: 3, createdSequence: 1, contentFingerprint: hex }] }],
    ["committed rebuilt", CommitResponse, { kind: "COMMITTED", reconstructed: true, revisions: [{ objectId: id(4), revisionId: id(5), sequence: 3, createdSequence: 1 }] }],
    ["vault deleting", CommitResponse, { kind: "REJECTED", code: "VAULT_DELETING" }],
    [
      "conflict",
      CommitResponse,
      { kind: "REJECTED", code: "CONFLICT", heads: [{ objectId: id(4), code: "CONFLICT", head }], blobs: [{ blobId: id(7), code: "BLOB_UNAVAILABLE" }], invalid: null },
    ],
    ["invalid batch", CommitResponse, { kind: "REJECTED", code: "INVALID_BATCH", heads: [], blobs: [], invalid: [{ index: 1, objectId: id(8) }] }],
    [
      "page",
      ListEventsResponse,
      {
        kind: "PAGE",
        events: [
          { sequence: 1, eventType: "REVISION", objectId: id(4), revisionId: id(5), deleted: false, createdSequence: 1, mutationId: id(3), manifestBlobId: id(6), manifestEpochId: id(2), contentBlobId: id(7), contentEpochId: id(2), batchIndex: 0, batchSize: 2 },
          { sequence: 2, eventType: "REVISION", objectId: id(8), revisionId: id(9), parentRevisionId: id(10), deleted: true, createdSequence: 1, mutationId: id(3), manifestBlobId: id(11), manifestEpochId: id(2), batchIndex: 1, batchSize: 2 },
          { sequence: 3, eventType: "EPOCH_ROTATED", epochId: id(13), batchIndex: 0, batchSize: 1 },
        ],
      },
    ],
    ["cursor expired", ListEventsResponse, { kind: "CURSOR_EXPIRED" }],
    ["vault state", VaultStateResponse, { kind: "STATE", sequence: 3, epochId: id(2), heads: [{ objectId: id(4), head }] }],
    ["status request", RevisionStatusRequest, { revisionIds: [id(5), id(9)] }],
    ["status", RevisionStatusResponse, { kind: "STATUS", revisions: [{ revisionId: id(5), exists: true, objectId: id(4), sequence: 3 }, { revisionId: id(9), exists: false }] }],
    ["error", ErrorBody, { error: "VAULT_NOT_FOUND" }],
  ])("%s", (_, schema, value) => {
    expect(roundTrip(schema, value)).toEqual(value);
  });

  it("the events query reads decimal strings", () => {
    const q = new URL(`http://x${routes.listEvents(id(1), 42, 500)}`).searchParams;
    expect(ListEventsQuery.parse(Object.fromEntries(q))).toEqual({ after: 42, limit: 500 });
    expect(ListEventsQuery.parse({ after: "0" })).toEqual({ after: 0 });
  });
});

describe("malformed requests are rejected", () => {
  it.each<[string, unknown]>([
    ["an id that is not a uuid", { ...prepare, blobId: "b-1" }],
    ["a uuid-like id with a non-hex digit", { ...prepare, blobId: "0190A1B2-0000-7000-8000-00000000000G" }],
    ["a short sha", { ...prepare, ciphertextSha256: "ab" }],
    ["an uppercase sha", { ...prepare, ciphertextSha256: hex.toUpperCase() }],
    ["a missing fingerprint key", (({ fingerprint: _, ...rest }) => rest)(prepare)],
    ["an unknown key", { ...prepare, owner: id(9) }],
    ["a negative size", { ...prepare, declaredSize: -1 }],
    ["a fractional size", { ...prepare, declaredSize: 1.5 }],
    ["a size as a string", { ...prepare, declaredSize: "120" }],
    ["an unsafe integer size", { ...prepare, declaredSize: 2 ** 60 }],
    ["an unknown kind", { ...prepare, kind: "IMAGE" }],
    ["forDelete as a string", { ...prepare, forDelete: "true" }],
  ])("prepare: %s", (_, body) => {
    expect(PrepareRequest.safeParse(body).success).toBe(false);
  });

  it.each<[string, unknown]>([
    ["no revisions key", { mutationId: id(3), epochId: id(2) }],
    ["revisions not an array", { ...commit, revisions: {} }],
    ["a null expected head written as a string", { ...commit, revisions: [{ ...commit.revisions[0]!, expectedHeadRevisionId: "null" }] }],
    ["a missing contentBlobId", { ...commit, revisions: [(({ contentBlobId: _, ...rest }) => rest)(commit.revisions[0]!)] }],
    ["an unknown key in an entry", { ...commit, revisions: [{ ...commit.revisions[0]!, path: "a.md" }] }],
    ["an attempt id that is not a uuid", { ...commit, attemptId: 7 }],
  ])("commit: %s", (_, body) => {
    expect(CommitRequest.safeParse(body).success).toBe(false);
  });

  it("an empty or oversized batch is not malformed: it is INVALID_BATCH, decided in §12.5 order", () => {
    expect(CommitRequest.safeParse({ ...commit, revisions: [] }).success).toBe(true);
    expect(CommitRequest.safeParse({ ...commit, revisions: Array.from({ length: 501 }, () => commit.revisions[0]) }).success).toBe(true);
  });

  it.each<[string, Record<string, string>]>([
    ["no after", {}],
    ["a negative after", { after: "-1" }],
    ["an exponent", { after: "1e3" }],
    ["a fraction", { after: "1.5" }],
    ["an unknown parameter", { after: "1", replica: "x" }],
  ])("events query: %s", (_, query) => {
    expect(ListEventsQuery.safeParse(query).success).toBe(false);
  });

  it("revision status: ids must be uuids", () => {
    expect(RevisionStatusRequest.safeParse({ revisionIds: ["r1"] }).success).toBe(false);
    expect(RevisionStatusRequest.safeParse({ revisionIds: [id(1)], extra: true }).success).toBe(false);
  });
});

describe("responses a client must refuse", () => {
  it.each<[string, z.ZodType, unknown]>([
    ["a COMMITTED revision without sequence", CommitResponse, { kind: "COMMITTED", revisions: [{ objectId: id(4), revisionId: id(5), createdSequence: 1 }] }],
    ["a REJECTED CONFLICT without heads", CommitResponse, { kind: "REJECTED", code: "CONFLICT" }],
    ["an unknown commit code", CommitResponse, { kind: "REJECTED", code: "MAYBE", heads: [], blobs: [], invalid: null }],
    ["an event of an unknown type", ListEventsResponse, { kind: "PAGE", events: [{ sequence: 1, eventType: "OTHER", batchIndex: 0, batchSize: 1 }] }],
    ["a REVISION event without its manifest", ListEventsResponse, { kind: "PAGE", events: [{ sequence: 1, eventType: "REVISION", objectId: id(4), revisionId: id(5), deleted: false, createdSequence: 1, mutationId: id(3), batchIndex: 0, batchSize: 1 }] }],
    ["an unknown release answer", ReleaseResponse, { result: "MAYBE" }],
    ["an unknown error code", ErrorBody, { error: "TEAPOT" }],
  ])("%s", (_, schema, value) => {
    expect(schema.safeParse(value).success).toBe(false);
  });
});

describe("§11.3 write capability", () => {
  it("the header round-trips, and only in its exact shape", () => {
    const tokenId = "0189abcd-1234-7def-8000-0123456789ab";
    const secret = "A".repeat(43);
    const value = P.capabilityHeaderValue(tokenId, secret);
    expect(value).toBe(`0189abcd12347def80000123456789ab.${secret}`);
    expect(P.parseCapabilityHeader(value)).toEqual({ tokenId, secret });
    for (const bad of [null, "", value.toUpperCase(), value.replace(".", ":"), `${value}=`, value.slice(0, -1), `x${value}`]) {
      expect(P.parseCapabilityHeader(bad)).toBeNull();
    }
  });

  it("a recipient_id is uuid-shaped but not UUIDv7: §30.1 derives the root ones from SHA-256(SPKI)", () => {
    // Version nibble 3, variant nibble 2: impossible for a UUIDv7, ordinary for a hash slice.
    const fromHash = "9f2c1a0b-4d5e-3f60-2a1b-0c0d0e0f1011";
    expect(P.RecipientId.safeParse(fromHash).success).toBe(true);
    expect(P.Uuid.safeParse(fromHash).success).toBe(false);
    expect(P.ChallengeRequest.safeParse({ recipientId: fromHash }).success).toBe(true);
    // A `replica_id`, by contrast, is a UUIDv7 the client generates (§6).
    expect(P.ChallengeRequest.safeParse({ recipientId: fromHash, replicaId: fromHash }).success).toBe(false);
  });

  it("the two responses are unions on `ok`, and a rejection names one code", () => {
    expect(P.ChallengeResponse.safeParse({ ok: true, challenge: "ab".repeat(16), sealedNonce: "cd".repeat(384), rootGeneration: 1, expiresInSeconds: 60 }).success).toBe(true);
    // A challenge is 16 bytes, never 32.
    expect(P.ChallengeResponse.safeParse({ ok: true, challenge: "ab".repeat(32), sealedNonce: "", rootGeneration: 1, expiresInSeconds: 60 }).success).toBe(false);
    expect(P.ChallengeResponse.safeParse({ ok: false, code: "RECIPIENT_UNKNOWN" }).success).toBe(true);
    expect(P.ChallengeResponse.safeParse({ ok: false, code: "PROOF_REJECTED" }).success).toBe(false);

    const token = { ok: true, tokenId: "0189abcd-1234-7def-8000-0123456789ab", secret: "A".repeat(43), scopes: ["VAULT_WRITE"], rootGeneration: 1, expiresInSeconds: 1800 };
    expect(P.CapabilityResponse.safeParse(token).success).toBe(true);
    // 32 bytes of base64url is 43 characters, unpadded.
    expect(P.CapabilityResponse.safeParse({ ...token, secret: `${"A".repeat(43)}=` }).success).toBe(false);
    expect(P.CapabilityResponse.safeParse({ ...token, scopes: ["SOMETHING_ELSE"] }).success).toBe(false);
    expect(P.CapabilityResponse.safeParse({ ok: false, code: "REPLICA_MISMATCH", replicaId: "0189abcd-1234-7def-8000-0123456789ab" }).success).toBe(true);
  });

  it("a proof is 32 bytes over a 16-byte challenge, and the request is strict", () => {
    const proof = { challenge: "ab".repeat(16), proof: "cd".repeat(32) };
    expect(P.ProofRequest.safeParse(proof).success).toBe(true);
    expect(P.ProofRequest.safeParse({ ...proof, proof: "cd".repeat(31) }).success).toBe(false);
    expect(P.ProofRequest.safeParse({ ...proof, extra: 1 }).success).toBe(false);
  });
});

describe("§28 / §29 / §32.1 directory reads", () => {
  it("builds the three routes, with the one `since` §22 actually defines", () => {
    expect(P.directoryRoutes.rootChain).toBe("/v1/security/root-chain");
    // §22 names `getRecipientRegistry(sinceVersion?)` and nothing equivalent for the root chain.
    expect(P.directoryRoutes.registry()).toBe("/v1/security/registry");
    expect(P.directoryRoutes.registry(0)).toBe("/v1/security/registry?since=0");
    expect(P.directoryRoutes.registry(7)).toBe("/v1/security/registry?since=7");
    expect(P.directoryRoutes.vaultDirectory(id(1), id(2))).toBe(`/v1/vaults/${id(1)}/epochs?recipient=${id(2)}`);
  });

  it("accepts the answers a Worker gives, bytes and all", () => {
    expect(P.RootChainResponse.safeParse({ kind: "ROOT_CHAIN", links: [{ generation: 1, descriptor: "00ff", transition: "aabb" }] }).success).toBe(true);
    // An empty chain is a legitimate answer: an account with no GENESIS yet, or another account's.
    expect(P.RootChainResponse.safeParse({ kind: "ROOT_CHAIN", links: [] }).success).toBe(true);
    expect(P.RegistryChainResponse.safeParse({ kind: "REGISTRY_CHAIN", versions: [] }).success).toBe(true);
    expect(
      P.VaultDirectoryResponse.safeParse({
        kind: "DIRECTORY",
        epochs: [{ epochId: id(3), descriptor: "00", descriptorHash: "0".repeat(64), state: "RETIRED" }],
        envelopes: [{ epochId: id(3), envelope: "00" }],
      }).success,
    ).toBe(true);
  });

  it("refuses an answer a client must not act on", () => {
    // Odd-length hex is not bytes.
    expect(P.RootChainResponse.safeParse({ kind: "ROOT_CHAIN", links: [{ generation: 1, descriptor: "0", transition: "00" }] }).success).toBe(false);
    // §34.3 has exactly two states; anything else is a server this client does not understand.
    expect(
      P.VaultDirectoryResponse.safeParse({ kind: "DIRECTORY", epochs: [{ epochId: id(3), descriptor: "00", descriptorHash: "0".repeat(64), state: "GONE" }], envelopes: [] }).success,
    ).toBe(false);
    expect(P.VaultDirectoryResponse.safeParse({ kind: "VAULT_NOT_FOUND" }).success).toBe(false);
  });

  it("parses the queries strictly, so an unknown parameter is a malformed request", () => {
    expect(P.RegistryQuery.safeParse({ since: "3" })).toMatchObject({ success: true, data: { since: 3 } });
    expect(P.RegistryQuery.safeParse({}).success).toBe(true);
    expect(P.RegistryQuery.safeParse({ since: "-1" }).success).toBe(false);
    expect(P.RegistryQuery.safeParse({ since: "3", limit: "1" }).success).toBe(false);
    expect(P.VaultDirectoryQuery.safeParse({ recipient: id(2) }).success).toBe(true);
    expect(P.VaultDirectoryQuery.safeParse({}).success).toBe(false);
  });
});
