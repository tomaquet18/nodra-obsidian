import { z } from "zod";
import { BROWSER_FAMILIES, OS_FAMILIES } from "./device.js";

export * from "./device.js";

// The sync-path HTTP API of Phase 0 (§11, §12.3, §13.2, §18.4, §22): one schema per request and
// response, shared by the Worker (workers/api) and the client adapter (sync-client). JSON bodies use
// camelCase; ids are UUID strings and byte fields lowercase hex. Requests are strict (an unknown key is
// a malformed request); responses are not, so that the server can add fields without breaking clients.
//
// Every protocol outcome, including a rejection (EPOCH_STALE, CONFLICT, ...), is a 200 with its body.
// Only the gateway's own refusals use an error status with ErrorBody: authentication, capability,
// vault access (VAULT_NOT_FOUND, always 404 and one body, §11.3) and malformed requests.

export const Uuid = z.uuid();
/**
 * A stored 16-byte id as a uuid-shaped string, with no RFC version check: ids the Worker answers with
 * but did not mint (a `recipient_id` of §30.1, a client's `request_id` of §35.15) carry whatever bytes
 * the signed record carried. `RecipientId` below is this shape.
 */
const StoredId = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
/** 32 bytes as 64 lowercase hex characters (ciphertext_sha256, content_fingerprint). */
export const Hex32 = z.string().regex(/^[0-9a-f]{64}$/);
const Uint = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const BlobKind = z.enum(["CONTENT", "MANIFEST"]);

// ---------------------------------------------------------------------------
// Errors of the gateway itself.

export const ERROR_STATUS = {
  INVALID_REQUEST: 400,
  /** No (valid) session. Real auth (Supabase session + Write Capability Token, §11.3) is a later slice. */
  UNAUTHENTICATED: 401,
  WRITE_CAPABILITY_REQUIRED: 403,
  SCOPE_REQUIRED: 403,
  RECIPIENT_REVOKED: 403,
  /** §11.3: the recipient is in neither the root nor the registry in force; the client re-enrols (§18.3). */
  RECIPIENT_UNKNOWN: 403,
  VAULT_NOT_FOUND: 404,
  /** getBlob of bytes that are not stored (never uploaded, or deleted by GC after pruning, §10.6). */
  BLOB_NOT_FOUND: 404,
  NOT_FOUND: 404,
  /**
   * §37 `acknowledgeSecurityEvent`: the id is not this account's, never existed, or was swept. One answer
   * for the three, like VAULT_NOT_FOUND (§11.3's anti-oracle).
   */
  SECURITY_EVENT_NOT_FOUND: 404,
  PAYLOAD_TOO_LARGE: 413,
  INTERNAL: 500,
} as const;
export type ErrorCode = keyof typeof ERROR_STATUS;
export const ErrorCode = z.enum(Object.keys(ERROR_STATUS) as [ErrorCode, ...ErrorCode[]]);
export const ErrorBody = z.object({ error: ErrorCode });
export type ErrorBody = z.infer<typeof ErrorBody>;

// ---------------------------------------------------------------------------
// Routes. `v` is the vault id, `b` a blob id.

export const routes = {
  /** POST PrepareRequest → PrepareResponse (§11.1). */
  prepareUpload: (v: string) => `/v1/vaults/${v}/uploads`,
  /** PUT raw ciphertext → PutResponse (§11.2); GET → the stored bytes (getBlob, §22). */
  blob: (v: string, b: string) => `/v1/vaults/${v}/blobs/${b}`,
  /** POST, no body → ReleaseResponse (§10.3). */
  releaseUpload: (v: string, b: string) => `/v1/vaults/${v}/blobs/${b}/release`,
  /** POST CommitRequest → CommitResponse (§12.3, §12.5). */
  commitMutation: (v: string) => `/v1/vaults/${v}/mutations`,
  /** GET ?after=&limit= → ListEventsResponse (§13.2). */
  listEvents: (v: string, after: number, limit?: number) => `/v1/vaults/${v}/events?after=${after}${limit === undefined ? "" : `&limit=${limit}`}`,
  /** GET → VaultStateResponse (§18.4). */
  vaultState: (v: string) => `/v1/vaults/${v}/state`,
  /** POST RevisionStatusRequest → RevisionStatusResponse (§18.4). */
  revisionStatus: (v: string) => `/v1/vaults/${v}/revisions/status`,
  /** GET ?after=&limit= → ReencryptListResponse (§35.13 listRevisionsToReencrypt). */
  revisionsToReencrypt: (v: string, after: string | null, limit?: number) =>
    `/v1/vaults/${v}/revisions/reencrypt?${[...(after === null ? [] : [`after=${encodeURIComponent(after)}`]), ...(limit === undefined ? [] : [`limit=${limit}`])].join("&")}`,
  /** POST ReencryptRequest → ReencryptResponse (§35.13 reencryptRevision). */
  reencryptRevision: (v: string) => `/v1/vaults/${v}/revisions/reencrypt`,
} as const;

// ---------------------------------------------------------------------------
// §11.1 prepare.

export const PrepareRequest = z.strictObject({
  blobId: Uuid,
  epochId: Uuid,
  kind: BlobKind,
  declaredSize: Uint,
  ciphertextSha256: Hex32,
  /** Only valid on a MANIFEST; a CONTENT with it is answered BLOB_TOO_LARGE in the §11.1 order, not here. */
  forDelete: z.boolean(),
  fingerprint: Hex32.nullable(),
  /** §35.13: the revision this blob re-encrypts (exempt from the general budget, capped by REENCRYPT_IN_FLIGHT). */
  forReencrypt: Uuid.nullable().optional(),
});
export type PrepareRequest = z.infer<typeof PrepareRequest>;

export const PrepareResponse = z.discriminatedUnion("ok", [
  z.object({ ok: z.literal(true), expiresInSeconds: Uint }),
  z.object({
    ok: z.literal(false),
    code: z.enum(["VAULT_DELETING", "BLOB_ID_CONFLICT", "BLOB_UNAVAILABLE", "BLOB_TOO_LARGE", "PENDING_BUDGET_EXCEEDED", "QUOTA_EXCEEDED", "EPOCH_STALE", "RATE_LIMITED"]),
    limit: z.enum(["GENERAL", "FOR_DELETE"]).optional(),
  }),
]);
export type PrepareResponse = z.infer<typeof PrepareResponse>;

// ---------------------------------------------------------------------------
// §11.2 PUT: the body is the raw ciphertext, exactly declared_size bytes with that Content-Length.

export const PutResponse = z.discriminatedUnion("ok", [
  z.object({ ok: z.literal(true) }),
  z.object({
    ok: z.literal(false),
    code: z.enum([
      "VAULT_DELETING",
      "BLOB_ID_CONFLICT",
      "BLOB_UNAVAILABLE",
      "BLOB_CORRUPT",
      "BLOB_CORRUPT_RETRYABLE",
      "BLOB_ALREADY_EXISTS",
      "BAD_UPLOAD_LENGTH",
      "UPLOAD_IN_PROGRESS",
      "UPLOAD_TIMEOUT",
    ]),
    /** UPLOAD_IN_PROGRESS from a live lease: seconds until it ends (§12.6: retry after upload_lease_until). */
    retryAfterSeconds: Uint.optional(),
  }),
]);
export type PutResponse = z.infer<typeof PutResponse>;

// ---------------------------------------------------------------------------
// §10.3 release.

export const ReleaseResponse = z.object({ result: z.enum(["OK", "VAULT_DELETING", "BLOB_ID_CONFLICT", "BLOB_IN_USE", "UPLOAD_IN_PROGRESS"]) });
export type ReleaseResponse = z.infer<typeof ReleaseResponse>;

// ---------------------------------------------------------------------------
// §12.3 / §12.5 commit.

export const CommitEntry = z.strictObject({
  objectId: Uuid,
  revisionId: Uuid,
  expectedHeadRevisionId: Uuid.nullable(),
  deleted: z.boolean(),
  manifestBlobId: Uuid,
  contentBlobId: Uuid.nullable(),
});

/** Batch size and shape (1–500 revisions, deleted ↔ no content, duplicates) are §12.5's INVALID_BATCH, not a malformed request. */
export const CommitRequest = z.strictObject({
  mutationId: Uuid,
  epochId: Uuid,
  attemptId: Uuid.optional(),
  revisions: z.array(CommitEntry),
});
export type CommitRequest = z.infer<typeof CommitRequest>;

/** A head with the fields of a REVISION event (§13.1, §18.4); blob fields are null once pruned. */
export const Head = z.object({
  revisionId: Uuid,
  sequence: Uint,
  deleted: z.boolean(),
  createdSequence: Uint,
  parentRevisionId: Uuid.nullable(),
  pruned: z.boolean(),
  manifestBlobId: Uuid.nullable(),
  manifestEpochId: Uuid.nullable(),
  contentBlobId: Uuid.nullable(),
  contentEpochId: Uuid.nullable(),
});
export type Head = z.infer<typeof Head>;

const CommitCode = z.enum(["INVALID_BATCH", "QUOTA_EXCEEDED", "EPOCH_STALE", "BLOB_UNAVAILABLE", "OBJECT_DELETED", "CONFLICT", "BLOB_ID_CONFLICT"]);

export const CommitResponse = z.union([
  z.object({
    kind: z.literal("COMMITTED"),
    reconstructed: z.literal(true).optional(),
    revisions: z.array(z.object({ objectId: Uuid, revisionId: Uuid, sequence: Uint, createdSequence: Uint, contentFingerprint: Hex32.nullable().optional() })),
  }),
  z.object({ kind: z.literal("REJECTED"), code: z.literal("VAULT_DELETING") }),
  z.object({
    kind: z.literal("REJECTED"),
    code: CommitCode,
    heads: z.array(z.object({ objectId: Uuid, code: z.enum(["OBJECT_DELETED", "CONFLICT"]), head: Head.nullable() })),
    blobs: z.array(z.object({ blobId: Uuid, code: CommitCode })),
    invalid: z.array(z.object({ index: Uint, objectId: Uuid })).nullable(),
  }),
]);
export type CommitResponse = z.infer<typeof CommitResponse>;

// ---------------------------------------------------------------------------
// §13.2 events (absent keys are null columns, §13.1).

const batch = { sequence: Uint, batchIndex: Uint, batchSize: Uint };

export const EventRow = z.discriminatedUnion("eventType", [
  z.object({
    ...batch,
    eventType: z.literal("REVISION"),
    objectId: Uuid,
    revisionId: Uuid,
    parentRevisionId: Uuid.optional(),
    deleted: z.boolean(),
    createdSequence: Uint,
    mutationId: Uuid,
    manifestBlobId: Uuid,
    manifestEpochId: Uuid,
    contentBlobId: Uuid.optional(),
    contentEpochId: Uuid.optional(),
  }),
  z.object({ ...batch, eventType: z.literal("EPOCH_ROTATED"), epochId: Uuid }),
  z.object({ ...batch, eventType: z.literal("SECURITY"), securityEventId: Uint }),
]);
export type EventRow = z.infer<typeof EventRow>;

/** §13.2: the page size the client asks for; the Worker clamps any other value into this range. */
export const PAGE_LIMIT = { min: 500, max: 1000 } as const;

const Decimal = z
  .string()
  .regex(/^\d{1,15}$/)
  .transform(Number);

export const ListEventsQuery = z.strictObject({ after: Decimal, limit: Decimal.optional() });

export const ListEventsResponse = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("PAGE"), events: z.array(EventRow) }),
  z.object({ kind: z.literal("CURSOR_EXPIRED") }),
]);
export type ListEventsResponse = z.infer<typeof ListEventsResponse>;

// ---------------------------------------------------------------------------
// §18.4 getVaultState and getRevisionStatus.

export const VaultStateResponse = z.object({
  kind: z.literal("STATE"),
  sequence: Uint,
  epochId: Uuid,
  heads: z.array(z.object({ objectId: Uuid, head: Head })),
});
export type VaultStateResponse = z.infer<typeof VaultStateResponse>;

export const RevisionStatusRequest = z.strictObject({ revisionIds: z.array(Uuid) });
export type RevisionStatusRequest = z.infer<typeof RevisionStatusRequest>;

export const RevisionStatusResponse = z.object({
  kind: z.literal("STATUS"),
  revisions: z.array(z.object({ revisionId: Uuid, exists: z.boolean(), objectId: Uuid.optional(), sequence: Uint.optional() })),
});
export type RevisionStatusResponse = z.infer<typeof RevisionStatusResponse>;

// ---------------------------------------------------------------------------
// §35.13 history re-encryption: `listRevisionsToReencrypt` (a read, §11.3 "solo login") and
// `reencryptRevision` (commitMutation's scope, VAULT_WRITE). Both answer INVALID_STATE for a Managed account.

/** The opaque page cursor: `<old content_blob_id, or ->/<revision_id>` of the page's last revision. */
export const ReencryptCursor = z.string().regex(/^(?:-|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

/** The page size the client may ask for; the Worker clamps any other value into this range. */
export const REENCRYPT_PAGE_LIMIT = { min: 1, max: 500 } as const;

export const ReencryptListQuery = z.strictObject({ after: ReencryptCursor.optional(), limit: Decimal.optional() });

export const RevisionToReencrypt = z.object({
  revisionId: Uuid,
  objectId: Uuid,
  parentRevisionId: Uuid.nullable(),
  deleted: z.boolean(),
  manifestBlobId: Uuid,
  manifestEpochId: Uuid,
  contentBlobId: Uuid.nullable(),
  contentEpochId: Uuid.nullable(),
});
export type RevisionToReencrypt = z.infer<typeof RevisionToReencrypt>;

export const ReencryptListResponse = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("PAGE"), revisions: z.array(RevisionToReencrypt), next: ReencryptCursor.nullable() }),
  z.object({ kind: z.literal("INVALID_STATE") }),
]);
export type ReencryptListResponse = z.infer<typeof ReencryptListResponse>;

export const ReencryptRequest = z.strictObject({
  revisionId: Uuid,
  expectedManifestBlobId: Uuid,
  newManifestBlobId: Uuid,
  newContentBlobId: Uuid.nullable(),
});
export type ReencryptRequest = z.infer<typeof ReencryptRequest>;

export const ReencryptResponse = z.discriminatedUnion("ok", [
  z.object({ ok: z.literal(true) }),
  z.object({
    ok: z.literal(false),
    code: z.enum(["VAULT_DELETING", "INVALID_STATE", "REVISION_NOT_FOUND", "REVISION_PRUNED", "REVISION_CHANGED", "EPOCH_STALE", "INVALID_BATCH"]),
  }),
]);
export type ReencryptResponse = z.infer<typeof ReencryptResponse>;

// ---------------------------------------------------------------------------
// §35 security bundles.

/** An NCE record as lowercase hex (§23.2). Bodies stay JSON, so bytes travel like every other field. */
export const HexBytes = z.string().regex(/^(?:[0-9a-f]{2})*$/);

/** POST SecurityBundleRequest → SecurityBundleResponse (§35.1.1). No vault in the route: the
 * bundle carries its own `vault_id`s inside the signed record, and §11.3 makes it the documented
 * exception to the per-vault access check. */
export const securityBundleRoute = "/v1/security/bundles";

export const SecurityBundleRequest = z.strictObject({ bundle: HexBytes });
export type SecurityBundleRequest = z.infer<typeof SecurityBundleRequest>;

/** The response codes of §35.1, retryable ones first. */
export const BundleFailureCode = z.enum([
  "SECURITY_STATE_STALE",
  "EPOCH_STALE",
  "VAULT_SET_STALE",
  "COVERAGE_STALE",
  "REAUTH_REQUIRED",
  "INVALID_SIGNATURE",
  "INVALID_REGISTRY",
  "INVALID_TRANSITION",
  "INVALID_STATE",
  "NONCE_REUSED",
  "INVALID_BUNDLE",
  "PLAN_LIMIT_EXCEEDED",
  "NOT_APPLICABLE_IN_MANAGED",
  // §35.15 (ADR-022): RECOVERY_NOT_MATURE is retryable from `maturesAt`; RECOVERY_REQUEST_REQUIRED is
  // definitive for that attempt but never stored, so the same bundle_id may be resent later.
  "RECOVERY_NOT_MATURE",
  "RECOVERY_REQUEST_REQUIRED",
  "RECOVERY_REQUEST_EXISTS",
]);
export type BundleFailureCode = z.infer<typeof BundleFailureCode>;

/** §35.15: the three operations a recovery request names, which is its `kind`. */
export const RecoveryRequestKind = z.enum(["RECOVERY_RESET", "RECOVERY_KIT_REPLACEMENT", "SWITCH_TO_MANAGED"]);
export type RecoveryRequestKind = z.infer<typeof RecoveryRequestKind>;

/**
 * The three refusals of §35.1.1 step 0 (`WRITE_CAPABILITY_REQUIRED`, `SCOPE_REQUIRED`,
 * `RECIPIENT_REVOKED`) are not here: they are emitted before any state is read, are never stored,
 * and travel as the gateway's own 401/403 like every other capability refusal (§11.3).
 */
export const SecurityBundleResponse = z.discriminatedUnion("ok", [
  z.object({
    ok: z.literal(true),
    operationType: z.string(),
    rootGeneration: Uint,
    registryVersion: Uint,
    configVersion: Uint,
    /** §6: the id of the `security_event` this bundle emitted. */
    securityEventId: Uint,
    epochs: z.array(z.object({ vaultId: Uuid, epochId: Uuid })),
    /** RECOVERY_REQUEST (§35.15): the request as filed, with the dates the Worker set (Unix ms). */
    recoveryRequest: z
      .object({ requestId: StoredId, kind: RecoveryRequestKind, requestedAt: Uint, maturesAt: Uint, expiresAt: Uint })
      .optional(),
  }),
  z.object({
    ok: z.literal(false),
    code: BundleFailureCode,
    /** The step of §35.1.1 that rejected, and the rule inside it. */
    step: z.string(),
    rule: z.string(),
    retryable: z.boolean(),
    message: z.string(),
    /** SECURITY_STATE_STALE: the three values in force (§35.1). */
    expected: z.object({ rootGeneration: Uint, registryVersion: Uint, configVersion: Uint }).optional(),
    /** VAULT_SET_STALE: the live vaults. */
    vaultIds: z.array(Uuid).optional(),
    /** COVERAGE_STALE: the RequiredEpochSet (§34.1). */
    required: z.array(z.object({ vaultId: Uuid, epochId: Uuid })).optional(),
    /** RECOVERY_NOT_MATURE: when the request matures (Unix ms, §35.15). */
    maturesAt: Uint.optional(),
    /** RECOVERY_REQUEST_EXISTS: the live request's kind and dates (§35.1). */
    liveRequest: z.object({ kind: RecoveryRequestKind, maturesAt: Uint, expiresAt: Uint }).optional(),
  }),
]);
export type SecurityBundleResponse = z.infer<typeof SecurityBundleResponse>;

// ---------------------------------------------------------------------------
// §11.3 write capability: the challenge, the proof of possession and the token.

/**
 * The two endpoints of §11.3. Neither carries a `vault_id`: a capability is per account and
 * recipient, and which vault it may write is decided at the write, by the rule of §11.3.
 */
export const capabilityRoutes = {
  /** POST ChallengeRequest → ChallengeResponse (§11.3 steps 1–3). */
  challenge: "/v1/capability/challenges",
  /** POST ProofRequest → CapabilityResponse (§11.3 steps 5–6). */
  token: "/v1/capability/tokens",
} as const;

/** The header of §11.3: `<token_id hex 32>.<secret base64url 43>`, sent beside the session. */
export const CAPABILITY_HEADER = "nodra-write-capability";

/**
 * A `recipient_id` as a uuid-shaped string. It is **not** `Uuid`: §30.1 makes the ACCOUNT and
 * RECOVERY ids the documented exception to UUIDv7 — they are the first 16 bytes of `SHA-256(SPKI)`,
 * so their version and variant nibbles are whatever the hash says.
 */
export const RecipientId = StoredId;

/** 16 bytes as 32 lowercase hex characters (a challenge, §11.3 step 2). */
export const Hex16 = z.string().regex(/^[0-9a-f]{32}$/);

export const CapabilityScope = z.enum(["VAULT_WRITE", "TRUSTED_SECURITY", "ACCOUNT_SECURITY", "RECOVERY_CONTROL"]);
export type CapabilityScope = z.infer<typeof CapabilityScope>;

/**
 * §11.3 step 1. `replicaId` is the session UUIDv7 an ACCOUNT recipient proposes (§6); a trusted
 * client never sends one, because its `replica_id` is its own `recipient_id` and the Worker will
 * not read a client-chosen value.
 */
export const ChallengeRequest = z.strictObject({ recipientId: RecipientId, replicaId: Uuid.optional() });
export type ChallengeRequest = z.infer<typeof ChallengeRequest>;

/**
 * §11.3 step 2 rejects a recipient the root and registry in force do not authorize. Both codes mean
 * "re-enrol" to the client (§18.3); they are distinguished because §11.3 names them separately and
 * they are not a cross-account oracle — the caller already proved it owns this account's session.
 */
export const RecipientRejection = z.enum(["RECIPIENT_REVOKED", "RECIPIENT_UNKNOWN"]);

export const ChallengeResponse = z.discriminatedUnion("ok", [
  z.object({
    ok: z.literal(true),
    /** 16 bytes: the one-use value both the OAEP label and the proof context carry. */
    challenge: Hex16,
    /** `RSA-OAEP-Encrypt(public key of the recipient, nonce, label = Context(...))`. */
    sealedNonce: HexBytes,
    /** The generation the label binds, which step 6 re-checks under the account lock. */
    rootGeneration: Uint,
    expiresInSeconds: Uint,
  }),
  z.object({ ok: z.literal(false), code: RecipientRejection }),
]);
export type ChallengeResponse = z.infer<typeof ChallengeResponse>;

/** §11.3 step 5: `HMAC(Context("nodra/write-capability-proof", challenge))`, 32 bytes. */
export const ProofRequest = z.strictObject({ challenge: Hex16, proof: Hex32 });
export type ProofRequest = z.infer<typeof ProofRequest>;

/**
 * §11.3 step 6's refusals.
 *
 * `PROOF_REJECTED` covers a wrong MAC, an unknown challenge, a replayed one and an expired one
 * alike: the Worker consumes the challenge on the attempt, so telling the four apart would only
 * help an attacker decide whether to keep grinding (see the SQL's `nodra_consume_challenge`).
 * `WRITE_CAPABILITY_REQUIRED` is §11.3's own answer for "the root changed under the challenge".
 */
export const CapabilityRejection = z.enum([
  "PROOF_REJECTED",
  "RECIPIENT_REVOKED",
  "RECIPIENT_UNKNOWN",
  "WRITE_CAPABILITY_REQUIRED",
  "VAULT_DELETING",
  "REPLICA_MISMATCH",
]);
export type CapabilityRejection = z.infer<typeof CapabilityRejection>;

export const CapabilityResponse = z.discriminatedUnion("ok", [
  z.object({
    ok: z.literal(true),
    tokenId: Uuid,
    /** 32 CSPRNG bytes, base64url without padding. The server keeps only its SHA-256. */
    secret: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    scopes: z.array(CapabilityScope),
    /** §6: absent for a RECOVERY token, which never writes. */
    replicaId: Uuid.optional(),
    rootGeneration: Uint,
    expiresInSeconds: Uint,
  }),
  z.object({
    ok: z.literal(false),
    code: CapabilityRejection,
    /** REPLICA_MISMATCH: the id already fixed for this session, which the client adopts (§6). */
    replicaId: Uuid.optional(),
  }),
]);
export type CapabilityResponse = z.infer<typeof CapabilityResponse>;

/** The header value of §11.3, as one string. */
export const capabilityHeaderValue = (tokenId: string, secret: string) => `${tokenId.replaceAll("-", "")}.${secret}`;

/** The inverse. Null for anything that is not exactly `<32 hex>.<43 base64url>`. */
export function parseCapabilityHeader(value: string | null): { readonly tokenId: string; readonly secret: string } | null {
  const m = /^([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$/.exec(value ?? "");
  if (m === null) return null;
  const h = m[1]!;
  return { tokenId: `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`, secret: m[2]! };
}

// ---------------------------------------------------------------------------
// §28 / §29 / §32.1 directory reads: the chains a client verifies for itself.

/**
 * The three reads of §22's `KeyLifecycleBackend` a client needs before it can open anything.
 *
 * §11.3's table puts all three in the "solo login" column: they carry no plaintext and no
 * authority — every record is signed, and the client re-derives each chain itself — so a session is
 * the whole gate. A Write Capability Token may be present (a trusted client always has one) and
 * changes nothing about what they answer, whatever its scopes.
 *
 * `rootChain` has no `since`: §22's `getRootState` promises the chain from GENESIS, and a client
 * verifying from a pin still needs the pinned generation's own descriptor to continue (§28.3).
 * `registry` has one, because §22 names `getRecipientRegistry(sinceVersion)` explicitly (§29).
 */
export const directoryRoutes = {
  /** GET → RootChainResponse (§28, the chain half of `getRootState`). */
  rootChain: "/v1/security/root-chain",
  /** GET ?since= → RegistryChainResponse (§29 `getRecipientRegistry`). */
  registry: (sinceVersion?: number) => `/v1/security/registry${sinceVersion === undefined ? "" : `?since=${sinceVersion}`}`,
  /** GET ?recipient= → VaultDirectoryResponse (§22 `listEpochDescriptors` + `listEpochEnvelopes`). */
  vaultDirectory: (v: string, recipientId: string) => `/v1/vaults/${v}/epochs?recipient=${recipientId}`,
  /** GET → RootStateResponse (§22 `getRootState` minus the root chain: profile, config, vaults). */
  rootState: "/v1/security/root-state",
} as const;

/** §28.1 + §28.2: one generation as stored, with the transition that installed it. */
export const RootChainResponse = z.object({
  kind: z.literal("ROOT_CHAIN"),
  links: z.array(z.object({ generation: Uint, descriptor: HexBytes, transition: HexBytes })),
});
export type RootChainResponse = z.infer<typeof RootChainResponse>;

export const RegistryQuery = z.strictObject({ since: Decimal.optional() });

/** §29: every version above the pin, in order. Empty means "nothing above yours" — never an error. */
export const RegistryChainResponse = z.object({
  kind: z.literal("REGISTRY_CHAIN"),
  versions: z.array(z.object({ version: Uint, registry: HexBytes })),
});
export type RegistryChainResponse = z.infer<typeof RegistryChainResponse>;

export const VaultDirectoryQuery = z.strictObject({ recipient: RecipientId });

/**
 * §32.1 and §32.2 together. `state` is unsigned (§22): it decides availability, never validity, so
 * a server that lies about it costs the client a readable blob and nothing else (§34.3).
 * `descriptorHash` is unsigned too and is only a hint; the client recomputes it while replaying.
 */
export const VaultDirectoryResponse = z.object({
  kind: z.literal("DIRECTORY"),
  epochs: z.array(z.object({ epochId: Uuid, descriptor: HexBytes, descriptorHash: Hex32, state: z.enum(["ACTIVE", "RETIRED"]) })),
  envelopes: z.array(z.object({ epochId: Uuid, envelope: HexBytes })),
});
export type VaultDirectoryResponse = z.infer<typeof VaultDirectoryResponse>;

/**
 * §35.15: the RECOVERY envelopes of a Private account are served only with a matured RECOVERY_RESET
 * request, and only those of the root's RECOVERY recipient in force. Otherwise `listEpochEnvelopes`
 * answers one of these (a protocol answer, 200): REQUIRED without a live reset request, or for the
 * recipient of an earlier kit; NOT_MATURE with the date the live one matures (Unix ms).
 */
export const VaultDirectoryRefusal = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("RECOVERY_REQUEST_REQUIRED") }),
  z.object({ kind: z.literal("RECOVERY_NOT_MATURE"), maturesAt: Uint }),
]);
export type VaultDirectoryRefusal = z.infer<typeof VaultDirectoryRefusal>;

/**
 * §22 / §35.15: the live recovery request of `getRootState`. The signed fields, so a client can verify
 * the request against its pinned root before showing it, and the dates, which are not signed.
 */
export const RecoveryRequestView = z.object({
  requestId: StoredId,
  kind: RecoveryRequestKind,
  rootGeneration: Uint,
  rootHash: Hex32,
  signature: HexBytes,
  requestedAt: Uint,
  maturesAt: Uint,
  expiresAt: Uint,
});
export type RecoveryRequestView = z.infer<typeof RecoveryRequestView>;

/** One row of `getRootState.deviceActivity` (§19). `browser`/`os`: null when unknown or not one of the lists. */
export const DeviceActivityRow = z.object({
  recipientId: RecipientId,
  lastActiveAt: Uint,
  browser: z.enum(BROWSER_FAMILIES).nullable().catch(null),
  os: z.enum(OS_FAMILIES).nullable().catch(null),
});
export type DeviceActivityRow = z.infer<typeof DeviceActivityRow>;

/**
 * §22 `getRootState` without the chain `rootChain` already serves. Nothing here is trusted before the
 * unlock: the profile is unauthenticated (§24), the config opens only under the account's two secrets
 * (§26), and the vault list is unsigned (a vault left out only earns VAULT_SET_STALE, §35.1). The
 * profile is the stored one; `configBlob`/`configVersion` are the config in force, which a config-only
 * bundle installs without a new profile, so the client puts them into the profile before unlocking.
 */
export const RootStateResponse = z.object({
  kind: z.literal("ROOT_STATE"),
  accountState: z.enum(["ACTIVE", "DELETING_SCHEDULED", "DELETING", "ORPHANED"]),
  maxBlobBytes: Uint,
  /** §40.1: the plan quota prepareUpload compares the account's usage with (QUOTA_EXCEEDED). */
  quotaBytes: Uint,
  pendingBudgetBytes: Uint,
  /** §40.1 FOR_DELETE_PENDING_BYTES: the for_delete manifests' own pending cap (PENDING_BUDGET_EXCEEDED FOR_DELETE). */
  forDeletePendingBytes: Uint,
  /** §40.1 DELETE_MANIFEST_ALLOWANCE: how far past the quota for_delete manifests may go (then QUOTA_EXCEEDED). */
  deleteManifestAllowance: Uint,
  /**
   * §35.10 step 1, §40: how many vaults the plan allows, counting ACTIVE and DELETING_SCHEDULED ones
   * (the `vaults` below). Null: the plan sets no limit. The Worker applies it again (PLAN_LIMIT_EXCEEDED).
   */
  maxVaults: Uint.nullable(),
  /** Null before GENESIS: the account has not run §35.2 yet. */
  profile: HexBytes.nullable(),
  configBlob: HexBytes.nullable(),
  configVersion: Uint.nullable(),
  vaults: z.array(z.object({ vaultId: Uuid, state: z.enum(["ACTIVE", "DELETING_SCHEDULED"]), currentWriteEpochId: Uuid.nullable() })),
  /**
   * §3.6: the Escrow Key in force (RSA-OAEP-3072 SPKI DER) with its `key_id`, over TLS and never pinned.
   * A Managed client wraps its escrow slots to it (§35.2, §35.7, §35.14).
   */
  escrowKey: z.object({ keyId: Hex16, spki: HexBytes }),
  /** §35.15: the live recovery request, or null. An older server's answer without it reads as null. */
  recoveryRequest: RecoveryRequestView.nullable().default(null),
  /**
   * §19: when each device last used its access, rounded down to the hour (Unix ms), and the families the
   * server parsed from that request's User-Agent. Unsigned and informative: the device list shows it as
   * reported by the server, beside the signed label, never in its place. A family outside the closed
   * lists reads as unknown; a malformed list as none, so it can never cost the rest of getRootState.
   */
  deviceActivity: z.array(DeviceActivityRow).default([]).catch([]),
});
export type RootStateResponse = z.infer<typeof RootStateResponse>;

// ---------------------------------------------------------------------------
// §24.2 / §35.7 the Managed unlock (ADR-021).

/**
 * §22 `managedUnlock` and `managedRecoveryUnlock`. §11.3: a login session and nothing else, so a new
 * browser of a Managed account unlocks with its login; the recovery route also needs a primary
 * authentication of 5 minutes or less (§35.12 step 2, REAUTH_REQUIRED).
 */
export const managedUnlockRoutes = {
  /** POST ManagedUnlockRequest → ManagedUnlockResponse: the UNLOCK slot re-wrapped (§24.2). */
  unlock: "/v1/security/managed-unlock",
  /** POST ManagedUnlockRequest → ManagedUnlockResponse: the RECOVERY slot re-wrapped (§35.7). */
  recovery: "/v1/security/managed-recovery-unlock",
} as const;

/** §24.2 step 2: the SPKI DER of the client's ephemeral RSA-OAEP-3072 key. */
export const ManagedUnlockRequest = z.strictObject({ ephemeralPublicKey: HexBytes });
export type ManagedUnlockRequest = z.infer<typeof ManagedUnlockRequest>;

/**
 * `rewrap`: the NCE bytes of an `EscrowRewrap` (§23.4). Like a bundle's, the two refusals are protocol
 * answers: INVALID_STATE for a Private account (no escrow), REAUTH_REQUIRED on the recovery route.
 */
export const ManagedUnlockResponse = z.discriminatedUnion("ok", [
  z.object({ ok: z.literal(true), rewrap: HexBytes }),
  z.object({ ok: z.literal(false), code: z.enum(["INVALID_STATE", "REAUTH_REQUIRED"]) }),
]);
export type ManagedUnlockResponse = z.infer<typeof ManagedUnlockResponse>;

// ---------------------------------------------------------------------------
// §37 security notifications: `listSecurityEvents` and `acknowledgeSecurityEvent` (§22).

/**
 * §11.3: `listSecurityEvents` is in the "solo login" column, so a session is the whole gate; the
 * capability header, when present, only decides whose `acknowledged` the answer carries (a live
 * TRUSTED_SECURITY token's replica; anything else reads every event as unacknowledged, §37).
 * `acknowledge` needs TRUSTED_SECURITY (persisted for the token's replica) or ACCOUNT_SECURITY
 * (accepted, nothing persisted); RECOVERY_CONTROL is SCOPE_REQUIRED.
 */
export const securityEventRoutes = {
  /** GET ?after= → SecurityEventsResponse. No `after` is 0: every event still retained. */
  list: (afterId?: number) => `/v1/security/events${afterId === undefined ? "" : `?after=${afterId}`}`,
  /** POST, no body → AcknowledgeResponse, or SECURITY_EVENT_NOT_FOUND (404). */
  acknowledge: (securityEventId: number) => `/v1/security/events/${securityEventId}/ack`,
} as const;

/** §37 `event_type`, in §37's order. */
export const SecurityEventType = z.enum([
  "CLIENT_ENROLLED",
  "CLIENT_REVOKED",
  "VAULT_CREATED",
  "SECRETS_CHANGED",
  "RECOVERY_KIT_REPLACED",
  "RECOVERY_RESET",
  "VAULT_DELETE_SCHEDULED",
  "ACCOUNT_DELETE_SCHEDULED",
  "VAULT_DELETE_CANCELLED",
  "ACCOUNT_DELETE_CANCELLED",
  "VAULT_PURGED",
  "SWITCHED_TO_PRIVATE",
  "SWITCHED_TO_MANAGED",
  // §35.15 (ADR-022).
  "RECOVERY_RESET_REQUESTED",
  "KIT_REPLACEMENT_REQUESTED",
  "SWITCH_TO_MANAGED_REQUESTED",
  "RECOVERY_REQUEST_VETOED",
  "RECOVERY_REQUEST_CANCELLED",
]);
export type SecurityEventType = z.infer<typeof SecurityEventType>;

export const SecurityEventsQuery = z.strictObject({ after: Decimal.optional() });

/**
 * §22 `SecurityEvent`: the §37 row plus `acknowledged`. Informative and unsigned (§37: "depende del
 * servidor honesto"). Ids use the loose `RecipientId` shape: they are the stored bytes, not minted here.
 */
export const SecurityEventRow = z.object({
  securityEventId: Uint,
  eventType: SecurityEventType,
  vaultId: RecipientId.nullable(),
  actorRecipientId: RecipientId.nullable(),
  /** §37: the request a §35.15 event names; null for every other event. */
  recoveryRequestId: RecipientId.nullable().optional(),
  rootGeneration: Uint,
  createdAt: z.string(),
  acknowledged: z.boolean(),
});
export type SecurityEventRow = z.infer<typeof SecurityEventRow>;

export const SecurityEventsResponse = z.object({ kind: z.literal("SECURITY_EVENTS"), events: z.array(SecurityEventRow) });
export type SecurityEventsResponse = z.infer<typeof SecurityEventsResponse>;

export const AcknowledgeResponse = z.object({ ok: z.literal(true) });
