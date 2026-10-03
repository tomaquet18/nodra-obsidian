import type { ManifestInput } from "./manifest.js";
import type {
  BlobKind,
  CommitResult,
  Content,
  ContentRef,
  LocalCompareHash,
  MutationId,
  ObjectId,
  PhysicalPath,
  PrepareRejection,
  ReleaseResponse,
  RevisionId,
  RevisionStatus,
  SyncEvent,
  VaultState as RemoteVaultState,
} from "@nodra/sync-core";

// Ports of the impure shell (§22). sync-core stays pure; everything here is an interface that a real
// adapter (Obsidian, Web Crypto, Supabase/R2) or a test double implements.

/** A file or folder as the adapter reports it (Obsidian `DataAdapter.stat`). */
export interface Stat {
  readonly type: "file" | "folder";
  readonly size: number;
  /**
   * The file's modification marker, read as the adapter's `changeMarker` says (NOTES question 146).
   * Absent: unknown, and the observation cache never skips hashing the file.
   */
  readonly mtime?: number;
}

/**
 * What `Stat.mtime` means (NOTES question 146):
 * - `counter`: a marker the adapter changes on EVERY content write and never gives again to another
 *   content of the same path (memfs, the web note store: a per-store counter). Equal (size, mtime) means
 *   the same bytes.
 * - `clock`: the file system's modification time in ms since the epoch, truncated to `granularityMs`
 *   (§12.2: precision differs between desktop, mobile and web). Equal (size, mtime) proves nothing by
 *   itself: a write within the same granule keeps it (the "racy" case).
 */
export type ChangeMarker = { readonly kind: "counter" } | { readonly kind: "clock"; readonly granularityMs: number };

/**
 * The vault's file system, shaped like Obsidian's `DataAdapter` so the plugin can implement it
 * directly. Paths are vault-relative with `/`. No operation is atomic across calls: the executor
 * re-reads before every replace (§13.4 step 4).
 */
export interface FileSystem {
  stat(path: PhysicalPath): Promise<Stat | null>;
  /** The file's exact bytes (Obsidian `readBinary`): Markdown and attachments alike (§2.1). */
  read(path: PhysicalPath): Promise<Content>;
  /** Creates or overwrites a file with exactly these bytes. The client only uses it on a fresh `nodra-tmp-*` name (§15 step 2). */
  write(path: PhysicalPath, data: Content): Promise<void>;
  /** Moves a file to a path that must be free; fails if the destination exists. */
  rename(from: PhysicalPath, to: PhysicalPath): Promise<void>;
  /**
   * Moves the temporary over an existing destination (or a free one): the ONLY operation that replaces
   * an existing file (§15 step 4). The adapter may move the temporary's identity or rewrite the destination.
   */
  replace(tmp: PhysicalPath, dest: PhysicalPath): Promise<void>;
  remove(path: PhysicalPath): Promise<void>;
  /** Direct children of a folder ("" is the vault root). */
  list(folder: PhysicalPath): Promise<{ readonly files: readonly PhysicalPath[]; readonly folders: readonly PhysicalPath[] }>;
  mkdir(path: PhysicalPath): Promise<void>;
  /** Removes an EMPTY folder; fails otherwise (never recursive). */
  rmdir(path: PhysicalPath): Promise<void>;
  /**
   * In-memory identity of the file at `path` in this instance (Obsidian's `TFile`), or null when the
   * adapter has none. Never persisted (§15 "Identidad y ecos").
   */
  identityOf(path: PhysicalPath): string | null;
  /** How to read `Stat.mtime`; absent: the adapter gives no usable marker (every observation hashes every file). */
  readonly changeMarker?: ChangeMarker | undefined;
}

/** Device Local Key (§20.1): AES-GCM over the local store's note content (rule 16). */
export interface DeviceLocalCrypto {
  encrypt(plaintext: Content): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array): Promise<Content>;
}

/** local_compare_hash = HMAC-SHA-256(LocalCompareKey, plaintext) (§12.2, §20.1). */
export interface LocalCompareHasher {
  hash(plaintext: Content): Promise<LocalCompareHash>;
}

/**
 * The revision a manifest blob is bound to by its AAD (§31.3). A content blob has none on purpose:
 * §31.3 leaves `object_id`, `revision_id` and the path out of its AAD so that one content blob can
 * be shared by several revisions (dedup, rename); the manifest supplies the binding (§9).
 */
export interface ManifestBinding {
  readonly objectId: ObjectId;
  readonly revisionId: RevisionId;
  /** `null` on the revision that creates the object (§8, §13.1). */
  readonly parentRevisionId: RevisionId | null;
}

export interface EncryptBlobInput {
  readonly epochId: string;
  readonly blobId: string;
  readonly kind: BlobKind;
  readonly payload: Uint8Array;
  /** Required for a MANIFEST (§31.3); ignored for a CONTENT. */
  readonly binding?: ManifestBinding;
}

export interface SealedBlob {
  readonly ciphertext: Uint8Array;
  readonly ciphertextSha256: string;
  readonly declaredSize: number;
  /**
   * `content_fingerprint` (§31.4) as lowercase hex, taken with the dedup key of `epochId`. Present
   * for a CONTENT blob only: it is the manifest's `content_fingerprint` field (§8), and it is
   * produced here because only the sealer holds the epoch whose dedup key §31.4 names.
   */
  readonly fingerprint?: string;
}

export interface OpenBlobInput {
  readonly epochId: string;
  readonly blobId: string;
  readonly kind: BlobKind;
  readonly ciphertext: Uint8Array;
  /** Required for a MANIFEST (§31.3). */
  readonly binding?: ManifestBinding;
  /** §9 step 2 for a CONTENT blob: the manifest's `content_fingerprint`, recomputed and compared. */
  readonly expectFingerprint?: string;
}

/**
 * The Revision Manifest codec (§8). It lives on the VaultCrypto port rather than beside the runner
 * for one reason: a manifest is never handled in plaintext outside this boundary — §8 says it is
 * encrypted whole (§31) — and its map and its §31.3 AAD name the same identity, so one
 * implementation owns both or they can drift apart. The real one is `nceManifestCodec` (§8 NCE);
 * `devManifestCodec` is the Phase 0 stand-in that goes with `DevVaultCrypto`.
 */
export interface ManifestCodec {
  encodeManifest(input: ManifestInput): Uint8Array;
  /** The inverse; throws when the payload is not a manifest of this format. */
  decodeManifest(payload: Uint8Array): ManifestInput;
}

/** The part of VaultCrypto (§22) the upload path needs: one blob's exact ciphertext (rule 13). */
export interface BlobCrypto extends ManifestCodec {
  /** Bytes the blob of this payload will declare (§11.1), known before encrypting (§12.1 batching). */
  declaredSize(payload: Uint8Array): number;
  encryptBlob(input: EncryptBlobInput): Promise<SealedBlob>;
}

export interface PrepareUploadInput {
  readonly blobId: string;
  readonly epochId: string;
  readonly kind: BlobKind;
  readonly declaredSize: number;
  readonly ciphertextSha256: string;
  readonly forDelete: boolean;
  readonly objectId: ObjectId;
  /** §35.13: the revision this blob re-encrypts; absent for every other upload. */
  readonly forReencrypt?: RevisionId;
}

export interface CommitMutationInput {
  readonly mutationId: MutationId;
  readonly epochId: string;
  readonly revisions: ReadonlyArray<{
    readonly objectId: ObjectId;
    readonly revisionId: RevisionId;
    readonly expectedHeadRevisionId: RevisionId | null;
    readonly deleted: boolean;
    readonly manifestBlobId: string;
    readonly contentBlobId: string | null;
  }>;
}

/** One revision `listRevisionsToReencrypt` names (§35.13), with its manifest already opened. */
export interface RevisionToReencrypt {
  readonly revisionId: RevisionId;
  readonly objectId: ObjectId;
  readonly parentRevisionId: RevisionId | null;
  readonly deleted: boolean;
  readonly manifestBlobId: string;
  readonly manifestEpochId: string;
  /** The content blob it references now, with its epoch; null for a delete. */
  readonly content: ContentRef | null;
  /**
   * Its §8 manifest, opened under its own (pre-switch) epoch with the §31.3 binding of this revision,
   * as the adapter opens every manifest it names (events, heads). The new manifest keeps every field
   * but the content ones (§35.13 "Cliente").
   */
  readonly manifest: ManifestInput;
}

export type ReencryptPage = { readonly kind: "PAGE"; readonly revisions: readonly RevisionToReencrypt[]; readonly next: string | null } | { readonly kind: "INVALID_STATE" };

export interface ReencryptRevisionInput {
  readonly revisionId: RevisionId;
  readonly expectedManifestBlobId: string;
  readonly newManifestBlobId: string;
  readonly newContentBlobId: string | null;
}

/** §35.13's answers that are protocol outcomes (VAULT_* are thrown, like on every other write). */
export type ReencryptRejection = "INVALID_STATE" | "REVISION_NOT_FOUND" | "REVISION_PRUNED" | "REVISION_CHANGED" | "EPOCH_STALE" | "INVALID_BATCH";

export type ReencryptRevisionResult = { readonly ok: true } | { readonly ok: false; readonly code: ReencryptRejection };

/** A PUT that exceeded its deadline (§12.6 UPLOAD_TIMEOUT): a failed attempt attributable to the object. */
export const UPLOAD_TIMEOUT = "UPLOAD_TIMEOUT";

/**
 * SyncBackend (§22) as the runner uses it, for one vault. A rejected promise means the outcome is
 * unknown (lost request or lost response); the runner never infers success from it.
 */
export interface SyncBackend {
  listEvents(afterSequence: number): Promise<{ readonly kind: "PAGE"; readonly events: readonly SyncEvent[] } | { readonly kind: "CURSOR_EXPIRED" }>;
  getVaultState(): Promise<RemoteVaultState>;
  prepareUpload(input: PrepareUploadInput): Promise<{ readonly ok: true; readonly expiresInSeconds: number } | { readonly ok: false; readonly code: PrepareRejection | "PENDING_BUDGET_EXCEEDED" }>;
  uploadBlob(blobId: string, ciphertext: Uint8Array): Promise<{ readonly ok: true } | { readonly ok: false; readonly code: PrepareRejection }>;
  releaseUpload(blobId: string): Promise<ReleaseResponse>;
  getRevisionStatus(revisionIds: readonly RevisionId[]): Promise<readonly RevisionStatus[]>;
  commitMutation(input: CommitMutationInput): Promise<CommitResult>;
  /**
   * getBlob + decryptContent of a revision's content (§22); PRUNED when its bytes are gone (§10.6).
   * `content` is the ref recorded with the revision in S or R, when there is one (NOTES question 99);
   * `sequence` is the revision's, when known. A ref whose blob is gone (BLOB_NOT_FOUND) is not proof of
   * pruning: a re-encryption (§35.13) may have replaced it, so the revision is read again from the server
   * (getVaultState, or listEvents from `sequence`) and its current blob tried once.
   */
  readRevision(
    revisionId: RevisionId,
    content?: ContentRef | null,
    sequence?: number,
  ): Promise<{ readonly kind: "CONTENT"; readonly plaintext: Content } | { readonly kind: "PRUNED" }>;
  /** §35.13: one page of the revisions still in an epoch before the vault's first Private one. */
  listRevisionsToReencrypt(after: string | null, limit: number): Promise<ReencryptPage>;
  /** §35.13: swaps one revision's blobs for the re-encrypted ones (idempotent). */
  reencryptRevision(input: ReencryptRevisionInput): Promise<ReencryptRevisionResult>;
}

/**
 * The part of the Web Locks API (`navigator.locks`, §20.2 "Elección") the leader uses; `navigator.locks`
 * implements it as is. The lock is held until the callback's promise settles. With `steal`, the current
 * holder's request rejects (AbortError) while its callback keeps running: fencing then stops its writes.
 */
export interface LockManagerPort {
  request<T>(
    name: string,
    options: { readonly mode: "exclusive"; readonly steal?: boolean; readonly signal?: AbortSignal },
    callback: (lock: unknown) => Promise<T>,
  ): Promise<T>;
}

/** The part of `BroadcastChannel` the leader and its followers use (§20.2); messages are only hints. */
export interface ChannelPort {
  postMessage(message: unknown): void;
  addEventListener(type: "message", listener: (event: { readonly data: unknown }) => void): void;
  removeEventListener(type: "message", listener: (event: { readonly data: unknown }) => void): void;
}
