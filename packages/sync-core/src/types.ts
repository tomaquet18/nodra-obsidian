// Client three-tree model (§12.2). Pure data: no I/O, no classes.

export type ObjectId = string;
export type RevisionId = string;
export type MutationId = string;
/** Logical path (§16). Physical projection lives in packages/path-projection. */
export type LogicalPath = string;
/**
 * A file's content: its exact bytes (§2.1: Markdown, images and attachments). Never a string, so no
 * layer can decode and re-encode a binary file by accident. Only the merge of §17 reads it as text.
 */
export type Content = Uint8Array;
/** `local_compare_hash` = HMAC-SHA-256(LocalCompareKey, plaintext), opaque here (§12.2). */
export type LocalCompareHash = string;
/**
 * A `local_compare_hash`, or "ABSENT" where there is no file. The same type as `LocalCompareHash` (a
 * string), named so every signature that accepts the sentinel says so.
 */
// eslint-disable-next-line @typescript-eslint/no-redundant-type-constituents -- the union documents the "ABSENT" sentinel; LocalCompareHash is a plain string
export type LocalCompareHashOrAbsent = LocalCompareHash | "ABSENT";

/**
 * A real server revision, as recorded in S (SyncedState) or in the R cache (RemoteState).
 * `localCompareHash` is null when the plaintext was never available on this device.
 * For a deleted revision the hash and path do not take part in equality.
 */
export interface RevisionEntry {
  readonly revisionId: RevisionId;
  readonly sequence: number;
  readonly path: LogicalPath;
  readonly localCompareHash: LocalCompareHash | null;
  readonly deleted: boolean;
  /** Sequence of the commit that created the object (§16.3 projection priority). */
  readonly createdSequence: number;
  /**
   * Where the revision's content ciphertext is (§13.1 `content_blob_id`, `content_epoch_id`), kept so
   * that the revision can be read after a restart even when it is no longer a head (a merge base).
   * null: a delete. Absent: not known (the backend gave none, or the entry predates this field).
   */
  readonly content?: ContentRef | null;
}

/** A revision's content blob and the epoch its key belongs to. */
export interface ContentRef {
  readonly blobId: string;
  readonly epochId: string;
}

export type SyncedEntry = RevisionEntry;
export type RemoteEntry = RevisionEntry;

/**
 * Observed local state per object (§12.2 rule 2). An object with no local entry is
 * treated as UNBOUND (remote object not yet applied).
 */
/** Physical path relative to the vault root (§16.1); never uploaded. */
export type PhysicalPath = string;

export type LocalEntry =
  | {
      readonly kind: "PRESENT";
      /** Logical path recorded with the last observation (§12.2 table). */
      readonly path: LogicalPath;
      /** Physical path observed now. */
      readonly physicalPath: PhysicalPath;
      /** Physical path recorded with the last observation; a different one means the file moved (rule 12). */
      readonly recordedPhysicalPath: PhysicalPath;
      readonly localCompareHash: LocalCompareHash;
    }
  /** Was materialized and its file is gone: the only state that may mean a local delete. */
  | { readonly kind: "ABSENT" }
  /** Not on disk by client decision: remote object not applied yet, or original after a conflict copy (rule 4). */
  | { readonly kind: "UNBOUND" }
  /**
   * Not on disk by the client's decision (§16.2): its projected path is too long (a projection
   * fact, re-evaluated at every plan) or this replica's file system rejected it.
   */
  | { readonly kind: "NOT_MATERIALIZED"; readonly reason: "LOCAL_PATH_TOO_LONG" | "LOCAL_FS_REJECTED" };


export type BlockedReason = "BLOB_TOO_LARGE" | "UPLOAD_TIMEOUT_MAX" | "INVALID_BATCH_REPEATED";

/** "The server rejected this content for this object" (§12.2 rule 8). */
export interface BlockedContent {
  readonly objectId: ObjectId;
  readonly localCompareHash: LocalCompareHash;
  readonly reason: BlockedReason;
}

export interface PlanInput {
  readonly local: ReadonlyMap<ObjectId, LocalEntry>;
  readonly remote: ReadonlyMap<ObjectId, RemoteEntry>;
  readonly synced: ReadonlyMap<ObjectId, SyncedEntry>;
  /** Outbox entries (outbox.ts); the planner only needs which objects are in flight (rule 9). */
  readonly outbox: ReadonlyArray<{ readonly objects: ReadonlyArray<{ readonly objectId: ObjectId }> }>;
  readonly blocked: ReadonlyArray<BlockedContent>;
  /** Objects whose content is text (mergeable line by line). Unknown means not text (conservative). */
  readonly textObjects: ReadonlySet<ObjectId>;
  /** Revisions known to be pruned (§10.6): their bytes cannot be downloaded as a merge base. */
  readonly prunedRevisions: ReadonlySet<RevisionId>;
  /** Untracked files on this replica's disk: they occupy paths (§16.3) and are never touched. */
  readonly untrackedFiles: readonly PhysicalPath[];
  /** Candidate 8-hex names for parking files in rename cycles (§16.7 rule 3); randomness is an input. */
  readonly tmpHex: readonly string[];
}

export type ConflictCopyReason =
  | "unmergeable" // both sides changed content and merge is not possible (not text / base pruned)
  | "noCommonAncestor" // §17.1: unknown ancestor, no field counts as unchanged
  | "remoteDeleted"; // §12.2 rule 5 / §18.2: remote delete vs local content change

export type Side = "local" | "remote";

export type Action =
  /** Download and decrypt a revision to learn its local_compare_hash (§12.2). */
  | { readonly kind: "fetchContent"; readonly objectId: ObjectId; readonly revisionId: RevisionId }
  /** S := R without writing or uploading (table row 4, rule 3a, delete/delete). */
  | { readonly kind: "advanceSynced"; readonly objectId: ObjectId; readonly revisionId: RevisionId }
  /** Upload the observed local state (content, path or delete) on top of `expectedHeadRevisionId`. */
  | {
      readonly kind: "upload";
      readonly objectId: ObjectId;
      readonly expectedHeadRevisionId: RevisionId | null;
      readonly deleted: boolean;
    }
  /**
   * Conservative apply of a remote revision to disk (§13.4, through the journal of §15) at
   * `physicalPath`: the object's current file, or its projected path when it is materialized.
   * A deleted revision removes the file.
   */
  | {
      readonly kind: "applyRemote";
      readonly objectId: ObjectId;
      readonly revisionId: RevisionId;
      readonly physicalPath: PhysicalPath;
    }
  /** Physical rename from the projection (§16.7), including parking under nodra-tmp-*. No logical change. */
  | {
      readonly kind: "movePhysical";
      readonly objectId: ObjectId;
      readonly from: PhysicalPath;
      readonly to: PhysicalPath;
    }
  /**
   * The object should take R but its projected path is not materializable (§16.2,
   * LOCAL_PATH_TOO_LONG): in one transaction S := R and L := NOT_MATERIALIZED. Nothing is written.
   */
  | { readonly kind: "markNotMaterialized"; readonly objectId: ObjectId; readonly revisionId: RevisionId }
  /** A NOT_MATERIALIZED object with nothing pending leaves the disk (§16.2). No logical change. */
  | { readonly kind: "removePhysical"; readonly objectId: ObjectId; readonly from: PhysicalPath }
  /**
   * Field-wise resolution (§17.1). `content: "merge"` runs merge3 with the bytes of S;
   * if the executor cannot merge, it falls back to a conflict copy (rule 4).
   */
  | {
      readonly kind: "resolve";
      readonly objectId: ObjectId;
      readonly baseRevisionId: RevisionId;
      readonly remoteRevisionId: RevisionId;
      readonly content: Side | "merge";
      readonly path: Side;
      readonly localRenameDiscarded: boolean;
    }
  /** Local content becomes a new object with the local path; the original takes R and is UNBOUND (rule 4). */
  | {
      readonly kind: "conflictCopy";
      readonly objectId: ObjectId;
      readonly remoteRevisionId: RevisionId;
      readonly reason: ConflictCopyReason;
    }
  /** Rule 5b: remote delete wins over a local rename without content change; notify. */
  | { readonly kind: "discardLocalRename"; readonly objectId: ObjectId; readonly remoteRevisionId: RevisionId }
  /** Rule 6: unconfirmed create that is ABSENT is forgotten without sending anything. */
  | { readonly kind: "forgetUnconfirmedCreate"; readonly objectId: ObjectId };

export type ActionKind = Action["kind"];
