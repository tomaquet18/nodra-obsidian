import type { FileStatEntry } from "./stat-cache.js";
import type { ClientFacts, IntentDecision, IntentState, Intent, JournalEntry, LocalCompareHash, LogicalPath, ObjectId, OtherSyncFacts, PhysicalPath, RevisionId } from "@nodra/sync-core";

// The persisted facts of one vault (§12.2 table, §15, §20.1, §20.2), in memory. Every field is a fact
// about the world, never a step of an algorithm. The store (store.ts) persists the difference between
// two of these values in one IndexedDB transaction.

/**
 * The last observation of an object (§12.2 table): which file it is, at which physical and logical
 * path, with which local_compare_hash; ABSENT is the `gone` bit; NOT_MATERIALIZED is the client's own
 * decision (§16.2). An object without an observation is UNBOUND (remote object not applied yet).
 */
export type Observation =
  | {
      readonly kind: "PRESENT";
      readonly logicalPath: LogicalPath;
      readonly physicalPath: PhysicalPath;
      /** null when unknown (the LocalCompareKey was lost, §20.1). */
      readonly hash: LocalCompareHash | null;
    }
  /** Was materialized and its file is gone at the last observation (Q45: it claims no path). */
  | { readonly kind: "ABSENT"; readonly logicalPath: LogicalPath }
  | { readonly kind: "NOT_MATERIALIZED" };

/**
 * The intent a journal entry applies (§20.2, plugin: "una escritura en disco por el journal"). The row is
 * deleted in the transaction that CLOSES the entry, together with its effect; a cancelled entry leaves the
 * row, so the intent is decided again from the new state (never lost, never applied twice).
 */
export interface IntentRef {
  readonly intentId: string;
  readonly decision: IntentDecision;
  /** CONFLICT_COPY: the new object's id (the entry's object). */
  readonly copyObjectId: ObjectId | null;
}

/** A journal entry (§15) of the client, optionally applying an intent. */
export type ClientJournalEntry = JournalEntry & { readonly intent?: IntentRef };

export interface VaultState {
  /** §20.2 fencing: the `meta` row's leader_epoch as last read. */
  readonly leaderEpoch: number;
  readonly facts: ClientFacts;
  readonly observations: ReadonlyMap<ObjectId, Observation>;
  /** At most one open entry (§15). */
  readonly journal: ClientJournalEntry | null;
  /** local_compare_hash cache by revision_id (§12.2): revisions whose plaintext this device saw. */
  readonly hashes: ReadonlyMap<RevisionId, LocalCompareHash>;
  /** pending_intents rows (§20.2), content encrypted at rest. */
  readonly intents: readonly Intent[];
  /** The leader's intent store (§20.2 "Versión local y orden"). */
  readonly intentState: IntentState;
  /** The observation cache (stat-cache.ts, NOTES question 146): the last hash of each file on disk, by physical path. */
  readonly fileStats: ReadonlyMap<PhysicalPath, FileStatEntry>;
  /**
   * §20.2, another sync tool (NOTES question 419): the content this replica's journal wrote per object,
   * and the arrivals the user accepted. Facts of this replica, pruned at every transition (executor.ts).
   */
  readonly otherSync: OtherSyncFacts;
}
