import { type ClientFacts, confirmByEcho, recordRemoteHeads } from "./outbox.js";
import type { ContentRef, LogicalPath, MutationId, ObjectId, RemoteEntry, RevisionId } from "./types.js";

// Remote state from events (§13) and full reconciliation (§18.4). Pure transitions: a page of
// events is recorded in R completely or not at all, together with the cursor (§13.4).

/** A REVISION event (§13.1), with the fields of its manifest already opened (path, deleted). */
export interface RevisionEvent {
  readonly kind: "REVISION";
  readonly sequence: number;
  readonly objectId: ObjectId;
  readonly revisionId: RevisionId;
  readonly parentRevisionId: RevisionId | null;
  readonly path: LogicalPath;
  readonly deleted: boolean;
  readonly createdSequence: number;
  readonly mutationId: MutationId;
  readonly batchIndex: number;
  readonly batchSize: number;
  /** content_blob_id and content_epoch_id of the event (null: a delete); absent when the backend gives none. */
  readonly content?: ContentRef | null;
}

export interface EpochRotatedEvent {
  readonly kind: "EPOCH_ROTATED";
  readonly sequence: number;
  readonly epochId: string;
  readonly batchIndex: 0;
  readonly batchSize: 1;
}

/**
 * A SECURITY event (§13.1, §37): a `security_event_id` the account's security log gained. It changes
 * nothing the planner reads — no head, no epoch — so here it only moves the cursor. For the client
 * it is a hint that the account's security log grew: sync-client reads that log with
 * `listSecurityEvents` and shows what this replica has not acknowledged (§37, `security-events.ts`).
 */
export interface SecurityEvent {
  readonly kind: "SECURITY";
  readonly sequence: number;
  readonly securityEventId: number;
  readonly batchIndex: 0;
  readonly batchSize: 1;
}

export type SyncEvent = RevisionEvent | EpochRotatedEvent | SecurityEvent;

const head = (e: RevisionEvent): RemoteEntry => ({
  revisionId: e.revisionId,
  sequence: e.sequence,
  path: e.path,
  localCompareHash: null,
  deleted: e.deleted,
  createdSequence: e.createdSequence,
  ...(e.content === undefined ? {} : { content: e.content }),
});

/** Every batch of the page is whole: it starts at index 0 and its indexes follow one another. */
function wholeBatches(page: readonly SyncEvent[]): boolean {
  for (let i = 0; i < page.length; i++) {
    const e = page[i]!;
    if (e.batchIndex === 0) continue;
    const prev = page[i - 1];
    if (prev === undefined || prev.batchIndex !== e.batchIndex - 1 || prev.batchSize !== e.batchSize) return false;
    if (e.kind === "REVISION" && (prev.kind !== "REVISION" || prev.mutationId !== e.mutationId)) return false;
  }
  const last = page[page.length - 1];
  return last === undefined || last.batchIndex === last.batchSize - 1;
}

/**
 * Applies one page of listEvents. §13.2 client defence: a page that does not start at cursor + 1,
 * has a gap, or holds an incomplete batch is discarded and the client reconciles (§18.4). Otherwise
 * every head goes to R without regression (rule 3), an event at or below S's sequence is a no-op,
 * EPOCH_ROTATED updates the write epoch, a SECURITY event only takes the cursor past it, and a batch
 * carrying all revisions of an own in-flight entry confirms it (§13.4). All in one transition, with the cursor.
 */
export function applyEvents(f: ClientFacts, page: readonly SyncEvent[]): { kind: "APPLIED"; facts: ClientFacts } | { kind: "RECONCILE" } {
  if (page.length === 0) return { kind: "APPLIED", facts: f };
  if (page[0]!.sequence !== f.cursor + 1) return { kind: "RECONCILE" };
  for (let i = 1; i < page.length; i++) if (page[i]!.sequence !== page[i - 1]!.sequence + 1) return { kind: "RECONCILE" };
  if (!wholeBatches(page)) return { kind: "RECONCILE" };

  let facts = f;
  const revisions = page.filter((e): e is RevisionEvent => e.kind === "REVISION");
  for (const e of page) if (e.kind === "EPOCH_ROTATED") facts = { ...facts, epochId: e.epochId };
  facts = recordRemoteHeads(
    facts,
    revisions.filter((e) => e.sequence > (f.synced.get(e.objectId)?.sequence ?? 0)).map((e) => ({ objectId: e.objectId, head: head(e) })),
  );
  for (const entry of f.outbox) {
    const echoes = entry.objects.map((o) => revisions.find((e) => e.revisionId === o.revisionId && e.objectId === o.objectId));
    if (echoes.every((e) => e !== undefined)) {
      facts = confirmByEcho(
        facts,
        entry.mutationId,
        echoes.map((e) => ({ objectId: e.objectId, revisionId: e.revisionId, sequence: e.sequence, createdSequence: e.createdSequence })),
      );
    }
  }
  return { kind: "APPLIED", facts: { ...facts, cursor: page[page.length - 1]!.sequence } };
}

/** getVaultState (§18.4 step 2): heads of every object (graveyard included) at one sequence N. */
export interface VaultState {
  readonly sequence: number;
  readonly epochId: string;
  readonly heads: ReadonlyArray<{ readonly objectId: ObjectId; readonly head: RemoteEntry }>;
}

/**
 * Full reconciliation, step 2 (§18.4): R takes the state (without regressing), the cursor becomes N.
 * Step 1 (settling the outbox with getRevisionStatus) must come first: an entry whose commit may have
 * been sent is still unsettled.
 */
export function applyVaultState(f: ClientFacts, state: VaultState): ClientFacts {
  if (f.outbox.some((e) => e.commitSent)) throw new Error("settle the outbox with getRevisionStatus before getVaultState (§18.4)");
  return { ...recordRemoteHeads(f, state.heads), cursor: state.sequence, epochId: state.epochId };
}
