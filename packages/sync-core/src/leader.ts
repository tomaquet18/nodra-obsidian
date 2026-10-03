import type { Content, LocalCompareHash, LogicalPath, ObjectId } from "./types.js";

// One writer per (installation, vault): the sync leader among tabs/windows (§20.2). Pure decisions:
// fencing by leader_epoch, intent order, whether an intent is current, and processing an intent
// together with the deletion of its pending_intents row (one atomic transition).

/** The vault's `meta` row. */
export interface VaultMeta {
  readonly leaderEpoch: number;
}

/** The new leader's FIRST transaction: increment leader_epoch and remember it (§20.2 "Relevo"). */
export function takeLeadership(meta: VaultMeta): { meta: VaultMeta; epoch: number } {
  const epoch = meta.leaderEpoch + 1;
  return { meta: { leaderEpoch: epoch }, epoch };
}

/** Every readwrite transaction of the leader reads leader_epoch first and aborts if it is not its own. */
export function fencedWriteAllowed(meta: VaultMeta, epoch: number): boolean {
  return meta.leaderEpoch === epoch;
}

export type IntentChange =
  | { readonly kind: "CONTENT"; readonly path: LogicalPath; readonly content: Content }
  | { readonly kind: "PATH"; readonly path: LogicalPath; readonly content: null }
  | { readonly kind: "DELETE"; readonly path: LogicalPath; readonly content: null };

/** A pending_intents row (§20.2 "Seguidores"). */
export interface Intent {
  readonly intentId: string;
  readonly contextId: string;
  /** Strictly increasing without gaps within its context. */
  readonly intentSeq: number;
  readonly objectId: ObjectId;
  /** local_version the follower edited on (0 for an object it creates). */
  readonly viewVersion: number;
  /** Summary (path, deleted, local_compare_hash) of the state the follower edited on; null when unknown (§20.1). */
  readonly viewFp: string | null;
  /** The previous intent of the same context for the same object whose result it has not seen yet. */
  readonly afterIntentId: string | null;
  readonly change: IntentChange;
}

/** The leader's intent store, next to pending_intents (never in the outbox). */
export interface IntentState {
  readonly localVersion: ReadonlyMap<ObjectId, number>;
  readonly lastIntent: ReadonlyMap<ObjectId, { readonly intentId: string; readonly version: number }>;
  /** At most one per context: its last intent that became a conflict copy (or applied to one). */
  readonly copyLinks: ReadonlyMap<string, { readonly intentId: string; readonly copyObjectId: ObjectId; readonly version: number }>;
}

export const emptyIntentState = (): IntentState => ({ localVersion: new Map(), lastIntent: new Map(), copyLinks: new Map() });

/** local_version increases on every change of the object's local state, whatever the cause. */
export function bumpLocalVersion(st: IntentState, objectId: ObjectId): IntentState {
  return { ...st, localVersion: new Map(st.localVersion).set(objectId, (st.localVersion.get(objectId) ?? 0) + 1) };
}

/** The next rows to process: the lowest intent_seq of each context. */
export function nextIntents(pending: readonly Intent[]): Intent[] {
  const byContext = new Map<string, Intent>();
  for (const i of pending) {
    const current = byContext.get(i.contextId);
    if (!current || i.intentSeq < current.intentSeq) byContext.set(i.contextId, i);
  }
  return [...byContext.values()].sort((a, b) => (a.contextId < b.contextId ? -1 : a.contextId > b.contextId ? 1 : 0));
}

export type IntentDecision =
  | { readonly kind: "APPLY"; readonly target: ObjectId }
  | { readonly kind: "CONFLICT_COPY"; readonly base: ObjectId }
  | { readonly kind: "DISCARD" };

/** What happens to an intent that is not current: a content change is kept as a copy, the rest is discarded. */
export const superseded = (i: Intent, base: ObjectId): IntentDecision =>
  i.change.kind === "CONTENT" ? { kind: "CONFLICT_COPY", base } : { kind: "DISCARD" };

/**
 * view_fp (§20.2): the summary (path, deleted, local_compare_hash) of an object's local state, the same
 * function on the follower and on the leader. `null` state = the object does not exist locally. Returns
 * null when the hash is unknown (§20.1, LocalCompareKey lost): an unknown summary never matches.
 */
export function viewFingerprint(s: { readonly path: LogicalPath; readonly deleted: boolean; readonly localCompareHash: LocalCompareHash | null } | null): string | null {
  if (s === null) return "absent";
  if (!s.deleted && s.localCompareHash === null) return null;
  return JSON.stringify([s.path, s.deleted, s.deleted ? null : s.localCompareHash]);
}

/**
 * §20.2: an intent is current if view_version == local_version, or it chains on the context's previous
 * intent with nothing in between, or view_fp matches the current state. A chain whose previous intent
 * became a conflict copy continues on the copy only while the copy is unchanged. A superseded content
 * change is kept as a conflict copy; a superseded path change or delete is discarded (and notified).
 * An unknown summary (null, on either side) never matches.
 */
export function decideIntent(i: Intent, st: IntentState, currentFp: (objectId: ObjectId) => string | null): IntentDecision {
  const link = st.copyLinks.get(i.contextId);
  if (link && i.afterIntentId !== null && i.afterIntentId === link.intentId) {
    return (st.localVersion.get(link.copyObjectId) ?? 0) === link.version ? { kind: "APPLY", target: link.copyObjectId } : superseded(i, link.copyObjectId);
  }
  const version = st.localVersion.get(i.objectId) ?? 0;
  const last = st.lastIntent.get(i.objectId);
  const current =
    i.viewVersion === version ||
    (i.afterIntentId !== null && last?.intentId === i.afterIntentId && last.version === version) ||
    (i.viewFp !== null && i.viewFp === currentFp(i.objectId));
  return current ? { kind: "APPLY", target: i.objectId } : superseded(i, i.objectId);
}

/**
 * Processes one intent and deletes its row in the same transition (it can never be applied twice).
 * `copyObjectId` is the id of the new object for a CONFLICT_COPY (an input: ids are not generated here).
 */
export function processIntent(
  st: IntentState,
  pending: readonly Intent[],
  i: Intent,
  decision: IntentDecision,
  copyObjectId?: ObjectId,
): { state: IntentState; pending: Intent[] } {
  if (!pending.some((p) => p.intentId === i.intentId)) throw new Error(`intent ${i.intentId} is not pending (already processed)`);
  const rest = pending.filter((p) => p.intentId !== i.intentId);
  const links = new Map(st.copyLinks);
  links.delete(i.contextId); // any later intent of the context replaces its link
  let state: IntentState = { ...st, copyLinks: links };
  if (decision.kind === "APPLY") {
    state = bumpLocalVersion(state, decision.target);
    const version = state.localVersion.get(decision.target)!;
    state = { ...state, lastIntent: new Map(state.lastIntent).set(decision.target, { intentId: i.intentId, version }) };
    const wasChain = st.copyLinks.get(i.contextId)?.copyObjectId === decision.target;
    if (wasChain) state = { ...state, copyLinks: new Map(state.copyLinks).set(i.contextId, { intentId: i.intentId, copyObjectId: decision.target, version }) };
  } else if (decision.kind === "CONFLICT_COPY") {
    if (copyObjectId === undefined) throw new Error("a conflict copy needs the new object's id");
    state = bumpLocalVersion(state, copyObjectId);
    const version = state.localVersion.get(copyObjectId)!;
    state = { ...state, copyLinks: new Map(state.copyLinks).set(i.contextId, { intentId: i.intentId, copyObjectId, version }) };
  }
  return { state, pending: rest };
}
