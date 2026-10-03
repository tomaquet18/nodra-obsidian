import { canonicalizePath } from "@nodra/path-projection";
import { type Intent, type IntentChange, type IntentDecision, type ObjectId, decideIntent, nextIntents, superseded } from "@nodra/sync-core";
import { commitIntent, deleteEntry, freePath, localViewFp, runEntry, writeEntry } from "./executor.js";
import type { ChannelPort, DeviceLocalCrypto } from "./ports.js";
import type { Client } from "./runner.js";
import type { IntentRef, VaultState } from "./state.js";
import { type VaultStore, insertIntent, loadPendingIntents, pendingIntentIds, readLocalView } from "./store.js";

// Intents between contexts of one installation (§20.2 "Seguidores", "Versión local y orden", "Entrega
// garantizada"). The source of truth is the pending_intents row, never a channel message: a message is
// only a hint to look at the table. The pure decisions are sync-core's (leader.ts).

// ---------------------------------------------------------------------------
// Channel messages (hints).

export type Outcome = IntentDecision["kind"];

export type LeaderMessage =
  /** Follower → leader: "look at pending_intents". */
  | { readonly kind: "intent"; readonly contextId: string }
  /** Leader → followers: the intent's row was processed (§20.2 `ack(context_id, intent_seq)`). */
  | { readonly kind: "ack"; readonly contextId: string; readonly intentSeq: number; readonly intentId: string; readonly outcome: Outcome }
  /** Leader → followers: the local state changed; re-read it from IndexedDB. */
  | { readonly kind: "state" }
  /** Leader → followers, every LEADER_HEARTBEAT while active (web only, §20.2 "Latido y toma forzosa"). */
  | { readonly kind: "heartbeat" };

const OUTCOMES: ReadonlySet<string> = new Set(["APPLY", "CONFLICT_COPY", "DISCARD"]);

/** A message from the channel, or null if it is not one of ours (it is only ever a hint). */
export function parseMessage(data: unknown): LeaderMessage | null {
  if (data === null || typeof data !== "object") return null;
  const m = data as Record<string, unknown>;
  if (m.kind === "state") return { kind: "state" };
  if (m.kind === "heartbeat") return { kind: "heartbeat" };
  if (m.kind === "intent" && typeof m.contextId === "string") return { kind: "intent", contextId: m.contextId };
  if (m.kind === "ack" && typeof m.contextId === "string" && typeof m.intentSeq === "number" && typeof m.intentId === "string" && typeof m.outcome === "string" && OUTCOMES.has(m.outcome)) {
    return { kind: "ack", contextId: m.contextId, intentSeq: m.intentSeq, intentId: m.intentId, outcome: m.outcome as Outcome };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Follower side.

/** What a context edited on: per object, its local_version and view_fp. */
export type View = ReadonlyMap<ObjectId, { readonly version: number; readonly fp: string | null }>;

/** A context (tab, window or plugin instance) as a follower. In memory only: a reload is a new context. */
export interface Follower {
  readonly contextId: string;
  /** Last intent_seq assigned: strictly increasing without gaps (1, 2, 3...). */
  seq: number;
  /** Per object, this context's last intent whose result it has not seen yet (after_intent_id). */
  readonly unseen: Map<ObjectId, string>;
  /**
   * Per object, this context's last intent and the view it was made on. An edit made on that same view
   * has not seen the intent's result either, even once acked (NOTES question 414): it chains on it.
   */
  readonly last: Map<ObjectId, { readonly intentId: string; readonly viewVersion: number; readonly viewFp: string | null }>;
  /** Intents sent and not yet known to be processed. */
  readonly sent: Map<string, ObjectId>;
  view: View;
  /** One insert at a time (rows are inserted in intent_seq order). */
  tail: Promise<unknown>;
}

export const newFollower = (contextId: string): Follower => ({ contextId, seq: 0, unseen: new Map(), last: new Map(), sent: new Map(), view: new Map(), tail: Promise.resolve() });

/** Re-reads the local state the follower edits on (the leader's caches in IndexedDB). */
export async function refreshView(store: VaultStore, f: Follower): Promise<void> {
  const { observations, localVersion } = await readLocalView(store);
  f.view = new Map([...observations].map(([id, o]) => [id, { version: localVersion.get(id) ?? 0, fp: localViewFp(o) }]));
}

/**
 * An edit of this context: the row is written to pending_intents first (intent_seq assigned with it),
 * then the leader is told on the channel. `view` is the state the edit was made on (default: the
 * follower's last view); an object missing from it is a creation (version 0, absent).
 */
export function submitIntent(
  store: VaultStore,
  dlc: DeviceLocalCrypto,
  channel: ChannelPort | null,
  f: Follower,
  edit: { readonly intentId: string; readonly objectId: ObjectId; readonly change: IntentChange },
  view: View = f.view,
): Promise<Intent> {
  const run = f.tail.then(async () => {
    const seen = view.get(edit.objectId);
    const viewVersion = seen?.version ?? 0;
    const viewFp = seen === undefined ? localViewFp(undefined) : seen.fp;
    // "Whose result it has not seen" is judged by the view the edit was made on, not by the ack: an editor
    // that keeps its loaded view while the user types edits on top of its own previous intent (Q414).
    const last = f.last.get(edit.objectId);
    const onOwnPrevious = last !== undefined && last.viewVersion === viewVersion && last.viewFp === viewFp ? last.intentId : null;
    const intent: Intent = {
      intentId: edit.intentId,
      contextId: f.contextId,
      intentSeq: f.seq + 1,
      objectId: edit.objectId,
      viewVersion,
      viewFp,
      afterIntentId: f.unseen.get(edit.objectId) ?? onOwnPrevious,
      change: edit.change,
    };
    await insertIntent(store, dlc, intent);
    f.seq = intent.intentSeq; // only once the row exists: no gap if the insert failed
    f.unseen.set(edit.objectId, intent.intentId);
    f.last.set(edit.objectId, { intentId: intent.intentId, viewVersion, viewFp });
    f.sent.set(intent.intentId, edit.objectId);
    channel?.postMessage({ kind: "intent", contextId: f.contextId } satisfies LeaderMessage);
    return intent;
  });
  f.tail = run.catch(() => undefined);
  return run;
}

/** Marks intents as processed: the view is refreshed first, so their results are seen. */
async function confirm(store: VaultStore, f: Follower, intentIds: readonly string[]): Promise<void> {
  if (intentIds.length === 0) return;
  await refreshView(store, f);
  for (const id of intentIds) {
    const objectId = f.sent.get(id);
    f.sent.delete(id);
    if (objectId !== undefined && f.unseen.get(objectId) === id) f.unseen.delete(objectId);
  }
}

/** A channel message for this follower (a hint: the state is re-read from IndexedDB). */
export async function followerReceive(store: VaultStore, f: Follower, data: unknown): Promise<void> {
  const m = parseMessage(data);
  if (m === null || m.kind === "intent" || m.kind === "heartbeat") return;
  if (m.kind === "ack" && m.contextId === f.contextId && f.sent.has(m.intentId)) await confirm(store, f, [m.intentId]);
  else await refreshView(store, f);
}

/**
 * Every INTENT_RESCAN (§20.2 "Entrega garantizada"): an intent whose row is gone was processed, even if
 * its ack was lost; if some row remains, the leader is told again. Content is never re-sent.
 */
export async function followerRescan(store: VaultStore, f: Follower, channel: ChannelPort | null): Promise<void> {
  const pending = await pendingIntentIds(store, f.contextId);
  await confirm(store, f, [...f.sent.keys()].filter((id) => !pending.has(id)));
  if ([...f.sent.keys()].some((id) => pending.has(id))) channel?.postMessage({ kind: "intent", contextId: f.contextId } satisfies LeaderMessage);
}

// ---------------------------------------------------------------------------
// Leader side.

/** INTENT_RESCAN (§20.2), in the units of `Client.now`. */
export const INTENT_RESCAN = 5;

/**
 * The decision for this client's local state. sync-core decides currency; here an APPLY that has no
 * local state to apply to (the object is not on disk, or its hash is unknown) is treated as superseded:
 * a content change is kept as a copy, anything else is discarded. Creations (an object nobody knows) apply.
 */
function localDecision(s: VaultState, i: Intent, d: IntentDecision): IntentDecision {
  if (d.kind !== "APPLY") return d;
  const o = s.observations.get(d.target);
  if (o?.kind === "PRESENT" && o.hash !== null) return d;
  const known = o !== undefined || s.facts.synced.has(d.target) || s.facts.remote.has(d.target);
  if (!known && d.target === i.objectId && i.change.kind === "CONTENT") return d;
  return superseded(i, d.target);
}

const logicalPathOf = (path: string): string | null => {
  const c = canonicalizePath(path);
  return c.ok ? c.path : null;
};

/**
 * One step of the leader's sweep (§20.2): the next pending_intents row (lowest intent_seq of a context)
 * is decided and processed, its row deleted in the same transition as its effect. A disk effect goes
 * through the journal (§15), and the row is deleted when the entry closes. Returns false when the sweep
 * found nothing to do.
 */
export async function processNextIntent(c: Client): Promise<boolean> {
  const { shell } = c;
  const now = c.now();
  if (!c.memory.intentHint && c.memory.lastSweep !== null && now - c.memory.lastSweep < (c.intentRescan ?? INTENT_RESCAN)) return false;
  c.memory.intentHint = false;
  c.memory.lastSweep = now;
  // The rows are facts already in IndexedDB: loading them changes nothing to persist.
  shell.state = { ...shell.state, intents: await loadPendingIntents(shell.store, shell.dlc) };
  const i = nextIntents(shell.state.intents)[0];
  if (i === undefined) return false;
  c.memory.intentHint = true; // keep sweeping while rows remain
  const s = shell.state;
  const decision = localDecision(s, i, decideIntent(i, s.intentState, (id) => localViewFp(s.observations.get(id))));
  c.log?.({ kind: "action", objectId: i.objectId, detail: `intent:${decision.kind}:${i.intentId}` });
  let outcome: Outcome = decision.kind;
  const ref = (copyObjectId: ObjectId | null = null): IntentRef => ({ intentId: i.intentId, decision, copyObjectId });
  const newFile = async (objectId: ObjectId, r: IntentRef) => {
    const logicalPath = logicalPathOf(i.change.path) ?? `nodra-intent-${shell.hex8()}.md`;
    const e = await writeEntry(shell, { objectId, dest: await freePath(shell, logicalPath), expectedPrevFp: "ABSENT", content: i.change.content ?? new Uint8Array(), newSynced: null, logicalPath });
    await runEntry(shell, { ...e, intent: r });
  };
  switch (decision.kind) {
    case "DISCARD":
      await commitIntent(shell, s, ref());
      c.log?.({ kind: "intentDiscarded", objectId: i.objectId });
      break;
    case "CONFLICT_COPY": {
      const copy = shell.newId("copy-");
      await newFile(copy, ref(copy));
      break;
    }
    case "APPLY": {
      const o = s.observations.get(decision.target);
      if (o?.kind !== "PRESENT" || o.hash === null) {
        await newFile(decision.target, ref()); // a creation (localDecision)
        break;
      }
      const change = i.change;
      if (change.kind === "PATH") {
        const logicalPath = logicalPathOf(change.path);
        if (logicalPath === null) {
          outcome = "DISCARD";
          await commitIntent(shell, s, { ...ref(), decision: { kind: "DISCARD" } });
        } else await commitIntent(shell, { ...s, observations: new Map(s.observations).set(decision.target, { ...o, logicalPath }) }, ref());
        break;
      }
      if (change.kind === "DELETE") {
        await runEntry(shell, { ...deleteEntry({ objectId: decision.target, dest: o.physicalPath, expectedPrevFp: o.hash, newSynced: null, marksNotMaterialized: false }), intent: ref() });
        break;
      }
      const e = await writeEntry(shell, {
        objectId: decision.target,
        dest: o.physicalPath,
        expectedPrevFp: o.hash,
        content: change.content,
        newSynced: null,
        logicalPath: logicalPathOf(change.path) ?? o.logicalPath,
      });
      await runEntry(shell, { ...e, intent: ref() });
      break;
    }
  }
  // Processed (row gone) → ack. A cancelled journal entry left the row: it is decided again at the next
  // periodic sweep, not the next tick, so the planner gets to act on whatever blocked it (Q64).
  if (!shell.state.intents.some((r) => r.intentId === i.intentId)) c.notify?.({ kind: "ack", contextId: i.contextId, intentSeq: i.intentSeq, intentId: i.intentId, outcome });
  else c.memory.intentHint = false;
  return true;
}
