// Several contexts (tabs, windows, plugin reloads) of one installation on one vault (§20.2): a lock,
// leader_epoch fencing, pending_intents written by followers and processed by the leader, frozen
// leaders, forced takeover and lost channel messages. Deterministic by seed. The vault state is the
// web model (editor state in IndexedDB); the plugin's disk queue is out of scope here.

import {
  type Intent,
  type IntentChange,
  type IntentState,
  type VaultMeta,
  bumpLocalVersion,
  decideIntent,
  emptyIntentState,
  fencedWriteAllowed,
  nextIntents,
  processIntent,
  takeLeadership,
} from "../../src/leader.js";
import { text, utf8 } from "../utf8.js";

export interface ObjectState {
  path: string;
  deleted: boolean;
  content: string;
}
export const fp = (s: ObjectState | undefined) => (s ? `${s.path}|${s.deleted}|${s.content}` : "absent");

/** The vault's IndexedDB tables shared by every context. */
export interface Db {
  meta: VaultMeta;
  pending: Intent[];
  intents: IntentState;
  objects: Map<string, ObjectState>;
  /** What produced each object's current state: an intent id, or "other" (leader edit, remote event). */
  changedBy: Map<string, string>;
}

export interface Context {
  readonly id: string;
  alive: boolean;
  frozen: boolean;
  /** The leader_epoch this context believes it holds (null = follower). */
  epoch: number | null;
  view: Map<string, { version: number; fp: string }>;
  seq: number;
  /** Per object: this context's last intent whose result it has not seen (after_intent_id). */
  unseen: Map<string, string>;
}

export interface LeaderFaults {
  readonly lostMessage: number;
  readonly freeze: number;
  readonly wake: number;
  readonly reload: number;
  readonly steal: number;
  readonly followerEdit: number;
  readonly leaderEdit: number;
  readonly activeUntil: number;
}

export interface LeaderVariant {
  /** Broken: writes do not check leader_epoch. */
  readonly noFencing?: boolean;
  /** Broken: an intent is applied but its row is not deleted. */
  readonly keepRows?: boolean;
  /** Broken: every intent is applied, current or not. */
  readonly ignoreCurrency?: boolean;
}

export interface Tabs {
  readonly db: Db;
  readonly contexts: Context[];
  lock: string | null;
  rng: number;
  step: number;
  readonly faults: LeaderFaults;
  readonly log: {
    commits: Array<{ contextId: string; epoch: number; metaEpoch: number }>;
    processed: Map<string, number>;
    created: string[];
    outcomes: Map<string, string>;
    unknownStateApplies: string[];
    steals: number;
    fencedAborts: number;
    copies: number;
    discards: number;
    chainedOnCopy: number;
    lostMessages: number;
    reloads: number;
  };
}

function random(t: Tabs): number {
  t.rng = (Math.imul(t.rng, 1103515245) + 12345) | 0;
  return ((t.rng >>> 8) & 0xffffff) / 0x1000000;
}
const chance = (t: Tabs, p: number) => t.step < t.faults.activeUntil && random(t) < p;
const pick = <T>(t: Tabs, xs: readonly T[]): T => xs[Math.floor(random(t) * xs.length)]!;

export function newTabs(seed: number, faults: LeaderFaults, contexts = 3): Tabs {
  const objects = new Map<string, ObjectState>([
    ["o1", { path: "o1.md", deleted: false, content: "one" }],
    ["o2", { path: "o2.md", deleted: false, content: "two" }],
  ]);
  const t: Tabs = {
    db: { meta: { leaderEpoch: 0 }, pending: [], intents: emptyIntentState(), objects, changedBy: new Map() },
    contexts: [],
    lock: null,
    rng: seed,
    step: 0,
    faults,
    log: {
      commits: [],
      processed: new Map(),
      created: [],
      outcomes: new Map(),
      unknownStateApplies: [],
      steals: 0,
      fencedAborts: 0,
      copies: 0,
      discards: 0,
      chainedOnCopy: 0,
      lostMessages: 0,
      reloads: 0,
    },
  };
  for (let i = 0; i < contexts; i++) t.contexts.push(newContext(t, `ctx-${i}`));
  return t;
}

function newContext(t: Tabs, id: string): Context {
  const c: Context = { id, alive: true, frozen: false, epoch: null, view: new Map(), seq: 0, unseen: new Map() };
  refreshView(t, c);
  return c;
}

function refreshView(t: Tabs, c: Context): void {
  for (const [id, s] of t.db.objects) c.view.set(id, { version: t.db.intents.localVersion.get(id) ?? 0, fp: fp(s) });
}

/** A readwrite transaction of a context that believes it is the leader (fenced by leader_epoch). */
export function write(t: Tabs, c: Context, v: LeaderVariant, body: () => void): boolean {
  if (c.epoch === null) return false;
  if (!v.noFencing && !fencedWriteAllowed(t.db.meta, c.epoch)) {
    t.log.fencedAborts++;
    c.epoch = null; // degraded to follower
    return false;
  }
  body();
  t.log.commits.push({ contextId: c.id, epoch: c.epoch, metaEpoch: t.db.meta.leaderEpoch });
  return true;
}

/** Acquiring the lock (free, or stolen with { steal: true }): the first transaction increments leader_epoch. */
export function acquire(t: Tabs, c: Context): void {
  const { meta, epoch } = takeLeadership(t.db.meta);
  t.db.meta = meta;
  t.lock = c.id;
  c.epoch = epoch;
  refreshView(t, c);
}

function broadcast(t: Tabs, ack?: { contextId: string; intentId: string; objectId: string }): void {
  for (const c of t.contexts) {
    if (!c.alive || c.epoch !== null) continue;
    if (chance(t, t.faults.lostMessage)) {
      t.log.lostMessages++;
      continue;
    }
    refreshView(t, c);
    if (ack && ack.contextId === c.id && c.unseen.get(ack.objectId) === ack.intentId) c.unseen.delete(ack.objectId);
  }
}

/** The leader processes the next intent of one context from its pending_intents row. */
export function sweepOne(t: Tabs, c: Context, v: LeaderVariant): boolean {
  const next = nextIntents(t.db.pending);
  if (next.length === 0) return false;
  const i = pick(t, next);
  return write(t, c, v, () => {
    const decision = v.ignoreCurrency ? { kind: "APPLY" as const, target: i.objectId } : decideIntent(i, t.db.intents, (id) => fp(t.db.objects.get(id)));
    const copyId = decision.kind === "CONFLICT_COPY" ? `${decision.base}~copy-${i.intentId}` : undefined;
    if (decision.kind === "APPLY") {
      // Oracle: the object is in a state the follower knew (what it saw, or its own previous result).
      const target = t.db.objects.get(decision.target);
      const known = fp(target) === i.viewFp || (i.afterIntentId !== null && t.db.changedBy.get(decision.target) === i.afterIntentId);
      if (!known) t.log.unknownStateApplies.push(i.intentId);
      if (decision.target !== i.objectId) t.log.chainedOnCopy++;
      applyChange(t, decision.target, i.change, i.intentId);
    } else if (decision.kind === "CONFLICT_COPY") {
      t.log.copies++;
      t.db.objects.set(copyId!, { path: `${i.change.path} (copy)`, deleted: false, content: i.change.content === null ? "" : text(i.change.content) });
      t.db.changedBy.set(copyId!, i.intentId);
    } else t.log.discards++;
    if (v.keepRows) {
      if (decision.kind === "APPLY") t.db.intents = bumpLocalVersion(t.db.intents, decision.target);
    } else {
      const r = processIntent(t.db.intents, t.db.pending, i, decision, copyId);
      t.db.intents = r.state;
      t.db.pending = r.pending;
    }
    t.log.processed.set(i.intentId, (t.log.processed.get(i.intentId) ?? 0) + 1);
    t.log.outcomes.set(i.intentId, decision.kind);
    broadcast(t, { contextId: i.contextId, intentId: i.intentId, objectId: i.objectId });
  });
}

function applyChange(t: Tabs, objectId: string, change: IntentChange, by: string): void {
  const s = t.db.objects.get(objectId) ?? { path: change.path, deleted: false, content: "" };
  t.db.objects.set(objectId, change.kind === "CONTENT" ? { ...s, path: change.path, content: text(change.content) } : change.kind === "PATH" ? { ...s, path: change.path } : { ...s, deleted: true });
  t.db.changedBy.set(objectId, by);
}

/** A follower's edit: written to pending_intents first (the channel message is only a hint). */
export function followerEdit(t: Tabs, c: Context): void {
  const live = [...c.view.keys()].filter((id) => !t.db.objects.get(id)?.deleted).sort();
  if (live.length === 0) return;
  const objectId = pick(t, live);
  const view = c.view.get(objectId)!;
  const r = random(t);
  const current = t.db.objects.get(objectId)!;
  const change: IntentChange =
    r < 0.7 ? { kind: "CONTENT", path: current.path, content: utf8(`${c.id} edit ${t.step}`) } : r < 0.9 ? { kind: "PATH", path: `${c.id}-${t.step}.md`, content: null } : { kind: "DELETE", path: current.path, content: null };
  const intent: Intent = {
    intentId: `${c.id}#${c.seq + 1}`,
    contextId: c.id,
    intentSeq: c.seq + 1,
    objectId,
    viewVersion: view.version,
    viewFp: view.fp,
    afterIntentId: c.unseen.get(objectId) ?? null,
    change,
  };
  c.seq++;
  t.db.pending.push(intent);
  t.log.created.push(intent.intentId);
  c.unseen.set(objectId, intent.intentId);
}

/** One scheduler step. Returns false once nothing is left to do after the active phase. */
export function step(t: Tabs, v: LeaderVariant): boolean {
  t.step++;
  const active = t.step < t.faults.activeUntil;
  // Lock handover: a free lock (holder gone) goes to the first alive, unfrozen context.
  const holder = t.contexts.find((c) => c.id === t.lock);
  if (!holder || !holder.alive) {
    const next = t.contexts.find((c) => c.alive && !c.frozen);
    if (next) acquire(t, next);
  }
  const c = pick(t, t.contexts.filter((x) => x.alive));
  if (active && chance(t, t.faults.reload)) {
    c.alive = false; // closed or reloaded: the browser releases its lock; its pending rows stay
    if (t.lock === c.id) t.lock = null;
    t.contexts.push(newContext(t, `ctx-${t.contexts.length}`));
    t.log.reloads++;
    return true;
  }
  if (c.frozen) {
    if (!active || chance(t, t.faults.wake)) c.frozen = false;
    return true;
  }
  if (c.epoch !== null) {
    // Believes it is the leader.
    if (active && chance(t, t.faults.freeze)) {
      c.frozen = true;
      return true;
    }
    if (active && chance(t, t.faults.leaderEdit)) {
      const id = pick(t, [...t.db.objects.keys()].sort());
      write(t, c, v, () => {
        applyChange(t, id, { kind: "CONTENT", path: t.db.objects.get(id)!.path, content: utf8(`leader edit ${t.step}`) }, "other");
        t.db.intents = bumpLocalVersion(t.db.intents, id);
        broadcast(t);
      });
      return true;
    }
    return sweepOne(t, c, v) || active || t.db.pending.length > 0;
  }
  // Follower.
  const leader = t.contexts.find((x) => x.id === t.lock);
  if (leader?.frozen && (!active || chance(t, t.faults.steal))) {
    t.log.steals++;
    acquire(t, c); // { steal: true }: the fencing deposes the frozen leader
    return true;
  }
  if (active && chance(t, t.faults.followerEdit)) followerEdit(t, c);
  return active || t.db.pending.length > 0 || t.contexts.some((x) => x.alive && x.frozen);
}

export function runTabs(t: Tabs, v: LeaderVariant, maxSteps: number): number | null {
  let idle = 0;
  while (t.step < maxSteps) {
    idle = step(t, v) ? 0 : idle + 1;
    if (idle > 20) return t.step;
  }
  return null;
}
