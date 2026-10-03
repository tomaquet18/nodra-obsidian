import { project } from "@nodra/path-projection";
import { type Intent, type IntentChange, type ObjectId, bytesStartWith, isMergeablePath, isTmpName } from "@nodra/sync-core";
import fc from "fast-check";
import { DEFAULT_SERVER, type Scenario, build, scenarioArb } from "@nodra/sync-core/test-support/scenario";
import {
  type ServerConfig,
  attachBlobs,
  expireMutationRows,
  gc,
  listToReencrypt,
  modelInvariants,
  preSwitchBlobs,
  prune,
  remoteCommit,
  rotateEpoch,
  switchToPrivate,
} from "@nodra/sync-core/test-support/server";
import type { Shell } from "../../src/executor.js";
import { type Follower, type View, followerRescan, newFollower, refreshView, submitIntent } from "../../src/intents.js";
import { type DiskQueue, diskQueue, isQueueClosed } from "../../src/queue.js";
import { reencryptPass } from "../../src/reencrypt.js";
import { type Client, OtherSyncToolError, newMemory, releaseHolds, retryAt, tick } from "../../src/runner.js";
import type { Observation, VaultState } from "../../src/state.js";
import {
  TABLES,
  type VaultStore,
  closeVaultStore,
  initVault,
  insertIntent,
  isFencedOut,
  loadPendingIntents,
  loadVault,
  openVaultStore,
  pendingIntentIds,
  persist,
  takeLeadership,
} from "../../src/store.js";
import { deviceLocal, freshIdb } from "../fixtures.js";
import { NO_NET_FAULTS, type NetFaults, devBlobCrypto, memBackend } from "../support/backend.js";
import { fromModel, isBinaryModel, toModel } from "../support/bytes.js";
import { type MemFs, type OpName, memFs } from "../support/memfs.js";
import { testHasher } from "../support/shell.js";

// End-to-end runs of the real client shell: runner + Dexie (fake-indexeddb) + the in-memory disk +
// sync-core's server model. The scenarios are sync-core's (test-support/scenario); a crash closes
// the database and drops every in-memory thing, and a new instance loads what was persisted.

export interface E2EFaults extends NetFaults {
  /** Per tick: the client instance crashes or reloads (database closed and reopened). */
  reload: number;
  /** Per client file operation: a crash right before it (partial writes included). */
  fileCrash: number;
  /** Per client file operation: the user edits, moves, creates or deletes a file just before it. */
  user: number;
  /** Per tick: a remote writer commits (new object, edit, rename or delete). */
  remoteWrite: number;
  rotateEpoch: number;
  prune: number;
  expireRows: number;
  /**
   * Per client file operation: the plugin instance unloads right there (§20.2 plugin): its disk queue
   * closes, the operation in progress finishes, no other starts, and a new instance takes the lock and
   * increments leader_epoch. The old instance stays alive as a deposed leader.
   */
  handover: number;
  /** Per tick: the deposed leader (if any) runs one more tick; it must write nothing (fencing, closed queue). */
  staleTick: number;
  /** Per tick: a follower context sends an intent (§20.2) on the view it has. */
  followerEdit: number;
  /** Per tick and follower: it rescans its rows or re-reads the state; otherwise its view grows stale. */
  followerRefresh: number;
  /**
   * Share of user and remote writes whose content is an attachment's bytes (§2.1): random bytes with
   * invalid UTF-8, one of a few binaries shared by several files, or an empty file; written to binary
   * names or to a Markdown name (a `.md` that is not UTF-8). 0 keeps the random stream of older seeds.
   */
  binary: number;
  /** Faults and other actors stop at this tick; afterwards the system must converge. */
  activeUntil: number;
  /**
   * §35.13: when above 0, a SWITCH_TO_PRIVATE happens at a random step of the active phase, and from then
   * on the client runs a re-encryption pass after a tick with this chance (at every step once the active
   * phase is over, until it is done). Absent or 0: no switch, and the random stream of older seeds.
   */
  reencrypt?: number;
  /**
   * Per tick: the account's quota changes state (backend.ts `QuotaState`: free, full, or full with the
   * delete allowance spent; §11.1, §12.6, §40.1). Once the active phase is over it is free again and the
   * user presses "Sync now" once (§12.6: retried when there is space, never in an automatic loop). Absent
   * or 0: always free, and the random stream of older seeds.
   */
  quota?: number;
  /**
   * Per follower edit of an object the follower already edited: it edits "like the web editor" (apps/web
   * Editor.tsx, NOTES question 414), on the view it had loaded when it sent its previous intent for that
   * object, even after that intent was acked: its text is its own previous edit plus more typing. Absent
   * or 0: the random stream of older seeds.
   */
  editorView?: number;
  /**
   * §20.2 (NOTES question 419): per remote edit of an object whose file this disk holds in sync, another
   * tool (Obsidian Sync, iCloud...) carries the new content, and the rename as the projection places it,
   * to this disk before the client applies it. 40% of those edits empty the file (the exempt content).
   * Absent or 0: none, and the random stream of older seeds.
   */
  otherTool?: number;
  /**
   * Per remote edit of such an object (and not carried): the user here happens to make exactly the same
   * edit, empty content 40% of the time. Absent or 0: none, and the random stream of older seeds.
   */
  coincidence?: number;
  /**
   * §15 "el adaptador puede resolver el rename del temporal ... modificando el destino": per replace, the
   * adapter dies after the destination holds the new content and before the temporary is removed (the
   * replay then cancels). Absent or 0: replaces are atomic, and the random stream of older seeds.
   */
  rewritingReplace?: number;
}

export const QUIET: E2EFaults = {
  drop: 0,
  lose: 0,
  crash: 0,
  putTimeout: 0,
  reload: 0,
  fileCrash: 0,
  user: 0,
  remoteWrite: 0,
  rotateEpoch: 0,
  prune: 0,
  expireRows: 0,
  handover: 0,
  staleTick: 0,
  followerEdit: 0,
  followerRefresh: 0,
  binary: 0,
  activeUntil: 0,
};

/** The fault mix of the end-to-end property runs (e2e.property.test.ts). */
export const PROPERTY_FAULTS: E2EFaults = {
  drop: 0.05,
  lose: 0.05,
  crash: 0.3,
  putTimeout: 0.02,
  reload: 0.03,
  fileCrash: 0.05,
  user: 0.1,
  remoteWrite: 0.04,
  rotateEpoch: 0.01,
  prune: 0.01,
  expireRows: 0.01,
  handover: 0.01,
  staleTick: 0.3,
  followerEdit: 0.15,
  followerRefresh: 0.2,
  binary: 0,
  activeUntil: 100,
};

/**
 * PROPERTY_FAULTS with attachments: the fault mix of the end-to-end property runs. PROPERTY_FAULTS itself
 * keeps `binary: 0` so that the seeded regression runs (e2e.test.ts, question 75) replay unchanged.
 */
export const ATTACHMENT_FAULTS: E2EFaults = { ...PROPERTY_FAULTS, binary: 0.25 };

/**
 * ATTACHMENT_FAULTS with quota refusals (§12.6, §40.1), for their own properties: kept apart so that the
 * other properties keep the random stream (and the coverage) they were tuned with.
 */
export const QUOTA_FAULTS: E2EFaults = { ...ATTACHMENT_FAULTS, quota: 0.05 };

/** A generated end-to-end run: a scenario and the seed of its faults. */
export const e2eSpecArb = fc.record({ scenario: scenarioArb, seed: fc.integer() });

/** A follower's intent as the harness saw it being made: the oracle's independent record. */
export interface SentIntent {
  readonly intent: Intent;
  /** view_fp of the state the follower actually edited on (its own view, whatever it sent). */
  readonly seenFp: string | null;
}

export interface Run {
  readonly disk: MemFs;
  readonly server: ReturnType<typeof build>["world"]["server"];
  client: Client;
  readonly log: {
    crashes: number;
    reloads: number;
    userActions: number;
    replaceWindow: number;
    /** User contents lost in a window that the run's WindowRule allows (empty without a rule). */
    readonly windowLosses: Set<string>;
    readonly merges: string[];
    readonly mergedTexts: string[];
    readonly violations: string[];
    /** Latest content the user wrote per file identity (what must never be lost silently). */
    readonly userContents: Map<string, string>;
    /** Runner diagnostics by kind (import, adopt, merge, conflictCopy, cancel, reconcile, rejected:*...). */
    readonly events: Map<string, number>;
    handovers: number;
    staleTicks: number;
    /** Stale ticks stopped by fencing or by the closed queue. */
    staleStopped: number;
    /** (E5) Store changes made by a deposed leader. */
    readonly staleWrites: string[];
    /** Every intent sent by a follower, by id. */
    readonly sent: Map<string, SentIntent>;
    /** Outcomes per intent id, one per processing (the `intent` diagnostics). */
    readonly processed: Map<string, string[]>;
    /** (E7) Intents applied on a state their follower did not know. */
    readonly unknownStateApplies: string[];
    /** Contents of follower edits that must not be lost (by intent id), like `userContents`. */
    readonly intentContents: Map<string, string>;
    /** (E8) Every content an actor ever wrote: initial files and revisions, user, remote and follower writes. */
    readonly authored: Set<string>;
    /** Conflict copies of binary objects (a binary name, or bytes that are not UTF-8). */
    binaryCopies: number;
    /** §35.13: the step the switch happened at (null: none yet), and the passes run. */
    switchedAt: number | null;
    reencryptPasses: number;
    /** Crashes of the instance inside a pass (a lost response with a crash, §35.13 "Crash y reanudación"). */
    passCrashes: number;
    /** §35.13: revisions a pass swapped, over the run. */
    reencrypted: number;
    /** Violations of the §44.5 server invariants and of "no revision lost or duplicated", at the step they appeared. */
    readonly serverViolations: string[];
    /** §20.2 at run time (NOTES question 419): another tool's writes, coincidences, and the pauses they caused. */
    readonly otherTool: {
      /** Contents another tool or a coincidence put on this disk, per object. */
      readonly written: Map<ObjectId, Set<string>>;
      carried: number;
      carriedEmpty: number;
      carriedRenames: number;
      coincidences: number;
      coincidencesEmpty: number;
      /** Each pause: its content arrivals (object, content) and its run of renames. */
      readonly pauses: Array<{ readonly arrivals: ReadonlyArray<{ readonly objectId: ObjectId; readonly content: string }>; readonly renames: number }>;
      /** Contents the user wrote to this disk (a coincidence with a remote edit may pause, as §20.2 says). */
      readonly userWritten: Set<string>;
      /** Replaces that died between rewriting the destination and removing the temporary. */
      rewriteCrashes: number;
      /** Pauses nothing on this disk explains (a false positive), or on empty content. */
      readonly violations: string[];
    };
  };
  writeAheadViolations(): string[];
  /** Quota refusals and delete-only mutations committed over the quota (backend.ts). */
  quota(): { readonly refusals: number; readonly deletesOverQuota: number };
  /** The pending_intents rows as the current leader's store has them. */
  pendingIntents(): Promise<Intent[]>;
  close(): void;
}

/**
 * (E3) The content the follower's own chain left before an intent chained after `afterIntentId`: the
 * content of the latest CONTENT intent of the chain, looking through PATH intents (which keep the content
 * they were sent on); null after a DELETE; undefined if the chain has no content change (then only the
 * content the follower saw counts). Older contents of the chain are not the chain's result.
 */
export function chainedContent(sent: ReadonlyMap<string, SentIntent>, afterIntentId: string | null): string | null | undefined {
  for (let id = afterIntentId; id !== null; ) {
    const s = sent.get(id);
    if (s === undefined) return undefined;
    const change = s.intent.change;
    if (change.kind === "CONTENT") return toModel(change.content);
    if (change.kind === "DELETE") return null;
    id = s.intent.afterIntentId;
  }
  return undefined;
}

function mulberry(seed: number): () => number {
  let s = seed | 0;
  return () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const CLIENT_OPS: ReadonlySet<OpName> = new Set(["write", "replace", "rename", "remove", "mkdir", "rmdir"]);
/** Operations the user can race with: the client's effects and its re-checks (never listings). */
const USER_RACE_OPS: ReadonlySet<OpName> = new Set(["stat", "write", "replace", "rename", "remove", "mkdir"]);
/** The user keeps the vault small, so a run stays fast. */
const MAX_USER_FILES = 24;
const USER_PATHS = ["n.md", "moved.md", "d/new.md", "N.md", "user.md", "sub/u.md"];
/** Where attachments land: binary names, plus Markdown names that then hold bytes that are not UTF-8. */
const BINARY_PATHS = ["img.png", "d/doc.pdf", "sub/clip.bin", "bad.md", ...USER_PATHS];
/** Binaries shared by several files (identical content): a PNG header, and bytes that are not UTF-8. */
const SHARED_BINARIES = [Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d]), Uint8Array.from([0xff, 0xfe, 0, 0x80, 0xc3, 0x28])].map(toModel);

/** Deliberately broken adapters, to prove each oracle can fail. */
export interface Broken {
  /** §20.2: the client forgets which content its own journal wrote (no explained writes). */
  readonly forgetsOwnWrites?: boolean;
  /** Every content hashes the same (a broken LocalCompareHasher). */
  readonly constantHash?: boolean;
  /** The backend never delivers events (the client never learns remote changes). */
  readonly noEvents?: boolean;
  /** The disk silently stores only the first characters of every client write. */
  readonly truncatingWrites?: boolean;
  /** The adapter reads through a string (TextDecoder, then TextEncoder): invalid UTF-8 comes back changed. */
  readonly lossyText?: boolean;
  /** A deposed leader adopts the leader_epoch it reads instead of the one it took (so fencing passes). */
  readonly staleAdoptsEpoch?: boolean;
  /** A follower re-sends (re-inserts) an intent whose row is gone, instead of taking it as processed. */
  readonly followerResends?: boolean;
  /** A follower sends the state as it is at sending time instead of the state it edited on. */
  readonly followerFreshView?: boolean;
  /**
   * The disk's coarse clock mtime is declared a `counter` marker: the observation cache then trusts equal
   * (size, mtime) alone, the naive cache that loses an edit made within one mtime granule (question 146).
   */
  readonly naiveStatCache?: boolean;
  /** §35.13: the adapter answers every reencryptRevision "ok" without sending it (the old blobs stay). */
  readonly reencryptLies?: boolean;
  /** §35.13: the adapter opens the listed manifests wrongly (another path): the new manifest misplaces the file. */
  readonly reencryptWrongPath?: boolean;
  /** The server model's broken variants (sync-core server.ts), e.g. `brokenReencryptKeepsOld`. */
  readonly server?: Partial<ServerConfig>;
  /** §12.6: after a QUOTA_EXCEEDED the client holds deletes with everything else (the gap of control-plane question 369). */
  readonly quotaHoldsDeletes?: boolean;
}

/**
 * The disk's modification marker (memfs MemMtime, NOTES question 146): "none" (no observation cache; the
 * seeded runs of e2e.test.ts keep their random stream, since every `stat` is a point of user activity),
 * "counter", or "coarse": a clock mtime with COARSE_MTIME_MS granularity over the run's clock, where
 * two consecutive ticks share a granule and a same-size edit keeps size and mtime equal.
 */
export type DiskMtime = "none" | "counter" | "coarse";
/** The run's wall clock advances TICK_MS per tick. */
const TICK_MS = 1000;
const COARSE_MTIME_MS = 2000;

/**
 * A write or remove of the client that met content it did not read last at that path: the user wrote
 * after the client's final re-read. The oracles count it as a violation unless a WindowRule allows it.
 */
export interface WindowEvent {
  readonly kind: "replace-destroyed" | "replace-placed" | "remove-destroyed";
  readonly path: string;
  /** The journaled action being executed ("applyRemote", "resolve", "movePhysical", ...), or null. */
  readonly action: string | null;
}

/** Decides which window events the spec allows. None by default: every such event is a violation. */
export type WindowRule = (e: WindowEvent) => boolean;

export async function startRun(
  scenario: Scenario,
  faults: E2EFaults,
  seed: number,
  broken: Broken = {},
  allowWindow: WindowRule = () => false,
  mtime: DiskMtime = "none",
): Promise<Run> {
  const { world: w } = build(scenario, undefined, seed, DEFAULT_SERVER);
  if (broken.server !== undefined) (w.server as { config: ServerConfig }).config = { ...w.server.config, ...broken.server };
  // §35.13 lists revisions by the epoch of their blobs: the seeded ones get theirs (no random draw).
  const reencrypting = (faults.reencrypt ?? 0) > 0;
  if (reencrypting) attachBlobs(w.server);
  const random = mulberry(seed ^ 0x5eed);
  const chance = (p: number) => p > 0 && step < faults.activeUntil && random() < p;
  let step = 0;
  const wallClock = () => w.server.now * TICK_MS;
  const disk = memFs(mtime === "coarse" ? { granularityMs: COARSE_MTIME_MS, clock: wallClock } : mtime);
  if (broken.naiveStatCache) (disk.fs as { changeMarker?: unknown }).changeMarker = { kind: "counter" };
  const fidToId = new Map<number, number>();
  for (const [path, f] of w.files) {
    const parts = path.split("/");
    for (let i = 1; i < parts.length; i++) disk.folders.add(parts.slice(0, i).join("/"));
    const file = disk.newFile(f.content, f.origin);
    fidToId.set(f.fid, file.id);
    disk.files.set(path, file);
  }
  const idb = freshIdb();
  const dlc = await deviceLocal();
  const open = () => openVaultStore({ installNs: "plugin:e2e", vaultId: "vault", ...idb });
  let store: VaultStore = await open();
  await initVault(store, { vaultId: w.facts.vaultId, replicaId: w.replica, epochId: w.facts.epochId });
  const epoch = await takeLeadership(store);
  const observations = new Map<ObjectId, Observation>();
  for (const [id, r] of w.recorded) {
    observations.set(id, r.physicalPath === null ? { kind: "ABSENT", logicalPath: r.logicalPath } : { kind: "PRESENT", logicalPath: r.logicalPath, physicalPath: r.physicalPath, hash: r.hash ?? null });
  }
  for (const id of w.notMaterialized) observations.set(id, { kind: "NOT_MATERIALIZED" });
  const hashes = new Map<string, string>();
  for (const revisionId of w.known) {
    const r = w.server.revisions.get(revisionId);
    if (r && !r.deleted) hashes.set(revisionId, `h:${r.content}`);
  }
  const initial: VaultState = { ...(await loadVault(store, dlc)), leaderEpoch: epoch, facts: w.facts, observations, hashes };
  await persist(store, dlc, await loadVault(store, dlc), initial);

  const crypto = devBlobCrypto();
  let hexes = 0;
  let ids = 0;
  const log: Run["log"] = {
    crashes: 0,
    reloads: 0,
    userActions: 0,
    replaceWindow: 0,
    windowLosses: new Set(),
    merges: [],
    mergedTexts: [],
    violations: [],
    userContents: new Map(),
    events: new Map(),
    handovers: 0,
    staleTicks: 0,
    staleStopped: 0,
    staleWrites: [],
    sent: new Map(),
    processed: new Map(),
    unknownStateApplies: [],
    intentContents: new Map(),
    authored: new Set([...w.files.values()].map((f) => f.content)),
    binaryCopies: 0,
    switchedAt: null,
    reencryptPasses: 0,
    passCrashes: 0,
    reencrypted: 0,
    serverViolations: [],
    otherTool: { written: new Map(), carried: 0, carriedEmpty: 0, carriedRenames: 0, coincidences: 0, coincidencesEmpty: 0, pauses: [], userWritten: new Set(), rewriteCrashes: 0, violations: [] },
  };
  for (const r of w.server.revisions.values()) if (!r.deleted) log.authored.add(r.content);
  /** A content some actor writes now: text, or (when `binary`) an attachment's bytes. */
  const author = (text: string, binary: boolean): string => {
    let content = text;
    if (binary) {
      const r = random();
      if (r < 0.15) content = "";
      else if (r < 0.45) content = SHARED_BINARIES[Math.floor(random() * SHARED_BINARIES.length)]!;
      else {
        // Unique (it embeds the text) and never UTF-8 (0xff); a NUL and a truncated sequence too.
        const noise = Array.from({ length: Math.floor(random() * 40) }, () => Math.floor(random() * 256));
        content = toModel(Uint8Array.from([0xff, 0, ...new TextEncoder().encode(text), 0xc3, ...noise]));
      }
    }
    log.authored.add(content);
    return content;
  };
  for (const f of disk.files.values()) if (f.origin === "user") log.userContents.set(String(f.id), f.content);
  // The initial local edits are the user's (the builder marks them touched).
  for (const [path, f] of w.files) if (f.touched) log.userContents.set(String(disk.files.get(path)!.id), f.content);

  const persistedBlobIds = async () => {
    const rows = (await store.db.table("attempts").toArray()) as Array<{ blobs: Array<{ blobId: string }> }>;
    return new Set(rows.flatMap((a) => a.blobs.map((b) => b.blobId)));
  };
  if (broken.lossyText) {
    const read = disk.fs.read;
    (disk.fs as { read: typeof read }).read = async (p) => new TextEncoder().encode(new TextDecoder().decode(await read(p)));
  }
  if (broken.truncatingWrites) {
    const write = disk.fs.write;
    (disk.fs as { write: typeof write }).write = (p, data) => write(p, data.slice(0, 2));
  }
  if ((faults.rewritingReplace ?? 0) > 0) {
    // The destination ends with the new content and the temporary is still there: what a rewriting adapter
    // leaves when it dies between its two steps (modelled after the atomic replace, whose oracles run).
    const replace = disk.fs.replace;
    (disk.fs as { replace: typeof replace }).replace = async (tmp, dest) => {
      const content = disk.files.get(tmp)?.content;
      await replace(tmp, dest);
      if (content !== undefined && chance(faults.rewritingReplace ?? 0)) {
        disk.files.set(tmp, disk.newFile(content, "client"));
        log.otherTool.rewriteCrashes++;
        disk.crash(`between rewriting ${dest} and removing ${tmp}`);
      }
    };
  }
  const net = memBackend(w.server, w.replica, crypto, random, persistedBlobIds, (where) => disk.crash(where));
  if (broken.reencryptLies) (net.backend as { reencryptRevision: typeof net.backend.reencryptRevision }).reencryptRevision = async () => ({ ok: true });
  if (broken.reencryptWrongPath) {
    const list = net.backend.listRevisionsToReencrypt;
    (net.backend as { listRevisionsToReencrypt: typeof list }).listRevisionsToReencrypt = async (after, limit) => {
      const page = await list(after, limit);
      return page.kind === "PAGE" ? { ...page, revisions: page.revisions.map((t) => ({ ...t, manifest: { ...t.manifest, path: `x-${t.manifest.path}` } })) } : page;
    };
  }
  // §35.13: the step of the switch, drawn only in re-encrypting runs.
  const switchAt = reencrypting ? Math.floor(random() * Math.max(1, faults.activeUntil)) : null;
  /** §44.5 on the server rows, and every revision ever seen still there, unchanged, once. */
  const ledger = new Map<string, string>();
  const revisionsSeen = new Map<string, string>();
  const checkServer = () => {
    for (const v of modelInvariants(w.server, ledger)) log.serverViolations.push(`step ${step}: ${v}`);
    const bySequence = new Map<number, string>();
    for (const r of w.server.revisions.values()) {
      const seen = JSON.stringify([r.objectId, r.sequence, r.path, r.content, r.deleted]);
      const before = revisionsSeen.get(r.revisionId);
      if (before !== undefined && before !== seen) log.serverViolations.push(`step ${step}: revision ${r.revisionId} changed from ${before} to ${seen}`);
      revisionsSeen.set(r.revisionId, seen);
      const other = bySequence.get(r.sequence);
      if (other !== undefined) log.serverViolations.push(`step ${step}: revisions ${other} and ${r.revisionId} share sequence ${r.sequence}`);
      bySequence.set(r.sequence, r.revisionId);
    }
    for (const id of revisionsSeen.keys()) if (!w.server.revisions.has(id)) log.serverViolations.push(`step ${step}: revision ${id} lost`);
  };
  disk.onCrash = () => closeVaultStore(store);
  net.faults = faults;
  if (broken.noEvents) {
    (net.backend as { listEvents: typeof net.backend.listEvents }).listEvents = async () => ({ kind: "PAGE", events: [] });
  }

  let queue: DiskQueue = diskQueue(disk.fs);
  let unloading = false;
  const makeClient = (state: VaultState, identities: Map<ObjectId, string>, scanned: boolean): Client => {
    queue = diskQueue(disk.fs);
    unloading = false;
    const shell: Shell = {
      fs: queue.fs,
      hasher: broken.constantHash ? { hash: async () => "h:same" } : testHasher,
      dlc,
      store,
      state,
      identities,
      createdFolders: new Set(),
      hex8: () => (++hexes * 2654435761 >>> 0).toString(16).padStart(8, "0").slice(-8),
      newId: (prefix) => `0190a1b2-${prefix}${(++ids).toString(36)}`,
      log: (e) => onEvent(e),
    };
    const memory = newMemory();
    memory.scanned = scanned;
    return {
      shell,
      backend: net.backend,
      blobs: crypto,
      now: () => w.server.now,
      wallClock,
      pendingBudgetBytes: w.server.config.pendingBudgetBytes,
      // The local rule 8 check changes which backend calls happen (a random draw each): not in the seeded "none" runs.
      ...(mtime === "none" ? {} : { maxBlobBytes: w.server.config.maxBlobBytes }),
      memory,
      log: (e) => onEvent(e),
      // §20.2 at run time: on in every run (the plugin's setting); the harness plays the user's "resume".
      otherSyncTool: { acknowledged: [] },
    };
  };
  // (E7) What last changed each object's local state: an intent id, or "" (any other cause).
  const changedBy = new Map<ObjectId, string>();
  const changedBefore = new Map<ObjectId, string>();
  const onEvent = (e: { readonly kind: string; readonly objectId?: ObjectId; readonly detail?: string }) => {
    log.events.set(e.kind, (log.events.get(e.kind) ?? 0) + 1);
    if (e.kind === "action") currentAction = e.detail ?? null;
    if (e.kind === "merge") log.merges.push(e.detail ?? "");
    if (e.kind === "merged") log.mergedTexts.push(e.detail ?? "");
    if (e.kind === "conflictCopy" && e.objectId !== undefined) {
      const head = w.server.heads.get(e.objectId);
      if (head !== undefined && (isBinaryModel(head.content) || !isMergeablePath(head.path))) log.binaryCopies++;
    }
    if (e.kind === "local-change" && e.objectId !== undefined) {
      changedBefore.set(e.objectId, changedBy.get(e.objectId) ?? "");
      changedBy.set(e.objectId, e.detail ?? "");
    }
    if (e.kind === "intent" && e.objectId !== undefined) {
      const { intentId, outcome, priorFp } = JSON.parse(e.detail!) as { intentId: string; outcome: string; priorFp: string | null };
      log.processed.set(intentId, [...(log.processed.get(intentId) ?? []), outcome]);
      const sent = log.sent.get(intentId);
      if (outcome !== "APPLY" || sent === undefined) return;
      // Oracle (§20.2 Fase 0, "aplicada sobre un estado que no conocía"): an intent is applied on the
      // state its follower saw, or on the result of its own previous intent (the chain).
      const by = changedBy.get(e.objectId) === intentId ? changedBefore.get(e.objectId) : changedBy.get(e.objectId);
      const known = (priorFp !== null && priorFp === sent.seenFp) || (sent.intent.afterIntentId !== null && by === sent.intent.afterIntentId);
      if (!known) log.unknownStateApplies.push(`${intentId} on ${e.objectId}: saw ${sent.seenFp}, applied on ${priorFp} (last changed by ${by || "other"})`);
      // The content it replaced (or deleted) was superseded knowingly by the user: no longer owed.
      const prior = contentOfFp(priorFp);
      if (known && prior !== null && sent.intent.change.kind !== "PATH") supersede(prior);
    }
  };
  /** The content behind a view_fp of the test hasher (`h:<content>`), or null. */
  const contentOfFp = (fp: string | null): string | null => {
    if (fp === null || !fp.startsWith("[")) return null;
    const [, deleted, hash] = JSON.parse(fp) as [string, boolean, string | null];
    return !deleted && hash !== null && hash.startsWith("h:") ? hash.slice(2) : null;
  };
  /** A content the user replaced or discarded on purpose is no longer owed (E2). */
  const supersede = (content: string) => {
    for (const [k, c] of log.userContents) if (c === content) log.userContents.delete(k);
    for (const [k, c] of log.intentContents) if (c === content) log.intentContents.delete(k);
  };
  const identities = new Map<ObjectId, string>();
  for (const [o, fid] of w.identity) if (fidToId.has(fid)) identities.set(o, String(fidToId.get(fid)));

  // Faults and user activity at every file operation of the client.
  const lastRead = new Map<string, string>();
  let currentAction: string | null = null;
  /** Content the client met in a window: exempt if the rule allows it (and then not a lost edit), else a violation. */
  const windowEvent = (kind: WindowEvent["kind"], path: string, content: string) => {
    if (allowWindow({ kind, path, action: currentAction })) {
      log.replaceWindow++;
      if (kind !== "replace-placed") log.windowLosses.add(content);
    } else log.violations.push(`${kind} of content the client did not read last at ${path} (during ${currentAction ?? "no action"})`);
  };
  disk.beforeOp = (op, path) => {
    if (op === "read") return;
    if (CLIENT_OPS.has(op) && !unloading && chance(faults.handover)) {
      // onunload right now: this operation is in progress and finishes; the queue starts no other.
      unloading = true;
      void queue.close();
    }
    if (CLIENT_OPS.has(op) && chance(faults.fileCrash)) {
      if (op === "write" && random() < 0.5) disk.partialWrite = Math.floor(random() * 4);
      else disk.crash(`${op} ${path}`);
    }
    if (USER_RACE_OPS.has(op) && disk.files.size < MAX_USER_FILES && chance(faults.user)) userAction(random() < 0.5 ? path : null);
    // Oracle (§44.5 "nunca borra del disco bytes que no pueda demostrar suyos"): a remove destroys only
    // content the client read last at that path.
    const f = op === "remove" ? disk.files.get(path) : undefined;
    if (f && lastRead.get(path) !== f.content) windowEvent("remove-destroyed", path, f.content);
  };
  /** A user action, half of the time on the very path the client is about to touch (concurrent writes). */
  const userAction = (target: string | null) => {
    log.userActions++;
    if (target !== null && target !== "" && !isTmpName(target)) {
      const f = disk.files.get(target);
      const content = author(`user at ${step}-${log.userActions}`, chance(faults.binary));
      log.otherTool.userWritten.add(content);
      if (f) {
        supersede(f.content);
        f.content = content;
      }
      else if (disk.folders.has(target)) disk.userWrite(`${target}/inside-${log.userActions}.md`, content);
      else if (![...disk.files.keys()].some((k) => target.startsWith(`${k}/`))) disk.userWrite(target, content);
      else return;
      const written = disk.files.get(target) ?? disk.files.get(`${target}/inside-${log.userActions}.md`)!;
      log.userContents.set(String(written.id), content);
      return;
    }
    const files = [...disk.files.keys()].filter((p) => !isTmpName(p)).sort();
    const tmps = [...disk.files.keys()].filter(isTmpName).sort();
    if (tmps.length > 0 && random() < 0.15) {
      // §44.1: the user edits a nodra-tmp-* file.
      const f = disk.files.get(tmps[Math.floor(random() * tmps.length)]!)!;
      // Like every user edit of a file, it supersedes what that file held (userContents does the same by
      // file id; intent contents are keyed by intent, so they are superseded by content).
      for (const [k, c] of log.intentContents) if (c === f.content) log.intentContents.delete(k);
      f.content = `${f.content}
user line ${step}`;
      log.authored.add(f.content);
      log.otherTool.userWritten.add(f.content);
      log.userContents.set(String(f.id), f.content);
      return;
    }
    const r = random();
    if (r < 0.4 && files.length > 0) {
      const p = files[Math.floor(random() * files.length)]!;
      const content = author(`user edit ${step}-${log.userActions}`, chance(faults.binary));
      log.otherTool.userWritten.add(content);
      supersede(disk.files.get(p)!.content);
      disk.files.get(p)!.content = content;
      log.userContents.set(String(disk.files.get(p)!.id), content);
    } else if (r < 0.6 && files.length > 0) {
      const p = files[Math.floor(random() * files.length)]!;
      const to = USER_PATHS[Math.floor(random() * USER_PATHS.length)]!;
      if (disk.files.has(to) || disk.folders.has(to) || [...disk.files.keys()].some((k) => k.startsWith(`${to}/`) || to.startsWith(`${k}/`))) return;
      const f = disk.files.get(p)!;
      disk.files.delete(p);
      disk.userWrite(to, f.content); // the folders of `to`
      // The same identity at the new path, as a write there (a spread would freeze the modification marker).
      disk.files.set(to, disk.newFile(f.content, "user", f.id));
    } else if (r < 0.85) {
      const binary = chance(faults.binary);
      const paths = binary ? BINARY_PATHS : USER_PATHS;
      const to = paths[Math.floor(random() * paths.length)]!;
      if (disk.files.has(to) || disk.folders.has(to) || [...disk.files.keys()].some((k) => k.startsWith(`${to}/`) || to.startsWith(`${k}/`))) return;
      const content = author(`created ${step}-${log.userActions}`, binary);
      log.otherTool.userWritten.add(content);
      disk.userWrite(to, content);
      log.userContents.set(String(disk.files.get(to)!.id), content);
    } else if (files.length > 0) {
      const p = files[Math.floor(random() * files.length)]!;
      // The user discards this content on purpose.
      log.userContents.delete(String(disk.files.get(p)!.id));
      supersede(disk.files.get(p)!.content);
      disk.files.delete(p);
    }
  };
  // Oracle (no overwrite): a replace destroys only content confirmed on the server or carried by a
  // merge; content the client did not read last at the destination is a window event.
  const originalRead = disk.fs.read;
  (disk.fs as { read: typeof disk.fs.read }).read = async (p) => {
    const c = await originalRead(p);
    lastRead.set(p, toModel(c));
    return c;
  };
  disk.afterOp = (op) => {
    if (op !== "replace") return;
    const last = disk.replaced[disk.replaced.length - 1]!;
    // Oracle (no truncated destination): what lands is a whole content (a revision, or a merge result).
    const placed = disk.files.get(last.dest)!.content;
    const intentId = currentAction?.startsWith("intent:") ? currentAction.split(":")[2]! : null;
    const sent = intentId !== null ? log.sent.get(intentId) : undefined;
    // A follower's edit is a whole content too (it is what the user typed in that context).
    const whole = [...w.server.revisions.values()].some((r) => r.content === placed) || log.mergedTexts.includes(placed) || (sent?.intent.change.content != null && toModel(sent.intent.change.content) === placed);
    if (lastRead.get(last.tmp) !== placed) windowEvent("replace-placed", last.dest, placed); // the user wrote our temporary after its re-check
    else if (!whole) log.violations.push(`truncated or unknown content placed at ${last.dest}`);
    if (last.destroyed === null) return;
    const confirmed = [...w.server.revisions.values()].some((r) => !r.deleted && r.content === last.destroyed);
    const merged = log.merges.includes(last.destroyed);
    if (lastRead.get(last.dest) !== last.destroyed) windowEvent("replace-destroyed", last.dest, last.destroyed);
    else if (sent !== undefined) {
      // An intent's replace is a local edit, not a remote apply (§44.5 speaks of remote events). It is
      // held to a narrower rule: it may only replace the content its follower saw, or the result of the
      // follower's own previous intent (the chain). Confirmation does not excuse anything else.
      const chained = chainedContent(log.sent, sent.intent.afterIntentId);
      if (contentOfFp(sent.seenFp) !== last.destroyed && chained !== last.destroyed) log.violations.push(`intent ${intentId} replaced content its follower never saw at ${last.dest}`);
    } else if (!confirmed && !merged) log.violations.push(`replace destroyed unconfirmed content at ${last.dest}`);
  };

  const run: Run = {
    disk,
    server: w.server,
    client: makeClient(initial, identities, true),
    log,
    writeAheadViolations: () => net.writeAheadViolations,
    quota: () => net.quotaLog,
    pendingIntents: () => loadPendingIntents(store, dlc),
    close: () => {
      closeVaultStore(store);
      if (stale) closeVaultStore(stale.store);
      for (const t of followers) closeVaultStore(t.store);
    },
  };
  const restart = async () => {
    closeVaultStore(store);
    disk.revive();
    store = await open();
    const e = await takeLeadership(store);
    run.client = makeClient({ ...(await loadVault(store, dlc)), leaderEpoch: e }, new Map(), false);
  };
  /** §20.2 plugin relay: the unloading instance's queue is closed; a new instance takes the lock. */
  let stale: { client: Client; store: VaultStore } | null = null;
  const handover = async () => {
    await queue.close();
    log.handovers++;
    if (stale) closeVaultStore(stale.store);
    stale = { client: run.client, store };
    store = await open(); // a new instance with its own connection; the old one stays open
    const e = await takeLeadership(store); // its FIRST transaction
    run.client = makeClient({ ...(await loadVault(store, dlc)), leaderEpoch: e }, new Map(), false);
  };
  const rawStore = async () => JSON.stringify(await Promise.all(TABLES.map((t) => store.db.table(t).toArray())));
  /** (E5) The deposed leader runs one more tick: whatever it tries, the store must not change. */
  const staleTick = async () => {
    if (stale === null) return;
    log.staleTicks++;
    const before = await rawStore();
    if (broken.staleAdoptsEpoch) {
      const meta = (await store.db.table("meta").get("meta")) as { leaderEpoch: number };
      stale.client.shell.state = { ...stale.client.shell.state, leaderEpoch: meta.leaderEpoch };
    }
    const saved = net.faults;
    net.faults = NO_NET_FAULTS; // a lost-response crash here would kill the current instance: not what this models
    try {
      await tick(stale.client);
    } catch (e) {
      if (e instanceof OtherSyncToolError) return; // a deposed leader's pause stops only itself
      if (!isFencedOut(e) && !isQueueClosed(e)) throw e;
      log.staleStopped++;
    } finally {
      net.faults = saved;
    }
    if ((await rawStore()) !== before) log.staleWrites.push(`step ${step}: a deposed leader changed the store`);
  };

  // Followers (§20.2): other contexts of the installation, each with its own database connection.
  type ViewEntry = { readonly version: number; readonly fp: string | null };
  const FOLLOWER_PATHS = ["f.md", "g/f.md", "n.md", "F.md", "moved.md"];
  let intents = 0;
  let contexts = 0;
  const followers: Array<{ f: Follower; store: VaultStore; loaded: Map<ObjectId, ViewEntry> }> = [];
  const newTab = async () => {
    const t = { f: newFollower(`ctx-${++contexts}`), store: await open(), loaded: new Map<ObjectId, ViewEntry>() };
    await refreshView(t.store, t.f);
    return t;
  };
  for (let i = 0; i < 2; i++) followers.push(await newTab());
  const followerStep = async () => {
    for (let k = 0; k < followers.length; k++) {
      const t = followers[k]!;
      if (!chance(faults.followerRefresh)) continue;
      const r = random();
      if (r < 0.05) {
        // A reload: a new context; the old one's rows stay in pending_intents.
        closeVaultStore(t.store);
        followers[k] = await newTab();
      } else if (r < 0.5) {
        if (broken.followerResends) {
          const pending = await pendingIntentIds(t.store, t.f.contextId);
          for (const id of t.f.sent.keys()) if (!pending.has(id)) await insertIntent(t.store, dlc, log.sent.get(id)!.intent).catch(() => undefined);
        }
        await followerRescan(t.store, t.f, null);
      } else await refreshView(t.store, t.f);
    }
    if (!chance(faults.followerEdit)) return;
    const t = followers[Math.floor(random() * followers.length)]!;
    const liveFp = (fp: string | null) => fp !== null && fp.startsWith("[") && !(JSON.parse(fp) as [string, boolean])[1];
    const live = [...t.f.view].filter(([, v]) => liveFp(v.fp)).map(([id]) => id).sort();
    const r = random();
    const n = ++intents;
    const text = `follower ${t.f.contextId} ${step}-${n}`;
    const path = FOLLOWER_PATHS[Math.floor(random() * FOLLOWER_PATHS.length)]!;
    let objectId: ObjectId;
    let change: IntentChange;
    let view: View = t.f.view;
    if (live.length === 0 || r < 0.15) {
      objectId = `0190a1b2-fnew-${n}`;
      change = { kind: "CONTENT", path, content: fromModel(text) };
    } else {
      objectId = live[Math.floor(random() * live.length)]!;
      // Like the web editor (Q414): the view it loaded for its previous intent on the object, kept.
      const kept = t.loaded.get(objectId);
      if (kept !== undefined && chance(faults.editorView ?? 0)) {
        view = new Map(t.f.view).set(objectId, kept);
        log.events.set("editorView", (log.events.get("editorView") ?? 0) + 1);
      }
      const [seenPath] = JSON.parse(view.get(objectId)!.fp!) as [string];
      change = r < 0.75 ? { kind: "CONTENT", path: seenPath, content: fromModel(text) } : r < 0.9 ? { kind: "PATH", path, content: null } : { kind: "DELETE", path: seenPath, content: null };
    }
    const seenFp = view.get(objectId)?.fp ?? "absent";
    const edited = view.get(objectId);
    if (edited !== undefined && liveFp(edited.fp)) t.loaded.set(objectId, edited);
    if (broken.followerFreshView) {
      const fresh = newFollower("fresh");
      await refreshView(t.store, fresh);
      view = fresh.view;
    }
    const intent = await submitIntent(t.store, dlc, null, t.f, { intentId: `0190a1b2-intent-${n}`, objectId, change }, view);
    log.sent.set(intent.intentId, { intent, seenFp });
    if (change.kind === "CONTENT") {
      log.intentContents.set(intent.intentId, text);
      log.authored.add(text);
    }
    // The channel hint reaches the leader, unless the message is lost (then its rescan finds the row).
    if (random() < 0.7) run.client.memory.intentHint = true;
  };

  (run as Run & { step: (i: number) => Promise<boolean> }).step = async (i: number) => {
    step = i;
    net.faults = i < faults.activeUntil ? faults : NO_NET_FAULTS;
    if (chance(faults.reload)) {
      log.reloads++;
      await restart();
    }
    if (chance(faults.remoteWrite)) remoteWrite();
    if (chance(faults.rotateEpoch)) rotateEpoch(w.server);
    if (chance(faults.expireRows)) expireMutationRows(w.server);
    if (chance(faults.prune)) prune(w.server);
    if (chance(faults.quota ?? 0)) {
      const r = random();
      net.quota = r < 0.4 ? "free" : r < 0.8 ? "full" : "spent";
      net.quotaLog.contentRefused = false;
    }
    if (i === faults.activeUntil && (faults.quota ?? 0) > 0) {
      // Space again, and the user says so ("Sync now"): what waited for it goes once.
      net.quota = "free";
      releaseHolds(run.client, "user");
    }
    if (disk.dead) {
      // The instance died in a call whose error the runner swallowed (a lost response): restart first,
      // before anything else touches the closed database.
      log.crashes++;
      await restart();
    }
    await followerStep();
    if (chance(faults.staleTick)) await staleTick();
    let busy = true;
    if (broken.forgetsOwnWrites) {
      const st = run.client.shell.state;
      run.client.shell.state = { ...st, otherSync: { ...st.otherSync, explainedWrites: new Map() } };
    }
    try {
      busy = await tick(run.client);
      const quotaHold = run.client.memory.holds.nonDeletes;
      if (broken.quotaHoldsDeletes && quotaHold !== null) run.client.memory.holds.writes = { ...quotaHold, scope: "writes" };
    } catch (e) {
      if (e instanceof OtherSyncToolError) otherToolPause(e);
      else if (disk.dead) {
        log.crashes++;
        disk.partialWrite = null;
        await restart();
      } else if (!(unloading && isQueueClosed(e))) throw e;
    }
    if (unloading && !disk.dead) await handover();
    let reencryptLeft = false;
    if (switchAt !== null) {
      if (log.switchedAt === null && i >= switchAt) {
        switchToPrivate(w.server);
        log.switchedAt = i;
      }
      if (log.switchedAt !== null && !disk.dead && (i >= faults.activeUntil || chance(faults.reencrypt ?? 0))) {
        log.reencryptPasses++;
        const r = await reencryptPass(run.client);
        log.reencrypted += r.swapped;
        if (disk.dead) {
          log.crashes++;
          log.passCrashes++;
          disk.partialWrite = null;
          await restart();
        }
      }
      const f = run.client.shell.state.facts;
      const listed = log.switchedAt === null ? { kind: "PAGE", revisions: [] } : listToReencrypt(w.server, null, 1);
      reencryptLeft = (listed.kind === "PAGE" && listed.revisions.length > 0) || f.attempts.some((a) => a.reencrypt !== undefined) || f.cleanup.length > 0;
      checkServer();
    }
    w.server.now++;
    // Rows left in pending_intents are work: the leader sweeps them within INTENT_RESCAN.
    // A client waiting for a retry (retry.ts) is not at rest: its hold ends as the clock advances.
    return busy || reencryptLeft || retryAt(run.client) !== null || i < faults.activeUntil || (await loadPendingIntents(store, dlc)).length > 0;
  };
  /**
   * §20.2: sync paused for another tool. Oracle: every content arrival is a content another tool (or a
   * coincidence) put on this disk for that object, never an empty one; a run of renames needs renames it
   * carried. Then the user resumes: "I removed the other tool" accepts exactly the arrivals shown, and a
   * new leadership starts the run of renames again from 0.
   */
  const otherToolPause = (e: OtherSyncToolError) => {
    const t = log.otherTool;
    const arrivals = e.arrivals.map((a) => ({ objectId: a.objectId, content: w.server.revisions.get(a.revisionId)?.content ?? "?" }));
    t.pauses.push({ arrivals, renames: e.renames });
    for (const a of arrivals) {
      if (a.content === "") t.violations.push(`step ${step}: paused on empty content of ${a.objectId}`);
      if (!t.written.get(a.objectId)?.has(a.content) && !t.userWritten.has(a.content)) t.violations.push(`step ${step}: paused on ${a.objectId} ${JSON.stringify(a.content)}, which nothing but this replica put on its disk`);
    }
    if (arrivals.length === 0 && t.carriedRenames === 0) t.violations.push(`step ${step}: paused after ${e.renames} renames, none carried by another tool`);
    run.client.otherSyncTool!.acknowledged.push(...e.arrivals.map(({ objectId, revisionId }) => ({ objectId, revisionId })));
    run.client.memory.projectionRenameArrivals = 0;
  };
  /** The file of `objectId` on this disk, if it holds exactly `content` (in sync with that head). */
  const fileInSync = (objectId: ObjectId, content: string): string | null => {
    const o = run.client.shell.state.observations.get(objectId);
    if (o?.kind !== "PRESENT") return null;
    return disk.files.get(o.physicalPath)?.content === content ? o.physicalPath : null;
  };
  /** Another tool (or a coincidence) puts a remote edit on this disk before the client applies it. */
  const carry = (target: { readonly objectId: ObjectId; readonly content: string }, from: string, how: "tool" | "coincidence") => {
    const head = w.server.heads.get(target.objectId)!;
    const t = log.otherTool;
    const f = disk.files.get(from)!;
    if (head.content !== target.content) {
      f.content = head.content;
      t.written.set(target.objectId, (t.written.get(target.objectId) ?? new Set()).add(head.content));
      if (how === "tool") [t.carried, t.carriedEmpty] = [t.carried + 1, t.carriedEmpty + (head.content === "" ? 1 : 0)];
      else [t.coincidences, t.coincidencesEmpty] = [t.coincidences + 1, t.coincidencesEmpty + (head.content === "" ? 1 : 0)];
    }
    if (how !== "tool") return;
    // The rename as the other device's projection placed it (§16.7), when that path is free here.
    const heads = [...w.server.heads.values()].filter((h) => !h.deleted);
    const layout = project({ objects: heads.map((h) => ({ objectId: h.objectId, logicalPath: h.path, createdSequence: h.createdSequence })), untrackedFiles: [] });
    const to = layout.files.get(target.objectId)?.physicalPath;
    if (to === undefined || to === from || to.includes("/") || disk.files.has(to) || disk.folders.has(to)) return; // a free top-level name only
    disk.files.delete(from);
    disk.files.set(to, f);
    t.carriedRenames++;
  };
  const remoteWrite = () => {
    const live = [...w.server.heads.values()].filter((h) => !h.deleted);
    const r = random();
    const binary = chance(faults.binary);
    if (live.length === 0 || r < 0.25) {
      const paths = binary ? ["n.md", "remote.md", "d/r.md", "r.png", "d/r.pdf"] : ["n.md", "remote.md", "d/r.md"];
      remoteCommit(w.server, `0190a1b2-remote-${step}`, { path: paths[Math.floor(random() * paths.length)]!, content: author(`remote ${step}`, binary), deleted: false });
      return;
    }
    const target = live[Math.floor(random() * live.length)]!;
    // §35.13 runs: a pure rename keeps the content blob (§7), so that revisions share one (drawn only there).
    if (reencrypting && random() < 0.3) {
      remoteCommit(w.server, target.objectId, { path: target.path === "renamed.md" ? "renamed-again.md" : "renamed.md", content: target.content, deleted: false });
      return;
    }
    const path = random() < 0.3 ? "renamed.md" : target.path;
    // §20.2 (drawn only when the faults are on): another tool, or the user by coincidence, makes this edit here too.
    const tool = r <= 0.9 && chance(faults.otherTool ?? 0);
    const coincidence = r <= 0.9 && !tool && chance(faults.coincidence ?? 0);
    const empty = (tool || coincidence) && random() < 0.4;
    if (empty) log.authored.add("");
    remoteCommit(w.server, target.objectId, { path, content: r > 0.9 || empty ? "" : author(`remote edit ${step}`, binary), deleted: r > 0.9 });
    const from = tool || coincidence ? fileInSync(target.objectId, target.content) : null;
    if (from !== null) carry(target, from, tool ? "tool" : "coincidence");
  };
  return run;
}

/** Runs until quiescent past the active phase; the tick count, or null at the bound. */
export async function runToRest(run: Run, maxTicks: number): Promise<number | null> {
  const stepFn = (run as Run & { step: (i: number) => Promise<boolean> }).step;
  for (let i = 0; i < maxTicks; i++) if (!(await stepFn(i))) return i;
  return null;
}

/** At rest: L = R = S (the plan is empty) and the disk is exactly the projection of the server heads. */
export function convergenceProblems(run: Run): string[] {
  const out: string[] = [];
  const s = run.client.shell.state;
  const heads = [...run.server.heads.values()].filter((h) => !h.deleted);
  const blocked = new Set(s.facts.blocked.map((b) => b.objectId));
  const layout = project({ objects: heads.map((h) => ({ objectId: h.objectId, logicalPath: h.path, createdSequence: h.createdSequence })), untrackedFiles: [] });
  const expected = new Map<string, string>();
  for (const [id, f] of layout.files) {
    if (f.notMaterialized !== null || blocked.has(id)) continue;
    expected.set(f.physicalPath, run.server.heads.get(id)!.content);
  }
  const actual = new Map([...run.disk.files].map(([p, f]) => [p, f.content]));
  if (blocked.size === 0) {
    for (const [p, c] of expected) if (actual.get(p) !== c) out.push(`${p}: expected ${JSON.stringify(c)}, disk ${JSON.stringify(actual.get(p) ?? null)}`);
    for (const p of actual.keys()) if (!expected.has(p)) out.push(`${p}: on disk, not projected`);
  }
  if (s.journal !== null) out.push("journal entry left open");
  if (s.facts.outbox.length > 0) out.push("outbox not empty");
  return out;
}

/**
 * No local edit disappears (sync-core property (e)): every content the user wrote and did not discard
 * ends in a confirmed revision, in a file on disk (conflict copies and recovery notes included), or
 * merged into a resolved result.
 */
export function lostEdits(run: Run): string[] {
  const confirmed = new Set([...run.server.revisions.values()].filter((r) => !r.deleted).map((r) => r.content));
  const onDisk = new Set([...run.disk.files.values()].map((f) => f.content));
  const merged = new Set(run.log.merges);
  // Window losses are here only if a WindowRule allowed them (see windows.ts).
  const owed = [...run.log.userContents.values(), ...run.log.intentContents.values()];
  return owed.filter((c) => !confirmed.has(c) && !onDisk.has(c) && !merged.has(c) && !run.log.windowLosses.has(c));
}

/**
 * (E8) Byte exactness: every content on the server and on disk is one some actor wrote (or a merge of
 * them), byte for byte. A byte prefix of one is allowed (recovery notes of partial temporaries; truncation
 * is E3's oracle); a content changed on the way (decoded and re-encoded, say) is not.
 */
export function unknownContents(run: Run): string[] {
  const known = new Set([...run.log.authored, ...run.log.mergedTexts, ...run.log.merges]);
  const knownBytes = [...known].map(fromModel);
  const isKnown = (c: string) => known.has(c) || knownBytes.some((k) => bytesStartWith(k, fromModel(c)));
  const out: string[] = [];
  const show = (c: string) => JSON.stringify(c.slice(0, 40));
  for (const r of run.server.revisions.values()) if (!r.deleted && !isKnown(r.content)) out.push(`server ${r.path}: ${show(r.content)}`);
  for (const [p, f] of run.disk.files) if (!isTmpName(p) && !isKnown(f.content)) out.push(`disk ${p}: ${show(f.content)}`);
  return out;
}

/** (E6) Every intent sent is processed exactly once, and no row is left once at rest. */
export async function intentDelivery(run: Run): Promise<string[]> {
  const out: string[] = [];
  for (const id of run.log.sent.keys()) {
    const n = run.log.processed.get(id)?.length ?? 0;
    if (n !== 1) out.push(`${id} processed ${n} times`);
  }
  for (const i of await run.pendingIntents()) out.push(`${i.intentId} still pending`);
  return out;
}

/**
 * §35.13 at the end of a re-encrypting run (at rest): the §44.5 server invariants held at every step, the
 * list is empty, and once the GC has run no blob of a pre-switch epoch is stored — no current or
 * historical revision is readable with a pre-switch epoch any more.
 */
export function reencryptionProblems(run: Run): string[] {
  const out = [...run.log.serverViolations];
  if (run.log.switchedAt === null) return out;
  const left = listToReencrypt(run.server, null, 1000);
  if (left.kind !== "PAGE") out.push(`list: ${left.kind}`);
  else for (const t of left.revisions) out.push(`still listed at rest: ${t.revisionId}`);
  run.server.now += 1_000_000;
  gc(run.server);
  for (const b of preSwitchBlobs(run.server)) out.push(`a pre-switch blob is stored after completion: ${b}`);
  for (const v of modelInvariants(run.server, new Map())) out.push(`after the GC: ${v}`);
  return out;
}
