// Single-replica simulator: an in-memory server (server.ts) and one client with an in-memory disk.
// Loop: refresh R → outbox step (cleanup, attempts, prepare, PUT, commit) or plan → execute the
// first action (§12.2). Faults: lost requests, lost responses, crashes (all in-memory state is lost;
// restart = load persisted facts, observe the disk, fetch remote, plan), PUT timeouts, a remote
// writer, epoch rotation and expired mutation rows. Deterministic by seed.
//
// Physical writes, renames and deletes go through the apply journal (§15) with crash points between
// every step (partial temporary writes included) and user edits in between, including the user
// touching nodra-tmp-* files. Not modelled: several real replicas and the multi-tab leader (§20.2),
// rename pairing after restart (rules 10-11): the simulator keeps file identity across a crash.

import { canonicalizePath, comparisonKey, project, utf8Length } from "@nodra/path-projection";
import { merge3 } from "../../src/merge.js";
import {
  type ClientFacts,
  type CommitResult,
  type OutboxStep,
  type UploadAttempt,
  type UploadRequest,
  applyCommitResult,
  applyPrepareRejection,
  applyRelease,
  applyRevisionStatus,
  enqueueUploads,
  markCommitSent,
  recordAttempt,
  recordPrepared,
  recordPutFailure,
  recordRemoteHeads,
  retireExpired,
  nextOutboxStep,
  setWriteEpoch,
} from "../../src/outbox.js";
import {
  type JournalEntry,
  isRecoveryName,
  isTmpName,
  openEntry,
  recoveryName,
  replaceAllowed,
  replay,
  strayDisposition,
  tmpDisposition,
  tmpPath,
} from "../../src/journal.js";
import { applyEvents, applyVaultState } from "../../src/events.js";
import { attributeFiles } from "../../src/observe.js";
import { plan, resolveLocal, resolveLocalPaths } from "../../src/plan.js";
import type { Action, LocalEntry, PlanInput, RevisionEntry } from "../../src/types.js";
import {
  type Server,
  type ServerRevision,
  commit,
  expireMutationRows,
  headEntry,
  prepare,
  put,
  release,
  remoteCommit,
  revisionStatus,
  listEvents,
  prune,
  rotateEpoch,
  vaultState,
} from "./server.js";
import { text, utf8 } from "../utf8.js";

export type { ServerRevision } from "./server.js";

export interface Faults {
  /** Probability that a request is lost before reaching the server. */
  readonly drop: number;
  /** Probability that the server applies a request but the response is lost. */
  readonly lose: number;
  /** Probability that a lost response comes with a crash (all in-memory state lost). */
  readonly crash: number;
  /** Probability that a PUT times out (§12.6 UPLOAD_TIMEOUT). */
  readonly putTimeout: number;
  /** Per step: remote writer commit, epoch rotation, expiry of mutation rows, local user edit. */
  readonly remoteWrite: number;
  readonly rotateEpoch: number;
  readonly expireRows: number;
  readonly userEdit: number;
  /** Crash at each step boundary of a physical file operation (§15). */
  readonly fileCrash: number;
  /** The user touches nodra-tmp-* files or creates one holding a prefix of an entry's content. */
  readonly tmpTouch: number;
  /** The user moves/renames a file or folder, or deletes a file. */
  readonly userMove: number;
  /** Per step: the server prunes history (§10.6), which can expire cursors and bases. */
  readonly prune: number;
  /** Per step: the client does not poll events (delays echoes, so resends of applied commits happen). */
  readonly skipPoll: number;
  /** When a commit's response is lost: an epoch rotation races it (§44.1 lost response + EPOCH_STALE). */
  readonly rotateOnLostCommit?: number;
  /** The user creates a file (new content, or a paste of an existing file's bytes). */
  readonly userCreate?: number;
  /** Plugin reload at the start of a tick: all in-memory state (identities included) is lost. */
  readonly reload?: number;
  /** Faults and other actors stop at this step; afterwards the system must converge. */
  readonly activeUntil: number;
}

export const NO_FAULTS: Faults = {
  drop: 0,
  lose: 0,
  crash: 0,
  putTimeout: 0,
  remoteWrite: 0,
  rotateEpoch: 0,
  expireRows: 0,
  userEdit: 0,
  fileCrash: 0,
  tmpTouch: 0,
  userMove: 0,
  prune: 0,
  skipPoll: 0,
  activeUntil: 0,
};

export type Planner = (input: PlanInput) => Action[];

/** A file on disk. `owner` mirrors the client's attribution; the rest are adapter facts and test oracles. */
export interface DiskFileState {
  owner: string | null;
  content: string;
  /** Adapter identity (moves with the file; a new file, a copy or a paste gets a new one). */
  readonly fid: number;
  /** Oracle: who created the file (the user, or the client writing an object). */
  readonly origin: "user" | "client";
  /** Oracle: the user edited it. */
  touched: boolean;
  /** Oracle: the object this file really is (null: nobody's, e.g. a user's new file not imported yet). */
  truth: string | null;
  /**
   * Oracle: found at a startup scan off every recorded path, with a hash that rule 11 cannot pair
   * uniquely (identical contents). Its object is legitimately deleted and it is re-created: history
   * may be lost, never content (§12.2 rule 11).
   */
  unpairable?: boolean;
}

/** A new file with a fresh adapter identity. */
export function newFile(w: World, owner: string | null, content: string, origin: "user" | "client"): DiskFileState {
  return { owner, content, fid: ++w.fids, origin, touched: origin === "user", truth: owner };
}

/** A client variant: the real one, or deliberately broken ones for evidence tests. */
export interface Variant {
  readonly planner: Planner;
  readonly enqueue?: typeof enqueueUploads;
  /** Broken: a lost or dropped commit response is taken as COMMITTED. */
  readonly assumeCommittedWhenUnknown?: boolean;
  /** Broken: the cleanup queue is never processed. */
  readonly skipRelease?: boolean;
  /** Broken: blobs are prepared before the attempt is persisted (no write-ahead). */
  readonly prepareBeforePersist?: boolean;
  /** Broken: writes go straight to the destination (no temporary), so a crash can truncate it. */
  readonly writeInPlace?: boolean;
  /** Broken: a cancelled entry always deletes its temporary. */
  readonly cancelDeletesTmp?: boolean;
  /** Broken: a cancelled entry always keeps its temporary as a recovery note. */
  readonly cancelKeepsTmp?: boolean;
  /** Broken: projection renames are not journaled (the observation is recorded afterwards). */
  readonly renameWithoutJournal?: boolean;
  /** Broken: pages of events are recorded without the §13.2 checks (partial batches accepted). */
  readonly acceptPartialPages?: boolean;
  /** Replaceable attribution (rules 10-11) for broken variants. */
  readonly attribute?: typeof attributeFiles;
  /** Broken: untracked files are never imported. */
  readonly noImport?: boolean;
}

export interface World {
  readonly server: Server;
  readonly replica: string;
  /** Prefix of every id this replica generates (unique across replicas). */
  readonly prefix: string;
  /** For each file the user deleted: the S revision it was synced to then and the content deleted (property (n)). */
  readonly userDeletedBase: Map<string, { base: string | undefined; content: string }>;
  // Disk and persisted local observation (§12.2 table).
  readonly files: Map<string, DiskFileState>;
  /** The client's attribution (object → file), re-derived from the disk at every tick (observe.ts). */
  readonly bound: Map<string, string>;
  /** Persisted last observation per object (§12.2 table): logical and physical path, and the hash. */
  readonly recorded: Map<string, { logicalPath: string; physicalPath: string | null; hash?: string | null }>;
  /** In-memory only: the adapter identity (TFile) of each object's file in this instance (rule 10). Lost on crash/reload. */
  readonly identity: Map<string, number>;
  /** Next file identity to hand out (the adapter's, not the client's). */
  fids: number;
  readonly gone: Set<string>;
  readonly notMaterialized: Set<string>;
  /** Persisted cache of revisions whose plaintext is known (their local_compare_hash). */
  readonly known: Set<string>;
  /** Persisted sync facts (outbox.ts). */
  facts: ClientFacts;
  /** Test hook: crash once at each of these points, the next time they are reached. */
  readonly forcedCrashes: Set<CrashPointName>;
  /** Test hook: runs between the steps of a physical operation (deterministic user activity). */
  betweenStepsHook?: (w: World) => void;
  /** Persisted apply journal (§15): at most one open entry. */
  journal: JournalEntry | null;
  /** Objects the user moved before the run (the only legitimate path-change uploads, rule 12). */
  readonly userMoved: Set<string>;
  /** Recovery notes created by this client, with whether their source was provably ours (§44.5). */
  readonly recoveryNotes: Map<string, { provable: boolean; content: string }>;
  /** In-memory only: blobs whose PUT completed in this instance (rule 13). Lost on crash. */
  memory: { putDone: Set<string>; scanned?: boolean };
  faults: Faults;
  rng: number;
  ids: number;
  copies: number;
  step: number;
  readonly log: {
    uploads: Array<{ objectId: string; deleted: boolean; localKind: LocalEntry["kind"] | "UNBOUND" }>;
    parked: number;
    conflictCopies: number;
    merges: number;
    mergedLocal: Set<string>;
    crashes: number;
    lostResponses: number;
    expiredRetired: number;
    statusQueries: number;
    rejections: Map<string, number>;
    /** Latest user-written content per file (object id, or path of an untracked file), as a hash. */
    userContents: Map<string, string>;
    /** Every whole content that legitimately exists (never a truncated write), for property (i). */
    wholeContents: Set<string>;
    /** Bytes the client deleted from disk, why, and the journal entry involved. */
    deletions: Array<{ content: string; reason: string; entry: JournalEntry | null }>;
    /** Path-change uploads of objects the user never moved (property (l)). */
    pathMisreads: string[];
    /** Delete uploads: expected head and the content the user deleted (property (n)). */
    deleteUploads: Array<{ objectId: string; expected: string | null; deleted: { base: string | undefined; content: string } | undefined }>;
    reconciliations: number;
    /** Every content this replica had on disk (at an observation) or as S, per object (property (n)). */
    seen: Map<string, Set<string>>;
    userMoves: number;
    userDeletes: number;
    /** Objects this replica applied a remote revision to (applyRemote executed). */
    applies: string[];
    /** Untracked files imported as new objects, and adoptions (§18.4 step 5). */
    imports: number;
    adoptions: number;
    /** Rule 11 pairings, with the oracle's verdict. */
    pairings: number;
    /** Absent objects left unpaired because a hash match was ambiguous (rule 11). */
    ambiguous: number;
    /** (u)/(v)/(w) violations seen by the oracle. */
    identityViolations: string[];
    reloads: number;
    userCreates: number;
    pastes: number;
    /** Physical operations cancelled because their destination was occupied at execution time. */
    occupiedCancels: number;
    journalReplays: number;
    journalCancels: number;
    partialWrites: number;
    recoveries: number;
    tmpTouches: number;
  };
}

export const hash = (content: string) => `h:${content}`;
const MANIFEST_OVERHEAD = 28;
export const blobSize = (payload: string) => utf8Length(payload) + MANIFEST_OVERHEAD;

/** Seeded PRNG (mulberry32). */
export function random(w: World): number {
  w.rng = (w.rng + 0x6d2b79f5) | 0;
  let t = w.rng;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const chance = (w: World, p: number) => p > 0 && w.step < w.faults.activeUntil && random(w) < p;
const nextId = (w: World, prefix: string) => `${w.prefix}${prefix}${(w.ids++).toString(36).padStart(4, "0")}`;

const entry = (r: ServerRevision, known: boolean): RevisionEntry => ({
  ...headEntry(r),
  localCompareHash: known && !r.deleted ? hash(r.content) : null,
});

function noteSeen(w: World, id: string, content: string): void {
  (w.log.seen.get(id) ?? w.log.seen.set(id, new Set()).get(id)!).add(content);
}

/** Persists an object's last observation (§12.2 table): its paths and the hash of the file there now. */
function record(w: World, id: string, logicalPath: string, physicalPath: string): void {
  const file = w.files.get(physicalPath);
  w.recorded.set(id, { logicalPath, physicalPath, hash: file ? hash(file.content) : null });
}

function setSynced(w: World, id: string, s: RevisionEntry): void {
  const r = w.server.revisions.get(s.revisionId);
  if (r && !r.deleted) noteSeen(w, id, r.content);
  w.facts = { ...w.facts, synced: new Map(w.facts.synced).set(id, s) };
}

/** Builds the planner input: observe L, load S and R, and the outbox (§12.2 principle). */
export function observe(w: World): PlanInput {
  const local = new Map<string, LocalEntry>();
  const ids = new Set([...w.bound.keys(), ...w.gone, ...w.notMaterialized]);
  for (const id of ids) {
    const physicalPath = w.bound.get(id);
    if (w.notMaterialized.has(id) && physicalPath === undefined) local.set(id, { kind: "NOT_MATERIALIZED", reason: "LOCAL_PATH_TOO_LONG" });
    else if (physicalPath !== undefined) {
      const rec = w.recorded.get(id)!;
      local.set(id, {
        kind: "PRESENT",
        path: rec.logicalPath,
        physicalPath,
        recordedPhysicalPath: rec.physicalPath ?? physicalPath, // absent at the last observation: nothing to derive from
        localCompareHash: hash(w.files.get(physicalPath)!.content),
      });
      noteSeen(w, id, w.files.get(physicalPath)!.content);
    } else if (w.gone.has(id) && w.recorded.has(id)) local.set(id, { kind: "ABSENT" });
  }
  const withHash = (e: RevisionEntry) => {
    const r = w.server.revisions.get(e.revisionId);
    return { ...e, localCompareHash: r && w.known.has(e.revisionId) && !e.deleted ? hash(r.content) : null };
  };
  const synced = new Map([...w.facts.synced].map(([id, s]) => [id, withHash(s)]));
  const remote = new Map([...w.facts.remote].map(([id, r]) => [id, withHash(r)]));
  const objects = new Set([...local.keys(), ...remote.keys(), ...synced.keys()]);
  const input: PlanInput = {
    local,
    remote,
    synced,
    outbox: w.facts.outbox,
    blocked: w.facts.blocked,
    textObjects: objects,
    prunedRevisions: w.server.pruned, // model shortcut: the client learns it when a download fails
    untrackedFiles: [...w.files].filter(([, f]) => f.owner === null).map(([p]) => p),
    tmpHex: [0, 1, 2, 3].map((i) => (w.step * 4 + i).toString(16).padStart(8, "0")),
  };
  // The last observation of L is a fact (§12.2 table): a moved file's physical path, and the logical
  // path rule 12 derives from it, are persisted now, not only at the next upload snapshot. Otherwise the
  // record keeps claiming the old path after the client writes another file there.
  const { local: resolved, unrepresentable } = resolveLocal(input);
  let changed = false;
  for (const [id, l] of input.local) {
    const r = resolved.get(id);
    if (l.kind !== "PRESENT" || r?.kind !== "PRESENT" || l.physicalPath === l.recordedPhysicalPath) continue;
    if (unrepresentable.has(id)) continue; // frozen by the planner: keep the record
    w.recorded.set(id, { ...w.recorded.get(id)!, logicalPath: r.path, physicalPath: r.physicalPath });
    local.set(id, { ...r, recordedPhysicalPath: r.physicalPath });
    changed = true;
  }
  return changed ? { ...input, local } : input;
}

/** Whether `path` is free for `owner`: no other file with the same key, inside it, or at an ancestor. */
function isFree(w: World, path: string, owner: string): boolean {
  const k = comparisonKey(path);
  for (const [p, f] of w.files) {
    if (f.owner === owner) continue;
    const fk = comparisonKey(p);
    if (fk === k || fk.startsWith(`${k}/`) || k.startsWith(`${fk}/`)) return false;
  }
  return true;
}

/** Throws when `path` is occupied for `owner` (same key, inside a file, or a folder with files). */
function assertFree(w: World, path: string, owner: string): void {
  const k = comparisonKey(path);
  for (const [p, f] of w.files) {
    if (f.owner === owner) continue;
    const fk = comparisonKey(p);
    if (fk === k || fk.startsWith(`${k}/`) || k.startsWith(`${fk}/`)) {
      throw new Error(`overwrite: ${owner} → ${path} occupied by ${f.owner ?? "untracked"} at ${p}`);
    }
  }
}

function conflictCopy(w: World, id: string, localPath: string, remoteRevisionId: string): void {
  const physical = w.bound.get(id)!;
  const copy = `${id}~copy${w.prefix}${++w.copies}`;
  const file = w.files.get(physical)!;
  file.owner = copy;
  file.truth = copy;
  w.identity.set(copy, file.fid);
  w.identity.delete(id);
  w.bound.set(copy, physical);
  record(w, copy, localPath, physical);
  w.bound.delete(id);
  w.recorded.delete(id);
  w.gone.delete(id);
  setSynced(w, id, entry(w.server.revisions.get(remoteRevisionId)!, true));
  w.log.conflictCopies++;
}

// ---------------------------------------------------------------------------
// Apply journal (§15). Every physical write, rename or delete opens an entry before touching the
// disk; a crash can happen between any two steps; the next start replays the open entry.

const dirOf = (p: string) => p.slice(0, p.lastIndexOf("/") + 1);
const fileHash = (w: World, p: string): string => {
  const file = w.files.get(p);
  return file ? hash(file.content) : "ABSENT";
};
const hex8 = (w: World) => Math.floor(random(w) * 2 ** 32).toString(16).padStart(8, "0");
const occupiedKey = (w: World, p: string) => [...w.files.keys()].some((k) => comparisonKey(k) === comparisonKey(p));

/** Named step boundaries of physical operations where a crash can be forced (deterministic tests). */
export type CrashPointName =
  | "opened"
  | "tmpPartial"
  | "tmpWritten"
  | "tmpCreated"
  | "replaced"
  | "renamed"
  | "deleted"
  | "recoveryRenamed"
  | "renamedUnjournaled"
  | "inPlacePartial";

/** Whether to crash at this point: forced once by name, or by chance. Does not crash yet. */
function crashNow(w: World, name: CrashPointName): boolean {
  const forced = w.forcedCrashes.has(name);
  if (forced) w.forcedCrashes.delete(name);
  return forced || chance(w, w.faults.fileCrash);
}

function crashPoint(w: World, name: CrashPointName): boolean {
  if (!crashNow(w, name)) return false;
  crash(w);
  return true;
}

/** A nodra-tmp-<8 hex> name that exists nowhere in the vault (§15 step 2). */
function freshTmpName(w: World): string {
  for (;;) {
    const name = `nodra-tmp-${hex8(w)}`;
    if (![...w.files.keys()].some((k) => k.endsWith(name))) return name;
  }
}

function logDeletion(w: World, content: string, reason: string, e: JournalEntry | null): void {
  w.log.deletions.push({ content, reason, entry: e });
}

/** Closes the open entry: the observation and S are recorded in the same transition (§15 step 5). */
function closeEntry(w: World): void {
  const e = w.journal!;
  const id = e.objectId;
  if (e.kind === "WRITE") {
    const placed = w.files.get(e.destPath)!;
    placed.owner = id;
    placed.truth = id;
    w.identity.set(id, placed.fid);
    w.bound.set(id, e.destPath);
    const logical = e.recordedLogicalPath ?? w.recorded.get(id)?.logicalPath ?? e.destPath;
    record(w, id, logical, e.destPath);
    w.gone.delete(id);
    w.notMaterialized.delete(id);
  } else if (e.kind === "RENAME") {
    w.bound.set(id, e.destPath);
    const moved = w.files.get(e.destPath);
    if (moved) w.identity.set(id, moved.fid);
    w.recorded.set(id, { ...w.recorded.get(id)!, physicalPath: e.destPath });
    if (isTmpName(e.destPath)) w.log.parked++;
  } else {
    w.bound.delete(id);
    w.recorded.delete(id);
    w.identity.delete(id);
    if (e.marksNotMaterialized) w.notMaterialized.add(id);
  }
  if (e.newSynced) {
    setSynced(w, id, e.newSynced);
    w.known.add(e.newSynced.revisionId);
  }
  w.journal = null;
}

/** Imports a kept temporary (or stray) as a recovery note: a new object of the user (§15). */
function importRecovery(w: World, path: string, provable: boolean): void {
  const file = w.files.get(path)!;
  let target = path;
  if (!isRecoveryName(path)) {
    const name = recoveryName(path, [hex8(w), hex8(w), hex8(w)], (p) => occupiedKey(w, p));
    if (name === null) return;
    w.files.delete(path);
    w.files.set(name, file);
    target = name;
    if (crashPoint(w, "recoveryRenamed")) return; // an untracked nodra-recuperado-* file: imported by the stray rule
  }
  const id = `0190a1b2-recov-${w.prefix}${(w.ids++).toString(36)}`;
  file.owner = id;
  file.truth = id;
  w.identity.set(id, file.fid);
  w.bound.set(id, target);
  record(w, id, canonical(target), target);
  w.recoveryNotes.set(id, { provable, content: file.content });
  w.log.recoveries++;
}

/** Cancels the open entry; its temporary is deleted only if provably ours (§15). */
function cancelEntry(w: World, variant: Variant): void {
  const e = w.journal!;
  w.journal = null;
  if (e.kind !== "WRITE") return;
  // A materialization that replaced its destination but is cancelled (the user edited the result
  // before the close): no observation attributes that file to the object, so it is untracked.
  const placed = w.files.get(e.destPath);
  if (placed?.owner === e.objectId && !w.recorded.has(e.objectId)) {
    placed.owner = null;
    placed.truth = null;
    w.identity.delete(e.objectId);
    w.bound.delete(e.objectId);
  }
  const tp = tmpPath(e);
  const file = w.files.get(tp);
  if (!file || file.owner !== null) return;
  const provable = tmpDisposition(e, utf8(file.content), (b) => hash(text(b))) === "DELETE";
  const decision = variant.cancelDeletesTmp ? "DELETE" : variant.cancelKeepsTmp ? "RECOVER" : provable ? "DELETE" : "RECOVER";
  if (decision === "DELETE") {
    // Re-read right before deleting (it is the current content) and delete only that.
    logDeletion(w, file.content, "tmp", e);
    w.files.delete(tp);
  } else importRecovery(w, tp, provable);
}

/** Replays the entry left open by a crash (§15 table), before observing anything else. */
function replayJournal(w: World, variant: Variant): void {
  const e = w.journal!;
  w.log.journalReplays++;
  const decision = replay(e, {
    tmpExists: e.tmpName !== null && w.files.has(tmpPath(e)),
    destFp: fileHash(w, e.destPath),
    sourceExists: e.sourcePath !== null && w.files.has(e.sourcePath),
  });
  if (decision === "COMPLETE") closeEntry(w);
  else {
    w.log.journalCancels++;
    cancelEntry(w, variant);
  }
}

/** nodra-tmp-* (and unimported nodra-recuperado-*) files bound to nothing (§15). */
function handleStrays(w: World): boolean {
  for (const [p, file] of [...w.files].sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (file.owner !== null || !(isTmpName(p) || isRecoveryName(p))) continue;
    if (strayDisposition(utf8(file.content)) === "DELETE") {
      logDeletion(w, file.content, "stray", null);
      w.files.delete(p);
    } else importRecovery(w, p, false);
    return true;
  }
  return false;
}

/** Runs one journaled physical operation, with crash points and user activity between steps. */
function runEntry(w: World, variant: Variant, e: JournalEntry): void {
  if (e.kind === "RENAME" && variant.renameWithoutJournal) {
    const file = w.files.get(e.sourcePath!)!;
    w.files.delete(e.sourcePath!);
    w.files.set(e.destPath, file);
    w.bound.set(e.objectId, e.destPath);
    if (crashPoint(w, "renamedUnjournaled")) return; // the observation still records the old physical path
    w.recorded.set(e.objectId, { ...w.recorded.get(e.objectId)!, physicalPath: e.destPath });
    return;
  }
  w.journal = openEntry(w.journal, e); // 1. the entry is persisted before touching the disk
  if (crashPoint(w, "opened")) return;
  betweenSteps(w);
  if (e.kind === "WRITE") {
    const content = text(e.content!);
    if (variant.writeInPlace) {
      if (crashNow(w, "inPlacePartial")) {
        w.files.set(e.destPath, newFile(w, e.objectId, content.slice(0, Math.floor(random(w) * content.length)), "client"));
        w.bound.set(e.objectId, e.destPath);
        crash(w);
        return;
      }
      w.files.set(e.destPath, newFile(w, e.objectId, content, "client"));
      closeEntry(w);
      return;
    }
    const tp = tmpPath(e);
    if (occupiedKey(w, tp)) return cancelEntry(w, variant); // 2. exclusive creation failed
    if (crashNow(w, "tmpPartial")) {
      w.files.set(tp, newFile(w, null, content.slice(0, Math.floor(random(w) * content.length)), "client")); // partial write
      w.log.partialWrites++;
      crash(w);
      return;
    }
    w.files.set(tp, newFile(w, null, content, "client"));
    if (crashPoint(w, "tmpWritten")) return;
    w.journal = { ...w.journal!, tmpCreated: true }; // 3. own transaction
    if (crashPoint(w, "tmpCreated")) return;
    betweenSteps(w);
    // 4. re-check the destination, then the only replace of an existing file
    if (!replaceAllowed(w.journal, fileHash(w, e.destPath))) return cancelEntry(w, variant);
    const tmp = w.files.get(tp);
    if (!tmp) return cancelEntry(w, variant);
    // §16.7 rule 4 / §13.4: the destination must still be free (a folder may have appeared there).
    if (!isFree(w, e.destPath, e.objectId)) {
      w.log.occupiedCancels++;
      return cancelEntry(w, variant);
    }
    // Blocked content (rule 8) must never be lost by an overwrite: only a merge that carries it
    // (rule 4) or a content already confirmed on the server may replace it.
    const destFp = fileHash(w, e.destPath);
    const blocked = w.facts.blocked.some((b) => b.objectId === e.objectId && b.localCompareHash === destFp);
    const preserved = w.log.mergedLocal.has(destFp) || [...w.server.revisions.values()].some((r) => !r.deleted && hash(r.content) === destFp);
    if (blocked && !preserved) throw new Error(`blocked content of ${e.objectId} overwritten`);
    assertFree(w, e.destPath, e.objectId);
    const previous = w.files.get(e.destPath);
    if (previous) logDeletion(w, previous.content, "replace", e);
    w.files.delete(tp);
    w.files.set(e.destPath, { ...tmp, owner: e.objectId, truth: e.objectId });
    w.bound.set(e.objectId, e.destPath); // file identity follows the file; the observation is recorded at close
    if (crashPoint(w, "replaced")) return;
    closeEntry(w); // 5.
    return;
  }
  if (e.kind === "RENAME") {
    // §16.7 rule 4: re-read the source and check the destination is free.
    if (fileHash(w, e.sourcePath!) !== e.finalFp) return cancelEntry(w, variant);
    if (!isFree(w, e.destPath, e.objectId)) {
      w.log.occupiedCancels++;
      return cancelEntry(w, variant);
    }
    const file = w.files.get(e.sourcePath!)!;
    w.files.delete(e.sourcePath!);
    w.files.set(e.destPath, file);
    w.bound.set(e.objectId, e.destPath);
    if (crashPoint(w, "renamed")) return;
    closeEntry(w);
    return;
  }
  // DELETE: only bytes that are exactly what the entry expects.
  if (fileHash(w, e.destPath) !== e.expectedPrevFp) return cancelEntry(w, variant);
  logDeletion(w, w.files.get(e.destPath)!.content, "delete", e);
  w.files.delete(e.destPath);
  w.bound.delete(e.objectId);
  if (crashPoint(w, "deleted")) return;
  closeEntry(w);
}

const writeEntry = (objectId: string, dest: string, expected: string, content: string, newSynced: RevisionEntry | null, logical: string, tmpName: string): JournalEntry => ({
  objectId,
  kind: "WRITE",
  sourcePath: null,
  destPath: dest,
  tmpName,
  expectedPrevFp: expected,
  finalFp: hash(content),
  newSynced,
  recordedLogicalPath: logical,
  tmpCreated: false,
  content: utf8(content),
  marksNotMaterialized: false,
});

const deleteEntry = (objectId: string, dest: string, expected: string, newSynced: RevisionEntry | null, marksNotMaterialized: boolean): JournalEntry => ({
  objectId,
  kind: "DELETE",
  sourcePath: null,
  destPath: dest,
  tmpName: null,
  expectedPrevFp: expected,
  finalFp: null,
  newSynced,
  recordedLogicalPath: null,
  tmpCreated: false,
  content: null,
  marksNotMaterialized,
});

/** Executes one non-upload plan action. Physical effects go through the journal. */
export function execute(w: World, input: PlanInput, a: Action, variant: Variant = { planner: plan }): void {
  const rev = (id: string) => w.server.revisions.get(id)!;
  const localPath = (id: string) => {
    const l = resolveLocalPaths(input).get(id);
    return l?.kind === "PRESENT" ? l.path : w.recorded.get(id)!.logicalPath;
  };
  /** The L the planner saw: the destination must still hold it (§13.4 step 1, §15 step 4). */
  const observedFp = (id: string) => {
    const l = input.local.get(id);
    return l?.kind === "PRESENT" ? l.localCompareHash : "ABSENT";
  };
  switch (a.kind) {
    case "upload":
      throw new Error("uploads go through the outbox");
    case "fetchContent":
      w.known.add(a.revisionId);
      return;
    case "advanceSynced":
      setSynced(w, a.objectId, entry(rev(a.revisionId), w.known.has(a.revisionId)));
      return;
    case "forgetUnconfirmedCreate":
      w.gone.delete(a.objectId);
      w.recorded.delete(a.objectId);
      return;
    case "applyRemote": {
      const r = rev(a.revisionId);
      w.log.applies.push(a.objectId);
      w.known.add(r.revisionId);
      const current = w.bound.get(a.objectId);
      if (r.deleted) {
        if (current === undefined) {
          w.gone.delete(a.objectId);
          setSynced(w, a.objectId, entry(r, true));
          return;
        }
        runEntry(w, variant, deleteEntry(a.objectId, current, observedFp(a.objectId), entry(r, true), false));
        return;
      }
      w.gone.delete(a.objectId);
      runEntry(w, variant, writeEntry(a.objectId, a.physicalPath, observedFp(a.objectId), r.content, entry(r, true), r.path, freshTmpName(w)));
      return;
    }
    case "movePhysical":
      runEntry(w, variant, {
        objectId: a.objectId,
        kind: "RENAME",
        sourcePath: a.from,
        destPath: a.to,
        tmpName: null,
        expectedPrevFp: "ABSENT",
        finalFp: fileHash(w, a.from),
        newSynced: null,
        recordedLogicalPath: null,
        tmpCreated: false,
        content: null,
        marksNotMaterialized: false,
      });
      return;
    case "markNotMaterialized":
      setSynced(w, a.objectId, entry(rev(a.revisionId), w.known.has(a.revisionId)));
      w.notMaterialized.add(a.objectId);
      w.gone.delete(a.objectId);
      return;
    case "removePhysical":
      runEntry(w, variant, deleteEntry(a.objectId, a.from, observedFp(a.objectId), null, true));
      return;
    case "conflictCopy":
      conflictCopy(w, a.objectId, localPath(a.objectId), a.remoteRevisionId);
      return;
    case "discardLocalRename":
      runEntry(w, variant, deleteEntry(a.objectId, w.bound.get(a.objectId)!, observedFp(a.objectId), entry(rev(a.remoteRevisionId), true), false));
      return;
    case "resolve": {
      const physical = w.bound.get(a.objectId)!;
      const local = w.files.get(physical)!.content;
      const r = rev(a.remoteRevisionId);
      let content = a.content === "local" ? local : r.content;
      if (a.content === "merge") {
        const m = merge3(rev(a.baseRevisionId).content, local, r.content);
        if (m.kind === "conflict") {
          conflictCopy(w, a.objectId, localPath(a.objectId), a.remoteRevisionId);
          return;
        }
        content = m.text;
        w.log.merges++;
        w.log.mergedLocal.add(hash(local));
        w.log.wholeContents.add(content);
      }
      const path = a.path === "local" ? localPath(a.objectId) : r.path;
      w.known.add(r.revisionId);
      if (content === local) {
        // M = L: only S := R (rule 4); the upload of M over R comes in the next plan.
        record(w, a.objectId, path, physical);
        setSynced(w, a.objectId, entry(r, true));
        return;
      }
      // M ≠ L: written through the journal; its close records S := R in the same transition.
      runEntry(w, variant, writeEntry(a.objectId, physical, hash(local), content, entry(r, true), path, freshTmpName(w)));
      return;
    }
  }
}

/** The planner's uploads become outbox entries (§12.1); the snapshot is taken now (rule 13). */
function enqueue(w: World, input: PlanInput, uploads: ReadonlyArray<Extract<Action, { kind: "upload" }>>, variant: Variant): void {
  const local = resolveLocalPaths(input);
  const requests: UploadRequest[] = uploads.map((u) => {
    const l = local.get(u.objectId);
    const manifest = (path: string, deleted: boolean) => blobSize(JSON.stringify({ path, deleted }));
    if (u.deleted || l?.kind !== "PRESENT") {
      const path = w.facts.synced.get(u.objectId)?.path ?? "";
      return { ...u, path, deleted: true, localCompareHash: null, plaintext: null, newBlobBytes: manifest(path, true) };
    }
    const content = w.files.get(l.physicalPath)!.content;
    // The observation of a moved file is persisted with the snapshot (§12.2 table).
    record(w, u.objectId, l.path, l.physicalPath);
    return {
      ...u,
      path: l.path,
      deleted: false,
      localCompareHash: l.localCompareHash,
      plaintext: utf8(content),
      newBlobBytes: blobSize(content) + manifest(l.path, false),
    };
  });
  for (const r of requests) {
    w.log.uploads.push({ objectId: r.objectId, deleted: r.deleted, localKind: input.local.get(r.objectId)?.kind ?? "UNBOUND" });
    const s = w.facts.synced.get(r.objectId);
    if (!r.deleted && s && !s.deleted && r.path !== s.path && !w.userMoved.has(r.objectId)) w.log.pathMisreads.push(`${r.objectId}: ${s.path} → ${r.path}`);
    if (r.deleted) w.log.deleteUploads.push({ objectId: r.objectId, expected: r.expectedHeadRevisionId, deleted: w.userDeletedBase.get(r.objectId) });
  }
  const ids = Array.from({ length: requests.length * 2 + 2 }, () => nextId(w, "m"));
  w.facts = (variant.enqueue ?? enqueueUploads)(w.facts, requests, { pendingBudgetBytes: w.server.config.pendingBudgetBytes }, ids);
}

function buildAttempt(w: World, mutationId: string): UploadAttempt {
  const e = w.facts.outbox.find((x) => x.mutationId === mutationId)!;
  const attemptId = nextId(w, "a");
  const blobs = e.objects.flatMap((o) => {
    const one = (kind: "CONTENT" | "MANIFEST", payload: string) => {
      const blobId = nextId(w, "b");
      const ciphertext = `${blobId}|${payload}`; // fake AEAD: a new blob_id gives a new ciphertext
      return {
        blobId,
        kind,
        objectId: o.objectId,
        declaredSize: blobSize(payload),
        ciphertextSha256: `sha(${ciphertext})`,
        ciphertext: utf8(ciphertext),
        forDelete: kind === "MANIFEST" && o.deleted,
        expiresAt: null,
      };
    };
    const manifest = one("MANIFEST", JSON.stringify({ path: o.path, deleted: o.deleted }));
    return o.deleted ? [manifest] : [manifest, one("CONTENT", text(o.plaintext!))];
  });
  return { attemptId, mutationId, replicaId: w.replica, epochId: w.facts.epochId, blobs };
}

type Delivery = "dropped" | "lost" | "delivered";
/** A request crosses the network: lost before the server, or applied with its response lost. */
function deliver<T>(w: World, call: () => T): { delivery: Delivery; response?: T } {
  if (chance(w, w.faults.drop)) return { delivery: "dropped" };
  const response = call();
  if (chance(w, w.faults.lose)) {
    w.log.lostResponses++;
    if (chance(w, w.faults.crash)) crash(w);
    return { delivery: "lost" };
  }
  return { delivery: "delivered", response };
}

/** A crash drops all in-memory state. Restart loads persisted facts, observes, fetches, plans. */
export function crash(w: World): void {
  w.log.crashes++;
  w.memory = { putDone: new Set(), scanned: false };
  w.identity.clear(); // adapter identities are never persisted (§15)
}

function prepareRequest(w: World, attempt: UploadAttempt, blobId: string) {
  const b = attempt.blobs.find((x) => x.blobId === blobId)!;
  const o = w.facts.outbox.find((e) => e.mutationId === attempt.mutationId)!.objects.find((x) => x.objectId === b.objectId)!;
  return {
    blobId,
    epochId: attempt.epochId,
    kind: b.kind,
    declaredSize: b.declaredSize,
    sha: b.ciphertextSha256,
    forDelete: b.forDelete,
    objectId: b.objectId,
    plaintext: b.kind === "CONTENT" && o.plaintext !== null ? text(o.plaintext) : null,
  };
}

function doPrepare(w: World, attempt: UploadAttempt, blobId: string): void {
  const sentAt = w.server.now;
  const { delivery, response } = deliver(w, () => prepare(w.server, w.replica, prepareRequest(w, attempt, blobId)));
  if (delivery !== "delivered" || !response) return;
  if (response.ok) w.facts = recordPrepared(w.facts, blobId, sentAt + response.expiresIn);
  else if (response.code !== "PENDING_BUDGET_EXCEEDED") {
    w.log.rejections.set(response.code, (w.log.rejections.get(response.code) ?? 0) + 1);
    w.facts = applyPrepareRejection(w.facts, attempt.mutationId, blobId, response.code);
    if (response.code === "EPOCH_STALE") w.facts = setWriteEpoch(w.facts, w.server.epoch);
  }
}

function runOutboxStep(w: World, s: OutboxStep, variant: Variant): void {
  const attemptOf = (mutationId: string) => w.facts.attempts.find((a) => a.mutationId === mutationId)!;
  const entryOf = (mutationId: string) => w.facts.outbox.find((e) => e.mutationId === mutationId)!;
  switch (s.kind) {
    case "release": {
      const { delivery, response } = deliver(w, () => release(w.server, w.replica, s.blobId));
      if (delivery === "delivered") w.facts = applyRelease(w.facts, s.blobId, response!);
      return;
    }
    case "revisionStatus": {
      w.log.statusQueries++;
      const e = entryOf(s.mutationId);
      const { delivery, response } = deliver(w, () => revisionStatus(w.server, e.objects.map((o) => o.revisionId)));
      if (delivery === "delivered") w.facts = applyRevisionStatus(w.facts, s.mutationId, response!);
      return;
    }
    case "encrypt": {
      const attempt = buildAttempt(w, s.mutationId);
      if (variant.prepareBeforePersist) {
        for (const b of attempt.blobs) {
          deliver(w, () => prepare(w.server, w.replica, prepareRequest(w, attempt, b.blobId)));
          if (chance(w, w.faults.crash)) {
            crash(w);
            return; // the attempt was never persisted: its PENDING blobs are unknown to the client
          }
        }
      }
      w.facts = recordAttempt(w.facts, attempt); // write-ahead: persisted before any request
      return;
    }
    case "retireExpired":
      w.log.expiredRetired++;
      w.facts = retireExpired(w.facts, s.mutationId, w.server.now);
      return;
    case "prepare":
      doPrepare(w, attemptOf(s.mutationId), s.blobId);
      return;
    case "put": {
      const attempt = attemptOf(s.mutationId);
      const b = attempt.blobs.find((x) => x.blobId === s.blobId)!;
      if (chance(w, w.faults.putTimeout)) {
        const o = entryOf(s.mutationId).objects.find((x) => x.objectId === b.objectId)!;
        w.facts = recordPutFailure(w.facts, o.objectId, o.localCompareHash);
        return;
      }
      const { delivery, response } = deliver(w, () => put(w.server, w.replica, s.blobId, b.ciphertext));
      if (delivery !== "delivered" || !response) return;
      if (response.ok) w.memory.putDone.add(s.blobId);
      else w.facts = applyPrepareRejection(w.facts, s.mutationId, s.blobId, response.code);
      return;
    }
    case "commit": {
      const e = entryOf(s.mutationId);
      const attempt = attemptOf(s.mutationId);
      w.facts = markCommitSent(w.facts, s.mutationId); // persisted before the request leaves
      const request = {
        mutationId: e.mutationId,
        epochId: attempt.epochId,
        revisions: e.objects.map((o) => ({
          objectId: o.objectId,
          revisionId: o.revisionId,
          expectedHeadRevisionId: o.expectedHeadRevisionId,
          deleted: o.deleted,
          manifestBlobId: attempt.blobs.find((b) => b.objectId === o.objectId && b.kind === "MANIFEST")!.blobId,
          contentBlobId: attempt.blobs.find((b) => b.objectId === o.objectId && b.kind === "CONTENT")?.blobId ?? null,
        })),
      };
      const { delivery, response } = deliver(w, () => commit(w.server, w.replica, request));
      if (delivery === "lost" && chance(w, w.faults.rotateOnLostCommit ?? 0)) rotateEpoch(w.server);
      let result: CommitResult | undefined = response;
      if (delivery !== "delivered" && variant.assumeCommittedWhenUnknown) {
        result = { kind: "COMMITTED", revisions: e.objects.map((o, i) => ({ objectId: o.objectId, revisionId: o.revisionId, sequence: 1e6 + i, createdSequence: 1 })) };
      }
      if (!result) return;
      if (result.kind === "REJECTED") w.log.rejections.set(result.code, (w.log.rejections.get(result.code) ?? 0) + 1);
      const applied = applyCommitResult(w.facts, s.mutationId, result, w.server.now);
      if (!applied.ok) throw new Error(`stored result of ${s.mutationId} does not match the outbox`);
      w.facts = applied.facts;
      if (result.kind === "COMMITTED") for (const r of result.revisions) w.known.add(r.revisionId);
      if (result.kind === "REJECTED" && result.code === "EPOCH_STALE") w.facts = setWriteEpoch(w.facts, w.server.epoch);
      return;
    }
  }
}

// ---------------------------------------------------------------------------
// Other actors (active until faults.activeUntil).

const REMOTE_CONTENTS = ["remote one", ["r", "s", "t"].join(String.fromCharCode(10)), ""];
const REMOTE_PATHS = ["n.md", "remote.md", "d/r.md", "N.md"];

function otherActors(w: World): void {
  if (chance(w, w.faults.remoteWrite)) {
    const live = [...w.server.heads.values()].filter((h) => !h.deleted);
    const pick = (xs: readonly string[]) => xs[Math.floor(random(w) * xs.length)]!;
    const r = random(w);
    if (live.length === 0 || r < 0.25) {
      remoteCommit(w.server, nextId(w, "0190a1b2-remote-"), { path: pick(REMOTE_PATHS), content: pick(REMOTE_CONTENTS), deleted: false });
    } else {
      const target = live[Math.floor(random(w) * live.length)]!;
      const deleted = r > 0.9;
      remoteCommit(w.server, target.objectId, { path: random(w) < 0.3 ? pick(REMOTE_PATHS) : target.path, content: deleted ? "" : `${pick(REMOTE_CONTENTS)}#${w.step}`, deleted });
    }
  }
  if (chance(w, w.faults.rotateEpoch)) rotateEpoch(w.server);
  if (chance(w, w.faults.expireRows)) expireMutationRows(w.server);
  if (chance(w, w.faults.prune)) prune(w.server);
  betweenSteps(w);
}

/** User activity (also between the steps of a physical operation). */
function betweenSteps(w: World): void {
  w.betweenStepsHook?.(w);
  userCreates(w);
  userEdit(w);
  userTouchesTmp(w);
  userMovesOrDeletes(w);
}

const MOVE_TARGETS = ["moved.md", "sub/moved.md", "d/moved.md", "n.md", "Foo/z.md"];

/** The user renames/moves a file, renames a whole folder, or deletes a file. */
function userMovesOrDeletes(w: World): void {
  if (!chance(w, w.faults.userMove)) return;
  // The user acts on files on disk; the client learns about it at the next observation.
  const busy = w.journal ? new Set([w.journal.destPath, w.journal.sourcePath]) : new Set<string | null>();
  const paths = userFiles(w).filter((p) => !busy.has(p));
  if (paths.length === 0) return;
  const from = paths[Math.floor(random(w) * paths.length)]!;
  const r = random(w);
  if (r < 0.3) {
    w.log.userDeletes++;
    const file = w.files.get(from)!;
    const id = file.truth ?? file.owner;
    if (id) w.userDeletedBase.set(id, { base: w.facts.synced.get(id)?.revisionId, content: file.content });
    // The user discards this content on purpose: it is no longer theirs to keep.
    for (const [k, h] of w.log.userContents) if (h === hash(file.content)) w.log.userContents.delete(k);
    w.files.delete(from);
    return;
  }
  const moves: Array<[string, string]> = [];
  if (r < 0.5 && from.includes("/")) {
    // Folder rename: every file of the folder moves (one rename per object, §16.5).
    const folder = from.slice(0, from.indexOf("/") + 1);
    const target = `${folder.slice(0, -1)}-renamed/`;
    for (const p of paths) if (p.startsWith(folder)) moves.push([p, target + p.slice(folder.length)]);
  } else {
    moves.push([from, MOVE_TARGETS[Math.floor(random(w) * MOVE_TARGETS.length)]!]);
    // Identical contents on several files (a copy kept next to the moved original): rule 11 must not pair.
    const copyAt = CREATE_PATHS[Math.floor(random(w) * CREATE_PATHS.length)]!;
    if (random(w) < 0.3 && isFree(w, copyAt, "")) {
      w.files.set(copyAt, newFile(w, null, w.files.get(from)!.content, "user"));
      w.log.pastes++;
      w.log.userContents.set(`created:${w.fids}`, hash(w.files.get(from)!.content));
    }
  }
  for (const [p, to] of moves) {
    if (!w.files.has(p) || !isFree(w, to, "")) continue;
    const file = w.files.get(p)!;
    w.files.delete(p);
    w.files.set(to, file);
    if (file.truth) w.userMoved.add(file.truth);
    w.log.userMoves++;
  }
}

/** Files the user can act on: everything except the client's temporaries. */
function userFiles(w: World): string[] {
  return [...w.files.keys()].filter((p) => !isTmpName(p)).sort();
}

function userEdit(w: World): void {
  if (chance(w, w.faults.userEdit)) {
    const paths = userFiles(w);
    if (paths.length > 0) {
      const p = paths[Math.floor(random(w) * paths.length)]!;
      const f = w.files.get(p)!;
      // The user replaces this file's content: whatever it held is the user's to discard.
      const previous = hash(f.content);
      for (const [k, h] of w.log.userContents) if (h === previous) w.log.userContents.delete(k);
      f.content = `user edit ${w.step}`;
      f.touched = true;
      w.log.userContents.set(`file:${f.fid}`, hash(f.content));
      w.log.wholeContents.add(f.content);
    }
  }
}

/** §44.1: the user edits a nodra-tmp-* file, or creates one holding a prefix of the open entry's content. */
function userTouchesTmp(w: World): void {
  if (!chance(w, w.faults.tmpTouch)) return;
  w.log.tmpTouches++;
  const e = w.journal;
  const setUser = (p: string, content: string, owner: string | null) => {
    const before = w.files.get(p);
    if (before) for (const [k, h] of w.log.userContents) if (h === hash(before.content)) w.log.userContents.delete(k);
    const existing = w.files.get(p);
    if (existing) {
      existing.content = content;
      existing.touched = true;
    } else w.files.set(p, { ...newFile(w, owner, content, "user") });
    w.log.userContents.set(`file:${p}`, hash(content));
    w.log.wholeContents.add(content);
  };
  if (e?.kind === "WRITE" && e.content && random(w) < 0.5) {
    const tp = tmpPath(e);
    // At the entry's own temporary path only before tmp_created (§44.1); after it, such a file is
    // indistinguishable from the entry's temporary and §15 may delete it (NOTES.md open question).
    const target = occupiedKey(w, tp) || e.tmpCreated ? `${dirOf(e.destPath)}nodra-tmp-${hex8(w)}` : tp;
    const whole = text(e.content);
    const prefix = whole.slice(0, 1 + Math.floor(random(w) * whole.length));
    if (!occupiedKey(w, target)) setUser(target, prefix, null);
    return;
  }
  const tmps = [...w.files.keys()].filter(isTmpName).sort();
  if (tmps.length === 0) return;
  const p = tmps[Math.floor(random(w) * tmps.length)]!;
  const file = w.files.get(p)!;
  setUser(p, `${file.content}${String.fromCharCode(10)}user line ${w.step}`, file.owner);
}

// ---------------------------------------------------------------------------

/** One page of listEvents (§13.2); CURSOR_EXPIRED or an invalid page → full reconciliation (§18.4). */
/** Returns true when something arrived (the client is not quiescent while events keep coming). */
function pollEvents(w: World, variant: Variant): boolean {
  const { delivery, response } = deliver(w, () => listEvents(w.server, w.facts.cursor));
  if (delivery !== "delivered" || !response) return false;
  if (response.kind === "CURSOR_EXPIRED") {
    reconcile(w);
    return true;
  }
  if (variant.acceptPartialPages) {
    // Broken: no §13.2 client defence; whatever arrives goes to R.
    const last = response.events[response.events.length - 1];
    w.facts = recordRemoteHeads(w.facts, response.events.flatMap((e) => (e.kind === "REVISION" ? [{ objectId: e.objectId, head: { revisionId: e.revisionId, sequence: e.sequence, path: e.path, localCompareHash: null, deleted: e.deleted, createdSequence: e.createdSequence } }] : [])));
    if (last) w.facts = { ...w.facts, cursor: last.sequence };
    return last !== undefined;
  }
  const applied = applyEvents(w.facts, response.events);
  if (applied.kind === "RECONCILE") {
    reconcile(w);
    return true;
  }
  w.facts = applied.facts;
  return response.events.length > 0;
}

/** §18.4: settle the outbox with getRevisionStatus, then take getVaultState. */
function reconcile(w: World): void {
  w.log.reconciliations++;
  for (const e of w.facts.outbox.filter((x) => x.commitSent)) {
    const { delivery, response } = deliver(w, () => revisionStatus(w.server, e.objects.map((o) => o.revisionId)));
    if (delivery !== "delivered") return; // try again on the next poll
    w.facts = applyRevisionStatus(w.facts, e.mutationId, response!);
  }
  const { delivery, response } = deliver(w, () => vaultState(w.server));
  if (delivery === "delivered") w.facts = applyVaultState(w.facts, response!);
}

// ---------------------------------------------------------------------------
// Attribution (rules 10-11), startup scan and import of untracked files (§15, §16.3, §18.4).

/** Re-derives which file is each object's from the disk, the recorded observations and the identities. */
/**
 * Oracle (w), recounted independently of the attribution under test. At a startup scan, a file that no
 * record claims by path is legitimately re-created (history lost, never content) when:
 * - its hash matches the last observation of some object whose recorded file is gone, but not uniquely
 *   in both directions (rule 11); or
 * - its own object's recorded path holds another file, which the startup scan attributes by path.
 */
function markUnpairable(w: World, recorded: ReadonlyArray<{ physicalPath: string | null; localCompareHash: string | null }>): void {
  const claimed = new Set(recorded.map((r) => r.physicalPath));
  const lost = recorded.filter((r) => r.physicalPath !== null && !w.files.has(r.physicalPath) && r.localCompareHash !== null);
  const free = [...w.files].filter(([p]) => !claimed.has(p));
  for (const f of w.files.values()) f.unpairable = false; // judged afresh at every startup
  for (const [, f] of free) {
    const h = hash(f.content);
    const objects = lost.filter((r) => r.localCompareHash === h).length;
    const files = free.filter(([, g]) => hash(g.content) === h).length;
    if (objects > 0 && (objects !== 1 || files !== 1)) f.unpairable = true;
    // Its own object's recorded path holds another file now: the startup scan takes that one by path (§15).
    const own = f.truth === null ? undefined : w.recorded.get(f.truth)?.physicalPath;
    if (own && w.files.has(own) && w.files.get(own) !== f) f.unpairable = true;
  }
}

export function rederive(w: World, variant: Variant): void {
  const recorded = [...w.recorded].map(([objectId, r]) => ({ objectId, physicalPath: r.physicalPath, localCompareHash: r.hash ?? null }));
  const disk = [...w.files].map(([path, f]) => ({ path, localCompareHash: hash(f.content), identity: String(f.fid) }));
  const identities = new Map([...w.identity].map(([o, fid]) => [o, String(fid)]));
  const startup = !w.memory.scanned;
  w.memory.scanned = true;
  if (startup) markUnpairable(w, recorded);
  const a = (variant.attribute ?? attributeFiles)(recorded, disk, identities, { startup });
  const paired = new Set(a.paired.map((p) => p.objectId));
  // Oracle (v): a pairing needs the exact hash of the last observation and a unique match both ways,
  // recounted here independently of attributeFiles.
  const claimed = new Set(identities.values());
  const pairedPaths = new Set(a.paired.map((p) => p.path));
  const untracked = new Set(a.untracked);
  for (const p of a.paired) {
    w.log.pairings++;
    const h = hash(w.files.get(p.path)!.content);
    const objects = recorded.filter((r) => r.localCompareHash === h && !identities.has(r.objectId) && (!a.byObject.has(r.objectId) || paired.has(r.objectId)));
    const files = disk.filter((d) => d.localCompareHash === h && !claimed.has(d.identity) && (untracked.has(d.path) || pairedPaths.has(d.path)));
    const exact = w.recorded.get(p.objectId)?.hash === h;
    if (!exact || objects.length !== 1 || files.length !== 1) {
      w.log.identityViolations.push(`(v) ${p.objectId} paired with ${p.path} (exact ${exact}, objects ${objects.length}, files ${files.length})`);
    }
  }
  for (const f of w.files.values()) f.owner = null;
  w.bound.clear();
  w.gone.clear();
  for (const [o, p] of a.byObject) {
    const f = w.files.get(p)!;
    // Oracle (u): while the instance runs, a file is registered as an object's state only if it is that
    // object. At startup, the scan by path and rule-11 pairing are the spec's own (no identities exist).
    if (!startup && f.truth !== o) w.log.identityViolations.push(`(u) ${o} took ${p}, which is ${f.truth ?? "nobody's"}`);
    f.owner = o;
    f.truth = o;
    w.bound.set(o, p);
    w.identity.set(o, f.fid);
    const r = w.recorded.get(o)!;
    w.recorded.set(o, { ...r, hash: hash(f.content) });
  }
  for (const o of a.absent) {
    w.gone.add(o);
    const r = w.recorded.get(o)!;
    if (!identities.has(o) && r.hash && a.untracked.filter((p) => hash(w.files.get(p)!.content) === r.hash).length > 0) w.log.ambiguous++;
    // The observed absence is the new last observation (§12.2 table): the record no longer claims its
    // old path, which the client may give to another object.
    w.recorded.set(o, { ...r, physicalPath: null, hash: null });
  }
  // Persists moves observed now (§12.2 table), whether or not the planner runs this tick.
  if ([...w.bound].some(([o, p]) => w.recorded.get(o)?.physicalPath !== p)) observe(w);
}

/**
 * An untracked file (not a nodra-tmp-* or recovery file, which §15 handles) becomes an object: adopted
 * when it is exactly the projection of an object not on disk (§18.4 step 5), otherwise a new object that
 * the planner uploads as a creation.
 */
function importUntracked(w: World, variant: Variant): boolean {
  if (variant.noImport) return false;
  const candidates = [...w.files].filter(([p, f]) => f.owner === null && !isTmpName(p) && !isRecoveryName(p)).map(([p]) => p).sort();
  if (candidates.length === 0) return false;
  for (const p of candidates) {
    const file = w.files.get(p)!;
    const adopted = adoptable(w, p, file);
    const c = canonicalizePath(p);
    if (!adopted && !c.ok) continue;
    const id = adopted ?? `0190a1b2-imp-${w.prefix}${(w.ids++).toString(36)}`;
    if (adopted) w.log.adoptions++;
    else {
      w.log.imports++;
      // Oracle (w): the client never creates an object from a file it wrote itself and the user never touched.
      if (file.origin === "client" && !file.touched && !file.unpairable) w.log.identityViolations.push(`(w) spurious object from ${p}`);
      file.unpairable = false;
    }
    file.owner = id;
    file.truth = id;
    w.bound.set(id, p);
    w.identity.set(id, file.fid);
    const logical = adopted ? (w.facts.remote.get(adopted) ?? w.facts.synced.get(adopted))!.path : (c as { path: string }).path;
    w.recorded.set(id, { logicalPath: logical, physicalPath: p, hash: hash(file.content) });
    w.notMaterialized.delete(id);
  }
  return true;
}

/** §18.4 step 5: the file is exactly the projection (path and content) of an object not on disk. */
function adoptable(w: World, path: string, file: DiskFileState): string | null {
  const heads = new Map([...w.facts.synced, ...w.facts.remote]);
  const objects = [...heads].filter(([, h]) => !h.deleted).map(([objectId, h]) => ({ objectId, logicalPath: h.path, createdSequence: h.createdSequence }));
  const others = [...w.files].filter(([p, f]) => f.owner === null && p !== path).map(([p]) => p);
  const projection = project({ objects, untrackedFiles: others });
  for (const [id, f] of projection.files) {
    if (f.physicalPath !== path || w.bound.has(id) || w.recorded.has(id)) continue;
    const r = w.server.revisions.get(heads.get(id)!.revisionId);
    if (r && w.known.has(r.revisionId) && hash(r.content) === hash(file.content)) return id;
  }
  return null;
}

const CREATE_PATHS = ["new.md", "notes/new.md", "n.md", "N.md", "pasted.md", "d/new.md"];

/** The user creates a file: new content, or a paste of another file's exact bytes. */
function userCreates(w: World): void {
  if (!chance(w, w.faults.userCreate ?? 0)) return;
  const path = CREATE_PATHS[Math.floor(random(w) * CREATE_PATHS.length)]!;
  if (!isFree(w, path, "")) return;
  const sources = [...w.files].filter(([p]) => !isTmpName(p)).sort(([a], [b]) => (a < b ? -1 : 1));
  const paste = sources.length > 0 && random(w) < 0.4;
  const content = paste ? sources[Math.floor(random(w) * sources.length)]![1].content : `created by the user at ${w.step}`;
  w.files.set(path, newFile(w, null, content, "user"));
  w.log.userContents.set(`created:${w.fids}`, hash(content));
  w.log.wholeContents.add(content);
  if (paste) w.log.pastes++;
  else w.log.userCreates++;
}

/** One loop iteration. Returns false when the client has nothing to do (quiescent). */
export function tick(w: World, variant: Variant): boolean {
  if (chance(w, w.faults.reload ?? 0)) {
    w.log.reloads++;
    crash(w); // plugin reload: identities are gone; the startup scan attributes by path (§15)
  }
  // A new instance resolves the open journal entry before observing anything (§15).
  if (w.journal === null) rederive(w, variant);
  if (w.journal !== null || handleStrays(w) || importUntracked(w, variant)) {
    if (w.journal !== null) replayJournal(w, variant);
    otherActors(w);
    w.server.now++;
    w.step++;
    return true;
  }
  const received = chance(w, w.faults.skipPoll) ? false : pollEvents(w, variant);
  const f = variant.skipRelease ? { ...w.facts, cleanup: [] } : w.facts;
  const s = nextOutboxStep(f, w.server.now, w.memory.putDone);
  // The outbox runs alongside the planner (as a real client does): odd steps plan first.
  let busy = true;
  if (s && w.step % 2 === 0) runOutboxStep(w, s, variant);
  else {
    const input = observe(w);
    const actions = variant.planner(input);
    const first = actions[0];
    if (first?.kind === "upload") enqueue(w, input, actions.filter((a): a is Extract<Action, { kind: "upload" }> => a.kind === "upload"), variant);
    else if (first) execute(w, input, first, variant);
    else if (s) runOutboxStep(w, s, variant);
    else busy = false;
  }
  const acting = w.step < w.faults.activeUntil;
  otherActors(w);
  w.server.now++;
  w.step++;
  return busy || acting || received;
}

/**
 * Runs until quiescent (and past the active phase) or `maxSteps`. Returns the step count, or null if
 * the bound was hit. `onStep` sees the world after every step.
 */
export function run(w: World, variant: Variant | Planner = { planner: plan }, maxSteps = 300, onStep?: (w: World) => boolean | void): number | null {
  const v: Variant = typeof variant === "function" ? { planner: variant } : variant;
  while (w.step < maxSteps) {
    const busy = tick(w, v);
    if (onStep?.(w) === true) return null; // the caller saw enough (e.g. an invariant violation)
    if (!busy) return w.step;
  }
  return null;
}

/** The projection of the confirmed tree (at rest L = R = S), with this replica's untracked files. */
export function restingProjection(w: World) {
  const objects = [...w.server.heads.values()]
    .filter((h) => !h.deleted)
    .map((h) => ({ objectId: h.objectId, logicalPath: h.path, createdSequence: h.createdSequence }));
  const untrackedFiles = [...w.files].filter(([, f]) => f.owner === null).map(([p]) => p);
  return project({ objects, untrackedFiles });
}

export const canonical = (p: string) => {
  const c = canonicalizePath(p);
  if (!c.ok) throw new Error(`not canonical: ${p}`);
  return c.path;
};
