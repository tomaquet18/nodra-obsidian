import { canonicalizePath, project } from "@nodra/path-projection";
import {
  type Action,
  type ClientFacts,
  type CommitResult,
  type Content,
  type LocalCompareHash,
  type LocalCompareHashOrAbsent,
  type LocalEntry,
  type ObjectId,
  type OutboxStep,
  type PhysicalPath,
  type PlanInput,
  type RecordedFile,
  type RevisionEntry,
  type RevisionId,
  type AttemptBlob,
  type ContentArrival,
  type UploadAttempt,
  type UploadRequest,
  PROJECTION_RENAME_ARRIVALS_TO_PAUSE,
  acknowledgeArrivals,
  applyCommitResult,
  applyEvents,
  applyPrepareRejection,
  applyRelease,
  applyRevisionStatus,
  applyVaultState,
  attributeFiles,
  blockContent,
  contentArrivals,
  enqueueUploads,
  expectedProjectionMoves,
  isDeleteOnly,
  isRecoveryName,
  isTmpName,
  markCommitSent,
  bytesEqual,
  isMergeablePath,
  nextOutboxStep,
  plan,
  projectionRenameArrivals,
  recordAttempt,
  renameArrivals,
  recordPrepared,
  recordPutFailure,
  resolveLocal,
  resolveLocalPaths,
  retireExpired,
  setWriteEpoch,
  strayDisposition,
} from "@nodra/sync-core";
import { decodeText, mergeContent } from "./content.js";
import type { ManifestInput } from "./manifest.js";
import { type Shell, commit, deleteEntry, importRecovery, listAll, readIfExists, renameEntry, replayOpenEntry, runEntry, writeEntry } from "./executor.js";
import { type LeaderMessage, processNextIntent } from "./intents.js";
import { type BlobCrypto, type Stat, type SyncBackend, UPLOAD_TIMEOUT } from "./ports.js";
import { CONDITION_CODES, type Hold, type HoldScope, SERVER_TIMED_CODES, failureOf, reactionTo } from "./retry.js";
import { type FileStatEntry, OBSERVED_BYTES_BUDGET, cachedHash, displacedPairs, statEntry } from "./stat-cache.js";
import type { Observation, VaultState } from "./state.js";

// The runner (§12.2 principle): load facts → observe → plan → execute the FIRST action → persist, and
// again. Nothing about "where we were" is persisted: after a crash a new instance replays the open
// journal entry (§15), observes, and plans. A thrown error ends the tick; persisted facts stay valid.

export interface Client {
  readonly shell: Shell;
  readonly backend: SyncBackend;
  readonly blobs: BlobCrypto;
  /** Monotonic clock (§12.1): only compared with deadlines derived from it. */
  readonly now: () => number;
  /** `pending_budget_bytes` of the plan (§22 getRootState). */
  readonly pendingBudgetBytes: number;
  /**
   * `max_blob_bytes` of the plan (§11.2, §22 getRootState). A content whose blob would exceed it is blocked
   * (rule 8, `BLOB_TOO_LARGE`) before it is sealed or prepared; absent, only the server's answer blocks it.
   */
  readonly maxBlobBytes?: number;
  /**
   * The device's wall clock in ms since the epoch, only compared with `clock` modification times
   * (stat-cache.ts). Absent: a `clock` marker never lets the observation skip a hash.
   */
  readonly wallClock?: () => number;
  /** In-memory only; a new instance starts empty (rule 13: PUT progress lives in memory). */
  readonly memory: {
    readonly putDone: Set<string>;
    /** Revisions whose bytes the backend reported pruned (§10.6). */
    readonly pruned: Set<RevisionId>;
    /** The instance already ran its startup scan (§15). */
    scanned: boolean;
    /** Untracked files at the last observation. */
    untracked: PhysicalPath[];
    turn: number;
    /** §20.2: a channel message (or a row left) asks for a sweep of pending_intents. */
    intentHint: boolean;
    /** `now` of the last sweep; null before the first one (a new leader sweeps at once). */
    lastSweep: number | null;
    /**
     * The bytes read by the last observation (cache misses only, up to OBSERVED_BYTES_BUDGET), so that the
     * upload planned right after it compares bytes instead of hashing them again (question 147).
     */
    observed: Map<PhysicalPath, { readonly content: Content; readonly hash: LocalCompareHash }>;
    /** The wait after a failed request, per scope (retry.ts): never persisted, a restart asks again. */
    holds: Record<HoldScope, Hold | null>;
    /** Consecutive failures per backend operation (the backoff exponent); an answer to it resets its count. */
    readonly failures: Map<keyof SyncBackend, number>;
    /**
     * §20.2: projection renames of another replica seen since this instance last did one itself. In memory:
     * a restart or a resume starts again from 0 (NOTES question 419).
     */
    projectionRenameArrivals: number;
    /** Renames of another replica already counted (`objectId|destination`): each counts once. */
    readonly countedRenames: Set<string>;
    /** local_compare_hash of the empty content (exempt from the content rule), once computed. */
    emptyHash: LocalCompareHash | null;
  };
  /** Diagnostics for tests and the panel (merges, conflict copies, cancelled operations...). */
  readonly log?: (event: { readonly kind: string; readonly objectId?: ObjectId; readonly detail?: string }) => void;
  /** The leader's channel (§20.2): acks to the followers. */
  readonly notify?: (message: LeaderMessage) => void;
  /** INTENT_RESCAN in `now` units (default intents.ts INTENT_RESCAN). */
  readonly intentRescan?: number;
  /**
   * §20.2 "Nodra es el único sincronizador de la carpeta", at run time (NOTES questions 417, 419): when
   * present, a remote revision found on disk before this replica wrote it, or PROJECTION_RENAME_ARRIVALS_TO_PAUSE
   * projection renames of another replica in a row, stop sync (OtherSyncToolError) before anything is sent.
   * Absent (the default): no check. Only the plugin sets it; the web has no disk another tool can write.
   * `acknowledged`: arrivals the user accepted ("I removed the other tool, resume"); the leader persists
   * them at its next check and empties the list.
   */
  readonly otherSyncTool?: { readonly acknowledged: ContentArrival[] };
}

/** An arrival as the host shows it: the object's local path. */
export interface ShownArrival extends ContentArrival {
  readonly path: string;
}

/**
 * §20.2: another tool seems to sync this vault's folder. Sync stops (retry.ts OTHER_SYNC_TOOL) until the
 * user resolves it; the content arrivals are what "resume" accepts. `renames`: projection renames of
 * another replica seen in a row (0 when content arrived).
 */
export class OtherSyncToolError extends Error {
  override readonly name = "OtherSyncToolError";
  readonly code = "OTHER_SYNC_TOOL";
  constructor(
    readonly arrivals: readonly ShownArrival[],
    readonly renames: number,
  ) {
    super(`another tool seems to be syncing this folder (${arrivals.length > 0 ? arrivals.map((a) => a.path).join(", ") : `${renames} renames`})`);
  }
}

export function newMemory(): Client["memory"] {
  return { putDone: new Set(), pruned: new Set(), scanned: false, untracked: [], turn: 0, intentHint: true, lastSweep: null, observed: new Map(), holds: { all: null, writes: null, nonDeletes: null }, failures: new Map(), projectionRenameArrivals: 0, countedRenames: new Set(), emptyHash: null };
}

// ---------------------------------------------------------------------------
// Holds (retry.ts): a failed request makes the client wait instead of asking again at every tick.

const held = (c: Client, scope: HoldScope): boolean => {
  const h = c.memory.holds[scope];
  return h !== null && c.now() < h.until;
};

/**
 * The earliest `now` at which a held request goes again (possibly past: the next tick sends it), or null:
 * nothing held, or only holds that wait for their condition to change (Infinity). A hold lasts until an
 * answer ends it. The controller sleeps until then; test harnesses treat a client with a pending retry as
 * not at rest.
 */
export function retryAt(c: Pick<Client, "memory">): number | null {
  const times = Object.values(c.memory.holds).filter((h): h is Hold => h !== null && Number.isFinite(h.until)).map((h) => h.until);
  return times.length === 0 ? null : Math.min(...times);
}

/** The hold that currently stops requests (the widest first), for the status line. */
export function activeHold(c: Pick<Client, "memory" | "now">): Hold | null {
  for (const h of [c.memory.holds.all, c.memory.holds.writes, c.memory.holds.nonDeletes]) if (h !== null && c.now() < h.until) return h;
  return null;
}

/**
 * The condition may have changed: holds waiting for it go at once (their failure count stays, so no new
 * notice). `user` ("Sync now") also cuts short the backoff of unknown outcomes; never a wait the server set.
 */
export function releaseHolds(c: Pick<Client, "memory" | "now">, why: "event" | "user"): void {
  for (const scope of ["all", "writes", "nonDeletes"] as const) {
    const h = c.memory.holds[scope];
    if (h === null || SERVER_TIMED_CODES.has(h.code)) continue;
    const release = why === "user" || CONDITION_CODES.has(h.code) || h.code === "PENDING_BUDGET_EXCEEDED";
    if (release) c.memory.holds[scope] = { ...h, until: Math.min(h.until, c.now()) };
  }
}

const WRITE_OPS: ReadonlySet<keyof SyncBackend> = new Set(["prepareUpload", "uploadBlob", "commitMutation", "releaseUpload"]);

/**
 * A request failed: stop (rethrown: the controller pauses) or hold its scope with the next backoff. The
 * exponent counts this operation's failures in a row: an answer to another request (a poll between two
 * failed commits) ends the hold but does not shorten the next wait. A code some scope already holds
 * (QUOTA_EXCEEDED of a delete after that of an edit) is not logged again: the user is told once.
 */
function failed(c: Client, op: keyof SyncBackend, error: unknown, deletesOnly = false): void {
  const failure = failureOf(error);
  const failures = (c.memory.failures.get(op) ?? 0) + 1;
  const r = reactionTo(failure, failures, { deletesOnly });
  if (r.kind === "stop") {
    c.log?.({ kind: "stop", detail: r.code });
    throw error;
  }
  c.memory.failures.set(op, failures);
  const known = Object.values(c.memory.holds).some((h) => h?.code === r.code);
  c.memory.holds[r.scope] = { scope: r.scope, code: r.code, until: c.now() + r.delaySeconds };
  if (!known) c.log?.({ kind: "hold", detail: r.code });
}

/**
 * A request got an answer: the holds it proves over end. Any answer ends "all"; a write answer ends
 * "writes"; only the answer to a request a "nonDeletes" hold was holding ends that one (a delete going
 * through says nothing about the quota of the rest, §40.1). A code still held elsewhere is not resumed.
 */
function answered(c: Client, op: keyof SyncBackend, deletesOnly = false): void {
  c.memory.failures.delete(op);
  const scopes: readonly HoldScope[] = !WRITE_OPS.has(op) ? ["all"] : deletesOnly ? ["all", "writes"] : ["all", "writes", "nonDeletes"];
  const ended = new Set<string>();
  for (const scope of scopes) {
    const h = c.memory.holds[scope];
    if (h === null) continue;
    c.memory.holds[scope] = null;
    ended.add(h.code);
  }
  for (const code of ended) if (!Object.values(c.memory.holds).some((h) => h?.code === code)) c.log?.({ kind: "resume", detail: code });
}

// ---------------------------------------------------------------------------
// Observation (§12.2 rule 2, rules 10-12, §15 startup scan, Q45: persisted at every observation).

/** Re-reads the disk, attributes files to objects and persists the observation. Returns true if it did extra work (stray or import). */
export async function observeDisk(c: Client): Promise<boolean> {
  const { shell } = c;
  const { files } = await listAll(shell.fs);
  const disk: Array<{ path: PhysicalPath; hash: LocalCompareHash; identity: string }> = [];
  // The observation cache (stat-cache.ts): a file is hashed unless its stat proves the cached hash.
  const marker = shell.fs.changeMarker;
  const fileStats = new Map<PhysicalPath, FileStatEntry>();
  c.memory.observed = new Map();
  let observedBytes = 0;
  let hits = 0;
  // Every stat first (each after its own `readAt`), so that a pair displaced anywhere is known before any hit.
  const stats = new Map<PhysicalPath, { readonly stat: Stat; readonly readAt: number | null }>();
  if (marker !== undefined) {
    for (const path of files) {
      const readAt = c.wallClock?.() ?? null;
      const stat = await shell.fs.stat(path);
      if (stat !== null) stats.set(path, { stat, readAt });
    }
  }
  const displaced = displacedPairs(shell.state.fileStats, new Map([...stats].map(([p, s]) => [p, s.stat])));
  for (const path of files) {
    const { stat: st = null, readAt = null } = stats.get(path) ?? {};
    if (marker !== undefined && st?.type !== "file") continue; // gone since the listing: the next observation sees it
    const prior = shell.state.fileStats.get(path);
    const cached = st === null ? null : cachedHash(prior, st, marker, readAt, displaced);
    if (cached !== null) {
      fileStats.set(path, prior!);
      hits++;
      disk.push({ path, hash: cached, identity: shell.fs.identityOf(path) ?? `path:${path}` });
      continue;
    }
    const content = await readIfExists(shell.fs, path);
    if (content === null) continue;
    const hash = await shell.hasher.hash(content);
    const entry = st === null ? null : statEntry(st, content, hash, marker, readAt);
    if (entry !== null) fileStats.set(path, entry);
    if (observedBytes + content.byteLength <= OBSERVED_BYTES_BUDGET) {
      c.memory.observed.set(path, { content, hash });
      observedBytes += content.byteLength;
    }
    disk.push({ path, hash, identity: shell.fs.identityOf(path) ?? `path:${path}` });
  }
  if (hits > 0) c.log?.({ kind: "cache-hit", detail: `${hits}/${files.length}` });
  const s = shell.state;
  const recorded: RecordedFile[] = [];
  for (const [objectId, o] of s.observations) {
    if (o.kind === "PRESENT") recorded.push({ objectId, physicalPath: o.physicalPath, localCompareHash: o.hash });
    else if (o.kind === "ABSENT") recorded.push({ objectId, physicalPath: null, localCompareHash: null });
  }
  const startup = !c.memory.scanned;
  c.memory.scanned = true;
  const a = attributeFiles(
    recorded,
    disk.map((d) => ({ path: d.path, localCompareHash: d.hash, identity: d.identity })),
    shell.identities,
    { startup },
  );
  const hashOf = new Map(disk.map((d) => [d.path, d.hash]));
  if (c.otherSyncTool !== undefined) countProjectionRenameArrivals(c, hashOf);
  const observations = new Map(s.observations);
  const local = new Map<ObjectId, LocalEntry>();
  shell.identities.clear();
  for (const [objectId, path] of a.byObject) {
    const prev = s.observations.get(objectId);
    const logicalPath = prev && prev.kind !== "NOT_MATERIALIZED" ? prev.logicalPath : path;
    const recordedPhysical = prev?.kind === "PRESENT" ? prev.physicalPath : path;
    local.set(objectId, { kind: "PRESENT", path: logicalPath, physicalPath: path, recordedPhysicalPath: recordedPhysical, localCompareHash: hashOf.get(path)! });
    observations.set(objectId, { kind: "PRESENT", logicalPath, physicalPath: path, hash: hashOf.get(path)! });
    const identity = shell.fs.identityOf(path);
    if (identity !== null) shell.identities.set(objectId, identity);
  }
  for (const objectId of a.absent) {
    const prev = s.observations.get(objectId);
    if (prev && prev.kind !== "NOT_MATERIALIZED") observations.set(objectId, { kind: "ABSENT", logicalPath: prev.logicalPath });
  }
  // Rule 12: a moved file's logical path comes from the physical → logical rule; persisted now (Q45).
  const input = planInput(c, { ...s, observations }, local, a.untracked);
  const { local: resolved, unrepresentable } = resolveLocal(input);
  for (const [objectId, l] of local) {
    const r = resolved.get(objectId);
    if (l.kind !== "PRESENT" || r?.kind !== "PRESENT" || l.physicalPath === l.recordedPhysicalPath || unrepresentable.has(objectId)) continue;
    observations.set(objectId, { kind: "PRESENT", logicalPath: r.path, physicalPath: r.physicalPath, hash: r.localCompareHash });
  }
  c.memory.untracked = [...a.untracked];
  await commit(shell, { ...s, observations, fileStats });
  if (await handleStray(c, a.untracked)) return true;
  return importUntracked(c, a.untracked);
}

/**
 * §20.2: planned projection moves (§16.7, from the last observation) that are already done on the disk,
 * without this replica. Only computed when a recorded file left its path (the planner is not run otherwise).
 */
function countProjectionRenameArrivals(c: Client, disk: ReadonlyMap<PhysicalPath, LocalCompareHash>): void {
  const s = c.shell.state;
  if (![...s.observations.values()].some((o) => o.kind === "PRESENT" && !disk.has(o.physicalPath))) return;
  const before = planInput(c, s);
  const moves = expectedProjectionMoves(before);
  for (const objectId of projectionRenameArrivals(before, disk)) countRename(c, objectId, moves.get(objectId)!.to);
}

/** One rename of another replica, counted once per (object, destination) whichever rule saw it first. */
function countRename(c: Client, objectId: ObjectId, to: PhysicalPath): void {
  const key = `${objectId}|${to}`;
  if (c.memory.countedRenames.has(key)) return;
  c.memory.countedRenames.add(key);
  c.memory.projectionRenameArrivals++;
  c.log?.({ kind: "other-sync-rename", objectId, detail: to });
}

/**
 * §20.2 (NOTES question 419): persists what the user accepted, then stops sync if a remote revision is on
 * disk before this replica wrote it, or after PROJECTION_RENAME_ARRIVALS_TO_PAUSE renames of another
 * replica in a row. Runs after the poll (R is current) and before anything is planned or sent.
 */
async function checkOtherSyncTool(c: Client, o: NonNullable<Client["otherSyncTool"]>): Promise<void> {
  if (o.acknowledged.length > 0) {
    const accepted = o.acknowledged.splice(0);
    await commit(c.shell, { ...c.shell.state, otherSync: acknowledgeArrivals(c.shell.state.otherSync, accepted) });
  }
  c.memory.emptyHash ??= await c.shell.hasher.hash(new Uint8Array());
  const s = c.shell.state;
  const input = planInput(c, s);
  const arrivals = contentArrivals(input, s.otherSync, c.memory.emptyHash);
  for (const a of renameArrivals(input)) {
    const l = input.local.get(a.objectId);
    if (l?.kind === "PRESENT") countRename(c, a.objectId, l.physicalPath);
  }
  const renames = c.memory.projectionRenameArrivals;
  if (arrivals.length === 0 && renames < PROJECTION_RENAME_ARRIVALS_TO_PAUSE) return;
  const shown = arrivals.map((a) => {
    const obs = s.observations.get(a.objectId);
    return { ...a, path: obs !== undefined && obs.kind !== "NOT_MATERIALIZED" ? obs.logicalPath : a.objectId };
  });
  c.log?.({ kind: "other-sync-tool", detail: shown.map((a) => a.path).join(", ") || `${renames} renames` });
  throw new OtherSyncToolError(shown, arrivals.length > 0 ? 0 : renames);
}

/** One nodra-tmp-* or unimported nodra-recuperado-* file bound to nothing (§15). */
async function handleStray(c: Client, untracked: readonly PhysicalPath[]): Promise<boolean> {
  const stray = untracked.find((p) => isTmpName(p) || isRecoveryName(p));
  if (stray === undefined) return false;
  const content = await readIfExists(c.shell.fs, stray);
  if (content === null) return true;
  // Only a temporary can be deleted as empty. Nodra never makes an empty recovery note (§15), so an empty
  // `nodra-recuperado-*.md` is the user's file (§44.5): it is imported like any other note.
  if (isTmpName(stray) && strayDisposition(content) === "DELETE") {
    // Our temporary (§15): re-read right before deleting; a failure means the user acted first.
    const again = await readIfExists(c.shell.fs, stray);
    if (again !== null && bytesEqual(again, content)) await c.shell.fs.remove(stray).catch(() => undefined);
  } else await importRecovery(c.shell, stray);
  return true;
}

/**
 * Untracked files become objects (Q19): adopted when exactly the projection (path and content) of an
 * object not on disk (§18.4 step 5), otherwise new objects the planner uploads as creations.
 */
async function importUntracked(c: Client, untracked: readonly PhysicalPath[]): Promise<boolean> {
  const { shell } = c;
  const candidates = untracked.filter((p) => !isTmpName(p) && !isRecoveryName(p));
  if (candidates.length === 0) return false;
  const s = shell.state;
  const heads = new Map([...s.facts.synced, ...s.facts.remote]);
  const objects = [...heads].filter(([, h]) => !h.deleted).map(([objectId, h]) => ({ objectId, logicalPath: h.path, createdSequence: h.createdSequence }));
  const observations = new Map(s.observations);
  let changed = false;
  for (const p of candidates) {
    const content = await readIfExists(shell.fs, p);
    if (content === null) continue;
    const hash = await hashRead(c, p, content);
    const projection = project({ objects, untrackedFiles: untracked.filter((u) => u !== p) });
    let adopted: ObjectId | null = null;
    for (const [id, f] of projection.files) {
      if (f.physicalPath !== p || observations.has(id)) continue;
      const head = heads.get(id)!;
      if (s.hashes.get(head.revisionId) === hash) adopted = id;
    }
    const canonical = canonicalizePath(p);
    if (adopted === null && !canonical.ok) continue;
    const id = adopted ?? shell.newId("import-");
    const logicalPath = adopted !== null ? heads.get(adopted)!.path : (canonical as { path: string }).path;
    observations.set(id, { kind: "PRESENT", logicalPath, physicalPath: p, hash });
    const identity = shell.fs.identityOf(p);
    if (identity !== null) shell.identities.set(id, identity);
    c.log?.({ kind: adopted !== null ? "adopt" : "import", objectId: id, detail: p });
    changed = true;
  }
  if (changed) await commit(shell, { ...s, observations });
  return changed;
}

// ---------------------------------------------------------------------------
// Planner input (§12.2): observed L, S and R with the cached local_compare_hash, the outbox.

function withHash(s: VaultState, e: RevisionEntry): RevisionEntry {
  return { ...e, localCompareHash: e.deleted ? null : (s.hashes.get(e.revisionId) ?? e.localCompareHash) };
}

export function planInput(c: Client, s: VaultState, local?: Map<ObjectId, LocalEntry>, untracked?: readonly PhysicalPath[]): PlanInput {
  const l = local ?? new Map<ObjectId, LocalEntry>();
  if (local === undefined) {
    for (const [objectId, o] of s.observations) l.set(objectId, localEntry(o));
  } else {
    for (const [objectId, o] of s.observations) if (!l.has(objectId)) l.set(objectId, localEntry(o));
  }
  const synced = new Map([...s.facts.synced].map(([id, e]) => [id, withHash(s, e)]));
  const remote = new Map([...s.facts.remote].map(([id, e]) => [id, withHash(s, e)]));
  return {
    local: l,
    remote,
    synced,
    outbox: s.facts.outbox,
    blocked: s.facts.blocked,
    textObjects: textObjects(l, remote, synced),
    prunedRevisions: c.memory.pruned,
    untrackedFiles: untracked ?? c.memory.untracked,
    tmpHex: [c.shell.hex8(), c.shell.hex8(), c.shell.hex8(), c.shell.hex8()],
  };
}

function localEntry(o: Observation): LocalEntry {
  switch (o.kind) {
    case "PRESENT":
      return { kind: "PRESENT", path: o.logicalPath, physicalPath: o.physicalPath, recordedPhysicalPath: o.physicalPath, localCompareHash: o.hash ?? "" };
    case "ABSENT":
      return { kind: "ABSENT" };
    case "NOT_MATERIALIZED":
      return { kind: "NOT_MATERIALIZED", reason: "LOCAL_PATH_TOO_LONG" };
  }
}

// ---------------------------------------------------------------------------
// One tick.

/** One loop iteration. Returns false when there was nothing to do. */
export async function tick(c: Client): Promise<boolean> {
  // A new instance resolves the open journal entry before observing anything (§15).
  if (c.shell.state.journal !== null) {
    c.log?.({ kind: "action", detail: "replay" });
    const outcome = await replayOpenEntry(c.shell); // never inside `log?.(...)`: it would be skipped without a log (Q121)
    c.log?.({ kind: `replay:${outcome}` });
    return true;
  }
  c.log?.({ kind: "action", detail: "observe" });
  if (await observeDisk(c)) return true;
  // Follower edits are local edits: decided on the state just observed, before remote events (§20.2).
  if (await processNextIntent(c)) return true;
  // Outcome unknown (retry.ts): no request at all until the backoff ends; the local work above goes on.
  // Once it ends, the tick sends both its poll and its outbox step even if the poll fails again: a broken
  // read path (events the client cannot apply) must not starve the uploads, nor the other way round.
  if (held(c, "all")) return false;
  const received = await poll(c);
  if (c.otherSyncTool !== undefined) await checkOtherSyncTool(c, c.otherSyncTool);
  // QUOTA_EXCEEDED (§12.6): while what needs quota waits, delete-only entries still go.
  const step = held(c, "writes") ? null : nextOutboxStep(c.shell.state.facts, c.now(), c.memory.putDone, { deletesOnly: held(c, "nonDeletes") });
  // A lapsed write hold with nothing left to send has nothing to retry (retryAt would never clear).
  if (step === null) for (const scope of ["writes", "nonDeletes"] as const) if (c.memory.holds[scope] !== null && !held(c, scope)) c.memory.holds[scope] = null;
  let busy = true;
  if (step && c.memory.turn++ % 2 === 0) await runOutboxStep(c, step);
  else {
    const input = planInput(c, c.shell.state);
    const actions = plan(input);
    const first = actions[0];
    if (first?.kind === "upload") await enqueue(c, input, actions.filter((a): a is Extract<Action, { kind: "upload" }> => a.kind === "upload"));
    else if (first) await execute(c, input, first);
    else if (step) await runOutboxStep(c, step);
    else busy = false;
  }
  return busy || received;
}

async function setFacts(c: Client, facts: ClientFacts, hashes?: ReadonlyMap<RevisionId, LocalCompareHash>): Promise<void> {
  await commit(c.shell, { ...c.shell.state, facts, hashes: hashes ?? c.shell.state.hashes });
}

/**
 * A backend call whose outcome may be unknown: null when it failed (the request or its response was lost,
 * or the server refused it), after holding its scope; a stop code is rethrown (retry.ts). `refused` names
 * an answer that is a refusal to wait on (PENDING_BUDGET_EXCEEDED, a release refused for a live lease).
 * `deletesOnly`: a request a "nonDeletes" hold lets through (retry.ts).
 */
async function call<T>(c: Client, op: keyof SyncBackend, p: () => Promise<T>, refused?: (out: T) => string | null, deletesOnly = false): Promise<T | null> {
  let out: T;
  try {
    out = await p();
  } catch (e) {
    failed(c, op, e, deletesOnly);
    return null;
  }
  const code = refused?.(out) ?? null;
  if (code === null) answered(c, op, deletesOnly);
  else failed(c, op, { name: "SyncBackendError", code }, deletesOnly);
  return out;
}

// ---------------------------------------------------------------------------
// Events and reconciliation (§13, §18.4).

async function poll(c: Client): Promise<boolean> {
  const page = await call(c, "listEvents", () => c.backend.listEvents(c.shell.state.facts.cursor));
  if (page === null) return false;
  // Remote changes may have freed space, cancelled a deletion or confirmed pending uploads (§12.6).
  if (page.kind === "PAGE" && page.events.length > 0) releaseHolds(c, "event");
  if (page.kind === "CURSOR_EXPIRED") {
    await reconcile(c);
    return true;
  }
  const applied = applyEvents(c.shell.state.facts, page.events);
  if (applied.kind === "RECONCILE") {
    await reconcile(c);
    return true;
  }
  if (applied.facts !== c.shell.state.facts) await setFacts(c, applied.facts);
  return page.events.length > 0;
}

async function reconcile(c: Client): Promise<void> {
  c.log?.({ kind: "reconcile" });
  for (const e of c.shell.state.facts.outbox.filter((x) => x.commitSent)) {
    const statuses = await call(c, "getRevisionStatus", () => c.backend.getRevisionStatus(e.objects.map((o) => o.revisionId)));
    if (statuses === null) return;
    await setFacts(c, applyRevisionStatus(c.shell.state.facts, e.mutationId, statuses));
  }
  const state = await call(c, "getVaultState", () => c.backend.getVaultState());
  if (state !== null) await setFacts(c, applyVaultState(c.shell.state.facts, state));
}

/**
 * §17 "ambas ramas son texto": an object whose every known path (local, S, R) is Markdown. The executor
 * still merges only UTF-8 bytes (content.ts); every other object's concurrent edits make a conflict copy.
 */
export function textObjects(local: ReadonlyMap<ObjectId, LocalEntry>, remote: ReadonlyMap<ObjectId, RevisionEntry>, synced: ReadonlyMap<ObjectId, RevisionEntry>): Set<ObjectId> {
  const paths = new Map<ObjectId, string[]>();
  const add = (id: ObjectId, path: string) => paths.set(id, [...(paths.get(id) ?? []), path]);
  for (const [id, e] of local) if (e.kind === "PRESENT") add(id, e.path);
  for (const tree of [remote, synced]) for (const [id, e] of tree) if (!e.deleted) add(id, e.path);
  return new Set([...paths].filter(([, ps]) => ps.every(isMergeablePath)).map(([id]) => id));
}

// ---------------------------------------------------------------------------
// Uploads (§12.1, rule 13).

/** The Revision Manifest plaintext of one revision (§8), ready to seal as its manifest blob (§31.3). */
export const manifestPayload = (c: Client, input: ManifestInput): Uint8Array => c.blobs.encodeManifest(input);

/**
 * The declared bytes a revision's manifest blob will take, for the §12.1 batching that happens
 * BEFORE revision ids exist. Every field of §8 except `path` is fixed-width in NCE (ids, a hash, a
 * uint, a bool), so a manifest with placeholder ids over the real path is exact to the byte for the
 * ids and off by nothing for the path — see NOTES question 256 for why an estimate is honest here.
 */
export function manifestSizeEstimate(c: Client, path: string, deleted: boolean): number {
  const placeholder = "00000000-0000-0000-0000-000000000000";
  return c.blobs.declaredSize(
    manifestPayload(c, {
      objectId: placeholder,
      revisionId: placeholder,
      parentRevisionId: placeholder,
      path,
      mtimeMs: 0,
      deleted,
      ...(deleted ? {} : { content: { blobId: placeholder, epochId: placeholder, fingerprint: "00".repeat(32), plaintextSize: 0 } }),
    }),
  );
}

/** The planner's uploads become outbox entries with the snapshot taken now (rule 13). */
async function enqueue(c: Client, input: PlanInput, uploads: ReadonlyArray<Extract<Action, { kind: "upload" }>>): Promise<void> {
  const s = c.shell.state;
  const local = resolveLocalPaths(input);
  const requests: UploadRequest[] = [];
  const tooLarge: Array<{ objectId: ObjectId; hash: LocalCompareHash; path: string }> = [];
  for (const u of uploads) {
    const l = local.get(u.objectId);
    if (u.deleted || l?.kind !== "PRESENT") {
      const path = s.facts.synced.get(u.objectId)?.path ?? "";
      requests.push({ ...u, path, deleted: true, localCompareHash: null, plaintext: null, mtimeMs: 0, newBlobBytes: manifestSizeEstimate(c, path, true) });
      continue;
    }
    // Rule 8 before reading: max_blob_bytes limits the FILE, its plaintext (§40; the server allows the §31.3
    // framing on top, control-plane NOTES question 381). The block is on the observed hash, whatever the
    // disk holds now.
    const size = observedSize(c, l.physicalPath, l.localCompareHash);
    if (c.maxBlobBytes !== undefined && size !== null && size > c.maxBlobBytes) {
      tooLarge.push({ objectId: u.objectId, hash: l.localCompareHash, path: l.path });
      continue;
    }
    const content = await readIfExists(c.shell.fs, l.physicalPath);
    if (content === null) return; // observe again first
    // §12.2 rule 2: never act on an observation the disk already contradicts; observe again first.
    if ((await hashRead(c, l.physicalPath, content)) !== l.localCompareHash) return;
    if (c.maxBlobBytes !== undefined && content.byteLength > c.maxBlobBytes) {
      tooLarge.push({ objectId: u.objectId, hash: l.localCompareHash, path: l.path });
      continue;
    }
    requests.push({
      ...u,
      path: l.path,
      deleted: false,
      localCompareHash: l.localCompareHash,
      plaintext: content,
      mtimeMs: observedMtime(c, l.physicalPath),
      newBlobBytes: c.blobs.declaredSize(content) + manifestSizeEstimate(c, l.path, false),
    });
  }
  const ids = Array.from({ length: requests.length * 2 + 2 }, () => c.shell.newId("m-"));
  const facts = tooLarge.reduce((f, t) => blockContent(f, t.objectId, t.hash, "BLOB_TOO_LARGE"), s.facts);
  await setFacts(c, enqueueUploads(facts, requests, { pendingBudgetBytes: c.pendingBudgetBytes }, ids));
  for (const t of tooLarge) c.log?.({ kind: "blocked", objectId: t.objectId, detail: `BLOB_TOO_LARGE ${t.path}` });
}

/**
 * `mtime_ms` of §8: the file's modification time, which only a `clock` marker actually is
 * (ports.ts `ChangeMarker`). With a `counter` marker — the web note store, memfs — the marker is not
 * a time, so the manifest records the device's wall clock instead, and 0 when there is none. §8
 * gives the field no protocol meaning; nothing in the client reads it back (NOTES question 257).
 */
function observedMtime(c: Client, path: PhysicalPath): number {
  if (c.shell.fs.changeMarker?.kind === "clock") {
    const entry = c.shell.state.fileStats.get(path);
    if (entry !== undefined) return entry.mtime;
  }
  return c.wallClock?.() ?? 0;
}

/** The byte size of the content the last observations hashed to `hash` at `path`, if they recorded it. */
function observedSize(c: Client, path: PhysicalPath, hash: LocalCompareHash): number | null {
  const seen = c.memory.observed.get(path);
  if (seen !== undefined && seen.hash === hash) return seen.content.byteLength;
  const entry = c.shell.state.fileStats.get(path);
  return entry !== undefined && entry.hash === hash ? entry.size : null;
}

/**
 * local_compare_hash of bytes just read at `path`: the last observation's hash when it read these same
 * bytes there (compared byte for byte: no second hash of the same bytes in one tick, question 147).
 */
async function hashRead(c: Client, path: PhysicalPath, content: Content): Promise<LocalCompareHash> {
  const seen = c.memory.observed.get(path);
  return seen !== undefined && bytesEqual(seen.content, content) ? seen.hash : c.shell.hasher.hash(content);
}

/** Rule 13: blob ids, encryption and ciphertext hashes are computed first; then one write-ahead transaction. */
async function buildAttempt(c: Client, mutationId: string): Promise<UploadAttempt> {
  const f = c.shell.state.facts;
  const e = f.outbox.find((x) => x.mutationId === mutationId)!;
  const blobs = [];
  for (const o of e.objects) {
    // Ids are allocated manifest-first (the order every earlier attempt used), but the CONTENT blob
    // is sealed first: its `content_fingerprint` (§31.4) and its `content_epoch_id` are fields of
    // the manifest (§8), so the manifest cannot exist until its content does.
    const manifestBlobId = c.shell.newId("b-");
    const contentBlobId = o.deleted ? null : c.shell.newId("b-");
    let content: ManifestInput["content"];
    let contentBlob: AttemptBlob | null = null;
    if (contentBlobId !== null) {
      const sealed = await c.blobs.encryptBlob({ epochId: f.epochId, blobId: contentBlobId, kind: "CONTENT", payload: o.plaintext! });
      contentBlob = { blobId: contentBlobId, kind: "CONTENT", objectId: o.objectId, declaredSize: sealed.declaredSize, ciphertextSha256: sealed.ciphertextSha256, ciphertext: sealed.ciphertext, forDelete: false, expiresAt: null };
      content = { blobId: contentBlobId, epochId: f.epochId, fingerprint: sealed.fingerprint ?? "", plaintextSize: o.plaintext!.byteLength };
    }
    // §31.3: the manifest's AAD names the revision, and its parent is `expectedHeadRevisionId` —
    // the head this revision is being written onto, which is what the commit declares (§12.5).
    const binding = { objectId: o.objectId, revisionId: o.revisionId, parentRevisionId: o.expectedHeadRevisionId };
    const payload = manifestPayload(c, { ...binding, path: o.path, mtimeMs: o.mtimeMs ?? 0, deleted: o.deleted, ...(content === undefined ? {} : { content }) });
    const sealed = await c.blobs.encryptBlob({ epochId: f.epochId, blobId: manifestBlobId, kind: "MANIFEST", payload, binding });
    blobs.push({ blobId: manifestBlobId, kind: "MANIFEST" as const, objectId: o.objectId, declaredSize: sealed.declaredSize, ciphertextSha256: sealed.ciphertextSha256, ciphertext: sealed.ciphertext, forDelete: o.deleted, expiresAt: null });
    if (contentBlob !== null) blobs.push(contentBlob);
  }
  return { attemptId: c.shell.newId("a-"), mutationId, replicaId: f.replicaId, epochId: f.epochId, blobs };
}

async function learnWriteEpoch(c: Client): Promise<void> {
  const state = await call(c, "getVaultState", () => c.backend.getVaultState());
  if (state !== null) await setFacts(c, setWriteEpoch(c.shell.state.facts, state.epochId));
}

async function runOutboxStep(c: Client, step: OutboxStep): Promise<void> {
  const f = () => c.shell.state.facts;
  const attemptOf = (mutationId: string) => f().attempts.find((a) => a.mutationId === mutationId)!;
  const entryOf = (mutationId: string) => f().outbox.find((e) => e.mutationId === mutationId)!;
  // Requests a QUOTA_EXCEEDED hold lets through (retry.ts "nonDeletes"): a delete-only entry's, a release.
  const deletesOnly = step.kind === "release" || isDeleteOnly(entryOf(step.mutationId));
  switch (step.kind) {
    case "release": {
      // UPLOAD_IN_PROGRESS and VAULT_DELETING keep the record (rule 13): wait before asking again.
      const r = await call(c, "releaseUpload", () => c.backend.releaseUpload(step.blobId), (x) => (x === "UPLOAD_IN_PROGRESS" || x === "VAULT_DELETING" ? x : null), deletesOnly);
      if (r !== null) await setFacts(c, applyRelease(f(), step.blobId, r));
      return;
    }
    case "revisionStatus": {
      const e = entryOf(step.mutationId);
      const statuses = await call(c, "getRevisionStatus", () => c.backend.getRevisionStatus(e.objects.map((o) => o.revisionId)));
      if (statuses !== null) await setFacts(c, applyRevisionStatus(f(), step.mutationId, statuses));
      return;
    }
    case "encrypt": {
      const attempt = await buildAttempt(c, step.mutationId);
      await setFacts(c, recordAttempt(f(), attempt)); // write-ahead: committed before any request
      return;
    }
    case "retireExpired":
      await setFacts(c, retireExpired(f(), step.mutationId, c.now()));
      return;
    case "prepare": {
      const attempt = attemptOf(step.mutationId);
      const b = attempt.blobs.find((x) => x.blobId === step.blobId)!;
      const sentAt = c.now();
      const r = await call(
        c,
        "prepareUpload",
        () =>
          c.backend.prepareUpload({
          blobId: b.blobId,
          epochId: attempt.epochId,
          kind: b.kind,
          declaredSize: b.declaredSize,
          ciphertextSha256: b.ciphertextSha256,
          forDelete: b.forDelete,
          objectId: b.objectId,
        }),
        // §12.6: kept, retried when pending uploads confirm or expire (after the cleanup queue, which goes first).
        (x) => (!x.ok && x.code === "PENDING_BUDGET_EXCEEDED" ? x.code : null),
        deletesOnly,
      );
      if (r === null) return;
      if (r.ok) await setFacts(c, recordPrepared(f(), b.blobId, sentAt + r.expiresInSeconds));
      else if (r.code !== "PENDING_BUDGET_EXCEEDED") {
        await setFacts(c, applyPrepareRejection(f(), step.mutationId, b.blobId, r.code));
        if (r.code === "EPOCH_STALE") await learnWriteEpoch(c);
      }
      return;
    }
    case "put": {
      const b = attemptOf(step.mutationId).blobs.find((x) => x.blobId === step.blobId)!;
      let timedOut = false;
      const r = await call(
        c,
        "uploadBlob",
        () =>
          c.backend.uploadBlob(b.blobId, b.ciphertext).catch((e: unknown) => {
            timedOut = (e as Error | null)?.name === UPLOAD_TIMEOUT;
            throw e;
          }),
        undefined,
        deletesOnly,
      );
      if (timedOut) {
        const o = entryOf(step.mutationId).objects.find((x) => x.objectId === b.objectId)!;
        const before = f().blocked.length;
        await setFacts(c, recordPutFailure(f(), o.objectId, o.localCompareHash));
        // §12.6: after UPLOAD_TIMEOUT_MAX the content is blocked and the user is told.
        if (f().blocked.length > before) c.log?.({ kind: "blocked", objectId: o.objectId, detail: `UPLOAD_TIMEOUT_MAX ${o.path}` });
      }
      if (r === null) return;
      if (r.ok) c.memory.putDone.add(b.blobId);
      else await setFacts(c, applyPrepareRejection(f(), step.mutationId, b.blobId, r.code));
      return;
    }
    case "commit": {
      const e = entryOf(step.mutationId);
      const attempt = attemptOf(step.mutationId);
      await setFacts(c, markCommitSent(f(), step.mutationId)); // persisted before the request leaves
      const result: CommitResult | null = await call(
        c,
        "commitMutation",
        () =>
          c.backend.commitMutation({
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
          }),
        undefined,
        deletesOnly,
      );
      if (result === null) return;
      const applied = applyCommitResult(f(), step.mutationId, result, c.now());
      if (!applied.ok) throw new Error(`stored result of ${step.mutationId} does not match the outbox`);
      let hashes = c.shell.state.hashes;
      if (result.kind === "COMMITTED") {
        hashes = new Map(hashes);
        for (const o of e.objects) if (o.localCompareHash !== null) (hashes as Map<RevisionId, LocalCompareHash>).set(o.revisionId, o.localCompareHash);
      }
      await setFacts(c, applied.facts, hashes);
      if (result.kind === "REJECTED") c.log?.({ kind: `rejected:${result.code}` });
      if (result.kind === "REJECTED" && result.code === "EPOCH_STALE") await learnWriteEpoch(c);
      return;
    }
  }
}

// ---------------------------------------------------------------------------
// Non-upload actions (§13.4, §15, §16.7, §17).

/**
 * Downloads a revision's plaintext and records its hash. "PRUNED" when its bytes are gone (§10.6);
 * null when the request failed (nothing learned: the next plan asks again). The revision is the one
 * of the object in R or S, whose recorded content ref goes with the request.
 */
async function download(c: Client, objectId: ObjectId, revisionId: RevisionId): Promise<Content | "PRUNED" | null> {
  const { remote, synced } = c.shell.state.facts;
  const entry = [remote.get(objectId), synced.get(objectId)].find((e) => e?.revisionId === revisionId);
  // The sequence lets the adapter find the revision again if a re-encryption replaced its blob (§35.13).
  const r = await call(c, "readRevision", () => c.backend.readRevision(revisionId, entry?.content, entry?.sequence));
  if (r === null) return null;
  if (r.kind === "PRUNED") {
    c.memory.pruned.add(revisionId);
    return "PRUNED";
  }
  const hash = await c.shell.hasher.hash(r.plaintext);
  if (c.shell.state.hashes.get(revisionId) !== hash) {
    await commit(c.shell, { ...c.shell.state, hashes: new Map(c.shell.state.hashes).set(revisionId, hash) });
  }
  return r.plaintext;
}

async function execute(c: Client, input: PlanInput, a: Exclude<Action, { kind: "upload" }>): Promise<void> {
  const { shell } = c;
  c.log?.({ kind: "action", objectId: a.objectId, detail: a.kind });
  const s = () => shell.state;
  const remoteEntry = (objectId: ObjectId, revisionId: RevisionId): RevisionEntry => {
    const r = s().facts.remote.get(objectId) ?? s().facts.synced.get(objectId);
    if (!r || r.revisionId !== revisionId) throw new Error(`${revisionId} is not the known head of ${objectId}`);
    return withHash(s(), r);
  };
  const observedFp = (objectId: ObjectId): LocalCompareHashOrAbsent => {
    const l = input.local.get(objectId);
    return l?.kind === "PRESENT" ? l.localCompareHash : "ABSENT";
  };
  const physicalOf = (objectId: ObjectId): PhysicalPath | null => {
    const o = s().observations.get(objectId);
    return o?.kind === "PRESENT" ? o.physicalPath : null;
  };
  const localPath = (objectId: ObjectId) => {
    const l = resolveLocalPaths(input).get(objectId);
    const o = s().observations.get(objectId);
    return l?.kind === "PRESENT" ? l.path : o && o.kind !== "NOT_MATERIALIZED" ? o.logicalPath : "";
  };
  const setSynced = (objectId: ObjectId, e: RevisionEntry, observations = s().observations) =>
    commit(shell, { ...s(), observations, facts: { ...s().facts, synced: new Map(s().facts.synced).set(objectId, e) } });
  switch (a.kind) {
    case "fetchContent":
      await download(c, a.objectId, a.revisionId);
      return;
    case "advanceSynced":
      await setSynced(a.objectId, remoteEntry(a.objectId, a.revisionId));
      return;
    case "forgetUnconfirmedCreate": {
      const observations = new Map(s().observations);
      observations.delete(a.objectId);
      await commit(shell, { ...s(), observations });
      return;
    }
    case "applyRemote": {
      const r = remoteEntry(a.objectId, a.revisionId);
      const current = physicalOf(a.objectId);
      if (r.deleted) {
        if (current === null) {
          const observations = new Map(s().observations);
          observations.delete(a.objectId);
          await setSynced(a.objectId, r, observations);
          return;
        }
        await journaled(c, deleteEntry({ objectId: a.objectId, dest: current, expectedPrevFp: observedFp(a.objectId), newSynced: r, marksNotMaterialized: false }));
        return;
      }
      const content = await download(c, a.objectId, r.revisionId);
      if (content === null || content === "PRUNED") return;
      const newSynced = { ...r, localCompareHash: await shell.hasher.hash(content) };
      const e = await writeEntry(shell, { objectId: a.objectId, dest: a.physicalPath, expectedPrevFp: observedFp(a.objectId), content, newSynced, logicalPath: r.path });
      await journaled(c, e);
      return;
    }
    case "movePhysical": {
      const e = await renameEntry(shell, { objectId: a.objectId, from: a.from, to: a.to });
      // §20.2: a projection rename this replica did itself ends a run of another replica's (NOTES question 419).
      if ((await runEntry(shell, e)) === "COMPLETE") c.memory.projectionRenameArrivals = 0;
      else c.log?.({ kind: "cancel", objectId: e.objectId });
      return;
    }
    case "markNotMaterialized":
      await setSynced(a.objectId, remoteEntry(a.objectId, a.revisionId), new Map(s().observations).set(a.objectId, { kind: "NOT_MATERIALIZED" }));
      return;
    case "removePhysical":
      await journaled(c, deleteEntry({ objectId: a.objectId, dest: a.from, expectedPrevFp: observedFp(a.objectId), newSynced: null, marksNotMaterialized: true }));
      return;
    case "conflictCopy":
      await conflictCopy(c, a.objectId, localPath(a.objectId), remoteEntry(a.objectId, a.remoteRevisionId));
      return;
    case "discardLocalRename": {
      const current = physicalOf(a.objectId);
      if (current === null) return;
      await journaled(c, deleteEntry({ objectId: a.objectId, dest: current, expectedPrevFp: observedFp(a.objectId), newSynced: remoteEntry(a.objectId, a.remoteRevisionId), marksNotMaterialized: false }));
      return;
    }
    case "resolve": {
      const physical = physicalOf(a.objectId);
      if (physical === null) return;
      const local = await readIfExists(shell.fs, physical);
      if (local === null) return;
      if ((await shell.hasher.hash(local)) !== observedFp(a.objectId)) return; // the disk moved on: observe again
      const r = remoteEntry(a.objectId, a.remoteRevisionId);
      const remoteContent = await download(c, a.objectId, r.revisionId);
      if (remoteContent === null || remoteContent === "PRUNED") return;
      let content = a.content === "local" ? local : remoteContent;
      if (a.content === "merge") {
        const base = await download(c, a.objectId, a.baseRevisionId);
        if (base === null) return;
        // §17: bytes of S available and all three sides text (the planner only asks for a Markdown path).
        const m = base === "PRUNED" ? { kind: "conflict" as const } : mergeContent(base, local, remoteContent);
        if (m.kind === "conflict") {
          await conflictCopy(c, a.objectId, localPath(a.objectId), r);
          return;
        }
        content = m.content;
        c.log?.({ kind: "merge", objectId: a.objectId, detail: decodeText(local) ?? "" });
        c.log?.({ kind: "merged", objectId: a.objectId, detail: decodeText(m.content) ?? "" });
      }
      const path = a.path === "local" ? localPath(a.objectId) : r.path;
      const newSynced = { ...r, localCompareHash: await shell.hasher.hash(remoteContent) };
      if (bytesEqual(content, local)) {
        // M = L: only S := R (rule 4); the upload of M over R comes in the next plan.
        const o = s().observations.get(a.objectId);
        const observations = o?.kind === "PRESENT" ? new Map(s().observations).set(a.objectId, { ...o, logicalPath: path }) : s().observations;
        await setSynced(a.objectId, newSynced, observations);
        return;
      }
      const e = await writeEntry(shell, { objectId: a.objectId, dest: physical, expectedPrevFp: await shell.hasher.hash(local), content, newSynced, logicalPath: path });
      await journaled(c, e);
      return;
    }
  }
}

/** Runs one journaled operation and reports a cancel (the disk changed under the plan). */
async function journaled(c: Client, e: Parameters<typeof runEntry>[1]): Promise<void> {
  if ((await runEntry(c.shell, e)) === "CANCEL") c.log?.({ kind: "cancel", objectId: e.objectId });
}

/** Rule 4: the local file becomes a new object; the original takes R and is UNBOUND, in one transition. */
async function conflictCopy(c: Client, objectId: ObjectId, localPath: string, r: RevisionEntry): Promise<void> {
  const { shell } = c;
  const s = shell.state;
  const o = s.observations.get(objectId);
  if (o?.kind !== "PRESENT") return;
  const copy = shell.newId("copy-");
  const observations = new Map(s.observations);
  observations.delete(objectId);
  observations.set(copy, { kind: "PRESENT", logicalPath: localPath, physicalPath: o.physicalPath, hash: o.hash });
  await commit(shell, { ...s, observations, facts: { ...s.facts, synced: new Map(s.facts.synced).set(objectId, r) } });
  const identity = shell.identities.get(objectId);
  shell.identities.delete(objectId);
  if (identity !== undefined) shell.identities.set(copy, identity);
  c.log?.({ kind: "conflictCopy", objectId });
}

