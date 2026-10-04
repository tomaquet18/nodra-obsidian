import { comparisonKey } from "@nodra/path-projection";
import {
  bytesEqual,
  type Content,
  type IntentState,
  type JournalEntry,
  type LocalCompareHashOrAbsent,
  type ObjectId,
  type PhysicalPath,
  type RevisionEntry,
  bumpLocalVersion,
  explainWrite,
  isRecoveryName,
  openEntry,
  processIntent,
  parkedDisposition,
  pruneOtherSyncFacts,
  recoveryName,
  replay,
  tmpDisposition,
  tmpPath,
  viewFingerprint,
} from "@nodra/sync-core";
import type { DeviceLocalCrypto, FileSystem, LocalCompareHasher } from "./ports.js";
import { isQueueClosed } from "./queue.js";
import type { ClientJournalEntry, IntentRef, Observation, VaultState } from "./state.js";
import { type VaultStore, persist } from "./store.js";

// The disk executor (§15, §13.4, §16.7): one journaled physical operation at a time. Every step that
// changes a fact is one store transition (one IndexedDB transaction); hashes are computed before it.
// sync-core decides (replay, tmpDisposition, replaceAllowed); this module only performs and re-reads.

/** The impure context of one client instance. `state` is the last persisted state. */
export interface Shell {
  readonly fs: FileSystem;
  readonly hasher: LocalCompareHasher;
  readonly dlc: DeviceLocalCrypto;
  readonly store: VaultStore;
  state: VaultState;
  /** In-memory adapter identities of each object's file (rule 10); lost on restart. */
  readonly identities: Map<ObjectId, string>;
  /** Folders this instance created (Q33): the only ones it may remove, and only when empty. */
  readonly createdFolders: Set<PhysicalPath>;
  /** Randomness (an input): 8 lowercase hex characters. */
  readonly hex8: () => string;
  /** New ids (object ids of recovery notes, mutation ids, ...). */
  readonly newId: (prefix: string) => string;
  /** Diagnostics (tests, panel): `local-change` per object whose local state changed, `intent` per processed intent. */
  readonly log?: (event: { readonly kind: string; readonly objectId?: ObjectId; readonly detail?: string }) => void;
}

/** The local state of an object as §20.2 sees it (path, deleted, hash), comparable across transitions. */
const localKey = (o: Observation | undefined): string =>
  o === undefined ? "" : o.kind === "PRESENT" ? JSON.stringify([o.kind, o.logicalPath, o.hash]) : o.kind === "ABSENT" ? JSON.stringify([o.kind, o.logicalPath]) : o.kind;

/** view_fp (§20.2) of an object's local state: the same function for the follower and the leader. */
export function localViewFp(o: Observation | undefined): string | null {
  if (o === undefined) return viewFingerprint(null);
  switch (o.kind) {
    case "PRESENT":
      return viewFingerprint({ path: o.logicalPath, deleted: false, localCompareHash: o.hash });
    case "ABSENT":
      return viewFingerprint({ path: o.logicalPath, deleted: true, localCompareHash: null });
    case "NOT_MATERIALIZED":
      return "not-materialized";
  }
}

/**
 * §20.2 "Versión local y orden": local_version increases every time the object's local state changes,
 * whatever the cause (observed user edit, planner action, remote apply, intent). Derived from the
 * transition itself, so no caller can forget it; an object whose version the transition already moved
 * (an intent's own application, processIntent) is not counted twice.
 */
function withLocalVersions(before: VaultState, next: VaultState): { state: VaultState; changed: ObjectId[] } {
  let st: IntentState = next.intentState;
  const changed: ObjectId[] = [];
  for (const id of new Set([...before.observations.keys(), ...next.observations.keys()])) {
    if (localKey(before.observations.get(id)) === localKey(next.observations.get(id))) continue;
    changed.push(id);
    if ((next.intentState.localVersion.get(id) ?? 0) !== (before.intentState.localVersion.get(id) ?? 0)) continue;
    st = bumpLocalVersion(st, id);
  }
  return { state: st === next.intentState ? next : { ...next, intentState: st }, changed };
}

/** §20.2 (NOTES question 419): the other-sync-tool facts that can no longer matter go with the transition that ends them. */
function withPrunedOtherSync(next: VaultState): VaultState {
  const f = next.otherSync;
  if (f.explainedWrites.size === 0 && f.acknowledged.size === 0) return next;
  const hashed = (m: ReadonlyMap<ObjectId, RevisionEntry>) =>
    new Map([...m].map(([id, e]) => [id, e.deleted ? e : { ...e, localCompareHash: next.hashes.get(e.revisionId) ?? e.localCompareHash }]));
  const pruned = pruneOtherSyncFacts(f, hashed(next.facts.synced), hashed(next.facts.remote));
  return pruned === f ? next : { ...next, otherSync: pruned };
}

/**
 * Persists `next` as one transition (one transaction) and makes it the current state. `appliedIntent`
 * names the intent this transition applied, for the diagnostics only.
 */
export async function commit(shell: Shell, next: VaultState, appliedIntent?: { readonly intentId: string; readonly target: ObjectId }): Promise<void> {
  const { state, changed } = withLocalVersions(shell.state, withPrunedOtherSync(next));
  await persist(shell.store, shell.dlc, shell.state, state);
  shell.state = state;
  for (const objectId of changed) shell.log?.({ kind: "local-change", objectId, detail: appliedIntent?.target === objectId ? appliedIntent.intentId : "" });
}

/** The object an intent's processing changes: the target, the new copy, or (discarded) none. */
export const intentTarget = (ref: IntentRef, objectId: ObjectId): ObjectId => (ref.decision.kind === "APPLY" ? ref.decision.target : (ref.copyObjectId ?? objectId));

/**
 * §20.2: processing an intent and deleting its row happen in ONE transition, together with its effect
 * (`next` already carries it). A row that is gone was processed already: nothing is applied twice.
 */
export async function commitIntent(shell: Shell, next: VaultState, ref: IntentRef): Promise<void> {
  const row = next.intents.find((r) => r.intentId === ref.intentId);
  if (row === undefined) {
    await commit(shell, next);
    return;
  }
  const r = processIntent(next.intentState, next.intents, row, ref.decision, ref.copyObjectId ?? undefined);
  const target = intentTarget(ref, row.objectId);
  const priorFp = localViewFp(shell.state.observations.get(target));
  await commit(shell, { ...next, intents: r.pending, intentState: r.state }, { intentId: ref.intentId, target });
  shell.log?.({ kind: "intent", objectId: target, detail: JSON.stringify({ intentId: ref.intentId, outcome: ref.decision.kind, priorFp }) });
}

const parentOf = (p: PhysicalPath) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");

/** Every file and folder of the vault (depth-first). */
export async function listAll(fs: FileSystem): Promise<{ files: PhysicalPath[]; folders: PhysicalPath[] }> {
  const files: PhysicalPath[] = [];
  const folders: PhysicalPath[] = [];
  const walk = async (folder: PhysicalPath) => {
    const l = await fs.list(folder);
    files.push(...l.files);
    for (const f of l.folders) {
      folders.push(f);
      await walk(f);
    }
  };
  await walk("");
  return { files: files.sort(), folders: folders.sort() };
}

/**
 * Reads a file; null if it is not (or no longer) a file. A failed read of a path that IS a file at the
 * stat right after may be a file created in between (a user race, NOTES question 149): read again, a
 * few times; a read that keeps failing on a file is an adapter error and propagates.
 */
export async function readIfExists(fs: FileSystem, path: PhysicalPath): Promise<Content | null> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fs.read(path);
    } catch (e) {
      if ((await fs.stat(path))?.type !== "file") return null;
      if (attempt >= 3) throw e;
    }
  }
}

/** The file at `path` still holds exactly `content` (a re-read right before deleting it). */
async function stillHolds(fs: FileSystem, path: PhysicalPath, content: Content): Promise<boolean> {
  const now = await readIfExists(fs, path);
  return now !== null && bytesEqual(now, content);
}

/**
 * Runs a physical operation. If it fails and `stillValid` says its precondition no longer holds (the
 * user acted in the window after the re-check), it reports false instead of failing: the entry is
 * cancelled and the next plan starts from a new observation. Otherwise the error propagates.
 */
async function guarded(op: () => Promise<void>, stillValid: () => Promise<boolean>): Promise<boolean> {
  try {
    await op();
    return true;
  } catch (e) {
    // A closed disk queue is not a user race: this instance stops here (§20.2).
    if (isQueueClosed(e) || (await stillValid())) throw e;
    return false;
  }
}

/** local_compare_hash of the file at `path`, "ABSENT" if nothing is there, "FOLDER" if a folder is. */
// eslint-disable-next-line @typescript-eslint/no-redundant-type-constituents -- "FOLDER" is a sentinel next to the hash (a string)
async function fingerprint(shell: Shell, path: PhysicalPath): Promise<LocalCompareHashOrAbsent | "FOLDER"> {
  const st = await shell.fs.stat(path);
  if (st === null) return "ABSENT";
  if (st.type === "folder") return "FOLDER";
  const content = await readIfExists(shell.fs, path);
  return content === null ? fingerprint(shell, path) : shell.hasher.hash(content);
}

/**
 * Q41 / §16.7 rule 4 / §13.4 step 4: `path` is free for a write or rename, except for `allowed` (the
 * object's own file, which a rename may move to a case or normalization variant of its path): no file or folder with the same comparison key, no file at an ancestor path, and
 * nothing inside it.
 */
async function isFree(shell: Shell, path: PhysicalPath, allowed: PhysicalPath | null, inPlace = false): Promise<boolean> {
  const k = comparisonKey(path);
  const { files, folders } = await listAll(shell.fs);
  for (const p of [...files, ...folders]) {
    if (p === allowed && files.includes(p)) continue;
    const pk = comparisonKey(p);
    // Q65: rewriting the object's own file in place (its hash is re-checked): a same-key entry at another
    // exact path can only coexist with it on a case-sensitive disk, where it is another file untouched by
    // a replace of this exact path. Without this, a case variant blocked the rewrite forever.
    if (inPlace && p !== path && (pk === k || pk.startsWith(`${k}/`))) continue;
    if (pk === k || pk.startsWith(`${k}/`) || (files.includes(p) && k.startsWith(`${pk}/`))) return false;
  }
  return true;
}

/**
 * A free path for a NEW file (§20.2: an intent that creates an object, or its conflict copy): `desired`
 * if free, else `<stem> <8 hex><ext>` next to it, else (its folder is blocked, e.g. by a file with the
 * folder's name, Q66) the same name at the vault root. The physical projection (§16.7) moves it afterwards.
 */
export async function freePath(shell: Shell, desired: PhysicalPath): Promise<PhysicalPath> {
  if (await isFree(shell, desired, null)) return desired;
  const slash = desired.lastIndexOf("/");
  const dot = desired.lastIndexOf(".");
  const [stem, ext] = dot > slash + 1 ? [desired.slice(0, dot), desired.slice(dot)] : [desired, ""];
  const base = stem.slice(slash + 1);
  for (let attempt = 0; ; attempt++) {
    // Next to it first; from the fourth attempt on, at the root, which only a same-name entry can block.
    const candidate = attempt < 3 ? `${stem} ${shell.hex8()}${ext}` : `${base} ${shell.hex8()}${ext}`;
    if (await isFree(shell, candidate, null)) return candidate;
  }
}

/**
 * Q33 / §16.6: empty folders are not synced and hold no bytes. An empty folder tree whose name collides
 * with `path` (typically a case variant, `Foo/` against `foo`) would block the projection forever, so
 * it is removed, deepest first, after listing it again. A folder with any file inside is never touched.
 */
async function clearEmptyBlockers(shell: Shell, path: PhysicalPath): Promise<void> {
  const k = comparisonKey(path);
  const { files, folders } = await listAll(shell.fs);
  if (files.some((p) => comparisonKey(p) === k || comparisonKey(p).startsWith(`${k}/`))) return;
  const blockers = folders.filter((p) => comparisonKey(p) === k || comparisonKey(p).startsWith(`${k}/`)).sort((a, b) => b.length - a.length);
  for (const folder of blockers) {
    const l = await shell.fs.list(folder);
    if (l.files.length > 0 || l.folders.length > 0) return;
    if (!(await guarded(() => shell.fs.rmdir(folder), async () => (await shell.fs.list(folder)).files.length === 0))) return;
    shell.createdFolders.delete(folder);
  }
}

/** §15 step 2: a `nodra-tmp-<8 hex>` name that exists in no folder of the vault. */
export async function freshTmpName(shell: Shell): Promise<string> {
  const { files, folders } = await listAll(shell.fs);
  const names = new Set([...files, ...folders].map((p) => p.slice(p.lastIndexOf("/") + 1)));
  for (;;) {
    const name = `nodra-tmp-${shell.hex8()}`;
    if (!names.has(name)) return name;
  }
}

export async function writeEntry(
  shell: Shell,
  w: { objectId: ObjectId; dest: PhysicalPath; expectedPrevFp: LocalCompareHashOrAbsent; content: Content; newSynced: RevisionEntry | null; logicalPath: string },
): Promise<ClientJournalEntry> {
  return {
    objectId: w.objectId,
    kind: "WRITE",
    sourcePath: null,
    destPath: w.dest,
    tmpName: await freshTmpName(shell),
    expectedPrevFp: w.expectedPrevFp,
    finalFp: await shell.hasher.hash(w.content),
    newSynced: w.newSynced,
    recordedLogicalPath: w.logicalPath,
    tmpCreated: false,
    content: w.content,
    marksNotMaterialized: false,
  };
}

export async function renameEntry(shell: Shell, r: { objectId: ObjectId; from: PhysicalPath; to: PhysicalPath }): Promise<JournalEntry> {
  const fp = await fingerprint(shell, r.from);
  return {
    objectId: r.objectId,
    kind: "RENAME",
    sourcePath: r.from,
    destPath: r.to,
    tmpName: null,
    expectedPrevFp: "ABSENT",
    finalFp: fp === "ABSENT" || fp === "FOLDER" ? null : fp,
    newSynced: null,
    recordedLogicalPath: null,
    tmpCreated: false,
    content: null,
    marksNotMaterialized: false,
  };
}

export function deleteEntry(d: {
  objectId: ObjectId;
  dest: PhysicalPath;
  expectedPrevFp: LocalCompareHashOrAbsent;
  newSynced: RevisionEntry | null;
  marksNotMaterialized: boolean;
}): JournalEntry {
  return {
    objectId: d.objectId,
    kind: "DELETE",
    sourcePath: null,
    destPath: d.dest,
    tmpName: null,
    expectedPrevFp: d.expectedPrevFp,
    finalFp: null,
    newSynced: d.newSynced,
    recordedLogicalPath: null,
    tmpCreated: false,
    content: null,
    marksNotMaterialized: d.marksNotMaterialized,
  };
}

/** Creates the destination's missing folders (remembering them, Q33); false if a file is in the way. */
async function ensureParent(shell: Shell, path: PhysicalPath): Promise<boolean> {
  const missing: PhysicalPath[] = [];
  for (let p = parentOf(path); p !== ""; p = parentOf(p)) {
    const st = await shell.fs.stat(p);
    if (st?.type === "file") return false;
    if (st === null) missing.push(p);
  }
  for (const p of missing.reverse()) {
    if (!(await guarded(() => shell.fs.mkdir(p), async () => (await shell.fs.stat(p))?.type !== "file" && !(await hasFileAncestor(shell, p))))) return false;
    shell.createdFolders.add(p);
  }
  return true;
}

async function hasFileAncestor(shell: Shell, path: PhysicalPath): Promise<boolean> {
  for (let p = parentOf(path); p !== ""; p = parentOf(p)) if ((await shell.fs.stat(p))?.type === "file") return true;
  return false;
}

const folderExists = async (shell: Shell, path: PhysicalPath) => {
  const parent = parentOf(path);
  return parent === "" || (await shell.fs.stat(parent))?.type === "folder";
};

/**
 * Runs one journaled operation (§15): the entry is persisted before touching the disk; every replace
 * or rename is preceded by a re-check. Returns how it ended; a thrown error (a crash) leaves the entry
 * open for the next instance to replay.
 */
export async function runEntry(shell: Shell, entry: ClientJournalEntry): Promise<"COMPLETE" | "CANCEL"> {
  // A DELETE parks the file under a fresh temporary name; the name is in the entry before the rename.
  const e = entry.kind === "DELETE" && entry.tmpName === null ? { ...entry, tmpName: await freshTmpName(shell) } : entry;
  await commit(shell, { ...shell.state, journal: openEntry(shell.state.journal, e) }); // 1.
  switch (e.kind) {
    case "WRITE": {
      const tp = tmpPath(e);
      // In place: the destination is the object's own file, whose exact bytes are re-checked below.
      const inPlace = e.expectedPrevFp !== "ABSENT";
      await clearEmptyBlockers(shell, e.destPath);
      if (!(await isFree(shell, e.destPath, e.destPath, inPlace)) || !(await ensureParent(shell, e.destPath))) return cancel(shell);
      if ((await shell.fs.stat(tp)) !== null) return cancel(shell); // 2. exclusive creation
      if (!(await guarded(() => shell.fs.write(tp, e.content!), () => folderExists(shell, tp)))) return cancel(shell);
      await commit(shell, { ...shell.state, journal: { ...e, tmpCreated: true } }); // 3. own transaction
      // 4. re-check the destination (content, a folder at it, a file at an ancestor) and our temporary.
      if ((await fingerprint(shell, e.destPath)) !== e.expectedPrevFp) return cancel(shell);
      if (!(await isFree(shell, e.destPath, e.destPath, inPlace))) return cancel(shell);
      if ((await fingerprint(shell, tp)) !== e.finalFp) return cancel(shell);
      const replaced = await guarded(
        () => shell.fs.replace(tp, e.destPath),
        async () => (await fingerprint(shell, tp)) === e.finalFp && (await isFree(shell, e.destPath, e.destPath, inPlace)) && (await folderExists(shell, e.destPath)),
      );
      if (!replaced) return cancel(shell, true); // the replace may have written the destination
      await close(shell);
      return "COMPLETE";
    }
    case "RENAME": {
      if (e.finalFp === null || (await fingerprint(shell, e.sourcePath!)) !== e.finalFp) return cancel(shell);
      await clearEmptyBlockers(shell, e.destPath);
      if (!(await isFree(shell, e.destPath, e.sourcePath)) || !(await ensureParent(shell, e.destPath))) return cancel(shell);
      if (!(await isFree(shell, e.destPath, e.sourcePath))) return cancel(shell);
      const renamed = await guarded(
        () => shell.fs.rename(e.sourcePath!, e.destPath),
        async () => (await fingerprint(shell, e.sourcePath!)) === e.finalFp && (await isFree(shell, e.destPath, e.sourcePath)) && (await folderExists(shell, e.destPath)),
      );
      if (!renamed) return cancel(shell);
      await close(shell);
      await removeVacatedFolders(shell, e.sourcePath!);
      return "COMPLETE";
    }
    case "DELETE": {
      // Park → verify → delete (§44.5): a plain remove after the re-read could destroy a user edit
      // that lands in between; the atomic rename takes whatever is there, and only that is judged.
      const park = tmpPath(e);
      if ((await fingerprint(shell, e.destPath)) !== e.expectedPrevFp) return cancel(shell);
      if ((await shell.fs.stat(park)) !== null) return cancel(shell);
      const parked = await guarded(
        () => shell.fs.rename(e.destPath, park),
        async () => (await fingerprint(shell, e.destPath)) === e.expectedPrevFp && (await shell.fs.stat(park)) === null,
      );
      if (!parked) return cancel(shell);
      return finishParked(shell);
    }
  }
}

/**
 * A DELETE whose file is parked: delete it only if it holds exactly the expected bytes (re-read right
 * before the remove, §15); otherwise put it back at its path if free, or import it as a recovery note.
 */
async function finishParked(shell: Shell): Promise<"COMPLETE" | "CANCEL"> {
  const e = shell.state.journal!;
  const park = tmpPath(e);
  const content = await readIfExists(shell.fs, park);
  if (content === null) {
    // The parked file is gone (the user removed it): the object's file is not on disk either way.
    await close(shell);
    return "COMPLETE";
  }
  if (parkedDisposition(e, await shell.hasher.hash(content)) === "DELETE") {
    if ((await stillHolds(shell.fs, park, content)) && (await guarded(() => shell.fs.remove(park), async () => (await readIfExists(shell.fs, park)) !== null))) {
      await close(shell);
      await removeVacatedFolders(shell, e.destPath);
      return "COMPLETE";
    }
    return finishParked(shell);
  }
  const restored =
    (await isFree(shell, e.destPath, null)) &&
    (await folderExists(shell, e.destPath)) &&
    (await guarded(() => shell.fs.rename(park, e.destPath), async () => (await shell.fs.stat(park)) !== null && (await isFree(shell, e.destPath, null))));
  if (!restored) await importRecovery(shell, park);
  return cancel(shell);
}

/** §15 step 5: closes the open entry; the observation and S are recorded in the same transition. */
async function close(shell: Shell): Promise<void> {
  const s = shell.state;
  const e = s.journal!;
  const id = e.objectId;
  const observations = new Map(s.observations);
  const previous = observations.get(id);
  if (e.kind === "WRITE") {
    const logicalPath = e.recordedLogicalPath ?? (previous && previous.kind !== "NOT_MATERIALIZED" ? previous.logicalPath : e.destPath);
    observations.set(id, { kind: "PRESENT", logicalPath, physicalPath: e.destPath, hash: e.finalFp });
  } else if (e.kind === "RENAME" && previous?.kind === "PRESENT") {
    observations.set(id, { ...previous, physicalPath: e.destPath });
  } else if (e.kind === "DELETE") {
    if (e.marksNotMaterialized) observations.set(id, { kind: "NOT_MATERIALIZED" });
    // A local delete (an intent): the object is gone locally, and the planner uploads the delete.
    else if (e.intent !== undefined && previous !== undefined && previous.kind !== "NOT_MATERIALIZED") observations.set(id, { kind: "ABSENT", logicalPath: previous.logicalPath });
    else observations.delete(id);
  }
  const identity = e.kind === "DELETE" ? null : shell.fs.identityOf(e.destPath);
  let facts = s.facts;
  let hashes = s.hashes;
  if (e.newSynced) {
    facts = { ...facts, synced: new Map(facts.synced).set(id, e.newSynced) };
    if (e.newSynced.localCompareHash !== null) hashes = new Map(hashes).set(e.newSynced.revisionId, e.newSynced.localCompareHash);
  }
  // §20.2: this replica wrote that content (the transition's pruning drops it once S holds it).
  const otherSync = e.kind === "WRITE" && e.finalFp !== null ? explainWrite(s.otherSync, id, e.finalFp) : s.otherSync;
  const next: VaultState = { ...s, journal: null, observations, facts, hashes, otherSync };
  if (e.intent !== undefined) await commitIntent(shell, next, e.intent);
  else await commit(shell, next);
  if (identity === null) shell.identities.delete(id);
  else shell.identities.set(id, identity);
}

/**
 * Cancels the open entry; its temporary is deleted only if provably ours (§15), else recovered. The
 * temporary is dealt with BEFORE the entry is cleared: a crash in between replays the cancel, instead
 * of leaving our own temporary as a stray that would become a recovery note.
 */
async function cancel(shell: Shell, possiblyReplaced = false): Promise<"CANCEL"> {
  const e = shell.state.journal!;
  if (e.kind === "WRITE") {
    const tp = tmpPath(e);
    const st = await shell.fs.stat(tp);
    if (st?.type === "file") {
      // Re-read right before deciding, and delete only what was just read.
      const content = await readIfExists(shell.fs, tp);
      if (content !== null) {
        const h = await shell.hasher.hash(content);
        if (tmpDisposition(e, content, () => h) === "DELETE") {
          // Re-read right before deleting, and delete only what was just read.
          if (await stillHolds(shell.fs, tp, content)) await guarded(() => shell.fs.remove(tp), async () => (await readIfExists(shell.fs, tp)) !== null);
        } else await importRecovery(shell, tp);
      }
    }
  }
  // §20.2 (NOTES question 419): a cancel after the replace may have happened (a failed replace, or a replay
  // of a crashed instance that had created its temporary) leaves on disk what this replica may have written:
  // an adapter that rewrites the destination can crash with the new content there and the temporary kept.
  const explained = possiblyReplaced && e.kind === "WRITE" && e.finalFp !== null;
  const otherSync = explained ? explainWrite(shell.state.otherSync, e.objectId, e.finalFp) : shell.state.otherSync;
  await commit(shell, { ...shell.state, journal: null, otherSync });
  return "CANCEL";
}

/**
 * Imports a kept temporary (or a stray) as a recovery note: renamed to `nodra-recuperado-<hex>.md` in
 * its folder and recorded as a new object of the user (§15). Returns the note's path, or null.
 */
export async function importRecovery(shell: Shell, path: PhysicalPath): Promise<PhysicalPath | null> {
  let target = path;
  if (!isRecoveryName(path)) {
    const { files, folders } = await listAll(shell.fs);
    const keys = new Set([...files, ...folders].map(comparisonKey));
    const name = recoveryName(path, [shell.hex8(), shell.hex8(), shell.hex8()], (p) => keys.has(comparisonKey(p)));
    if (name === null) return null;
    if (!(await guarded(() => shell.fs.rename(path, name), async () => (await shell.fs.stat(path)) !== null && (await shell.fs.stat(name)) === null))) return null;
    target = name;
  }
  const content = await readIfExists(shell.fs, target);
  if (content === null) return null;
  const hash = await shell.hasher.hash(content);
  const id = shell.newId("recovery-");
  const observation: Observation = { kind: "PRESENT", logicalPath: target, physicalPath: target, hash };
  await commit(shell, { ...shell.state, observations: new Map(shell.state.observations).set(id, observation) });
  const identity = shell.fs.identityOf(target);
  if (identity !== null) shell.identities.set(id, identity);
  return target;
}

/** Replays the entry a previous instance left open (§15 table), before observing anything else. */
export async function replayOpenEntry(shell: Shell): Promise<"COMPLETE" | "CANCEL" | null> {
  const e = shell.state.journal;
  if (e === null) return null;
  if (e.kind === "DELETE" && e.tmpName !== null && (await shell.fs.stat(tmpPath(e))) !== null) return finishParked(shell);
  const dest = await fingerprint(shell, e.destPath);
  const decision = replay(e, {
    tmpExists: e.tmpName !== null && (await shell.fs.stat(tmpPath(e))) !== null,
    destFp: dest === "FOLDER" ? "FOLDER" : dest,
    sourceExists: e.sourcePath !== null && (await shell.fs.stat(e.sourcePath)) !== null,
  });
  if (decision === "COMPLETE") {
    await close(shell);
    return "COMPLETE";
  }
  return cancel(shell, e.tmpCreated);
}

/**
 * Q33: after the client vacated `path`, remove its parent folders that this instance created and that
 * are now empty (re-listed right before), deepest first. Never a folder the client did not create.
 */
export async function removeVacatedFolders(shell: Shell, path: PhysicalPath): Promise<void> {
  for (let folder = parentOf(path); folder !== ""; folder = parentOf(folder)) {
    if (!shell.createdFolders.has(folder)) return;
    const l = await shell.fs.list(folder);
    if (l.files.length > 0 || l.folders.length > 0) return;
    if (!(await guarded(() => shell.fs.rmdir(folder), async () => (await shell.fs.list(folder)).files.length === 0))) return;
    shell.createdFolders.delete(folder);
  }
}

