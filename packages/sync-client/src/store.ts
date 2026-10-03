import Dexie from "dexie";
import { type ClientFacts, type Content, type Intent, type IntentState, type ObjectId, adoptReplicaId, fencedWriteAllowed, takeLeadership as nextLeaderEpoch } from "@nodra/sync-core";
import type { DeviceLocalCrypto } from "./ports.js";
import type { ClientJournalEntry, Observation, VaultState } from "./state.js";

// IndexedDB persistence of one vault's facts (§12.2 table, §15, §20.1, §20.2) with Dexie.
//
// One database per (installation, vault): `nodra:<install_ns>:<vault_id>` (§20.2 namespaces).
// `persist(before, after)` writes the difference between two states in ONE readwrite transaction,
// so every sync-core transition (a pure function from state to state) is atomic by construction.
//
// HARD RULE (CLAUDE.md "Persistencia"): nothing but IndexedDB is awaited inside a transaction.
// Structurally: the transaction bodies below only receive rows that are already computed and
// sealed; encryption (Device Local Key, rule 16) happens before the transaction opens, decryption
// after the read transaction closes. No caller can pass a callback into a transaction.

export const SCHEMA_VERSION = 6;

/** The vault-state tables of schema versions 1 to 3. */
const SCHEMA_V3 = {
  /** The vault's `meta` row: leader_epoch (§20.2 fencing), ids, write epoch and event cursor (§13.2). */
  meta: "id",
  /** S (§12.2 rule 1). */
  synced: "objectId",
  /** R cache (§12.2 rule 3). */
  remote: "objectId",
  /** Last local observation (§12.2 table), persisted at every observation (Q45). */
  observations: "objectId",
  /** Immutable outbox entries (rule 13), plaintext sealed with the Device Local Key (rule 16). */
  outbox: "mutationId, position",
  /** Write-ahead upload attempts with their exact ciphertext (rule 13). */
  attempts: "attemptId, &mutationId, position",
  /** pending_upload_cleanup (rule 13). */
  cleanup: "blobId, position",
  /** Blocked content (rule 8). */
  blocked: "id, objectId, position",
  /** INVALID_BATCH counters, upload failures (§12.6) and byte caps (§12.1). */
  counters: "id",
  /** The apply journal (§15): at most one row, content sealed. */
  journal: "id",
  /** local_compare_hash cache by revision_id (§12.2). */
  hashes: "revisionId",
  /** pending_intents (§20.2), change content sealed. */
  pendingIntents: "intentId, [contextId+intentSeq]",
  /** The leader's intent store per object: local_version and last intent (§20.2). */
  intentObjects: "objectId",
  /** Intents turned into conflict copies, at most one per context (§20.2). */
  copyLinks: "contextId",
} as const;

const SCHEMA = {
  ...SCHEMA_V3,
  /** The observation cache (stat-cache.ts, NOTES question 146), by physical path. Added in schema version 4. */
  fileStats: "path",
  /** §20.2 another sync tool (NOTES question 419): final_fp of this replica's last own WRITE per object. Added in schema version 6. */
  explainedWrites: "objectId",
  /** §20.2: the remote revision per object whose arrival the user accepted. Added in schema version 6. */
  acknowledgedArrivals: "objectId",
} as const;

/** The vault-state tables of schema versions 4 and 5. */
const SCHEMA_V5 = { ...SCHEMA_V3, fileStats: "path" } as const;

/**
 * The web replica's note store (§20.1, §20.2: "en web, el estado del editor en IndexedDB"), in the vault's
 * database so that its writes are fenced by `meta` like every other leader write (idb-fs.ts). Not part of
 * the vault state: the plugin never uses it, and `loadVault` never reads it. Added in schema version 2.
 */
const FILES_SCHEMA = { files: "path, parent" } as const;
/** The note store's change counter (idb-fs.ts `Stat.mtime`, a `counter` marker). Added in schema version 4. */
const FILE_SEQ_SCHEMA = { fileSeq: "id" } as const;
/**
 * §28.3 / §29 / §32.1 pins: the last root generation, registry version and Epoch Descriptor this
 * client PROVED. Added in schema version 5.
 *
 * Deliberately outside {@link SCHEMA}: `persist` mirrors the sync-core state onto every table it
 * lists, so a pin there would be deleted at the first transition. A pin is not vault state — it is
 * a fact about what this device has verified, written by whichever context verified it (leader or
 * not), which is also why its writes are not fenced.
 */
const PINS_SCHEMA = { pins: "id" } as const;

export type TableName = keyof typeof SCHEMA;
export const TABLES = Object.keys(SCHEMA) as TableName[];

export interface StoreOptions {
  /** `plugin:<installation_id hex>` or `web:<account_id hex>` (§20.2). */
  readonly installNs: string;
  readonly vaultId: string;
  /** Injected IndexedDB (tests: fake-indexeddb); defaults to the global one. */
  readonly indexedDB?: IDBFactory;
  readonly IDBKeyRange?: typeof IDBKeyRange;
}

export interface VaultStore {
  readonly db: Dexie;
}

export class FencedOut extends Error {
  override readonly name = "FencedOut";
}

/** A write aborted by §20.2 fencing (whatever wrapper the IndexedDB library puts around it). */
export const isFencedOut = (e: unknown): boolean =>
  e !== null && typeof e === "object" && (e instanceof FencedOut || (e as { name?: unknown }).name === "FencedOut" || isFencedOut((e as { inner?: unknown }).inner ?? null));

export async function openVaultStore(options: StoreOptions): Promise<VaultStore> {
  const deps = options.indexedDB && options.IDBKeyRange ? { indexedDB: options.indexedDB, IDBKeyRange: options.IDBKeyRange } : {};
  const db = new Dexie(`nodra:${options.installNs}:${options.vaultId}`, deps);
  db.version(1).stores(SCHEMA_V3);
  db.version(2).stores({ ...SCHEMA_V3, ...FILES_SCHEMA });
  // Version 3: content is bytes (NOTES question 52). Sealed content was already the AES-GCM of the UTF-8
  // bytes, so it opens unchanged as bytes. An attempt's ciphertext was a string whose UTF-8 bytes were the
  // PUT body and the input of its ciphertext_sha256: it becomes exactly those bytes (rule 13 still holds).
  db.version(3)
    .stores({ ...SCHEMA_V3, ...FILES_SCHEMA })
    .upgrade((tx) =>
      tx
        .table("attempts")
        .toCollection()
        .modify((row: { blobs: Array<{ ciphertext: unknown }> }) => {
          for (const b of row.blobs) if (typeof b.ciphertext === "string") b.ciphertext = new TextEncoder().encode(b.ciphertext);
        }),
    );
  // Version 4: the observation cache and the note store's change counter, both new and empty (the first
  // observation hashes every file, as before).
  db.version(4).stores({ ...SCHEMA_V5, ...FILES_SCHEMA, ...FILE_SEQ_SCHEMA });
  // Version 5: the §28.3/§29/§32.1 pins, new and empty. A client without one replays each chain from
  // its start, which is what §34.1 keeps possible and what §35.3 already requires.
  db.version(5).stores({ ...SCHEMA_V5, ...FILES_SCHEMA, ...FILE_SEQ_SCHEMA, ...PINS_SCHEMA });
  // Version 6: the §20.2 other-sync-tool facts, new and empty (nothing explained, nothing accepted).
  db.version(SCHEMA_VERSION).stores({ ...SCHEMA, ...FILES_SCHEMA, ...FILE_SEQ_SCHEMA, ...PINS_SCHEMA });
  await db.open();
  return { db };
}

export function closeVaultStore(store: VaultStore): void {
  store.db.close();
}

export interface MetaRow {
  readonly id: "meta";
  readonly leaderEpoch: number;
  readonly vaultId: string;
  readonly replicaId: string;
  readonly epochId: string;
  readonly cursor: number;
}

/** Creates the meta row of a new vault (one transaction); a no-op if it exists. */
export async function initVault(store: VaultStore, ids: { vaultId: string; replicaId: string; epochId: string }): Promise<void> {
  const meta = store.db.table<MetaRow, string>("meta");
  await store.db.transaction("rw", meta, async () => {
    if (!(await meta.get("meta"))) await meta.add({ id: "meta", leaderEpoch: 0, cursor: 0, ...ids });
  });
}

/** §20.2 "Relevo": the new leader's FIRST transaction increments leader_epoch; returns its value. */
export async function takeLeadership(store: VaultStore): Promise<number> {
  const meta = store.db.table<MetaRow, string>("meta");
  return store.db.transaction("rw", meta, async () => {
    const row = await meta.get("meta");
    if (!row) throw new Error("vault not initialized");
    const { epoch } = nextLeaderEpoch({ leaderEpoch: row.leaderEpoch });
    await meta.put({ ...row, leaderEpoch: epoch });
    return epoch;
  });
}

// ---------------------------------------------------------------------------
// Rows. Note content is carried as { $secret } until sealed (encrypted) before the transaction.

interface Secret {
  readonly $secret: Content;
}
interface Sealed {
  readonly $sealed: Uint8Array;
}
type Row = Record<string, unknown>;
type Rows = Record<TableName, Map<string, Row>>;

const secret = (content: Content | null): Secret | null => (content === null ? null : { $secret: content });

function rowsOf(s: VaultState): Rows {
  const f = s.facts;
  const rows = Object.fromEntries(TABLES.map((t) => [t, new Map<string, Row>()])) as Rows;
  const put = (t: TableName, key: string, row: Row) => rows[t].set(key, row);
  put("meta", "meta", { id: "meta", leaderEpoch: s.leaderEpoch, vaultId: f.vaultId, replicaId: f.replicaId, epochId: f.epochId, cursor: f.cursor });
  for (const [objectId, e] of f.synced) put("synced", objectId, { objectId, ...e });
  for (const [objectId, e] of f.remote) put("remote", objectId, { objectId, ...e });
  for (const [objectId, o] of s.observations) put("observations", objectId, { objectId, ...o });
  f.outbox.forEach((e, position) =>
    put("outbox", e.mutationId, { ...e, position, objects: e.objects.map((o) => ({ ...o, plaintext: secret(o.plaintext) })) }),
  );
  f.attempts.forEach((a, position) => put("attempts", a.attemptId, { ...a, position }));
  f.cleanup.forEach((c, position) => put("cleanup", c.blobId, { ...c, position }));
  f.blocked.forEach((b, position) => put("blocked", `${b.objectId}|${b.localCompareHash}`, { id: `${b.objectId}|${b.localCompareHash}`, ...b, position }));
  const counters: Array<[string, ReadonlyMap<string, number>]> = [
    ["invalidBatch", f.invalidBatchCounts],
    ["uploadFailure", f.uploadFailures],
    ["byteCap", f.byteCaps],
  ];
  for (const [kind, m] of counters) for (const [name, value] of m) put("counters", `${kind}:${name}`, { id: `${kind}:${name}`, kind, name, value });
  if (s.journal) put("journal", "open", { id: "open", ...s.journal, content: secret(s.journal.content) });
  for (const [revisionId, hash] of s.hashes) put("hashes", revisionId, { revisionId, hash });
  for (const i of s.intents) put("pendingIntents", i.intentId, { ...i, change: { ...i.change, content: secret(i.change.content) } });
  const objects = new Set([...s.intentState.localVersion.keys(), ...s.intentState.lastIntent.keys()]);
  for (const objectId of objects) {
    put("intentObjects", objectId, { objectId, localVersion: s.intentState.localVersion.get(objectId) ?? null, lastIntent: s.intentState.lastIntent.get(objectId) ?? null });
  }
  for (const [contextId, link] of s.intentState.copyLinks) put("copyLinks", contextId, { contextId, ...link });
  for (const [path, e] of s.fileStats) put("fileStats", path, { path, ...e });
  for (const [objectId, hash] of s.otherSync.explainedWrites) put("explainedWrites", objectId, { objectId, hash });
  for (const [objectId, revisionId] of s.otherSync.acknowledged) put("acknowledgedArrivals", objectId, { objectId, revisionId });
  return rows;
}

/** Replaces every { $secret } by { $sealed } (async, outside any transaction). */
async function seal(value: unknown, dlc: DeviceLocalCrypto): Promise<unknown> {
  if (value === null || typeof value !== "object" || value instanceof Uint8Array) return value;
  if ("$secret" in value) return { $sealed: await dlc.encrypt((value as Secret).$secret) } satisfies Sealed;
  if (Array.isArray(value)) return Promise.all(value.map((v) => seal(v, dlc)));
  const out: Row = {};
  for (const [k, v] of Object.entries(value)) out[k] = await seal(v, dlc);
  return out;
}

/** Replaces every { $sealed } by its plaintext (async, after the read transaction). */
async function unseal(value: unknown, dlc: DeviceLocalCrypto): Promise<unknown> {
  if (value === null || typeof value !== "object" || value instanceof Uint8Array) return value;
  if ("$sealed" in value) return dlc.decrypt((value as Sealed).$sealed);
  if (Array.isArray(value)) return Promise.all(value.map((v) => unseal(v, dlc)));
  const out: Row = {};
  for (const [k, v] of Object.entries(value)) out[k] = await unseal(v, dlc);
  return out;
}

/**
 * Identity tokens of byte arrays (NOTES question 147). State values are immutable, so the same array is
 * the same bytes; two distinct arrays compare as different, which only re-writes an equal row (never
 * skips a changed one). Serializing the bytes instead cost a base64 of every outbox plaintext and every
 * attempt ciphertext at every transition, whatever it changed (question 143).
 */
const byteIds = new WeakMap<Uint8Array, number>();
let nextByteId = 0;
const byteId = (v: Uint8Array): number => {
  let id = byteIds.get(v);
  if (id === undefined) byteIds.set(v, (id = ++nextByteId));
  return id;
};

/** A row's comparison key; a byte array compares by identity (above), never as `{"0":…}` objects. */
const rowKey = (row: Row): string => JSON.stringify(row, (_k, v: unknown) => (v instanceof Uint8Array ? `u8#${byteId(v)}` : v));

interface Writes {
  readonly table: TableName;
  readonly puts: readonly Row[];
  readonly deletes: readonly string[];
}

/**
 * Persists the transition `before → after` in ONE readwrite transaction over the tables it touches
 * plus `meta`, which is read first for §20.2 fencing (a deposed leader's write aborts).
 */
export async function persist(store: VaultStore, dlc: DeviceLocalCrypto, before: VaultState, after: VaultState): Promise<void> {
  const prev = rowsOf(before);
  const next = rowsOf(after);
  const writes: Writes[] = [];
  for (const table of TABLES) {
    const puts: Row[] = [];
    for (const [key, row] of next[table]) {
      const old = prev[table].get(key);
      if (old === undefined || rowKey(old) !== rowKey(row)) puts.push(row);
    }
    const deletes = [...prev[table].keys()].filter((k) => !next[table].has(k));
    if (puts.length > 0 || deletes.length > 0) writes.push({ table, puts: (await seal(puts, dlc)) as Row[], deletes });
  }
  if (writes.length === 0) return;
  await write(store, after.leaderEpoch, writes);
}

/** The only readwrite transaction body of a transition: precomputed rows, IndexedDB calls only. */
function write(store: VaultStore, fence: number, writes: readonly Writes[]): Promise<void> {
  const names = new Set<TableName>(["meta", ...writes.map((w) => w.table)]);
  const tables = [...names].map((n) => store.db.table(n));
  return store.db.transaction("rw", tables, async () => {
    const meta = (await store.db.table<MetaRow, string>("meta").get("meta")) ?? null;
    if (meta === null || !fencedWriteAllowed({ leaderEpoch: meta.leaderEpoch }, fence)) {
      throw new FencedOut(`fenced: leader_epoch is ${meta?.leaderEpoch ?? "missing"}, this leader holds ${fence}`);
    }
    for (const w of writes) {
      const t = store.db.table(w.table);
      if (w.deletes.length > 0) await t.bulkDelete([...w.deletes]);
      if (w.puts.length > 0) await t.bulkPut([...w.puts]);
    }
  });
}

/**
 * §6, §35.8: the vault's facts follow the replica that leads now. A trusted replica's id is its
 * recipient_id, which a re-enrollment changes; the new leader records the new id (and drops the
 * previous one's cleanup records, §12.2 rule 13) in one fenced transaction before it plans anything.
 * Nothing else changes: the outbox and the journal survive a re-enrollment (§18.3, §35.8 step 2).
 */
export async function adoptReplica(store: VaultStore, dlc: DeviceLocalCrypto, state: VaultState, replicaId: string): Promise<VaultState> {
  const facts = adoptReplicaId(state.facts, replicaId);
  if (facts === state.facts) return state;
  const after = { ...state, facts };
  await persist(store, dlc, state, after);
  return after;
}

/** Reads every table in one read transaction, then decrypts outside it. */
export async function loadVault(store: VaultStore, dlc: DeviceLocalCrypto): Promise<VaultState> {
  const raw = await store.db.transaction("r", TABLES.map((t) => store.db.table(t)), async () => {
    const out = {} as Record<TableName, Row[]>;
    for (const t of TABLES) out[t] = (await store.db.table(t).toArray()) as Row[];
    return out;
  });
  const rows = (await unseal(raw, dlc)) as Record<TableName, Row[]>;
  const meta = rows.meta[0] as unknown as MetaRow | undefined;
  if (!meta) throw new Error("vault not initialized");
  const strip = <T>(row: Row, ...keys: string[]): T => {
    const copy = { ...row };
    for (const k of keys) delete copy[k];
    return copy as T;
  };
  const byPosition = (xs: Row[]) => [...xs].sort((a, b) => (a.position as number) - (b.position as number));
  const counters = (kind: string) => new Map(rows.counters.filter((c) => c.kind === kind).map((c) => [c.name as string, c.value as number]));
  const facts: ClientFacts = {
    vaultId: meta.vaultId,
    replicaId: meta.replicaId,
    epochId: meta.epochId,
    cursor: meta.cursor,
    synced: new Map(rows.synced.map((r) => [r.objectId as string, strip(r, "objectId")])),
    remote: new Map(rows.remote.map((r) => [r.objectId as string, strip(r, "objectId")])),
    outbox: byPosition(rows.outbox).map((r) => strip(r, "position")),
    attempts: byPosition(rows.attempts).map((r) => strip(r, "position")),
    cleanup: byPosition(rows.cleanup).map((r) => strip(r, "position")),
    blocked: byPosition(rows.blocked).map((r) => strip(r, "position", "id")),
    invalidBatchCounts: counters("invalidBatch"),
    uploadFailures: counters("uploadFailure"),
    byteCaps: counters("byteCap"),
  };
  const intentState: IntentState = {
    localVersion: new Map(rows.intentObjects.filter((r) => r.localVersion !== null).map((r) => [r.objectId as string, r.localVersion as number])),
    lastIntent: new Map(
      rows.intentObjects.filter((r) => r.lastIntent !== null).map((r) => [r.objectId as string, r.lastIntent as { intentId: string; version: number }]),
    ),
    copyLinks: new Map(rows.copyLinks.map((r) => [r.contextId as string, strip(r, "contextId")])),
  };
  const journalRow = rows.journal[0];
  return {
    leaderEpoch: meta.leaderEpoch,
    facts,
    observations: new Map(rows.observations.map((r) => [r.objectId as string, strip<Observation>(r, "objectId")])),
    journal: journalRow ? strip<ClientJournalEntry>(journalRow, "id") : null,
    hashes: new Map(rows.hashes.map((r) => [r.revisionId as string, r.hash as string])),
    intents: sortIntents(rows.pendingIntents),
    intentState,
    fileStats: new Map(rows.fileStats.map((r) => [r.path as string, strip(r, "path")])),
    otherSync: {
      explainedWrites: new Map(rows.explainedWrites.map((r) => [r.objectId as string, r.hash as string])),
      acknowledged: new Map(rows.acknowledgedArrivals.map((r) => [r.objectId as string, r.revisionId as string])),
    },
  };
}

const sortIntents = (rows: Row[]): Intent[] =>
  [...rows].sort((a, b) => (a.contextId === b.contextId ? (a.intentSeq as number) - (b.intentSeq as number) : a.contextId! < b.contextId! ? -1 : 1)) as unknown as Intent[];

// ---------------------------------------------------------------------------
// pending_intents outside the leader's transitions (§20.2 "Seguidores", "Entrega garantizada").

/**
 * A follower writes its intent BEFORE announcing it on the channel: sealed first (Device Local Key),
 * then one readwrite transaction that only inserts the row. Not fenced: a follower never writes the
 * leader's state, and a row is a fact whoever the leader is. `add` fails on a duplicate intent_id.
 */
export async function insertIntent(store: VaultStore, dlc: DeviceLocalCrypto, intent: Intent): Promise<void> {
  const row = (await seal({ ...intent, change: { ...intent.change, content: secret(intent.change.content) } }, dlc)) as Row;
  const table = store.db.table("pendingIntents");
  await store.db.transaction("rw", table, async () => {
    await table.add(row);
  });
}

/** The leader's sweep: every pending_intents row, in (context, intent_seq) order. */
export async function loadPendingIntents(store: VaultStore, dlc: DeviceLocalCrypto): Promise<Intent[]> {
  const table = store.db.table("pendingIntents");
  const raw = await store.db.transaction("r", table, async () => (await table.toArray()) as Row[]);
  return sortIntents((await unseal(raw, dlc)) as Row[]);
}

/** The intent ids of one context still pending (a follower's rescan, §20.2 "Entrega garantizada"). */
export async function pendingIntentIds(store: VaultStore, contextId: string): Promise<Set<string>> {
  const table = store.db.table("pendingIntents");
  const rows = await store.db.transaction("r", table, async () => (await table.toArray()) as Row[]);
  return new Set(rows.filter((r) => r.contextId === contextId).map((r) => r.intentId as string));
}

/** What a follower reads to edit on (§20.2): the local state of each object and its local_version. */
export async function readLocalView(store: VaultStore): Promise<{ observations: Map<ObjectId, Observation>; localVersion: Map<ObjectId, number> }> {
  const tables = [store.db.table("observations"), store.db.table("intentObjects")];
  const [obs, versions] = await store.db.transaction("r", tables, async () => [(await tables[0]!.toArray()) as Row[], (await tables[1]!.toArray()) as Row[]]);
  return {
    observations: new Map(obs!.map((r) => {
      const copy = { ...r };
      delete copy.objectId;
      return [r.objectId as string, copy as unknown as Observation];
    })),
    localVersion: new Map(versions!.filter((r) => r.localVersion !== null).map((r) => [r.objectId as string, r.localVersion as number])),
  };
}

// ---------------------------------------------------------------------------
// §22 `LocalStore.pins`: the §28.3, §29 and §32.1 pins of this device, for this vault's database.

/** What a trusted client remembers about each chain (§28.3, §29, §32.1). Byte fields are hex. */
export interface StoredPins {
  /** §28.3: the root generation in force when this client last verified, and its `root_hash`. */
  readonly root?: { readonly generation: number; readonly rootHash: string };
  /** §29: the registry version in force then, and its `registry_hash`. */
  readonly registry?: { readonly version: number; readonly registryHash: string };
  /** §32.1: "el último `descriptor_hash` de cada vault" — this database holds exactly one vault. */
  readonly epoch?: { readonly epochId: string; readonly descriptorHash: string };
}

type PinRow = { readonly id: keyof StoredPins } & Record<string, unknown>;

/** Every pin this device has proved for this vault. Absent keys mean "never verified here". */
export async function readPins(store: VaultStore): Promise<StoredPins> {
  const table = store.db.table("pins");
  const rows = await store.db.transaction("r", table, async () => (await table.toArray()) as PinRow[]);
  const out: Record<string, unknown> = {};
  for (const { id, ...rest } of rows) out[id] = rest;
  return out as StoredPins;
}

/**
 * Advances the pins this device holds, in one transaction.
 *
 * Not fenced: a pin is not the leader's state, and §28.3 / §32.1 make it monotonic anyway — the
 * verifier that produced it refused anything that did not extend what was already proved, so two
 * contexts writing concurrently can only write the same value or a strictly later one.
 */
export async function writePins(store: VaultStore, pins: StoredPins): Promise<void> {
  const rows = Object.entries(pins)
    .filter(([, v]) => v !== undefined)
    .map(([id, v]) => ({ id, ...(v as object) }));
  if (rows.length === 0) return;
  const table = store.db.table("pins");
  await store.db.transaction("rw", table, async () => {
    await table.bulkPut(rows);
  });
}

// ---------------------------------------------------------------------------
// This installation's vault databases, what is not synced in them, and forgetting them (NOTES question 413).

type InstallationDeps = Omit<StoreOptions, "vaultId">;

const idbOf = (o: InstallationDeps): IDBFactory | undefined => o.indexedDB ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB;

/**
 * The vaults this installation holds a database for: the `nodra:<install_ns>:<vault_id>` names
 * `indexedDB.databases()` lists, plus `known` (the vault the host chose, for a platform that cannot list).
 */
export async function localVaultIds(o: InstallationDeps & { readonly known?: readonly string[] }): Promise<string[]> {
  const prefix = `nodra:${o.installNs}:`;
  const listed = (await idbOf(o)?.databases?.().catch(() => [])) ?? [];
  const found = listed.map((d) => d.name ?? "").filter((n) => n.startsWith(prefix)).map((n) => n.slice(prefix.length));
  return [...new Set([...(o.known ?? []).filter((id) => id !== ""), ...found])];
}

/**
 * How many objects hold a local change this vault's database has not confirmed on the server: in the
 * outbox, in `pending_intents`, in the open journal entry, or with L ≠ S at the last observation (§20.1
 * "trabajo pendiente"). Read without the Device Local Key: only ids, paths and hashes are compared.
 */
export async function unsyncedChanges(store: VaultStore): Promise<number> {
  const names = ["synced", "observations", "outbox", "pendingIntents", "journal"] as const;
  const tables = names.map((n) => store.db.table(n));
  const [synced, observations, outbox, intents, journal] = await store.db.transaction("r", tables, () => Promise.all(tables.map((t) => t.toArray() as Promise<Row[]>)));
  const s = new Map(synced!.map((r) => [r.objectId as string, r as unknown as RevisionEntryRow]));
  const changed = new Set<string>();
  for (const e of outbox!) for (const r of e.objects as readonly { objectId: string }[]) changed.add(r.objectId);
  for (const i of [...intents!, ...journal!]) changed.add(i.objectId as string);
  for (const r of observations!) {
    const o = r as unknown as Observation & { objectId: string };
    const base = s.get(o.objectId);
    const live = base !== undefined && !base.deleted;
    if (o.kind === "PRESENT" && (!live || base.path !== o.logicalPath || base.localCompareHash !== o.hash)) changed.add(o.objectId);
    if (o.kind === "ABSENT" && live) changed.add(o.objectId);
  }
  return changed.size;
}

interface RevisionEntryRow {
  readonly path: string;
  readonly localCompareHash: string | null;
  readonly deleted: boolean;
}

/** Deletes one vault's database (every table: S, R, outbox, journal, intents, pins, the web's notes). */
export async function deleteVaultStore(o: StoreOptions): Promise<void> {
  const deps = o.indexedDB && o.IDBKeyRange ? { indexedDB: o.indexedDB, IDBKeyRange: o.IDBKeyRange } : {};
  await new Dexie(`nodra:${o.installNs}:${o.vaultId}`, deps).delete();
}
