import { generateDeviceLocalKey, generateLocalCompareKey, webCryptoDeviceLocal, webCryptoLocalCompare } from "./crypto.js";
import type { DeviceLocalCrypto, LocalCompareHasher } from "./ports.js";
import Dexie from "dexie";
import { v7 as uuidv7 } from "uuid";

// Per-installation state of §20.1/§20.2 (plugin and web alike), in `nodra:<install_ns>`: the Device
// Local Key, the replica id (§6), the LocalCompareKey of each vault, and trust.ts's recipient row and
// account pins. Keys are generated non-extractable and stored as CryptoKey.
//
// §20.2: "El estado por instalación no usa lock de larga duración: cada actualización es una sola
// transacción readwrite de IndexedDB que compara y aumenta un contador install_version
// (compare-and-set); quien pierde la comparación relee y reintenta o aborta." Every write below goes
// through `commit`, which is exactly that transaction. Nothing is generated inside it (CLAUDE.md
// "Persistencia"): read, compute outside, then commit against the version that was read.

interface Row {
  readonly id: string;
  readonly value: unknown;
}

const VERSION = "install_version";

export interface IdbDeps {
  readonly indexedDB?: IDBFactory;
  readonly IDBKeyRange?: typeof IDBKeyRange;
}

/** What one read of the per-installation store saw: its `install_version` and the rows asked for. */
export interface InstallationSnapshot {
  readonly version: number;
  readonly rows: ReadonlyMap<string, unknown>;
}

/**
 * §20.2's compare-and-set over `nodra:<install_ns>`. `commit` writes (a `null` value deletes) and
 * bumps `install_version` in ONE readwrite transaction, only if the version is still `expected`;
 * false means another context got there first and the caller must re-read and decide again.
 */
export interface InstallationStore {
  read(ids: readonly string[]): Promise<InstallationSnapshot>;
  commit(expected: number, writes: Readonly<Record<string, unknown>>): Promise<boolean>;
}

/** `nodra:<install_ns>`, table `state`: one row per id, `install_version` among them. */
export function installationStore(o: { readonly installNs: string } & IdbDeps): InstallationStore {
  const deps = o.indexedDB && o.IDBKeyRange ? { indexedDB: o.indexedDB, IDBKeyRange: o.IDBKeyRange } : {};
  const withDb = async <T>(body: (db: Dexie, table: Dexie.Table<Row, string>) => Promise<T>): Promise<T> => {
    const db = new Dexie(`nodra:${o.installNs}`, deps);
    db.version(1).stores({ state: "id" });
    await db.open();
    try {
      return await body(db, db.table("state"));
    } finally {
      db.close();
    }
  };
  return {
    read: (ids) =>
      withDb((db, table) =>
        db.transaction("r", table, async () => {
          const rows = await table.bulkGet([VERSION, ...ids]);
          const version = (rows[0]?.value as number | undefined) ?? 0;
          const found = new Map<string, unknown>();
          ids.forEach((id, i) => {
            const row = rows[i + 1];
            if (row !== undefined) found.set(id, row.value);
          });
          return { version, rows: found };
        }),
      ),
    commit: (expected, writes) =>
      withDb((db, table) =>
        db.transaction("rw", table, async () => {
          const current = ((await table.get(VERSION))?.value as number | undefined) ?? 0;
          if (current !== expected) return false;
          for (const [id, value] of Object.entries(writes)) {
            if (value === null) await table.delete(id);
            else await table.put({ id, value });
          }
          await table.put({ id: VERSION, value: current + 1 });
          return true;
        }),
      ),
  };
}

/**
 * The value of `id`, created with `make` if absent: read, generate outside any transaction, commit
 * against the version read. A lost comparison re-reads; whoever inserted first wins, so every context
 * of the installation ends up with the same key.
 */
export async function getOrCreate<T>(store: InstallationStore, id: string, make: () => Promise<T>): Promise<T> {
  let made: { value: T } | null = null;
  for (;;) {
    const snap = await store.read([id]);
    if (snap.rows.has(id)) return snap.rows.get(id) as T;
    made ??= { value: await make() };
    if (await store.commit(snap.version, { [id]: made.value })) return made.value;
  }
}

export interface InstallationState {
  /** The dev stand-in's replica id only; a trusted replica's is its `recipient_id` (§6, trust.ts). */
  readonly replicaId: string;
  readonly dlc: DeviceLocalCrypto;
  readonly hasher: LocalCompareHasher;
  close(): void;
}

export async function openInstallation(o: { readonly installNs: string; readonly vaultId: string } & IdbDeps): Promise<InstallationState> {
  const store = installationStore(o);
  const replicaId = await getOrCreate(store, "replica_id", async () => uuidv7());
  const deviceKey = await getOrCreate(store, "device_local_key", generateDeviceLocalKey);
  const compareKey = await getOrCreate(store, `local_compare_key:${o.vaultId}`, generateLocalCompareKey);
  return { replicaId, dlc: webCryptoDeviceLocal(deviceKey), hasher: webCryptoLocalCompare(compareKey), close: () => {} };
}
