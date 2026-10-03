import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { describe, expect, it } from "vitest";
import { installationStore } from "../src/installation.js";
import { initVault, localVaultIds, openVaultStore, closeVaultStore, unsyncedChanges } from "../src/store.js";
import {
  ACCOUNT,
  ACCOUNT_ROWS,
  PINS,
  RECIPIENT,
  SECURITY_BUNDLE,
  accountPins,
  disconnectInstallation,
  installationAccount,
  localSyncState,
  readAccountRows,
  requireAccount,
  trustedIdentity,
  webInstallNs,
} from "../src/trust.js";
import { SECURITY_EVENTS } from "../src/security-events.js";

// NOTES question 413: the per-installation rows that belong to an account (§20.2) are used only for
// that account, and removed only by the user's explicit disconnect.

const A = "01900000-0000-7000-8000-00000000000a";
const B = "01900000-0000-7000-8000-00000000000b";
const PLUGIN = "plugin:0190000000007000800000000000abcd";
const pins = { rootGeneration: 1, rootHash: "aa", genesisRootHash: "aa", registryVersion: 1, registryHash: "bb", configVersion: 1 };
const rows = (entries: Record<string, unknown>) => new Map(Object.entries(entries));
const idb = () => ({ indexedDB: new IDBFactory(), IDBKeyRange });

describe("whose account state an installation holds", () => {
  it("nothing: NONE; an `account` row: that account; account rows without one: UNKNOWN", () => {
    expect(installationAccount(rows({ replica_id: "r", device_local_key: "k" }), PLUGIN)).toEqual({ kind: "NONE" });
    expect(installationAccount(rows({ [ACCOUNT]: { accountId: A, email: "a@x.test" }, [PINS]: pins }), PLUGIN)).toEqual({ kind: "ACCOUNT", accountId: A, email: "a@x.test" });
    for (const id of ACCOUNT_ROWS) expect(installationAccount(rows({ [id]: {} }), PLUGIN), id).toEqual({ kind: "UNKNOWN" });
    expect(ACCOUNT_ROWS).toEqual(expect.arrayContaining([RECIPIENT, PINS, SECURITY_BUNDLE, SECURITY_EVENTS]));
  });

  it("a browser's rows written before the `account` row: its namespace names the account (`web:<account_id hex>`)", () => {
    expect(installationAccount(rows({ [PINS]: pins }), webInstallNs(A))).toEqual({ kind: "ACCOUNT", accountId: A.replaceAll("-", ""), email: null });
    expect(() => requireAccount(rows({ [PINS]: pins }), { installNs: webInstallNs(A), accountId: A })).not.toThrow();
    expect(() => requireAccount(rows({ [PINS]: pins }), { installNs: webInstallNs(A), accountId: B })).toThrow(expect.objectContaining({ code: "INSTALLATION_OTHER_ACCOUNT" }));
    // An `account` row wins over the name, and an empty browser store is simply unbound.
    expect(installationAccount(rows({ [ACCOUNT]: { accountId: B, email: null }, [PINS]: pins }), webInstallNs(A))).toMatchObject({ accountId: B });
    expect(installationAccount(rows({}), webInstallNs(A))).toEqual({ kind: "NONE" });
  });

  it("requireAccount: the same account passes (whatever the dashes), another or an unknown one is INSTALLATION_OTHER_ACCOUNT naming it", () => {
    const bound = rows({ [ACCOUNT]: { accountId: A, email: "a@x.test" }, [RECIPIENT]: {} });
    expect(() => requireAccount(bound, { installNs: PLUGIN, accountId: A.replaceAll("-", "").toUpperCase() })).not.toThrow();
    expect(() => requireAccount(rows({}), { installNs: PLUGIN, accountId: B })).not.toThrow();
    expect(() => requireAccount(bound, { installNs: PLUGIN, accountId: B })).toThrow(expect.objectContaining({ code: "INSTALLATION_OTHER_ACCOUNT", other: { accountId: A, email: "a@x.test" } }));
    expect(() => requireAccount(rows({ [PINS]: pins }), { installNs: PLUGIN, accountId: A })).toThrow(expect.objectContaining({ code: "INSTALLATION_OTHER_ACCOUNT", other: { accountId: null, email: null } }));
  });
});

describe("reading account rows (IndexedDB)", () => {
  it("another account's pins and key are refused, and nothing is written or deleted by the refusal", async () => {
    const deps = idb();
    const store = installationStore({ installNs: PLUGIN, ...deps });
    expect(await store.commit(0, { [ACCOUNT]: { accountId: A, email: null }, [PINS]: pins, [RECIPIENT]: { status: "PENDING" } })).toBe(true);
    await expect(accountPins({ installNs: PLUGIN, accountId: B, ...deps })).rejects.toMatchObject({ code: "INSTALLATION_OTHER_ACCOUNT" });
    await expect(trustedIdentity({ installNs: PLUGIN, accountId: B, ...deps })).rejects.toMatchObject({ code: "INSTALLATION_OTHER_ACCOUNT" });
    await expect(readAccountRows(store, { installNs: PLUGIN, accountId: B }, [SECURITY_BUNDLE])).rejects.toMatchObject({ code: "INSTALLATION_OTHER_ACCOUNT" });
    const after = await store.read([ACCOUNT, PINS, RECIPIENT]);
    expect(after.version).toBe(1);
    expect(after.rows.size).toBe(3);
    expect(await accountPins({ installNs: PLUGIN, accountId: A, ...deps })).toEqual(pins);
  });

  it("legacy rows (no `account` row) are refused even to the account that wrote them, and are not deleted", async () => {
    const deps = idb();
    const store = installationStore({ installNs: PLUGIN, ...deps });
    await store.commit(0, { [PINS]: pins });
    await expect(accountPins({ installNs: PLUGIN, accountId: A, ...deps })).rejects.toMatchObject({ code: "INSTALLATION_OTHER_ACCOUNT", other: { accountId: null } });
    expect((await store.read([PINS])).rows.get(PINS)).toEqual(pins);
  });
});

describe("disconnectInstallation", () => {
  it("removes the account rows, every vault database and its LocalCompareKey; keeps the installation's own keys", async () => {
    const deps = idb();
    const store = installationStore({ installNs: PLUGIN, ...deps });
    const keep = { device_local_key: "dlk", replica_id: "r", "local_compare_key:other-installation-vault": "x" };
    await store.commit(0, { ...keep, [ACCOUNT]: { accountId: A, email: null }, [PINS]: pins, [RECIPIENT]: {}, [SECURITY_BUNDLE]: {}, [SECURITY_EVENTS]: {}, "local_compare_key:v1": "k1", "local_compare_key:v2": "k2" });
    for (const vaultId of ["v1", "v2"]) {
      const v = await openVaultStore({ installNs: PLUGIN, vaultId, ...deps });
      await initVault(v, { vaultId, replicaId: "r", epochId: "e" });
      closeVaultStore(v);
    }
    // Another installation's vault database on the same origin is not this one's.
    closeVaultStore(await openVaultStore({ installNs: "plugin:someoneelse", vaultId: "v1", ...deps }));
    expect((await localVaultIds({ installNs: PLUGIN, ...deps })).sort()).toEqual(["v1", "v2"]);

    await disconnectInstallation({ installNs: PLUGIN, ...deps });

    const after = await store.read([...Object.keys(keep), ACCOUNT, ...ACCOUNT_ROWS, "local_compare_key:v1", "local_compare_key:v2"]);
    expect(Object.fromEntries(after.rows)).toEqual(keep);
    expect(await localVaultIds({ installNs: PLUGIN, ...deps })).toEqual([]);
    expect(await localVaultIds({ installNs: "plugin:someoneelse", ...deps })).toEqual(["v1"]);
    // Unbound now: the next enrollment binds it to whoever signs in.
    expect(await accountPins({ installNs: PLUGIN, accountId: B, ...deps })).toBeNull();
  });

  it("refuses any installation that is not the plugin's: a browser's vault database holds the notes themselves", async () => {
    const deps = idb();
    const web = webInstallNs(A);
    const store = installationStore({ installNs: web, ...deps });
    await store.commit(0, { [ACCOUNT]: { accountId: A, email: null }, [PINS]: pins });
    const v = await openVaultStore({ installNs: web, vaultId: "v1", ...deps });
    await initVault(v, { vaultId: "v1", replicaId: "r", epochId: "e" });
    closeVaultStore(v);

    await expect(disconnectInstallation({ installNs: web, ...deps })).rejects.toMatchObject({ code: "DISCONNECT_UNSUPPORTED" });

    // Nothing was removed: the vault database (the web's notes) and the account rows are all there.
    expect(await localVaultIds({ installNs: web, ...deps })).toEqual(["v1"]);
    expect(Object.fromEntries((await store.read([ACCOUNT, PINS])).rows)).toEqual({ [ACCOUNT]: { accountId: A, email: null }, [PINS]: pins });
  });

  it("a known vault the platform cannot list is removed too; an installation with nothing is a no-op", async () => {
    const deps = idb();
    const f = deps.indexedDB;
    // An IndexedDB without `databases()` (a platform that cannot list): only the known vault is found.
    const noList = { ...deps, indexedDB: { open: f.open.bind(f), deleteDatabase: f.deleteDatabase.bind(f), cmp: f.cmp.bind(f) } as unknown as IDBFactory };
    const v = await openVaultStore({ installNs: PLUGIN, vaultId: "v1", ...deps });
    await initVault(v, { vaultId: "v1", replicaId: "r", epochId: "e" });
    closeVaultStore(v);
    expect(await localVaultIds({ installNs: PLUGIN, ...noList })).toEqual([]);
    await disconnectInstallation({ installNs: PLUGIN, ...noList, knownVaultIds: ["v1"] });
    expect(await localVaultIds({ installNs: PLUGIN, ...deps })).toEqual([]);
    await disconnectInstallation({ installNs: "plugin:empty", ...deps });
  });
});

describe("unsyncedChanges: what a disconnect would leave the other account without", () => {
  it("counts outbox objects, pending intents, the open journal and L ≠ S at the last observation; a synced object is not counted", async () => {
    const deps = idb();
    const v = await openVaultStore({ installNs: PLUGIN, vaultId: "v1", ...deps });
    await initVault(v, { vaultId: "v1", replicaId: "r", epochId: "e" });
    expect(await unsyncedChanges(v)).toBe(0);
    const entry = (path: string, hash: string, deleted = false) => ({ revisionId: `r-${path}`, sequence: 1, path, localCompareHash: hash, deleted, createdSequence: 1 });
    await v.db.table("synced").bulkPut([
      { objectId: "same", ...entry("same.md", "h1") },
      { objectId: "edited", ...entry("edited.md", "h1") },
      { objectId: "moved", ...entry("moved.md", "h1") },
      { objectId: "gone", ...entry("gone.md", "h1") },
      { objectId: "deleted", ...entry("deleted.md", "h1", true) },
    ]);
    const present = (objectId: string, logicalPath: string, hash: string) => ({ objectId, kind: "PRESENT", logicalPath, physicalPath: logicalPath, hash });
    await v.db.table("observations").bulkPut([
      present("same", "same.md", "h1"),
      present("edited", "edited.md", "h2"),
      present("moved", "elsewhere.md", "h1"),
      { objectId: "gone", kind: "ABSENT", logicalPath: "gone.md" },
      { objectId: "deleted", kind: "ABSENT", logicalPath: "deleted.md" },
      present("new", "new.md", "h3"),
    ]);
    expect(await unsyncedChanges(v)).toBe(4); // edited, moved, gone, new
    await v.db.table("outbox").put({ mutationId: "m", position: 0, objects: [{ objectId: "queued" }, { objectId: "edited" }] });
    await v.db.table("pendingIntents").put({ intentId: "i", contextId: "c", intentSeq: 1, objectId: "typed" });
    await v.db.table("journal").put({ id: "open", objectId: "applying" });
    expect(await unsyncedChanges(v)).toBe(7);
    closeVaultStore(v);
    expect(await localSyncState({ installNs: PLUGIN, ...deps })).toEqual({ vaultIds: ["v1"], unsynced: 7 });
  });
});
