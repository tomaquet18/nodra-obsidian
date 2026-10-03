import Dexie from "dexie";
import { afterEach, describe, expect, it } from "vitest";
import { closeVaultStore, initVault, loadVault, openVaultStore, persist, takeLeadership } from "../src/store.js";
import { deviceLocal, emptyVault, freshIdb, richVault } from "./fixtures.js";
import { guardForeignAwaits } from "./guard.js";
import { utf8 } from "./support/bytes.js";

// CLAUDE.md "Persistencia": never await anything that is not IndexedDB inside a Dexie transaction.
// An IndexedDB transaction commits by itself as soon as it has no pending request, so awaiting
// crypto.subtle, fetch or a timer kills it midway.

describe("no non-IndexedDB await inside a Dexie transaction", () => {
  let restore: (() => void) | null = null;
  afterEach(() => {
    restore?.();
    restore = null;
  });

  it("the hazard is real: awaiting crypto.subtle inside a transaction makes the next write fail", async () => {
    const db = new Dexie("hazard", freshIdb());
    db.version(1).stores({ t: "k" });
    await db.open();
    const attempt = db.transaction("rw", db.table("t"), async () => {
      await db.table("t").put({ k: 1 });
      await crypto.subtle.digest("SHA-256", new Uint8Array([1, 2, 3]));
      await db.table("t").put({ k: 2 });
    });
    await expect(attempt).rejects.toThrow(/PrematureCommit|TransactionInactive|committed too early|not active/i);
    db.close();
  });

  it("the guard detects it: Web Crypto called while a transaction is active throws", async () => {
    restore = guardForeignAwaits();
    const db = new Dexie("guarded", freshIdb());
    db.version(1).stores({ t: "k" });
    await db.open();
    const dlc = await deviceLocal(); // outside any transaction: allowed
    const broken = db.transaction("rw", db.table("t"), async () => {
      const sealed = await dlc.encrypt(utf8("note")); // the broken shape: encrypt inside the transaction
      await db.table("t").put({ k: 1, sealed });
    });
    await expect(broken).rejects.toThrow(/inside a Dexie transaction/);
    db.close();
  });

  it("every store transition passes the guard (encryption and hashing happen before the transaction)", async () => {
    const idb = freshIdb();
    const dlc = await deviceLocal();
    restore = guardForeignAwaits();
    const store = await openVaultStore({ installNs: "plugin:0001", vaultId: "vault-1", ...idb });
    await initVault(store, { vaultId: "vault-1", replicaId: "replica-1", epochId: "e1" });
    const epoch = await takeLeadership(store);
    const rich = richVault(epoch);
    await persist(store, dlc, { ...emptyVault(), leaderEpoch: epoch }, rich);
    expect(await loadVault(store, dlc)).toEqual(rich);
    await persist(store, dlc, rich, { ...rich, journal: null, intents: [] });
    closeVaultStore(store);
  });
});
