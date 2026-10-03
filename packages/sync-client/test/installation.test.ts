import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { describe, expect, it } from "vitest";
import { getOrCreate, installationStore, openInstallation } from "../src/installation.js";
import { guardForeignAwaits } from "./guard.js";
import { utf8 } from "./support/bytes.js";

// §20.1: the Device Local Key and the LocalCompareKey survive a restart, or every stored
// local_compare_hash and sealed outbox entry would be lost; the replica id (§6) is stable too.

describe("per-installation state", () => {
  it("a reopened installation has the same replica id, the same LocalCompareKey and opens what it sealed", async () => {
    const idb = { indexedDB: new IDBFactory(), IDBKeyRange };
    const first = await openInstallation({ installNs: "plugin:abc", vaultId: "v1", ...idb });
    const hash = await first.hasher.hash(utf8("note"));
    const sealed = await first.dlc.encrypt(utf8("secret"));
    first.close();
    const again = await openInstallation({ installNs: "plugin:abc", vaultId: "v1", ...idb });
    expect(again.replicaId).toBe(first.replicaId);
    expect(await again.hasher.hash(utf8("note"))).toBe(hash);
    expect(await again.dlc.decrypt(sealed)).toEqual(utf8("secret"));
    again.close();
  });

  it("another vault of the installation has its own LocalCompareKey; another installation its own replica id", async () => {
    const idb = { indexedDB: new IDBFactory(), IDBKeyRange };
    const v1 = await openInstallation({ installNs: "plugin:abc", vaultId: "v1", ...idb });
    const v2 = await openInstallation({ installNs: "plugin:abc", vaultId: "v2", ...idb });
    const other = await openInstallation({ installNs: "plugin:def", vaultId: "v1", ...idb });
    expect(await v1.hasher.hash(utf8("note"))).not.toBe(await v2.hasher.hash(utf8("note")));
    expect(v2.replicaId).toBe(v1.replicaId);
    expect(other.replicaId).not.toBe(v1.replicaId);
    for (const i of [v1, v2, other]) i.close();
  });
});

describe("§20.2 install_version compare-and-set", () => {
  const idb = () => ({ indexedDB: new IDBFactory(), IDBKeyRange });

  it("of two commits against the same version exactly one lands; the loser changes nothing and sees the winner on re-read", async () => {
    const store = installationStore({ installNs: "web:abc", ...idb() });
    const snap = await store.read(["recipient"]);
    expect(snap.version).toBe(0);
    const results = await Promise.all([store.commit(snap.version, { recipient: "A" }), store.commit(snap.version, { recipient: "B" })]);
    expect(results.filter(Boolean)).toHaveLength(1);
    const after = await store.read(["recipient"]);
    expect(after.version).toBe(1);
    expect(after.rows.get("recipient")).toBe(results[0] ? "A" : "B");
  });

  it("a null value deletes, and still bumps the version", async () => {
    const store = installationStore({ installNs: "web:abc", ...idb() });
    expect(await store.commit(0, { recipient: "A", pins: 1 })).toBe(true);
    expect(await store.commit(1, { recipient: null })).toBe(true);
    const after = await store.read(["recipient", "pins"]);
    expect(after.version).toBe(2);
    expect(after.rows.has("recipient")).toBe(false);
    expect(after.rows.get("pins")).toBe(1);
  });

  it("getOrCreate from many contexts at once: one key wins, every context gets it, and nothing but IndexedDB runs inside a transaction", async () => {
    const shared = idb();
    const restore = guardForeignAwaits();
    try {
      let made = 0;
      const make = async () => {
        made++;
        await new Promise((r) => queueMicrotask(() => r(null)));
        return `key-${made}`;
      };
      const got = await Promise.all(Array.from({ length: 5 }, () => getOrCreate(installationStore({ installNs: "web:abc", ...shared }), "device_local_key", make)));
      expect(new Set(got).size).toBe(1);
      expect((await installationStore({ installNs: "web:abc", ...shared }).read(["device_local_key"])).rows.get("device_local_key")).toBe(got[0]);
    } finally {
      restore();
    }
  });
});
