import Dexie from "dexie";
import { describe, expect, it, vi } from "vitest";
import { type VaultStore, adoptReplica, closeVaultStore, initVault, loadVault, openVaultStore, persist, takeLeadership, SCHEMA_VERSION, TABLES } from "../src/store.js";
import type { VaultState } from "../src/state.js";
import { SECRET, SECRET_TEXT, deviceLocal, emptyVault, freshIdb, richVault } from "./fixtures.js";

const open = (idb: ReturnType<typeof freshIdb>, vaultId = "vault-1") => openVaultStore({ installNs: "plugin:0001", vaultId, ...idb });

async function started(idb: ReturnType<typeof freshIdb>, vaultId = "vault-1"): Promise<{ store: VaultStore; epoch: number }> {
  const store = await open(idb, vaultId);
  await initVault(store, { vaultId, replicaId: "replica-1", epochId: "e1" });
  return { store, epoch: await takeLeadership(store) };
}

/** Everything the store holds, as raw rows (what an attacker reading IndexedDB would see). */
async function rawDump(store: VaultStore): Promise<string> {
  const out: Record<string, unknown[]> = {};
  for (const t of TABLES) out[t] = await store.db.table(t).toArray();
  // Bytes are shown as Latin-1 text, so plaintext bytes stored unsealed would show up in the dump.
  return JSON.stringify(out, (_k, v) => (v instanceof Uint8Array ? String.fromCharCode(...v) : v));
}

describe("Dexie store (§20.1, §12.2 persistence table, §15, §20.2)", () => {
  it("is a versioned schema with one database per (installation, vault)", async () => {
    const idb = freshIdb();
    const a = await open(idb, "vault-1");
    const b = await open(idb, "vault-2");
    expect(a.db.name).toBe("nodra:plugin:0001:vault-1");
    expect(b.db.name).toBe("nodra:plugin:0001:vault-2");
    expect(a.db.verno).toBe(SCHEMA_VERSION);
    // files, fileSeq: the web note store (idb-fs.ts); pins: the §28.3/§29/§32.1 pins (directory.ts).
    // None of the three is vault state, which is why `persist` must not see them in TABLES.
    expect(a.db.tables.map((t) => t.name).sort()).toEqual([...TABLES, "files", "fileSeq", "pins"].sort());
    closeVaultStore(a);
    closeVaultStore(b);
  });

  it("schema 3 upgrade: an attempt's string ciphertext becomes exactly its UTF-8 bytes, the PUT body it had (NOTES question 142)", async () => {
    const idb = freshIdb();
    const old = new Dexie("nodra:plugin:0001:vault-1", idb);
    old.version(2).stores({ meta: "id", attempts: "attemptId, &mutationId, position" });
    await old.open();
    await old.table("meta").put({ id: "meta", leaderEpoch: 0, vaultId: "vault-1", replicaId: "replica-1", epochId: "e1", cursor: 0 });
    const blob = { blobId: "b1", kind: "CONTENT", objectId: "o1", declaredSize: 7, ciphertextSha256: "s", forDelete: false, expiresAt: null };
    await old.table("attempts").put({ attemptId: "a1", mutationId: "m1", replicaId: "replica-1", epochId: "e1", position: 0, blobs: [{ ...blob, ciphertext: "héllo✓" }] });
    old.close();
    const store = await open(idb);
    expect(store.db.verno).toBe(SCHEMA_VERSION);
    const state = await loadVault(store, await deviceLocal());
    expect(state.facts.attempts).toEqual([{ attemptId: "a1", mutationId: "m1", replicaId: "replica-1", epochId: "e1", blobs: [{ ...blob, ciphertext: new TextEncoder().encode("héllo✓") }] }]);
    closeVaultStore(store);
  });

  it("schema 4 upgrade: a version 3 vault opens with an empty observation cache (the next observation hashes everything)", async () => {
    const idb = freshIdb();
    const dlc = await deviceLocal();
    const old = new Dexie("nodra:plugin:0001:vault-1", idb);
    old.version(3).stores({ meta: "id", observations: "objectId", files: "path, parent" });
    await old.open();
    await old.table("meta").put({ id: "meta", leaderEpoch: 0, vaultId: "vault-1", replicaId: "replica-1", epochId: "e1", cursor: 0 });
    await old.table("observations").put({ objectId: "o1", kind: "PRESENT", logicalPath: "a.md", physicalPath: "a.md", hash: "h" });
    old.close();
    const store = await open(idb);
    expect(store.db.verno).toBe(SCHEMA_VERSION);
    const state = await loadVault(store, dlc);
    expect(state.fileStats).toEqual(new Map());
    expect(state.observations.get("o1")).toEqual({ kind: "PRESENT", logicalPath: "a.md", physicalPath: "a.md", hash: "h" });
    closeVaultStore(store);
  });

  it("question 147: a transition serializes no byte array to compare rows, and an equal copy of one only re-writes its row", async () => {
    const idb = freshIdb();
    const counting = await deviceLocal();
    let seals = 0;
    const dlc = { ...counting, encrypt: async (p: Uint8Array) => (seals++, counting.encrypt(p)) };
    const { store, epoch } = await started(idb);
    const rich = richVault(epoch);
    await persist(store, dlc, { ...emptyVault(), leaderEpoch: epoch }, rich);
    const btoa = vi.spyOn(globalThis, "btoa");
    seals = 0;
    const moved: VaultState = { ...rich, facts: { ...rich.facts, cursor: rich.facts.cursor + 1 } };
    await persist(store, dlc, rich, moved);
    expect(btoa).not.toHaveBeenCalled(); // before: a base64 of every outbox plaintext and attempt ciphertext, twice
    expect(seals).toBe(0);
    const [entry] = moved.facts.outbox;
    const copied: VaultState = {
      ...moved,
      facts: { ...moved.facts, outbox: [{ ...entry!, objects: entry!.objects.map((o) => ({ ...o, plaintext: o.plaintext && o.plaintext.slice() })) }, ...moved.facts.outbox.slice(1)] },
    };
    await persist(store, dlc, moved, copied);
    expect(seals).toBeGreaterThan(0); // written again (never skipped): a new array is not assumed equal
    btoa.mockRestore();
    closeVaultStore(store);
    const reopened = await open(idb);
    expect((await loadVault(reopened, counting)).facts.outbox).toEqual(copied.facts.outbox);
    closeVaultStore(reopened);
  });

  it("round-trips every persisted fact across a close and reopen (a crash)", async () => {
    const idb = freshIdb();
    const dlc = await deviceLocal();
    const { store, epoch } = await started(idb);
    const before: VaultState = { ...emptyVault(), leaderEpoch: epoch };
    const rich = richVault(epoch);
    await persist(store, dlc, before, rich);
    closeVaultStore(store);
    const reopened = await open(idb);
    expect(await loadVault(reopened, dlc)).toEqual(rich);
    closeVaultStore(reopened);
  });

  it("rule 16: note content is encrypted at rest; upload ciphertext is stored as it is", async () => {
    const idb = freshIdb();
    const dlc = await deviceLocal();
    const { store, epoch } = await started(idb);
    await persist(store, dlc, { ...emptyVault(), leaderEpoch: epoch }, richVault(epoch));
    const dump = await rawDump(store);
    expect(dump).not.toContain(SECRET_TEXT);
    expect(dump).not.toContain('"other"');
    expect(dump).toContain("opaque-ciphertext");
    // The dump can fail: content bytes stored unsealed would show up in it.
    await store.db.table("hashes").put({ revisionId: "leak", hash: SECRET });
    expect(await rawDump(store)).toContain(SECRET_TEXT);
    closeVaultStore(store);
  });

  it("removes what a transition removes (retired entry, closed journal, processed intent, forgotten observation)", async () => {
    const idb = freshIdb();
    const dlc = await deviceLocal();
    const { store, epoch } = await started(idb);
    const rich = richVault(epoch);
    await persist(store, dlc, { ...emptyVault(), leaderEpoch: epoch }, rich);
    const observations = new Map(rich.observations);
    observations.delete("o2");
    const next: VaultState = {
      ...rich,
      facts: { ...rich.facts, outbox: rich.facts.outbox.slice(1), attempts: [], cleanup: [], invalidBatchCounts: new Map(), cursor: 43 },
      journal: null,
      intents: rich.intents.slice(1),
      observations,
    };
    await persist(store, dlc, rich, next);
    closeVaultStore(store);
    const reopened = await open(idb);
    expect(await loadVault(reopened, dlc)).toEqual(next);
    closeVaultStore(reopened);
  });

  it("one transition is one transaction: a write that fails midway leaves nothing applied", async () => {
    const idb = freshIdb();
    const dlc = await deviceLocal();
    const { store, epoch } = await started(idb);
    const rich = richVault(epoch);
    await persist(store, dlc, { ...emptyVault(), leaderEpoch: epoch }, rich);
    // A value IndexedDB cannot store (structured clone fails) in a table written after others.
    const poisoned: VaultState = {
      ...rich,
      facts: { ...rich.facts, cursor: 99, outbox: rich.facts.outbox.slice(1) },
      hashes: new Map([...rich.hashes, ["r9", (() => "fn") as unknown as string]]),
    };
    await expect(persist(store, dlc, rich, poisoned)).rejects.toThrow();
    closeVaultStore(store);
    const reopened = await open(idb);
    expect(await loadVault(reopened, dlc)).toEqual(rich);
    closeVaultStore(reopened);
  });

  it("each persist runs exactly one readwrite transaction", async () => {
    const idb = freshIdb();
    const dlc = await deviceLocal();
    const { store, epoch } = await started(idb);
    const modes: string[] = [];
    const original = store.db.transaction.bind(store.db) as (...args: unknown[]) => unknown;
    (store.db as unknown as { transaction: (...args: unknown[]) => unknown }).transaction = (...args: unknown[]) => {
      modes.push(String(args[0]));
      return original(...args);
    };
    await persist(store, dlc, { ...emptyVault(), leaderEpoch: epoch }, richVault(epoch));
    expect(modes).toEqual(["rw"]);
    closeVaultStore(store);
  });

  it("§20.2 fencing: a deposed leader's transition aborts and writes nothing", async () => {
    const idb = freshIdb();
    const dlc = await deviceLocal();
    const { store, epoch } = await started(idb);
    const other = await open(idb);
    const newer = await takeLeadership(other);
    expect(newer).toBe(epoch + 1);
    await expect(persist(store, dlc, { ...emptyVault(), leaderEpoch: epoch }, richVault(epoch))).rejects.toThrow(/fenced/);
    const state = await loadVault(other, dlc);
    expect(state.facts.outbox).toEqual([]);
    expect(state.leaderEpoch).toBe(newer);
    closeVaultStore(store);
    closeVaultStore(other);
  });

  it("vaults never share rows", async () => {
    const idb = freshIdb();
    const dlc = await deviceLocal();
    const one = await started(idb, "vault-1");
    const two = await started(idb, "vault-2");
    await persist(one.store, dlc, { ...emptyVault(), leaderEpoch: one.epoch }, richVault(one.epoch));
    const loaded = await loadVault(two.store, dlc);
    expect(loaded.facts.outbox).toEqual([]);
    expect(loaded.observations.size).toBe(0);
    closeVaultStore(one.store);
    closeVaultStore(two.store);
  });

  it("§6/§35.8 re-enrollment: the new leader adopts the new replica id, drops the old id's cleanup records, keeps outbox and attempts", async () => {
    const idb = freshIdb();
    const dlc = await deviceLocal();
    const { store, epoch } = await started(idb);
    await persist(store, dlc, { ...emptyVault(), leaderEpoch: epoch }, richVault(epoch));
    const before = await loadVault(store, dlc);
    expect(before.facts.cleanup).toHaveLength(1);

    const same = await adoptReplica(store, dlc, before, "replica-1");
    expect(same).toBe(before); // same id: nothing written

    await adoptReplica(store, dlc, before, "replica-2");
    const after = await loadVault(store, dlc);
    expect(after.facts.replicaId).toBe("replica-2");
    expect(after.facts.cleanup).toEqual([]);
    expect(after.facts.outbox).toEqual(before.facts.outbox);
    expect(after.facts.attempts).toEqual(before.facts.attempts);
    expect(after.leaderEpoch).toBe(epoch);
    closeVaultStore(store);
  });

  it("§20.2: a deposed leader cannot adopt a replica id (the adoption is fenced like every write)", async () => {
    const idb = freshIdb();
    const dlc = await deviceLocal();
    const { store, epoch } = await started(idb);
    const loaded = { ...(await loadVault(store, dlc)), leaderEpoch: epoch };
    const other = await open(idb);
    await takeLeadership(other);
    await expect(adoptReplica(store, dlc, loaded, "replica-2")).rejects.toThrow(/fenced/);
    expect((await loadVault(other, dlc)).facts.replicaId).toBe("replica-1");
    closeVaultStore(store);
    closeVaultStore(other);
  });
});
