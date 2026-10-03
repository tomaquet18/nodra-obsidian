import { describe, expect, it } from "vitest";
import { indexedDbFileSystem, readNotes } from "../src/idb-fs.js";
import { type VaultStore, closeVaultStore, initVault, isFencedOut, openVaultStore, persist, takeLeadership, loadVault } from "../src/store.js";
import { deviceLocal, freshIdb } from "./fixtures.js";
import { FS_CONFORMANCE_CASES } from "./support/fs-conformance.js";
import { utf8 } from "./support/bytes.js";

// The web note store (§20.1, §20.2): the FileSystem port over the vault's IndexedDB. It must pass the
// same conformance suite as memfs and the Obsidian adapter, fence every write like the leader's state
// writes, and never hold a note in plaintext.

async function setup() {
  const idb = freshIdb();
  const dlc = await deviceLocal();
  const open = () => openVaultStore({ installNs: "web:test", vaultId: "vault-1", ...idb });
  const store = await open();
  await initVault(store, { vaultId: "vault-1", replicaId: "replica-1", epochId: "e1" });
  const epoch = await takeLeadership(store);
  return { store, dlc, epoch, open, fs: indexedDbFileSystem(store, dlc, epoch) };
}

const snapshot = async (store: VaultStore) => JSON.stringify(await store.db.table("files").toArray(), (_, v) => (v instanceof Uint8Array ? [...v] : v));

describe("FileSystem port conformance: web IndexedDB note store", () => {
  it.each(FS_CONFORMANCE_CASES.map((c) => [c.name, c] as const))("%s", async (_, c) => {
    const t = await setup();
    await c.run(t.fs);
    closeVaultStore(t.store);
  });
});

describe("web note store: the change marker (NOTES question 146)", () => {
  it("is a counter kept in the database: a new instance (a reload, a new leader) never gives an old value back", async () => {
    const t = await setup();
    await t.fs.write("a.md", utf8("one"));
    const first = (await t.fs.stat("a.md"))?.mtime;
    await t.fs.remove("a.md");
    closeVaultStore(t.store);
    const store = await t.open();
    const epoch = await takeLeadership(store);
    const fs = indexedDbFileSystem(store, t.dlc, epoch);
    await fs.write("a.md", utf8("two"));
    const second = (await fs.stat("a.md"))?.mtime;
    expect(typeof first).toBe("number");
    expect(second).toBeGreaterThan(first!);
    expect(fs.changeMarker).toEqual({ kind: "counter" });
    closeVaultStore(store);
  });
});

describe("web note store: identities after a reload (§12.2 rule 10)", () => {
  // Bug found in slice 20: a web tab reopened on the same IndexedDB (a page reload, a re-enrollment)
  // knew no identity for the files already there, so after the startup scan every note was untracked
  // again and imported as a new object on every tick, forever. Obsidian gives every file a TFile at
  // load; the note store's equivalent is the listing.
  it("a new instance gives every file it lists an identity, kept until the file moves or goes", async () => {
    const t = await setup();
    await t.fs.mkdir("d");
    await t.fs.write("d/a.md", utf8("one"));
    closeVaultStore(t.store);
    const store = await t.open();
    const fs = indexedDbFileSystem(store, t.dlc, await takeLeadership(store));
    expect(fs.identityOf("nope.md")).toBeNull();
    expect((await fs.list("d")).files).toEqual(["d/a.md"]);
    const id = fs.identityOf("d/a.md");
    expect(id).not.toBeNull();
    await fs.list("d");
    expect(fs.identityOf("d/a.md")).toBe(id); // listing again never renames the identity
    await fs.rename("d/a.md", "b.md");
    expect(fs.identityOf("b.md")).toBe(id);
    closeVaultStore(store);
  });
});

describe("web note store: fencing (§20.2) and sealing (§20.1)", () => {
  it("after another leader increments leader_epoch, every write of the old one is fenced out and changes nothing", async () => {
    const t = await setup();
    await t.fs.mkdir("d");
    await t.fs.write("d/a.md", utf8("one"));
    const other = await t.open();
    await takeLeadership(other); // the new leader's first transaction (a forced takeover in web)
    const before = await snapshot(t.store);
    const writes: Array<() => Promise<unknown>> = [
      () => t.fs.write("d/a.md", utf8("two")),
      () => t.fs.write("b.md", utf8("new")),
      () => t.fs.rename("d/a.md", "c.md"),
      () => t.fs.replace("d/a.md", "c.md"),
      () => t.fs.remove("d/a.md"),
      () => t.fs.mkdir("e"),
      () => t.fs.rmdir("d"),
    ];
    for (const w of writes) {
      const error = await w().then(() => null, (e: unknown) => e);
      expect(isFencedOut(error)).toBe(true);
    }
    expect(await snapshot(t.store)).toBe(before);
    expect(await t.fs.read("d/a.md")).toEqual(utf8("one")); // reads are not fenced
    closeVaultStore(other);
    closeVaultStore(t.store);
  });

  it("a read-only store (a follower's) cannot write at all", async () => {
    const t = await setup();
    const ro = indexedDbFileSystem(t.store, t.dlc, null);
    expect(isFencedOut(await ro.write("a.md", utf8("x")).then(() => null, (e: unknown) => e))).toBe(true);
    expect(await ro.stat("a.md")).toBeNull();
    closeVaultStore(t.store);
  });

  it("the note store only holds ciphertext; readNotes returns the observed notes with their content and local_version", async () => {
    const t = await setup();
    await t.fs.write("a.md", utf8("a very secret note"));
    expect(await snapshot(t.store)).not.toContain("secret");
    const raw = new TextDecoder().decode(((await t.store.db.table("files").get("a.md")) as { sealed: Uint8Array }).sealed);
    expect(raw).not.toContain("secret");
    const s = await loadVault(t.store, t.dlc);
    await persist(t.store, t.dlc, s, {
      ...s,
      leaderEpoch: t.epoch,
      observations: new Map([["o1", { kind: "PRESENT", logicalPath: "A.md", physicalPath: "a.md", hash: "h" }]]),
      intentState: { ...s.intentState, localVersion: new Map([["o1", 3]]) },
    });
    expect(await readNotes(t.store, t.dlc)).toEqual([
      { objectId: "o1", path: "A.md", content: utf8("a very secret note"), version: 3, observation: { kind: "PRESENT", logicalPath: "A.md", physicalPath: "a.md", hash: "h" } },
    ]);
    closeVaultStore(t.store);
  });
});
