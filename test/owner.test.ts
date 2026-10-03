import { fakeLocks } from "@nodra/sync-client/test-support/tabs";
import { describe, expect, it } from "vitest";
import { ownerLockName, takeOwnership } from "../src/owner.js";

// §20.2: the plugin's `owner` lock. One instance per installation writes the vault folder; a busy
// lock is waited for (never answered with a new installation_id); the id is re-read once the lock
// is held.

const ID = "0190a000-0000-7000-8000-000000000001";
const OTHER = "0190a000-0000-7000-8000-000000000002";
const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

describe("§20.2 owner lock (plugin)", () => {
  it("a free lock is taken at once, for the installation_id in local storage", async () => {
    const locks = fakeLocks();
    const owned = await takeOwnership({ locks, installationId: () => ID });
    expect(owned.installationId).toBe(ID);
    expect(locks.holderOf(ownerLockName(ID))).not.toBeNull();
    owned.release();
    await tick();
    expect(locks.holderOf(ownerLockName(ID))).toBeNull();
  });

  it("held by another instance: after OWNER_WAIT it says so, keeps waiting with the SAME id, and takes the lock when released", async () => {
    const locks = fakeLocks();
    const first = await takeOwnership({ locks, installationId: () => ID });
    let waiting = 0;
    const asked: string[] = [];
    const second = takeOwnership({
      locks,
      ownerWaitMs: 10,
      installationId: () => {
        asked.push(ID);
        return ID;
      },
      onWaiting: () => waiting++,
    });
    let owned = false;
    void second.then(() => (owned = true));
    await tick(40);
    expect(waiting).toBe(1);
    expect(owned).toBe(false);
    expect(new Set(asked)).toEqual(new Set([ID])); // never another id because the lock is busy
    first.release();
    const got = await second;
    expect(got.installationId).toBe(ID);
    got.release();
  });

  it("the id is re-read after the lock is taken: changed meanwhile, the stale lock is released and the current id's is taken", async () => {
    const locks = fakeLocks();
    const first = await takeOwnership({ locks, installationId: () => ID });
    let current = ID;
    const second = takeOwnership({ locks, ownerWaitMs: 1_000, installationId: () => current });
    await tick();
    // The owning instance ran "treat as a new installation": new id written, THEN its old lock released.
    current = OTHER;
    first.release();
    const got = await second;
    expect(got.installationId).toBe(OTHER);
    expect(locks.holderOf(ownerLockName(ID))).toBeNull();
    expect(locks.holderOf(ownerLockName(OTHER))).not.toBeNull();
    got.release();
  });

  it("an unload while waiting withdraws the queued request", async () => {
    const locks = fakeLocks();
    const first = await takeOwnership({ locks, installationId: () => ID });
    const abort = new AbortController();
    const second = takeOwnership({ locks, ownerWaitMs: 1_000, installationId: () => ID, signal: abort.signal });
    abort.abort();
    await expect(second).rejects.toBeDefined();
    first.release();
  });
});
