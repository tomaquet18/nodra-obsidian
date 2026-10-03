import type { RevisionEntry } from "@nodra/sync-core";
import type { Shell } from "../../src/executor.js";
import type { LocalCompareHasher } from "../../src/ports.js";
import type { VaultState } from "../../src/state.js";
import { closeVaultStore, initVault, loadVault, openVaultStore, persist, takeLeadership } from "../../src/store.js";
import { deviceLocal, freshIdb } from "../fixtures.js";
import { type MemFs, type MemMtime, memFs } from "./memfs.js";
import { toModel } from "./bytes.js";

/** Readable test hash: the real one is HMAC (crypto.ts), tested separately. */
export const testHasher: LocalCompareHasher = { hash: async (plaintext) => `h:${toModel(plaintext)}` };

export const rev = (revisionId: string, path: string, content: string, sequence = 1): RevisionEntry => ({
  revisionId,
  sequence,
  path,
  localCompareHash: `h:${content}`,
  deleted: false,
  createdSequence: 1,
});

export interface Rig {
  shell: Shell;
  disk: MemFs;
  /** Crash: drop every in-memory thing, close the database, reopen it and load the persisted facts. */
  restart(): Promise<void>;
  /** The persisted state as a fresh instance would load it. */
  persisted(): Promise<VaultState>;
}

export async function rig(setup?: (s: VaultState) => VaultState, mtime?: MemMtime): Promise<Rig> {
  const idb = freshIdb();
  const dlc = await deviceLocal();
  const disk = memFs(mtime);
  let hexes = 0;
  const open = () => openVaultStore({ installNs: "plugin:test", vaultId: "vault-1", ...idb });
  let store = await open();
  await initVault(store, { vaultId: "vault-1", replicaId: "replica-1", epochId: "e1" });
  await takeLeadership(store);
  let state = await loadVault(store, dlc);
  if (setup) {
    const next = setup(state);
    await persist(store, dlc, state, next);
    state = next;
  }
  let ids = 0;
  const make = (st: VaultState): Shell => ({
    fs: disk.fs,
    hasher: testHasher,
    dlc,
    store,
    state: st,
    identities: new Map(),
    createdFolders: new Set(),
    hex8: () => (++hexes).toString(16).padStart(8, "0"),
    newId: (prefix) => `${prefix}${++ids}`,
  });
  disk.onCrash = () => closeVaultStore(store);
  const r: Rig = {
    shell: make(state),
    disk,
    async restart() {
      closeVaultStore(store);
      disk.revive();
      store = await open();
      const epoch = await takeLeadership(store);
      r.shell = make({ ...(await loadVault(store, dlc)), leaderEpoch: epoch });
    },
    async persisted() {
      const other = await open();
      const s = await loadVault(other, dlc);
      closeVaultStore(other);
      return s;
    },
  };
  return r;
}
