import { newServer } from "@nodra/sync-core/test-support/server";
import type { Shell } from "../../src/executor.js";
import type { LeaderMessage } from "../../src/intents.js";
import type { ChannelPort, FileSystem, LockManagerPort } from "../../src/ports.js";
import { type Client, newMemory } from "../../src/runner.js";
import { type VaultStore, closeVaultStore, initVault, loadVault, openVaultStore } from "../../src/store.js";
import { deviceLocal, freshIdb } from "../fixtures.js";
import { NO_NET_FAULTS, devBlobCrypto, memBackend } from "./backend.js";
import { type MemFs, memFs } from "./memfs.js";
import { testHasher } from "./shell.js";

// Fakes of the browser pieces of §20.2 (Web Locks, BroadcastChannel) and a rig with several contexts
// of one installation sharing one IndexedDB, one disk and one server.

const abortError = () => Object.assign(new Error("The request was aborted"), { name: "AbortError" });

interface Holder {
  readonly reject: (e: unknown) => void;
  stolen: boolean;
}

/**
 * `navigator.locks` for exclusive locks: FIFO queue per name, `signal` withdraws a queued request, and
 * `steal` rejects the holder's request (AbortError) and grants at once while the old callback keeps running.
 */
export function fakeLocks(): LockManagerPort & { holderOf(name: string): string | null; readonly grants: string[] } {
  const holders = new Map<string, Holder>();
  const queues = new Map<string, Array<() => void>>();
  const grants: string[] = [];
  let n = 0;
  const next = (name: string) => {
    holders.delete(name);
    queues.get(name)?.shift()?.();
  };
  return {
    grants,
    holderOf: (name) => (holders.has(name) ? name : null),
    request<T>(name: string, options: { readonly steal?: boolean; readonly signal?: AbortSignal }, callback: (lock: unknown) => Promise<T>): Promise<T> {
      return new Promise<T>((resolve, reject) => {
        const id = `req-${++n}`;
        // The Web Locks API refuses this combination (a stolen lock is granted at once, so there is no
        // queued request for the signal to withdraw): browsers reject with NotSupportedError.
        if (options.steal && options.signal !== undefined) {
          return reject(new DOMException("`steal` and `signal` cannot be used together", "NotSupportedError"));
        }
        if (options.signal?.aborted) return reject(abortError());
        const grant = () => {
          const h: Holder = { reject, stolen: false };
          holders.set(name, h);
          grants.push(id);
          callback({ name }).then(
            (v) => {
              if (holders.get(name) === h) next(name);
              if (!h.stolen) resolve(v);
            },
            (e) => {
              if (holders.get(name) === h) next(name);
              if (!h.stolen) reject(e);
            },
          );
        };
        const current = holders.get(name);
        if (options.steal && current) {
          current.stolen = true;
          current.reject(abortError());
          holders.delete(name);
          grant();
        } else if (!current) grant();
        else {
          const q = queues.get(name) ?? [];
          queues.set(name, q);
          q.push(grant);
          options.signal?.addEventListener("abort", () => {
            const i = q.indexOf(grant);
            if (i >= 0) {
              q.splice(i, 1);
              reject(abortError());
            }
          });
        }
      });
    },
  };
}

/**
 * BroadcastChannel: a message goes to every OTHER port of the same name. Delivery is explicit
 * (`flush`), so tests choose when, and can lose, duplicate or reorder messages.
 */
export function channelHub() {
  type Listener = (event: { readonly data: unknown }) => void;
  const ports = new Map<string, Set<Listener>>();
  const queue: Array<{ from: string; data: unknown }> = [];
  const sent: unknown[] = [];
  const hub = {
    sent,
    open(id: string): ChannelPort {
      const listeners = new Set<Listener>();
      ports.set(id, listeners);
      return {
        postMessage: (data) => {
          sent.push(data);
          queue.push({ from: id, data: JSON.parse(JSON.stringify(data)) });
        },
        addEventListener: (_t, l) => listeners.add(l),
        removeEventListener: (_t, l) => listeners.delete(l),
      };
    },
    /** Delivers what is queued; `lose` drops, `duplicate` delivers twice, `reverse` delivers in reverse order. */
    flush(opts: { lose?: (data: unknown) => boolean; duplicate?: boolean; reverse?: boolean } = {}) {
      const batch = queue.splice(0, queue.length);
      if (opts.reverse) batch.reverse();
      for (const m of batch) {
        if (opts.lose?.(m.data)) continue;
        for (let k = 0; k < (opts.duplicate ? 2 : 1); k++) {
          for (const [id, ls] of ports) if (id !== m.from) for (const l of ls) l({ data: m.data });
        }
      }
      return batch.length;
    },
  };
  return hub;
}

/** Several contexts of one installation on one vault: one IndexedDB, one disk, one server. */
export async function tabsRig() {
  const idb = freshIdb();
  const dlc = await deviceLocal();
  const disk: MemFs = memFs();
  const server = newServer({ pendingBudgetBytes: 20000, maxBlobBytes: 5000, uploadWindow: 40 });
  const crypto = devBlobCrypto();
  const net = memBackend(server, "replica-1", crypto, () => 0.99, async () => new Set(), (where) => disk.crash(where));
  net.faults = NO_NET_FAULTS;
  const open = () => openVaultStore({ installNs: "plugin:tabs", vaultId: "vault-1", ...idb });
  const first = await open();
  await initVault(first, { vaultId: "vault-1", replicaId: "replica-1", epochId: "e1" });
  closeVaultStore(first);
  let hexes = 0;
  let ids = 0;
  const events: Array<{ kind: string; objectId?: string; detail?: string }> = [];
  /** A client for a leader that holds `epoch`, writing through `fs`. */
  const client = async (store: VaultStore, epoch: number, fs: FileSystem = disk.fs, notify?: (m: LeaderMessage) => void): Promise<Client> => {
    const log = (e: { kind: string; objectId?: string; detail?: string }) => events.push(e);
    const shell: Shell = {
      fs,
      hasher: testHasher,
      dlc,
      store,
      state: { ...(await loadVault(store, dlc)), leaderEpoch: epoch },
      identities: new Map(),
      createdFolders: new Set(),
      hex8: () => (++hexes).toString(16).padStart(8, "0"),
      newId: (prefix) => `${prefix}${++ids}`,
      log,
    };
    return { shell, backend: net.backend, blobs: crypto, now: () => server.now, pendingBudgetBytes: 20000, memory: newMemory(), log, ...(notify ? { notify } : {}) };
  };
  return { idb, dlc, disk, server, net, open, client, events };
}
