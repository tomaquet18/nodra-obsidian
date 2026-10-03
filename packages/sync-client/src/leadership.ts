import type { FileSystem, ChannelPort, LockManagerPort } from "./ports.js";
import { type LeaderMessage, parseMessage } from "./intents.js";
import { isQueueClosed, diskQueue } from "./queue.js";
import { type Client, tick } from "./runner.js";
import { type VaultStore, isFencedOut, takeLeadership } from "./store.js";

// Leadership of one vault among the contexts of one installation (§20.2 "Elección", "Fencing",
// "Escrituras fuera de IndexedDB (plugin)", "Relevo"). The lock is Web Locks (`navigator.locks`), the
// channel BroadcastChannel, both behind ports. Nothing here is persisted but leader_epoch.

export const leaderLockName = (installNs: string, vaultId: string): string => `nodra:${installNs}:${vaultId}:leader`;
export const channelName = (installNs: string, vaultId: string): string => `nodra:${installNs}:${vaultId}`;

export type LeadershipEnd =
  /** Released on request (onunload, or never granted before the stop). */
  | { readonly kind: "STOPPED" }
  /** A write aborted by fencing: another context took over; this one is a follower again. */
  | { readonly kind: "FENCED" }
  /** The instance failed (e.g. a persistent disk error, Q55); the lock is released after the queue closed. */
  | { readonly kind: "FAILED"; readonly error: unknown };

export interface Leadership {
  /** True between the leader_epoch increment and the end. */
  readonly leading: () => boolean;
  /** Settles when this context has stopped leading (the disk queue is closed by then). */
  readonly ended: Promise<LeadershipEnd>;
  /** Stops leading: closes the disk queue, waits for the write in progress, then the lock is released. */
  stop(): Promise<LeadershipEnd>;
}

export interface LeadOptions {
  readonly locks: LockManagerPort;
  readonly channel: ChannelPort;
  readonly store: VaultStore;
  readonly installNs: string;
  readonly vaultId: string;
  /**
   * The vault's file system; the leader only writes it through its own disk queue. A function is called
   * with this leader's epoch once it holds it (web: the note store fences its writes with it, idb-fs.ts).
   */
  readonly fs: FileSystem | ((epoch: number) => FileSystem);
  /**
   * Builds the leader's client AFTER the leader_epoch increment (§20.2 "Relevo": nothing is read before
   * it): the state loaded from IndexedDB with `leaderEpoch: epoch`, the queued `fs`, and `notify` wired
   * to the channel.
   */
  readonly client: (epoch: number, fs: FileSystem, notify: (m: LeaderMessage) => void) => Promise<Client>;
  /** Waits after an idle tick; `wake` resolves on a channel message or a stop. */
  readonly idle: (wake: Promise<void>) => Promise<void>;
  /**
   * `{ steal: true }` (web only: a visible follower after LEADER_TIMEOUT, or an unlock in a follower).
   * NEVER in the plugin: disk writes cannot be fenced, so leadership only changes on release.
   */
  readonly steal?: boolean;
}

/**
 * Requests the vault's leader lock and, once granted, leads: the FIRST transaction increments
 * leader_epoch, the channel is subscribed before the first sweep of pending_intents, then the runner
 * ticks until stopped or fenced out. The disk queue is closed (and its write in progress awaited)
 * before the lock callback returns, so the lock is never released with a disk write in flight.
 */
export function lead(o: LeadOptions): Leadership {
  let stopping = false;
  /** The lock was stolen (web): the browser rejected this request while `run` goes on. */
  let deposed = false;
  let leading = false;
  let close: (() => Promise<void>) | null = null;
  let wake = () => {};
  const abort = new AbortController();
  let result: Promise<LeadershipEnd> | null = null;

  const run = async (): Promise<LeadershipEnd> => {
    if (stopping) return { kind: "STOPPED" };
    let epoch: number;
    try {
      epoch = await takeLeadership(o.store);
    } catch (error) {
      return { kind: "FAILED", error };
    }
    const queue = diskQueue(typeof o.fs === "function" ? o.fs(epoch) : o.fs);
    close = queue.close;
    leading = true;
    let client: Client | null = null;
    const listener = (event: { readonly data: unknown }) => {
      if (parseMessage(event.data)?.kind !== "intent") return;
      if (client) client.memory.intentHint = true;
      wake();
    };
    o.channel.addEventListener("message", listener); // before the first sweep
    try {
      client = await o.client(epoch, queue.fs, (m) => o.channel.postMessage(m));
      client.memory.intentHint = true; // a new leader sweeps pending_intents at once
      while (!stopping && !deposed) {
        const busy = await tick(client);
        if (busy) o.channel.postMessage({ kind: "state" } satisfies LeaderMessage);
        else if (!stopping && !deposed) await o.idle(new Promise<void>((r) => (wake = r)));
      }
      return deposed && !stopping ? { kind: "FENCED" } : { kind: "STOPPED" };
    } catch (error) {
      if (isFencedOut(error)) return { kind: "FENCED" };
      if (isQueueClosed(error) && stopping) return { kind: "STOPPED" };
      return { kind: "FAILED", error };
    } finally {
      leading = false;
      o.channel.removeEventListener("message", listener);
      await queue.close();
    }
  };

  // The Web Locks API refuses `steal` with `signal` (NotSupportedError). A stolen lock is granted at once,
  // so it is never queued and there is nothing for the signal to withdraw.
  const request = o.locks.request(leaderLockName(o.installNs, o.vaultId), { mode: "exclusive", ...(o.steal ? { steal: true } : { signal: abort.signal }) }, () => {
    result = run();
    return result;
  });
  // A stolen lock rejects this request while `run` goes on: it starts no new tick, and fencing aborts
  // whatever write the tick in progress attempts (§20.2). The end is `run`'s.
  const ended: Promise<LeadershipEnd> = request.then(
    (end) => end,
    (error) => {
      if (result === null) return stopping ? { kind: "STOPPED" } : { kind: "FAILED", error };
      deposed = true;
      wake();
      return result;
    },
  );
  return {
    leading: () => leading && !deposed,
    ended,
    async stop() {
      stopping = true;
      if (result === null) abort.abort(); // still queued for the lock: withdraw the request
      wake();
      await close?.();
      return ended;
    },
  };
}
