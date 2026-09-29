import type { LockManagerPort } from "@nodra/sync-client";
import { pluginInstallNs } from "./controller.js";

// §20.2 "Copias, sincronización y movimientos del vault (plugin)": each plugin instance holds the
// exclusive lock `nodra:<install_ns>:owner` while it is loaded, so two instances can never write the
// same vault folder (the leader's fencing covers IndexedDB, not the disk). Free of the `obsidian`
// runtime so it runs in tests; main.ts wires it to `navigator.locks` and Obsidian's local storage.

/** §20.2 `OWNER_WAIT`, initial value. */
export const OWNER_WAIT_MS = 10_000;

export const ownerLockName = (installationId: string): string => `nodra:${pluginInstallNs(installationId)}:owner`;

export interface OwnerDeps {
  readonly locks: LockManagerPort;
  /**
   * The `installation_id` in Obsidian's per-vault, per-device local storage, read afresh on every call.
   * A busy lock NEVER makes a new one: that would be a forced takeover of the folder (§20.2).
   */
  readonly installationId: () => string;
  readonly ownerWaitMs?: number;
  /** OWNER_WAIT passed and the lock is still held: "otra instancia de Nodra controla este vault". */
  readonly onWaiting?: () => void;
  /** Aborts a request still queued (the plugin unloads while it waits). */
  readonly signal?: AbortSignal;
}

export interface Ownership {
  readonly installationId: string;
  /** Releases the lock; onunload calls it FIRST, before the disk queue is drained (§20.2). */
  release(): void;
}

/** Holds `name` until `release()`; resolves once it is granted. The request stays queued past OWNER_WAIT. */
function hold(d: OwnerDeps, name: string): Promise<() => void> {
  return new Promise((resolve, reject) => {
    let release!: () => void;
    const released = new Promise<void>((r) => (release = r));
    const waiting = setTimeout(() => d.onWaiting?.(), d.ownerWaitMs ?? OWNER_WAIT_MS);
    d.locks
      .request(name, { mode: "exclusive", ...(d.signal === undefined ? {} : { signal: d.signal }) }, async () => {
        clearTimeout(waiting);
        resolve(release);
        await released;
      })
      .catch((e: unknown) => {
        clearTimeout(waiting);
        reject(e);
      });
  });
}

/**
 * §20.2: take the `owner` lock of this vault's installation, then — before syncing — re-read the
 * `installation_id`. If it changed while this instance waited ("tratar como instalación nueva" in the
 * instance that owned it), the lock taken is released and the current id's lock is requested instead.
 */
export async function takeOwnership(d: OwnerDeps): Promise<Ownership> {
  for (;;) {
    const installationId = d.installationId();
    const release = await hold(d, ownerLockName(installationId));
    if (d.installationId() === installationId) return { installationId, release };
    release();
  }
}
