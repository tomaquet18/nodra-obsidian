import type { FileSystem } from "./ports.js";

// The leader's single disk write queue (§20.2 "Escrituras fuera de IndexedDB (plugin)"). Fencing only
// protects IndexedDB, so every write to the vault goes through one queue of the leader instance. When
// the instance loses leadership or unloads, it closes the queue, waits for the write in progress, never
// starts another, and only then releases the lock.

export class QueueClosed extends Error {
  override readonly name = "QueueClosed";
}

export interface DiskQueue {
  /** The vault file system as the leader must use it: reads pass through, writes go through the queue. */
  readonly fs: FileSystem;
  readonly closed: () => boolean;
  /** Closes the queue and resolves once the write in progress (if any) has finished. */
  close(): Promise<void>;
}

export function diskQueue(inner: FileSystem): DiskQueue {
  let closed = false;
  let tail: Promise<unknown> = Promise.resolve();
  const queued = <T>(op: () => Promise<T>): Promise<T> => {
    const run = tail.then(() => {
      if (closed) throw new QueueClosed("the disk queue is closed: this instance is no longer the leader");
      return op();
    });
    tail = run.catch(() => undefined);
    return run;
  };
  // Property lookups happen at call time, so a wrapped adapter (tests) keeps working.
  const fs: FileSystem = {
    stat: (p) => inner.stat(p),
    read: (p) => inner.read(p),
    list: (f) => inner.list(f),
    identityOf: (p) => inner.identityOf(p),
    get changeMarker() {
      return inner.changeMarker;
    },
    write: (p, data) => queued(() => inner.write(p, data)),
    rename: (from, to) => queued(() => inner.rename(from, to)),
    replace: (tmp, dest) => queued(() => inner.replace(tmp, dest)),
    remove: (p) => queued(() => inner.remove(p)),
    mkdir: (p) => queued(() => inner.mkdir(p)),
    rmdir: (p) => queued(() => inner.rmdir(p)),
  };
  return {
    fs,
    closed: () => closed,
    async close() {
      closed = true;
      await tail;
    },
  };
}

export const isQueueClosed = (e: unknown): boolean => e instanceof QueueClosed;
