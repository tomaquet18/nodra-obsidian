import { describe, expect, it } from "vitest";
import { remoteCommit } from "@nodra/sync-core/test-support/server";
import { type LeaderMessage, newFollower, refreshView, submitIntent } from "../src/intents.js";
import { type Leadership, lead, leaderLockName } from "../src/leadership.js";
import type { FileSystem } from "../src/ports.js";
import { QueueClosed, diskQueue } from "../src/queue.js";
import { closeVaultStore, loadVault } from "../src/store.js";
import { channelHub, fakeLocks, tabsRig } from "./support/tabs.js";
import { utf8 } from "./support/bytes.js";

// §20.2 leadership with fakes of Web Locks and BroadcastChannel: the lock decides who leads, the first
// transaction increments leader_epoch, the disk queue closes before the lock is released, and fencing
// stops a deposed leader (web only: the plugin never steals).

const until = async (cond: () => boolean | Promise<boolean>, what: string, max = 2000) => {
  for (let i = 0; i < max; i++) {
    if (await cond()) return;
    await new Promise((r) => setTimeout(r, 0));
  }
  throw new Error(`timed out waiting for ${what}`);
};

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
}

describe("the leader's disk queue (§20.2 plugin)", () => {
  it("close waits for the write in progress; later and queued writes never start; reads still work", async () => {
    const gate = deferred();
    const started: string[] = [];
    const inner = {
      stat: async () => null,
      read: async () => utf8("r"),
      list: async () => ({ files: [], folders: [] }),
      identityOf: () => null,
      write: async (p: string) => {
        started.push(p);
        if (p === "slow.md") await gate.promise;
      },
      rename: async () => undefined,
      replace: async () => undefined,
      remove: async () => undefined,
      mkdir: async () => undefined,
      rmdir: async () => undefined,
    } satisfies FileSystem;
    const q = diskQueue(inner);
    const slow = q.fs.write("slow.md", utf8("x"));
    const queuedWrite = q.fs.write("queued.md", utf8("x")); // waits behind slow.md: one queue
    await until(() => started.length === 1, "the first write");
    let closed = false;
    const closing = q.close().then(() => (closed = true));
    await new Promise((r) => setTimeout(r, 5));
    expect(closed).toBe(false); // the write in progress is awaited
    gate.resolve();
    await slow;
    await closing;
    await expect(queuedWrite).rejects.toBeInstanceOf(QueueClosed);
    await expect(q.fs.remove("x.md")).rejects.toBeInstanceOf(QueueClosed);
    expect(await q.fs.read("x.md")).toEqual(utf8("r"));
    expect(started).toEqual(["slow.md"]);
  });
});

describe("§20.2 election and relay through the lock", () => {
  async function setup() {
    const rig = await tabsRig();
    const locks = fakeLocks();
    const hub = channelHub();
    const stores: Array<Awaited<ReturnType<typeof rig.open>>> = [];
    const readEpochs: number[] = [];
    const start = (name: string, opts: { steal?: boolean; fs?: FileSystem; idle?: (wake: Promise<void>) => Promise<void> } = {}): Promise<Leadership> =>
      rig.open().then((store) => {
        stores.push(store);
        return lead({
          locks,
          channel: hub.open(name),
          store,
          installNs: "plugin:tabs",
          vaultId: "vault-1",
          fs: opts.fs ?? rig.disk.fs,
          ...(opts.steal ? { steal: true } : {}),
          idle: opts.idle ?? ((wake) => wake),
          client: async (epoch, fs, notify) => {
            readEpochs.push((await loadVault(store, rig.dlc)).leaderEpoch); // nothing read before the increment
            return rig.client(store, epoch, fs, notify);
          },
        });
      });
    const epoch = async () => (await loadVault(stores[0]!, rig.dlc)).leaderEpoch;
    return { rig, locks, hub, start, epoch, readEpochs, close: () => stores.forEach(closeVaultStore) };
  }

  it("one leader at a time: the second context waits; on stop the lock passes and leader_epoch is incremented first", async () => {
    const t = await setup();
    const a = await t.start("a");
    await until(() => a.leading(), "a to lead");
    const b = await t.start("b");
    await new Promise((r) => setTimeout(r, 5));
    expect(b.leading()).toBe(false);
    expect(await t.epoch()).toBe(1);
    expect(await a.stop()).toEqual({ kind: "STOPPED" });
    await until(() => b.leading(), "b to lead");
    expect(await t.epoch()).toBe(2);
    expect(t.readEpochs).toEqual([1, 2]);
    expect(await b.stop()).toEqual({ kind: "STOPPED" });
    t.close();
  });

  it("a stop while still queued withdraws the request: that context never leads nor touches leader_epoch", async () => {
    const t = await setup();
    const a = await t.start("a");
    await until(() => a.leading(), "a to lead");
    const b = await t.start("b");
    expect(await b.stop()).toEqual({ kind: "STOPPED" });
    await a.stop();
    await new Promise((r) => setTimeout(r, 5));
    expect(await t.epoch()).toBe(1);
    expect(t.locks.holderOf(leaderLockName("plugin:tabs", "vault-1"))).toBeNull();
    t.close();
  });

  it("plugin handover: the lock is released only after the write in progress finished, and no other write starts", async () => {
    const t = await setup();
    remoteCommit(t.rig.server, "o1", { path: "r.md", content: "remote", deleted: false });
    const gate = deferred();
    let writes = 0;
    let blocked = false;
    const fs: FileSystem = {
      ...t.rig.disk.fs,
      stat: (p) => t.rig.disk.fs.stat(p),
      read: (p) => t.rig.disk.fs.read(p),
      list: (p) => t.rig.disk.fs.list(p),
      identityOf: (p) => t.rig.disk.fs.identityOf(p),
      write: async (p, d) => {
        writes++;
        blocked = true;
        await gate.promise; // the materialization's temporary is being written
        await t.rig.disk.fs.write(p, d);
      },
    };
    const a = await t.start("a", { fs, idle: async () => new Promise((r) => setTimeout(r, 1)) });
    await until(() => blocked, "a's first disk write");
    const stopping = a.stop();
    const b = await t.start("b");
    await new Promise((r) => setTimeout(r, 5));
    expect(b.leading()).toBe(false); // a still holds the lock: its write is in progress
    gate.resolve();
    expect(await stopping).toEqual({ kind: "STOPPED" });
    await until(() => b.leading(), "b to lead");
    expect(writes).toBe(1);
    // b finishes the materialization a left open in the journal.
    await until(() => t.rig.disk.files.get("r.md")?.content === "remote", "r.md materialized by b");
    await b.stop();
    t.close();
  });

  it("web: a forced takeover deposes the old leader: its next write is fenced, it ends FENCED and wrote nothing after the increment", async () => {
    const t = await setup();
    const a = await t.start("a");
    await until(() => a.leading(), "a to lead");
    const b = await t.start("b", { steal: true });
    await until(() => b.leading(), "b to lead");
    expect(await t.epoch()).toBe(2);
    await until(() => !a.leading(), "a to see its request rejected"); // it starts no new tick
    // The frozen a wakes up with work to do (a user file on disk): its first transaction aborts.
    t.rig.disk.userWrite("user.md", "typed while a was frozen");
    const snapshot = async () => JSON.stringify(await t.rig.open().then(async (s) => {
      const rows = await Promise.all(["meta", "observations"].map((n) => s.db.table(n).toArray()));
      closeVaultStore(s);
      return rows;
    }));
    // Stop b first so only a acts; b's own writes are legitimate and would muddy the snapshot.
    await b.stop();
    const before = await snapshot();
    t.hub.open("waker").postMessage({ kind: "intent", contextId: "x" } satisfies LeaderMessage);
    t.hub.flush();
    expect(await a.ended).toEqual({ kind: "FENCED" });
    expect(await snapshot()).toBe(before);
    t.close();
  });

  it("the channel is subscribed before the first sweep: a follower's hint wakes the idle leader, which acks", async () => {
    const t = await setup();
    t.rig.disk.userWrite("a.md", "one");
    const a = await t.start("a");
    await until(() => a.leading(), "a to lead");
    await until(async () => [...t.rig.server.heads.values()].length === 1, "a.md uploaded");
    const fstore = await t.rig.open();
    const f = newFollower("ctx-f");
    await refreshView(fstore, f);
    const port = t.hub.open("f");
    const acks: unknown[] = [];
    port.addEventListener("message", (e) => acks.push(e.data));
    const [id] = [...f.view.keys()];
    await submitIntent(fstore, t.rig.dlc, port, f, { intentId: "i1", objectId: id!, change: { kind: "CONTENT", path: "a.md", content: utf8("from f") } });
    for (let i = 0; i < 50 && !acks.some((m) => (m as LeaderMessage).kind === "ack"); i++) {
      t.hub.flush();
      await new Promise((r) => setTimeout(r, 1));
    }
    expect(acks).toContainEqual({ kind: "ack", contextId: "ctx-f", intentSeq: 1, intentId: "i1", outcome: "APPLY" });
    expect(t.rig.disk.files.get("a.md")?.content).toBe("from f");
    await a.stop();
    closeVaultStore(fstore);
    t.close();
  });
});
