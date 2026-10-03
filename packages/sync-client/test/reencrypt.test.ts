import { reencryptKey } from "@nodra/sync-core";
import { REENCRYPT_IN_FLIGHT as SERVER_IN_FLIGHT, gc, listToReencrypt, modelInvariants, newServer, pendingOf, preSwitchBlobs, prune, remoteCommit, rotateEpoch, switchToPrivate } from "@nodra/sync-core/test-support/server";
import type { Server } from "@nodra/sync-core/test-support/server";
import { describe, expect, it } from "vitest";
import type { Shell } from "../src/executor.js";
import type { SyncBackend } from "../src/ports.js";
import { REENCRYPT_IN_FLIGHT, type ReencryptPassResult, reencryptPass } from "../src/reencrypt.js";
import { type Client, newMemory, tick } from "../src/runner.js";
import { type VaultStore, closeVaultStore, initVault, loadVault, openVaultStore, takeLeadership } from "../src/store.js";
import { deviceLocal, freshIdb } from "./fixtures.js";
import { NO_NET_FAULTS, devBlobCrypto, memBackend } from "./support/backend.js";
import { memFs } from "./support/memfs.js";
import { testHasher } from "./support/shell.js";

// §35.13 the client's re-encryption of the history (§44.3 T14, T19, T20; the crash cases of T19 in
// "crash antes y después de cada subida y del commit"), over the server model with its own §35.13 calls.

const REPLICA = "replica-1";

type Op = keyof SyncBackend;
type Crash = { readonly op: Op; readonly at: number; readonly when: "before" | "after" };

/** One replica over the server model, with Dexie and a disk; `crash` kills it at one backend call. */
async function harness(o: { crash?: Crash | null; broken?: (b: SyncBackend) => SyncBackend } = {}) {
  const idb = freshIdb();
  const dlc = await deviceLocal();
  const disk = memFs();
  const server = newServer({ pendingBudgetBytes: 20000, maxBlobBytes: 5000, uploadWindow: 40 });
  const crypto = devBlobCrypto();
  const open = () => openVaultStore({ installNs: "plugin:reencrypt", vaultId: "vault-1", ...idb });
  let store: VaultStore = await open();
  await initVault(store, { vaultId: "vault-1", replicaId: REPLICA, epochId: "e1" });
  const persistedBlobIds = async () => {
    const rows = (await store.db.table("attempts").toArray()) as Array<{ blobs: Array<{ blobId: string }> }>;
    return new Set(rows.flatMap((a) => a.blobs.map((b) => b.blobId)));
  };
  const net = memBackend(server, REPLICA, crypto, () => 0.99, persistedBlobIds, (where) => disk.crash(where));
  net.faults = NO_NET_FAULTS;
  disk.onCrash = () => closeVaultStore(store);
  const calls = new Map<Op, number>();
  let crash = o.crash ?? null;
  /** The backend as the client sees it: counted, and killed at the planned call. */
  const backend = Object.fromEntries(
    (Object.keys(net.backend) as Op[]).map((op) => [
      op,
      async (...args: unknown[]) => {
        const n = (calls.get(op) ?? 0) + 1;
        calls.set(op, n);
        const planned = crash !== null && crash.op === op && crash.at === n ? crash : null;
        if (planned?.when === "before") {
          crash = null;
          disk.crash(`before ${op}`);
        }
        const out = await (net.backend[op] as (...a: unknown[]) => Promise<unknown>)(...args);
        if (planned?.when === "after") {
          crash = null;
          disk.crash(`after ${op}`);
        }
        return out;
      },
    ]),
  ) as unknown as SyncBackend;
  let ids = 0;
  const make = async (): Promise<Client> => {
    const leaderEpoch = await takeLeadership(store);
    const shell: Shell = {
      fs: disk.fs,
      hasher: testHasher,
      dlc,
      store,
      state: { ...(await loadVault(store, dlc)), leaderEpoch },
      identities: new Map(),
      createdFolders: new Set(),
      hex8: () => (++ids).toString(16).padStart(8, "0"),
      newId: (prefix) => `${prefix}${++ids}`,
    };
    return { shell, backend: o.broken ? o.broken(backend) : backend, blobs: crypto, now: () => server.now, pendingBudgetBytes: 20000, memory: newMemory() };
  };
  const h = {
    server,
    net,
    disk,
    calls,
    crashes: 0,
    client: await make(),
    async restart() {
      closeVaultStore(store);
      disk.revive();
      store = await open();
      h.client = await make();
      h.crashes++;
    },
    /** One pass; a crash restarts the instance (a fresh one loads what was persisted). */
    async pass(options?: Parameters<typeof reencryptPass>[1]): Promise<ReencryptPassResult | "CRASHED"> {
      const r = await reencryptPass(h.client, options).catch((e: unknown) => ({ listed: 0, swapped: 0, notPrivate: false, error: e }));
      if (disk.dead) {
        await h.restart();
        return "CRASHED";
      }
      return r;
    },
    async tick(): Promise<boolean> {
      let busy = true;
      try {
        busy = await tick(h.client);
      } catch (e) {
        if (!disk.dead) throw e;
        await h.restart();
      }
      server.now++;
      return busy;
    },
    /** Ticks until the replica is at rest: it has applied the events, the switch's EPOCH_ROTATED included. */
    async settle() {
      for (let i = 0; i < 100; i++) if (!(await h.tick())) return;
      throw new Error("no rest");
    },
    /** Passes and ticks until the server lists nothing and no attempt or cleanup record is left. */
    async untilDone(max = 60): Promise<number> {
      for (let i = 0; i < max; i++) {
        const r = await h.pass();
        for (let k = 0; k < 3; k++) await h.tick();
        const f = h.client.shell.state.facts;
        const left = f.attempts.filter((a) => a.reencrypt !== undefined).length + f.cleanup.length;
        if (r !== "CRASHED" && r.error === null && r.listed === 0 && left === 0) return i;
      }
      throw new Error("re-encryption never finished");
    },
  };
  return h;
}

type Harness = Awaited<ReturnType<typeof harness>>;

/**
 * A history in e1 (and e2): edits, a rename that keeps its content blob (two revisions share it), a
 * delete, identical content in two files, an empty file; then the switch (e3) and one write after it.
 */
function history(server: Server): void {
  const a1 = remoteCommit(server, "a", { path: "a.md", content: "alpha", deleted: false });
  remoteCommit(server, "a", { path: "a.md", content: "alpha 2", deleted: false });
  remoteCommit(server, "b", { path: "b.md", content: "same", deleted: false });
  remoteCommit(server, "b", { path: "moved/b.md", content: "same", deleted: false }); // rename: same blob
  remoteCommit(server, "c", { path: "c.md", content: "same", deleted: false }); // identical bytes, own blob
  rotateEpoch(server);
  remoteCommit(server, "d", { path: "d.md", content: "", deleted: false }); // empty file, e2
  remoteCommit(server, "e", { path: "e.md", content: "doomed", deleted: false });
  remoteCommit(server, "e", { path: "e.md", content: "", deleted: true });
  void a1;
  switchToPrivate(server);
  remoteCommit(server, "f", { path: "f.md", content: "after the switch", deleted: false });
}

/** Every revision as the server has it, blobs aside: what a re-encryption must leave exactly as it was (pruning aside). */
const revisions = (s: Server) =>
  [...s.revisions.values()]
    .map((r) => ({ revisionId: r.revisionId, objectId: r.objectId, sequence: r.sequence, path: r.path, content: r.content, deleted: r.deleted }))
    .sort((a, b) => a.sequence - b.sequence);

/** What a finished re-encryption leaves: nothing listed, no pre-switch blob once collected, nothing lost. */
function finished(h: Harness, before: ReturnType<typeof revisions>): void {
  const ledger = new Map<string, string>();
  expect(modelInvariants(h.server, ledger)).toEqual([]);
  expect(listToReencrypt(h.server, null, 100)).toEqual({ kind: "PAGE", revisions: [], next: null });
  expect(revisions(h.server)).toEqual(before);
  // Nothing of ours left PENDING (every refused or abandoned attempt was released), write-ahead held.
  expect(pendingOf(h.server, REPLICA)).toEqual([]);
  expect(h.net.writeAheadViolations).toEqual([]);
  // §35.13 "Fin": once the GC has run, no blob of a pre-switch epoch is stored.
  h.server.now += 200_000;
  gc(h.server);
  expect(preSwitchBlobs(h.server)).toEqual([]);
  expect(modelInvariants(h.server, ledger)).toEqual([]);
}

describe("§35.13 the client re-encrypts the history", () => {
  it("every revision of a pre-switch epoch ends in the write epoch, with its path and plaintext; the list is the progress", async () => {
    const h = await harness();
    history(h.server);
    const before = revisions(h.server);
    await h.settle(); // learns e3 from EPOCH_ROTATED, as the client that switched knows it
    const first = await h.pass();
    expect(first).toMatchObject({ listed: 8, swapped: 8, notPrivate: false, error: null });
    finished(h, before);
    // The shared content went through one new blob: 6 new contents for 7 live revisions (and 8 manifests).
    const sealed = [...h.server.blobs.values()].filter((b) => b.forReencrypt !== null);
    expect([sealed.filter((b) => b.kind === "CONTENT").length, sealed.filter((b) => b.kind === "MANIFEST").length]).toEqual([6, 8]);
    // A second pass lists nothing: the facts are the server's.
    expect(await h.pass()).toMatchObject({ listed: 0, swapped: 0, error: null });
  });

  it("T19: a swap repeated (its answer lost) is the same success, and changes nothing", async () => {
    const h = await harness({ crash: { op: "reencryptRevision", at: 1, when: "after" } });
    history(h.server);
    const before = revisions(h.server);
    await h.settle();
    expect(await h.pass()).toBe("CRASHED");
    // The attempt of the revision already swapped survived the crash (with those of the others in flight).
    const kept = h.client.shell.state.facts.attempts.filter((a) => a.reencrypt !== undefined);
    const done = kept.filter((a) => h.server.revisions.get(a.reencrypt!.revisionId)?.manifestBlobId === a.reencrypt!.newManifestBlobId);
    expect(done).toHaveLength(1);
    const swapped = h.server.revisions.get(done[0]!.reencrypt!.revisionId)!;
    // The next pass resumes it: the very same swap goes again, answers success, and changes nothing.
    const sent: string[] = [];
    const inner = h.client.backend;
    h.client = { ...h.client, backend: { ...inner, reencryptRevision: async (input) => (sent.push(JSON.stringify(input)), inner.reencryptRevision(input)) } };
    await h.untilDone();
    expect(sent).toContain(JSON.stringify({ revisionId: swapped.revisionId, expectedManifestBlobId: done[0]!.reencrypt!.expectedManifestBlobId, newManifestBlobId: swapped.manifestBlobId, newContentBlobId: swapped.contentBlobId }));
    expect(h.server.revisions.get(swapped.revisionId)).toBe(swapped);
    finished(h, before);
  });

  it("REENCRYPT_IN_FLIGHT: never more than 4 revisions in flight, and the server never refuses the fifth", async () => {
    let inFlight = 0;
    let most = 0;
    const refusals: string[] = [];
    const h = await harness({
      broken: (b) => ({
        ...b,
        async prepareUpload(input) {
          const r = await b.prepareUpload(input);
          if (!r.ok && r.code === "PENDING_BUDGET_EXCEEDED") refusals.push(input.blobId);
          return r;
        },
        async listRevisionsToReencrypt(after, limit) {
          return b.listRevisionsToReencrypt(after, limit);
        },
        async readRevision(...args) {
          inFlight++;
          most = Math.max(most, inFlight);
          try {
            return await b.readRevision(...args);
          } finally {
            await Promise.resolve();
          }
        },
        async reencryptRevision(input) {
          try {
            return await b.reencryptRevision(input);
          } finally {
            inFlight--;
          }
        },
      }),
    });
    for (let i = 0; i < 12; i++) remoteCommit(h.server, `o${i}`, { path: `o${i}.md`, content: `c${i}`, deleted: false });
    switchToPrivate(h.server);
    await h.settle();
    [inFlight, most] = [0, 0]; // the ticks read revisions too: only the pass counts
    expect(await h.pass()).toMatchObject({ listed: 12, swapped: 12, error: null });
    expect(REENCRYPT_IN_FLIGHT).toBe(SERVER_IN_FLIGHT);
    expect(most).toBe(REENCRYPT_IN_FLIGHT);
    expect(refusals).toEqual([]);
  });

  it("a revision that changed or was pruned under the pass: its blobs go to pending_upload_cleanup and the tick releases them", async () => {
    const h = await harness({
      broken: (b) => ({
        ...b,
        async reencryptRevision(input) {
          // Just before the first swap: the revision's history is pruned under it (§10.6).
          if (input.revisionId.startsWith("a@") && !h.server.pruned.has(input.revisionId)) prune(h.server);
          return b.reencryptRevision(input);
        },
      }),
    });
    history(h.server);
    await h.settle();
    const r = await h.pass();
    expect(r).toMatchObject({ error: null });
    // The refused swaps (REVISION_PRUNED) released their blobs through pending_upload_cleanup, in the pass.
    const released = [...h.server.blobs.values()].filter((b) => b.forReencrypt !== null && b.state === "DELETING");
    expect(released.length).toBeGreaterThan(0);
    expect(h.client.shell.state.facts.cleanup).toEqual([]);
    await h.untilDone();
    expect(pendingOf(h.server, REPLICA)).toEqual([]);
    expect(listToReencrypt(h.server, null, 100)).toEqual({ kind: "PAGE", revisions: [], next: null });
  });

  it("T20 on the client: a rotation between the upload and the swap → EPOCH_STALE, released, sealed again in the next pass", async () => {
    let rotated = false;
    const h = await harness({
      broken: (b) => ({
        ...b,
        async reencryptRevision(input) {
          if (!rotated) {
            rotated = true;
            rotateEpoch(h.server);
          }
          return b.reencryptRevision(input);
        },
      }),
    });
    history(h.server);
    const before = revisions(h.server);
    await h.settle();
    await h.untilDone();
    expect(h.client.shell.state.facts.epochId).toBe(h.server.epoch);
    finished(h, before);
  });

  it("an account that is not Private: the pass stops at INVALID_STATE and records nothing", async () => {
    const h = await harness();
    history(h.server);
    h.server.managed = true;
    await h.settle();
    expect(await h.pass()).toMatchObject({ listed: 0, notPrivate: true, error: null });
    expect(h.client.shell.state.facts.attempts).toEqual([]);
  });
});

// §44.3 T19 "crash antes y después de cada subida y del commit → al volver a listar, termina sin
// pérdidas": the instance dies right before, or right after, the n-th call of each external effect.
const EFFECTS: Op[] = ["prepareUpload", "uploadBlob", "reencryptRevision", "releaseUpload", "readRevision", "listRevisionsToReencrypt"];
const CASES: Crash[] = EFFECTS.flatMap((op) => [1, 2, 5].flatMap((at) => (["before", "after"] as const).map((when) => ({ op, at, when }))));

describe("crash before and after every external effect of the re-encryption", () => {
  it.each(CASES)("$when $op #$at: a new instance lists again and ends without losing or duplicating a revision", async (crash) => {
    // A pruning under the first pass makes some swaps fail, so that releases (the cleanup's effect) happen too.
    let pruned = false;
    const h = await harness({
      crash,
      broken: (b) => ({
        ...b,
        async reencryptRevision(input) {
          if (!pruned && input.revisionId.startsWith("a@")) {
            pruned = true;
            prune(h.server);
          }
          return b.reencryptRevision(input);
        },
      }),
    });
    history(h.server);
    const before = revisions(h.server);
    const ledger = new Map<string, string>();
    await h.settle();
    for (let i = 0; i < 40; i++) {
      await h.pass();
      expect(modelInvariants(h.server, ledger)).toEqual([]);
      await h.tick();
      const f = h.client.shell.state.facts;
      const left = listToReencrypt(h.server, null, 100);
      if (left.kind === "PAGE" && left.revisions.length === 0 && f.cleanup.length === 0 && f.attempts.length === 0) break;
    }
    // The crash really happened (a call numbered that high exists in this run), unless the run never got there.
    if ((h.calls.get(crash.op) ?? 0) >= crash.at) expect(h.crashes).toBe(1);
    finished(h, before);
    expect(h.client.shell.state.facts.attempts.filter((a) => a.mutationId.startsWith(reencryptKey("")))).toEqual([]);
  });
});
