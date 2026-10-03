import { describe, expect, it } from "vitest";
import type { Scenario } from "@nodra/sync-core/test-support/scenario";
import { newServer, remoteCommit } from "@nodra/sync-core/test-support/server";
import type { PrepareUploadInput } from "../src/ports.js";
import { runEntry, writeEntry } from "../src/executor.js";
import { newMemory, tick } from "../src/runner.js";
import { closeVaultStore, takeLeadership } from "../src/store.js";
import { devBlobCrypto, memBackend } from "./support/backend.js";
import { guardForeignAwaits } from "./guard.js";
import { QUIET, runToRest, startRun } from "./sim/e2e.js";
import { SPEC_WINDOWS } from "./sim/windows.js";
import { Crash } from "./support/memfs.js";
import { rev, rig } from "./support/shell.js";
import { tabsRig } from "./support/tabs.js";
import { utf8 } from "./support/bytes.js";

// Rule 13 write-ahead through the real store: the attempt (blob ids and exact ciphertext) is committed
// in IndexedDB before any prepareUpload, and a new instance resumes it without re-encrypting.

const edited = (): Scenario => ({
  objects: [{ path: "a.md", content: "one", second: null, replica: "head", mod: "edit", editContent: "local", moveTarget: "moved.md" }],
  localCreates: [],
  untracked: [],
  swap: false,
  merge: false,
});

describe("write-ahead upload attempts (§12.2 rule 13)", () => {
  it("the write-ahead oracle can fail: a prepare of a blob that was never persisted is reported", async () => {
    const server = newServer({ pendingBudgetBytes: 20000, maxBlobBytes: 5000, uploadWindow: 40 });
    const net = memBackend(server, "replica-1", devBlobCrypto(), () => 0.99, async () => new Set(), () => {
      throw new Error("no crash here");
    });
    await net.backend.prepareUpload({ blobId: "b-unpersisted", epochId: "e1", kind: "MANIFEST", declaredSize: 30, ciphertextSha256: "sha", forDelete: false, objectId: "o1" });
    expect(net.writeAheadViolations).toEqual(["b-unpersisted"]);
  });

  it("every prepare happens after its attempt is committed, and a crash right at the prepare resumes the same attempt", async () => {
    const run = await startRun(edited(), QUIET, 7);
    const prepares: PrepareUploadInput[] = [];
    const backend = run.client.backend as { prepareUpload: typeof run.client.backend.prepareUpload };
    const original = backend.prepareUpload.bind(backend);
    let crashed = false;
    backend.prepareUpload = async (input) => {
      prepares.push(input);
      if (!crashed) {
        crashed = true;
        run.disk.crash("at the first prepare");
      }
      return original(input);
    };
    expect(await runToRest(run, 300)).not.toBeNull();
    expect(run.log.crashes).toBe(1);
    expect(run.writeAheadViolations()).toEqual([]);
    // The blob prepared after the restart is the one of the persisted attempt: same id, same ciphertext hash.
    expect(prepares[1]).toEqual(prepares[0]);
    expect([...run.server.heads.values()].map((h) => h.content)).toEqual([`local-0${String.fromCharCode(10)}local`]);
    run.close();
  });
});

describe("no non-IndexedDB await inside a transaction, across a whole run", () => {
  it("a run with crashes, edits, remote changes and uploads never calls Web Crypto, fetch or a timer inside a Dexie transaction", async () => {
    const restore = guardForeignAwaits();
    try {
      const run = await startRun(edited(), { ...QUIET, fileCrash: 0.1, remoteWrite: 0.1, user: 0.1, activeUntil: 40 }, 11, {}, SPEC_WINDOWS);
      expect(await runToRest(run, 400)).not.toBeNull();
      run.close();
    } finally {
      restore();
    }
  });
});

describe("bug (Q65): livelock between a resolve and a case variant", () => {
  it("a local and a remote edit of a.md plus a new A.md converge: the resolve is not cancelled forever", async () => {
    const rig = await tabsRig();
    rig.disk.userWrite("a.md", "one\ntwo\nthree");
    const store = await rig.open();
    const c = await rig.client(store, await takeLeadership(store));
    const settle = async () => {
      for (let i = 0; i < 300; i++) {
        const busy = await tick(c);
        rig.server.now++;
        if (!busy) return i;
      }
      return null;
    };
    expect(await settle()).not.toBeNull();
    const id = [...c.shell.state.observations.keys()][0]!;
    remoteCommit(rig.server, id, { path: "a.md", content: "REMOTE\ntwo\nthree", deleted: false });
    rig.disk.files.get("a.md")!.content = "one\ntwo\nLOCAL";
    rig.disk.userWrite("A.md", "case variant");
    expect(await settle()).not.toBeNull();
    const heads = [...rig.server.heads.values()].map((h) => h.content).sort();
    expect(heads).toEqual(["REMOTE\ntwo\nLOCAL", "case variant"]);
    closeVaultStore(store);
  });
});

/** Settles one client: ticks until it has nothing to do, or null at the bound (a livelock). */
async function settleRig(rig: Awaited<ReturnType<typeof tabsRig>>, c: Awaited<ReturnType<Awaited<ReturnType<typeof tabsRig>>["client"]>>) {
  for (let i = 0; i < 200; i++) {
    const busy = await tick(c);
    rig.server.now++;
    if (!busy) return i;
  }
  return null;
}

/** One file synced at `from`, then renamed remotely to `to`: the client must follow without livelocking. */
async function remoteRename(from: string, to: string) {
  const rig = await tabsRig();
  rig.disk.userWrite(from, "x");
  const store = await rig.open();
  const c = await rig.client(store, await takeLeadership(store));
  try {
    expect(await settleRig(rig, c)).not.toBeNull();
    remoteCommit(rig.server, [...c.shell.state.observations.keys()][0]!, { path: to, content: "x", deleted: false });
    expect(await settleRig(rig, c)).not.toBeNull();
    return { files: [...rig.disk.files.keys()], folders: [...rig.disk.folders] };
  } finally {
    closeVaultStore(store);
  }
}

describe("bug (Q74): a move onto the name of the file's own parent folder", () => {
  // The richer e2e generator found it (about 1 run in 150). `Foo/y.md` renamed remotely to `foo`: the
  // destination's comparison key is the source's own parent folder, so every movePhysical was cancelled
  // (§16.7 rule 4, Q41) and the planner planned it again. The physical plan now parks the file outside
  // the folder first; the emptied folder is cleared when `foo` is written.
  it("converges", async () => {
    expect(await remoteRename("Foo/y.md", "foo")).toEqual({ files: ["foo"], folders: [] });
  });
});

describe("bug (Q75): a move into a folder named like the file itself", () => {
  // e2e runs 22 and 115 (fc.sample seed 11): an object whose file is `g` (or `foo`) takes the logical
  // path `g/f.md`; the folder `g/` cannot be created while the file `g` exists, so every movePhysical
  // was cancelled by ensureParent and planned again.
  it("converges", async () => {
    expect(await remoteRename("g", "g/f.md")).toEqual({ files: ["g/f.md"], folders: ["g"] });
  });
});

describe("bug (Q121): a client without `log` never replayed the open journal entry", () => {
  // `c.log?.({ kind: `replay:${await replayOpenEntry(...)}` })` skips its argument when there is no log,
  // so tick() reported work forever without touching the entry: a microtask-only livelock that froze the
  // plugin (which passes no log) after a failed write. The e2e harness always passes a log.
  it("tick() resolves the open entry whether or not a log is attached", async () => {
    const r = await rig();
    const e = await writeEntry(r.shell, { objectId: "o1", dest: "n.md", expectedPrevFp: "ABSENT", content: utf8("remote"), newSynced: rev("r2", "n.md", "remote"), logicalPath: "n.md" });
    r.disk.afterOp = (op) => {
      if (op === "replace") r.disk.crash("after replace");
    };
    await expect(runEntry(r.shell, e)).rejects.toThrow(Crash);
    r.disk.afterOp = null;
    await r.restart();
    expect(r.shell.state.journal).not.toBeNull();
    const server = newServer({ pendingBudgetBytes: 20000, maxBlobBytes: 5000, uploadWindow: 40 });
    const net = memBackend(server, "replica-1", devBlobCrypto(), () => 0.99, async () => new Set(), () => {
      throw new Error("no crash here");
    });
    await tick({ shell: r.shell, backend: net.backend, blobs: devBlobCrypto(), now: () => 0, pendingBudgetBytes: 20000, memory: newMemory() });
    expect(r.shell.state.journal).toBeNull();
    expect(r.shell.state.facts.synced.get("o1")?.revisionId).toBe("r2");
  });
});
