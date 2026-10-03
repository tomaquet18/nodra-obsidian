import { describe, expect, it } from "vitest";
import { remoteCommit } from "@nodra/sync-core/test-support/server";
import type { FileSystem } from "../src/ports.js";
import { type Client, OtherSyncToolError, tick } from "../src/runner.js";
import { failureOf, isStop } from "../src/retry.js";
import { closeVaultStore, takeLeadership } from "../src/store.js";
import { Crash } from "./support/memfs.js";
import { tabsRig } from "./support/tabs.js";

// §20.2 "Nodra es el único sincronizador de la carpeta", at run time (NOTES questions 417, 419): the real
// runner over the in-memory disk and the server model. "Another tool" is the test writing to the disk.

type Rig = Awaited<ReturnType<typeof tabsRig>>;

async function start(detect = true) {
  const rig = await tabsRig();
  let store = await rig.open();
  const make = async (): Promise<Client> => {
    const c = await rig.client(store, await takeLeadership(store));
    return detect ? { ...c, otherSyncTool: { acknowledged: [] } } : c;
  };
  const t = { rig, c: await make(), close: () => closeVaultStore(store) };
  /** A crash: the database closes, a new instance loads what was persisted. */
  const restart = async () => {
    closeVaultStore(store);
    rig.disk.revive();
    store = await rig.open();
    t.c = await make();
  };
  return Object.assign(t, { restart });
}

/** Ticks until the client has nothing to do; the stop it met, if any. Null at the bound is a livelock. */
async function settle(rig: Rig, c: Client): Promise<"rest" | OtherSyncToolError> {
  for (let i = 0; i < 300; i++) {
    let busy: boolean;
    try {
      busy = await tick(c);
    } catch (e) {
      if (e instanceof OtherSyncToolError) return e;
      throw e;
    }
    rig.server.now++;
    if (!busy) return "rest";
  }
  throw new Error("no rest within 300 ticks");
}

/** One synced file a.md holding `content`; returns its object id. */
async function synced(t: Awaited<ReturnType<typeof start>>, content = "one"): Promise<string> {
  t.rig.disk.userWrite("a.md", content);
  expect(await settle(t.rig, t.c)).toBe("rest");
  return [...t.c.shell.state.observations.keys()][0]!;
}

const heads = (rig: Rig) => [...rig.server.heads.values()].map((h) => [h.path, h.content]);
const revisions = (rig: Rig) => rig.server.revisions.size;

describe("§44: a crash between writing a file and fixing its base does not trigger the detection", () => {
  it("an adapter that rewrites the destination crashes after the new content is in place, before the temporary is deleted → replay cancels (§15) → no pause", async () => {
    const t = await start();
    const id = await synced(t);
    remoteCommit(t.rig.server, id, { path: "a.md", content: "two", deleted: false });
    // §15: "el adaptador puede resolver el rename del temporal ... modificando el destino".
    const fs = t.rig.disk.fs as { replace: FileSystem["replace"] };
    const replace = fs.replace;
    fs.replace = async (tmp, dest) => {
      t.rig.disk.userWrite(dest, t.rig.disk.files.get(tmp)!.content);
      t.rig.disk.crash("rewriting replace, before removing the temporary");
    };
    await expect(settle(t.rig, t.c)).rejects.toThrow(Crash);
    fs.replace = replace;
    expect(t.rig.disk.files.get("a.md")?.content).toBe("two");
    expect([...t.rig.disk.files.keys()].some((p) => p.includes("nodra-tmp-"))).toBe(true);
    await t.restart();
    expect(t.c.shell.state.journal).not.toBeNull();
    const before = revisions(t.rig);
    expect(await settle(t.rig, t.c)).toBe("rest");
    expect(t.rig.events.some((e) => e.kind === "replay:CANCEL")).toBe(true);
    expect(t.c.shell.state.facts.synced.get(id)?.revisionId).toBe(t.rig.server.heads.get(id)!.revisionId);
    expect([...t.rig.disk.files.keys()]).toEqual(["a.md"]);
    expect(revisions(t.rig)).toBe(before); // nothing sent: no spurious commit
    expect(t.c.shell.state.otherSync.explainedWrites.size).toBe(0); // pruned once S holds it
    t.close();
  });

  it("an atomic replace crashing right after it → replay completes → no pause", async () => {
    const t = await start();
    const id = await synced(t);
    remoteCommit(t.rig.server, id, { path: "a.md", content: "two", deleted: false });
    t.rig.disk.afterOp = (op) => {
      if (op === "replace") t.rig.disk.crash("after replace");
    };
    await expect(settle(t.rig, t.c)).rejects.toThrow(Crash);
    t.rig.disk.afterOp = null;
    await t.restart();
    expect(await settle(t.rig, t.c)).toBe("rest");
    expect(t.rig.events.some((e) => e.kind === "replay:COMPLETE")).toBe(true);
    expect(t.rig.disk.files.get("a.md")?.content).toBe("two");
    t.close();
  });
});

describe("another tool writes the remote revision's content before this replica applies it", () => {
  it("sync pauses with OTHER_SYNC_TOOL naming (object, revision, path), sends nothing, and pauses again after a restart", async () => {
    const t = await start();
    const id = await synced(t);
    remoteCommit(t.rig.server, id, { path: "a.md", content: "two", deleted: false });
    t.rig.disk.userWrite("a.md", "two"); // the other tool
    const before = revisions(t.rig);
    const stop = await settle(t.rig, t.c);
    expect(stop).toBeInstanceOf(OtherSyncToolError);
    const e = stop as OtherSyncToolError;
    expect(e.arrivals).toEqual([{ objectId: id, revisionId: t.rig.server.heads.get(id)!.revisionId, path: "a.md" }]);
    expect(isStop(e)).toBe(true);
    expect(failureOf(e).code).toBe("OTHER_SYNC_TOOL");
    expect(revisions(t.rig)).toBe(before);
    expect(t.c.shell.state.facts.synced.get(id)?.revisionId).not.toBe(t.rig.server.heads.get(id)!.revisionId);
    // The pause is derived from facts: a new instance finds it again.
    await t.restart();
    expect(await settle(t.rig, t.c)).toBeInstanceOf(OtherSyncToolError);
    t.close();
  });

  it("resume accepts exactly the arrivals shown: S follows R, nothing is sent, and detection re-arms for the next revision", async () => {
    const t = await start();
    const id = await synced(t);
    remoteCommit(t.rig.server, id, { path: "a.md", content: "two", deleted: false });
    t.rig.disk.userWrite("a.md", "two");
    const stop = (await settle(t.rig, t.c)) as OtherSyncToolError;
    const before = revisions(t.rig);
    t.c.otherSyncTool!.acknowledged.push(...stop.arrivals);
    expect(await settle(t.rig, t.c)).toBe("rest");
    expect(t.c.shell.state.facts.synced.get(id)?.revisionId).toBe(stop.arrivals[0]!.revisionId);
    expect(revisions(t.rig)).toBe(before);
    expect(t.c.shell.state.otherSync.acknowledged.size).toBe(0); // pruned: S reached it
    remoteCommit(t.rig.server, id, { path: "a.md", content: "three", deleted: false });
    t.rig.disk.userWrite("a.md", "three");
    expect(await settle(t.rig, t.c)).toBeInstanceOf(OtherSyncToolError);
    t.close();
  });

  it("the acknowledgement is persisted: a crash right after it does not pause again for the same arrival", async () => {
    const t = await start();
    t.rig.disk.userWrite("b.md", "bee");
    const id = await synced(t);
    const other = [...t.c.shell.state.observations].find(([, o]) => o.kind === "PRESENT" && o.physicalPath === "b.md")![0];
    const a = [...t.c.shell.state.observations].find(([, o]) => o.kind === "PRESENT" && o.physicalPath === "a.md")![0];
    expect(id).toBeDefined();
    remoteCommit(t.rig.server, a, { path: "a.md", content: "two", deleted: false });
    t.rig.disk.userWrite("a.md", "two");
    const stop = (await settle(t.rig, t.c)) as OtherSyncToolError;
    expect(stop).toBeInstanceOf(OtherSyncToolError);
    // The next tick persists the acknowledgement at its check, then dies downloading b.md's new revision.
    remoteCommit(t.rig.server, other, { path: "b.md", content: "bee two", deleted: false });
    t.c.otherSyncTool!.acknowledged.push(...stop.arrivals);
    const backend = t.c.backend as { readRevision: typeof t.c.backend.readRevision };
    const readRevision = backend.readRevision;
    backend.readRevision = async () => t.rig.disk.crash("downloading, after the acknowledgement");
    await tick(t.c).catch(() => undefined); // the runner may take the failed download for a lost response
    expect(t.rig.disk.dead).toBe(true);
    backend.readRevision = readRevision;
    await t.restart();
    expect(t.c.shell.state.otherSync.acknowledged.get(a)).toBe(stop.arrivals[0]!.revisionId);
    expect(await settle(t.rig, t.c)).toBe("rest");
    expect(t.rig.disk.files.get("b.md")?.content).toBe("bee two");
    t.close();
  });

  it("empty content is exempt: another tool (or a coincidence) emptying the file does not pause", async () => {
    const t = await start();
    const id = await synced(t);
    remoteCommit(t.rig.server, id, { path: "a.md", content: "", deleted: false });
    t.rig.disk.userWrite("a.md", "");
    expect(await settle(t.rig, t.c)).toBe("rest");
    expect(t.c.shell.state.facts.synced.get(id)?.revisionId).toBe(t.rig.server.heads.get(id)!.revisionId);
    t.close();
  });

  it("off by default: without `otherSyncTool` the same arrival is taken as convergence (S := R)", async () => {
    const t = await start(false);
    const id = await synced(t);
    remoteCommit(t.rig.server, id, { path: "a.md", content: "two", deleted: false });
    t.rig.disk.userWrite("a.md", "two");
    expect(await settle(t.rig, t.c)).toBe("rest");
    expect(t.c.shell.state.facts.synced.get(id)?.revisionId).toBe(t.rig.server.heads.get(id)!.revisionId);
    t.close();
  });
});

describe("what is not another tool", () => {
  it("§44 own commit echo: the event of the revision that is already the base → no-op, no pause", async () => {
    const t = await start();
    const id = await synced(t);
    t.rig.disk.userWrite("a.md", "mine");
    expect(await settle(t.rig, t.c)).toBe("rest");
    expect(heads(t.rig)).toEqual([["a.md", "mine"]]);
    expect(t.c.shell.state.facts.synced.get(id)?.revisionId).toBe(t.rig.server.heads.get(id)!.revisionId);
    expect(t.c.shell.state.facts.cursor).toBeGreaterThan(0); // the echo was read
    t.close();
  });

  it("a concurrent local edit with other content is a conflict (merge), not another tool", async () => {
    const t = await start();
    const id = await synced(t, "one\ntwo\nthree");
    remoteCommit(t.rig.server, id, { path: "a.md", content: "REMOTE\ntwo\nthree", deleted: false });
    t.rig.disk.userWrite("a.md", "one\ntwo\nLOCAL");
    expect(await settle(t.rig, t.c)).toBe("rest");
    expect(heads(t.rig)).toEqual([["a.md", "REMOTE\ntwo\nLOCAL"]]);
    t.close();
  });
});

describe("renames of another replica on disk before they are applied: three in a row pause", () => {
  /** A remote rename of the object, whose file another tool moves on this disk first. */
  const foreignRename = (t: Awaited<ReturnType<typeof start>>, id: string, to: string) => {
    const from = [...t.rig.disk.files.keys()].find((p) => p.endsWith(".md"))!;
    remoteCommit(t.rig.server, id, { path: to, content: t.rig.disk.files.get(from)!.content, deleted: false });
    const f = t.rig.disk.files.get(from)!;
    t.rig.disk.files.delete(from);
    t.rig.disk.files.set(to, f);
  };
  const ownRename = (t: Awaited<ReturnType<typeof start>>, id: string, to: string) => {
    const from = [...t.rig.disk.files.keys()].find((p) => p.endsWith(".md"))!;
    remoteCommit(t.rig.server, id, { path: to, content: t.rig.disk.files.get(from)!.content, deleted: false });
  };

  it("the third one pauses", async () => {
    const t = await start();
    const id = await synced(t);
    foreignRename(t, id, "b.md");
    expect(await settle(t.rig, t.c)).toBe("rest");
    foreignRename(t, id, "c.md");
    expect(await settle(t.rig, t.c)).toBe("rest");
    foreignRename(t, id, "d.md");
    const stop = await settle(t.rig, t.c);
    expect(stop).toBeInstanceOf(OtherSyncToolError);
    expect((stop as OtherSyncToolError).renames).toBe(3);
    t.close();
  });

  it("the rename is already known (polled) when another tool does it: counted once, by whichever rule sees it", async () => {
    const t = await start();
    const id = await synced(t);
    remoteCommit(t.rig.server, id, { path: "b.md", content: "one", deleted: false });
    expect(await tick(t.c)).toBe(true); // polls the rename and fetches its content
    expect(t.c.shell.state.facts.remote.get(id)?.path).toBe("b.md");
    const f = t.rig.disk.files.get("a.md")!;
    t.rig.disk.files.delete("a.md");
    t.rig.disk.files.set("b.md", f);
    expect(await settle(t.rig, t.c)).toBe("rest");
    expect(t.c.memory.projectionRenameArrivals).toBe(1);
    expect(t.rig.events.filter((e) => e.kind === "other-sync-rename")).toHaveLength(1);
    t.close();
  });

  it("a rename this replica does itself resets the run: two, own, two → no pause", async () => {
    const t = await start();
    const id = await synced(t);
    foreignRename(t, id, "b.md");
    expect(await settle(t.rig, t.c)).toBe("rest");
    foreignRename(t, id, "c.md");
    expect(await settle(t.rig, t.c)).toBe("rest");
    ownRename(t, id, "d.md");
    expect(await settle(t.rig, t.c)).toBe("rest");
    expect(t.rig.disk.files.has("d.md")).toBe(true);
    foreignRename(t, id, "e.md");
    expect(await settle(t.rig, t.c)).toBe("rest");
    foreignRename(t, id, "f.md");
    expect(await settle(t.rig, t.c)).toBe("rest");
    expect(t.c.memory.projectionRenameArrivals).toBe(2);
    t.close();
  });
});
