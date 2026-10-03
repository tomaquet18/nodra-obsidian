import { describe, expect, it } from "vitest";
import type { IntentChange } from "@nodra/sync-core";
import { type Follower, type LeaderMessage, followerReceive, followerRescan, newFollower, refreshView, submitIntent } from "../src/intents.js";
import { diskQueue } from "../src/queue.js";
import { type Client, tick } from "../src/runner.js";
import { type VaultStore, closeVaultStore, loadPendingIntents, loadVault, pendingIntentIds, takeLeadership } from "../src/store.js";
import { channelHub, tabsRig } from "./support/tabs.js";
import { utf8 } from "./support/bytes.js";

// §20.2 intents through the real client: a follower writes its row to pending_intents, the leader
// decides it with sync-core (leader.ts) and applies it through the journal (§15); the row is deleted in
// the same transaction as the effect. Channel messages are only hints.

type Rig = Awaited<ReturnType<typeof tabsRig>>;

async function leader(rig: Rig, notify?: (m: LeaderMessage) => void) {
  const store = await rig.open();
  const epoch = await takeLeadership(store);
  return { store, client: await rig.client(store, epoch, rig.disk.fs, notify) };
}

/** Ticks until quiescent (the server clock advances one unit per tick). */
async function settle(rig: Rig, c: Client, max = 300): Promise<void> {
  for (let i = 0; i < max; i++) {
    const busy = await tick(c);
    rig.server.now++;
    if (!busy && c.shell.state.intents.length === 0 && (await loadPendingIntents(c.shell.store, c.shell.dlc)).length === 0) return;
  }
  throw new Error("not quiescent");
}

/** A vault with a.md ("one") synced, the leader, and a follower context with a fresh view. */
async function world(notify?: (m: LeaderMessage) => void) {
  const rig = await tabsRig();
  rig.disk.userWrite("a.md", "one");
  const l = await leader(rig, notify);
  await settle(rig, l.client);
  const id = [...l.client.shell.state.observations.keys()][0]!;
  const fstore = await rig.open();
  const f = newFollower("ctx-f");
  await refreshView(fstore, f);
  return { rig, l, id, fstore, f };
}

const content = (path: string, text: string): IntentChange => ({ kind: "CONTENT", path, content: utf8(text) });
const intentEvents = (rig: Rig) => rig.events.filter((e) => e.kind === "intent").map((e) => JSON.parse(e.detail!) as { intentId: string; outcome: string; priorFp: string });
const serverContents = (rig: Rig) => [...rig.server.heads.values()].filter((h) => !h.deleted).map((h) => [h.path, h.content]).sort();
const submit = (w: { rig: Rig; fstore: VaultStore; f: Follower }, intentId: string, objectId: string, change: IntentChange) =>
  submitIntent(w.fstore, w.rig.dlc, null, w.f, { intentId, objectId, change });

describe("§20.2 intents: current edits apply, superseded ones never overwrite", () => {
  it("a current content change is applied through the journal, uploaded, and acked; its row is gone", async () => {
    const acks: LeaderMessage[] = [];
    const w = await world((m) => acks.push(m));
    const sent = await submit(w, "i1", w.id, content("a.md", "from follower"));
    expect(sent).toMatchObject({ intentSeq: 1, viewVersion: 1, afterIntentId: null });
    await settle(w.rig, w.l.client);
    expect(w.rig.disk.files.get("a.md")?.content).toBe("from follower");
    expect(serverContents(w.rig)).toEqual([["a.md", "from follower"]]);
    expect(await pendingIntentIds(w.fstore, "ctx-f")).toEqual(new Set());
    expect(acks).toEqual([{ kind: "ack", contextId: "ctx-f", intentSeq: 1, intentId: "i1", outcome: "APPLY" }]);
    expect(intentEvents(w.rig).map((e) => [e.intentId, e.outcome])).toEqual([["i1", "APPLY"]]);
  });

  it("local_version increases on every change of the local state, whatever the cause (here: a user edit on disk)", async () => {
    const w = await world();
    const before = w.l.client.shell.state.intentState.localVersion.get(w.id)!;
    w.rig.disk.files.get("a.md")!.content = "user";
    await tick(w.l.client);
    expect(w.l.client.shell.state.intentState.localVersion.get(w.id)).toBe(before + 1);
    expect((await loadVault(w.fstore, w.rig.dlc)).intentState.localVersion.get(w.id)).toBe(before + 1);
  });

  it("stale view (the user edited in between): the content change becomes a conflict copy, the user's edit stays", async () => {
    const w = await world();
    w.rig.disk.files.get("a.md")!.content = "user";
    await settle(w.rig, w.l.client);
    await submit(w, "i1", w.id, content("a.md", "from follower"));
    await settle(w.rig, w.l.client);
    expect(w.rig.disk.files.get("a.md")?.content).toBe("user");
    expect([...w.rig.disk.files.values()].map((f) => f.content).sort()).toEqual(["from follower", "user"]);
    expect(serverContents(w.rig).map(([, c]) => c).sort()).toEqual(["from follower", "user"]);
    expect(intentEvents(w.rig).map((e) => e.outcome)).toEqual(["CONFLICT_COPY"]);
  });

  it("stale view: a path change or a delete is discarded (and acked as such); nothing moves", async () => {
    const acks: LeaderMessage[] = [];
    const w = await world((m) => acks.push(m));
    w.rig.disk.files.get("a.md")!.content = "user";
    await settle(w.rig, w.l.client);
    await submit(w, "i1", w.id, { kind: "PATH", path: "b.md", content: null });
    await submit(w, "i2", w.id, { kind: "DELETE", path: "a.md", content: null });
    await settle(w.rig, w.l.client);
    expect([...w.rig.disk.files.keys()]).toEqual(["a.md"]);
    expect(serverContents(w.rig)).toEqual([["a.md", "user"]]);
    expect(acks.map((m) => m.kind === "ack" && m.outcome)).toEqual(["DISCARD", "DISCARD"]);
  });

  it("a view_fp that still matches makes an intent current although local_version moved (own upload confirmed)", async () => {
    const w = await world();
    // Same content written back: the observation's hash changes twice, the state the follower saw returns.
    w.rig.disk.files.get("a.md")!.content = "tmp";
    await tick(w.l.client);
    w.rig.disk.files.get("a.md")!.content = "one";
    await settle(w.rig, w.l.client);
    await submit(w, "i1", w.id, content("a.md", "from follower"));
    await settle(w.rig, w.l.client);
    expect(intentEvents(w.rig).map((e) => e.outcome)).toEqual(["APPLY"]);
    expect(w.rig.disk.files.get("a.md")?.content).toBe("from follower");
  });

  it("a chain of edits without seeing the results: each chains on the previous one (after_intent_id)", async () => {
    const w = await world();
    const first = await submit(w, "i1", w.id, content("a.md", "v1"));
    const second = await submit(w, "i2", w.id, content("a.md", "v2"));
    expect(second).toMatchObject({ intentSeq: 2, afterIntentId: first.intentId, viewVersion: first.viewVersion });
    await settle(w.rig, w.l.client);
    expect(intentEvents(w.rig).map((e) => [e.intentId, e.outcome])).toEqual([
      ["i1", "APPLY"],
      ["i2", "APPLY"],
    ]);
    expect(serverContents(w.rig)).toEqual([["a.md", "v2"]]);
  });

  it("a current path change renames the object; a current delete deletes it; a creation creates one", async () => {
    const w = await world();
    await submit(w, "i1", w.id, { kind: "PATH", path: "b.md", content: null });
    await settle(w.rig, w.l.client);
    expect(serverContents(w.rig)).toEqual([["b.md", "one"]]);
    expect([...w.rig.disk.files.keys()]).toEqual(["b.md"]);
    await refreshView(w.fstore, w.f);
    await submit(w, "i2", w.id, { kind: "DELETE", path: "b.md", content: null });
    await submit(w, "i3", "new-object", content("c.md", "created"));
    await settle(w.rig, w.l.client);
    expect(serverContents(w.rig)).toEqual([["c.md", "created"]]);
    expect([...w.rig.disk.files.keys()]).toEqual(["c.md"]);
  });

  it("bug (Q64): an intent whose write keeps being cancelled does not starve the planner that clears the way", async () => {
    const w = await world();
    // A case variant of a.md appears (untracked): until the projection moves it, a.md is not free for a
    // replace (§16.7 rule 4, Q41), so every journaled write of a.md is cancelled.
    w.rig.disk.userWrite("A.md", "case variant");
    await submit(w, "i1", w.id, content("a.md", "from follower"));
    w.l.client.memory.intentHint = true;
    await settle(w.rig, w.l.client);
    expect(intentEvents(w.rig).map((e) => e.intentId)).toEqual(["i1"]);
    expect(serverContents(w.rig).map(([, c]) => c).sort()).toEqual(["case variant", "from follower"]);
  });

  it("bug (Q66): a creation under a path whose folder is a file still lands somewhere (no endless search for a free name)", async () => {
    const w = await world();
    w.rig.disk.userWrite("g", "a file named like the folder");
    await submit(w, "i1", "new-object", content("g/f.md", "created"));
    w.l.client.memory.intentHint = true;
    await settle(w.rig, w.l.client);
    expect(intentEvents(w.rig).map((e) => [e.intentId, e.outcome])).toEqual([["i1", "APPLY"]]);
    expect(serverContents(w.rig).map(([, c]) => c).sort()).toEqual(["a file named like the folder", "created", "one"]);
  });

  it("a creation whose path is taken lands next to it; the projection settles both", async () => {
    const w = await world();
    await submit(w, "i1", "new-object", content("a.md", "created"));
    await settle(w.rig, w.l.client);
    expect(serverContents(w.rig).map(([, c]) => c).sort()).toEqual(["created", "one"]);
    expect(w.rig.disk.files.get("a.md")?.content).toBe("one");
  });
});

describe("§20.2 delivery: rows are the truth, messages only hints", () => {
  it("duplicated and reordered hints from two contexts: every intent is processed once, in intent_seq order per context", async () => {
    const w = await world();
    const hub = channelHub();
    const leaderPort = hub.open("leader");
    let hints = 0;
    leaderPort.addEventListener("message", () => {
      hints++;
      w.l.client.memory.intentHint = true;
    });
    const g = newFollower("ctx-g");
    const gstore = await w.rig.open();
    await refreshView(gstore, g);
    const fPort = hub.open("f");
    const gPort = hub.open("g");
    await submitIntent(w.fstore, w.rig.dlc, fPort, w.f, { intentId: "f1", objectId: w.id, change: content("a.md", "f one") });
    await submitIntent(gstore, w.rig.dlc, gPort, g, { intentId: "g1", objectId: w.id, change: content("a.md", "g one") });
    await submitIntent(w.fstore, w.rig.dlc, fPort, w.f, { intentId: "f2", objectId: w.id, change: content("a.md", "f two") });
    await submitIntent(gstore, w.rig.dlc, gPort, g, { intentId: "g2", objectId: "g-new", change: content("g.md", "g new") });
    hub.flush({ duplicate: true, reverse: true });
    expect(hints).toBe(8);
    await settle(w.rig, w.l.client);
    const order = intentEvents(w.rig).map((e) => e.intentId);
    expect([...order].sort()).toEqual(["f1", "f2", "g1", "g2"]);
    expect(order.indexOf("f1")).toBeLessThan(order.indexOf("f2"));
    expect(order.indexOf("g1")).toBeLessThan(order.indexOf("g2"));
    // f2 chains on f1 (its own edit); g1 was made on the state f1 superseded → kept as a conflict copy.
    expect(intentEvents(w.rig).map((e) => [e.intentId, e.outcome])).toEqual([
      ["f1", "APPLY"],
      ["f2", "APPLY"],
      ["g1", "CONFLICT_COPY"],
      ["g2", "APPLY"],
    ]);
    expect(serverContents(w.rig).map(([, c]) => c).sort()).toEqual(["f two", "g new", "g one"]);
  });

  it("with every message lost the leader still processes the rows (periodic rescan); the follower confirms by the rows being gone", async () => {
    const w = await world();
    const hub = channelHub();
    const fPort = hub.open("f");
    await submitIntent(w.fstore, w.rig.dlc, fPort, w.f, { intentId: "i1", objectId: w.id, change: content("a.md", "lost hint") });
    hub.flush({ lose: () => true });
    w.l.client.memory.intentHint = false;
    w.l.client.memory.lastSweep = w.rig.server.now; // just swept: only the rescan period brings it
    await settle(w.rig, w.l.client);
    expect(w.rig.disk.files.get("a.md")?.content).toBe("lost hint");
    expect(w.f.unseen.get(w.id)).toBe("i1");
    const posted = hub.sent.length;
    await followerRescan(w.fstore, w.f, fPort);
    expect(w.f.unseen.size).toBe(0);
    expect(w.f.sent.size).toBe(0);
    expect(hub.sent.length).toBe(posted); // nothing re-sent: the row is gone
    expect(w.f.view.get(w.id)?.version).toBe(w.l.client.shell.state.intentState.localVersion.get(w.id));
  });

  it("a rescan with a row still pending re-sends only the hint, never the content", async () => {
    const w = await world();
    const hub = channelHub();
    const fPort = hub.open("f");
    await submitIntent(w.fstore, w.rig.dlc, fPort, w.f, { intentId: "i1", objectId: w.id, change: content("a.md", "x") });
    await followerRescan(w.fstore, w.f, fPort);
    expect(hub.sent).toEqual([
      { kind: "intent", contextId: "ctx-f" },
      { kind: "intent", contextId: "ctx-f" },
    ]);
    expect((await loadPendingIntents(w.fstore, w.rig.dlc)).map((i) => i.intentId)).toEqual(["i1"]);
  });

  it("an ack clears after_intent_id only after the follower re-read the state", async () => {
    const w = await world();
    await submit(w, "i1", w.id, content("a.md", "v1"));
    await settle(w.rig, w.l.client);
    await followerReceive(w.fstore, w.f, { kind: "ack", contextId: "ctx-f", intentSeq: 1, intentId: "i1", outcome: "APPLY" });
    expect(w.f.unseen.size).toBe(0);
    const next = await submit(w, "i2", w.id, content("a.md", "v2"));
    expect(next.afterIntentId).toBeNull();
    expect(next.viewVersion).toBe(w.l.client.shell.state.intentState.localVersion.get(w.id));
    await followerReceive(w.fstore, w.f, { kind: "bogus" });
    await followerReceive(w.fstore, w.f, "not even an object");
  });

  it("bug (Q414): an edit on the view of the context's previous intent chains on it even after its ack (the editor never saw the result)", async () => {
    // The web editor sends each edit on the note as it last LOADED it (an explicit view), and keeps that
    // view while the user types. Its first edit ("A") is applied, uploaded and acked; the ack arrives while
    // the user is still typing, so the editor does not reload the note. Its next edit is made on top of its
    // own "A", on the same view as before: it must chain on "A" (after_intent_id), not become a conflict
    // copy of the user's own typing against the user's own "A".
    const acks: LeaderMessage[] = [];
    const w = await world((m) => acks.push(m));
    const view = new Map(w.f.view);
    await submitIntent(w.fstore, w.rig.dlc, null, w.f, { intentId: "i1", objectId: w.id, change: content("a.md", "A") }, view);
    await settle(w.rig, w.l.client);
    expect(serverContents(w.rig)).toEqual([["a.md", "A"]]);
    for (const m of acks) await followerReceive(w.fstore, w.f, m);
    expect(w.f.unseen.size).toBe(0);
    const next = await submitIntent(w.fstore, w.rig.dlc, null, w.f, { intentId: "i2", objectId: w.id, change: content("a.md", "Aixo es una prova") }, view);
    await settle(w.rig, w.l.client);
    expect(intentEvents(w.rig).map((e) => [e.intentId, e.outcome])).toEqual([
      ["i1", "APPLY"],
      ["i2", "APPLY"],
    ]);
    expect(serverContents(w.rig)).toEqual([["a.md", "Aixo es una prova"]]);
    expect(next.afterIntentId).toBe("i1");
    expect([...w.rig.disk.files.keys()]).toEqual(["a.md"]);
  });
});

describe("§20.2 intents across crashes and handovers", () => {
  const restart = async (w: Awaited<ReturnType<typeof world>>) => {
    closeVaultStore(w.l.store);
    w.rig.disk.revive();
    w.rig.disk.beforeOp = null;
    w.l = await leader(w.rig);
  };

  for (const at of ["write", "replace"] as const) {
    it(`a crash at the intent's ${at} (journal open): the next leader completes or re-decides it, applied exactly once`, async () => {
      const w = await world();
      await submit(w, "i1", w.id, content("a.md", "from follower"));
      w.rig.disk.onCrash = () => closeVaultStore(w.l.store);
      w.rig.disk.beforeOp = (op) => {
        if (op === at) w.rig.disk.crash(`at ${at}`);
      };
      w.l.client.memory.intentHint = true; // the follower's hint
      await expect(tick(w.l.client)).rejects.toThrow(/crash/);
      expect(w.l.client.shell.state.journal?.intent?.intentId).toBe("i1");
      await restart(w);
      await settle(w.rig, w.l.client);
      expect(w.rig.disk.files.get("a.md")?.content).toBe("from follower");
      expect(intentEvents(w.rig).map((e) => [e.intentId, e.outcome])).toEqual([["i1", "APPLY"]]);
      expect(await pendingIntentIds(w.fstore, "ctx-f")).toEqual(new Set());
      expect([...w.rig.disk.files.keys()]).toEqual(["a.md"]);
    });
  }

  it("graceful handover mid-transition: the old leader's queue closes after its write in progress; the new leader finishes the intent", async () => {
    const w = await world();
    await submit(w, "i1", w.id, content("a.md", "from follower"));
    const q = diskQueue(w.rig.disk.fs);
    const old = await w.rig.client(w.l.store, w.l.client.shell.state.leaderEpoch, q.fs);
    let closing: Promise<void> | null = null;
    w.rig.disk.beforeOp = (op) => {
      if (op === "write" && closing === null) closing = q.close(); // unload arrives during the temporary's write
    };
    await expect(tick(old)).rejects.toThrow(/queue is closed/);
    await closing;
    w.rig.disk.beforeOp = null;
    // The write in progress finished (the temporary exists); no later operation started.
    expect([...w.rig.disk.files.keys()].some((p) => p.startsWith("nodra-tmp-"))).toBe(true);
    expect(w.rig.disk.files.get("a.md")?.content).toBe("one");
    const next = await leader(w.rig);
    await settle(w.rig, next.client);
    expect(w.rig.disk.files.get("a.md")?.content).toBe("from follower");
    expect([...w.rig.disk.files.keys()]).toEqual(["a.md"]);
    expect(intentEvents(w.rig).map((e) => e.intentId)).toEqual(["i1"]);
  });

  it("a deposed leader stops at its first write: fencing rejects it and the store is untouched; the new leader processes the intent", async () => {
    const w = await world();
    await submit(w, "i1", w.id, content("a.md", "from follower"));
    const next = await leader(w.rig); // takeover: leader_epoch incremented first
    const raw = async () => JSON.stringify(await Promise.all(["meta", "observations", "pendingIntents", "journal", "intentObjects"].map((t) => next.store.db.table(t).toArray())));
    const before = await raw();
    // The old leader wakes up and tries to process the intent: its first transaction (journal open) aborts.
    w.l.client.memory.intentHint = true;
    await expect(tick(w.l.client)).rejects.toThrow(/fenced/);
    expect(await raw()).toBe(before);
    expect(w.rig.disk.files.get("a.md")?.content).toBe("one");
    await settle(w.rig, next.client);
    expect(w.rig.disk.files.get("a.md")?.content).toBe("from follower");
    expect(intentEvents(w.rig).map((e) => e.intentId)).toEqual(["i1"]);
  });
});
