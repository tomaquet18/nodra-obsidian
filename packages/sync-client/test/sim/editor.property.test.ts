import fc from "fast-check";
import { describe, expect, inject, it } from "vitest";
import type { ObjectId } from "@nodra/sync-core";
import { type LeaderMessage, type View, followerReceive, followerRescan, newFollower, refreshView, submitIntent } from "../../src/intents.js";
import { localViewFp } from "../../src/executor.js";
import { type Client, tick } from "../../src/runner.js";
import { rebaseText } from "../../src/rebase.js";
import { type VaultStore, closeVaultStore, loadPendingIntents, readLocalView, takeLeadership } from "../../src/store.js";
import { utf8 } from "../support/bytes.js";
import { tabsRig } from "../support/tabs.js";

// (Q414) One user typing in one editor, nobody else writing: never a conflict copy, never a lost edit.
//
// The editor follows the discipline of apps/web Editor.tsx (editor-sync.ts): each pause sends the whole
// text as an intent on the note as the editor last LOADED it. When it learns a newer state of the note
// with nothing of this context for it unprocessed (replica.pending): with nothing unsent it loads it; with
// a pause pending it rebases the text being typed onto it (Q415, `rebaseText`), or keeps its view if that
// conflicts. The leader, the store and the follower are the real ones (runner, Dexie, intents.ts). Acks
// and state messages are delivered late, lost (the rescan confirms instead), and the leader is replaced
// now and then (a new instance, §20.2 "Relevo"). The only writer is the user, so every intent must apply.
//
// (Q415) The same editor while another writer (the leader's disk, as Obsidian or a remote change would be)
// changes a line far from the one the user types: the change arrives while a pause is pending, and it
// must merge (never a copy, never a lost line).

const SIM = inject("nodraSim") === true;
const runs = (fast: number, full: number) => (SIM ? full : fast);
const BROKEN_SEED = 20260930;

/** Uncomfortable texts: empty, the original content, repeats of one another. */
const TEXTS = ["", "one", "A", "Aixo", "Aixo es una prova", "A"];

type Op =
  | { readonly k: "type"; readonly text: string }
  | { readonly k: "pause" }
  | { readonly k: "leader" }
  | { readonly k: "deliver"; readonly lose: boolean }
  | { readonly k: "rescan" }
  | { readonly k: "load" }
  | { readonly k: "relay" }
  | { readonly k: "remote"; readonly text: string };

const opArb: fc.Arbitrary<Op> = fc.oneof(
  { weight: 4, arbitrary: fc.constantFrom(...TEXTS).map((text): Op => ({ k: "type", text })) },
  { weight: 3, arbitrary: fc.constant<Op>({ k: "pause" }) },
  { weight: 4, arbitrary: fc.constant<Op>({ k: "leader" }) },
  { weight: 3, arbitrary: fc.boolean().map((lose): Op => ({ k: "deliver", lose })) },
  { weight: 1, arbitrary: fc.constant<Op>({ k: "rescan" }) },
  { weight: 3, arbitrary: fc.constant<Op>({ k: "load" }) },
  { weight: 1, arbitrary: fc.constant<Op>({ k: "relay" }) },
);

interface Broken {
  /** The follower forgets its previous intent once acked (the code before Q414): no chain after the ack. */
  readonly forgetsChainOnAck?: boolean;
  /** The editor never rebases (the code before Q415): with a pause pending it keeps its loaded view. */
  readonly noRebase?: boolean;
}

/** (Q415) The user types line 1; the other writer changes line 3; line 2 keeps them apart (§17.1). */
const MID = "mid";
const withLine = (text: string, i: number, line: string) => {
  const lines = text.split("\n");
  lines[i] = line;
  return lines.join("\n");
};

async function typing(ops: readonly Op[], broken: Broken, remote = false): Promise<{ outcomes: string[]; server: string[][]; disk: string[][]; typed: string }> {
  const rig = await tabsRig();
  rig.disk.userWrite("a.md", remote ? `one\n${MID}\nr` : "one");
  const messages: LeaderMessage[] = [];
  const stores: VaultStore[] = [];
  const leader = async (): Promise<Client> => {
    const store = await rig.open();
    stores.push(store);
    return rig.client(store, await takeLeadership(store), rig.disk.fs, (m) => messages.push(m));
  };
  let client = await leader();
  const settle = async () => {
    for (let i = 0; i < 300; i++) {
      const busy = await tick(client);
      rig.server.now++;
      if (!busy && (await loadPendingIntents(client.shell.store, client.shell.dlc)).length === 0) return;
    }
    throw new Error("not quiescent");
  };
  await settle();
  const id = [...client.shell.state.observations.keys()][0]!;
  const fstore = await rig.open();
  stores.push(fstore);
  const f = newFollower("ctx-editor");
  await refreshView(fstore, f);

  // The editor: the view it loaded, its text, and whether a pause is pending.
  const loaded = async (): Promise<{ view: View; text: string }> => {
    const { observations, localVersion } = await readLocalView(fstore);
    const o = observations.get(id);
    const path = o?.kind === "PRESENT" ? o.physicalPath : "a.md";
    // One read, as the web's NoteView (version, observation and content together).
    return { view: new Map([[id as ObjectId, { version: localVersion.get(id) ?? 0, fp: localViewFp(o) }]]), text: localVersion.has(id) ? (rig.disk.files.get(path)?.content ?? "") : "" };
  };
  // `loadedText`: the text of the editor's view; `sent`: the text of the last pause sent on that view.
  let editor = { ...(await loaded()), dirty: false, sent: null as string | null };
  let loadedText = editor.text;
  let typed = remote ? "one" : editor.text;
  let other = "r";
  let n = 0;
  const pause = async () => {
    if (!editor.dirty) return;
    if (broken.forgetsChainOnAck && !f.unseen.has(id)) f.last.delete(id);
    await submitIntent(fstore, rig.dlc, null, f, { intentId: `i${++n}`, objectId: id, change: { kind: "CONTENT", path: "a.md", content: utf8(editor.text) } }, editor.view);
    client.memory.intentHint = true;
    editor = { ...editor, dirty: false, sent: editor.text };
  };
  // Editor.tsx's effect when the store shows the note (editor-sync.ts `follow`).
  const learn = async () => {
    if (f.unseen.has(id)) return; // never on a state this tab did not know
    const now = await loaded();
    if (!editor.dirty) {
      editor = { ...now, dirty: false, sent: null };
      loadedText = now.text;
      return;
    }
    if (broken.noRebase) return;
    const merged = rebaseText(loadedText, editor.sent, editor.text, now.text);
    if (merged === null) return;
    editor = { view: now.view, text: merged, dirty: true, sent: null };
    loadedText = now.text;
  };
  const deliver = async (lose: boolean) => {
    for (const m of messages.splice(0)) if (!lose) await followerReceive(fstore, f, JSON.parse(JSON.stringify(m)));
  };

  try {
    for (const op of ops) {
      switch (op.k) {
        case "type":
          editor = { ...editor, text: remote ? withLine(editor.text, 0, op.text) : op.text, dirty: true };
          typed = op.text;
          break;
        case "pause":
          await pause();
          break;
        case "leader":
          await tick(client);
          rig.server.now++;
          break;
        case "deliver":
          await deliver(op.lose);
          break;
        case "rescan":
          await followerRescan(fstore, f, null);
          break;
        case "load":
          await learn();
          break;
        case "relay":
          client = await leader(); // the old instance is gone; the new one rebuilds from IndexedDB
          break;
        case "remote":
          // Another writer changes line 3 while nothing of this tab is unprocessed (else §20.2 may copy a
          // pause sent on the older view: Decision A), and the tab learns it at once (the state message).
          if (f.unseen.has(id)) break;
          rig.disk.userWrite("a.md", withLine(rig.disk.files.get("a.md")!.content, 2, op.text));
          other = op.text;
          await settle();
          await followerReceive(fstore, f, { kind: "state" } satisfies LeaderMessage); // leadership.ts posts it after a busy tick
          await learn();
          break;
      }
    }
    await pause(); // the editor's unmount flush
    for (let round = 0; round < 5; round++) {
      await settle();
      await deliver(false);
      await followerRescan(fstore, f, null);
    }
    const outcomes = rig.events.filter((e) => e.kind === "intent").map((e) => (JSON.parse(e.detail!) as { outcome: string }).outcome);
    const server = [...rig.server.heads.values()].filter((h) => !h.deleted).map((h) => [h.path, h.content]);
    const disk = [...rig.disk.files].map(([p, x]) => [p, x.content]);
    return { outcomes, server, disk, typed: remote ? `${typed}\n${MID}\n${other}` : typed };
  } finally {
    for (const s of stores) closeVaultStore(s);
  }
}

const singleWriter = (broken: Broken) =>
  fc.asyncProperty(fc.array(opArb, { minLength: 1, maxLength: 40 }), async (ops) => {
    const r = await typing(ops, broken);
    expect(r.outcomes.filter((o) => o !== "APPLY")).toEqual([]); // never a conflict copy of oneself
    expect(r.server).toEqual([["a.md", r.typed]]); // never a lost edit: the last text typed is the note
    expect(r.disk).toEqual([["a.md", r.typed]]);
  });

/** (Q415) The other writer's line 3: empty, the original, a repeat. */
const remoteOpArb: fc.Arbitrary<Op> = fc.oneof(
  { weight: 6, arbitrary: opArb },
  { weight: 2, arbitrary: fc.constantFrom("r", "", "R2", "one").map((text): Op => ({ k: "remote", text })) },
);

const remoteLine = (broken: Broken) =>
  fc.asyncProperty(fc.array(remoteOpArb, { minLength: 1, maxLength: 40 }), async (ops) => {
    const r = await typing(ops, broken, true);
    expect(r.outcomes.filter((o) => o !== "APPLY")).toEqual([]); // never a conflict copy
    expect(r.server).toEqual([["a.md", r.typed]]); // both writers' last lines: nothing lost
    expect(r.disk).toEqual([["a.md", r.typed]]);
  });

describe("(Q414) a single writer typing in one editor", () => {
  it("never makes a conflict copy of its own edits, nor loses one; the code before Q414 is caught", async () => {
    await fc.assert(singleWriter({}), { numRuns: runs(40, 1000) });
    const caught = await fc.check(singleWriter({ forgetsChainOnAck: true }), { numRuns: runs(200, 1000), endOnFailure: true, seed: BROKEN_SEED });
    expect(caught.failed).toBe(true);
    // Caught for the reported reason: the user's own typing became a conflict copy.
    expect((await typing(caught.counterexample![0], { forgetsChainOnAck: true })).outcomes).toContain("CONFLICT_COPY");
  }, 1_800_000);
});

describe("(Q415) a change far from the typed line, arriving while the user types", () => {
  it("is merged into the editor's text (never a conflict copy, nothing lost); the code before Q415 is caught", async () => {
    await fc.assert(remoteLine({}), { numRuns: runs(40, 1000) });
    const caught = await fc.check(remoteLine({ noRebase: true }), { numRuns: runs(200, 1000), endOnFailure: true, seed: BROKEN_SEED });
    expect(caught.failed).toBe(true);
    // Caught for the reported reason: a pause typed on the older view became a conflict copy.
    expect((await typing(caught.counterexample![0], { noRebase: true }, true)).outcomes).toContain("CONFLICT_COPY");
  }, 1_800_000);
});
