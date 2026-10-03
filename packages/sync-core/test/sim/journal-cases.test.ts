import { describe, expect, it } from "vitest";
import { tmpPath } from "../../src/journal.js";
import { plan } from "../../src/plan.js";
import { type Scenario, build } from "./scenario.js";
import { type CrashPointName, type World, newFile, run, tick } from "./simulator.js";

// Deterministic §44.1 cases for the apply journal (§15), with crashes forced at named points.

const NL = String.fromCharCode(10);
const REAL = { planner: plan };
const obj = (over: Partial<Scenario["objects"][number]> = {}): Scenario["objects"][number] => ({
  path: "n.md",
  content: ["a", "b", "c", "d", "e"].join(NL),
  second: null,
  replica: "rev1",
  mod: "none",
  editContent: "",
  moveTarget: "moved.md",
  ...over,
});
const scenario = (objects: Scenario["objects"], over: Partial<Scenario> = {}): Scenario => ({
  objects,
  localCreates: [],
  untracked: [],
  swap: false,
  merge: false,
  ...over,
});
/** A synced object whose remote content changed: the client applies it in place (a journaled WRITE). */
const remoteEdit = (content = "remote content, fairly long") => scenario([obj({ second: { path: "n.md", content, deleted: false } })]);

/** Ticks until an entry is left open by a forced crash. */
function untilOpenEntry(w: World, crashAt: CrashPointName): void {
  w.forcedCrashes.add(crashAt);
  for (let i = 0; i < 200 && w.journal === null; i++) tick(w, REAL);
  expect(w.journal, `no entry left open at ${crashAt}`).not.toBeNull();
}

const files = (w: World) => [...w.files].map(([p, f]) => ({ p, owner: f.owner, content: f.content }));

describe("§44.1 apply journal: crash in every step of a write", () => {
  it("merge that resolves, crash after the replace → replay completes (S := R); no second merge, no copy", () => {
    const { world: w } = build(scenario([obj()], { merge: true }));
    untilOpenEntry(w, "replaced");
    expect(w.log.merges).toBe(1);
    expect(run(w, REAL, 500)).not.toBeNull();
    expect(w.log.journalReplays).toBe(1);
    expect(w.log.merges).toBe(1);
    expect(w.log.conflictCopies).toBe(0);
    const head = [...w.server.heads.values()][0]!;
    expect(head.content).toBe(["A", "b", "c", "d", "E"].join(NL));
  });

  it("crash after the temporary is complete but before tmp_created → exact content: deleted, no recovery note", () => {
    const { world: w } = build(remoteEdit());
    untilOpenEntry(w, "tmpWritten");
    expect(w.journal?.tmpCreated).toBe(false);
    expect(run(w, REAL, 500)).not.toBeNull();
    expect(w.log.deletions.filter((d) => d.reason === "tmp").map((d) => d.content)).toEqual(["remote content, fairly long"]);
    expect(w.recoveryNotes.size).toBe(0);
    expect(files(w).map((f) => f.content)).toEqual(["remote content, fairly long"]);
  });

  it("crash mid-write of the temporary (prefix, no tmp_created) → kept as a recovery note (the prefix proof needs tmp_created)", () => {
    const { world: w } = build(remoteEdit(), undefined, 7);
    untilOpenEntry(w, "tmpPartial");
    const partial = w.files.get(tmpPath(w.journal!))!.content;
    expect(run(w, REAL, 500)).not.toBeNull();
    if (partial.length === 0) {
      expect(w.recoveryNotes.size).toBe(0); // zero bytes: always deleted, never an empty note
    } else {
      expect([...w.recoveryNotes.values()]).toEqual([{ provable: false, content: partial }]);
    }
    expect(files(w).some((f) => f.content === "remote content, fairly long")).toBe(true);
  });

  it("the user edits the temporary before the cancel → kept as a recovery note with the user's line", () => {
    const { world: w } = build(remoteEdit());
    untilOpenEntry(w, "tmpCreated");
    const tp = tmpPath(w.journal!);
    w.files.get(tp)!.content += `${NL}user line`;
    // The destination changed too, so the replay cannot complete: it cancels.
    run(w, REAL, 500);
    expect([...w.recoveryNotes.values()].map((n) => n.content)).toEqual([`remote content, fairly long${NL}user line`]);
    expect(w.log.deletions.filter((d) => d.reason === "tmp")).toEqual([]);
  });

  it("a user file named nodra-tmp-* holding a prefix of the entry's content → not deleted: imported as a recovery note", () => {
    const { world: w } = build(remoteEdit());
    untilOpenEntry(w, "opened");
    const tp = tmpPath(w.journal!);
    w.files.set(tp, newFile(w, null, "remote con", "user"));
    run(w, REAL, 500);
    expect([...w.recoveryNotes.values()]).toEqual([{ provable: false, content: "remote con" }]);
  });

  it("a zero-byte temporary (the content never arrived) → always deleted, never an empty recovery note", () => {
    const { world: w } = build(remoteEdit());
    untilOpenEntry(w, "opened");
    w.files.set(tmpPath(w.journal!), newFile(w, null, "", "user"));
    run(w, REAL, 500);
    expect(w.recoveryNotes.size).toBe(0);
    expect(w.log.deletions.filter((d) => d.reason === "tmp").map((d) => d.content)).toEqual([""]);
  });

  it("the user edits the destination during the apply → no overwrite; the user's content is kept and uploaded", () => {
    const { world: w } = build(remoteEdit());
    untilOpenEntry(w, "tmpCreated");
    const dest = w.journal!.destPath;
    w.files.get(dest)!.content = "user wins the race";
    run(w, REAL, 500);
    const all = [...w.files.values()].map((f) => f.content).concat([...w.server.revisions.values()].map((r) => r.content));
    expect(all).toContain("user wins the race");
  });
});

describe("§16.7 rule 4: the destination is re-checked right before the operation", () => {
  it("bug (multi-replica simulation): a folder that appears at the destination after planning → no overwrite, re-plan", () => {
    const { world: w } = build(scenario([obj({ path: "a.md", content: "a", second: { path: "foo", content: "a", deleted: false } })]));
    // Right after the projection move a.md → foo is journaled, the user creates Foo/x.md.
    let fired = false;
    w.betweenStepsHook = (x) => {
      if (fired || x.journal?.kind !== "RENAME" || x.journal.destPath !== "foo") return;
      fired = true;
      x.files.set("Foo/x.md", newFile(x, null, "user folder", "user"));
    };
    expect(() => run(w, REAL, 500)).not.toThrow();
    expect(fired).toBe(true);
    expect(w.files.get("Foo/x.md")?.content).toBe("user folder");
    expect([...w.files.values()].map((f) => f.content).sort()).toEqual(["a", "user folder"]);
  });
});

describe("§44.1 renames of the projection and parking", () => {
  it("cycle of renames, crash after parking in nodra-tmp-* → the parked file stays bound to its object and reaches its path", () => {
    const { world: w } = build(
      scenario([obj({ path: "d/1.md", content: "one" }), obj({ path: "d/2.md", content: "two" })], { swap: true }),
    );
    w.forcedCrashes.add("renamed");
    for (let i = 0; i < 300 && !(w.journal?.kind === "RENAME" && w.journal.destPath.includes("nodra-tmp-")); i++) tick(w, REAL);
    expect(w.journal?.destPath).toMatch(/nodra-tmp-/);
    expect(run(w, REAL, 500)).not.toBeNull();
    expect(w.recoveryNotes.size).toBe(0); // the parked file was never taken for a stray temporary
    expect(w.log.pathMisreads).toEqual([]);
    const byContent = Object.fromEntries(files(w).map((f) => [f.content, f.p]));
    expect(byContent).toEqual({ one: "d/2.md", two: "d/1.md" });
  });
});
