import { describe, expect, it } from "vitest";
import { plan } from "../../src/plan.js";
import { type Scenario, build } from "./scenario.js";
import { NO_FAULTS, type World, crash, newFile, observe, rederive, run, tick } from "./simulator.js";

// Deterministic §44.1 cases for file identity, rename pairing and untracked files.

const REAL = { planner: plan };
const obj = (path: string, content: string): Scenario["objects"][number] => ({ path, content, second: null, replica: "head", mod: "none", editContent: "", moveTarget: "moved.md" });
const scenario = (objects: Scenario["objects"], over: Partial<Scenario> = {}): Scenario => ({ objects, localCreates: [], untracked: [], swap: false, merge: false, ...over });
const ID0 = "0190a1b2-0000-7000-8000-000000000000";
const settle = (w: World) => expect(run(w, REAL, 500)).not.toBeNull();
const userMove = (w: World, from: string, to: string) => {
  const f = w.files.get(from)!;
  w.files.delete(from);
  w.files.set(to, f);
  if (f.truth) w.userMoved.add(f.truth);
};
const liveContents = (w: World) => [...w.server.heads.values()].filter((h) => !h.deleted).map((h) => h.content).sort();

describe("§12.2 table: the last observation persists where the file is", () => {
  it("bug (identity simulation (w)): every observation persists where a moved file is, not only an upload snapshot", () => {
    const { world: w } = build(scenario([obj("n.md", "one")]));
    settle(w);
    userMove(w, "n.md", "moved.md");
    w.bound.set(ID0, "moved.md"); // attributed by identity at this tick's observation (rule 10)
    observe(w);
    // Otherwise a later client write at n.md leaves two records claiming it, and after a reload the
    // startup scan gives it to neither: the client's own file is imported as a new object.
    expect(w.recorded.get(ID0)).toMatchObject({ logicalPath: "moved.md", physicalPath: "moved.md" });
  });

  it("bug (identity simulation (w)): the observation that attributes a moved file by identity persists it, planner or not", () => {
    const { world: w } = build(scenario([obj("n.md", "one")]));
    settle(w);
    userMove(w, "n.md", "moved.md");
    rederive(w, REAL); // e.g. a tick that only runs an outbox step
    expect(w.recorded.get(ID0)).toMatchObject({ logicalPath: "moved.md", physicalPath: "moved.md" });
  });

  it("bug (identity simulation (w)): a file the client writes is recorded with its hash (its last observation)", () => {
    const { world: w } = build(scenario([{ ...obj("n.md", "remote"), replica: "unseen" }]));
    for (let i = 0; i < 50 && !w.recorded.has(ID0); i++) tick(w, REAL);
    // Without it, a move before the next observation and a reload leave rule 11 nothing to pair on.
    expect(w.recorded.get(ID0)).toMatchObject({ physicalPath: "n.md", hash: "h:remote" });
  });

  it("bug (identity simulation (w), harness): the built world records the hash of every laid-out file", () => {
    const { world: w } = build(scenario([obj("n.md", "one")]));
    expect(w.recorded.get(ID0)).toMatchObject({ physicalPath: "n.md", hash: "h:one" });
  });

  it("a reload after an observed, not yet uploaded move never re-imports the file", () => {
    const { world: w } = build(scenario([obj("n.md", "one")]));
    settle(w);
    userMove(w, "n.md", "moved.md");
    tick(w, REAL);
    crash(w);
    settle(w);
    expect(w.log.imports).toBe(0);
    expect(liveContents(w)).toEqual(["one"]);
    expect(w.server.heads.get(ID0)?.path).toBe("moved.md");
  });

  it("bug (identity simulation (w)): an observed absence is persisted, so the old path is no longer claimed", () => {
    const { world: w } = build(scenario([obj("n.md", "one")]));
    settle(w);
    w.files.delete("n.md");
    tick(w, REAL);
    // Otherwise, once the client writes another object at n.md, two records claim it and the startup
    // scan after a reload gives it to neither: the client's own file is imported as a new object.
    expect(w.recorded.get(ID0)).toMatchObject({ physicalPath: null, hash: null });
  });
});

describe("§44.1 identity after a restart (rule 11)", () => {
  it("absent object + new file with the exact hash, unique → rename with the same object_id", () => {
    const { world: w } = build(scenario([obj("n.md", "unique content")]));
    settle(w);
    crash(w);
    userMove(w, "n.md", "elsewhere.md"); // moved while the plugin was not running
    settle(w);
    expect(w.log.pairings).toBe(1);
    expect(w.server.heads.get(ID0)?.path).toBe("elsewhere.md");
    expect(liveContents(w)).toEqual(["unique content"]);
  });

  it("ambiguous (a pasted copy with the same bytes) → delete + create, no content lost", () => {
    const { world: w } = build(scenario([obj("n.md", "same bytes")]));
    settle(w);
    crash(w);
    userMove(w, "n.md", "a.md");
    w.files.set("b.md", newFile(w, null, "same bytes", "user"));
    settle(w);
    expect(w.log.pairings).toBe(0);
    expect(w.server.heads.get(ID0)?.deleted).toBe(true);
    expect(liveContents(w)).toEqual(["same bytes", "same bytes"]);
  });

  it("two identical client-written files moved while not running → no pairing; re-created, no content lost, and this is not a spurious object", () => {
    const { world: w } = build(scenario([obj("d/a.md", "same"), obj("d/b.md", "same")]));
    settle(w);
    crash(w);
    userMove(w, "d/a.md", "e/a.md");
    userMove(w, "d/b.md", "e/b.md");
    settle(w);
    expect(w.log.pairings).toBe(0);
    expect(w.log.identityViolations).toEqual([]);
    expect(liveContents(w)).toEqual(["same", "same"]);
    expect([...w.server.heads.values()].filter((h) => !h.deleted).map((h) => h.path).sort()).toEqual(["e/a.md", "e/b.md"]);
  });

  it("a file moved while not running onto another object's recorded path → the startup scan takes it by path; the other file is re-created; no content lost", () => {
    const { world: w } = build(scenario([obj("a.md", "A"), obj("b.md", "B")]));
    settle(w);
    const idB = [...w.server.heads.values()].find((h) => h.content === "B")!.objectId;
    crash(w);
    userMove(w, "a.md", "moved.md");
    userMove(w, "b.md", "a.md");
    settle(w);
    expect(w.log.identityViolations).toEqual([]);
    expect(liveContents(w)).toEqual(["A", "B"]);
    expect(w.server.heads.get(ID0)).toMatchObject({ path: "a.md", content: "B" }); // history lost, never content
    expect(w.server.heads.get(idB)?.deleted).toBe(true);
  });
});

describe("§44.1 delayed events within a running instance (rule 10)", () => {
  it("a file created at the old path after a rename → the renamed object keeps its id; the new file becomes a new object", () => {
    const { world: w } = build(scenario([obj("n.md", "original")]));
    settle(w);
    userMove(w, "n.md", "renamed.md");
    w.files.set("n.md", newFile(w, null, "brand new", "user"));
    settle(w);
    expect(w.server.heads.get(ID0)).toMatchObject({ path: "renamed.md", content: "original" });
    expect(liveContents(w)).toEqual(["brand new", "original"]);
  });

  it("a delete, then another file moved onto that path → the right object is deleted", () => {
    const { world: w } = build(scenario([obj("a.md", "A"), obj("b.md", "B")]));
    settle(w);
    const idB = [...w.server.heads.values()].find((h) => h.content === "B")!.objectId;
    w.files.delete("a.md");
    userMove(w, "b.md", "a.md");
    settle(w);
    expect(w.server.heads.get(ID0)?.deleted).toBe(true);
    expect(w.server.heads.get(idB)).toMatchObject({ path: "a.md", content: "B", deleted: false });
  });
});

describe("§44.1 untracked files", () => {
  it("a remote object projected onto an untracked local file → suffix, nothing overwritten; the file is imported and syncs", () => {
    const { world: w } = build(scenario([obj("n.md", "remote")].map((o) => ({ ...o, replica: "unseen" as const })), { untracked: [{ path: "n.md", content: "mine" }] }));
    settle(w);
    expect(liveContents(w)).toEqual(["mine", "remote"]);
    expect([...w.files.values()].map((f) => f.content).sort()).toEqual(["mine", "remote"]);
  });

  it("renaming to 'Research (Nodra conflict deadbeef).md' with a foreign tag → the logical name keeps the suffix", () => {
    const { world: w } = build(scenario([obj("Research.md", "r")]));
    settle(w);
    userMove(w, "Research.md", "Research (Nodra conflict deadbeef).md");
    settle(w);
    expect(w.server.heads.get(ID0)?.path).toBe("Research (Nodra conflict deadbeef).md");
  });
});
