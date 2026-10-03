import { describe, expect, it } from "vitest";
import { planRenames } from "../src/rename-plan.js";
import { planInput, simulate } from "./helpers.js";

const cur = (entries: Array<[string, string]>) => new Map(entries);
const des = (entries: Array<[string, string | null]>) => new Map(entries);

describe("§16.7 physical rename plan (Annex B.1 Plan de renames)", () => {
  it("a rename whose target is free", () => {
    const i = planInput({ current: cur([["a", "x.md"]]), desired: des([["a", "y.md"]]) });
    expect(planRenames(i).actions).toEqual([{ kind: "rename", objectId: "a", from: "x.md", to: "y.md" }]);
  });

  it("a chain runs in dependency order without overwriting", () => {
    const i = planInput({
      current: cur([
        ["a", "1.md"],
        ["b", "2.md"],
      ]),
      desired: des([
        ["a", "2.md"],
        ["b", "3.md"],
      ]),
    });
    const plan = planRenames(i);
    expect(plan.actions.map((a) => a.objectId)).toEqual(["b", "a"]);
    expect(simulate(i, plan.actions)).toEqual(
      new Map([
        ["a", "2.md"],
        ["b", "3.md"],
      ]),
    );
  });

  it("swap of two files is broken by parking one under nodra-tmp-<8 hex> in its folder", () => {
    const i = planInput({
      current: cur([
        ["a", "d/1.md"],
        ["b", "d/2.md"],
      ]),
      desired: des([
        ["a", "d/2.md"],
        ["b", "d/1.md"],
      ]),
    });
    const plan = planRenames(i);
    expect(plan.actions[0]).toEqual({ kind: "rename", objectId: "a", from: "d/1.md", to: "d/nodra-tmp-00000001" });
    expect(simulate(i, plan.actions)).toEqual(
      new Map([
        ["a", "d/2.md"],
        ["b", "d/1.md"],
      ]),
    );
    expect(plan.blocked).toEqual([]);
  });

  it("three-cycle plus a chain, no overwrite, one parking", () => {
    const i = planInput({
      current: cur([
        ["a", "1.md"],
        ["b", "2.md"],
        ["c", "3.md"],
        ["d", "4.md"],
      ]),
      desired: des([
        ["a", "2.md"],
        ["b", "3.md"],
        ["c", "1.md"],
        ["d", "5.md"],
      ]),
    });
    const plan = planRenames(i);
    expect(simulate(i, plan.actions)).toEqual(
      new Map([
        ["a", "2.md"],
        ["b", "3.md"],
        ["c", "1.md"],
        ["d", "5.md"],
      ]),
    );
    expect(plan.actions.filter((a) => a.kind === "rename" && a.to.includes("nodra-tmp-"))).toHaveLength(1);
  });

  it("bug (sync-core simulation): a cycle through a folder is broken by parking outside that folder", () => {
    // a leaves Foo/ for n.md; b wants the file name "foo", blocked by the folder Foo/ that holds a.
    const i = planInput({
      current: cur([
        ["a", "Foo/y.md"],
        ["b", "n.md"],
      ]),
      desired: des([
        ["a", "n.md"],
        ["b", "foo"],
      ]),
    });
    const plan = planRenames(i);
    expect(plan.blocked).toEqual([]);
    expect(simulate(i, plan.actions)).toEqual(
      new Map([
        ["a", "n.md"],
        ["b", "foo"],
      ]),
    );
  });

  it("bug (Q74): a file moving onto the name of its own parent folder is parked outside that folder first", () => {
    // `Foo/y.md` to `foo`: the folder `Foo/` that holds the file blocks its own target, so a direct
    // rename is impossible (the executor's re-check cancelled it forever). Park at the root, then move.
    const i = planInput({ current: cur([["a", "Foo/y.md"]]), desired: des([["a", "foo"]]) });
    const plan = planRenames(i);
    expect(plan).toEqual({
      actions: [
        { kind: "rename", objectId: "a", from: "Foo/y.md", to: "nodra-tmp-00000001" },
        { kind: "rename", objectId: "a", from: "nodra-tmp-00000001", to: "foo" },
      ],
      blocked: [],
    });
    expect(simulate(i, plan.actions)).toEqual(new Map([["a", "foo"]]));
  });

  it("bug (Q75): a file moving into a folder with its own name is parked first", () => {
    // `d/g` to `d/G/f.md`: the folder `d/G/` cannot be created while the file `d/g` exists.
    const i = planInput({ current: cur([["a", "d/g"]]), desired: des([["a", "d/G/f.md"]]) });
    const plan = planRenames(i);
    expect(plan).toEqual({
      actions: [
        { kind: "rename", objectId: "a", from: "d/g", to: "d/nodra-tmp-00000001" },
        { kind: "rename", objectId: "a", from: "d/nodra-tmp-00000001", to: "d/G/f.md" },
      ],
      blocked: [],
    });
    expect(simulate(i, plan.actions)).toEqual(new Map([["a", "d/G/f.md"]]));
  });

  it("a self-blocked move with no tmp name available stays blocked", () => {
    const i = planInput({ current: cur([["a", "g"]]), desired: des([["a", "g/f.md"]]), tmpHex: [] });
    expect(planRenames(i)).toEqual({ actions: [], blocked: ["a"] });
  });

  it("the simulator rejects a self-blocked rename", () => {
    // The oracle of these tests must be able to fail on the Q74/Q75 shape.
    const i = planInput({ current: cur([["a", "g"]]), desired: des([["a", "g/f.md"]]) });
    expect(() => simulate(i, [{ kind: "rename", objectId: "a", from: "g", to: "g/f.md" }])).toThrow(/self-blocked/);
    const j = planInput({ current: cur([["a", "Foo/y.md"]]), desired: des([["a", "foo"]]) });
    expect(() => simulate(j, [{ kind: "rename", objectId: "a", from: "Foo/y.md", to: "foo" }])).toThrow(/self-blocked/);
  });

  it("after a crash while parked, the parked file (bound to its object) goes to its projected path", () => {
    const i = planInput({
      current: cur([
        ["a", "nodra-tmp-00000001"],
        ["b", "1.md"],
      ]),
      desired: des([
        ["a", "2.md"],
        ["b", "1.md"],
      ]),
    });
    expect(planRenames(i).actions).toEqual([
      { kind: "rename", objectId: "a", from: "nodra-tmp-00000001", to: "2.md" },
    ]);
  });

  it("an existing nodra-tmp-* name anywhere in the vault is never reused", () => {
    const i = planInput({
      current: cur([
        ["a", "d/1.md"],
        ["b", "d/2.md"],
      ]),
      desired: des([
        ["a", "d/2.md"],
        ["b", "d/1.md"],
      ]),
      untrackedFiles: ["other/NODRA-TMP-00000001"],
    });
    const plan = planRenames(i);
    expect(plan.actions[0]).toMatchObject({ to: "d/nodra-tmp-00000002" });
    simulate(i, plan.actions);
  });

  it("with no tmp name available the cycle stays blocked and nothing is overwritten", () => {
    const i = planInput({
      current: cur([
        ["a", "1.md"],
        ["b", "2.md"],
      ]),
      desired: des([
        ["a", "2.md"],
        ["b", "1.md"],
      ]),
      tmpHex: [],
    });
    expect(planRenames(i)).toEqual({ actions: [], blocked: ["a", "b"] });
  });

  it("an untracked file blocks the target: no rename and no parking", () => {
    const i = planInput({ current: cur([["a", "1.md"]]), desired: des([["a", "2.md"]]), untrackedFiles: ["2.md"] });
    expect(planRenames(i)).toEqual({ actions: [], blocked: ["a"] });
  });

  it("hierarchical block: a file cannot land where a folder with files exists", () => {
    const i = planInput({ current: cur([["a", "x.md"]]), desired: des([["a", "foo"]]), untrackedFiles: ["foo/z.md"] });
    expect(planRenames(i).blocked).toEqual(["a"]);
  });

  it("a case-only rename is allowed (the target is occupied only by the file itself)", () => {
    const i = planInput({ current: cur([["a", "Notes.md"]]), desired: des([["a", "notes.md"]]) });
    expect(planRenames(i).actions).toEqual([{ kind: "rename", objectId: "a", from: "Notes.md", to: "notes.md" }]);
  });

  it("an object not on disk is created at its projected path", () => {
    const i = planInput({ desired: des([["a", "n.md"]]) });
    expect(planRenames(i).actions).toEqual([{ kind: "create", objectId: "a", to: "n.md" }]);
  });

  it("an in-flight object gets no physical action and its file keeps blocking", () => {
    const i = planInput({
      current: cur([
        ["a", "1.md"],
        ["b", "2.md"],
      ]),
      desired: des([
        ["a", "3.md"],
        ["b", "1.md"],
      ]),
      inFlight: new Set(["a"]),
    });
    expect(planRenames(i)).toEqual({ actions: [], blocked: ["b"] });
  });

  it("NOT_MATERIALIZED with nothing pending leaves the disk; with something pending it stays", () => {
    const i = planInput({
      current: cur([
        ["a", "1.md"],
        ["b", "2.md"],
      ]),
      desired: des([
        ["a", null],
        ["b", null],
      ]),
      pending: new Set(["b"]),
    });
    expect(planRenames(i).actions).toEqual([{ kind: "remove", objectId: "a", from: "1.md" }]);
  });
});
