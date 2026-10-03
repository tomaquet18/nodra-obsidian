import { describe, expect, it } from "vitest";
import type { Scenario } from "@nodra/sync-core/test-support/scenario";
import { QUIET, lostEdits, runToRest, startRun } from "./sim/e2e.js";
import { SPEC_WINDOWS, replaceWindow, temporaryRemoveWindow } from "./sim/windows.js";

// Deterministic cases of the only exemptions (windows.ts): each happens, is a violation without its
// rule, and is accepted with it. Removes of user files have no window (see executor.test.ts, Q60).

const remoteEdit = (): Scenario => ({
  objects: [{ path: "a.md", content: "one", second: { path: "a.md", content: "two", deleted: false }, replica: "rev1", mod: "none", editContent: "", moveTarget: "moved.md" }],
  localCreates: [],
  untracked: [],
  swap: false,
  merge: false,
});

async function replaceRace(rule?: typeof SPEC_WINDOWS) {
  const run = await startRun(remoteEdit(), QUIET, 5, {}, rule);
  // The user edits a.md right before the client replaces it (after the final re-check).
  const before = run.disk.beforeOp;
  run.disk.beforeOp = (op, path) => {
    before?.(op, path);
    if (op === "replace" && run.disk.files.has("a.md")) run.disk.files.get("a.md")!.content = "user in the window";
    if (op === "replace") run.log.userContents.set(String(run.disk.files.get("a.md")!.id), "user in the window");
  };
  await runToRest(run, 200);
  run.close();
  return run;
}

async function temporaryRace(rule?: typeof SPEC_WINDOWS) {
  const run = await startRun(remoteEdit(), QUIET, 5, {}, rule);
  // The user deletes a.md while its temporary is written, so the replace is cancelled; then the user
  // edits the temporary right before the client removes it (after the client's re-read).
  const before = run.disk.beforeOp;
  run.disk.beforeOp = (op, path) => {
    const target = run.disk.files.get("a.md");
    if (op === "write" && path.includes("nodra-tmp-") && target && target.content === "one") target.content = "user edit";
    if (op === "remove" && path.includes("nodra-tmp-") && run.disk.files.has(path)) {
      const f = run.disk.files.get(path)!;
      f.content = "user wrote the temporary";
      run.log.userContents.set(String(f.id), f.content);
    }
    before?.(op, path); // the oracle runs after the user acted
  };
  await runToRest(run, 200);
  run.close();
  return run;
}

describe("the §13.4 replace window (§44.5), applying remote content", () => {
  it("is a violation without the rule", async () => {
    const run = await replaceRace();
    expect(run.log.violations.some((v) => v.startsWith("replace-destroyed"))).toBe(true);
  }, 60_000);

  it("is accepted with the rule, and only it", async () => {
    const run = await replaceRace(replaceWindow);
    expect(run.log.violations).toEqual([]);
    expect(lostEdits(run)).toEqual([]);
    expect(run.log.replaceWindow).toBe(1);
  }, 60_000);
});

describe("the §15 re-read window when deleting an own temporary", () => {
  it("is a violation without the rule", async () => {
    const run = await temporaryRace();
    expect(run.log.violations.some((v) => v.startsWith("remove-destroyed") && v.includes("nodra-tmp-"))).toBe(true);
  }, 60_000);

  it("is accepted with the rule", async () => {
    const run = await temporaryRace(temporaryRemoveWindow);
    expect(run.log.violations).toEqual([]);
    expect(lostEdits(run)).toEqual([]);
  }, 60_000);
});
