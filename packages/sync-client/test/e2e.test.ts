import fc from "fast-check";
import { describe, expect, it } from "vitest";
import type { IntentChange } from "@nodra/sync-core";
import { type Scenario, scenarioArb } from "@nodra/sync-core/test-support/scenario";
import { ATTACHMENT_FAULTS, type E2EFaults, PROPERTY_FAULTS, QUIET, type SentIntent, chainedContent, convergenceProblems, e2eSpecArb, intentDelivery, lostEdits, runToRest, startRun } from "./sim/e2e.js";
import { SPEC_WINDOWS } from "./sim/windows.js";
import { utf8 } from "./support/bytes.js";

// A few seeded end-to-end runs in the fast suite; the long runs are in test/sim (pnpm test:sim).

const obj = (path: string, content: string, over: Partial<Scenario["objects"][number]> = {}): Scenario["objects"][number] => ({
  path,
  content,
  second: null,
  replica: "head",
  mod: "none",
  editContent: "",
  moveTarget: "moved.md",
  ...over,
});
const scenario = (objects: Scenario["objects"], over: Partial<Scenario> = {}): Scenario => ({ objects, localCreates: [], untracked: [], swap: false, merge: false, ...over });

export const FAULTY: E2EFaults = {
  drop: 0.05,
  lose: 0.05,
  crash: 0.3,
  putTimeout: 0.02,
  reload: 0.03,
  fileCrash: 0.03,
  user: 0.04,
  remoteWrite: 0.03,
  rotateEpoch: 0.01,
  prune: 0.01,
  expireRows: 0.01,
  handover: 0.01,
  staleTick: 0.3,
  followerEdit: 0.1,
  followerRefresh: 0.2,
  binary: 0,
  activeUntil: 80,
};

const OK = { ticks: expect.any(Number), convergence: [], lost: [], violations: [], writeAhead: [], staleWrites: [], intents: [], unknownStateApplies: [] };

async function check(s: Scenario, faults: E2EFaults, seed: number, maxTicks = 1500) {
  const run = await startRun(s, faults, seed, {}, SPEC_WINDOWS);
  const ticks = await runToRest(run, maxTicks);
  const report = {
    ticks,
    convergence: convergenceProblems(run),
    lost: lostEdits(run),
    violations: run.log.violations,
    writeAhead: run.writeAheadViolations(),
    staleWrites: run.log.staleWrites,
    intents: await intentDelivery(run),
    unknownStateApplies: run.log.unknownStateApplies,
  };
  run.close();
  return { run, report };
}

describe("end to end: runner + Dexie + in-memory disk + server model", () => {
  it("quiet: a remote edit, an unseen object, a local edit, a local delete and an untracked file converge", async () => {
    const s = scenario(
      [
        obj("a.md", "one", { second: { path: "a.md", content: "two", deleted: false }, replica: "rev1" }),
        obj("b.md", "bee", { replica: "unseen" }),
        obj("c.md", "sea", { mod: "edit", editContent: "local" }),
        obj("d/e.md", "dee", { mod: "delete" }),
      ],
      { untracked: [{ path: "mine.md", content: "user file" }] },
    );
    const { run, report } = await check(s, QUIET, 1);
    expect(report).toEqual(OK);
    expect([...run.disk.files.keys()].sort()).toEqual(["a.md", "b.md", "c.md", "mine.md"]);
  }, 60_000);

  it("a local rename and a remote rename of different files, then a crash in the middle of each operation", async () => {
    const s = scenario([obj("a.md", "A", { mod: "move", moveTarget: "moved.md" }), obj("b.md", "B", { second: { path: "sub/b.md", content: "B", deleted: false }, replica: "rev1" })]);
    for (const seed of [2, 3, 4]) {
      const { report } = await check(s, { ...QUIET, fileCrash: 0.3, activeUntil: 40 }, seed);
      expect(report, `seed ${seed}`).toEqual(OK);
    }
  }, 60_000);

  it("seeded fault runs over generated scenarios", async () => {
    await fc.assert(
      fc.asyncProperty(scenarioArb, fc.integer(), async (s, seed) => {
        const { report } = await check(s, FAULTY, seed);
        expect(report).toEqual(OK);
      }),
      { numRuns: 3, seed: 20260921 },
    );
  }, 120_000);

  // Question 75: property runs (fc.sample of the property's arbitrary, seed 11) that failed for reasons
  // other than the intent replace window. 22 and 115: a file moving into a folder named like itself
  // (Q74/Q75, the physical plan); 66: E3 missed the follower's chain through a PATH intent (the oracle).
  it.each([22, 66, 115])("bug (Q75): property run %i of seed 11", async (index) => {
    const spec = fc.sample(e2eSpecArb, { seed: 11, numRuns: index + 1 })[index]!;
    const { report } = await check(spec.scenario, PROPERTY_FAULTS, spec.seed, 2500);
    expect(report).toEqual(OK);
  }, 120_000);
});

describe("bug (Q352): an empty file under a recovery-note name is the user's, never deleted (§15, §44.5)", () => {
  // The sim property (E2) found it (seed -501602904, path below): the user moved a recovery note away and
  // created an empty file under its old name. The runner took that unimported `nodra-recuperado-*.md` for
  // a stray, parked it under a `nodra-tmp-*` name because it was empty, and the next observation deleted
  // the empty temporary. Nodra never makes an empty recovery note (§15), so such a file is always the user's.
  it("quiet: the empty file is imported and uploaded, and stays on disk", async () => {
    const note = "nodra-recuperado-90710952.md";
    const { run, report } = await check(scenario([], { untracked: [{ path: note, content: "" }] }), QUIET, 1);
    expect(report).toEqual(OK);
    expect(run.disk.files.get(note)?.content).toBe("");
    expect([...run.server.heads.values()].filter((h) => !h.deleted).map((h) => [h.path, h.content])).toEqual([[note, ""]]);
  }, 60_000);

  it("the (E2) property counterexample replays clean", async () => {
    await fc.assert(
      fc.asyncProperty(e2eSpecArb, async (spec) => {
        const run = await startRun(spec.scenario, ATTACHMENT_FAULTS, spec.seed, {}, SPEC_WINDOWS, spec.seed % 2 === 0 ? "coarse" : "counter");
        try {
          expect(await runToRest(run, 2500)).not.toBeNull();
          expect(lostEdits(run)).toEqual([]);
        } finally {
          run.close();
        }
      }),
      { seed: -501602904, path: "4:2:3:2:3:4:4:4:10:11:11:12:12:12:12:12:12:14:13:13:46", endOnFailure: true },
    );
  }, 120_000);
});

describe("(E3) the result of a follower's own chain (chainedContent)", () => {
  const chain = (...changes: IntentChange[]) => {
    const sent = new Map<string, SentIntent>();
    changes.forEach((change, i) => {
      const intentId = `i${i + 1}`;
      const intent = { intentId, contextId: "ctx", intentSeq: i + 1, objectId: "o", viewVersion: 0, viewFp: null, afterIntentId: i === 0 ? null : `i${i}`, change };
      sent.set(intentId, { intent, seenFp: null } as unknown as SentIntent);
    });
    return sent;
  };
  const content = (c: string): IntentChange => ({ kind: "CONTENT", path: "a.md", content: utf8(c) });
  const path: IntentChange = { kind: "PATH", path: "b.md", content: null };

  it("bug (Q75, run 66): a PATH intent keeps the content of the chain before it", () => {
    expect(chainedContent(chain(content("A"), path), "i2")).toBe("A");
  });

  it("only the latest content of the chain counts, never an older one", () => {
    expect(chainedContent(chain(content("A"), content("B")), "i2")).toBe("B");
    expect(chainedContent(chain(content("A"), content("B"), path, path), "i4")).toBe("B");
  });

  it("after a DELETE the chain left no content; a chain of PATH intents only leaves what the follower saw", () => {
    expect(chainedContent(chain(content("A"), { kind: "DELETE", path: "a.md", content: null }), "i2")).toBeNull();
    expect(chainedContent(chain(path, path), "i2")).toBeUndefined();
    expect(chainedContent(chain(content("A")), null)).toBeUndefined();
  });
});
