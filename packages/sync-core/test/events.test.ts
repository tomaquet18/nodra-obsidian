import { describe, expect, it } from "vitest";
import { type RevisionEvent, type SyncEvent, applyEvents, applyVaultState } from "../src/events.js";
import { type ClientFacts, emptyFacts, enqueueUploads, markCommitSent } from "../src/outbox.js";
import { rev } from "./fixtures.js";
import { text, utf8 } from "./utf8.js";

const facts = (over: Partial<ClientFacts> = {}): ClientFacts => ({ ...emptyFacts("vault", "replica-1", "e1"), ...over });
const ev = (sequence: number, objectId: string, over: Partial<RevisionEvent> = {}): RevisionEvent => ({
  kind: "REVISION",
  sequence,
  objectId,
  revisionId: `${objectId}@${sequence}`,
  parentRevisionId: null,
  path: `${objectId}.md`,
  deleted: false,
  createdSequence: sequence,
  mutationId: `m${sequence}`,
  batchIndex: 0,
  batchSize: 1,
  ...over,
});
/** A batch of `size` revisions starting at `first` (one mutation). */
const batch = (first: number, ids: string[]): RevisionEvent[] =>
  ids.map((id, i) => ev(first + i, id, { mutationId: `m${first}`, batchIndex: i, batchSize: ids.length }));

describe("§13.2 / §13.4: applying a page of events", () => {
  it("records every head in R and advances the cursor to the last event", () => {
    const r = applyEvents(facts(), [ev(1, "a"), ...batch(2, ["b", "c"])]);
    expect(r.kind).toBe("APPLIED");
    if (r.kind !== "APPLIED") return;
    expect(r.facts.cursor).toBe(3);
    expect([...r.facts.remote.keys()]).toEqual(["a", "b", "c"]);
    expect(r.facts.remote.get("b")).toEqual(rev("b@2", 2, "b.md", null, false, 2));
  });

  it("the content ref of an event goes to R with the head (null for a delete; absent when the event has none)", () => {
    const r = applyEvents(facts(), [ev(1, "a", { content: { blobId: "blob-a", epochId: "e1" } }), ev(2, "b", { deleted: true, content: null }), ev(3, "c")]);
    if (r.kind !== "APPLIED") throw new Error(r.kind);
    expect(r.facts.remote.get("a")).toEqual({ ...rev("a@1", 1, "a.md", null, false, 1), content: { blobId: "blob-a", epochId: "e1" } });
    expect(r.facts.remote.get("b")?.content).toBeNull();
    expect(r.facts.remote.get("c")).not.toHaveProperty("content");
  });

  it("an empty page changes nothing", () => {
    const f = facts({ cursor: 5 });
    expect(applyEvents(f, [])).toEqual({ kind: "APPLIED", facts: f });
  });

  it("client defence: a page that does not start at cursor + 1 → full reconciliation", () => {
    expect(applyEvents(facts({ cursor: 1 }), [ev(3, "a")])).toEqual({ kind: "RECONCILE" });
  });

  it("client defence: non-contiguous events → full reconciliation", () => {
    expect(applyEvents(facts(), [ev(1, "a"), ev(3, "b")])).toEqual({ kind: "RECONCILE" });
  });

  it("never applies a partial batch: a page cut inside a batch is rejected whole", () => {
    const cut = batch(1, ["a", "b", "c"]).slice(0, 2);
    expect(applyEvents(facts(), cut)).toEqual({ kind: "RECONCILE" });
    const startsInside = batch(1, ["a", "b", "c"]).slice(1);
    expect(applyEvents(facts({ cursor: 1 }), startsInside)).toEqual({ kind: "RECONCILE" });
  });

  it("R never regresses: an event older than the known head is a no-op", () => {
    const f = facts({ cursor: 4, remote: new Map([["a", rev("a@9", 9, "a.md", null)]]) });
    const r = applyEvents(f, [ev(5, "a", { revisionId: "a@5" })]);
    expect(r.kind === "APPLIED" && r.facts.remote.get("a")?.revisionId).toBe("a@9");
  });

  it("an event at or below S's sequence is a no-op (echo of an own commit already processed)", () => {
    const f = facts({ cursor: 4, synced: new Map([["a", rev("a@5", 5, "a.md", "h")]]) });
    const r = applyEvents(f, [ev(5, "a")]);
    expect(r.kind === "APPLIED" && r.facts.remote.has("a")).toBe(false);
  });

  it("the echo of an own in-flight entry equals COMMITTED for that entry (§13.4)", () => {
    let f = enqueueUploads(
      facts(),
      [{ objectId: "a", expectedHeadRevisionId: null, path: "a.md", deleted: false, localCompareHash: "h", plaintext: utf8("x"), newBlobBytes: 1 }],
      { pendingBudgetBytes: 100 },
      ["mut", "rev-a"],
    );
    f = markCommitSent(f, "mut");
    const r = applyEvents(f, [ev(1, "a", { revisionId: "rev-a", mutationId: "mut" })]);
    expect(r.kind).toBe("APPLIED");
    if (r.kind !== "APPLIED") return;
    expect(r.facts.outbox).toEqual([]);
    expect(r.facts.synced.get("a")).toEqual(rev("rev-a", 1, "a.md", "h", false, 1));
  });

  it("an EPOCH_ROTATED event updates the known write epoch", () => {
    const e: SyncEvent = { kind: "EPOCH_ROTATED", sequence: 1, epochId: "e2", batchIndex: 0, batchSize: 1 };
    const r = applyEvents(facts(), [e]);
    expect(r.kind === "APPLIED" && r.facts.epochId).toBe("e2");
  });

  it("a SECURITY event (§37) only moves the cursor: every other fact is the one before", () => {
    const before = facts();
    const e: SyncEvent = { kind: "SECURITY", sequence: 1, securityEventId: 7, batchIndex: 0, batchSize: 1 };
    const r = applyEvents(before, [e]);
    expect(r).toEqual({ kind: "APPLIED", facts: { ...before, cursor: 1 } });
  });

  it("a SECURITY event still counts in the page's sequence: one after a gap reconciles (§13.2)", () => {
    const e: SyncEvent = { kind: "SECURITY", sequence: 2, securityEventId: 7, batchIndex: 0, batchSize: 1 };
    expect(applyEvents(facts(), [e]).kind).toBe("RECONCILE");
  });
});

describe("§18.4 full reconciliation", () => {
  it("R takes the state's heads (graveyard included) without regressing, and the cursor becomes N", () => {
    const f = facts({ cursor: 3, remote: new Map([["b", rev("b@20", 20, "b.md", null)]]) });
    const r = applyVaultState(f, {
      sequence: 12,
      epochId: "e3",
      heads: [
        { objectId: "a", head: rev("a@10", 10, "a.md", null) },
        { objectId: "b", head: rev("b@11", 11, "b.md", null) },
        { objectId: "c", head: rev("c@12", 12, "c.md", null, true) },
      ],
    });
    expect(r.cursor).toBe(12);
    expect(r.epochId).toBe("e3");
    expect(r.remote.get("a")?.revisionId).toBe("a@10");
    expect(r.remote.get("b")?.revisionId).toBe("b@20");
    expect(r.remote.get("c")?.deleted).toBe(true);
  });

  it("refuses to run while the outbox is not settled (§18.4 step 1 comes first)", () => {
    const f = enqueueUploads(
      facts(),
      [{ objectId: "a", expectedHeadRevisionId: null, path: "a.md", deleted: false, localCompareHash: "h", plaintext: utf8("x"), newBlobBytes: 1 }],
      { pendingBudgetBytes: 100 },
      ["mut", "rev-a"],
    );
    expect(() => applyVaultState(markCommitSent(f, "mut"), { sequence: 1, epochId: "e1", heads: [] })).toThrow();
  });
});
