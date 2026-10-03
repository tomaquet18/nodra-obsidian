import { remoteCommit } from "@nodra/sync-core/test-support/server";
import { describe, expect, it } from "vitest";
import { SyncBackendError } from "../src/http-backend.js";
import { type PrepareUploadInput, type SyncBackend, UPLOAD_TIMEOUT } from "../src/ports.js";
import { describeError, isPersistentError, noticeFor } from "../src/controller.js";
import { CapabilityError } from "../src/capability.js";
import { DirectoryError } from "../src/directory.js";
import { SessionError } from "../src/session.js";
import { needsReenrollment, reactionTo } from "../src/retry.js";
import { type Client, releaseHolds, retryAt, tick } from "../src/runner.js";
import { closeVaultStore, loadVault, openVaultStore, takeLeadership } from "../src/store.js";
import { tabsRig } from "./support/tabs.js";

// The client's reaction to each server answer (§11.1–§11.3, §12.6, §13.3, §18.3; retry.ts). One client
// uploads a local file over the server model while a scripted refusal answers one operation. The loop
// ticks once per simulated second, more often than the controller would (it sleeps until the hold ends),
// so a bounded request count proves the runner itself waits: no hot loop, whatever drives it.

type Op = keyof SyncBackend;
/** What the refused operation answers instead of the server: an error to throw, or a value to return. */
type Refusal = { readonly throws: unknown } | { readonly returns: unknown };

const backendError = (code: string, status?: number, retryAfterSeconds?: number) => new SyncBackendError(code, status, retryAfterSeconds);
const timeout = () => Object.assign(new Error("PUT timed out"), { name: UPLOAD_TIMEOUT });

/** A scripted refusal: `n` counts the calls of its operation (from 1); `args` are the call's own. */
type Refuse = (n: number, ...args: never[]) => Refusal | null;

async function setup(o: { refuse?: Partial<Record<Op, Refuse>>; ignoreHolds?: boolean } = {}) {
  const rig = await tabsRig();
  rig.disk.userWrite("a.md", "one");
  const store = await rig.open();
  const base = await rig.client(store, await takeLeadership(store));
  const calls: Array<{ op: Op; at: number }> = [];
  const refuse: Partial<Record<Op, Refuse | null>> = { ...o.refuse };
  const backend = Object.fromEntries(
    (Object.keys(base.backend) as Op[]).map((op) => [
      op,
      async (...args: unknown[]) => {
        calls.push({ op, at: rig.server.now });
        const r = (refuse[op] as ((n: number, ...a: unknown[]) => Refusal | null) | null | undefined)?.(calls.filter((x) => x.op === op).length, ...args) ?? null;
        if (r !== null && "throws" in r) throw r.throws;
        if (r !== null) return r.returns;
        return (base.backend[op] as (...a: unknown[]) => Promise<unknown>)(...args);
      },
    ]),
  ) as unknown as SyncBackend;
  let c: Client = { ...base, backend };
  /** `seconds` ticks, one per simulated second. A broken client that ignores holds forgets them after each tick. */
  const run = async (seconds: number) => {
    for (let i = 0; i < seconds; i++) {
      await tick(c);
      if (o.ignoreHolds) c.memory.holds = { all: null, writes: null, nonDeletes: null };
      rig.server.now++;
    }
  };
  /** Ticks until nothing is left to do or retry (null at the bound). */
  const settle = async (max = 2000) => {
    for (let i = 0; i < max; i++) {
      const busy = await tick(c);
      rig.server.now++;
      if (!busy && retryAt(c) === null) return i;
    }
    return null;
  };
  const count = (op: Op, from = -Infinity, to = Infinity) => calls.filter((x) => x.op === op && x.at >= from && x.at < to).length;
  const uploaded = () => [...rig.server.heads.values()].some((h) => h.path === "a.md" && h.content === "one" && !h.deleted);
  const kinds = (kind: string) => rig.events.filter((e) => e.kind === kind).map((e) => e.detail);
  let db = store;
  /** A crash and a new instance (§12.2): memory is lost (holds included), the facts are loaded again. */
  const restart = async () => {
    closeVaultStore(db);
    db = await openVaultStore({ installNs: "plugin:tabs", vaultId: "vault-1", ...rig.idb });
    c = { ...(await rig.client(db, await takeLeadership(db))), backend };
    t.c = c;
  };
  const t = { rig, store, c, calls, refuse, run, settle, count, uploaded, kinds, restart, close: () => closeVaultStore(db) };
  return t;
}

describe("the backoff policy (retry.ts)", () => {
  it("doubles from the base up to the cap; a server-given wait is honoured (at least one second)", () => {
    const delays = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((n) => reactionTo({ code: "RATE_LIMITED" }, n));
    expect(delays.map((r) => (r.kind === "hold" ? r.delaySeconds : null))).toEqual([2, 4, 8, 16, 32, 64, 128, 256, 300, 300]);
    expect(reactionTo({ code: "UPLOAD_IN_PROGRESS", retryAfterSeconds: 45 }, 1)).toEqual({ kind: "hold", scope: "writes", code: "UPLOAD_IN_PROGRESS", delaySeconds: 45 });
    expect(reactionTo({ code: "UPLOAD_IN_PROGRESS", retryAfterSeconds: 0 }, 1)).toMatchObject({ delaySeconds: 1 });
    expect(reactionTo({ code: "UNREACHABLE" }, 1)).toMatchObject({ scope: "all" });
    // §12.6, §40.1: a quota refusal holds what needs quota; deletes go on until one of them is refused too.
    expect(reactionTo({ code: "QUOTA_EXCEEDED" }, 1)).toMatchObject({ scope: "nonDeletes", delaySeconds: Infinity });
    expect(reactionTo({ code: "QUOTA_EXCEEDED" }, 1, { deletesOnly: true })).toMatchObject({ scope: "writes", delaySeconds: Infinity });
    expect(reactionTo({ code: "VAULT_DELETING" }, 1)).toMatchObject({ scope: "writes", delaySeconds: Infinity });
    expect(reactionTo({ code: "VAULT_NOT_FOUND", status: 404 }, 1)).toEqual({ kind: "stop", code: "VAULT_NOT_FOUND" });
    expect(reactionTo({ code: "BAD_RESPONSE", status: 401 }, 1)).toMatchObject({ kind: "stop" });
  });
});

describe("codes retried on a timer: bounded requests while refused, recovery when it ends", () => {
  // Over 600 s a hot loop sends one request every tick or two (hundreds); the backoff sends about
  // log2(cap) + 600 / cap of them. A refused PUT is watched for 35 s only: the model's prepared blobs
  // expire after 40 s, and an expired blob that travelled alone is itself a failure of the object (§12.6,
  // blocked after UPLOAD_TIMEOUT_MAX; tested below). A hot loop sends ~17 PUTs in 35 s, the backoff 4.
  it.each<[string, Op, Refusal, number, number]>([
    ["RATE_LIMITED at prepare (§11.1: exponential)", "prepareUpload", { throws: backendError("RATE_LIMITED") }, 600, 12],
    ["PENDING_BUDGET_EXCEEDED at prepare (§12.6)", "prepareUpload", { returns: { ok: false, code: "PENDING_BUDGET_EXCEEDED" } }, 600, 12],
    ["UPLOAD_IN_PROGRESS at PUT, no retry-after", "uploadBlob", { throws: backendError("UPLOAD_IN_PROGRESS") }, 35, 5],
    ["BLOB_CORRUPT_RETRYABLE twice in a row at PUT (the adapter retried once)", "uploadBlob", { throws: backendError("BLOB_CORRUPT_RETRYABLE") }, 35, 5],
    ["BAD_UPLOAD_LENGTH twice in a row at PUT", "uploadBlob", { throws: backendError("BAD_UPLOAD_LENGTH") }, 35, 5],
    ["a 500 INTERNAL at commit (outcome unknown)", "commitMutation", { throws: backendError("INTERNAL", 500) }, 600, 16],
    ["the network is down at commit", "commitMutation", { throws: new TypeError("fetch failed") }, 600, 16],
  ])("%s", async (_, op, refusal, seconds, bound) => {
    const t = await setup({ refuse: { [op]: () => refusal } });
    await t.run(seconds);
    expect(t.count(op)).toBeGreaterThan(1);
    expect(t.count(op)).toBeLessThanOrEqual(bound);
    expect(t.uploaded()).toBe(false);
    expect(t.c.shell.state.facts.outbox.length).toBe(1); // §12.6: the entry is kept
    t.refuse[op] = null;
    expect(await t.settle()).not.toBeNull();
    expect(t.uploaded()).toBe(true);
    expect(t.c.shell.state.facts.outbox).toEqual([]);
    expect(t.c.memory.holds).toEqual({ all: null, writes: null, nonDeletes: null });
    t.close();
  });

  it("the request-count oracle can fail: a client that ignores its holds hammers the server", async () => {
    const t = await setup({ refuse: { prepareUpload: () => ({ throws: backendError("RATE_LIMITED") }) }, ignoreHolds: true });
    await t.run(600);
    expect(t.count("prepareUpload")).toBeGreaterThan(100);
    t.close();
  });

  it("the network is down for every request: nothing at all is sent during a backoff, reads included", async () => {
    const down = () => ({ throws: new TypeError("fetch failed") });
    const t = await setup({ refuse: { listEvents: down, prepareUpload: down, getVaultState: down } });
    await t.run(600);
    // At most the poll and one outbox step when a backoff ends (runner.ts tick), 15 backoffs in 600 s.
    expect(t.calls.length).toBeLessThanOrEqual(32);
    const gaps = t.calls.slice(1).map((x, i) => x.at - t.calls[i]!.at);
    expect(gaps.filter((g) => g > 0).every((g) => g >= 2)).toBe(true);
    t.refuse.listEvents = t.refuse.prepareUpload = t.refuse.getVaultState = null;
    expect(await t.settle()).not.toBeNull();
    expect(t.uploaded()).toBe(true);
    t.close();
  });

  it("UPLOAD_IN_PROGRESS with retryAfterSeconds (§12.6: after upload_lease_until): no PUT before it, one right after", async () => {
    const t = await setup({ refuse: { uploadBlob: (n) => (n === 1 ? { throws: backendError("UPLOAD_IN_PROGRESS", undefined, 30) } : null) } });
    const oracle = (): boolean => {
      const puts = t.calls.filter((x) => x.op === "uploadBlob");
      return puts.length >= 2 && puts[1]!.at - puts[0]!.at >= 30;
    };
    expect(await t.settle()).not.toBeNull();
    expect(oracle()).toBe(true);
    expect(t.uploaded()).toBe(true);
    t.close();
    // Broken variant: the same refusal with a client that ignores the wait; the oracle catches it.
    const broken = await setup({ refuse: { uploadBlob: (n) => (n === 1 ? { throws: backendError("UPLOAD_IN_PROGRESS", undefined, 30) } : null) }, ignoreHolds: true });
    await broken.run(60);
    const puts = broken.calls.filter((x) => x.op === "uploadBlob");
    expect(puts[1]!.at - puts[0]!.at).toBeLessThan(30);
    broken.close();
  });

  it("UPLOAD_TIMEOUT: the PUT is retried with exponential spacing, and blocked after UPLOAD_TIMEOUT_MAX (§12.6)", async () => {
    const t = await setup({ refuse: { uploadBlob: () => ({ throws: timeout() }) } });
    await t.run(300);
    const at = t.calls.filter((x) => x.op === "uploadBlob").map((x) => x.at);
    expect(at.length).toBe(3); // UPLOAD_TIMEOUT_MAX
    expect(at[1]! - at[0]!).toBeGreaterThanOrEqual(2);
    expect(at[2]! - at[1]!).toBeGreaterThanOrEqual(4);
    expect(t.kinds("blocked")).toEqual(["UPLOAD_TIMEOUT_MAX a.md"]);
    expect(t.c.shell.state.facts.blocked.map((b) => b.reason)).toEqual(["UPLOAD_TIMEOUT_MAX"]);
    t.close();
  });

  it("releaseUpload answering UPLOAD_IN_PROGRESS keeps the cleanup record (rule 13) and waits between attempts", async () => {
    // A PUT answered BLOB_CORRUPT drops the attempt: its blobs go to the cleanup queue, released first.
    const t = await setup({
      refuse: {
        uploadBlob: (n) => (n === 1 ? { returns: { ok: false, code: "BLOB_CORRUPT" } } : null),
        releaseUpload: () => ({ returns: "UPLOAD_IN_PROGRESS" }),
      },
    });
    await t.run(600);
    expect(t.count("releaseUpload")).toBeGreaterThan(1);
    expect(t.count("releaseUpload")).toBeLessThanOrEqual(12);
    expect(t.c.shell.state.facts.cleanup.length).toBeGreaterThan(0);
    t.refuse.releaseUpload = null;
    expect(await t.settle()).not.toBeNull();
    expect(t.c.shell.state.facts.cleanup).toEqual([]);
    expect(t.uploaded()).toBe(true);
    t.close();
  });
});

describe("conditions (QUOTA_EXCEEDED, VAULT_DELETING): kept, told once, retried only when the condition may have changed", () => {
  it.each<[string, Op, Refusal]>([
    ["QUOTA_EXCEEDED at prepare (§11.1)", "prepareUpload", { throws: backendError("QUOTA_EXCEEDED") }],
    ["QUOTA_EXCEEDED at commit", "commitMutation", { throws: backendError("QUOTA_EXCEEDED") }],
    ["VAULT_DELETING at prepare (§12.6: keep the outbox, notify)", "prepareUpload", { throws: backendError("VAULT_DELETING") }],
    ["VAULT_DELETING at commit", "commitMutation", { throws: backendError("VAULT_DELETING") }],
  ])("%s", async (_, op, refusal) => {
    const t = await setup({ refuse: { [op]: () => refusal } });
    const code = (refusal as { throws: SyncBackendError }).throws.code;
    await t.run(3600);
    expect(t.count(op)).toBe(1); // never on a timer
    expect(t.kinds("hold")).toEqual([code]);
    expect(t.c.shell.state.facts.outbox.length).toBe(1);
    expect((await loadVault(t.store, t.rig.dlc)).facts.outbox.length).toBe(1); // kept in IndexedDB
    // Reads go on: a remote edit reaches the disk while uploads wait, and releases the hold (space may be free).
    remoteCommit(t.rig.server, "remote-1", { path: "r.md", content: "from elsewhere", deleted: false });
    const before = t.count(op);
    await t.run(60);
    expect(t.rig.disk.files.get("r.md")?.content).toBe("from elsewhere");
    expect(t.count(op)).toBe(before + 1);
    expect(t.kinds("hold")).toEqual([code]); // the same condition: no second notice
    // The user says it is over ("Sync now"), and it is.
    t.refuse[op] = null;
    releaseHolds(t.c, "user");
    expect(await t.settle()).not.toBeNull();
    expect(t.uploaded()).toBe(true);
    expect(t.kinds("resume")).toEqual([code]);
    t.close();
  });

  it("the once-only oracle can fail: a client that forgets its hold is refused (and logs a hold) at every retry", async () => {
    const t = await setup({ refuse: { prepareUpload: () => ({ throws: backendError("QUOTA_EXCEEDED") }) }, ignoreHolds: true });
    await t.run(60);
    expect(t.count("prepareUpload")).toBeGreaterThan(10);
    expect(t.kinds("hold").length).toBeGreaterThan(10);
    t.close();
  });
});

describe("QUOTA_EXCEEDED and deletes (§12.6, §11.1, §40.1 DELETE_MANIFEST_ALLOWANCE): deletes go on, the rest waits", () => {
  /**
   * The account over its quota: every prepare that needs quota is refused; a for_delete manifest too once
   * the allowance is spent (`allowance: false`, which a test may change). `seen` counts the prepares of each kind.
   */
  function overQuota(o: { allowance: boolean }) {
    const seen = { content: 0, forDelete: 0 };
    const refuse = (_n: number, input: PrepareUploadInput): Refusal | null => {
      if (input.forDelete) seen.forDelete++;
      else seen.content++;
      return input.forDelete && o.allowance ? null : { throws: backendError("QUOTA_EXCEEDED") };
    };
    return { seen, refuse, o };
  }
  /** a.md confirmed first, with space. */
  async function confirmed() {
    const t = await setup();
    expect(await t.settle()).not.toBeNull();
    expect(t.uploaded()).toBe(true);
    return t;
  }
  const headAt = (t: Awaited<ReturnType<typeof setup>>, path: string) => [...t.rig.server.heads.values()].find((h) => h.path === path);
  const deleteOnly = (t: Awaited<ReturnType<typeof setup>>) => t.c.shell.state.facts.outbox.map((e) => e.objects.every((o) => o.deleted));

  it("under a hold, a delete-only change is uploaded and committed; the edit stays held; told once; Sync now sends the edit", async () => {
    const t = await confirmed();
    const q = overQuota({ allowance: true });
    t.refuse.prepareUpload = q.refuse;
    t.rig.disk.userWrite("b.md", "two");
    await t.run(30);
    expect(t.kinds("hold")).toEqual(["QUOTA_EXCEEDED"]);
    expect(q.seen.content).toBe(1);
    t.rig.disk.files.delete("a.md");
    await t.run(3600);
    expect(headAt(t, "a.md")?.deleted).toBe(true); // the delete went through the hold
    expect(headAt(t, "b.md")).toBeUndefined();
    expect(deleteOnly(t)).toEqual([false]); // the edit is kept (§12.6)
    expect((await loadVault(t.store, t.rig.dlc)).facts.outbox).toHaveLength(1);
    // Never on a timer: the delete's own event may release the hold once (question 369), nothing more.
    expect(q.seen.content).toBeLessThanOrEqual(2);
    expect(t.kinds("hold")).toEqual(["QUOTA_EXCEEDED"]);
    expect(t.kinds("resume")).toEqual([]); // a delete's answer does not prove there is space
    t.refuse.prepareUpload = null;
    releaseHolds(t.c, "user");
    expect(await t.settle()).not.toBeNull();
    expect(headAt(t, "b.md")?.content).toBe("two");
    expect(t.c.shell.state.facts.outbox).toEqual([]);
    expect(t.kinds("resume")).toEqual(["QUOTA_EXCEEDED"]);
    t.close();
  });

  it("an edit and a delete in one mutation wait together: the entry is immutable and kept (rule 13, §12.6)", async () => {
    const t = await confirmed();
    const q = overQuota({ allowance: true });
    t.refuse.prepareUpload = q.refuse;
    t.rig.disk.userWrite("b.md", "two");
    t.rig.disk.files.delete("a.md"); // seen by the same observation: one entry with both
    await t.run(600);
    expect(t.c.shell.state.facts.outbox.map((e) => e.objects.map((o) => o.path).sort())).toEqual([["a.md", "b.md"]]);
    expect(headAt(t, "a.md")?.deleted).toBe(false);
    expect(q.seen.content).toBe(1);
    expect(t.kinds("hold")).toEqual(["QUOTA_EXCEEDED"]);
    t.refuse.prepareUpload = null;
    releaseHolds(t.c, "user");
    expect(await t.settle()).not.toBeNull();
    expect(headAt(t, "a.md")?.deleted).toBe(true);
    expect(headAt(t, "b.md")?.content).toBe("two");
    t.close();
  });

  it("a delete refused too (the allowance is spent): deletes wait as well, told once, no timer; Sync now retries each once", async () => {
    const t = await confirmed();
    const q = overQuota({ allowance: false });
    t.refuse.prepareUpload = q.refuse;
    t.rig.disk.userWrite("b.md", "two");
    await t.run(30);
    t.rig.disk.files.delete("a.md");
    await t.run(3600);
    expect(q.seen).toEqual({ content: 1, forDelete: 1 });
    expect(headAt(t, "a.md")?.deleted).toBe(false);
    expect((await loadVault(t.store, t.rig.dlc)).facts.outbox).toHaveLength(2); // both kept (§12.6)
    expect(deleteOnly(t)).toEqual([false, true]);
    expect(t.kinds("hold")).toEqual(["QUOTA_EXCEEDED"]);
    // "Sync now" while still full: one more request of each, then waiting again.
    releaseHolds(t.c, "user");
    await t.run(3600);
    expect(q.seen).toEqual({ content: 2, forDelete: 2 });
    expect(t.kinds("hold")).toEqual(["QUOTA_EXCEEDED"]);
    // Room for deletes only (their old manifests were pruned, say): the delete goes, the edit still waits,
    // and the condition is not over: no resume, so no second notice when the edit is refused again.
    q.o.allowance = true;
    releaseHolds(t.c, "user");
    await t.run(600);
    expect(headAt(t, "a.md")?.deleted).toBe(true);
    expect(deleteOnly(t)).toEqual([false]);
    expect(t.kinds("resume")).toEqual([]);
    expect(t.kinds("hold")).toEqual(["QUOTA_EXCEEDED"]);
    // With space, the edit goes too.
    t.refuse.prepareUpload = null;
    releaseHolds(t.c, "user");
    expect(await t.settle()).not.toBeNull();
    expect(headAt(t, "b.md")?.content).toBe("two");
    expect(t.kinds("resume")).toEqual(["QUOTA_EXCEEDED"]);
    t.close();
  });

  it("the delete of an object whose edit is held waits for that edit (§12.2 rule 9: one entry per object)", async () => {
    const t = await confirmed();
    const q = overQuota({ allowance: true });
    t.refuse.prepareUpload = q.refuse;
    t.rig.disk.files.get("a.md")!.content = "one edited";
    await t.run(30);
    expect(t.kinds("hold")).toEqual(["QUOTA_EXCEEDED"]);
    t.rig.disk.files.delete("a.md");
    await t.run(600);
    expect(q.seen.forDelete).toBe(0);
    expect(headAt(t, "a.md")).toMatchObject({ deleted: false, content: "one" });
    t.refuse.prepareUpload = null;
    releaseHolds(t.c, "user");
    expect(await t.settle()).not.toBeNull();
    // The edit is confirmed first, then the delete over it.
    expect([...t.rig.server.revisions.values()].some((r) => r.content === "one edited" && !r.deleted)).toBe(true);
    expect(headAt(t, "a.md")?.deleted).toBe(true);
    t.close();
  });

  it("a restart during the hold forgets it (nothing persisted): one request per start, and deletes still go", async () => {
    const t = await confirmed();
    const q = overQuota({ allowance: true });
    t.refuse.prepareUpload = q.refuse;
    t.rig.disk.userWrite("b.md", "two");
    await t.run(30);
    expect(q.seen.content).toBe(1);
    await t.restart();
    await t.run(30);
    expect(q.seen.content).toBe(2); // the new instance asks once, and holds again
    t.rig.disk.files.delete("a.md");
    await t.run(600);
    expect(headAt(t, "a.md")?.deleted).toBe(true);
    expect(deleteOnly(t)).toEqual([false]);
    expect(q.seen.content).toBeLessThanOrEqual(3);
    t.close();
  });

  it("the oracle can fail: a client that holds deletes with the rest never deletes over the quota", async () => {
    const t = await confirmed();
    const q = overQuota({ allowance: true });
    t.refuse.prepareUpload = q.refuse;
    t.rig.disk.userWrite("b.md", "two");
    await t.run(30);
    // Broken variant: the old scope, every write held.
    const h = t.c.memory.holds.nonDeletes!;
    t.c.memory.holds.writes = { ...h, scope: "writes" };
    t.rig.disk.files.delete("a.md");
    await t.run(600);
    expect(headAt(t, "a.md")?.deleted).toBe(false);
    t.close();
  });
});

describe("stops: the server refuses the vault or the credentials; tick throws, nothing is dropped", () => {
  it.each<[string, Op, unknown]>([
    ["VAULT_NOT_FOUND (§12.6: stop syncing the vault, keep the outbox)", "listEvents", backendError("VAULT_NOT_FOUND", 404)],
    ["VAULT_NOT_FOUND at prepare", "prepareUpload", backendError("VAULT_NOT_FOUND", 404)],
    ["RECIPIENT_REVOKED (§18.3: keep the outbox, wait for re-enrollment)", "prepareUpload", backendError("RECIPIENT_REVOKED", 403)],
    ["WRITE_CAPABILITY_REQUIRED", "commitMutation", backendError("WRITE_CAPABILITY_REQUIRED", 403)],
    ["UNAUTHENTICATED", "listEvents", backendError("UNAUTHENTICATED", 401)],
    // §18.3 before any request is answered: the capability's own challenge, or the verified registry.
    ["RECIPIENT_REVOKED from the capability challenge (§11.3 step 2)", "prepareUpload", new CapabilityError("RECIPIENT_REVOKED")],
    ["RECIPIENT_NOT_ACTIVE from the verified registry (directory.ts)", "prepareUpload", new DirectoryError("RECIPIENT_NOT_ACTIVE", "revoked")],
    // §11.3 before any request is sent: the login ended here (signed out), or is now another session.
    ["NOT_SIGNED_IN from the session headers (session.ts)", "listEvents", new SessionError("NOT_SIGNED_IN", "signed out")],
    ["SESSION_CHANGED from the session headers (session.ts)", "prepareUpload", new SessionError("SESSION_CHANGED", "another session")],
  ])("%s", async (_, op, error) => {
    const t = await setup({ refuse: { [op]: () => ({ throws: error }) } });
    let thrown: unknown = null;
    for (let i = 0; i < 50 && thrown === null; i++) {
      try {
        await tick(t.c);
      } catch (e) {
        thrown = e;
      }
      t.rig.server.now++;
    }
    expect(thrown).toBe(error);
    expect(t.count(op)).toBe(1);
    expect(t.kinds("stop")).toEqual([(error as { code: string }).code]);
    expect(t.rig.disk.files.get("a.md")?.content).toBe("one");
    const persisted = (await loadVault(t.store, t.rig.dlc)).facts;
    if (op !== "listEvents") expect(persisted.outbox.length).toBe(1);
    t.close();
  });
});

describe("re-enrollment (§18.3, §35.8): a stop the host answers with 'enroll again', never a retry loop", () => {
  it("the device's own refusals are stops that ask for re-enrollment; any other capability or directory failure is an unknown outcome", () => {
    for (const e of [backendError("RECIPIENT_REVOKED", 403), backendError("RECIPIENT_UNKNOWN", 403), new CapabilityError("RECIPIENT_REVOKED"), new CapabilityError("RECIPIENT_UNKNOWN"), new DirectoryError("RECIPIENT_NOT_ACTIVE", "x")]) {
      expect(needsReenrollment(e)).toBe(true);
      expect(isPersistentError(e)).toBe(true);
      expect(describeError(e)).toMatch(/enrolled again/);
    }
    for (const e of [backendError("VAULT_NOT_FOUND", 404), new CapabilityError("BAD_RESPONSE"), new DirectoryError("REGISTRY_INVALID", "x"), new Error("RECIPIENT_REVOKED")]) {
      expect(needsReenrollment(e)).toBe(false);
    }
    // A login that cannot answer is not a refusal: held and retried.
    expect(isPersistentError(new SessionError("UNREACHABLE", "x"))).toBe(false);
    expect(describeError(new SessionError("NOT_SIGNED_IN", "x"))).toMatch(/signed out/);
    // Before slice 20 a CapabilityError was "UNREACHABLE": held and retried with backoff, forever.
    expect(reactionTo({ code: "UNREACHABLE" }, 1)).toMatchObject({ kind: "hold", scope: "all" });
    expect(isPersistentError(new CapabilityError("BAD_RESPONSE"))).toBe(false);
  });
});

describe("CURSOR_EXPIRED (§13.3): full reconciliation, then events again", () => {
  it("the heads come from getVaultState and a remote edit made meanwhile reaches the disk", async () => {
    const t = await setup({ refuse: { listEvents: (n) => (n === 2 ? { returns: { kind: "CURSOR_EXPIRED" } } : null) } });
    await t.run(1);
    remoteCommit(t.rig.server, "remote-1", { path: "r.md", content: "meanwhile", deleted: false });
    expect(await t.settle()).not.toBeNull();
    expect(t.kinds("reconcile")).toEqual([undefined]);
    expect(t.count("getVaultState")).toBeGreaterThanOrEqual(1);
    expect(t.rig.disk.files.get("r.md")?.content).toBe("meanwhile");
    expect(t.uploaded()).toBe(true);
    t.close();
  });
});

describe("surfacing (controller.ts): one notice per condition until an answer shows it is over", () => {
  const hold = (code: string) => ({ kind: "hold", detail: code });
  it("a condition is told once; a resume re-arms it; timed codes and other events are not told", () => {
    const noticed = new Set<string>();
    const told = [hold("QUOTA_EXCEEDED"), hold("QUOTA_EXCEEDED"), hold("RATE_LIMITED"), hold("UNREACHABLE"), hold("VAULT_DELETING"), hold("QUOTA_EXCEEDED")].map((e) => noticeFor(e, noticed));
    expect(told.filter((m) => m !== null)).toHaveLength(2);
    expect(noticeFor({ kind: "resume", detail: "QUOTA_EXCEEDED" }, noticed)).toBeNull();
    expect(noticeFor(hold("QUOTA_EXCEEDED"), noticed)).toContain("quota");
    expect(noticeFor(hold("VAULT_DELETING"), noticed)).toBeNull(); // still not over
  });

  it("the once-only oracle can fail: without the remembered set every hold is a new notice", () => {
    const told = [hold("QUOTA_EXCEEDED"), hold("QUOTA_EXCEEDED"), hold("QUOTA_EXCEEDED")].map((e) => noticeFor(e, new Set()));
    expect(told.filter((m) => m !== null)).toHaveLength(3);
  });

  it("blocked contents and INVALID_BATCH are told; each stop code pauses with its own reason", () => {
    expect(noticeFor({ kind: "blocked", detail: "BLOB_TOO_LARGE big.pdf" }, new Set())).toContain("big.pdf: it is larger than the plan's file limit");
    expect(noticeFor({ kind: "blocked", detail: "UPLOAD_TIMEOUT_MAX slow.png" }, new Set())).toContain("slow.png: the connection is too slow");
    expect(noticeFor({ kind: "rejected:INVALID_BATCH" }, new Set())).toContain("client bug");
    for (const [code, status, text] of [
      ["VAULT_NOT_FOUND", 404, "no longer exists"],
      ["RECIPIENT_REVOKED", 403, "revoked"],
      ["WRITE_CAPABILITY_REQUIRED", 403, "write permission"],
      ["UNAUTHENTICATED", 401, "session"],
    ] as const) {
      const e = backendError(code, status);
      expect(isPersistentError(e)).toBe(true);
      expect(describeError(e)).toContain(text);
    }
    expect(isPersistentError(backendError("QUOTA_EXCEEDED"))).toBe(false);
  });
});
