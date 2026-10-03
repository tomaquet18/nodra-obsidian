import type * as P from "@nodra/protocol";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { describe, expect, it } from "vitest";
import { installationStore } from "../src/installation.js";
import { type SecurityAlert, type SecurityEventsPort, advanceThrough, securityMonitor } from "../src/security-events.js";

// §37 on the client, against a server model with the Worker's semantics (per-replica acks, `> afterId`,
// gaps after the sweep, SECURITY_EVENT_NOT_FOUND for a swept id) and the real per-installation store on
// fake-indexeddb. A "restart" is a new monitor over the same store: nothing carries over but the facts.
// The same flows over the real Worker are in tests/integration/test/security-events.http.test.ts.

/** The account's §37 log as the server holds it, for one replica. */
function server() {
  const events: { id: number; type: P.SecurityEventType }[] = [];
  const acked = new Set<number>();
  let next = 1;
  let online = true;
  const calls: string[] = [];
  const offline = () => {
    if (!online) throw new Error("unreachable");
  };
  const port: SecurityEventsPort = {
    async list(afterId) {
      calls.push(`list ${afterId}`);
      offline();
      return events
        .filter((e) => e.id > afterId)
        .map((e) => ({ securityEventId: e.id, eventType: e.type, vaultId: null, actorRecipientId: null, rootGeneration: 1, createdAt: `t${e.id}`, acknowledged: acked.has(e.id) }));
    },
    async acknowledge(id) {
      calls.push(`ack ${id}`);
      offline();
      if (!events.some((e) => e.id === id)) return "NOT_FOUND";
      acked.add(id);
      return "ACKNOWLEDGED";
    },
  };
  return {
    port,
    acked,
    calls,
    emit(type: P.SecurityEventType) {
      events.push({ id: next++, type });
    },
    /** §37 / §6: the 180-day sweep takes every event up to `id`, and leaves a gap in the ids. */
    sweep(id: number) {
      for (let i = events.length - 1; i >= 0; i--) if (events[i]!.id <= id) events.splice(i, 1);
    },
    setOnline(value: boolean) {
      online = value;
    },
  };
}

function device(port: SecurityEventsPort) {
  const store = installationStore({ installNs: "plugin:sec", indexedDB: new IDBFactory(), IDBKeyRange });
  /** One run of the client (a restart makes a new one). `react` is what the UI does with an alert. */
  const run = (react: (alert: SecurityAlert, monitor: ReturnType<typeof securityMonitor>) => unknown = () => {}) => {
    const seen: SecurityAlert[] = [];
    const reactions: unknown[] = [];
    const monitor = securityMonitor({ port, store, surface: (alert) => (seen.push(alert), reactions.push(react(alert, monitor))) });
    return { monitor, seen, settled: () => Promise.all(reactions) };
  };
  const facts = async () => (await store.read(["security_events"])).rows.get("security_events");
  return { run, facts };
}

describe("§37: the client surfaces every unacknowledged event, and only the user acknowledges it", () => {
  it("another device's enrollment: one alarming alert, the same run never repeats it, a restart shows it again until acknowledged", async () => {
    const s = server();
    const d = device(s.port);
    s.emit("CLIENT_ENROLLED");
    const first = d.run();
    await first.monitor.check();
    expect(first.seen).toMatchObject([{ id: 1, eventType: "CLIENT_ENROLLED", alarming: true }]);
    await first.monitor.check();
    expect(first.seen).toHaveLength(1);
    expect(s.acked.size).toBe(0);

    const restarted = d.run();
    await restarted.monitor.check();
    expect(restarted.seen.map((a) => a.id)).toEqual([1]);

    await restarted.monitor.acknowledge(1);
    expect([...s.acked]).toEqual([1]);
    await restarted.monitor.check();
    const afterAck = d.run();
    await afterAck.monitor.check();
    expect(afterAck.seen).toEqual([]);
    // The watermark moved past it: the next list starts after 1.
    expect(await d.facts()).toEqual({ through: 1, pendingAcks: [] });
    expect(s.calls.at(-1)).toBe("list 1");
  });

  it("a later event is surfaced by itself; an earlier unacknowledged one keeps the watermark where it is", async () => {
    const s = server();
    const d = device(s.port);
    s.emit("VAULT_CREATED");
    s.emit("RECOVERY_KIT_REPLACED");
    const r = d.run();
    await r.monitor.check();
    await r.monitor.acknowledge(2);
    s.emit("SECRETS_CHANGED");
    await r.monitor.check();
    expect(r.seen.map((a) => [a.id, a.alarming])).toEqual([[1, false], [2, true], [3, true]]);
    expect(await d.facts()).toEqual({ through: 0, pendingAcks: [] });
  });

  it("an acknowledgement that cannot reach the server is kept as a fact, never shown again, and resent", async () => {
    const s = server();
    const d = device(s.port);
    s.emit("RECOVERY_RESET");
    const r = d.run();
    await r.monitor.check();
    s.setOnline(false);
    await expect(r.monitor.acknowledge(1)).rejects.toThrow("unreachable");
    expect(await d.facts()).toEqual({ through: 0, pendingAcks: [1] });
    s.setOnline(true);
    const restarted = d.run();
    await restarted.monitor.check();
    expect(restarted.seen).toEqual([]); // the user already acknowledged it here
    expect([...s.acked]).toEqual([1]);
    // Resent before the list, so the same check already reads it acknowledged and moves past it.
    expect(s.calls.slice(-2)).toEqual(["ack 1", "list 0"]);
    expect(await d.facts()).toEqual({ through: 1, pendingAcks: [] });
  });

  it("a gap in the ids left by the 180-day sweep does not break the reader", async () => {
    const s = server();
    const d = device(s.port);
    for (const t of ["VAULT_CREATED", "VAULT_CREATED", "CLIENT_REVOKED", "CLIENT_ENROLLED", "VAULT_DELETE_SCHEDULED"] as const) s.emit(t);
    const r = d.run();
    await r.monitor.check();
    await r.monitor.acknowledge(1);
    await r.monitor.acknowledge(2);
    await r.monitor.check();
    expect(await d.facts()).toEqual({ through: 2, pendingAcks: [] });
    s.sweep(4); // 3 and 4 were never acknowledged; the sweep takes them anyway
    const restarted = d.run();
    await restarted.monitor.check();
    expect(restarted.seen.map((a) => a.id)).toEqual([5]);
    await restarted.monitor.acknowledge(5);
    await restarted.monitor.check();
    expect(await d.facts()).toEqual({ through: 5, pendingAcks: [] });
    // A pending ack of a swept id is answered NOT_FOUND, and that settles it too.
    await expect(restarted.monitor.acknowledge(3)).resolves.toBeUndefined();
    expect(await d.facts()).toEqual({ through: 5, pendingAcks: [] });
  });

  it("advanceThrough crosses gaps, stops at the first unacknowledged event and ignores what is at or below it", () => {
    const e = (securityEventId: number, acknowledged: boolean) => ({ securityEventId, acknowledged });
    expect(advanceThrough(2, [e(5, true), e(9, true), e(12, false), e(13, true)])).toBe(9);
    expect(advanceThrough(2, [e(1, false), e(4, true)])).toBe(4);
    expect(advanceThrough(7, [])).toBe(7);
    expect(advanceThrough(0, [e(3, false), e(1, true)])).toBe(1);
  });

  it("broken variant (a): a client that acknowledges on read loses the alert the user never saw", async () => {
    // The property the first test checks, as a function of what the UI does with an alert.
    const unseenAfterRestart = async (react?: Parameters<ReturnType<typeof device>["run"]>[0]) => {
      const s = server();
      const d = device(s.port);
      s.emit("CLIENT_ENROLLED");
      const first = d.run(react);
      await first.monitor.check();
      await first.settled(); // whatever the surface started is over before the restart
      const restarted = d.run();
      await restarted.monitor.check();
      return restarted.seen.map((a) => a.id);
    };
    expect(await unseenAfterRestart()).toEqual([1]);
    // The variant: the surface acknowledges what it is handed, before any user acts.
    expect(await unseenAfterRestart((alert, monitor) => monitor.acknowledge(alert.id))).toEqual([]);
  });
});
