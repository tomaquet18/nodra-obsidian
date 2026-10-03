import * as P from "@nodra/protocol";
import type { InstallationStore } from "./installation.js";
import { SyncBackendError } from "./http-backend.js";

// §37 on the client: "Todos los clientes activos DEBEN mostrar los eventos no reconocidos." A SECURITY
// event in a vault's log (§13.1) is only a hint that the account's security log grew; the log itself is
// `listSecurityEvents` (§22), per account, and the ack is `acknowledgeSecurityEvent`, persisted by the
// Worker for this replica (§11.3, TRUSTED_SECURITY). Nothing here acknowledges on the user's behalf:
// an event leaves the screen only through `acknowledge`, which the user's own action calls.
//
// Facts persisted (per installation, §20.2 compare-and-set; never "which step we were at"):
//   * `through`: the server said every event at or below it is acknowledged by this replica. It is only
//     where the next list starts; the server's `acknowledged` stays the truth for everything above it.
//   * `pendingAcks`: acks the user gave here that the server has not confirmed yet. Written before the
//     call (write-ahead), resent on every check until the server answers, never shown again meanwhile.
// What was shown in this run is memory only, so a restart shows every unacknowledged event again.

export type SecurityEventType = P.SecurityEventType;

/** One unacknowledged §37 event, as the user is told about it. */
export interface SecurityAlert {
  readonly id: number;
  readonly eventType: SecurityEventType;
  readonly vaultId: string | null;
  readonly createdAt: string;
  /** The events that can mean someone else holds the account's secrets or its Recovery Kit. */
  readonly alarming: boolean;
  readonly message: string;
}

/** §22's two calls, for this replica's credentials. */
export interface SecurityEventsPort {
  list(afterId: number): Promise<readonly P.SecurityEventRow[]>;
  /** NOT_FOUND: not this account's, or swept (§37) — either way there is nothing left to acknowledge. */
  acknowledge(id: number): Promise<"ACKNOWLEDGED" | "NOT_FOUND">;
}

export interface SecurityFacts {
  readonly through: number;
  readonly pendingAcks: readonly number[];
}

/** The per-installation row of these facts (§20.2); it belongs to the account (trust.ts `ACCOUNT_ROWS`). */
export const SECURITY_EVENTS = "security_events";
const FACTS = SECURITY_EVENTS;
const EMPTY: SecurityFacts = { through: 0, pendingAcks: [] };

/**
 * The next `through`: past every leading event the server reports acknowledged. The ids are the
 * server's order (§6: ascending, gaps allowed), so a gap left by the 180-day sweep is simply crossed.
 */
export function advanceThrough(through: number, events: readonly Pick<P.SecurityEventRow, "securityEventId" | "acknowledged">[]): number {
  let t = through;
  for (const e of [...events].sort((a, b) => a.securityEventId - b.securityEventId)) {
    if (e.securityEventId <= t) continue;
    if (!e.acknowledged) break;
    t = e.securityEventId;
  }
  return t;
}

/** What to show now: unacknowledged by the server, not acknowledged here already, not shown in this run. */
export function toSurface(events: readonly P.SecurityEventRow[], facts: SecurityFacts, shown: ReadonlySet<number>): SecurityAlert[] {
  const pending = new Set(facts.pendingAcks);
  return events
    .filter((e) => !e.acknowledged && !pending.has(e.securityEventId) && !shown.has(e.securityEventId))
    .map((e) => ({
      id: e.securityEventId,
      eventType: e.eventType,
      vaultId: e.vaultId,
      createdAt: e.createdAt,
      alarming: ALARMING.has(e.eventType),
      message: `${MESSAGES[e.eventType]} (${e.createdAt})`,
    }));
}

const ALARMING: ReadonlySet<SecurityEventType> = new Set<SecurityEventType>([
  "CLIENT_ENROLLED",
  "SECRETS_CHANGED",
  "RECOVERY_KIT_REPLACED",
  "RECOVERY_RESET",
  "VAULT_DELETE_SCHEDULED",
  "ACCOUNT_DELETE_SCHEDULED",
  "SWITCHED_TO_MANAGED",
  // §35.15: each can take the account away from its owner once RECOVERY_DELAY has passed unvetoed.
  "RECOVERY_RESET_REQUESTED",
  "KIT_REPLACEMENT_REQUESTED",
  "SWITCH_TO_MANAGED_REQUESTED",
]);

const MESSAGES: Readonly<Record<SecurityEventType, string>> = {
  CLIENT_ENROLLED:
    "A device was given access to your Nodra account. If it was not you, your Encryption Password and Account Secret Key are compromised: revoke the device and run a Security Reset with your Recovery Kit.",
  CLIENT_REVOKED: "A device's access to your Nodra account was revoked.",
  VAULT_CREATED: "A vault was created in your Nodra account.",
  SECRETS_CHANGED:
    "Your Encryption Password or Account Secret Key was changed. If it was not you, run a Security Reset with your Recovery Kit.",
  RECOVERY_KIT_REPLACED: "Your Recovery Kit was replaced. If it was not you, your Encryption Password and Account Secret Key are compromised.",
  RECOVERY_RESET: "A Security Reset was run with your Recovery Kit and every device must enroll again. If it was not you, your Recovery Kit is compromised.",
  VAULT_DELETE_SCHEDULED: "A vault was scheduled for deletion in 14 days. If it was not you, cancel it now.",
  ACCOUNT_DELETE_SCHEDULED: "Your Nodra account was scheduled for deletion in 14 days. If it was not you, cancel it now.",
  VAULT_DELETE_CANCELLED: "A scheduled vault deletion was cancelled.",
  ACCOUNT_DELETE_CANCELLED: "The scheduled deletion of your Nodra account was cancelled.",
  VAULT_PURGED: "A deleted vault was erased for good.",
  SWITCHED_TO_PRIVATE: "Your Nodra account was switched to Private: only your Encryption Password, Account Secret Key and Recovery Kit open it now.",
  SWITCHED_TO_MANAGED:
    "Your Nodra account was switched to Managed: the service can now read your notes, and your old Recovery Kit no longer controls the account. If it was not you, your Encryption Password and Account Secret Key are compromised.",
  RECOVERY_RESET_REQUESTED:
    "A Security Reset of your Nodra account was requested with your Recovery Kit. It can run in 72 hours. If it was not you, veto it now with your Encryption Password and Account Secret Key.",
  KIT_REPLACEMENT_REQUESTED:
    "A replacement of your Recovery Kit was requested. It can run in 72 hours. If it was not you, veto it now with your current Recovery Kit: your Encryption Password and Account Secret Key are compromised.",
  SWITCH_TO_MANAGED_REQUESTED:
    "A switch of your Nodra account to Managed was requested. It can run in 72 hours. If it was not you, veto it now with your current Recovery Kit: your Encryption Password and Account Secret Key are compromised.",
  RECOVERY_REQUEST_VETOED: "A pending recovery request of your Nodra account was vetoed.",
  RECOVERY_REQUEST_CANCELLED: "A pending recovery request of your Nodra account was cancelled by whoever filed it.",
};

/** The facts under §20.2's compare-and-set: `change` is pure and re-applied to whatever was there. */
async function update(store: InstallationStore, change: (f: SecurityFacts) => SecurityFacts): Promise<SecurityFacts> {
  for (;;) {
    const snap = await store.read([FACTS]);
    const next = change((snap.rows.get(FACTS) as SecurityFacts | undefined) ?? EMPTY);
    if (await store.commit(snap.version, { [FACTS]: next })) return next;
  }
}

export interface SecurityMonitor {
  /** Resends pending acks, reads the log after `through`, and surfaces each new unacknowledged event once. */
  check(): Promise<void>;
  /** The user's acknowledgement: persisted first, then sent. A failed send stays pending and is resent. */
  acknowledge(id: number): Promise<void>;
}

export function securityMonitor(o: { readonly port: SecurityEventsPort; readonly store: InstallationStore; readonly surface: (alert: SecurityAlert) => void }): SecurityMonitor {
  const shown = new Set<number>();
  return {
    async check() {
      const facts = ((await o.store.read([FACTS])).rows.get(FACTS) as SecurityFacts | undefined) ?? EMPTY;
      const confirmed = new Set<number>();
      for (const id of facts.pendingAcks) {
        await o.port.acknowledge(id); // ACKNOWLEDGED or NOT_FOUND: either way, nothing is pending any more
        confirmed.add(id);
      }
      const events = await o.port.list(facts.through);
      const through = advanceThrough(facts.through, events);
      const now = await update(o.store, (f) => ({
        through: Math.max(f.through, through),
        pendingAcks: f.pendingAcks.filter((id) => !confirmed.has(id)),
      }));
      for (const alert of toSurface(events, now, shown)) {
        shown.add(alert.id);
        o.surface(alert);
      }
    },
    async acknowledge(id) {
      shown.add(id);
      await update(o.store, (f) => (f.pendingAcks.includes(id) ? f : { ...f, pendingAcks: [...f.pendingAcks, id] }));
      await o.port.acknowledge(id);
      await update(o.store, (f) => ({ ...f, pendingAcks: f.pendingAcks.filter((p) => p !== id) }));
    },
  };
}

/** The refusals a fresh proof of possession can fix (§11.3), as in http-backend.ts. */
const AUTH_REFUSALS: ReadonlySet<string> = new Set(["WRITE_CAPABILITY_REQUIRED", "SCOPE_REQUIRED", "UNAUTHENTICATED"]);

/** {@link SecurityEventsPort} over the Worker. Anything but an answer throws a `SyncBackendError`. */
export function httpSecurityEvents(o: {
  readonly baseUrl: string;
  readonly fetch: typeof fetch;
  readonly headers: () => Record<string, string> | Promise<Record<string, string>>;
  readonly onAuthRefusal?: (code: string) => Promise<boolean>;
}): SecurityEventsPort {
  async function send(method: string, path: string): Promise<{ status: number; body: unknown }> {
    for (let attempt = 0; ; attempt++) {
      const res = await o.fetch(`${o.baseUrl}${path}`, { method, headers: { ...(await o.headers()) } });
      const body: unknown = await res.json().catch(() => null);
      const error = res.ok ? null : P.ErrorBody.safeParse(body);
      const code = error?.success ? error.data.error : null;
      if (code !== null && attempt === 0 && AUTH_REFUSALS.has(code) && o.onAuthRefusal !== undefined && (await o.onAuthRefusal(code))) continue;
      if (!res.ok && code !== "SECURITY_EVENT_NOT_FOUND") throw new SyncBackendError(code ?? "BAD_RESPONSE", res.status);
      return { status: res.status, body };
    }
  }
  return {
    async list(afterId) {
      const parsed = P.SecurityEventsResponse.safeParse((await send("GET", P.securityEventRoutes.list(afterId))).body);
      if (!parsed.success) throw new SyncBackendError("BAD_RESPONSE");
      return parsed.data.events;
    },
    async acknowledge(id) {
      const r = await send("POST", P.securityEventRoutes.acknowledge(id));
      if (r.status === 404) return "NOT_FOUND";
      if (!P.AcknowledgeResponse.safeParse(r.body).success) throw new SyncBackendError("BAD_RESPONSE", r.status);
      return "ACKNOWLEDGED";
    },
  };
}
