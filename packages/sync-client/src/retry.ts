import { UPLOAD_TIMEOUT } from "./ports.js";

// How the client reacts to a failed server request (§11.1–§11.3, §12.6, §18.3). Pure: the runner keeps
// the resulting hold in memory only (runner.ts `memory.holds`), never in IndexedDB. A hold is not a fact
// about the vault but a pause between retries: after a restart the next request simply asks again, one
// request per start. What must survive a restart is already persisted as facts: the outbox (kept on every
// code below), blocked contents (rule 8) and the upload failure counters (§12.6).
//
// Three reactions:
//   - stop: the server refuses this vault or these credentials; sync stops with a notice until the user
//     acts (the controller pauses). The outbox stays in IndexedDB untouched (§12.6 VAULT_NOT_FOUND,
//     RECIPIENT_REVOKED: kept, never discarded).
//   - hold "writes": outbox requests (prepare, PUT, commit, release) wait; reads (events, downloads) go on.
//   - hold "nonDeletes": QUOTA_EXCEEDED for a request that needs quota. Outbox entries with a revision
//     that is not a delete wait; delete-only entries (for_delete manifests, exempt within
//     DELETE_MANIFEST_ALLOWANCE, §11.1, §40.1) and the cleanup queue go on (§12.6 "los borrados siguen
//     permitidos"). A delete refused with QUOTA_EXCEEDED (the allowance is spent) holds "writes".
//   - hold "all": the outcome of the request is unknown (the network, a 5xx, an unreadable answer); every
//     request waits, with exponential backoff.
// A hold of `Infinity` waits for its condition to change (§11.1 "nunca en bucle automático"): a remote
// event (another device freed space, the deletion was cancelled), "Sync now", or a restart.

export type HoldScope = "all" | "writes" | "nonDeletes";

export interface Hold {
  readonly scope: HoldScope;
  readonly code: string;
  /** `now` (the runner's monotonic seconds) from which the request may go again; Infinity: until the condition changes. */
  readonly until: number;
}

export type Reaction =
  | { readonly kind: "stop"; readonly code: string }
  | { readonly kind: "hold"; readonly scope: HoldScope; readonly code: string; readonly delaySeconds: number };

/** The server refuses this vault or these credentials (§11.3, §12.6, §18.3): sync stops until the user acts. */
export const STOP_CODES: ReadonlySet<string> = new Set([
  "VAULT_NOT_FOUND",
  "NOT_FOUND",
  "UNAUTHENTICATED",
  "WRITE_CAPABILITY_REQUIRED",
  "SCOPE_REQUIRED",
  "RECIPIENT_REVOKED",
  "RECIPIENT_UNKNOWN",
  "RECIPIENT_NOT_ACTIVE",
  // session.ts, before a request is sent: the login ended on this device, or is now another session.
  "NOT_SIGNED_IN",
  "SESSION_CHANGED",
  // runner.ts OtherSyncToolError (§20.2): another tool seems to sync the vault folder; the user resolves it.
  "OTHER_SYNC_TOOL",
]);

/** The login's own refusals (session.ts `SessionError`), thrown by the session headers: stops. */
const LOGIN_STOP_CODES: ReadonlySet<string> = new Set(["NOT_SIGNED_IN", "SESSION_CHANGED"]);

/**
 * §18.3, §35.5, §35.8: this device's recipient is no longer authorized. Proving possession again, or
 * retrying, can only fail the same way: the answer is re-enrollment, which the host offers. The outbox
 * is kept for it (§18.3). RECIPIENT_NOT_ACTIVE is the client's own reading of the verified registry
 * (directory.ts); the other two are the Worker's (§11.3).
 */
export const REENROLL_CODES: ReadonlySet<string> = new Set(["RECIPIENT_REVOKED", "RECIPIENT_UNKNOWN", "RECIPIENT_NOT_ACTIVE"]);

/** True when `error` means this device must enroll again (§18.3) rather than retry. */
export function needsReenrollment(error: unknown): boolean {
  return REENROLL_CODES.has(failureOf(error).code);
}

/** Retried only when the condition changes (§11.1, §12.6): the user is told once. */
export const CONDITION_CODES: ReadonlySet<string> = new Set(["QUOTA_EXCEEDED", "VAULT_DELETING"]);

/** A wait the server set (retry-after, a lease): "Sync now" does not cut it short. */
export const SERVER_TIMED_CODES: ReadonlySet<string> = new Set(["RATE_LIMITED", "UPLOAD_IN_PROGRESS"]);

interface Backoff {
  readonly baseSeconds: number;
  readonly capSeconds: number;
}

/** Write-path codes retried on a timer (§12.6). */
const WRITE_BACKOFF: ReadonlyMap<string, Backoff> = new Map([
  ["RATE_LIMITED", { baseSeconds: 2, capSeconds: 300 }],
  // §12.6: after upload_lease_until; the Worker answers its distance as retryAfterSeconds.
  ["UPLOAD_IN_PROGRESS", { baseSeconds: 2, capSeconds: 300 }],
  ["UPLOAD_TIMEOUT", { baseSeconds: 2, capSeconds: 60 }],
  // Retried at once by the adapter (§11.2); a second failure in a row waits.
  ["BLOB_CORRUPT_RETRYABLE", { baseSeconds: 2, capSeconds: 60 }],
  ["BAD_UPLOAD_LENGTH", { baseSeconds: 2, capSeconds: 60 }],
  // §12.6: retry when pending uploads confirm (a remote event releases it early) or expire (≥ 1 h).
  ["PENDING_BUDGET_EXCEEDED", { baseSeconds: 2, capSeconds: 300 }],
]);

/** Outcome unknown (network, 5xx, unreadable answer): every request waits. */
const UNKNOWN_BACKOFF: Backoff = { baseSeconds: 2, capSeconds: 60 };

/** The protocol code of a failed request: the adapter's SyncBackendError code, UPLOAD_TIMEOUT, or UNREACHABLE. */
export function failureOf(error: unknown): { readonly code: string; readonly status?: number; readonly retryAfterSeconds?: number } {
  if (typeof error !== "object" || error === null) return { code: "UNREACHABLE" };
  const e = error as { name?: unknown; code?: unknown; status?: unknown; retryAfterSeconds?: unknown };
  const retryAfterSeconds = typeof e.retryAfterSeconds === "number" ? { retryAfterSeconds: e.retryAfterSeconds } : {};
  if (e.name === UPLOAD_TIMEOUT) return { code: "UPLOAD_TIMEOUT", ...retryAfterSeconds };
  // Not an answer to the request, but a refusal of this device itself: the capability's challenge
  // (§11.3 step 2, capability.ts) or the verified registry (directory.ts). Anything else they throw is
  // an unknown outcome, like the network.
  if ((e.name === "CapabilityError" || e.name === "DirectoryError") && typeof e.code === "string" && REENROLL_CODES.has(e.code)) return { code: e.code };
  if (e.name === "SessionError" && typeof e.code === "string" && LOGIN_STOP_CODES.has(e.code)) return { code: e.code };
  if (e.name === "OtherSyncToolError") return { code: "OTHER_SYNC_TOOL" };
  if (e.name !== "SyncBackendError" || typeof e.code !== "string") return { code: "UNREACHABLE" };
  return { code: e.code, ...(typeof e.status === "number" ? { status: e.status } : {}), ...retryAfterSeconds };
}

/** True when this error stops sync (the controller pauses with a notice instead of retrying). */
export function isStop(error: unknown): boolean {
  return reactionTo(failureOf(error), 1).kind === "stop";
}

/**
 * The reaction to the `failures`-th consecutive failure of one operation (1 for the first). `deletesOnly`:
 * the request was one a "nonDeletes" hold lets through (a delete-only entry's, or a release).
 */
export function reactionTo(
  failure: { readonly code: string; readonly status?: number; readonly retryAfterSeconds?: number },
  failures: number,
  request: { readonly deletesOnly?: boolean } = {},
): Reaction {
  const { code } = failure;
  // Any other 401/403 is a refusal of these credentials too (the gateway's own codes, §11.3).
  if (STOP_CODES.has(code) || failure.status === 401 || failure.status === 403) return { kind: "stop", code };
  if (code === "QUOTA_EXCEEDED" && !request.deletesOnly) return { kind: "hold", scope: "nonDeletes", code, delaySeconds: Infinity };
  if (CONDITION_CODES.has(code)) return { kind: "hold", scope: "writes", code, delaySeconds: Infinity };
  const write = WRITE_BACKOFF.get(code);
  const b = write ?? UNKNOWN_BACKOFF;
  // A server-given wait is honoured, never shortened; at least one second, so that "0" never loops.
  const delaySeconds = failure.retryAfterSeconds !== undefined ? Math.max(1, failure.retryAfterSeconds) : Math.min(b.capSeconds, b.baseSeconds * 2 ** Math.min(30, failures - 1));
  return { kind: "hold", scope: write ? "writes" : "all", code, delaySeconds };
}
