// §35.15: the lifecycle of a recovery request, as the Worker stores it and every reader judges it.
//
// "Matured" and "expired" are never stored transitions anyone has to run on time: they are what a
// `PENDING` row *is* at a given instant of the database clock, evaluated lazily under the account
// lock (§35.15 "Reloj"). These two predicates are that evaluation, written once, so the validator
// of §35.1.1, the envelope gate of `listEpochEnvelopes` and a client showing the request to its
// user can never disagree about the boundaries — `matures_at` is already mature, `expires_at` is
// already dead.
import type { RecoveryRequestKind } from "./operations.js";

/** §35.15: `recovery_requests.state`. Only `PENDING` is live; the other five are final. */
export type RecoveryRequestState = "PENDING" | "VETOED" | "CANCELLED" | "CONSUMED" | "INVALIDATED" | "EXPIRED";

/** One `recovery_requests` row, as step 0c reads it under the account lock. Dates are Unix ms. */
export interface StoredRecoveryRequest {
  readonly requestId: Uint8Array;
  readonly kind: RecoveryRequestKind;
  readonly rootGeneration: number;
  readonly state: RecoveryRequestState;
  readonly maturesAt: number;
  readonly expiresAt: number;
}

/**
 * §35.15: "viva" is `PENDING` and `now < expires_at`. Without a clock nothing is live: a caller that
 * forgot to read `now()` fails closed instead of treating every request as current.
 */
export function isLive(request: Pick<StoredRecoveryRequest, "state" | "expiresAt">, now: number | undefined): boolean {
  return now !== undefined && request.state === "PENDING" && now < request.expiresAt;
}

/** §35.15: "madura" is live and `matures_at <= now`. Not a stored state. */
export function isMature(
  request: Pick<StoredRecoveryRequest, "state" | "maturesAt" | "expiresAt">,
  now: number | undefined,
): boolean {
  return isLive(request, now) && request.maturesAt <= (now as number);
}

/**
 * What a reader shows: the stored state, with a `PENDING` row split by the clock into the three
 * moments of its life. `EXPIRED` covers a `PENDING` row past `expires_at` that no locked read has
 * rewritten yet — the lazy write of §35.15 changes nothing about what the row already means.
 */
export type RecoveryRequestPhase = "WAITING" | "MATURE" | Exclude<RecoveryRequestState, "PENDING">;

export function recoveryRequestPhase(
  request: Pick<StoredRecoveryRequest, "state" | "maturesAt" | "expiresAt">,
  now: number,
): RecoveryRequestPhase {
  if (request.state !== "PENDING") return request.state;
  if (!isLive(request, now)) return "EXPIRED";
  return isMature(request, now) ? "MATURE" : "WAITING";
}
