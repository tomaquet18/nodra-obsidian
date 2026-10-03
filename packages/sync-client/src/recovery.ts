// §35.15 (ADR-022) on the client: the request, veto and cancellation of a delayed recovery operation,
// and the pending request every active client must show (§35.15 "Notificaciones").
//
// Two authorities sign these records, and each is unlocked the way the rest of this package unlocks it:
//   - the root (role 1): Root Unlock with the two secrets, the chains proved against the §26 config
//     (`unlockAccount`), the Signing handle for this call only. It requests a kit replacement or a
//     SWITCH_TO_MANAGED, cancels its own request, and vetoes a reset — the veto from any client with
//     Root Unlock (ACCOUNT_SECURITY), not only a trusted one, because it creates no envelope;
//   - the Recovery Kit (role 3): opened against the root in force (§27.3 through `openRecoveryKit`),
//     a RECOVERY_CONTROL capability proved with its decrypt key, its Recovery Authority signing the
//     record. It requests a reset, cancels it, and vetoes a kit replacement or a switch. The kit is
//     never stored (§27.1): its handles live in this module's locals for one call.
//
// Nothing here is persisted. A record is idempotent in what matters: a lost answer is resent with the
// SAME bytes within the call (the stored result comes back if it landed), and a second attempt later
// is judged against what `getRootState` then says — a request that is already ours is ours, a veto of
// a request that is no longer live has nothing left to do. Which of two attempts lands changes nothing
// the user keeps, so no §35.1 row is needed (as in `recoverManagedAccount`).
import { openRecoveryKit, proveCapabilityWithDecryptKey, recoveryRequestPhase, requestRecovery, rootRecipients, cancelRecovery, verifyRecoveryRequest, vetoRecovery } from "@nodra/key-lifecycle";
import type { BuiltRecoveryRecord, RecoveryRecordBundleRequest, RecoveryRecordView, RecoveryRequestKind } from "@nodra/key-lifecycle";
import * as P from "@nodra/protocol";
import { v7 as uuidv7 } from "uuid";
import { type CapabilitySession, capabilitySession } from "./capability.js";
import { fromHex, toHex, uuidToBytes } from "./manifest.js";
import {
  type AccountPins,
  type AccountSecrets,
  type AccountTransport,
  type Submitted,
  type TrustSession,
  TrustError,
  accountCapability,
  accountTransport,
  provedRegistry,
  provedRoot,
  submit,
  trustedCapability,
  trustedIdentity,
  unlockAccount,
  uuidOf,
} from "./trust.js";
import type { IdbDeps, InstallationStore } from "./installation.js";
import { installationStore } from "./installation.js";

/** The credential that vetoes a request of each kind (§35.15): the authority the requester lacks. */
export type VetoCredential = "SECRETS" | "RECOVERY_KIT";

/** A live recovery request, as a client shows it. The dates are the server's (§35.15: not signed). */
export interface PendingRecovery {
  readonly requestId: string;
  readonly kind: RecoveryRequestKind;
  readonly requestedAt: number;
  readonly maturesAt: number;
  readonly expiresAt: number;
  /** WAITING until `maturesAt`; MATURE until `expiresAt`, when the requester may run the operation. */
  readonly phase: "WAITING" | "MATURE";
  /** What the user is asked for to veto it: Password + Secret Key for a reset, the Recovery Kit otherwise. */
  readonly vetoWith: VetoCredential;
}

export interface RecoveryContext extends TrustSession {
  /** Tests only: the transport, when it is not `httpDirectory` over `fetch`. */
  readonly transport?: AccountTransport;
  /** This installation's pins (§28.3), when it holds them: the root is then proved through them. */
  readonly pins?: AccountPins;
}

const vetoWith = (kind: RecoveryRequestKind): VetoCredential => (kind === "RECOVERY_RESET" ? "SECRETS" : "RECOVERY_KIT");

/**
 * §35.15 "Al recibir uno de los tres eventos *_REQUESTED, todo cliente activo DEBE mostrarlo": the live
 * request of `getRootState`, if its signature verifies against the root chain proved from GENESIS
 * (through the pins when given). One that does not verify is not a request of this account's
 * authorities — the Worker verified it when it was filed — so it is not shown as one.
 */
export async function pendingRecovery(o: RecoveryContext, now: number = Date.now()): Promise<PendingRecovery | null> {
  const transport = o.transport ?? accountTransport(o);
  const live = (await transport.rootState()).recoveryRequest;
  if (live === null) return null;
  const phase = recoveryRequestPhase({ state: "PENDING", maturesAt: live.maturesAt, expiresAt: live.expiresAt }, now);
  if (phase !== "WAITING" && phase !== "MATURE") return null;
  const account = uuidToBytes(o.accountId);
  const root = await provedRoot(transport, account, o.pins);
  const verified = await verifyRecoveryRequest(account, root.root.descriptor, root.root.rootHash, {
    requestId: uuidToBytes(live.requestId),
    kind: live.kind,
    rootGeneration: live.rootGeneration,
    rootHash: fromHex(live.rootHash),
    signature: fromHex(live.signature),
  });
  if (!verified) return null;
  return { requestId: live.requestId, kind: live.kind, requestedAt: live.requestedAt, maturesAt: live.maturesAt, expiresAt: live.expiresAt, phase, vetoWith: vetoWith(live.kind) };
}

/**
 * Phase 2's precondition, read before a heavy bundle is built (§35.7, §35.9, §35.14): null when a
 * matured request of `kind` is live; otherwise the TrustError the Worker's answer would turn into.
 * Only an early answer for the user: the Worker decides again in §35.1.1 step 0c.
 */
export async function maturedRequestProblem(o: RecoveryContext, kind: RecoveryRequestKind, now: number = Date.now()): Promise<TrustError | null> {
  const pending = await pendingRecovery(o, now);
  if (pending === null || pending.kind !== kind) {
    return new TrustError("RECOVERY_REQUEST_REQUIRED", `${kind} in a Private account needs a request that has waited the recovery delay (§35.15): request it first`);
  }
  if (pending.phase === "WAITING") return new TrustError("RECOVERY_NOT_MATURE", `the ${kind} request matures at ${new Date(pending.maturesAt).toISOString()}`);
  return null;
}

// --- Sending ---------------------------------------------------------------------------------------

const MAX_SENDS = 3;
const MAX_BUILDS = 3;

/** One built record and the capability that carries it, for one attempt. */
interface Attempt {
  readonly built: BuiltRecoveryRecord;
  readonly capability: CapabilitySession;
}

/** The SAME bytes up to {@link MAX_SENDS} times until the Worker answers (§35.1 "Respuesta perdida"). */
async function answer(o: TrustSession, attempt: Attempt, operation: string): Promise<P.SecurityBundleResponse> {
  const bundle = toHex(attempt.built.serializedBundle);
  let detail = "";
  for (let i = 0; i < MAX_SENDS; i++) {
    const submitted = await submit(o, await attempt.capability.headers(), bundle).catch((e: unknown): Submitted => ({ kind: "NO_ANSWER", detail: String(e) }));
    if (submitted.kind === "ANSWER") return submitted.answer;
    detail = submitted.detail;
  }
  throw new TrustError("OPERATION_PENDING", `no answer to ${operation} (${detail}); try again: a request that landed is found, a veto of an ended request has nothing to do`);
}

/**
 * Builds and sends a record until it is applied or its effect is already there. `done` reads the live
 * request after a definitive refusal and says whether the record's purpose is met anyway (a lost
 * answer to a request, a veto racing another). A stale answer (the root, registry or config moved)
 * builds it again from a fresh view.
 */
async function deliver(
  o: RecoveryContext,
  operation: string,
  attempt: () => Promise<Attempt>,
  done: (live: PendingRecovery | null) => boolean,
): Promise<P.SecurityBundleResponse | null> {
  let last = "";
  for (let builds = 0; builds < MAX_BUILDS; builds++) {
    const a = await attempt();
    try {
      const answered = await answer(o, a, operation);
      if (answered.ok) return answered;
      if (done(await pendingRecovery(o))) return null;
      if (answered.code === "RECOVERY_REQUEST_EXISTS") throw new TrustError("RECOVERY_REQUEST_EXISTS", `another recovery request is live (${answered.liveRequest?.kind ?? "unknown kind"}): veto or cancel it first`);
      if (!answered.retryable) throw new TrustError("OPERATION_REJECTED", `${operation} refused: ${answered.code}`);
      last = answered.code;
    } finally {
      a.capability.forget();
    }
  }
  throw new TrustError("OPERATION_REJECTED", `${operation} was answered ${last || "stale"} ${MAX_BUILDS} times in a row`);
}

// --- Role 1: the root (Password + Secret Key) ------------------------------------------------------

export interface SecretsRecoveryOptions extends RecoveryContext, IdbDeps {
  readonly installNs: string;
  /** §35.15: Root Unlock of the Private account, for this call only; never stored (§20.1). */
  readonly secrets: AccountSecrets;
  /** Tests only: the §20.2 per-installation store. */
  readonly installation?: InstallationStore;
}

/**
 * A role-1 attempt: Root Unlock proved against the §26 config, the Signing handle signs, and the
 * capability is this device's own (TRUSTED_SECURITY) if it is trusted, else the ACCOUNT recipient's
 * (ACCOUNT_SECURITY) — unless `trustedOnly`, which a request needs (§35.15: role 1 · TRUSTED_SECURITY).
 */
async function rootAttempt(
  o: SecretsRecoveryOptions,
  trustedOnly: boolean,
  sign: (request: RecoveryRecordBundleRequest) => Promise<BuiltRecoveryRecord>,
  record: { readonly requestId: string; readonly kind: RecoveryRequestKind },
): Promise<Attempt> {
  const identity = await trustedIdentity({ ...o, installation: o.installation ?? installationStore(o) });
  if (identity === null && trustedOnly) throw new TrustError("NOT_TRUSTED", "a kit replacement or a switch to Managed is requested from a trusted client (§35.9, §35.14)");
  const unlocked = await unlockAccount(o.transport ?? accountTransport(o), o.accountId, o.secrets, o.pins);
  if (unlocked.mode !== "PRIVATE") throw new TrustError("WRONG_MODE", "delay and veto exist only in a Private account (§35.15)");
  const built = await sign({ view: unlocked.view, bundleId: uuidToBytes(uuidv7()), requestId: uuidToBytes(record.requestId), kind: record.kind, signingKey: unlocked.unlock.signingKey });
  const capability = identity !== null ? trustedCapability(o, identity) : await accountCapability(o, unlocked);
  return { built, capability };
}

/** What `requestRecoveryWithSecrets` and `requestRecoveryResetWithKit` filed. */
export interface FiledRecovery {
  readonly requestId: string;
  readonly kind: RecoveryRequestKind;
  readonly maturesAt: number;
  readonly expiresAt: number;
}

function filed(requestId: string, kind: RecoveryRequestKind, answered: P.SecurityBundleResponse | null, live: PendingRecovery | null): FiledRecovery {
  if (answered?.ok === true && answered.recoveryRequest !== undefined) {
    return { requestId, kind, maturesAt: answered.recoveryRequest.maturesAt, expiresAt: answered.recoveryRequest.expiresAt };
  }
  if (live !== null && live.requestId === requestId) return { requestId, kind, maturesAt: live.maturesAt, expiresAt: live.expiresAt };
  throw new TrustError("SERVER_REFUSED", "the request was applied but the server shows no such live request");
}

/**
 * §35.9 / §35.14 phase 1, from a trusted client: a request signed with the Account Signing Key in force.
 * The Recovery Kit in force may veto it until it matures (`RECOVERY_DELAY`); after that, the operation
 * itself runs (`switchAccountToManaged`, or a kit replacement).
 */
export async function requestRecoveryWithSecrets(o: SecretsRecoveryOptions & { readonly kind: "RECOVERY_KIT_REPLACEMENT" | "SWITCH_TO_MANAGED" }): Promise<FiledRecovery> {
  const requestId = uuidv7();
  const mine = (live: PendingRecovery | null) => live !== null && live.requestId === requestId;
  const answered = await deliver(o, "RECOVERY_REQUEST", () => rootAttempt(o, true, requestRecovery, { requestId, kind: o.kind }), mine);
  return filed(requestId, o.kind, answered, answered === null ? await pendingRecovery(o) : null);
}

/** No live request with this id any more: a veto or cancel has nothing left to do. */
const ended = (requestId: string) => (live: PendingRecovery | null) => live === null || live.requestId !== requestId;

/**
 * §35.15 the veto of a RECOVERY_RESET, with Password + Secret Key (role 1), from any client with Root
 * Unlock. Resolves once the request is no longer live — vetoed by this call, or ended otherwise.
 */
export async function vetoRecoveryWithSecrets(o: SecretsRecoveryOptions & { readonly request: Pick<PendingRecovery, "requestId" | "kind"> }): Promise<void> {
  if (o.request.kind !== "RECOVERY_RESET") throw new TrustError("WRONG_MODE", `a ${o.request.kind} request is vetoed with the Recovery Kit (§35.15)`);
  await deliver(o, "RECOVERY_VETO", () => rootAttempt(o, false, vetoRecovery, o.request), ended(o.request.requestId));
}

/** §35.15 the requester takes back its own kit-replacement or switch request (role 1). */
export async function cancelRecoveryWithSecrets(o: SecretsRecoveryOptions & { readonly request: Pick<PendingRecovery, "requestId" | "kind"> }): Promise<void> {
  if (o.request.kind === "RECOVERY_RESET") throw new TrustError("WRONG_MODE", "a reset request is cancelled with the Recovery Kit that filed it (§35.15)");
  await deliver(o, "RECOVERY_CANCEL", () => rootAttempt(o, false, cancelRecovery, o.request), ended(o.request.requestId));
}

// --- Role 3: the Recovery Kit ------------------------------------------------------------------------

export interface KitRecoveryOptions extends RecoveryContext {
  /** §27.1: the Recovery Kit exactly as delivered (the file's bytes). Used for this call, never stored. */
  readonly recoveryKit: Uint8Array;
}

/**
 * A role-3 attempt: the root chain proved from GENESIS (through the pins when given), the kit opened
 * and checked against the root in force (§27.3 steps 1–2, against the kit's own genesis), a
 * RECOVERY_CONTROL capability proved with its decrypt key, and its Recovery Authority signing.
 */
async function kitAttempt(
  o: KitRecoveryOptions,
  sign: (request: RecoveryRecordBundleRequest) => Promise<BuiltRecoveryRecord>,
  record: { readonly requestId: string; readonly kind: RecoveryRequestKind },
): Promise<Attempt> {
  const transport = o.transport ?? accountTransport(o);
  const account = uuidToBytes(o.accountId);
  const state = await transport.rootState();
  if (state.configVersion === null) throw new TrustError("NO_ACCOUNT_ROOT", "this account has no root yet (§35.2)");
  const root = await provedRoot(transport, account, o.pins);
  if (root.mode !== "PRIVATE") throw new TrustError("WRONG_MODE", "delay and veto exist only in a Private account (§35.15)");
  const registry = await provedRegistry(transport, account, root, o.pins);
  const opened = await openRecoveryKit({
    serialized: o.recoveryKit,
    accountId: account,
    genesisRootHash: root.root.genesisRootHash ?? root.root.rootHash,
    currentDescriptor: root.root.descriptor,
  });
  if (!opened.ok) throw new TrustError("RECOVERY_KIT_REJECTED", `${opened.failure.code}: ${opened.failure.message}`);
  const view: RecoveryRecordView = {
    accountId: account,
    root: root.root.descriptor,
    rootHash: root.root.rootHash,
    registry: registry.registry,
    // §26: the plaintext copy in force; a record installs no config, it only carries the CAS triple.
    configVersion: state.configVersion,
  };
  const built = await sign({ view, bundleId: uuidToBytes(uuidv7()), requestId: uuidToBytes(record.requestId), kind: record.kind, signingKey: opened.value.authorityKey });
  // §11.3: RECOVERY_CONTROL, proved with the kit's decrypt key; no replica.
  const capability = capabilitySession({
    baseUrl: o.baseUrl,
    fetch: o.fetch,
    sessionHeaders: o.sessionHeaders,
    accountId: o.accountId,
    serverSessionId: o.serverSessionId,
    recipientId: uuidOf((await rootRecipients(root.root.descriptor))[1]!.recipientId),
    prove: (input) => proveCapabilityWithDecryptKey({ privateKey: opened.value.encryptionKey, ...input }),
  });
  return { built, capability };
}

/** §35.7 phase 1: a RECOVERY_RESET request signed with the Recovery Kit in force (login + kit). */
export async function requestRecoveryResetWithKit(o: KitRecoveryOptions): Promise<FiledRecovery> {
  const requestId = uuidv7();
  const mine = (live: PendingRecovery | null) => live !== null && live.requestId === requestId;
  const answered = await deliver(o, "RECOVERY_REQUEST", () => kitAttempt(o, requestRecovery, { requestId, kind: "RECOVERY_RESET" }), mine);
  return filed(requestId, "RECOVERY_RESET", answered, answered === null ? await pendingRecovery(o) : null);
}

/** §35.15 the veto of a kit replacement or a SWITCH_TO_MANAGED, with the Recovery Kit in force (role 3). */
export async function vetoRecoveryWithKit(o: KitRecoveryOptions & { readonly request: Pick<PendingRecovery, "requestId" | "kind"> }): Promise<void> {
  if (o.request.kind === "RECOVERY_RESET") throw new TrustError("WRONG_MODE", "a reset request is vetoed with Password + Secret Key (§35.15)");
  await deliver(o, "RECOVERY_VETO", () => kitAttempt(o, vetoRecovery, o.request), ended(o.request.requestId));
}

/** §35.15 the kit holder takes back its own reset request (role 3). */
export async function cancelRecoveryWithKit(o: KitRecoveryOptions & { readonly request: Pick<PendingRecovery, "requestId" | "kind"> }): Promise<void> {
  if (o.request.kind !== "RECOVERY_RESET") throw new TrustError("WRONG_MODE", `a ${o.request.kind} request is cancelled with Password + Secret Key (§35.15)`);
  await deliver(o, "RECOVERY_CANCEL", () => kitAttempt(o, cancelRecovery, o.request), ended(o.request.requestId));
}
