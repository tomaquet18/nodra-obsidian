import { v7 as uuidv7 } from "uuid";
import { type BlobOpener, httpSyncBackend } from "./http-backend.js";
import { type InstallationState, installationStore, openInstallation } from "./installation.js";
import type { LeaderMessage } from "./intents.js";
import { type Leadership, type LeadershipEnd, channelName, lead } from "./leadership.js";
import type { BlobCrypto, ChannelPort, DeviceLocalCrypto, FileSystem, LockManagerPort, SyncBackend } from "./ports.js";
import { reencryptPass } from "./reencrypt.js";
import { CONDITION_CODES, failureOf, isStop, needsReenrollment } from "./retry.js";
import type { ContentArrival } from "@nodra/sync-core";
import { type Client, OtherSyncToolError, type ShownArrival, activeHold, newMemory, releaseHolds, retryAt } from "./runner.js";
import { type SecurityAlert, type SecurityMonitor, httpSecurityEvents, securityMonitor } from "./security-events.js";
import { type VaultStore, adoptReplica, initVault, loadVault, openVaultStore } from "./store.js";

// The Phase 0 sync wiring of one vault, shared by the Obsidian plugin and the web app: the file system,
// Web Locks, BroadcastChannel, IndexedDB and fetch come in as ports. It leads through `lead()`, idles
// between ticks until woken, a manual sync or the poll interval (§13.5), and turns a failed leadership
// into a retry with backoff or a pause with a notice (NOTES question 55). The web adds the §20.2 heartbeat,
// the forced takeover (`takeOver`) and "a hidden leader starts no new work".
//
// Server answers (retry.ts, §12.6): the runner holds requests after a failure; the idle leader sleeps until
// the hold ends (never a tick per request), the status line names the wait, and a condition the user must
// know about (quota, vault scheduled for deletion) is noticed once until an answer shows it is over. A
// refusal of the vault or the credentials stops sync with a notice (the outbox stays in IndexedDB).

export interface Settings {
  readonly serverUrl: string;
  /**
   * §11.3: the login session's access token (a Supabase JWT; the dev identity provider's in the demo), or
   * a getter of the current one when the login renews it (`supabaseAuth().accessToken`).
   */
  readonly accessToken: string | (() => string | Promise<string>);
  readonly vaultId: string;
}

export interface Timing {
  /** §13.5: an active plugin polls every 30–60 s. */
  readonly pollMs: number;
  /** First retry delay after a failure; doubles each time. */
  readonly backoffMs: number;
  /** Consecutive failures before pausing. */
  readonly maxFailures: number;
}

export const DEFAULT_TIMING: Timing = { pollMs: 30_000, backoffMs: 2_000, maxFailures: 5 };

/**
 * The plan's limits the runner cuts batches and decides rule 8 with (§11.2, §12.1, §40.1). Never
 * hardcoded: they are server-side values, read from §22 getRootState (`sessionPlanLimits`, trust.ts).
 */
export interface PlanLimits {
  readonly pendingBudgetBytes: number;
  readonly maxBlobBytes: number;
}

export type SyncStatus = {
  readonly kind: "idle" | "syncing" | "paused" | "error";
  readonly detail?: string;
  /**
   * §18.3, §35.8: sync stopped because this device's recipient is revoked or unknown. The host offers
   * re-enrollment (§35.4 again, with the two secrets) instead of retrying; the outbox is kept for it.
   */
  readonly reenroll?: true;
  /**
   * The protocol code behind the status, when there is one (retry.ts): the hold an idle leader waits
   * on, or the refusal that stopped sync. For the host's own wording; `detail` is only for people.
   */
  readonly code?: string;
  /** An error that is being retried with backoff (failurePolicy "retry"), not a stop. */
  readonly retrying?: true;
  /**
   * §20.2 (code OTHER_SYNC_TOOL, NOTES question 419): what made sync stop because another tool seems to
   * sync the vault folder: the remote revisions found on disk before this replica wrote them, or the run
   * of renames of another replica. `acknowledgeOtherSyncTool` accepts exactly these arrivals and resumes.
   */
  readonly otherSyncTool?: { readonly arrivals: readonly ShownArrival[]; readonly renames: number };
};

/**
 * Who this replica is to the Worker: its `replica_id` (§6) and the headers of every request. A trusted
 * replica's is its own `recipient_id` and its headers carry its Write Capability (trust.ts,
 * `trustedReplica`); the dev stand-in (dev-crypto.ts, `devReplicaAuth`) is for tests only.
 */
export interface ReplicaAuth {
  readonly replicaId: string;
  headers(): Record<string, string> | Promise<Record<string, string>>;
  /** A request was refused for an authentication reason: true when a fresh proof makes it worth resending. */
  onAuthRefusal?(code: string): Promise<boolean>;
}

export interface SyncClientDeps {
  /** The vault's file system for the leader holding `epoch` (the web note store fences with it). */
  readonly fs: (o: { readonly epoch: number; readonly store: VaultStore; readonly dlc: DeviceLocalCrypto }) => FileSystem;
  readonly locks: LockManagerPort;
  readonly channel: (name: string) => ChannelPort & { close?(): void };
  readonly fetch: typeof fetch;
  readonly settings: Settings;
  /** §20.2 `install_ns`: `plugin:<installation_id hex>` or `web:<account_id hex>`. */
  readonly installNs: string;
  /** §6, §11.3: the replica id and the credentials of every request. */
  readonly auth: (installation: InstallationState) => ReplicaAuth;
  /**
   * The vault's `VaultCrypto` (§22): `realVaultCrypto` (directory.ts) for a trusted replica, which
   * needs the store this receives because the §28.3/§29/§32.1 pins live in it. There is no default:
   * the demo runs on the real one, and a test that wants `DevVaultCrypto` says so.
   */
  readonly vaultCrypto: (o: {
    readonly vaultId: string;
    readonly store: VaultStore;
    readonly replicaId: string;
  }) => (BlobCrypto & BlobOpener) | Promise<BlobCrypto & BlobOpener>;
  /**
   * §22 getRootState's plan limits (§40.1: adjustable without a protocol change). Asked once per
   * leadership, so a new leadership (start, takeover, retry after a failure, resume) uses the
   * current ones. Not persisted: the server's answer is the fact.
   */
  readonly planLimits: () => Promise<PlanLimits>;
  readonly indexedDB?: IDBFactory;
  readonly IDBKeyRange?: typeof IDBKeyRange;
  readonly timing?: Partial<Timing>;
  readonly onStatus?: (status: SyncStatus) => void;
  readonly notice?: (message: string) => void;
  readonly log?: Client["log"];
  /** Each end of this context's leadership (FENCED: another context took over; this one follows again). */
  readonly onLeadershipEnd?: (end: LeadershipEnd) => void;
  /**
   * Web only (§20.2 "Latido y toma forzosa"): the leader posts a heartbeat every `heartbeatMs` while
   * `active()` (visible), and starts no new work while hidden. Enables `takeOver`. Never in the plugin.
   */
  readonly web?: { readonly heartbeatMs: number; readonly active: () => boolean };
  /**
   * §20.2 "Nodra es el único sincronizador de la carpeta" at run time (runner.ts `otherSyncTool`, NOTES
   * question 419): stop sync when another tool seems to sync the vault folder. Off by default; the plugin
   * turns it on (the web has no disk another tool can write).
   */
  readonly detectOtherSyncTools?: boolean;
  /**
   * §37: each unacknowledged security event of the account, once per run of this client (so again
   * after a restart, until acknowledged). Only the user acknowledges, through
   * `acknowledgeSecurityEvent`; nothing here does it for them. Checked when the client opens, when
   * a vault's log carries a SECURITY event (§13.1), on "sync now", and at the next poll after a
   * check that failed. Absent: the client never reads the security log.
   */
  readonly onSecurityAlert?: (alert: SecurityAlert) => void;
  /**
   * §35.13 step 14, on the trusted client that switched to Private: the leader walks the server's
   * list of revisions still in a pre-switch epoch (`reencryptPass`) between ticks. Nothing about the
   * walk is persisted: each leadership (a start, a reload, a takeover after a crash) lists again, and
   * so do an EPOCH_ROTATED or SECURITY event in the vault's log and "sync now". A Managed account
   * answers INVALID_STATE, which reports nothing. Absent: the history is not re-encrypted here.
   */
  readonly reencryptHistory?: {
    /** §3.5: the visible progress, which is the server's count. */
    readonly onProgress?: (progress: ReencryptionProgress) => void;
    readonly inFlight?: number;
  };
}

/** §35.13 "el progreso visible es ese recuento": what the server still lists for this vault. */
export interface ReencryptionProgress {
  /** Revisions the last pass left listed (listed minus swapped). */
  readonly remaining: number;
  /** A pass found the list empty: this vault's history is under post-switch epochs only. */
  readonly done: boolean;
}

export interface Opened {
  readonly store: VaultStore;
  readonly installation: InstallationState;
}

export interface SyncClient {
  /** Wakes the idle leader (a local change); nothing while paused or stopped. */
  wake(): void;
  /** Sync now (§14 "sync manual"): wakes the leader at once; after a failure pause, resumes. */
  syncNow(): void;
  pause(): Promise<void>;
  resume(): void;
  /** Closes the disk queue, waits for the write in progress, releases the lock (§20.2), closes the store. */
  stop(): Promise<void>;
  status(): SyncStatus;
  /** True while this context is the vault's leader (after its leader_epoch increment). */
  leading(): boolean;
  /** Web only: request the lock with `{ steal: true }` (a visible follower after LEADER_TIMEOUT). */
  takeOver(): void;
  /** The vault store and installation this context opened (followers read and write intents through them). */
  opened(): Promise<Opened>;
  /** §37: the user acknowledged this event (persisted first, then sent; resent until the server answers). */
  acknowledgeSecurityEvent(id: number): Promise<void>;
  /**
   * §20.2: "I removed the other tool, resume". While stopped with OTHER_SYNC_TOOL, accepts exactly the
   * arrivals of the status (the leader persists them before anything else) and resumes; nothing otherwise.
   * Detection re-arms for any later arrival, and the run of renames starts again from 0.
   */
  acknowledgeOtherSyncTool(): void;
}

function signal() {
  let fired = false;
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return {
    promise,
    fired: () => fired,
    fire: () => {
      fired = true;
      resolve();
    },
  };
}

/** A timer that can be cancelled (so an idle wait never leaves one behind). */
function sleep(ms: number) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const promise = new Promise<void>((r) => (timer = setTimeout(r, ms)));
  return { promise, cancel: () => clearTimeout(timer) };
}

const hex8 = () => [...crypto.getRandomValues(new Uint8Array(4))].map((b) => b.toString(16).padStart(2, "0")).join("");

export function startSyncClient(d: SyncClientDeps): SyncClient {
  const timing = { ...DEFAULT_TIMING, ...d.timing };
  const { vaultId } = d.settings;
  const { installNs } = d;
  let status: SyncStatus = { kind: "syncing" };
  const setStatus = (s: SyncStatus) => {
    if (s.kind === status.kind && s.detail === status.detail) return;
    status = s;
    d.onStatus?.(s);
  };

  let halted = false; // paused by the user, by a failure, or stopped
  let stopped = false;
  let stealNext = false;
  let running: Promise<void> | null = null;
  let current: Leadership | null = null;
  let kick = signal();
  const wakeUp = () => kick.fire();

  // §35.13: a re-encryption pass is due (in memory only; the server's list is the fact).
  let reencryptDue = false;
  /** The last pass failed or made no progress: list again after the next sleep, never in a hot loop. */
  let reencryptAfterSleep = false;
  const reencrypt = d.reencryptHistory;

  // Opened once per controller; reused by every leadership (a new leadership reloads the facts).
  let opening: Promise<Opened & { backend: SyncBackend; blobs: BlobCrypto & BlobOpener; replicaId: string }> | null = null;
  /** The last backend error, shown while idle (the runner itself treats it as "outcome unknown"). */
  let backendProblem: string | null = null;
  /** The leading client (its in-memory holds) while this context leads. */
  let active: Client | null = null;
  /** Conditions already noticed; one goes when an answer shows it is over (the runner's "resume"). */
  const noticed = new Set<string>();
  /** §20.2: arrivals the user accepted, handed to the next leader (runner.ts `otherSyncTool`). */
  const acknowledgedArrivals: ContentArrival[] = [];

  // §37: the security log's reader, when the host shows alerts. Checks never overlap; one asked for
  // during a check runs right after it. `securityStale`: the last check failed, so the next poll retries.
  let security: SecurityMonitor | null = null;
  let securityStale = false;
  let checking: Promise<void> | null = null;
  let checkAgain = false;
  const checkSecurity = (): void => {
    if (security === null || stopped) return;
    if (checking !== null) {
      checkAgain = true;
      return;
    }
    const monitor = security;
    checking = monitor
      .check()
      .then(
        () => void (securityStale = false),
        () => void (securityStale = true),
      )
      .finally(() => {
        checking = null;
        if (checkAgain) {
          checkAgain = false;
          checkSecurity();
        }
      });
  };

  const open = async () => {
    const idb = d.indexedDB && d.IDBKeyRange ? { indexedDB: d.indexedDB, IDBKeyRange: d.IDBKeyRange } : {};
    const installation = await openInstallation({ installNs, vaultId, ...idb });
    // The store comes first now: the real VaultCrypto keeps its §32.1 pin in it (directory.ts).
    const store = await openVaultStore({ installNs, vaultId, ...idb });
    const auth = d.auth(installation);
    const crypto = await d.vaultCrypto({ vaultId, store, replicaId: auth.replicaId });
    const http = httpSyncBackend({
      baseUrl: d.settings.serverUrl.replace(/\/+$/, ""),
      vaultId,
      fetch: (input, init) => d.fetch(input, init),
      headers: () => auth.headers(),
      ...(auth.onAuthRefusal === undefined ? {} : { onAuthRefusal: (code: string) => auth.onAuthRefusal!(code) }),
      opener: crypto,
    });
    const tracked = Object.fromEntries(
      Object.entries(http).map(([name, fn]) => [
        name,
        async (...args: unknown[]) => {
          try {
            const out = await (fn as (...a: unknown[]) => Promise<unknown>)(...args);
            backendProblem = null;
            return out;
          } catch (e) {
            backendProblem = `server: ${describeError(e)}`;
            throw e;
          }
        },
      ]),
    ) as unknown as SyncBackend;
    // §13.1: a SECURITY event in the vault's log says the account's security log grew (§37).
    const listEvents = tracked.listEvents;
    const backend: SyncBackend = {
      ...tracked,
      async listEvents(after) {
        const page = await listEvents(after);
        if (page.kind === "PAGE" && page.events.some((e) => e.kind === "SECURITY")) checkSecurity();
        if (page.kind === "PAGE" && page.events.some((e) => e.kind === "SECURITY" || e.kind === "EPOCH_ROTATED")) reencryptDue = true;
        return page;
      },
    };
    const onAlert = d.onSecurityAlert;
    if (onAlert !== undefined) {
      security = securityMonitor({
        port: httpSecurityEvents({
          baseUrl: d.settings.serverUrl.replace(/\/+$/, ""),
          fetch: (input, init) => d.fetch(input, init),
          headers: () => auth.headers(),
          ...(auth.onAuthRefusal === undefined ? {} : { onAuthRefusal: (code: string) => auth.onAuthRefusal!(code) }),
        }),
        store: installationStore({ installNs, ...idb }),
        surface: (alert) => onAlert(alert),
      });
      checkSecurity();
    }
    const meta = await store.db.table("meta").get("meta");
    if (meta === undefined) {
      // The write epoch of a new local vault; afterwards the runner learns it (NOTES question 51).
      const { epochId } = await http.getVaultState();
      await initVault(store, { vaultId, replicaId: auth.replicaId, epochId });
    }
    return { store, backend, blobs: crypto, installation, replicaId: auth.replicaId };
  };
  const ensureOpen = () =>
    (opening ??= open().catch((e) => {
      opening = null;
      throw e;
    }));

  const leadOnce = async () => {
    const { store, backend, blobs, installation, replicaId } = await ensureOpen();
    if (halted) return { kind: "STOPPED" } as const; // paused or stopped while opening
    const channel = d.channel(channelName(installNs, vaultId));
    const steal = stealNext;
    stealNext = false;
    reencryptDue = reencrypt !== undefined; // each leadership lists again (§35.13 "Crash y reanudación")
    reencryptAfterSleep = false;
    const leadership = lead({
      locks: d.locks,
      channel,
      store,
      installNs,
      vaultId,
      fs: (epoch) => d.fs({ epoch, store, dlc: installation.dlc }),
      ...(steal ? { steal: true } : {}),
      client: async (epoch, fs, notify): Promise<Client> => (active = {
        shell: {
          fs,
          hasher: installation.hasher,
          dlc: installation.dlc,
          store,
          // After the leader_epoch increment, so the adoption is fenced like every other write (§20.2).
          state: await adoptReplica(store, installation.dlc, { ...(await loadVault(store, installation.dlc)), leaderEpoch: epoch }, replicaId),
          identities: new Map(),
          createdFolders: new Set(),
          hex8,
          newId: () => uuidv7(),
        },
        backend,
        blobs,
        now: () => performance.now() / 1000,
        // §22 getRootState, asked again by every leadership (§40.1: the server may change them).
        ...(await d.planLimits()),
        wallClock: () => Date.now(),
        memory: newMemory(),
        ...(d.detectOtherSyncTools === true ? { otherSyncTool: { acknowledged: acknowledgedArrivals } } : {}),
        notify,
        log: (event) => {
          const message = noticeFor(event, noticed);
          if (message !== null) d.notice?.(message);
          d.log?.(event);
        },
      }),
      idle: async (wake) => {
        failures = 0;
        if (securityStale) checkSecurity();
        if (kick.fired()) {
          kick = signal(); // woken during the tick: tick again
          return;
        }
        if (reencrypt !== undefined && reencryptDue && active !== null) {
          reencryptDue = false;
          const pass = await reencryptPass(active, reencrypt.inFlight === undefined ? {} : { inFlight: reencrypt.inFlight });
          if (!pass.notPrivate) reencrypt.onProgress?.({ remaining: Math.max(0, pass.listed - pass.swapped), done: pass.error === null && pass.listed === 0 });
          if (pass.error === null && pass.swapped > 0) {
            reencryptDue = true; // progress: tick, then list again
            return;
          }
          if (pass.error !== null || pass.listed > 0) reencryptAfterSleep = true;
        }
        const hold = active === null ? null : activeHold(active);
        const detail = hold !== null ? `waiting: ${HOLD_TEXT[hold.code] ?? `server: ${hold.code}`}` : backendProblem;
        setStatus(detail === null ? { kind: "idle" } : { kind: "idle", detail, ...(hold !== null ? { code: hold.code } : {}) });
        // Until the next poll (§13.5) or the end of a hold, whichever comes first.
        const retry = active === null ? null : retryAt(active);
        // A hold already over (its request is not due: the tick just found nothing to send) waits for the poll.
        const untilRetry = retry === null ? Infinity : (retry - active!.now()) * 1000;
        const poll = sleep(untilRetry > 0 ? Math.min(timing.pollMs, untilRetry) : timing.pollMs);
        await Promise.race([wake, kick.promise, poll.promise]);
        poll.cancel();
        kick = signal();
        if (reencryptAfterSleep) [reencryptAfterSleep, reencryptDue] = [false, true];
        // §20.2: a hidden leader starts no new work; a visible follower takes over after LEADER_TIMEOUT.
        while (d.web && !d.web.active() && !halted) {
          await kick.promise;
          kick = signal();
        }
        if (!halted) setStatus({ kind: "syncing" });
      },
    });
    current = leadership;
    const web = d.web;
    const beat = web
      ? setInterval(() => {
          if (leadership.leading() && web.active()) channel.postMessage({ kind: "heartbeat" } satisfies LeaderMessage);
        }, web.heartbeatMs)
      : null;
    const end = await leadership.ended;
    if (beat !== null) clearInterval(beat);
    d.onLeadershipEnd?.(end);
    if (current === leadership) current = null;
    active = null; // its holds die with it: a new leadership asks again
    channel.close?.();
    return end;
  };

  let failures = 0;
  const run = async () => {
    while (!halted) {
      let error: unknown;
      try {
        const end = await leadOnce();
        if (end.kind === "STOPPED") {
          if (stealNext && !halted) continue; // a queued request withdrawn to be made again with steal
          return;
        }
        if (end.kind === "FENCED") continue; // queue for the lock again, as a follower
        error = end.error;
      } catch (e) {
        error = e;
      }
      if (halted) return;
      const decision = failurePolicy(error, ++failures, timing);
      if (decision.kind === "pause") {
        halted = true;
        const code = isStop(error) ? { code: failureOf(error).code } : {};
        if (needsReenrollment(error)) {
          // Not something "resume" fixes: the host offers enrolling again (§18.3), once.
          setStatus({ kind: "error", detail: decision.reason, reenroll: true, ...code });
          return;
        }
        if (error instanceof OtherSyncToolError) {
          // §20.2: "el plugin pausa el sync de ese vault y avisa"; the user resolves it (acknowledgeOtherSyncTool).
          setStatus({ kind: "error", detail: decision.reason, ...code, otherSyncTool: { arrivals: error.arrivals, renames: error.renames } });
          d.notice?.("Nodra paused sync: another tool seems to be syncing this folder. Remove it, then resume from the Nodra panel.");
          return;
        }
        setStatus({ kind: "error", detail: decision.reason, ...code });
        d.notice?.(`Nodra paused sync: ${decision.reason}. Fix it, then resume or sync now.`);
        return;
      }
      setStatus({ kind: "error", detail: `retrying: ${describeError(error)}`, retrying: true });
      const wait = sleep(decision.delayMs);
      await Promise.race([wait.promise, kick.promise]);
      wait.cancel();
      kick = signal();
    }
  };

  const begin = () => {
    halted = false;
    failures = 0;
    setStatus({ kind: "syncing" });
    running = run();
  };
  const halt = async () => {
    halted = true;
    stealNext = false;
    const leadership = current;
    wakeUp();
    await leadership?.stop();
    await running;
  };

  begin();
  return {
    wake: () => {
      if (!halted) wakeUp();
    },
    syncNow() {
      if (stopped) return;
      checkSecurity();
      if (reencrypt !== undefined) reencryptDue = true;
      if (halted && status.kind === "error") begin();
      else {
        if (active !== null) releaseHolds(active, "user"); // the user says the condition may be over
        wakeUp();
      }
    },
    async pause() {
      if (halted) return;
      await halt();
      setStatus({ kind: "paused" });
    },
    resume() {
      if (!stopped && halted) begin();
    },
    async stop() {
      stopped = true;
      await halt();
      await checking;
      const o = await opening?.catch(() => null);
      o?.installation.close();
      o?.store.db.close();
    },
    status: () => status,
    leading: () => current?.leading() ?? false,
    takeOver() {
      if (!d.web || halted || current?.leading()) return;
      stealNext = true;
      void current?.stop(); // withdraws the queued request; `run` requests again with steal
    },
    opened: () => ensureOpen().then(({ store, installation }) => ({ store, installation })),
    acknowledgeOtherSyncTool() {
      const o = status.otherSyncTool;
      if (stopped || !halted || o === undefined) return;
      acknowledgedArrivals.push(...o.arrivals.map(({ objectId, revisionId }) => ({ objectId, revisionId })));
      begin();
    },
    async acknowledgeSecurityEvent(id) {
      await ensureOpen();
      if (security === null) throw new Error("this client does not read the security log (no onSecurityAlert)");
      await security.acknowledge(id);
    },
  };
}

// ---------------------------------------------------------------------------
// Failures (NOTES question 55): a persistent one pauses sync with a notice; anything else is retried a
// few times with backoff, then pauses too. Never a crash loop.

const PERSISTENT_CODES = ["EACCES", "EPERM", "ENOSPC", "EROFS", "EDQUOT"];
const PERSISTENT_NAMES = ["QuotaExceededError"];

export type FailureDecision = { readonly kind: "retry"; readonly delayMs: number } | { readonly kind: "pause"; readonly reason: string };

/** The status line while the runner waits (retry.ts codes). */
const HOLD_TEXT: Readonly<Record<string, string>> = {
  QUOTA_EXCEEDED: "storage quota exceeded; uploads resume when there is space",
  VAULT_DELETING: "vault scheduled for deletion; changes are kept, not uploaded",
  PENDING_BUDGET_EXCEEDED: "too many uploads pending on the server",
  RATE_LIMITED: "the server is limiting requests",
  UPLOAD_IN_PROGRESS: "an earlier upload is still in progress",
  UPLOAD_TIMEOUT: "an upload timed out",
  BLOB_CORRUPT_RETRYABLE: "an upload arrived damaged",
  BAD_UPLOAD_LENGTH: "an upload arrived damaged",
  UNREACHABLE: "server unreachable",
};

/** Why sync stopped (retry.ts STOP_CODES), for the pause notice. */
const STOP_TEXT: Readonly<Record<string, string>> = {
  VAULT_NOT_FOUND: "this vault no longer exists on the server; unsent changes are kept on this device",
  NOT_FOUND: "the server does not know this address or vault",
  UNAUTHENTICATED: "the server refused the session",
  NOT_SIGNED_IN: "signed out on this device; sign in again",
  SESSION_CHANGED: "the login is now another session; start sync again with it",
  WRITE_CAPABILITY_REQUIRED: "the server refused this device's write permission",
  SCOPE_REQUIRED: "this device may not write to this vault",
  RECIPIENT_REVOKED: "this device's access was revoked; unsent changes are kept until it is enrolled again",
  RECIPIENT_UNKNOWN: "this device is not enrolled; unsent changes are kept until it is enrolled again",
  RECIPIENT_NOT_ACTIVE: "this device's access was revoked; unsent changes are kept until it is enrolled again",
  OTHER_SYNC_TOOL: "another tool seems to be syncing this folder",
};

/** Conditions the user is told about once (§12.6: "notificar al usuario"). */
const CONDITION_NOTICE: Readonly<Record<string, string>> = {
  QUOTA_EXCEEDED: "Nodra: the storage quota is full. Local changes are kept and upload when there is space (Sync now retries).",
  VAULT_DELETING: "Nodra: this vault is scheduled for deletion. Local changes are kept but not uploaded.",
};

/** The notice for a runner event, or null; `noticed` keeps a condition from being told twice. */
export function noticeFor(event: { readonly kind: string; readonly detail?: string }, noticed: Set<string>): string | null {
  const detail = event.detail ?? "";
  switch (event.kind) {
    case "blocked": {
      // Rule 8: once per content (the block is a persisted fact, logged when it is recorded).
      const [reason, ...rest] = detail.split(" ");
      const path = rest.join(" ") || "a file";
      if (reason === "UPLOAD_TIMEOUT_MAX") return `Nodra does not sync ${path}: the connection is too slow for this file. It is retried when the file changes.`;
      return `Nodra does not sync ${path}: it is larger than the plan's file limit.`;
    }
    case "hold":
      if (!CONDITION_CODES.has(detail) || noticed.has(detail)) return null;
      noticed.add(detail);
      return CONDITION_NOTICE[detail] ?? null;
    case "resume":
      noticed.delete(detail);
      return null;
    case "rejected:INVALID_BATCH":
      // §12.6: a client bug; the entry is retired and its objects planned again.
      return "Nodra: the server rejected an upload as malformed (a client bug). It is retried as a new upload; please report it.";
    default:
      return null;
  }
}

export function describeError(error: unknown): string {
  if (isStop(error)) {
    const { code } = failureOf(error);
    return STOP_TEXT[code] ?? `the server refused: ${code}`;
  }
  if (error instanceof Error) {
    const code = (error as { code?: unknown }).code;
    return typeof code === "string" && !error.message.includes(code) ? `${code}: ${error.message}` : error.message;
  }
  return String(error);
}

/** Persistent: the disk refuses (permissions, full, read-only), IndexedDB is full, or the server refuses these credentials. */
export function isPersistentError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const e = error as { code?: unknown; name?: unknown; message?: unknown; status?: unknown; inner?: unknown };
  if (typeof e.code === "string" && PERSISTENT_CODES.includes(e.code)) return true;
  if (typeof e.name === "string" && PERSISTENT_NAMES.includes(e.name)) return true;
  if (e.name === "SyncBackendError" && (e.status === 401 || e.status === 403 || e.status === 404)) return true;
  if (isStop(error)) return true;
  if (typeof e.message === "string" && PERSISTENT_CODES.some((c) => new RegExp(`\\b${c}\\b`).test(e.message as string))) return true;
  return isPersistentError(e.inner ?? null);
}

export function failurePolicy(error: unknown, consecutiveFailures: number, o: { readonly backoffMs: number; readonly maxFailures: number }): FailureDecision {
  if (isPersistentError(error)) return { kind: "pause", reason: describeError(error) };
  if (consecutiveFailures >= o.maxFailures) return { kind: "pause", reason: `${consecutiveFailures} failures in a row; last: ${describeError(error)}` };
  return { kind: "retry", delayMs: o.backoffMs * 2 ** (consecutiveFailures - 1) };
}
