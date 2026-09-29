import {
  type AccountProtection,
  type AccountSecrets,
  type AccountState,
  type ChannelPort,
  type Device,
  type Client,
  type FileSystem,
  type LockManagerPort,
  type RecoveryPhase,
  type Settings as SyncSettings,
  type SyncClientDeps,
  type SyncStatus,
  type Timing as ClientTiming,
  type TrustSession,
  DEFAULT_TIMING as CLIENT_TIMING,
  accessTokenSession,
  accountProtection,
  accountState,
  createVaultFromClient,
  enrollReplica,
  listDevices,
  recoverManagedAccountWithRelogin,
  revokeDevice,
  settleSecurityBundle,
  startSyncClient,
  trustedIdentity,
  trustedReplica,
  vaultLimitProblem,
} from "@nodra/sync-client";
import { debounce } from "lodash-es";

// The plugin's sync wiring, free of the `obsidian` runtime so it runs in tests. The shared controller
// (sync-client `startSyncClient`) leads through `lead()` (never with `steal`: §20.2 plugin); here vault
// events become debounced wake-ups (§12.2 rule 2 hints, §14).

export type { SecurityAlert, SyncStatus } from "@nodra/sync-client";

/** Settings over a frozen access token (tests, and the §35.7 recovery, which swaps its token itself). */
export type Settings = SyncSettings & { readonly accessToken: string };

export interface Timing extends ClientTiming {
  /** §14 quiet period. */
  readonly quietMs: number;
  /** §14 maximum dirty window. */
  readonly maxDirtyMs: number;
}

export const DEFAULT_TIMING: Timing = { ...CLIENT_TIMING, quietMs: 3_000, maxDirtyMs: 30_000 };

export interface SyncDeps extends Pick<SyncClientDeps, "auth" | "vaultCrypto" | "planLimits" | "onSecurityAlert"> {
  readonly fs: FileSystem;
  readonly locks: LockManagerPort;
  readonly channel: (name: string) => ChannelPort & { close?(): void };
  readonly fetch: typeof fetch;
  /** The access token may be a getter: the login's, which renews (login.ts). */
  readonly settings: SyncSettings;
  /** UUIDv7 kept in Obsidian's per-vault, per-device local storage (§20.2 `install_ns`). */
  readonly installationId: string;
  readonly indexedDB?: IDBFactory;
  readonly IDBKeyRange?: typeof IDBKeyRange;
  readonly timing?: Partial<Timing>;
  readonly onStatus?: (status: SyncStatus) => void;
  readonly notice?: (message: string) => void;
  readonly log?: Client["log"];
}

export interface SyncController {
  /** A vault event: debounced (§14), it wakes the idle leader. */
  hint(): void;
  /** Sync now (§14 "sync manual"): wakes the leader at once; after a failure pause, resumes. */
  syncNow(): void;
  pause(): Promise<void>;
  resume(): void;
  /** onunload: closes the disk queue, waits for the write in progress, releases the lock (§20.2). */
  stop(): Promise<void>;
  status(): SyncStatus;
  /** §37: the user acknowledged this security event (the only way one is acknowledged). */
  acknowledgeSecurityEvent(id: number): Promise<void>;
}

/** §14 in one place: quiet period, and a maximum dirty window after which a burst fires anyway. */
export function hintDebouncer(fire: () => void, t: Pick<Timing, "quietMs" | "maxDirtyMs">) {
  return debounce(fire, t.quietMs, { maxWait: t.maxDirtyMs });
}

/** §20.2: `plugin:<installation_id hex>`, fixed for the life of the installation. */
export const pluginInstallNs = (installationId: string) => `plugin:${installationId.replaceAll("-", "")}`;

export function startSync(d: SyncDeps): SyncController {
  const timing = { ...DEFAULT_TIMING, ...d.timing };
  const { fs, installationId, ...rest } = d;
  const c = startSyncClient({ ...rest, timing, installNs: pluginInstallNs(installationId), fs: () => fs });
  const debounced = hintDebouncer(() => c.wake(), timing);
  return {
    hint: () => debounced(),
    syncNow() {
      debounced.cancel();
      c.syncNow();
    },
    async pause() {
      debounced.cancel();
      await c.pause();
    },
    resume: () => c.resume(),
    async stop() {
      debounced.cancel();
      await c.stop();
    },
    status: () => c.status(),
    acknowledgeSecurityEvent: (id) => c.acknowledgeSecurityEvent(id),
  };
}

interface Connection {
  readonly settings: SyncSettings;
  /** This installation's login session (login.ts `loginSession`); without it, `settings` holds a frozen token. */
  readonly session?: TrustSession;
  readonly installationId: string;
  readonly fetch: typeof fetch;
  readonly indexedDB?: IDBFactory;
  readonly IDBKeyRange?: typeof IDBKeyRange;
}

const idbOf = (c: Connection) => (c.indexedDB && c.IDBKeyRange ? { indexedDB: c.indexedDB, IDBKeyRange: c.IDBKeyRange } : {});

function sessionOf(c: Connection): TrustSession {
  if (c.session !== undefined) return c.session;
  const { serverUrl, accessToken } = c.settings;
  if (typeof accessToken !== "string") throw new Error("a renewing login needs its loginSession");
  return accessTokenSession({ serverUrl, accessToken, fetch: c.fetch });
}

/**
 * Which Nodra vault this Obsidian vault syncs to, chosen ONCE: a folder synced to one vault and then
 * pointed at another would upload all its notes into the second as new files. The choice in the
 * settings is kept whatever the account lists (a vault that is gone answers VAULT_NOT_FOUND and sync
 * stops; it never falls back to another vault). With none: the only live vault is taken and
 * remembered; with several the user is asked; with none live there is nothing to sync.
 */
export type VaultChoice =
  | { readonly kind: "SYNC"; readonly vaultId: string; readonly remember: boolean }
  | { readonly kind: "ASK"; readonly vaults: readonly string[] }
  | { readonly kind: "NONE" };

export function chooseVault(chosen: string, vaults: AccountState["vaults"]): VaultChoice {
  if (chosen !== "") return { kind: "SYNC", vaultId: chosen, remember: false };
  const live = vaults.filter((v) => v.state === "ACTIVE").map((v) => v.vaultId);
  if (live.length === 0) return { kind: "NONE" };
  if (live.length === 1) return { kind: "SYNC", vaultId: live[0]!, remember: true };
  return { kind: "ASK", vaults: live };
}

/**
 * The plugin's trusted replica (§35.4 done), or null when this installation has not enrolled yet, and
 * the vault decision (`chooseVault`). The session is this installation's own login (§11.3), never
 * another client's. A security bundle this installation sent without an answer is resent first (§35.1).
 */
export async function trustedPlugin(c: Connection): Promise<{ readonly session: TrustSession; readonly replica: Pick<SyncClientDeps, "auth" | "vaultCrypto" | "planLimits"> | null; readonly vault: VaultChoice }> {
  const session = sessionOf(c);
  const installNs = pluginInstallNs(c.installationId);
  await settleSecurityBundle({ ...session, ...idbOf(c), installNs }).catch(() => null);
  const identity = await trustedIdentity({ installNs, ...idbOf(c) });
  const vault = chooseVault(c.settings.vaultId, c.settings.vaultId !== "" ? [] : (await accountState(session)).vaults);
  return { session, replica: identity === null ? null : trustedReplica(session, identity), vault };
}

const accountOf = (c: Connection) => ({ ...sessionOf(c), ...idbOf(c), installNs: pluginInstallNs(c.installationId) });

/** §35.1: the account's devices from the verified registry, this installation marked. */
export const pluginDevices = (c: Connection): Promise<readonly Device[]> => listDevices(accountOf(c));

/**
 * §3.6: the account's protection mode as the verified root chain derives it (through this
 * installation's pins once enrolled). It decides whether the user is asked for the two secrets.
 */
export const pluginProtection = (c: Connection): Promise<AccountProtection> => accountProtection(accountOf(c));

/** The two secrets, only for a Private account (§24); a Managed one unlocks with the login (§24.2). */
const secretsOf = (c: { readonly secrets?: AccountSecrets | undefined }) => (c.secrets === undefined ? {} : { secrets: c.secrets });

/** §35.5 from this plugin; on a Private account with the two secrets typed for this call only (§20.1). */
export const revokeFromPlugin = (c: Connection & { readonly secrets?: AccountSecrets | undefined; readonly recipientId: string }): Promise<void> =>
  revokeDevice({ ...accountOf(c), ...secretsOf(c), recipientId: c.recipientId });

/** §35.10 step 1 from getRootState: why no vault can be created, or null. */
export const pluginVaultLimit = (c: Connection): Promise<string | null> => vaultLimitProblem(accountOf(c));

/** §35.10 from this plugin: the new vault's id (other Obsidian vaults can then choose it). */
export const createVaultFromPlugin = (c: Connection & { readonly secrets?: AccountSecrets | undefined }): Promise<string> => createVaultFromClient({ ...accountOf(c), ...secretsOf(c) });

/**
 * §35.4 "alta de plugin" (and §35.8 again) for this installation: a Managed account with the login
 * alone (§24.2), a Private one with the secrets the user typed for this call only.
 */
export async function enrollPlugin(c: Connection & { readonly secrets?: AccountSecrets | undefined; readonly label: string }): Promise<void> {
  await enrollReplica({ ...sessionOf(c), ...idbOf(c), installNs: pluginInstallNs(c.installationId), type: "PLUGIN_INSTALLATION", label: c.label, ...secretsOf(c) });
}

/**
 * §35.7 "Modo Managed" from this plugin, trusted or not: the login alone, with a primary authentication
 * of the last 5 minutes; on REAUTH_REQUIRED `relogin` asks the user to log in again and yields the new
 * access token (null: they did not). Resolves with the access token that recovered the account. Every
 * device ends REVOKED, this installation too, which then enrolls again with that login (§35.8, §24.2).
 */
export const recoverFromPlugin = (
  c: { readonly settings: Pick<Settings, "serverUrl" | "accessToken">; readonly fetch: typeof fetch; readonly relogin: () => Promise<string | null>; readonly onPhase?: (phase: RecoveryPhase) => void },
): Promise<{ readonly accessToken: string }> =>
  recoverManagedAccountWithRelogin({ serverUrl: c.settings.serverUrl, accessToken: c.settings.accessToken, fetch: c.fetch, relogin: c.relogin, ...(c.onPhase ? { onPhase: c.onPhase } : {}) });
