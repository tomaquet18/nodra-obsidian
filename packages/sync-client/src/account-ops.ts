// §35.5 (revoke a browser or a plugin), §35.10 (create an additional vault) and the ADR-021 mode
// switches (§35.13, §35.14) on a trusted client, the Managed §35.7 reset (login only),
// plus the device list §35.1 requires before either: "Antes de crear envelopes para otros recipients,
// la UI DEBE mostrar la lista de dispositivos activos del Registry verificado."
//
// The builders are key-lifecycle's (`revokeClient`, `createVault`); what lives here is where their
// inputs come from and what is persisted around the send:
//   - the view is `unlockAccount`'s: Root Unlock with the two secrets, the chains replayed through
//     this installation's pins and checked against the §26 config. Never the server's word: an older
//     registry served here would make this client seal a new epoch for a device already revoked;
//   - the device list is the registry replayed from GENESIS through the pins (§28.3, §29), never a
//     list the server hands over;
//   - §35.1 "El cliente persiste el bundle_id de todo bundle enviado hasta recibir respuesta": the
//     exact bundle bytes are one `security_bundle` row of the per-installation store (§20.2 CAS),
//     written BEFORE the first send and deleted by the answer. A fact, not a step: "this bundle may
//     have been applied, and nobody has heard". No answer → the SAME bytes are sent again (a few times
//     in the call, then at the next security operation or start), and a stored result comes back for
//     them if they landed. A §35.1 answer that is retryable (the state moved: SECURITY_STATE_STALE,
//     EPOCH_STALE, VAULT_SET_STALE, COVERAGE_STALE) proves the bytes were not applied — a resend of an
//     applied `bundle_id` is answered its stored result before any state check — so the row goes and
//     the operation is built again from a freshly proved view, with a new `bundle_id`.
import {
  createVault,
  idKey,
  liveVaults,
  openEscrowedRecoveryKeys,
  proveCapabilityWithDecryptKey,
  recoveryReset,
  revokeClient,
  rootRecipients,
  switchToManaged,
  switchToPrivate,
  unlockForRewrap,
} from "@nodra/key-lifecycle";
import type { AccountView, ClientPins, OperationUnlock, RecoveryKeyPairs, RewrapUnlock, UnlockedAccount } from "@nodra/key-lifecycle";
import { clientFamilyText } from "@nodra/protocol";
import type * as P from "@nodra/protocol";
import { capabilitySession } from "./capability.js";
import { maturedRequestProblem } from "./recovery.js";
import { v7 as uuidv7 } from "uuid";
import { type IdbDeps, type InstallationStore, installationStore } from "./installation.js";
import { toHex, uuidToBytes } from "./manifest.js";
import { accessTokenSession } from "./session.js";
import {
  type AccountPins,
  type AccountSecrets,
  type AccountTransport,
  type Submitted,
  type TrustSession,
  type TrustedIdentity,
  type Unlocked,
  PINS,
  RECIPIENT,
  SECURITY_BUNDLE,
  TrustError,
  bindAccount,
  accountTransport,
  encryptionPasswordProblem,
  escrowKeyOf,
  hexPins,
  laterPins,
  openManagedSlot,
  proveAccount,
  provedChains,
  provedRegistry,
  provedRoot,
  provedVaults,
  readAccountRows,
  submit,
  trustedCapability,
  trustedIdentity,
  unlockAccount,
  uuidOf,
} from "./trust.js";

const PENDING = SECURITY_BUNDLE;

/** The row §35.1 asks for: the exact bytes of a bundle sent (or about to be) and not yet answered. */
interface PendingBundle {
  readonly operation: "REVOKE_CLIENT" | "CREATE_VAULT" | "SWITCH_TO_PRIVATE" | "SWITCH_TO_MANAGED";
  /** The serialized SecurityBundle, hex: what is resent, byte for byte. */
  readonly bundle: string;
  /** The account pins it establishes once applied (§28.3, §26); only ever raised (`laterPins`). */
  readonly pins: AccountPins;
}

export interface AccountContext extends TrustSession, IdbDeps {
  readonly installNs: string;
  /** The session's email, recorded with the §20.2 binding if this installation had none (NOTES question 413). */
  readonly accountEmail?: string;
  /** Tests only: the transport, when it is not `httpDirectory` over `fetch`. */
  readonly transport?: AccountTransport;
  /** Tests only: the §20.2 per-installation store, when it is not `installationStore` over IndexedDB. */
  readonly installation?: InstallationStore;
}

export interface SecurityOperationOptions extends AccountContext {
  /**
   * §35.1 Root Unlock of a Private account: asked from the user for this call only; never stored
   * (§20.1). A Managed account unlocks with the login (§24.2): the verified root chain decides.
   */
  readonly secrets?: AccountSecrets;
}

// --- The device list -------------------------------------------------------------------------------

// §29: the label a device enrolls with, built where it runs (the web from `navigator`, the plugin from
// Obsidian's `Platform`), re-exported so neither needs the protocol package for it.
export { BROWSER_FAMILIES, DEVICE_LABEL_MAX, OS_FAMILIES, browserDeviceLabel, fitDeviceLabel, pluginDeviceLabel } from "@nodra/protocol";
export type { BrowserFamily, NavigatorLike, OsFamily } from "@nodra/protocol";

/**
 * §19: what the server says about a device's last use of its access. Unsigned and informative: shown
 * beside the signed label, marked as the server's, and never able to change the label, the status or
 * which devices are listed.
 */
export interface DeviceActivity {
  /** Unix ms, on the hour: the device obtained a capability within the hour starting here. */
  readonly lastActiveAt: number;
  /** "Chrome on Windows": the families the server parsed from that request; null when unknown. */
  readonly client: string | null;
}

/** One client recipient of the verified registry (§29, §30). */
export interface Device {
  readonly recipientId: string;
  readonly type: "PLUGIN_INSTALLATION" | "TRUSTED_BROWSER";
  /** What the device called itself when it enrolled (§35.4); signed with the registry, so not the server's. */
  readonly label: string;
  readonly status: "ACTIVE" | "REVOKED";
  /** This installation's own recipient. */
  readonly thisDevice: boolean;
  /** §19, reported by the server; null when it reports nothing for this device. */
  readonly activity: DeviceActivity | null;
}

/**
 * §19: the server's activity report joined onto the verified list. The list is the registry's — a row
 * for a recipient it does not carry is dropped, never added — and only `activity` comes from the report.
 */
export function withServerActivity(devices: readonly Omit<Device, "activity">[], reported: readonly P.DeviceActivityRow[]): Device[] {
  const byId = new Map<string, P.DeviceActivityRow>();
  for (const row of reported) {
    const key = row.recipientId.toLowerCase();
    if (!byId.has(key)) byId.set(key, row);
  }
  return devices.map((d) => {
    const row = byId.get(d.recipientId.toLowerCase());
    return { ...d, activity: row === undefined ? null : { lastActiveAt: row.lastActiveAt, client: clientFamilyText(row) } };
  });
}

/**
 * The account's client recipients as the registry in force says, replayed from GENESIS and through this
 * installation's pins (§28.3, §29): a registry the Account Signing Key did not sign, or one older than
 * the pin, is refused (CHAIN_INVALID) rather than shown. Needs no secret; an operation that is about to
 * create envelopes proves the same registry again against the §26 config (`unlockAccount`). Beside each
 * one, what getRootState reports of its last activity (§19); without that report the list is the same.
 */
export async function listDevices(o: AccountContext): Promise<readonly Device[]> {
  const store = o.installation ?? installationStore(o);
  const transport = o.transport ?? accountTransport(o);
  // First the §20.2 binding check (INSTALLATION_OTHER_ACCOUNT before any request), then the report
  // beside the chains, never able to fail the list: no report is no activity.
  const snap = await readAccountRows(store, o, [RECIPIENT, PINS]);
  const reported = Promise.resolve()
    .then(() => transport.rootState())
    .then(
      (s) => s.deviceActivity ?? [],
      () => [],
    );
  const pins = snap.rows.get(PINS) as AccountPins | undefined;
  const identity = await trustedIdentity({ ...o, installation: store });
  const { registry } = await provedChains(transport, uuidToBytes(o.accountId), pins);
  const mine = identity === null ? null : identity.recipientId.replaceAll("-", "");
  const devices = registry.registry.recipients.map((r) => ({
    recipientId: uuidOf(r.recipient_id),
    type: r.type,
    label: r.label,
    status: r.status,
    thisDevice: idKey(r.recipient_id) === mine,
  }));
  return withServerActivity(devices, await reported);
}

// --- Sending, and the §35.1 row ------------------------------------------------------------------

/** How many times one call sends the same bytes without an answer, and how many views it may build. */
const MAX_SENDS = 3;
const MAX_BUILDS = 3;
const MAX_ROUNDS = 32;

type Answer = { readonly applied: true } | { readonly applied: false; readonly code: string; readonly retryable: boolean };

/** One send of the exact bytes with this device's TRUSTED_SECURITY capability (§11.3). */
async function sendOnce(o: AccountContext, identity: TrustedIdentity, bundle: string): Promise<Submitted> {
  const capability = trustedCapability(o, identity);
  try {
    return await submit(o, await capability.headers(), bundle);
  } catch (e) {
    // The capability could not be had (network, a step-0 refusal): nothing about the bundle is known.
    return { kind: "NO_ANSWER", detail: String(e) };
  } finally {
    capability.forget();
  }
}

/**
 * The PENDING row, if any, settled: its SAME bytes sent up to {@link MAX_SENDS} times until an answer
 * comes, then the row deleted (and, if applied, its pins raised) in one compare-and-set. Null: there
 * was no row. No answer at all: OPERATION_PENDING, and the row stays for the next attempt.
 */
async function settle(o: AccountContext, identity: TrustedIdentity, store: InstallationStore): Promise<{ readonly operation: PendingBundle["operation"]; readonly answer: Answer } | null> {
  let answer: Answer | null = null;
  let sent: PendingBundle | null = null;
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const snap = await readAccountRows(store, o, [PENDING, PINS]);
    const row = snap.rows.get(PENDING) as PendingBundle | undefined;
    if (row === undefined || (sent !== null && row.bundle !== sent.bundle)) {
      // Nothing pending, or another context settled ours (and maybe wrote its own): ours is settled.
      return answer === null || sent === null ? null : { operation: sent.operation, answer };
    }
    if (answer === null) {
      let last = "";
      for (let i = 0; i < MAX_SENDS && answer === null; i++) {
        const submitted = await sendOnce(o, identity, row.bundle);
        if (submitted.kind === "NO_ANSWER") last = submitted.detail;
        else answer = submitted.answer.ok ? { applied: true } : { applied: false, code: submitted.answer.code, retryable: submitted.answer.retryable };
      }
      if (answer === null) throw new TrustError("OPERATION_PENDING", `no answer to ${row.operation} (${last}); the same bundle is resent next time`);
      sent = row;
    }
    const pins = answer.applied ? laterPins(snap.rows.get(PINS) as AccountPins | undefined, row.pins) : undefined;
    if (await store.commit(snap.version, { [PENDING]: null, ...(pins === undefined ? {} : { [PINS]: pins, ...bindAccount(snap, o) }) })) return { operation: row.operation, answer };
  }
  throw new TrustError("INSTALLATION_CONTENDED", `the per-installation store changed ${MAX_ROUNDS} times under a security bundle`);
}

async function requireTrusted(o: AccountContext): Promise<TrustedIdentity> {
  const identity = await trustedIdentity({ ...o, installation: o.installation ?? installationStore(o) });
  if (identity === null) throw new TrustError("NOT_TRUSTED", "only a trusted client (§35.1) can revoke a device or create a vault: trust this client first (§35.4)");
  return identity;
}

/**
 * §35.1 at start-up, with the login and this device's own key (no secret): a security bundle this
 * installation sent without hearing back is resent, SAME bytes, and settled. Null: nothing was pending.
 */
export async function settleSecurityBundle(o: AccountContext): Promise<{ readonly applied: boolean; readonly code?: string } | null> {
  const identity = await trustedIdentity({ ...o, installation: o.installation ?? installationStore(o) });
  if (identity === null) return null;
  const settled = await settle(o, identity, o.installation ?? installationStore(o));
  if (settled === null) return null;
  return settled.answer.applied ? { applied: true } : { applied: false, code: settled.answer.code };
}

interface Built<T> {
  readonly serializedBundle: Uint8Array;
  readonly pins: ClientPins;
  readonly result: T;
}

/**
 * One §35.5/§35.10 operation, whole: settle what is pending, prove the view (Root Unlock, pins,
 * config), build, persist, send, and build again from a new view only when the answer proved the
 * state moved.
 */
async function operate<T, U extends UnlockedAccount = OperationUnlock>(
  o: SecurityOperationOptions,
  operation: PendingBundle["operation"],
  build: (unlocked: Unlocked<U>, identity: TrustedIdentity) => Promise<Built<T>>,
  prove: (transport: AccountTransport, pins: AccountPins) => Promise<Unlocked<U>> = (transport, pins) => unlockAccount(transport, o.accountId, o.secrets, pins) as unknown as Promise<Unlocked<U>>,
): Promise<T> {
  const store = o.installation ?? installationStore(o);
  const transport = o.transport ?? accountTransport(o);
  const identity = await requireTrusted(o);
  await settle(o, identity, store); // §35.1: the saved bytes before any new security operation
  let builds = 0;
  let lastCode = "";
  for (let round = 0; round < MAX_ROUNDS && builds < MAX_BUILDS; round++) {
    const snap = await readAccountRows(store, o, [PENDING, PINS]);
    if (snap.rows.has(PENDING)) {
      await settle(o, identity, store); // another context's, written meanwhile: its bytes go first
      continue;
    }
    const pins = snap.rows.get(PINS) as AccountPins | undefined;
    if (pins === undefined) throw new TrustError("NOT_TRUSTED", "this installation holds no pins (§35.1 trusted client)");
    const unlocked = await prove(transport, pins);
    const mine = identity.recipientId.replaceAll("-", "");
    if (!unlocked.view.registry.recipients.some((r) => idKey(r.recipient_id) === mine && r.status === "ACTIVE")) {
      throw new TrustError("NOT_TRUSTED", "the verified registry no longer lists this device ACTIVE: enroll it again (§35.8)");
    }
    const built = await build(unlocked, identity);
    builds++;
    const row: PendingBundle = { operation, bundle: toHex(built.serializedBundle), pins: hexPins(built.pins) };
    if (!(await store.commit(snap.version, { [PENDING]: row, ...bindAccount(snap, o) }))) continue; // never sent: built again from the next read
    const settled = await settle(o, identity, store);
    if (settled === null) continue; // another context settled it: whether it landed, the next view says
    if (settled.answer.applied) return built.result;
    // §35.15: building again cannot help a delayed operation without its matured request.
    if (settled.answer.code === "RECOVERY_REQUEST_REQUIRED" || settled.answer.code === "RECOVERY_NOT_MATURE") {
      throw new TrustError(settled.answer.code, `${operation} in a Private account needs a request that has waited the recovery delay (§35.15)`);
    }
    if (!settled.answer.retryable) throw new TrustError("OPERATION_REJECTED", `${operation} refused: ${settled.answer.code}`);
    lastCode = settled.answer.code;
  }
  throw new TrustError("OPERATION_REJECTED", `${operation} was answered ${lastCode || "stale"} ${builds} times in a row`);
}

// --- §35.5 ---------------------------------------------------------------------------------------

/**
 * §35.5 "Revocar browser o plugin", from this trusted client: the registry with `recipientId` REVOKED,
 * a new epoch in every live vault sealed for ACCOUNT, RECOVERY and the recipients that stay ACTIVE, and
 * the config rewritten, in one bundle. Refuses revoking this device itself, or one the verified
 * registry does not list ACTIVE (INVALID_TARGET).
 */
export function revokeDevice(o: SecurityOperationOptions & { readonly recipientId: string }): Promise<void> {
  const target = o.recipientId.replaceAll("-", "").toLowerCase();
  return operate(o, "REVOKE_CLIENT", async (unlocked, identity) => {
    if (target === identity.recipientId.replaceAll("-", "")) throw new TrustError("INVALID_TARGET", "this device cannot revoke itself: revoke it from another trusted device");
    const hit = unlocked.view.registry.recipients.find((r) => idKey(r.recipient_id) === target);
    if (hit?.status !== "ACTIVE") throw new TrustError("INVALID_TARGET", `the verified registry does not list ${o.recipientId} ACTIVE`);
    // Steps 3–4: one fresh epoch per live vault (§35.1.1 step 7 answers VAULT_SET_STALE for a missing one).
    const newEpochIds = new Map(liveVaults(unlocked.view.vaults).map((v) => [idKey(v.vaultId), uuidToBytes(uuidv7())] as const));
    const revoked = await revokeClient({
      view: unlocked.view,
      bundleId: uuidToBytes(uuidv7()),
      revoke: [hit.recipient_id],
      newEpochIds,
      keys: { signingKey: unlocked.unlock.signingKey, configKey: unlocked.unlock.derived.configKey },
    });
    return { serializedBundle: revoked.serializedBundle, pins: revoked.pins, result: undefined };
  });
}

// --- §35.10 --------------------------------------------------------------------------------------

/**
 * §35.10 step 1, before anything is unlocked: the plan's vault limit from getRootState (§22, §40),
 * counting ACTIVE and DELETING_SCHEDULED vaults. Null when there is room (or no limit).
 */
export async function vaultLimitProblem(o: AccountContext): Promise<string | null> {
  const state = await (o.transport ?? accountTransport(o)).rootState();
  if (state.maxVaults === null || state.vaults.length < state.maxVaults) return null;
  return `the plan allows ${state.maxVaults} vault${state.maxVaults === 1 ? "" : "s"} and the account has ${state.vaults.length} (a vault scheduled for deletion still counts)`;
}

/**
 * §35.10 "Crear vault adicional", from this trusted client: E1 of a new vault sealed for ACCOUNT,
 * RECOVERY and every ACTIVE recipient of the verified registry. The limit is checked here from
 * getRootState and again by the Worker (PLAN_LIMIT_EXCEEDED, definitive). Returns the new vault's id.
 */
export async function createVaultFromClient(o: SecurityOperationOptions): Promise<string> {
  const limit = await vaultLimitProblem(o);
  if (limit !== null) throw new TrustError("PLAN_LIMIT_EXCEEDED", limit);
  return operate(o, "CREATE_VAULT", async (unlocked) => {
    const vaultId = uuidv7();
    const created = await createVault({
      view: unlocked.view,
      bundleId: uuidToBytes(uuidv7()),
      vaultId: uuidToBytes(vaultId),
      epochId: uuidToBytes(uuidv7()),
      keys: { signingKey: unlocked.unlock.signingKey },
    });
    return { serializedBundle: created.serializedBundle, pins: created.pins, result: vaultId };
  });
}

// --- §35.13 SWITCH_TO_PRIVATE ------------------------------------------------------------------------

const newEpochIdsOf = (view: AccountView) => new Map(liveVaults(view.vaults).map((v) => [idKey(v.vaultId), uuidToBytes(uuidv7())] as const));

function unbuildable(operation: string, failure: { readonly step: number; readonly code: string; readonly message: string }): never {
  throw new TrustError("ACCOUNT_UNBUILDABLE", `${operation} step ${failure.step}: ${failure.code}: ${failure.message}`);
}

function requireMode(unlocked: Unlocked<UnlockedAccount>, mode: "MANAGED" | "PRIVATE", operation: string): void {
  if (unlocked.mode !== mode) throw new TrustError("WRONG_MODE", `${operation} needs a ${mode === "MANAGED" ? "Managed" : "Private"} account; its verified root chain says ${unlocked.mode}`);
}

export interface SwitchToPrivateOptions extends AccountContext {
  /** §35.13 step 2: the Encryption Password the user defines, for this call only (§20.1). */
  readonly password: string;
  /** Step 2: generated when omitted, which is the normal case. It is what the Setup Kit shows. */
  readonly secretKey?: string;
}

/** The two documents of §35.13 steps 2 and 5, shown before anything is sent, and never stored. */
export interface PrivateKits {
  /** §24: the new Account Secret Key as the Setup Kit shows it. */
  readonly secretKey: string;
  /** §27.1: the new Recovery Kit, the downloadable file's bytes. */
  readonly recoveryKit: Uint8Array;
}

export interface SwitchToPrivatePreparation {
  readonly kits: PrivateKits;
  /**
   * Steps 11–13, once the user saved both kits: persisted, sent and settled like every §35.1 bundle
   * (a lost answer resends the same bytes). A stale answer builds it again from a new view with the
   * SAME Password, Secret Key and Recovery keys, so the kits shown stay the account's.
   */
  confirm(): Promise<void>;
}

/**
 * §35.13 "Pasar de Managed a Private", from a trusted client of a Managed account (its login unlocks
 * it, §24.2): the new Setup Kit and Recovery Kit, then `confirm`. The history re-encryption of step
 * 14 is the controller's (`reencryptHistory`), from the server's list alone.
 */
export async function prepareSwitchToPrivate(o: SwitchToPrivateOptions): Promise<SwitchToPrivatePreparation> {
  const weak = encryptionPasswordProblem(o.password);
  if (weak !== null) throw new TrustError("WEAK_PASSWORD", weak);
  await requireTrusted(o);
  const pins = (await readAccountRows(o.installation ?? installationStore(o), o, [PINS])).rows.get(PINS) as AccountPins | undefined;
  if (pins === undefined) throw new TrustError("NOT_TRUSTED", "this installation holds no pins (§35.1 trusted client)");
  const fixed: { secretKey?: string; recoveryKeys?: RecoveryKeyPairs } = o.secretKey === undefined ? {} : { secretKey: o.secretKey };
  const build = async (unlocked: Unlocked) => {
    requireMode(unlocked, "MANAGED", "SWITCH_TO_PRIVATE");
    const switched = await switchToPrivate({
      view: unlocked.view,
      bundleId: uuidToBytes(uuidv7()),
      keys: { operationKey: unlocked.unlock.operationKey, signingKey: unlocked.unlock.signingKey },
      password: o.password,
      ...fixed,
      newEpochIds: newEpochIdsOf(unlocked.view),
      sources: unlocked.sources,
    });
    if (!switched.ok) unbuildable("SWITCH_TO_PRIVATE", switched.failure);
    switched.value.setupKit.accountSecretKey.fill(0); // §24: the text is what the user keeps
    return switched.value;
  };
  // Steps 1–5 now, for the kits; the bundle itself is built again at confirm from the view then in force.
  const first = await build(await unlockAccount(o.transport ?? accountTransport(o), o.accountId, undefined, pins));
  fixed.secretKey = first.setupKit.accountSecretKeyText;
  fixed.recoveryKeys = first.recoveryKit.keys;
  return {
    kits: { secretKey: first.setupKit.accountSecretKeyText, recoveryKit: first.recoveryKit.serialized },
    confirm: () =>
      operate(o, "SWITCH_TO_PRIVATE", async (unlocked) => {
        const switched = await build(unlocked);
        return { serializedBundle: switched.serializedBundle, pins: switched.pins, result: undefined };
      }),
  };
}

// --- §35.14 SWITCH_TO_MANAGED ------------------------------------------------------------------------

export interface SwitchToManagedOptions extends AccountContext {
  /** §35.14 step 1: the Private Root Unlock, for this call only (§20.1). */
  readonly secrets: AccountSecrets;
  /** §35.14 step 2: the user confirmed giving the server read access to all the content. */
  readonly confirmReadAccess: true;
}

/**
 * §35.14 "Pasar de Private a Managed", from a trusted client of a Private account: the same account
 * keys re-wrapped under a new `RootUnlockKey`, new Recovery keys in the escrow, a new epoch per vault
 * with no envelope for the old Recovery Kit. The UI must have said what this gives the server (step 2).
 */
export async function switchAccountToManaged(o: SwitchToManagedOptions): Promise<void> {
  if (o.confirmReadAccess !== true) throw new TrustError("NOT_CONFIRMED", "SWITCH_TO_MANAGED gives the server read access to all the content: the user must confirm it (§35.14 step 2)");
  const transport = o.transport ?? accountTransport(o);
  // §35.14 phase 2 (ADR-022): only with a matured SWITCH_TO_MANAGED request; told before the bundle is built.
  const pins = (await readAccountRows(o.installation ?? installationStore(o), o, [PINS])).rows.get(PINS) as AccountPins | undefined;
  const mode = (await provedRoot(transport, uuidToBytes(o.accountId), pins)).mode;
  if (mode === "PRIVATE") {
    const problem = await maturedRequestProblem({ ...o, transport, ...(pins === undefined ? {} : { pins }) }, "SWITCH_TO_MANAGED");
    if (problem !== null) throw problem;
  }
  return operate<void, RewrapUnlock>(
    o,
    "SWITCH_TO_MANAGED",
    async (unlocked) => {
      requireMode(unlocked, "PRIVATE", "SWITCH_TO_MANAGED");
      const switched = await switchToManaged({
        view: unlocked.view,
        bundleId: uuidToBytes(uuidv7()),
        keys: { encryptionKey: unlocked.unlock.encryptionKey, signingKey: unlocked.unlock.signingKey },
        escrowKey: await escrowKeyOf(await transport.rootState()),
        newEpochIds: newEpochIdsOf(unlocked.view),
        sources: unlocked.sources,
      });
      if (!switched.ok) unbuildable("SWITCH_TO_MANAGED", switched.failure);
      return { serializedBundle: switched.value.serializedBundle, pins: switched.value.pins, result: undefined };
    },
    (t, pins) => proveAccount(t, o.accountId, o.secrets, pins, unlockForRewrap),
  );
}

// --- §35.7 in Managed mode ---------------------------------------------------------------------------

/**
 * §35.7 "Modo Managed": a RECOVERY_RESET authorized by the login (with a primary authentication of 5
 * minutes or less), the Recovery privates out of the escrow's RECOVERY slot through
 * managed-recovery-unlock. Needs no trusted client, no pins and no secret: the chains are replayed from
 * GENESIS and the escrowed keys proved against the root in force (§35.7 step 2). Every recipient ends
 * REVOKED; each device enrolls again with its login (§35.8, §24.2).
 *
 * The bundle is not persisted: its SAME bytes are resent within the call, and nothing the user keeps
 * depends on which of two resets lands (a Managed reset shows no kit), so a crash only means running it
 * again, which a stale answer turns into a build from the new view.
 */
export async function recoverManagedAccount(o: TrustSession & { readonly transport?: AccountTransport }): Promise<void> {
  const transport = o.transport ?? accountTransport(o);
  const account = uuidToBytes(o.accountId);
  let lastCode = "";
  for (let builds = 0; builds < MAX_BUILDS; builds++) {
    const state = await transport.rootState();
    if (state.profile === null || state.configVersion === null) throw new TrustError("NO_ACCOUNT_ROOT", "this account has no root yet (§35.2)");
    const root = await provedRoot(transport, account, undefined);
    if (root.mode !== "MANAGED") throw new TrustError("WRONG_MODE", "a Private account is recovered with its Recovery Kit (§35.7)");
    const registry = await provedRegistry(transport, account, root, undefined);
    const opened = await openManagedSlot(transport, account, "RECOVERY");
    if (opened.slot !== "RECOVERY") throw new TrustError("SERVER_REFUSED", "managed-recovery-unlock answered another slot");
    const handles = await openEscrowedRecoveryKeys({ keys: opened.recoveryKeys, accountId: account, currentDescriptor: root.root.descriptor });
    if (!handles.ok) throw new TrustError("UNLOCK_FAILED", `the escrowed Recovery keys are not the root's: ${handles.failure.code}`);
    // Step 5's sources: the RECOVERY envelope of every epoch, the only one these keys open.
    const recoveryRecipientId = uuidOf((await rootRecipients(root.root.descriptor))[1]!.recipientId);
    const { vaults, sources } = await provedVaults(transport, state, recoveryRecipientId, root, registry);
    const view: AccountView = {
      accountId: account,
      root: root.root.descriptor,
      rootHash: root.root.rootHash,
      genesisRootHash: root.root.genesisRootHash ?? root.root.rootHash,
      registry: registry.registry,
      registryHash: registry.registryHash,
      // §26: the plaintext copy in force; the reset writes it + 1 without reading the old config.
      configVersion: state.configVersion,
      vaults,
    };
    const reset = await recoveryReset({ view, bundleId: uuidToBytes(uuidv7()), recovery: handles.value, newEpochIds: newEpochIdsOf(view), sources, escrowKey: await escrowKeyOf(state) });
    if (!reset.ok) unbuildable("RECOVERY_RESET", reset.failure);
    // §11.3: RECOVERY_CONTROL, proved with the Recovery key; no replica.
    const capability = capabilitySession({
      baseUrl: o.baseUrl,
      fetch: o.fetch,
      sessionHeaders: o.sessionHeaders,
      accountId: o.accountId,
      serverSessionId: o.serverSessionId,
      recipientId: recoveryRecipientId,
      prove: (input) => proveCapabilityWithDecryptKey({ privateKey: handles.value.encryptionKey, ...input }),
    });
    try {
      const bundle = toHex(reset.value.serializedBundle);
      let answer: Answer | null = null;
      let detail = "";
      for (let i = 0; i < MAX_SENDS && answer === null; i++) {
        const submitted = await submit(o, await capability.headers(), bundle).catch((e: unknown): Submitted => ({ kind: "NO_ANSWER", detail: String(e) }));
        if (submitted.kind === "NO_ANSWER") detail = submitted.detail;
        else answer = submitted.answer.ok ? { applied: true } : { applied: false, code: submitted.answer.code, retryable: submitted.answer.retryable };
      }
      if (answer === null) throw new TrustError("OPERATION_PENDING", `no answer to RECOVERY_RESET (${detail})`);
      if (answer.applied) return;
      if (!answer.retryable) throw new TrustError("OPERATION_REJECTED", `RECOVERY_RESET refused: ${answer.code}`);
      lastCode = answer.code;
    } finally {
      capability.forget();
    }
  }
  throw new TrustError("OPERATION_REJECTED", `RECOVERY_RESET was answered ${lastCode || "stale"} ${MAX_BUILDS} times in a row`);
}

/** Where a Managed recovery stands, for the UI's progress. */
export type RecoveryPhase = "RECOVERING" | "REAUTH";

/**
 * `recoverManagedAccount` from a client holding a login's access token (a browser, the plugin). When
 * the server answers REAUTH_REQUIRED (a primary authentication older than 5 minutes, §35.12 step 2),
 * `relogin` asks the user to log in again and yields the new session's access token (null: they did
 * not), and the recovery is retried with it. Resolves with the access token that recovered the account.
 */
export async function recoverManagedAccountWithRelogin(o: {
  readonly serverUrl: string;
  readonly accessToken: string;
  readonly fetch: typeof fetch;
  readonly relogin: () => Promise<string | null>;
  readonly onPhase?: (phase: RecoveryPhase) => void;
}): Promise<{ readonly accessToken: string }> {
  let accessToken = o.accessToken;
  for (;;) {
    o.onPhase?.("RECOVERING");
    try {
      await recoverManagedAccount(accessTokenSession({ serverUrl: o.serverUrl, accessToken, fetch: o.fetch }));
      return { accessToken };
    } catch (e) {
      if (!(e instanceof TrustError && e.code === "REAUTH_REQUIRED")) throw e;
      o.onPhase?.("REAUTH");
      const token = await o.relogin();
      if (token === null) throw e;
      accessToken = token;
    }
  }
}
