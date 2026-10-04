// §35.3 and §35.4 on the client: unlock (with the two secrets in Private, with the login through the
// escrow in Managed, §24.2; the verified root chain alone picks which, §3.6), prove the account's state against the
// §26 config, become a trusted recipient, and keep that recipient's private key where §20.1 says —
// a non-extractable `CryptoKey` in the installation's IndexedDB (`nodra:<install_ns>`), the same in
// the web and in the plugin (both run in an origin with IndexedDB).
//
// What is persisted is a fact, never a step (CLAUDE.md): the recipient row is PENDING (§35.4 step 6:
// the key, its id and the exact bundle bytes, written BEFORE the bundle is sent) or ACTIVE, and the
// account pins (§28.3, §26) are what the last applied enrollment proved. A restart that finds PENDING
// does not resume anything: it resends the same bytes (§35.4 "Al arrancar…") and lets the answer and
// the registry decide. Every write is a §20.2 compare-and-set on `install_version` (installation.ts),
// so two contexts enrolling at once can never overwrite each other's key.
//
// Nothing here persists the password, the Account Secret Key, a derived key or an Operation/Signing
// handle (§20.1's right-hand column): they live in this module's locals for one call.
import * as P from "@nodra/protocol";
import { exportEnvelopePublicKey, generateRecipientKeyPair, importEnvelopePublicKey } from "@nodra/crypto";
import type { EnvelopeUnwrapKey, HkdfBase } from "@nodra/crypto";
import { EPOCH_DESCRIPTOR, EPOCH_ENVELOPE, ESCROW_REWRAP, REGISTRY, ROOT_DESCRIPTOR, ROOT_TRANSITION, decodeRecord } from "@nodra/encoding/records";
import type { AccountSecurityConfig, EpochEnvelope, EscrowRewrap, Registry } from "@nodra/encoding/records";
import {
  createAccount,
  createManagedAccount,
  enrollClient,
  idKey,
  openEscrowRewrap,
  parseAccountSecurityProfile,
  prepareEnrollment,
  proveCapabilityWithDecryptKey,
  proveCapabilityWithUnwrapKey,
  rootRecipients,
  unlockForOperation,
  verifyEpochChain,
  verifyRegistryChain,
  verifyRootChain,
} from "@nodra/key-lifecycle";
import type {
  AccountSecrets,
  AccountView,
  ClientPins,
  ClientVault,
  EnvelopeSource,
  EscrowPublicKey,
  OpenedEscrow,
  OperationUnlock,
  ProtectionMode,
  RecipientIdentity,
  Result,
  RootChainLink,
  UnlockRequest,
  UnlockedAccount,
} from "@nodra/key-lifecycle";

export type { AccountSecrets } from "@nodra/key-lifecycle";
import { v7 as uuidv7 } from "uuid";
import { CapabilityError, type CapabilitySession, capabilitySession } from "./capability.js";
import { type DirectoryTransport, httpDirectory, realVaultCrypto } from "./directory.js";
import type { BlobOpener } from "./http-backend.js";
import { uuidToBytes } from "./manifest.js";
import { type IdbDeps, type InstallationSnapshot, type InstallationStore, installationStore } from "./installation.js";
import { SECURITY_EVENTS } from "./security-events.js";
import type { BlobCrypto } from "./ports.js";
import { type VaultStore, closeVaultStore, deleteVaultStore, localVaultIds, openVaultStore, unsyncedChanges } from "./store.js";
import type { PlanLimits, ReplicaAuth, SyncClientDeps } from "./controller.js";

export type TrustFailureCode =
  /** NOTES question 413: `disconnectInstallation` on an installation that is not the plugin's (a browser's notes live in the vault database it would delete). */
  | "DISCONNECT_UNSUPPORTED"
  /** §24: the password or the Account Secret Key is wrong (one answer for both, on purpose). */
  | "SECRETS_REJECTED"
  /** §24/§26: the unlock failed for another reason (a profile or config that is not canonical, KDF limits). */
  | "UNLOCK_FAILED"
  /** §35.2 has not run for this account: there is nothing to unlock. */
  | "NO_ACCOUNT_ROOT"
  /** §26: the root or registry the server served is not the one the decrypted config names. */
  | "CONFIG_MISMATCH"
  /** §28/§29/§32.1: a chain the server served does not verify. */
  | "CHAIN_INVALID"
  /** §35.4 steps 3–5 refused to build a bundle (e.g. an epoch with no ACCOUNT envelope). */
  | "ENROLLMENT_UNBUILDABLE"
  /** §35.4 step 8: the bundle was not applied and the recipient is not ACTIVE; the PENDING key is gone. */
  | "ENROLLMENT_REJECTED"
  /**
   * §35.4 step 8 / §35.1 "Respuesta perdida": no answer from the bundle route (network, a gateway, a
   * step-0 refusal). The PENDING row is kept; the next attempt resends the SAME bytes, never new keys.
   */
  | "ENROLLMENT_PENDING"
  /**
   * §35.2 / §3.7: CREATE_ACCOUNT before the login's email is confirmed. Retryable: the PENDING row is
   * kept, and the SAME bundle is resent once the email is confirmed (the kits already shown stay valid).
   */
  | "EMAIL_UNCONFIRMED"
  /** §20.2: the per-installation compare-and-set kept losing to other contexts; nothing was overwritten. */
  | "INSTALLATION_CONTENDED"
  /** §26/§28.3: the server served a config older than this installation's `config_version` pin. */
  | "CONFIG_ROLLBACK"
  /** §20.1: a stored recipient key is extractable or has other usages than `["unwrapKey"]`. */
  | "RECIPIENT_KEY_UNSAFE"
  /** The server refused a read this module needs. */
  | "SERVER_REFUSED"
  /** §35.2 on an account that already has a root: this client trusts itself (§35.4) instead. */
  | "ACCOUNT_EXISTS"
  /** §24: the Encryption Password does not meet the minimum (`encryptionPasswordProblem`). */
  | "WEAK_PASSWORD"
  /** §35.2 steps 2–14 refused to build the account (a keyset failure, a Recovery Kit self-test, §27.3). */
  | "ACCOUNT_UNBUILDABLE"
  /** §35.1 "trusted client": this installation holds no ACTIVE recipient (or no pins), or the verified registry no longer lists it ACTIVE. */
  | "NOT_TRUSTED"
  /** §35.5: the device to revoke is this one, or is not ACTIVE in the verified registry. */
  | "INVALID_TARGET"
  /** §35.10 step 1, §40: the plan's vault limit (getRootState `maxVaults`) is already reached. */
  | "PLAN_LIMIT_EXCEEDED"
  /** §35.1 "Respuesta perdida": no answer to a security bundle; its SAME bytes are resent next time. */
  | "OPERATION_PENDING"
  /** §35.1: the Worker refused a security bundle for good (the code is in the message), or it stayed stale. */
  | "OPERATION_REJECTED"
  /** §3.6, §24: the verified root chain says Private, and this call was given no Password + Secret Key. */
  | "SECRETS_REQUIRED"
  /** §35.13/§35.14: the operation needs the other protection mode than the one the verified chain says. */
  | "WRONG_MODE"
  /** §35.14 step 2: the user did not confirm giving the server read access. */
  | "NOT_CONFIRMED"
  /** §35.7: managed-recovery-unlock needs a primary authentication of 5 minutes or less; log in again. */
  | "REAUTH_REQUIRED"
  /**
   * §20.2: this installation's account state (recipient key, pins, pending bundles) belongs to another
   * account than the session's, or to an unknown one (rows written before the binding existed). Never
   * resolved on its own: only the user's explicit `disconnectInstallation` removes it (NOTES question 413).
   */
  | "INSTALLATION_OTHER_ACCOUNT"
  /** §35.15: a delayed operation (§35.9, §35.14, §35.7 Private) with no live request of its kind: file one first. */
  | "RECOVERY_REQUEST_REQUIRED"
  /** §35.15: the request has not matured; the message carries `matures_at`. */
  | "RECOVERY_NOT_MATURE"
  /** §35.15: another recovery request is live in the account (at most one at a time). */
  | "RECOVERY_REQUEST_EXISTS"
  /** §35.15: the Recovery Kit given does not open, or is not the one the root in force names (§27.3). */
  | "RECOVERY_KIT_REJECTED";

export class TrustError extends Error {
  constructor(
    readonly code: TrustFailureCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "TrustError";
  }
}

/** The recipient types a client can be (§29). ACCOUNT and RECOVERY live in the root, not here. */
export type ClientRecipientType = "PLUGIN_INSTALLATION" | "TRUSTED_BROWSER";

/** A trusted replica: its `recipient_id` is its `replica_id` (§6), and its key opens its envelopes. */
export interface TrustedIdentity {
  readonly recipientId: string;
  readonly type: ClientRecipientType;
  readonly privateKey: EnvelopeUnwrapKey;
}

/**
 * The account-level pins of §28.3 and §26 (`config_version` among them), hex. The §32.1 epoch pins
 * are per vault and live in the vault store (directory.ts).
 */
export interface AccountPins {
  readonly rootGeneration: number;
  readonly rootHash: string;
  readonly genesisRootHash: string;
  readonly registryVersion: number;
  readonly registryHash: string;
  readonly configVersion: number;
}

/** The row §35.4 step 6 persists, and step 8 turns ACTIVE or deletes. */
interface RecipientRow {
  readonly status: "PENDING" | "ACTIVE";
  /**
   * The bundle a PENDING row carries: ENROLL_CLIENT (absent, §35.4) or CREATE_ACCOUNT (§35.2 step 15),
   * which is resent with the login alone (§35.1) and settled by `settleAccountCreation`.
   */
  readonly operation?: "CREATE_ACCOUNT";
  readonly recipientId: string;
  readonly type: ClientRecipientType;
  readonly privateKey: CryptoKey;
  /** The exact serialized bundle, hex; only while PENDING. */
  readonly bundle?: string;
  /** The pins this bundle establishes once applied (§35.4 step 8); only while PENDING. */
  readonly pins?: AccountPins;
}

export type { IdbDeps, InstallationStore } from "./installation.js";

/** The per-installation rows (§20.2): exported for account-ops.ts, which adds its own. */
export const RECIPIENT = "recipient";
export const PINS = "account_pins";
/** account-ops.ts's §35.1 row: the exact bytes of a security bundle not yet answered. */
export const SECURITY_BUNDLE = "security_bundle";
/** The account this installation's account state belongs to (NOTES question 413). */
export const ACCOUNT = "account";

/** Every per-installation row that belongs to one account (the rest — the Device Local Key, `replica_id` — belong to the installation). */
export const ACCOUNT_ROWS: readonly string[] = [RECIPIENT, PINS, SECURITY_BUNDLE, SECURITY_EVENTS];

// --- §20.2: whose account state this installation holds (NOTES question 413) ----------------------
//
// The per-installation store is per installation, not per account: a plugin's `install_ns` is its
// `installation_id`, so an Obsidian vault signed in with another account finds the first account's
// recipient key and pins. Used for the second account they are wrong (its root chain is not an
// extension of the first one's pin: PIN_NOT_ANCESTOR) or worse (the first account's key over the
// second account's session). So the account is a fact of the store: the `account` row, written in
// the same compare-and-set as the first row that belongs to it, and compared with the session's
// account before any of those rows is used. A mismatch, and rows with no `account` row at all
// (written before this row existed), are never resolved here: a server that could make a client drop
// its keys by naming another account could also make it enroll into keys it controls. Only the user's
// explicit `disconnectInstallation` removes them.

/** The `account` row: which account, and the email the user signed in with then (shown, never trusted). */
export interface InstallationAccountRow {
  readonly accountId: string;
  readonly email: string | null;
}

/** Whose account state a snapshot holds. */
export type InstallationAccount =
  | { readonly kind: "NONE" }
  | { readonly kind: "ACCOUNT"; readonly accountId: string; readonly email: string | null }
  /** Account rows without an `account` row: written before the binding, for an account nobody recorded. */
  | { readonly kind: "UNKNOWN" };

const bare = (id: string) => id.replaceAll("-", "").toLowerCase();

/** §20.2: a browser's installation is `web:<account_id hex>`, one per account: its name is its binding. */
export const webInstallNs = (accountId: string) => `web:${accountId.replaceAll("-", "")}`;

/** Whose account state `rows` (a read that included {@link ACCOUNT} and {@link ACCOUNT_ROWS}) holds, in the namespace `installNs`. */
export function installationAccount(rows: ReadonlyMap<string, unknown>, installNs: string): InstallationAccount {
  const bound = rows.get(ACCOUNT) as InstallationAccountRow | undefined;
  if (bound !== undefined) return { kind: "ACCOUNT", accountId: bound.accountId, email: bound.email };
  if (!ACCOUNT_ROWS.some((id) => rows.has(id))) return { kind: "NONE" };
  // Rows written before the `account` row existed: a browser's namespace names their account.
  const named = /^web:([0-9a-f]{32})$/i.exec(installNs);
  return named === null ? { kind: "UNKNOWN" } : { kind: "ACCOUNT", accountId: named[1]!, email: null };
}

/** The other account an installation's rows belong to: its id and email when recorded, null when unknown. */
export interface OtherAccount {
  readonly accountId: string | null;
  readonly email: string | null;
}

export class InstallationOtherAccountError extends TrustError {
  constructor(readonly other: OtherAccount) {
    super(
      "INSTALLATION_OTHER_ACCOUNT",
      `this installation is connected to ${other.accountId === null ? "an earlier account" : `another account (${other.email ?? other.accountId})`}; disconnect it first to use it with this one`,
    );
    this.name = "InstallationOtherAccountError";
  }
}

/** The other account an error names, when it is INSTALLATION_OTHER_ACCOUNT; null otherwise. */
export const otherAccountOf = (e: unknown): OtherAccount | null => (e instanceof InstallationOtherAccountError ? e.other : null);

/** Throws INSTALLATION_OTHER_ACCOUNT unless `rows` hold nothing, or `accountId`'s state. */
export function requireAccount(rows: ReadonlyMap<string, unknown>, o: { readonly installNs: string; readonly accountId: string }): void {
  const held = installationAccount(rows, o.installNs);
  if (held.kind === "NONE" || (held.kind === "ACCOUNT" && bare(held.accountId) === bare(o.accountId))) return;
  throw new InstallationOtherAccountError(held.kind === "UNKNOWN" ? { accountId: null, email: null } : { accountId: held.accountId, email: held.email });
}

/** Who writes account rows: the session's account, and the email to show if another one signs in later. */
export interface AccountBinding {
  readonly installNs: string;
  readonly accountId: string;
  readonly accountEmail?: string;
}

/**
 * One §20.2 read of `ids` that fails with INSTALLATION_OTHER_ACCOUNT before any of them can be used
 * for another account. Every read of an account row goes through here; the snapshot's version is the
 * one to commit against, so a disconnect in between makes that commit lose.
 */
export async function readAccountRows(store: InstallationStore, o: AccountBinding, ids: readonly string[]): Promise<InstallationSnapshot> {
  const snap = await store.read([...new Set([ACCOUNT, ...ACCOUNT_ROWS, ...ids])]);
  requireAccount(snap.rows, o);
  return snap;
}

/** The `account` row to write with an account row, when the snapshot has none yet (a fact, written once). */
export const bindAccount = (snap: InstallationSnapshot, o: AccountBinding): Record<string, InstallationAccountRow> =>
  snap.rows.has(ACCOUNT) ? {} : { [ACCOUNT]: { accountId: o.accountId, email: o.accountEmail ?? null } };

/** Where an installation's local state is: its namespace, and the vault it chose (for a platform that cannot list databases). */
export interface LocalInstallation extends IdbDeps {
  readonly installNs: string;
  readonly knownVaultIds?: readonly string[];
  /** Tests only: the §20.2 per-installation store, when it is not `installationStore` over IndexedDB. */
  readonly installation?: InstallationStore;
}

/** What {@link disconnectInstallation} would remove, for the confirmation the user reads first. */
export interface LocalSyncState {
  readonly vaultIds: readonly string[];
  /** Objects with a local change the server never confirmed (store.ts `unsyncedChanges`), over every vault. */
  readonly unsynced: number;
}

export async function localSyncState(o: LocalInstallation): Promise<LocalSyncState> {
  const vaultIds = await localVaultIds({ ...o, known: o.knownVaultIds ?? [] });
  let unsynced = 0;
  for (const vaultId of vaultIds) {
    const store = await openVaultStore({ ...o, vaultId });
    try {
      unsynced += await unsyncedChanges(store);
    } finally {
      closeVaultStore(store);
    }
  }
  return { vaultIds, unsynced };
}

/**
 * The user's explicit "disconnect this vault" (NOTES question 413), and the ONLY code that removes
 * account rows of another account: every vault database of this installation (S, the R cache, the
 * outbox, the journal, `pending_intents`, the vault pins), then, in one §20.2 compare-and-set, the
 * `account` row, the recipient key, the account pins, a pending security bundle, the security-log
 * facts and each vault's LocalCompareKey. The Device Local Key and `replica_id` stay (they are the
 * installation's, not the account's). Nothing on disk is touched: in the plugin the notes are the
 * files, and an unsynced change stays there as a file, which the next connection observes as local
 * content with no base (S empty) and uploads (§12.2). Sync must be stopped first (a vault database
 * open elsewhere blocks its deletion). The databases go first: a crash in between leaves the binding,
 * so the installation still says INSTALLATION_OTHER_ACCOUNT and the user disconnects again.
 */
export async function disconnectInstallation(o: LocalInstallation): Promise<void> {
  // Only the plugin's notes are files outside the vault database. A browser's notes ARE that database
  // (idb-fs), so deleting it there would destroy them, unsynced changes included.
  if (!o.installNs.startsWith("plugin:")) {
    throw new TrustError("DISCONNECT_UNSUPPORTED", `only a plugin installation can be disconnected; ${o.installNs.split(":")[0]} keeps its notes in the vault database`);
  }
  const vaultIds = await localVaultIds({ ...o, known: o.knownVaultIds ?? [] });
  for (const vaultId of vaultIds) await deleteVaultStore({ ...o, vaultId });
  const store = o.installation ?? installationStore(o);
  const ids = [ACCOUNT, ...ACCOUNT_ROWS, ...vaultIds.map((v) => `local_compare_key:${v}`)];
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const snap = await store.read(ids);
    if (await store.commit(snap.version, Object.fromEntries(ids.map((id) => [id, null])))) return;
  }
  throw new TrustError("INSTALLATION_CONTENDED", `the per-installation store changed ${MAX_ROUNDS} times under the disconnect`);
}

/**
 * §20.1: the recipient key is `["unwrapKey"]` and non-extractable, or it is not used. Checked on the
 * way in and on the way out, so neither a bug here nor a row some other code wrote can hand the
 * sync path a key that could give the `epoch_secret` back as bytes.
 */
function assertSafeKey(key: CryptoKey): asserts key is EnvelopeUnwrapKey {
  if (key.extractable || key.usages.length !== 1 || key.usages[0] !== "unwrapKey") {
    throw new TrustError("RECIPIENT_KEY_UNSAFE", `the recipient key is ${key.extractable ? "extractable" : "not unwrapKey-only"} (§20.1)`);
  }
}

function identityOf(row: RecipientRow): TrustedIdentity {
  assertSafeKey(row.privateKey);
  return { recipientId: row.recipientId, type: row.type, privateKey: row.privateKey };
}

/**
 * This installation's ACTIVE recipient for `accountId`, or null when it has not enrolled (or is still
 * PENDING). Another account's: INSTALLATION_OTHER_ACCOUNT.
 */
export async function trustedIdentity(o: AccountBinding & IdbDeps & { readonly installation?: InstallationStore }): Promise<TrustedIdentity | null> {
  const row = (await readAccountRows(o.installation ?? installationStore(o), o, [RECIPIENT])).rows.get(RECIPIENT) as RecipientRow | undefined;
  return row === undefined || row.status !== "ACTIVE" ? null : identityOf(row);
}

/** The account pins this installation holds for `accountId` (§28.3), or null before its first applied enrollment. */
export async function accountPins(o: AccountBinding & IdbDeps & { readonly installation?: InstallationStore }): Promise<AccountPins | null> {
  return ((await readAccountRows(o.installation ?? installationStore(o), o, [PINS])).rows.get(PINS) as AccountPins | undefined) ?? null;
}

/** §26 "continuidad de pins": pins only move forward, and a higher `config_version` is a later state. */
export function laterPins(held: AccountPins | undefined, proved: AccountPins | undefined): AccountPins | undefined {
  if (proved === undefined) return held;
  if (held === undefined) return proved;
  return proved.configVersion >= held.configVersion ? proved : held;
}

// --- The account's state, proved against the config (§35.3) -------------------------------------

export interface AccountTransport extends DirectoryTransport {
  rootState(): Promise<P.RootStateResponse>;
  /** §24.2 `managedUnlock` (UNLOCK) and §35.7 `managedRecoveryUnlock` (RECOVERY): one slot re-wrapped to this SPKI. */
  managedUnlock(slot: "UNLOCK" | "RECOVERY", ephemeralSpki: Uint8Array): Promise<P.ManagedUnlockResponse>;
}

const fromHex = (text: string) => Uint8Array.from({ length: text.length / 2 }, (_, i) => Number.parseInt(text.slice(i * 2, i * 2 + 2), 16));
const toHex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
export const uuidOf = (bytes: Uint8Array) => {
  const h = toHex(bytes);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
};
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * §26: "Un cliente DEBE rechazar cualquier raíz o registry distinto del que indica el config." The
 * config is the one record the server cannot forge (it opens only under the two secrets), so it is
 * what pins a client without pins (§35.3) to the history the account really has. Without this, a
 * server could serve an older, perfectly valid registry — one where a revoked device is ACTIVE.
 */
export function checkAgainstConfig(
  config: AccountSecurityConfig,
  proved: { readonly rootGeneration: number; readonly rootHash: Uint8Array; readonly genesisRootHash: Uint8Array; readonly registryVersion: number; readonly registryHash: Uint8Array },
): void {
  const mismatch = (what: string) => {
    throw new TrustError("CONFIG_MISMATCH", `the ${what} served is not the one the account's config names (§26)`);
  };
  if (proved.rootGeneration !== config.root_generation || !same(proved.rootHash, config.root_hash)) mismatch("root");
  if (!same(proved.genesisRootHash, config.genesis_root_hash)) mismatch("genesis root");
  if (proved.registryVersion !== config.registry_version || !same(proved.registryHash, config.registry_hash)) mismatch("registry");
}

/** §28 from GENESIS, through this installation's root pin when it holds one (§28.3), and the mode it sets (§3.6). */
export async function provedRoot(transport: AccountTransport, account: Uint8Array, pins: AccountPins | undefined) {
  const chain = await transport.rootChain();
  const links: RootChainLink[] = chain.links.map((l) => ({ transition: decodeRecord(ROOT_TRANSITION, fromHex(l.transition)), descriptor: decodeRecord(ROOT_DESCRIPTOR, fromHex(l.descriptor)) }));
  const rootPin = pins === undefined ? {} : { pin: { rootGeneration: pins.rootGeneration, rootHash: fromHex(pins.rootHash) } };
  const root = await verifyRootChain(links, { accountId: account, ...rootPin });
  if (!root.ok) throw new TrustError("CHAIN_INVALID", `root: ${root.failure.code}`);
  const signingKeys = new Map(links.map((l) => [l.descriptor.root_generation, l.descriptor.account_signing_public_key]));
  const rootCryptoVersions = new Map(links.map((l) => [l.descriptor.root_generation, l.descriptor.crypto_version]));
  // §3.5: a Private account that was Managed before; the operator could read its earlier history.
  const switchedToPrivate = root.value.mode === "PRIVATE" && links.some((l) => l.transition.transition_type === "SWITCH_TO_PRIVATE");
  return { root: root.value, signingKeys, rootCryptoVersions, mode: root.value.mode, switchedToPrivate };
}

export type ProvedRoot = Awaited<ReturnType<typeof provedRoot>>;

/** §29 from GENESIS, through this installation's registry pin when it holds one (§28.3). */
export async function provedRegistry(transport: AccountTransport, account: Uint8Array, root: ProvedRoot, pins: AccountPins | undefined) {
  const registries: Registry[] = (await transport.registry()).versions.map((v) => decodeRecord(REGISTRY, fromHex(v.registry)));
  const registryPin = pins === undefined ? {} : { pin: { registryVersion: pins.registryVersion, registryHash: fromHex(pins.registryHash) } };
  const registry = await verifyRegistryChain(registries, { accountId: account, accountSigningKeys: root.signingKeys, currentRootGeneration: root.root.rootGeneration, ...registryPin });
  if (!registry.ok) throw new TrustError("CHAIN_INVALID", `registry: ${registry.failure.code}`);
  return registry.value;
}

/** §28 then §29, from GENESIS, and through this installation's pins when it holds them (§28.3). */
export async function provedChains(transport: AccountTransport, account: Uint8Array, pins: AccountPins | undefined) {
  const root = await provedRoot(transport, account, pins);
  return { ...root, registry: await provedRegistry(transport, account, root, pins) };
}

/**
 * §24.2 steps 2–4 (UNLOCK) and §35.7 (RECOVERY): a fresh RSA-OAEP-3072 pair whose private half is
 * non-extractable and `["unwrapKey"]` only, its SPKI sent, the answer opened with it, and the pair
 * dropped. Only called once the verified root chain says Managed: a server that then answers "no
 * escrow" (INVALID_STATE) contradicts the chain, which is CONFIG_MISMATCH, never a reason to switch paths.
 */
export async function openManagedSlot(transport: AccountTransport, account: Uint8Array, slot: "UNLOCK" | "RECOVERY"): Promise<OpenedEscrow> {
  const ephemeral = await generateRecipientKeyPair();
  const spki = await exportEnvelopePublicKey(ephemeral.publicKey);
  const answer = await transport.managedUnlock(slot, spki);
  if (!answer.ok) {
    if (answer.code === "REAUTH_REQUIRED") throw new TrustError("REAUTH_REQUIRED", "the recovery slot needs a login of the last 5 minutes (§35.7): log in again");
    throw new TrustError("CONFIG_MISMATCH", "the verified root chain says this account is Managed, and the server says it holds no escrow (§3.6)");
  }
  let rewrap: EscrowRewrap;
  try {
    rewrap = decodeRecord(ESCROW_REWRAP, fromHex(answer.rewrap));
  } catch (e) {
    throw new TrustError("SERVER_REFUSED", `the re-wrapped ${slot} slot is not an EscrowRewrap: ${String(e)}`);
  }
  const opened = await openEscrowRewrap({ accountId: account, slot, ephemeralKey: ephemeral.privateKey, ephemeralSpki: spki, rewrap });
  if (!opened.ok) throw new TrustError("UNLOCK_FAILED", `${opened.failure.code}: ${opened.failure.message}`);
  return opened.value;
}

/** §3.6: the Escrow Key in force, as getRootState serves it — over TLS, never pinned. */
export async function escrowKeyOf(state: P.RootStateResponse): Promise<EscrowPublicKey> {
  return { keyId: fromHex(state.escrowKey.keyId), publicKey: await importEnvelopePublicKey(fromHex(state.escrowKey.spki)) };
}

export interface Unlocked<U extends UnlockedAccount = OperationUnlock> {
  readonly unlock: U;
  readonly view: AccountView;
  /** The ACCOUNT envelope of every epoch of every vault, verified against its descriptor's chain. */
  readonly sources: readonly EnvelopeSource[];
  readonly accountRecipientId: string;
  /** §3.6: derived from the verified root chain, never from the server. */
  readonly mode: ProtectionMode;
}

/**
 * §35.3 Root Unlock, plus §28.3/§26 for an installation that holds pins: a config older than the
 * pinned `config_version` is refused before the registry is read, and the chains must extend the
 * pinned ones.
 *
 * §3.6: the key source of §24 is chosen from the mode the verified root chain derives, and from
 * nothing else. Managed: the UNLOCK slot through managed-unlock (§24.2); `secrets` is not used.
 * Private: the two secrets, which the caller must have asked for (SECRETS_REQUIRED otherwise). A
 * profile of the other mode's shape is the server contradicting the chain: CONFIG_MISMATCH.
 */
export function unlockAccount(transport: AccountTransport, accountId: string, secrets: AccountSecrets | undefined, pins: AccountPins | undefined): Promise<Unlocked> {
  return proveAccount(transport, accountId, secrets, pins, unlockForOperation);
}

/** `unlockAccount` with the handles another §25.1 row gives (`unlockForRewrap` in §35.14). */
export async function proveAccount<U extends UnlockedAccount>(
  transport: AccountTransport,
  accountId: string,
  secrets: AccountSecrets | undefined,
  pins: AccountPins | undefined,
  open: (request: UnlockRequest) => Promise<Result<U>>,
): Promise<Unlocked<U>> {
  const account = uuidToBytes(accountId);
  const state = await transport.rootState();
  if (state.profile === null || state.configBlob === null || state.configVersion === null) throw new TrustError("NO_ACCOUNT_ROOT", "this account has no root yet (§35.2)");
  const parsed = parseAccountSecurityProfile(fromHex(state.profile));
  if (!parsed.ok) throw new TrustError("SERVER_REFUSED", parsed.failure.message);
  // The stored profile plus the config in force (§26): a config-only bundle installs only the latter.
  const profile = { ...parsed.value, config_blob: fromHex(state.configBlob), config_version: state.configVersion };

  // §3.6: the mode, from the root chain replayed from GENESIS (through the pin), before any key exists.
  const root = await provedRoot(transport, account, pins);
  let source: { readonly secrets: AccountSecrets } | { readonly rootUnlockKey: HkdfBase };
  if (root.mode === "MANAGED") {
    const opened = await openManagedSlot(transport, account, "UNLOCK");
    if (opened.slot !== "UNLOCK") throw new TrustError("SERVER_REFUSED", "managed-unlock answered another slot");
    source = { rootUnlockKey: opened.rootUnlockBase };
  } else {
    if (secrets === undefined) throw new TrustError("SECRETS_REQUIRED", "this account is Private (its verified root chain says so): the Encryption Password and the Account Secret Key are needed");
    source = { secrets };
  }
  const unlocked = await open({ accountId: account, profile, ...source });
  if (!unlocked.ok) {
    const code = unlocked.failure.code;
    // MALFORMED_PROFILE here is a profile of the other mode's shape (§23.4): the server contradicts the chain.
    const mapped = code === "MALFORMED_PROFILE" ? "CONFIG_MISMATCH" : root.mode === "PRIVATE" && (code === "SECRETS_REJECTED" || code === "BAD_SECRET_KEY_FORMAT") ? "SECRETS_REJECTED" : "UNLOCK_FAILED";
    throw new TrustError(mapped, `${code}: ${unlocked.failure.message}`);
  }
  const { config } = unlocked.value;
  // §26 "Limitación (rollback)": an older config under the same secrets decrypts fine, and only the
  // pin tells it apart. Never the other way round: a `config_version` above the pin is accepted.
  if (pins !== undefined && config.config_version < pins.configVersion) {
    throw new TrustError("CONFIG_ROLLBACK", `the server served config_version ${config.config_version}; this installation pinned ${pins.configVersion} (§26)`);
  }

  // §29 through the pins, then both chains pinned by the config rather than by the server.
  const registry = await provedRegistry(transport, account, root, pins);
  const genesisRootHash = root.root.genesisRootHash ?? root.root.rootHash;
  checkAgainstConfig(config, {
    rootGeneration: root.root.rootGeneration,
    rootHash: root.root.rootHash,
    genesisRootHash,
    registryVersion: registry.registry.registry_version,
    registryHash: registry.registryHash,
  });

  // §32.1 for every vault the account lists, read as the ACCOUNT recipient (§35.4 step 4's source).
  const accountRecipientId = uuidOf((await rootRecipients(root.root.descriptor))[0]!.recipientId);
  const { vaults, sources } = await provedVaults(transport, state, accountRecipientId, root, registry);
  return {
    unlock: unlocked.value,
    view: {
      accountId: account,
      root: root.root.descriptor,
      rootHash: root.root.rootHash,
      genesisRootHash,
      registry: registry.registry,
      registryHash: registry.registryHash,
      configVersion: config.config_version,
      vaults,
    },
    sources,
    accountRecipientId,
    mode: root.mode,
  };
}

/**
 * §32.1 for every vault getRootState lists, read as `recipientId` (a root recipient: ACCOUNT, or
 * RECOVERY in §35.7): each vault's chain verified, and that recipient's envelope of each epoch.
 */
export async function provedVaults(
  transport: AccountTransport,
  state: P.RootStateResponse,
  recipientId: string,
  root: ProvedRoot,
  registry: { readonly hashes: ReadonlyMap<number, Uint8Array> },
): Promise<{ readonly vaults: readonly ClientVault[]; readonly sources: readonly EnvelopeSource[] }> {
  const vaults: ClientVault[] = [];
  const sources: EnvelopeSource[] = [];
  for (const vault of state.vaults) {
    const listed = await transport.vaultDirectory(vault.vaultId, recipientId);
    if (listed.kind === "VAULT_NOT_FOUND") continue; // deleted since the listing: not part of the set
    const descriptors = listed.epochs.map((e) => decodeRecord(EPOCH_DESCRIPTOR, fromHex(e.descriptor)));
    const proved = await verifyEpochChain(descriptors, {
      vaultId: uuidToBytes(vault.vaultId),
      accountSigningKeys: root.signingKeys,
      rootHashes: root.root.hashes,
      rootCryptoVersions: root.rootCryptoVersions,
      registryHashes: registry.hashes,
    });
    if (!proved.ok) throw new TrustError("CHAIN_INVALID", `vault ${vault.vaultId}: ${proved.failure.code}`);
    const envelopes = new Map<string, EpochEnvelope>(listed.envelopes.map((e) => [e.epochId, decodeRecord(EPOCH_ENVELOPE, fromHex(e.envelope))]));
    for (const descriptor of descriptors) {
      const envelope = envelopes.get(uuidOf(descriptor.epoch_id));
      if (envelope !== undefined) sources.push({ descriptor, envelope });
    }
    vaults.push({
      vaultId: uuidToBytes(vault.vaultId),
      state: vault.state,
      epochs: listed.epochs.map((e, i) => ({ descriptor: descriptors[i]!, state: e.state })),
      current: { epochId: proved.value.current.epoch_id, descriptorHash: proved.value.currentHash },
    });
  }
  return { vaults, sources };
}

// --- §35.4 -----------------------------------------------------------------------------------------

export interface TrustSession {
  readonly baseUrl: string;
  readonly fetch: typeof fetch;
  /** The session headers (the Supabase bearer; the dev token in the demo), read at each request: the token renews. */
  readonly sessionHeaders: () => Record<string, string> | Promise<Record<string, string>>;
  readonly accountId: string;
  /** The `session_id` claim (§11.3): what every capability label binds. */
  readonly serverSessionId: string;
}

export interface EnrollOptions extends TrustSession, IdbDeps {
  readonly installNs: string;
  readonly type: ClientRecipientType;
  /** What the device list of §35.1 will show. */
  readonly label: string;
  /** The email the user signed in with: recorded with the binding, shown if another account signs in here. */
  readonly accountEmail?: string;
  /**
   * Private accounts (§24): asked from the user for this call only; never stored (§20.1). A Managed
   * account needs none: the verified root chain decides, and the login unlocks it (§24.2).
   */
  readonly secrets?: AccountSecrets;
  /** Tests only: the transport, when it is not `httpDirectory` over `fetch`. */
  readonly transport?: AccountTransport;
  /** Tests only: the §20.2 per-installation store, when it is not `installationStore` over IndexedDB. */
  readonly installation?: InstallationStore;
}

const base = (s: TrustSession) => s.baseUrl.replace(/\/+$/, "");

export function accountTransport(s: TrustSession): AccountTransport {
  return {
    ...httpDirectory({ baseUrl: base(s), fetch: s.fetch, headers: s.sessionHeaders }),
    // §24.2 / §35.7: the login session and nothing else (§11.3).
    async managedUnlock(slot, ephemeralSpki) {
      const res = await s.fetch(`${base(s)}${slot === "UNLOCK" ? P.managedUnlockRoutes.unlock : P.managedUnlockRoutes.recovery}`, {
        method: "POST",
        headers: { ...(await s.sessionHeaders()), "content-type": "application/json" },
        body: JSON.stringify({ ephemeralPublicKey: toHex(ephemeralSpki) } satisfies P.ManagedUnlockRequest),
      });
      const value: unknown = await res.json().catch(() => null);
      const parsed = P.ManagedUnlockResponse.safeParse(value);
      if (parsed.success) return parsed.data;
      const error = P.ErrorBody.safeParse(value);
      throw new TrustError("SERVER_REFUSED", `${slot === "UNLOCK" ? "managed-unlock" : "managed-recovery-unlock"}: ${error.success ? error.data.error : `HTTP_${res.status}`}`);
    },
  };
}

/**
 * §11.3 with the ACCOUNT recipient and the Operation handle: the token that carries
 * ACCOUNT_SECURITY, which ENROLL_CLIENT needs (§35.1.1). §6 fixes one `replica_id` per session; if
 * another client of the same session already fixed one, the session's is adopted (it is only used to
 * name this short-lived token, never to write a vault).
 */
export async function accountCapability(s: TrustSession, unlocked: Unlocked): Promise<CapabilitySession> {
  const session = capabilitySession({
    baseUrl: base(s),
    fetch: s.fetch,
    sessionHeaders: s.sessionHeaders,
    accountId: s.accountId,
    serverSessionId: s.serverSessionId,
    recipientId: unlocked.accountRecipientId,
    replicaId: uuidv7(),
    prove: (input) => proveCapabilityWithDecryptKey({ privateKey: unlocked.unlock.operationKey, ...input }),
  });
  try {
    await session.headers();
  } catch (e) {
    if (!(e instanceof CapabilityError && e.code === "REPLICA_MISMATCH")) throw e;
    await session.headers();
  }
  return session;
}

/** What the bundle route said: a §35.1 answer, or nothing a client can act on (§35.1 "Respuesta perdida"). */
export type Submitted = { readonly kind: "ANSWER"; readonly answer: P.SecurityBundleResponse } | { readonly kind: "NO_ANSWER"; readonly detail: string };

export async function submit(s: TrustSession, headers: Record<string, string>, bundleHex: string): Promise<Submitted> {
  const res = await s.fetch(`${base(s)}${P.securityBundleRoute}`, {
    method: "POST",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({ bundle: bundleHex } satisfies P.SecurityBundleRequest),
  });
  const value: unknown = await res.json().catch(() => null);
  const parsed = P.SecurityBundleResponse.safeParse(value);
  if (parsed.success) return { kind: "ANSWER", answer: parsed.data };
  // A gateway error, a step-0 refusal (§35.1: never stored, the same bundle may be resent), a rate
  // limit: the bundle was not judged, so nothing about it is known.
  const error = P.ErrorBody.safeParse(value);
  return { kind: "NO_ANSWER", detail: error.success ? error.data.error : `HTTP_${res.status}` };
}

/**
 * §35.4 step 8, for any answer that is not "applied": what does the registry in force say about the
 * PENDING recipient? Read through the chains (and the pins), never through the server's word alone.
 */
async function registryStatus(transport: AccountTransport, accountId: string, recipientId: string, pins: AccountPins | undefined): Promise<"ACTIVE" | "REVOKED" | "ABSENT"> {
  const { registry } = await provedChains(transport, uuidToBytes(accountId), pins);
  const mine = idKey(uuidToBytes(recipientId));
  const hit = registry.registry.recipients.find((r) => idKey(r.recipient_id) === mine);
  return hit === undefined ? "ABSENT" : hit.status;
}

/**
 * What sending a PENDING bundle proved about it (§35.4 steps 7–8). APPLIED: the answer, or the
 * registry, lists the recipient ACTIVE. CLOSED: a §35.1 answer that is not "applied" and a registry
 * without it ACTIVE — the bytes can never land any more (the expected versions they carry are gone, or
 * the refusal is stored), so the key is deleted; `repeat` when §35.4 says to start again from step 1
 * (a retryable answer, or case (ii), REVOKED). No answer at all throws ENROLLMENT_PENDING: the row
 * stays, and only its SAME bytes are ever sent again.
 */
type Sent = { readonly kind: "APPLIED" } | { readonly kind: "CLOSED"; readonly repeat: boolean; readonly code: string };

async function send(o: EnrollOptions, transport: AccountTransport, unlocked: Unlocked, row: RecipientRow, pins: AccountPins | undefined): Promise<Sent> {
  let submitted: Submitted;
  try {
    const capability = await accountCapability(o, unlocked);
    try {
      submitted = await submit(o, await capability.headers(), row.bundle!);
    } finally {
      capability.forget();
    }
  } catch (e) {
    submitted = { kind: "NO_ANSWER", detail: String(e) };
  }
  if (submitted.kind === "NO_ANSWER") {
    throw new TrustError("ENROLLMENT_PENDING", `no answer to the enrollment (${submitted.detail}); the same bundle is resent next time`);
  }
  if (submitted.answer.ok) return { kind: "APPLIED" };
  const status = await registryStatus(transport, o.accountId, row.recipientId, pins);
  if (status === "ACTIVE") return { kind: "APPLIED" }; // (i) applied; the stored result expired, or a race
  return { kind: "CLOSED", repeat: status === "REVOKED" || submitted.answer.retryable, code: submitted.answer.code };
}

/** How many fresh pairs one call may build (§35.4 "repite desde el paso 1"), and how many reads it may make. */
const MAX_BUILDS = 3;
const MAX_ROUNDS = 32;

export const hexPins = (p: ClientPins): AccountPins => ({
  rootGeneration: p.rootGeneration,
  rootHash: toHex(p.rootHash),
  genesisRootHash: toHex(p.genesisRootHash),
  registryVersion: p.registryVersion,
  registryHash: toHex(p.registryHash),
  configVersion: p.configVersion,
});

/** Steps 2–5: a fresh pair and its bundle, from a view proved in this call. Nothing is persisted here. */
async function build(o: EnrollOptions, unlocked: Unlocked): Promise<RecipientRow> {
  const recipientId = uuidv7();
  const keys = await prepareEnrollment({ recipientId: uuidToBytes(recipientId), type: o.type, label: o.label });
  const enrolled = await enrollClient({
    view: unlocked.view,
    bundleId: uuidToBytes(uuidv7()),
    recipient: keys.recipient,
    prover: keys.prover,
    keys: { signingKey: unlocked.unlock.signingKey, configKey: unlocked.unlock.derived.configKey, operationKey: unlocked.unlock.operationKey },
    sources: unlocked.sources,
  });
  if (!enrolled.ok) throw new TrustError("ENROLLMENT_UNBUILDABLE", `${enrolled.failure.code}: ${enrolled.failure.message}`);
  assertSafeKey(keys.privateKey);
  return { status: "PENDING", recipientId, type: o.type, privateKey: keys.privateKey, bundle: toHex(enrolled.value.serializedBundle), pins: hexPins(enrolled.value.pins) };
}

/**
 * §35.4 "Trust this browser / alta de plugin", whole, and §35.8 re-enrollment: returns this
 * installation's ACTIVE recipient, enrolling it first if it has none or if the registry no longer
 * lists it ACTIVE.
 *
 * It is a loop over the persisted facts, never a resumed step: each round re-reads the §20.2
 * per-installation store and decides from what is there. Every write is a compare-and-set against the
 * `install_version` read in the same round; a lost comparison only means "read again". Hence, with
 * any number of contexts of one installation running this at once:
 *   - one PENDING row at most is ever written, and a context that finds one (its own, another's, or a
 *     crash's) sends ITS bytes rather than building a pair of its own (§35.4 step 6);
 *   - a key the server holds as ACTIVE is never deleted or overwritten: deleting needs a §35.1 answer
 *     that proves the bytes can no longer land, and replacing an ACTIVE row needs the registry to list
 *     it REVOKED or not at all (§35.8 step 3);
 *   - the losers adopt the winner's recipient.
 */
export async function enrollReplica(o: EnrollOptions): Promise<TrustedIdentity> {
  const store = o.installation ?? installationStore(o);
  const transport = o.transport ?? accountTransport(o);
  // A §35.2 creation this installation left PENDING is settled first (§35.4 "Al arrancar…": the saved
  // bytes before any other security operation); if it landed, this installation is already trusted.
  const created = await settleAccountCreation({ ...o, transport, installation: store });
  if (created !== null) return created;
  /** What this call proved about each bundle it sent (keyed by recipient id). */
  const proved = new Map<string, Sent>();
  /** A row whose bundle this call proved applied: restored if another context deleted it meanwhile. */
  let applied: RecipientRow | null = null;
  /** A pair built by this call and not yet persisted; dropped (never sent) if another row wins. */
  let fresh: RecipientRow | null = null;
  let unlocked: Unlocked | null = null;
  let builds = 0;

  for (let round = 0; round < MAX_ROUNDS; round++) {
    const snap = await readAccountRows(store, o, [RECIPIENT, PINS]);
    const row = snap.rows.get(RECIPIENT) as RecipientRow | undefined;
    const pins = snap.rows.get(PINS) as AccountPins | undefined;
    // Step 1: Root Unlock, and the account's state proved against the config and the pins (§35.3, §26).
    unlocked ??= await unlockAccount(transport, o.accountId, o.secrets, pins);

    if (row?.status === "PENDING") {
      fresh = null; // one PENDING at a time: whoever's it is, it is the one that may land
      const known = proved.get(row.recipientId);
      if (known === undefined) {
        proved.set(row.recipientId, await send(o, transport, unlocked, row, pins));
        continue;
      }
      if (known.kind === "APPLIED") {
        applied = row;
        const active: RecipientRow = { status: "ACTIVE", recipientId: row.recipientId, type: row.type, privateKey: row.privateKey };
        const next = laterPins(pins, row.pins);
        if (await store.commit(snap.version, { [RECIPIENT]: active, ...(next === undefined ? {} : { [PINS]: next }), ...bindAccount(snap, o) })) return identityOf(active);
        continue;
      }
      // (ii) or (iii): the PENDING state ends and its bytes are never sent again.
      if (!(await store.commit(snap.version, { [RECIPIENT]: null }))) continue;
      if (!known.repeat) throw new TrustError("ENROLLMENT_REJECTED", `the enrollment was not applied: ${known.code}`);
      unlocked = null; // "repite §35.4 desde el paso 1": the state moved, so the view is proved again
      continue;
    }

    if (row?.status === "ACTIVE") {
      const status = row.recipientId === applied?.recipientId ? "ACTIVE" : await registryStatus(transport, o.accountId, row.recipientId, pins);
      if (status === "ACTIVE") return identityOf(row);
      // §35.8 / §18.3: revoked. The old key opens nothing now; the commit below replaces it (step 3).
    } else if (applied !== null) {
      // Our applied row was deleted by a context that could not know: the server holds this key.
      const active: RecipientRow = { status: "ACTIVE", recipientId: applied.recipientId, type: applied.type, privateKey: applied.privateKey };
      if (await store.commit(snap.version, { [RECIPIENT]: active, ...bindAccount(snap, o) })) return identityOf(active);
      continue;
    }

    // Steps 2–6: a fresh pair, persisted BEFORE it is sent, against the version this round read.
    if (fresh === null) {
      if (builds === MAX_BUILDS) throw new TrustError("ENROLLMENT_REJECTED", `${MAX_BUILDS} enrollments in a row were not applied`);
      builds++;
      fresh = await build(o, unlocked);
    }
    if (await store.commit(snap.version, { [RECIPIENT]: fresh, ...bindAccount(snap, o) })) fresh = null; // next round sends it
  }
  throw new TrustError("INSTALLATION_CONTENDED", `the per-installation store changed ${MAX_ROUNDS} times under this enrollment`);
}


/// --- §35.2 "Creación de cuenta", on the first client ------------------------------------------------

/** What `accountState` tells a client that just logged in: has §35.2 run, and which vaults are live. */
export interface AccountState {
  readonly hasRoot: boolean;
  readonly vaults: readonly { readonly vaultId: string; readonly state: "ACTIVE" | "DELETING_SCHEDULED" }[];
}

/** §22 getRootState with the login alone (§11.3): what the next screen is — create, trust, or open. */
export async function accountState(s: TrustSession, transport: AccountTransport = accountTransport(s)): Promise<AccountState> {
  const state = await transport.rootState();
  return { hasRoot: state.profile !== null, vaults: state.vaults.map((v) => ({ vaultId: v.vaultId, state: v.state })) };
}

/** Code points an Encryption Password needs at least (§24 "requisitos mínimos de fuerza"; NOTES question 324). */
export const MIN_ENCRYPTION_PASSWORD = 12;

/** §24: why this Encryption Password is refused, or null. A floor, not a strength meter. */
export function encryptionPasswordProblem(password: string): string | null {
  if ([...password.normalize("NFKC")].length < MIN_ENCRYPTION_PASSWORD) return `the Encryption Password needs at least ${MIN_ENCRYPTION_PASSWORD} characters`;
  if (password.trim() !== password) return "the Encryption Password cannot start or end with a space";
  return null;
}

/** The two documents of §35.2, shown before the account exists (steps 3 and 8) and never stored. */
export interface AccountKits {
  readonly accountId: string;
  /** The first vault (§35.2 step 12). */
  readonly vaultId: string;
  /** §3.3, §24: the Account Secret Key as the Setup Kit shows it (32 Crockford Base32 characters in groups of 4). */
  readonly secretKey: string;
  /** §27.1: the Recovery Kit exactly as delivered, the downloadable file's bytes. Never sent to the backend. */
  readonly recoveryKit: Uint8Array;
}

/** §35.2 in Private mode: the two kits to show before the account exists. */
export interface AccountCreation {
  readonly mode: "PRIVATE";
  readonly kits: AccountKits;
  /**
   * Steps 15–17, once the user has saved both kits: the PENDING row (key, id, the exact bundle bytes)
   * is persisted BEFORE the bundle is sent, then the answer, or the registry, settles it. Returns the
   * installation's ACTIVE recipient. Refused (ACCOUNT_EXISTS) if this installation already has one.
   */
  confirm(): Promise<TrustedIdentity>;
}

/** §35.2 in Managed mode (the default, §3.6): nothing to show, nothing the user keeps. */
export interface ManagedAccountCreation {
  readonly mode: "MANAGED";
  readonly kits: null;
  readonly accountId: string;
  /** The first vault (§35.2 step 12). */
  readonly vaultId: string;
  /** Steps 15–17, exactly as in Private. */
  confirm(): Promise<TrustedIdentity>;
}

interface CreateAccountBase extends TrustSession, IdbDeps {
  readonly installNs: string;
  readonly type: ClientRecipientType;
  readonly label: string;
  /** The email the user signed in with, recorded with the binding (NOTES question 413). */
  readonly accountEmail?: string;
  readonly transport?: AccountTransport;
  readonly installation?: InstallationStore;
}

/** §35.2 "Toda cuenta nueva se crea en modo Managed": no mode, or MANAGED. */
export interface CreateManagedAccountOptions extends CreateAccountBase {
  readonly mode?: "MANAGED";
  readonly password?: never;
}

/** Private stays selectable at creation (and is reached later with §35.13). */
export interface CreatePrivateAccountOptions extends CreateAccountBase {
  readonly mode: "PRIVATE";
  /** Step 2: the Encryption Password the user chose, for this call only (§20.1). */
  readonly password: string;
}

export type CreateAccountOptions = CreateManagedAccountOptions | CreatePrivateAccountOptions;

/**
 * §35.2 steps 2–14, locally. Nothing is persisted or sent: that is `confirm`. The derived keys and the
 * extractable account privates are not kept by the result (step 17).
 *
 * Managed (the default, §3.6): a random `RootUnlockKey` instead of steps 2–3, the Recovery privates
 * serialized as `EscrowedRecoveryKeys` and self-tested, both escrow slots wrapped to the Escrow Key
 * getRootState serves (over TLS, never pinned) and carried in the CREATE_ACCOUNT bundle. No kit.
 *
 * Private: the Account Secret Key (step 3), the keyset, the Recovery Kit and its self-test against the
 * pending root (step 8: `createAccount` returns no kit that failed it), shown before `confirm`.
 */
export function prepareAccountCreation(o: CreatePrivateAccountOptions): Promise<AccountCreation>;
export function prepareAccountCreation(o: CreateManagedAccountOptions): Promise<ManagedAccountCreation>;
export async function prepareAccountCreation(o: CreateAccountOptions): Promise<AccountCreation | ManagedAccountCreation> {
  if (o.mode === "PRIVATE") {
    const weak = encryptionPasswordProblem(o.password);
    if (weak !== null) throw new TrustError("WEAK_PASSWORD", weak);
  }
  const transport = o.transport ?? accountTransport(o);
  const state = await transport.rootState();
  if (state.profile !== null) throw new TrustError("ACCOUNT_EXISTS", "this account already exists: trust this client instead (§35.4)");
  const recipientId = uuidv7();
  const vaultId = uuidv7();
  const keys = await prepareEnrollment({ recipientId: uuidToBytes(recipientId), type: o.type, label: o.label });
  const request = {
    accountId: uuidToBytes(o.accountId),
    bundleId: uuidToBytes(uuidv7()),
    vaultId: uuidToBytes(vaultId),
    epochId: uuidToBytes(uuidv7()),
    recipient: keys.recipient,
  };
  const created = o.mode === "PRIVATE" ? await createAccount({ ...request, password: o.password }) : await createManagedAccount({ ...request, escrowKey: await escrowKeyOf(state) });
  if (!created.ok) throw new TrustError("ACCOUNT_UNBUILDABLE", `step ${created.failure.step}: ${created.failure.code}`);
  assertSafeKey(keys.privateKey);
  const row: RecipientRow = {
    status: "PENDING",
    operation: "CREATE_ACCOUNT",
    recipientId,
    type: o.type,
    privateKey: keys.privateKey,
    bundle: toHex(created.value.serializedBundle),
    pins: hexPins(created.value.pins),
  };
  const confirm = () => confirmCreation(o, transport, row);
  if (!("setupKit" in created.value)) return { mode: "MANAGED", kits: null, accountId: o.accountId, vaultId, confirm };
  const secretKey = created.value.setupKit.accountSecretKeyText;
  created.value.setupKit.accountSecretKey.fill(0); // §24: the bytes are not needed once the text exists
  return { mode: "PRIVATE", kits: { accountId: o.accountId, vaultId, secretKey, recoveryKit: created.value.recoveryKit.serialized }, confirm };
}

/** §35.2 steps 15–17: the PENDING row persisted BEFORE the first send, then settled. */
async function confirmCreation(o: CreateAccountBase, transport: AccountTransport, row: RecipientRow): Promise<TrustedIdentity> {
  const store = o.installation ?? installationStore(o);
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const snap = await readAccountRows(store, o, [RECIPIENT]);
    const held = snap.rows.get(RECIPIENT) as RecipientRow | undefined;
    if (held !== undefined && held.recipientId !== row.recipientId) throw new TrustError("ACCOUNT_EXISTS", "this installation already holds a recipient");
    if (held === undefined && !(await store.commit(snap.version, { [RECIPIENT]: row, ...bindAccount(snap, o) }))) continue;
    const settled = await settleAccountCreation({ ...o, transport, installation: store });
    if (settled !== null) return settled;
    // Settled by another context of this installation meanwhile.
    const now = (await readAccountRows(store, o, [RECIPIENT])).rows.get(RECIPIENT) as RecipientRow | undefined;
    if (now?.status === "ACTIVE" && now.recipientId === row.recipientId) return identityOf(now);
    throw new TrustError("ENROLLMENT_REJECTED", "the account creation was not applied");
  }
  throw new TrustError("INSTALLATION_CONTENDED", `the per-installation store changed ${MAX_ROUNDS} times under this account creation`);
}

/**
 * §35.2 step 17, and §35.1's resend at start-up (which needs only the login): if this installation
 * holds a PENDING CREATE_ACCOUNT row, sends its SAME bytes with the session alone and settles it.
 * Applied — the answer says so, or the registry lists the recipient ACTIVE (a stored result that
 * expired answers INVALID_STATE "ya tiene raíz") — the row turns ACTIVE with its pins and the identity
 * is returned. Any other answer, with the recipient absent or REVOKED: the row is deleted and
 * ENROLLMENT_REJECTED thrown (another device created the account first, say). No answer:
 * ENROLLMENT_PENDING, and the row stays for the next attempt. Null: there was nothing to settle.
 */
export async function settleAccountCreation(
  o: TrustSession & IdbDeps & { readonly installNs: string; readonly accountEmail?: string; readonly transport?: AccountTransport; readonly installation?: InstallationStore },
): Promise<TrustedIdentity | null> {
  const store = o.installation ?? installationStore(o);
  const transport = o.transport ?? accountTransport(o);
  /** What the one send of this call proved: applied, or refused with this code. */
  let outcome: { readonly applied: true } | { readonly applied: false; readonly code: string } | null = null;
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const snap = await readAccountRows(store, o, [RECIPIENT, PINS]);
    const row = snap.rows.get(RECIPIENT) as RecipientRow | undefined;
    if (row?.status !== "PENDING" || row.operation !== "CREATE_ACCOUNT") return null;
    if (outcome === null) {
      const submitted = await submit(o, await o.sessionHeaders(), row.bundle!).catch((e: unknown): Submitted => ({ kind: "NO_ANSWER", detail: String(e) }));
      if (submitted.kind === "NO_ANSWER") throw new TrustError("ENROLLMENT_PENDING", `no answer to the account creation (${submitted.detail}); the same bundle is resent next time`);
      if (submitted.answer.ok) outcome = { applied: true };
      else if ((await accountState(o, transport)).hasRoot && (await registryStatus(transport, o.accountId, row.recipientId, undefined)) === "ACTIVE") outcome = { applied: true };
      else if (submitted.answer.code === "EMAIL_UNCONFIRMED") {
        throw new TrustError("EMAIL_UNCONFIRMED", "the login's email is not confirmed yet; the same bundle is resent once it is");
      } else outcome = { applied: false, code: submitted.answer.code };
    }
    if (!outcome.applied) {
      if (await store.commit(snap.version, { [RECIPIENT]: null })) throw new TrustError("ENROLLMENT_REJECTED", `the account creation was not applied: ${outcome.code}`);
      continue;
    }
    const active: RecipientRow = { status: "ACTIVE", recipientId: row.recipientId, type: row.type, privateKey: row.privateKey };
    const next = laterPins(snap.rows.get(PINS) as AccountPins | undefined, row.pins);
    if (await store.commit(snap.version, { [RECIPIENT]: active, ...(next === undefined ? {} : { [PINS]: next }), ...bindAccount(snap, o) })) return identityOf(active);
  }
  throw new TrustError("INSTALLATION_CONTENDED", `the per-installation store changed ${MAX_ROUNDS} times under this account creation`);
}

// --- Daily use (§35.4, last line: "el cliente abre sus envelopes sin Password ni Secret Key") ------

/** §11.3 for a trusted replica: its own recipient, its own `["unwrapKey"]` key, `replica_id = recipient_id` (§6). */
export function trustedCapability(s: TrustSession, identity: TrustedIdentity): CapabilitySession {
  return capabilitySession({
    baseUrl: base(s),
    fetch: s.fetch,
    sessionHeaders: s.sessionHeaders,
    accountId: s.accountId,
    serverSessionId: s.serverSessionId,
    recipientId: identity.recipientId,
    prove: (input) => proveCapabilityWithUnwrapKey({ privateKey: identity.privateKey, ...input }),
  });
}

/** The §22 `VaultCrypto` of a trusted replica over HTTP (directory.ts), for one vault store. */
export function trustedVaultCrypto(s: TrustSession, identity: TrustedIdentity, o: { readonly vaultId: string; readonly store: VaultStore }): Promise<BlobCrypto & BlobOpener> {
  const recipient: RecipientIdentity = { recipientId: uuidToBytes(identity.recipientId), type: identity.type };
  return realVaultCrypto({ transport: accountTransport(s), accountId: s.accountId, vaultId: o.vaultId, recipient, privateKey: identity.privateKey, store: o.store });
}

/**
 * §22 getRootState's plan limits with the login alone (§11.3), fresh at each call: §40.1 makes them
 * server-side values ("el cliente nunca lo hardcodea"), so the controller asks per leadership.
 */
export function sessionPlanLimits(s: TrustSession, transport: AccountTransport = accountTransport(s)): () => Promise<PlanLimits> {
  return async () => {
    const { pendingBudgetBytes, maxBlobBytes } = await transport.rootState();
    return { pendingBudgetBytes, maxBlobBytes };
  };
}

/**
 * The controller's three hooks for a trusted replica (§35.4 done): its `replica_id` is its
 * `recipient_id` (§6), every request carries its own capability (§11.3), the vault opens under the
 * real §31 crypto, and the plan's limits come from getRootState. The first two are the whole
 * difference between the demo and the dev stand-ins.
 */
export function trustedReplica(s: TrustSession, identity: TrustedIdentity): Pick<SyncClientDeps, "auth" | "vaultCrypto" | "planLimits"> {
  const capability = trustedCapability(s, identity);
  const auth: ReplicaAuth = { replicaId: identity.recipientId, headers: () => capability.headers(), onAuthRefusal: (code) => capability.onAuthRefusal(code) };
  return { auth: () => auth, vaultCrypto: ({ vaultId, store }) => trustedVaultCrypto(s, identity, { vaultId, store }), planLimits: sessionPlanLimits(s) };
}
