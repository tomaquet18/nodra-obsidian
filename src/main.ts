import type { AccountSecrets, LoginMethod } from "@nodra/sync-client";
import { type App, FileSystemAdapter, Modal, Notice, Platform, Plugin, PluginSettingTab, Setting, TFile, type TAbstractFile } from "obsidian";
import { v7 as uuidv7 } from "uuid";
import { type SecretStore, pluginAuthStorage } from "./auth-storage.js";
import {
  type PendingRecovery,
  type SecurityAlert,
  type SyncController,
  createVaultFromPlugin,
  disconnectPlugin,
  enrollPlugin,
  otherAccountOf,
  pluginDevices,
  pluginLocalState,
  pluginPendingRecovery,
  pluginProtection,
  pluginVaultLimit,
  recoverFromPlugin,
  revokeFromPlugin,
  startSync,
  trustedPlugin,
  vetoFromPlugin,
} from "./controller.js";
import { pluginLabel } from "./device-label.js";
import { obsidianFileSystem } from "./fs.js";
import { OAUTH_ACTION, type PluginAuth, type PluginGitHub, type PluginLogin, loginConnection, pluginAuth, pluginGitHub, signInProblem } from "./login.js";
import { detectOtherSyncTools, keptConfirmations, observeSyncTools, parseConfirmations, type SyncSignal, unconfirmedSignals } from "./other-sync.js";
import { type Ownership, takeOwnership } from "./owner.js";
import {
  type PanelFacts,
  type PluginPhase,
  type Protection,
  OTHER_SYNC_MANUAL_STEPS,
  disconnectConfirmation,
  otherSyncConfirmation,
  panelState,
  pendingRecoveryText,
  statusBarText,
  statusBarTitle,
} from "./panel.js";
import { type PanelActions, NodraPanelView, VIEW_TYPE_NODRA } from "./panel-view.js";
import { type PluginSettings, DEFAULT_SETTINGS, apiFetch, loadSettings } from "./settings.js";
import { PUBLISHED_KEY, attachmentFolderSetting, publishVaultSettings } from "./vault-settings.js";

// The Nodra Obsidian plugin (§42): the sync client over the vault's DataAdapter, on the real §31 crypto,
// against the API and Supabase project fixed at build (globals.d.ts). Everything is done from the Nodra
// panel in the right sidebar (panel-view.ts; its decisions in panel.ts), opened by the ribbon button or
// the status bar; the commands are shortcuts. Each vault signs in with its own Supabase Auth session
// (login.ts, §11.3), kept outside the vault (auth-storage.ts), then connects (enrolls) once (§35.4): a
// Managed account (ADR-021, the default) with the login alone (§24.2); a Private one with the account's
// two secrets, typed into the panel and never stored. Its recipient key stays non-extractable in
// IndexedDB (§20.1). The account itself is created in Nodra Web (§35.2). From a trusted plugin: the
// device list and revocation (§35.5), a new vault (§35.10), and re-enrollment when this installation
// was revoked (§35.8). A Managed account can be recovered from here with the login alone (§35.7).
// Which Nodra vault this Obsidian vault syncs to is chosen once (`chooseVault`). The login is email +
// password or GitHub (§3.7): the system browser, back through `obsidian://nodra-auth` (login.ts).

const INSTALLATION_KEY = "nodra-installation-id";
/** Set once the panel has been offered on this vault and device (the first run opens it, once). */
const FIRST_RUN_KEY = "nodra-panel-offered";
/** §20.2: the other-sync-tool signals the user confirmed on this vault and device (NOTES question 416). */
const OTHER_SYNC_CONFIRMED_KEY = "nodra-other-sync-confirmed";
const SIGN_IN_FIRST = "Nodra: sign in first, from the Nodra panel.";
/**
 * How often the attachment folder setting is checked besides Obsidian's `config-changed` event, which is
 * internal (not in obsidian.d.ts) and may change: a check reads memory and stats one file, and writes
 * only when the setting changed (vault-settings.ts).
 */
const VAULT_SETTINGS_CHECK_MS = 30_000;

type NodeFs = { promises: { rename(from: string, to: string): Promise<void> } };

/** Obsidian's internal core plugin "Sync" (not in obsidian.d.ts; NOTES question 416). Null when the app does not expose it. */
function coreSyncPlugin(app: App): { enabled: boolean; disable(userInitiated: boolean): unknown } | null {
  const sync = (app as { internalPlugins?: { plugins?: Record<string, unknown> } }).internalPlugins?.plugins?.["sync"] as { enabled?: unknown; disable?: unknown } | undefined;
  if (sync === undefined || typeof sync.enabled !== "boolean" || typeof sync.disable !== "function") return null;
  return sync as { enabled: boolean; disable(userInitiated: boolean): unknown };
}

/**
 * Node's fs.rename on the files behind the vault (desktop only, manifest isDesktopOnly): it replaces an
 * existing destination, which DataAdapter.rename refuses (NOTES question 115). Null off desktop.
 */
function replacingRename(adapter: unknown): ((tmp: string, dest: string) => Promise<void>) | null {
  if (!Platform.isDesktopApp || !(adapter instanceof FileSystemAdapter)) return null;
  const nodeFs = (window as unknown as { require?: (m: string) => NodeFs }).require?.("fs");
  if (!nodeFs) return null;
  return (tmp, dest) => nodeFs.promises.rename(adapter.getFullPath(tmp), adapter.getFullPath(dest));
}

export default class NodraPlugin extends Plugin {
  override settings: PluginSettings = DEFAULT_SETTINGS;
  /** Every request to the Nodra API goes through this one fetch (staging: the Cloudflare Access headers, NOTES question 393). */
  private readonly api: typeof fetch = NODRA_ENV === "staging" ? apiFetch(NODRA_API_URL, () => this.settings, (input, init) => fetch(input, init)) : (input, init) => fetch(input, init);
  private auth: PluginAuth | null = null;
  /** §3.7: this instance's GitHub sign-in (one pending flow at most). */
  private github: PluginGitHub | null = null;
  private controller: SyncController | null = null;
  private statusEl: HTMLElement | null = null;
  /** §20.2: the `owner` lock of this vault's installation, once held; requested once per load. */
  private ownership: Ownership | null = null;
  private owning: Promise<Ownership> | null = null;
  private readonly unloading = new AbortController();
  private publishingSettings = false;

  // What the panel shows (panel.ts `PanelFacts`): facts about the plugin, in memory only.
  private phase: PluginPhase = { kind: "starting" };
  private email: string | null = null;
  private protection: Protection | null = null;
  private busy: PanelFacts["busy"] = null;
  private problem: string | null = null;
  private lastSyncedAt: number | null = null;
  private readonly listeners = new Set<() => void>();

  /** The panel's controls, each one of the flows below (the same the commands use). */
  private readonly panelActions: PanelActions = {
    signIn: (email, password) => this.signIn(email, password),
    signInWithGitHub: () => void this.signInWithGitHub(),
    cancelGitHub: () => void this.github?.cancel(),
    connect: (secrets) => this.connect(secrets),
    chooseVault: (vaultId) => this.chooseVault(vaultId),
    createVault: () => void this.createVault(),
    syncNow: () => this.syncNow(),
    pause: () => void this.controller?.pause(),
    resume: () => (this.controller ? this.controller.resume() : void this.restart()),
    restart: () => void this.restart(),
    signInAgain: () => void this.logout(),
    signOut: () => void this.logout(),
    devices: () => void this.devices(),
    recover: () => void this.recoverDialog(),
    disconnect: () => void this.disconnectDialog(),
    confirmNoOtherSync: () => this.confirmNoOtherSyncDialog(),
    turnOffObsidianSync: () => void this.turnOffObsidianSync(),
    resumeAfterOtherTool: () => this.controller?.acknowledgeOtherSyncTool(),
  };

  override async onload(): Promise<void> {
    const { settings, rewrite } = loadSettings(await this.loadData());
    this.settings = settings;
    // A development build kept the session token in data.json: it goes, and is not carried over.
    if (rewrite) await this.saveSettings();
    // Obsidian's secret storage (1.11.4, the minAppVersion); the vault's local storage if it is missing.
    const secrets = (this.app as { secretStorage?: SecretStore }).secretStorage;
    this.auth = pluginAuth({
      apiUrl: NODRA_API_URL,
      supabaseUrl: NODRA_SUPABASE_URL,
      anonKey: NODRA_SUPABASE_ANON_KEY,
      storage: pluginAuthStorage({ secrets, local: { load: (key) => this.app.loadLocalStorage(key), save: (key, value) => this.app.saveLocalStorage(key, value) } }),
      installationId: this.installationId(),
      api: this.api,
      authFetch: (input, init) => fetch(input, init),
    });
    // §3.7: Obsidian routes `obsidian://nodra-auth?vault=<id>&…` to this vault's window; the flow value
    // decides whether it is this instance's sign-in (login.ts `pluginGitHub`).
    this.github = pluginGitHub({ auth: this.auth, vault: this.vaultId(), open: (url) => void window.open(url) });
    this.registerObsidianProtocolHandler(OAUTH_ACTION, (params) => void this.githubCallback(params as unknown as Record<string, string | undefined>));
    this.registerView(VIEW_TYPE_NODRA, (leaf) => new NodraPanelView(leaf, { facts: () => this.facts(), subscribe: (l) => this.subscribe(l), actions: this.panelActions }));
    this.addRibbonIcon("cloud", "Nodra", () => void this.openPanel());
    this.addSettingTab(new NodraSettingTab(this.app, this));
    this.statusEl = this.addStatusBarItem();
    this.statusEl.addClass("mod-clickable");
    this.registerDomEvent(this.statusEl, "click", () => void this.openPanel());
    this.registerDomEvent(window, "online", () => this.changed());
    this.registerDomEvent(window, "offline", () => this.changed());
    this.changed();
    this.addCommand({ id: "open-panel", name: "Open the Nodra panel", callback: () => void this.openPanel() });
    this.addCommand({ id: "sync-now", name: "Sync now", callback: () => this.syncNow() });
    this.addCommand({ id: "login", name: "Sign in", callback: () => void this.openPanel() });
    this.addCommand({ id: "logout", name: "Sign out", callback: () => void this.logout() });
    this.addCommand({ id: "enroll", name: "Enroll this vault", callback: () => this.enrollDialog() });
    this.addCommand({ id: "devices", name: "Manage devices", callback: () => void this.devices() });
    this.addCommand({ id: "create-vault", name: "Create a new Nodra vault", callback: () => void this.createVault() });
    this.addCommand({ id: "recover", name: "Recover the account", callback: () => void this.recoverDialog() });
    this.addCommand({ id: "veto-recovery", name: "Veto a pending recovery request", callback: () => void this.pendingRecovery(true) });
    this.addCommand({
      id: "toggle-pause",
      name: "Pause or resume sync",
      callback: () => {
        const c = this.controller;
        if (c === null) return void this.restart();
        if (c.status().kind === "paused" || c.status().kind === "error") c.resume();
        else void c.pause();
      },
    });
    // Vault events are only hints (§12.2 rule 2); registered once the vault is indexed, so the startup
    // `create` burst does not count.
    this.app.workspace.onLayoutReady(() => {
      const hint = () => this.controller?.hint();
      this.registerEvent(this.app.vault.on("create", hint));
      this.registerEvent(this.app.vault.on("modify", hint));
      this.registerEvent(this.app.vault.on("delete", hint));
      this.registerEvent(this.app.vault.on("rename", hint));
      // §20.3: the attachment folder setting, published when it changes (event, and a periodic check).
      const onConfig = this.app.vault.on as unknown as (name: string, cb: () => void) => ReturnType<typeof this.app.vault.on>;
      this.registerEvent(onConfig.call(this.app.vault, "config-changed", () => void this.publishVaultSettings()));
      this.registerInterval(window.setInterval(() => void this.publishVaultSettings(), VAULT_SETTINGS_CHECK_MS));
      void this.firstRun();
      void this.restart();
    });
  }

  override onunload(): void {
    // §20.2: the owner lock goes FIRST (a reload finds it free at once); the disk queue stays protected
    // by the leader lock, which stop() releases only after the write in progress. Obsidian does not await.
    this.unloading.abort();
    this.ownership?.release();
    this.ownership = null;
    void this.controller?.stop();
    this.controller = null;
    this.listeners.clear();
    void this.github?.cancel();
    void this.auth?.dispose();
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
  }

  /** The Nodra panel in the right sidebar: the one already open, or a new one; then shown. */
  async openPanel(): Promise<void> {
    const { workspace } = this.app;
    let leaf = workspace.getLeavesOfType(VIEW_TYPE_NODRA)[0] ?? null;
    if (leaf === null) {
      leaf = workspace.getRightLeaf(false);
      if (leaf === null) return;
      await leaf.setViewState({ type: VIEW_TYPE_NODRA, active: true });
    }
    await workspace.revealLeaf(leaf);
  }

  /** The plugin just enabled on this vault and device, signed out: the panel opens by itself, once. */
  private async firstRun(): Promise<void> {
    if (this.app.loadLocalStorage(FIRST_RUN_KEY) !== null) return;
    this.app.saveLocalStorage(FIRST_RUN_KEY, "1");
    const login = await this.auth?.current().catch(() => null);
    if (login == null) await this.openPanel();
  }

  private facts(): PanelFacts {
    return { phase: this.phase, email: this.email, protection: this.protection, busy: this.busy, problem: this.problem, online: navigator.onLine, lastSyncedAt: this.lastSyncedAt, now: Date.now() };
  }

  /** §3.7: this vault's id, the `vault` of the callback URL (Obsidian URI: name or id). */
  private vaultId(): string {
    const id = (this.app as { appId?: unknown }).appId;
    return typeof id === "string" && id !== "" ? id : this.app.vault.getName();
  }

  private subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** A fact changed: the status bar and every open panel follow. */
  private changed(): void {
    const state = panelState(this.facts());
    this.statusEl?.setText(statusBarText(state));
    this.statusEl?.setAttr("title", statusBarTitle(state));
    for (const listener of this.listeners) listener();
  }

  private setPhase(phase: PluginPhase): void {
    this.phase = phase;
    const s = phase.kind === "syncing" ? phase.status : null;
    if (s !== null && s.kind === "idle" && s.code === undefined && s.detail === undefined) this.lastSyncedAt = Date.now();
    this.changed();
  }

  /** This installation's login as a new session (login.ts); null when signed out, or unreadable (shown). */
  async currentLogin(): Promise<PluginLogin | null> {
    try {
      return (await this.auth?.current()) ?? null;
    } catch (e) {
      this.setPhase({ kind: "login-unreadable", detail: signInProblem(e) });
      return null;
    }
  }

  /** (Re)starts sync over a new session of the current login. */
  async restart(): Promise<void> {
    await this.controller?.stop();
    this.controller = null;
    this.problem = null;
    this.setPhase({ kind: "starting" });
    if (!("locks" in navigator) || typeof BroadcastChannel === "undefined") return this.setPhase({ kind: "unsupported" });
    const login = await this.currentLogin();
    if (login === null) {
      this.email = null;
      this.protection = null;
      if (this.phase.kind !== "login-unreadable") this.setPhase({ kind: "signed-out" });
      return;
    }
    this.email = login.email;
    let installationId: string;
    try {
      installationId = (await this.own()).installationId;
    } catch {
      return; // unloaded while waiting for the owner lock
    }
    const conn = { ...loginConnection(login, this.settings.vaultId), installationId, email: login.email };
    let trusted: Awaited<ReturnType<typeof trustedPlugin>>;
    try {
      trusted = await trustedPlugin(conn);
    } catch (e) {
      // §20.2: another account's connection is never used, nor removed without the user (NOTES question 413).
      const other = otherAccountOf(e);
      if (other !== null) return this.setPhase({ kind: "other-account", otherEmail: other.email });
      return this.setPhase({ kind: "unreachable", detail: String(e) });
    }
    void this.checkProtection(conn);
    if (trusted.replica === null) return this.setPhase({ kind: "not-enrolled" });
    const choice = trusted.vault;
    if (choice.kind === "NONE") return this.setPhase({ kind: "no-vault" });
    if (choice.kind === "ASK") {
      this.setPhase({ kind: "choose-vault", vaults: choice.vaults });
      return void this.openPanel();
    }
    if (choice.remember) await this.chooseVault(choice.vaultId, false);
    // §20.2: another sync tool on this folder holds sync until the user removes it or confirms (NOTES question 416).
    const held = await this.otherSyncTools();
    if (held.length > 0) return this.setPhase({ kind: "other-sync-tool", signals: held });
    const sync = loginConnection(login, choice.vaultId);
    let offered = false;
    this.controller = startSync({
      ...trusted.replica,
      fs: obsidianFileSystem(
        this.app.vault.adapter,
        (path) => {
          const f: TAbstractFile | null = this.app.vault.getAbstractFileByPath(path);
          return f instanceof TFile ? f : null;
        },
        replacingRename(this.app.vault.adapter) ?? undefined,
      ),
      locks: navigator.locks,
      channel: (name) => new BroadcastChannel(name),
      fetch: sync.fetch,
      settings: sync.settings,
      installationId,
      onStatus: (status) => {
        this.setPhase({ kind: "syncing", status });
        // §18.3, §35.8: revoked; told once per start, and the panel offers to connect again.
        if (status.reenroll && !offered) {
          offered = true;
          const notice = new Notice("Nodra: this vault's access was revoked, so it stopped syncing. Unsent changes are kept until it is connected again.", 0);
          notice.messageEl.createEl("button", { text: "Connect again" }).addEventListener("click", (event) => {
            event.stopPropagation();
            notice.hide();
            void this.openPanel();
          });
        }
      },
      notice: (message) => new Notice(message, 0),
      onSecurityAlert: (alert) => this.securityAlert(alert),
    });
    this.setPhase({ kind: "syncing", status: this.controller.status() });
    void this.pendingRecovery(false);
    void this.publishVaultSettings();
  }

  /**
   * §20.3: Obsidian's attachment folder setting for the other clients (vault-settings.ts), only while this
   * vault syncs. A failure is retried at the next check.
   */
  private async publishVaultSettings(): Promise<void> {
    if (this.controller === null || this.publishingSettings) return;
    this.publishingSettings = true;
    try {
      const last: unknown = this.app.loadLocalStorage(PUBLISHED_KEY);
      const wrote = await publishVaultSettings({
        adapter: this.app.vault.adapter,
        setting: attachmentFolderSetting(this.app.vault),
        lastPublished: typeof last === "string" ? last : null,
        remember: (value) => this.app.saveLocalStorage(PUBLISHED_KEY, value),
      });
      // Obsidian sends no vault event for a dot path: the sync is told directly.
      if (wrote) this.controller?.hint();
    } catch {
      // the next check retries
    } finally {
      this.publishingSettings = false;
    }
  }

  /** §35.15: the request ids already shown in this run; a restart shows a live one again. */
  private readonly shownRecovery = new Set<string>();

  /**
   * §35.15: the account's live recovery request, shown with its dates and a Veto button until the
   * user acts, once per run (`always`: the command, which says so when there is none).
   */
  private async pendingRecovery(always: boolean): Promise<void> {
    const conn = await this.connection();
    if (conn === null) return;
    let pending: PendingRecovery | null;
    try {
      pending = await pluginPendingRecovery(conn);
    } catch (e) {
      if (always) new Notice(`Nodra: the pending recovery request could not be checked: ${String(e)}`, 0);
      return;
    }
    if (pending === null) {
      if (always) new Notice("Nodra: no recovery request is pending on your account.");
      return;
    }
    if (!always && this.shownRecovery.has(pending.requestId)) return;
    this.shownRecovery.add(pending.requestId);
    const notice = new Notice(`Nodra: ${pendingRecoveryText(pending)}`, 0);
    const found = pending;
    notice.messageEl.createEl("button", { text: "Veto" }).addEventListener("click", (event) => {
      event.stopPropagation();
      notice.hide();
      this.vetoDialog(found);
    });
  }

  /** §35.15 the veto, with the credential the request asks for; neither is stored. */
  private vetoDialog(pending: PendingRecovery): void {
    const veto = async (credential: { readonly secrets: AccountSecrets } | { readonly recoveryKit: Uint8Array }) => {
      const conn = await this.connection();
      if (conn === null) return;
      try {
        await vetoFromPlugin({ ...conn, request: pending, ...credential });
        new Notice("Nodra: the recovery request is vetoed.");
      } catch (e) {
        new Notice(`Nodra: the veto failed: ${String(e)}`, 0);
      }
    };
    if (pending.vetoWith === "SECRETS") {
      new SecretsModal(this.app, "Veto this recovery request", "The Security Reset is stopped for good.", "Veto", true, async (secrets) => {
        if (secrets !== undefined) await veto({ secrets });
      }).open();
    } else {
      new RecoveryKitModal(this.app, (recoveryKit) => veto({ recoveryKit })).open();
    }
  }

  /**
   * §20.2, at every start: the known signals of another sync tool on this folder, minus those the user
   * confirmed on this device. A confirmation whose signal is gone is dropped, so it asks again if it returns.
   */
  private async otherSyncTools(): Promise<SyncSignal[]> {
    const { adapter, configDir } = this.app.vault;
    const facts = await observeSyncTools({
      adapter,
      configDir,
      basePath: adapter instanceof FileSystemAdapter ? adapter.getBasePath() : null,
      coreSyncEnabled: coreSyncPlugin(this.app)?.enabled ?? null,
    });
    const detected = detectOtherSyncTools(facts);
    const confirmed = parseConfirmations(this.app.loadLocalStorage(OTHER_SYNC_CONFIRMED_KEY));
    const kept = keptConfirmations(detected, confirmed);
    if (kept.join() !== confirmed.join()) this.app.saveLocalStorage(OTHER_SYNC_CONFIRMED_KEY, kept);
    return unconfirmedSignals(detected, kept);
  }

  /** §20.2: the explicit confirmation, for exactly the signals shown; then sync starts. */
  private confirmNoOtherSyncDialog(): void {
    if (this.phase.kind !== "other-sync-tool") return;
    const { signals } = this.phase;
    const c = otherSyncConfirmation(signals);
    new ConfirmModal(this.app, c.title, c.text, c.action, () => {
      const confirmed = parseConfirmations(this.app.loadLocalStorage(OTHER_SYNC_CONFIRMED_KEY));
      this.app.saveLocalStorage(OTHER_SYNC_CONFIRMED_KEY, [...new Set([...confirmed, ...signals.map((s) => s.id)])].sort());
      void this.restart();
    }).open();
  }

  /** NOTES question 128: the core Sync plugin off for this vault, only on the user's click; its manual steps when the app does not expose it. */
  private async turnOffObsidianSync(): Promise<void> {
    const sync = coreSyncPlugin(this.app);
    if (sync === null) {
      this.problem = OTHER_SYNC_MANUAL_STEPS;
      return this.changed();
    }
    try {
      await sync.disable(true);
    } catch {
      this.problem = OTHER_SYNC_MANUAL_STEPS;
      return this.changed();
    }
    new Notice("Nodra: Obsidian Sync is off for this vault.");
    await this.restart();
  }

  /** §3.6, once per login: Managed connects with the login alone, Private asks for the two secrets. */
  private async checkProtection(conn: Parameters<typeof pluginProtection>[0]): Promise<void> {
    if (this.protection !== null) return;
    try {
      this.protection = (await pluginProtection(conn)).mode;
    } catch (e) {
      this.problem = `Your account could not be checked: ${String(e)}`;
    }
    this.changed();
  }

  private syncNow(): void {
    if (this.controller) this.controller.syncNow();
    else void this.openPanel();
  }

  /**
   * §37: every unacknowledged event is shown until the user acknowledges it; nothing else acknowledges
   * it. One that can mean the account is compromised (`alarming`) opens a dialog; "Later" closes it
   * unacknowledged, so it opens again at the next start. The rest stay as a notice with its own button.
   */
  private securityAlert(alert: SecurityAlert): void {
    // §35.15: a request is also shown with its dates and its veto, from getRootState.
    if (alert.eventType.endsWith("_REQUESTED")) void this.pendingRecovery(false);
    const acknowledge = () =>
      void this.controller?.acknowledgeSecurityEvent(alert.id).catch(() => {
        new Notice("Nodra: acknowledged on this device; the server is told as soon as it is reachable.");
      });
    if (alert.alarming) {
      new SecurityAlertModal(this.app, alert.message, (modal) => {
        modal.close();
        acknowledge();
      }).open();
      return;
    }
    const notice = new Notice(`Nodra: ${alert.message}`, 0);
    notice.messageEl.createEl("button", { text: "Acknowledge" }).addEventListener("click", (event) => {
      event.stopPropagation();
      notice.hide();
      acknowledge();
    });
  }

  /** What the account operations take: a new session of the current login; null (and a notice) when signed out. */
  private async connection() {
    const login = await this.currentLogin();
    if (login === null) {
      new Notice(SIGN_IN_FIRST);
      return null;
    }
    const installationId = this.ownership?.installationId ?? this.installationId();
    return { ...loginConnection(login, this.settings.vaultId), installationId, email: login.email };
  }

  /** §35.4 for this installation. The secrets live only for this call. Throws when it fails. */
  private async enroll(secrets: AccountSecrets | undefined): Promise<void> {
    const conn = await this.connection();
    if (conn === null) throw new Error("signed out");
    await enrollPlugin({ ...conn, secrets, label: pluginLabel(Platform, this.app.vault.getName()) });
  }

  /** The panel's "Connect this vault": §35.4, then sync; a failure is shown in the panel. */
  private async connect(secrets: AccountSecrets | undefined): Promise<void> {
    if (this.busy !== null) return;
    this.busy = "connect";
    this.problem = null;
    this.changed();
    try {
      await this.enroll(secrets);
    } catch (e) {
      this.problem = `Could not connect: ${String(e)}`;
      return;
    } finally {
      this.busy = null;
      this.changed();
    }
    await this.restart();
  }

  /** §35.4 from the command or after a recovery, with notices; then sync. */
  private async enrollWithNotices(secrets: AccountSecrets | undefined): Promise<void> {
    new Notice("Nodra: enrolling this vault…");
    try {
      await this.enroll(secrets);
    } catch (e) {
      return void new Notice(`Nodra: enrollment failed: ${String(e)}`, 0);
    }
    new Notice("Nodra: enrolled. Starting sync.");
    await this.restart();
  }

  /** §35.4 (and §35.8 again after a revocation): on a Private account, the two secrets for this one call. */
  private enrollDialog(): void {
    void this.unlockDialog("Enroll this vault", "", "Enroll", (secrets) => this.enrollWithNotices(secrets));
  }

  /**
   * A security operation's dialog. §3.6: the verified root chain says whether the account is Managed,
   * which unlocks with the login alone (§24.2), or Private, which asks for the two secrets (§24).
   */
  private async unlockDialog(heading: string, text: string, action: string, submit: (secrets: AccountSecrets | undefined) => Promise<void>): Promise<void> {
    const conn = await this.connection();
    if (conn === null) return;
    let mode;
    try {
      mode = (await pluginProtection(conn)).mode;
    } catch (e) {
      return void new Notice(`Nodra: the account could not be verified: ${String(e)}`, 0);
    }
    new SecretsModal(this.app, heading, text, action, mode === "PRIVATE", submit).open();
  }

  /** Chosen once: saved, then sync starts on it (a later change would mix two vaults in one folder). */
  private async chooseVault(vaultId: string, restart = true): Promise<void> {
    this.settings = { ...this.settings, vaultId };
    await this.saveSettings();
    if (restart) await this.restart();
  }

  /** §35.1: the verified device list, then §35.5 on the one the user picks, with the two secrets. */
  private async devices(): Promise<void> {
    const conn = await this.connection();
    if (conn === null) return;
    let list;
    try {
      list = await pluginDevices(conn);
    } catch (e) {
      return void new Notice(`Nodra: the device list could not be verified: ${String(e)}`, 0);
    }
    new DevicesModal(this.app, list, (device) =>
      void this.unlockDialog(`Revoke "${device.label}"`, "It stops syncing at once, and every vault gets a new key it cannot open. What it already downloaded stays on it.", "Revoke", async (secrets) => {
        try {
          await revokeFromPlugin({ ...conn, secrets, recipientId: device.recipientId });
          new Notice(`Nodra: "${device.label}" is revoked.`);
        } catch (e) {
          new Notice(`Nodra: revocation failed: ${String(e)}`, 0);
        }
      }),
    ).open();
  }

  /** §35.10, after the plan's limit (getRootState) and the device list that will be able to read it. */
  private async createVault(): Promise<void> {
    const conn = await this.connection();
    if (conn === null) return;
    let active: number;
    try {
      const limit = await pluginVaultLimit(conn);
      if (limit !== null) return void new Notice(`Nodra: no new vault: ${limit}.`, 0);
      active = (await pluginDevices(conn)).filter((d) => d.status === "ACTIVE").length;
    } catch (e) {
      return void new Notice(`Nodra: ${String(e)}`, 0);
    }
    await this.unlockDialog("Create a new Nodra vault", `Readable by the ${active} active device${active === 1 ? "" : "s"} of your account. This Obsidian vault keeps syncing to the vault it chose; another Obsidian vault can choose the new one.`, "Create", async (secrets) => {
      try {
        const vaultId = await createVaultFromPlugin({ ...conn, secrets });
        new Notice(`Nodra: vault ${vaultId} created.`);
      } catch (e) {
        new Notice(`Nodra: the vault was not created: ${String(e)}`, 0);
      }
    });
  }

  /** §35.7 "Modo Managed": offered on a Managed account only; a Private one is recovered with its Recovery Kit. */
  private async recoverDialog(): Promise<void> {
    const conn = await this.connection();
    if (conn === null) return;
    let mode;
    try {
      mode = (await pluginProtection(conn)).mode;
    } catch (e) {
      return void new Notice(`Nodra: the account could not be verified: ${String(e)}`, 0);
    }
    if (mode === "PRIVATE") return void new Notice("Nodra: this account is Private: it is recovered with its Recovery Kit, not with the login.", 0);
    new ConfirmModal(
      this.app,
      "Recover your account",
      "Can't unlock this Managed account from any device, or think someone else got into it? Recovery goes through your login: it replaces the account's keys and revokes every device, this vault too, and each one enrolls again with your login. Your notes are kept. This vault enrolls again right after.",
      "Recover my account",
      () => void this.recover(),
    ).open();
  }

  /**
   * §35.7 from this installation. Sync stops first (this installation ends REVOKED). REAUTH_REQUIRED (a
   * login older than 5 minutes) asks for the login password and signs in again: a new session, kept in
   * the auth storage. Done: this vault enrolls again over a session built from that login (§35.8,
   * §24.2), then syncs.
   */
  private async recover(): Promise<void> {
    await this.controller?.stop();
    this.controller = null;
    this.setPhase({ kind: "starting" });
    const auth = this.auth;
    const login = await this.currentLogin();
    if (auth === null || login === null) return void new Notice(SIGN_IN_FIRST);
    try {
      await recoverFromPlugin({
        settings: { serverUrl: NODRA_API_URL, accessToken: await login.accessToken() },
        fetch: this.api,
        onPhase: (phase) => {
          if (phase === "RECOVERING") new Notice("Nodra: recovering the account…");
        },
        relogin: async () => {
          // §3.7: every method the user has; GitHub only when it is linked (an OAuth-only user has no password).
          const methods: readonly LoginMethod[] = await auth.loginMethods().catch(() => ["password"] as const);
          const github = this.github;
          const withGitHub = methods.includes("github") && github !== null ? () => github.reauthenticate() : null;
          return new Promise((resolve) =>
            new ReloginModal(this.app, login.email, methods.includes("password") || methods.length === 0 ? (password) => auth.relogin(password) : null, withGitHub, () => void github?.cancel(), resolve).open(),
          );
        },
      });
    } catch (e) {
      new Notice(`Nodra: the account was not recovered: ${String(e)}`, 0);
      return void (await this.restart());
    }
    new Notice("Nodra: the account is recovered. Every device was revoked; each one enrolls again with your login.", 0);
    await this.enrollWithNotices(undefined);
  }

  /** §11.3 from the panel: a new session of this installation's own; sync starts again over it. A refusal is shown in the panel. */
  private async signIn(email: string, password: string): Promise<void> {
    if (this.busy !== null || this.auth === null) return;
    this.busy = "sign-in";
    this.problem = null;
    this.changed();
    try {
      await this.auth.signIn(email, password);
    } catch (e) {
      this.problem = signInProblem(e);
      return;
    } finally {
      this.busy = null;
      this.changed();
    }
    this.protection = null;
    await this.restart();
  }

  /**
   * §3.7 from the panel: GitHub in the system browser, then the callback (`githubCallback`). The panel
   * waits with Cancel; 10 minutes without a callback end the flow. Account creation stays in Nodra Web:
   * a GitHub user without an account gets the existing "create your account in Nodra Web" state.
   */
  private async signInWithGitHub(): Promise<void> {
    if (this.busy !== null || this.github === null) return;
    this.busy = "github";
    this.problem = null;
    this.changed();
    let outcome: "SIGNED_IN" | "CANCELLED";
    try {
      outcome = await this.github.signIn();
    } catch (e) {
      this.problem = signInProblem(e);
      return;
    } finally {
      this.busy = null;
      this.changed();
    }
    if (outcome === "CANCELLED") return;
    this.protection = null;
    await this.restart();
  }

  /** `obsidian://nodra-auth`: a callback this instance did not start (or too late) changes nothing and says so. */
  private async githubCallback(params: Record<string, string | undefined>): Promise<void> {
    const handled = await this.github?.callback(params);
    if (handled === "IGNORED") new Notice("Nodra: this sign-in link is not for this vault or has expired.");
  }

  /**
   * "Disconnect this vault" (NOTES question 413): the confirmation says what goes, what stays, and how
   * many changes the other account never got; nothing is removed unless the user confirms.
   */
  private async disconnectDialog(): Promise<void> {
    if (this.busy !== null || this.phase.kind !== "other-account") return;
    const { otherEmail } = this.phase;
    const installationId = this.ownership?.installationId ?? this.installationId();
    let unsynced: number;
    try {
      unsynced = (await pluginLocalState({ installationId, vaultId: this.settings.vaultId })).unsynced;
    } catch (e) {
      this.problem = `The local sync data could not be read: ${String(e)}`;
      return this.changed();
    }
    const c = disconnectConfirmation({ otherEmail, email: this.email ?? "", unsynced });
    new ConfirmModal(this.app, c.title, c.text, c.action, () => void this.disconnect(installationId)).open();
  }

  /** After the confirmation: sync stopped, the chosen Nodra vault forgotten, the connection and local sync data removed; then connect. */
  private async disconnect(installationId: string): Promise<void> {
    if (this.busy !== null) return;
    this.busy = "disconnect";
    this.problem = null;
    this.changed();
    try {
      await this.controller?.stop();
      this.controller = null;
      const vaultId = this.settings.vaultId;
      // The other account's vault is forgotten first: a crash after it leaves the connection, shown again.
      if (vaultId !== "") await this.chooseVault("", false);
      await disconnectPlugin({ installationId, vaultId });
    } catch (e) {
      this.problem = `Could not disconnect: ${String(e)}`;
      return;
    } finally {
      this.busy = null;
      this.changed();
    }
    new Notice("Nodra: this vault is disconnected. Connect it to your account from the Nodra panel.");
    this.protection = null;
    await this.restart();
  }

  /** Stops sync, then ends this installation's session; the enrolled key stays, so signing in again resumes sync. */
  async logout(): Promise<void> {
    await this.controller?.stop();
    this.controller = null;
    await this.auth?.signOut().catch(() => undefined); // the local session is dropped even when the server does not answer
    this.email = null;
    this.protection = null;
    this.problem = null;
    this.setPhase({ kind: "signed-out" });
  }

  /**
   * §20.2: this instance's `owner` lock, requested once per load. While another instance holds it this
   * one does not sync and says so; the request stays queued until it is granted or the plugin unloads.
   */
  private own(): Promise<Ownership> {
    this.owning ??= takeOwnership({
      locks: navigator.locks,
      installationId: () => this.installationId(),
      signal: this.unloading.signal,
      onWaiting: () => this.setPhase({ kind: "waiting-owner" }),
    }).then((o) => {
      if (this.unloading.signal.aborted) {
        o.release(); // granted as the plugin unloaded: never keep it
        throw new Error("unloaded");
      }
      return (this.ownership = o);
    });
    return this.owning;
  }

  /** §20.2: generated once per vault and device, kept in Obsidian's local storage (outside the vault folder). */
  private installationId(): string {
    const existing: unknown = this.app.loadLocalStorage(INSTALLATION_KEY);
    if (typeof existing === "string" && existing !== "") return existing;
    const id = uuidv7();
    this.app.saveLocalStorage(INSTALLATION_KEY, id);
    return id;
  }
}

/** What is not in the Nodra panel: which Nodra vault was chosen, restarting sync, and (staging) Cloudflare Access. */
class NodraSettingTab extends PluginSettingTab {
  constructor(
    app: App,
    private readonly plugin: NodraPlugin,
  ) {
    super(app, plugin);
  }

  override display(): void {
    const { containerEl } = this;
    containerEl.empty();
    new Setting(containerEl)
      .setName("Use the Nodra panel")
      .setDesc("Sign in, connect this vault, and see and control sync from the Nodra panel in the right sidebar: the Nodra button in the ribbon, or the status bar item.")
      .addButton((b) => b.setButtonText("Open the Nodra panel").setCta().onClick(() => void this.plugin.openPanel()));
    const { vaultId } = this.plugin.settings;
    new Setting(containerEl)
      .setName("Nodra vault")
      .setDesc(vaultId === "" ? "Not chosen yet: asked when sync starts if your account has several." : `${vaultId} (chosen once for this Obsidian vault).`);
    new Setting(containerEl)
      .setName("Restart sync")
      .setDesc("Stop and start syncing this vault again.")
      .addButton((b) => b.setButtonText("Restart").onClick(() => void this.plugin.restart()));
    if (NODRA_ENV === "staging") {
      // NOTES question 393: only the staging API sits behind Cloudflare Access.
      new Setting(containerEl).setName("Cloudflare Access").setHeading();
      const desc = "The staging API's service token, sent with every request to the API and nowhere else. Kept in this plugin's data.json in plain text.";
      const field = (name: string, key: "accessClientId" | "accessClientSecret", password = false) =>
        new Setting(containerEl)
          .setName(name)
          .setDesc(desc)
          .addText((t) => {
            if (password) t.inputEl.type = "password";
            t.setValue(this.plugin.settings[key]).onChange(async (value) => {
              this.plugin.settings = { ...this.plugin.settings, [key]: value.trim() };
              await this.plugin.saveSettings();
            });
          });
      field("Access client id", "accessClientId");
      field("Access client secret", "accessClientSecret", true);
    }
  }
}

/**
 * One security operation (§35.1 Root Unlock). A Private account: the two secrets, dropped with the
 * dialog (§20.1). A Managed account: only the confirmation, since the login unlocks it (§24.2).
 */
class SecretsModal extends Modal {
  constructor(
    app: App,
    private readonly heading: string,
    private readonly text: string,
    private readonly action: string,
    private readonly askSecrets: boolean,
    private readonly submit: (secrets: AccountSecrets | undefined) => Promise<void>,
  ) {
    super(app);
  }

  override onOpen(): void {
    const { contentEl } = this;
    this.setTitle(this.heading);
    if (this.text !== "") contentEl.createEl("p", { text: this.text });
    let password = "";
    let secretKey = "";
    if (this.askSecrets) {
      contentEl.createEl("p", { text: "This account is Private: your Encryption Password and the Account Secret Key from your Setup Kit. They are used once and not stored." });
      new Setting(contentEl).setName("Encryption Password").addText((t) => {
        t.inputEl.type = "password";
        t.onChange((v) => (password = v));
      });
      new Setting(contentEl).setName("Account Secret Key").addText((t) => t.onChange((v) => (secretKey = v.trim())));
    } else {
      contentEl.createEl("p", { text: "This account is Managed: your login unlocks it, nothing else is needed." });
    }
    new Setting(contentEl).addButton((b) =>
      b.setButtonText(this.action).setCta().onClick(() => {
        this.close();
        void this.submit(this.askSecrets ? { password, secretKey } : undefined);
      }),
    );
  }

  override onClose(): void {
    this.contentEl.empty();
  }
}

/** §35.15: the veto of a kit replacement or a switch to Managed, with the current Recovery Kit file. */
class RecoveryKitModal extends Modal {
  constructor(
    app: App,
    private readonly submit: (recoveryKit: Uint8Array) => Promise<void>,
  ) {
    super(app);
  }

  override onOpen(): void {
    const { contentEl } = this;
    this.setTitle("Veto this recovery request");
    contentEl.createEl("p", { text: "Open your current Recovery Kit file. The request is stopped for good. The kit is used once and not stored." });
    const input = contentEl.createEl("input", { type: "file" });
    new Setting(contentEl).addButton((b) =>
      b.setButtonText("Veto").setWarning().onClick(() => {
        const file = input.files?.[0];
        if (file === undefined) return void new Notice("Nodra: choose your Recovery Kit file first.");
        this.close();
        void file.arrayBuffer().then((bytes) => this.submit(new Uint8Array(bytes)));
      }),
    );
  }

  override onClose(): void {
    this.contentEl.empty();
  }
}

/** A confirmation before an operation that cannot be undone. */
class ConfirmModal extends Modal {
  constructor(
    app: App,
    private readonly heading: string,
    /** One paragraph, or several. */
    private readonly text: string | readonly string[],
    private readonly action: string,
    private readonly confirm: () => void,
  ) {
    super(app);
  }

  override onOpen(): void {
    const { contentEl } = this;
    this.setTitle(this.heading);
    for (const text of typeof this.text === "string" ? [this.text] : this.text) contentEl.createEl("p", { text });
    new Setting(contentEl)
      .addButton((b) => b.setButtonText("Cancel").onClick(() => this.close()))
      .addButton((b) =>
        b.setButtonText(this.action).setWarning().onClick(() => {
          this.close();
          this.confirm();
        }),
      );
  }

  override onClose(): void {
    this.contentEl.empty();
  }
}

/**
 * §35.7 REAUTH_REQUIRED: a sign-in of the last 5 minutes, as the same user, with the methods the user
 * has (§3.7): the password (`login`, null for an OAuth-only user) and GitHub (`github`, null when not
 * linked), which must come back as the same user. A refused attempt stays in the dialog to try again;
 * closing it yields null (and ends a pending GitHub flow). The password is not kept.
 */
class ReloginModal extends Modal {
  private done = false;

  constructor(
    app: App,
    private readonly email: string,
    private readonly login: ((password: string) => Promise<string>) | null,
    private readonly github: (() => Promise<string | null>) | null,
    private readonly cancelGitHub: () => void,
    private readonly resolve: (accessToken: string | null) => void,
  ) {
    super(app);
  }

  private finish(accessToken: string): void {
    this.done = true;
    this.close();
    this.resolve(accessToken);
  }

  override onOpen(): void {
    const { contentEl } = this;
    this.setTitle("Sign in again to recover");
    const how = this.login !== null && this.github !== null ? "enter your password or continue with GitHub" : this.github !== null ? "continue with GitHub" : `enter the password of ${this.email} again`;
    contentEl.createEl("p", { text: `For your safety, recovery needs a recent sign-in as ${this.email}: ${how}.` });
    const error = contentEl.createEl("p", { cls: "mod-warning" });
    const login = this.login;
    if (login !== null) {
      let password = "";
      new Setting(contentEl).setName("Password").addText((t) => {
        t.inputEl.type = "password";
        t.onChange((v) => (password = v));
      });
      new Setting(contentEl).addButton((b) =>
        b.setButtonText("Sign in and retry").setCta().onClick(() => {
          if (password === "") return;
          login(password).then(
            (accessToken) => this.finish(accessToken),
            (e: unknown) => error.setText(signInProblem(e)),
          );
        }),
      );
    }
    const github = this.github;
    if (github !== null) {
      const waiting = contentEl.createEl("p", { cls: "nodra-panel-muted" });
      new Setting(contentEl).addButton((b) =>
        b.setButtonText("Continue with GitHub").onClick(() => {
          error.setText("");
          waiting.setText("Waiting for GitHub… Finish in your browser, choosing the GitHub account you sign in to Nodra with.");
          github().then(
            (accessToken) => {
              waiting.setText("");
              if (accessToken !== null) this.finish(accessToken);
            },
            (e: unknown) => {
              waiting.setText("");
              error.setText(signInProblem(e));
            },
          );
        }),
      );
    }
    new Setting(contentEl).addButton((b) => b.setButtonText("Cancel").onClick(() => this.close()));
  }

  override onClose(): void {
    this.contentEl.empty();
    if (!this.done) {
      this.cancelGitHub();
      this.resolve(null);
    }
  }
}

/** §35.1: the devices of the verified registry, each ACTIVE one but this one with "Revoke". */
class DevicesModal extends Modal {
  constructor(
    app: App,
    private readonly list: readonly { recipientId: string; label: string; type: string; status: string; thisDevice: boolean }[],
    private readonly revoke: (device: { recipientId: string; label: string }) => void,
  ) {
    super(app);
  }

  override onOpen(): void {
    const { contentEl } = this;
    this.setTitle("Nodra devices");
    for (const d of this.list) {
      const row = new Setting(contentEl)
        .setName(`${d.label}${d.thisDevice ? " (this vault)" : ""}`)
        .setDesc(`${d.type === "PLUGIN_INSTALLATION" ? "Obsidian plugin" : "browser"} · ${d.recipientId.slice(-8)} · ${d.status.toLowerCase()}`);
      if (d.status === "ACTIVE" && !d.thisDevice) {
        row.addButton((b) =>
          b.setButtonText("Revoke").setWarning().onClick(() => {
            this.close();
            this.revoke(d);
          }),
        );
      }
    }
  }

  override onClose(): void {
    this.contentEl.empty();
  }
}

/** §37: an event that can mean someone else holds the account's secrets or its Recovery Kit. */
class SecurityAlertModal extends Modal {
  constructor(
    app: App,
    private readonly message: string,
    private readonly acknowledge: (modal: SecurityAlertModal) => void,
  ) {
    super(app);
  }

  override onOpen(): void {
    const { contentEl } = this;
    this.setTitle("Nodra security alert");
    contentEl.createEl("p", { text: this.message });
    new Setting(contentEl)
      .addButton((b) => b.setButtonText("Later").onClick(() => this.close()))
      .addButton((b) => b.setButtonText("I have seen this").setCta().onClick(() => this.acknowledge(this)));
  }

  override onClose(): void {
    this.contentEl.empty();
  }
}
