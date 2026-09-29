import type { AccountSecrets } from "@nodra/sync-client";
import { type App, FileSystemAdapter, Modal, Notice, Platform, Plugin, PluginSettingTab, Setting, TFile, type TAbstractFile } from "obsidian";
import { v7 as uuidv7 } from "uuid";
import { type SecretStore, pluginAuthStorage } from "./auth-storage.js";
import {
  type SecurityAlert,
  type SyncController,
  type SyncStatus,
  createVaultFromPlugin,
  enrollPlugin,
  pluginDevices,
  pluginProtection,
  pluginVaultLimit,
  recoverFromPlugin,
  revokeFromPlugin,
  startSync,
  trustedPlugin,
} from "./controller.js";
import { obsidianFileSystem } from "./fs.js";
import { type PluginAuth, type PluginLogin, loginConnection, pluginAuth, signInProblem } from "./login.js";
import { type Ownership, takeOwnership } from "./owner.js";
import { type PluginSettings, DEFAULT_SETTINGS, apiFetch, loadSettings } from "./settings.js";

// The Nodra Obsidian plugin (§42): the sync client over the vault's DataAdapter, on the real §31 crypto,
// against the API and Supabase project fixed at build (globals.d.ts). Each vault signs in with its own
// Supabase Auth session (login.ts, §11.3), kept outside the vault (auth-storage.ts), then enrolls once
// (§35.4): a Managed account (ADR-021, the default) with the login alone (§24.2); a Private one with the
// account's two secrets, typed into a dialog and never stored. Its recipient key stays non-extractable
// in IndexedDB (§20.1). The account itself is created in Nodra Web (§35.2). From a trusted plugin: the
// device list and revocation (§35.5), a new vault (§35.10), and re-enrollment when this installation
// was revoked (§35.8). A Managed account can be recovered from here with the login alone (§35.7).
// Which Nodra vault this Obsidian vault syncs to is chosen once (`chooseVault`).

const INSTALLATION_KEY = "nodra-installation-id";
/** Where accounts are created (§35.2): the plugin creates none. */
const WEB_URL = "https://app.nodranotes.com";
const SIGN_IN_FIRST = 'Nodra: sign in first (command "Nodra: Sign in").';

type NodeFs = { promises: { rename(from: string, to: string): Promise<void> } };

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

const LABEL: Record<SyncStatus["kind"], string> = { idle: "Nodra: idle", syncing: "Nodra: syncing", paused: "Nodra: paused", error: "Nodra: error" };

export default class NodraPlugin extends Plugin {
  override settings: PluginSettings = DEFAULT_SETTINGS;
  /** Every request to the Nodra API goes through this one fetch (staging: the Cloudflare Access headers, NOTES question 393). */
  private readonly api: typeof fetch = NODRA_ENV === "staging" ? apiFetch(NODRA_API_URL, () => this.settings, (input, init) => fetch(input, init)) : (input, init) => fetch(input, init);
  private auth: PluginAuth | null = null;
  private controller: SyncController | null = null;
  private statusEl: HTMLElement | null = null;
  /** §20.2: the `owner` lock of this vault's installation, once held; requested once per load. */
  private ownership: Ownership | null = null;
  private owning: Promise<Ownership> | null = null;
  private readonly unloading = new AbortController();

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
    this.addSettingTab(new NodraSettingTab(this.app, this));
    this.statusEl = this.addStatusBarItem();
    this.show({ kind: "paused", detail: "not started" });
    this.addCommand({
      id: "sync-now",
      name: "Sync now",
      callback: () => {
        if (this.controller) this.controller.syncNow();
        else new Notice('Nodra is not syncing: sign in with the command "Nodra: Sign in", then enroll this vault.');
      },
    });
    this.addCommand({ id: "login", name: "Sign in", callback: () => this.signInDialog() });
    this.addCommand({ id: "logout", name: "Sign out", callback: () => void this.logout() });
    this.addCommand({ id: "enroll", name: "Enroll this vault", callback: () => this.enrollDialog() });
    this.addCommand({ id: "devices", name: "Manage devices", callback: () => void this.devices() });
    this.addCommand({ id: "create-vault", name: "Create a new Nodra vault", callback: () => void this.createVault() });
    this.addCommand({ id: "recover", name: "Recover the account", callback: () => void this.recoverDialog() });
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
    void this.auth?.dispose();
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
  }

  /** This installation's login as a new session (login.ts); null when signed out, or unreadable (shown). */
  async currentLogin(): Promise<PluginLogin | null> {
    try {
      return (await this.auth?.current()) ?? null;
    } catch (e) {
      this.show({ kind: "error", detail: `the login could not be read: ${signInProblem(e)}` });
      return null;
    }
  }

  /** (Re)starts sync over a new session of the current login. */
  async restart(): Promise<void> {
    await this.controller?.stop();
    this.controller = null;
    if (!("locks" in navigator) || typeof BroadcastChannel === "undefined") {
      this.show({ kind: "error", detail: "this device is not supported: Nodra needs navigator.locks and BroadcastChannel" });
      return;
    }
    const login = await this.currentLogin();
    if (login === null) {
      this.show({ kind: "paused", detail: 'signed out: run the command "Nodra: Sign in"' });
      return;
    }
    let installationId: string;
    try {
      installationId = (await this.own()).installationId;
    } catch {
      return; // unloaded while waiting for the owner lock
    }
    let trusted: Awaited<ReturnType<typeof trustedPlugin>>;
    try {
      trusted = await trustedPlugin({ ...loginConnection(login, this.settings.vaultId), installationId });
    } catch (e) {
      this.show({ kind: "error", detail: `Nodra could not be reached: ${String(e)}` });
      return;
    }
    if (trusted.replica === null) {
      this.show({ kind: "paused", detail: 'not enrolled: run the command "Nodra: Enroll this vault"' });
      return;
    }
    const choice = trusted.vault;
    if (choice.kind === "NONE") {
      this.show({ kind: "paused", detail: `the account has no vault yet: finish creating it at ${WEB_URL}` });
      return;
    }
    if (choice.kind === "ASK") {
      this.show({ kind: "paused", detail: "choose which Nodra vault this Obsidian vault syncs to" });
      new VaultPickerModal(this.app, choice.vaults, (vaultId) => void this.chooseVault(vaultId)).open();
      return;
    }
    if (choice.remember) await this.chooseVault(choice.vaultId, false);
    const conn = loginConnection(login, choice.vaultId);
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
      fetch: conn.fetch,
      settings: conn.settings,
      installationId,
      onStatus: (status) => {
        this.show(status);
        // §18.3, §35.8: revoked; offered once per start, and the command stays available.
        if (status.reenroll && !offered) {
          offered = true;
          const notice = new Notice("Nodra: this vault's access was revoked, so it stopped syncing. Unsent changes are kept until it is enrolled again.", 0);
          notice.messageEl.createEl("button", { text: "Enroll again" }).addEventListener("click", (event) => {
            event.stopPropagation();
            notice.hide();
            this.enrollDialog();
          });
        }
      },
      notice: (message) => new Notice(message, 0),
      onSecurityAlert: (alert) => this.securityAlert(alert),
    });
  }

  /**
   * §37: every unacknowledged event is shown until the user acknowledges it; nothing else acknowledges
   * it. One that can mean the account is compromised (`alarming`) opens a dialog; "Later" closes it
   * unacknowledged, so it opens again at the next start. The rest stay as a notice with its own button.
   */
  private securityAlert(alert: SecurityAlert): void {
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
    return { ...loginConnection(login, this.settings.vaultId), installationId };
  }

  /** §35.4 for this installation, then sync. The secrets live only for this call. */
  private async enroll(secrets: AccountSecrets | undefined): Promise<void> {
    const conn = await this.connection();
    if (conn === null) return;
    new Notice("Nodra: enrolling this vault…");
    try {
      await enrollPlugin({ ...conn, secrets, label: `Obsidian: ${this.app.vault.getName()}` });
    } catch (e) {
      return void new Notice(`Nodra: enrollment failed: ${String(e)}`, 0);
    }
    new Notice("Nodra: enrolled. Starting sync.");
    await this.restart();
  }

  /** §35.4 (and §35.8 again after a revocation): on a Private account, the two secrets for this one call. */
  private enrollDialog(): void {
    void this.unlockDialog("Enroll this vault", "", "Enroll", (secrets) => this.enroll(secrets));
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
        relogin: () => new Promise((resolve) => new ReloginModal(this.app, login.email, (password) => auth.relogin(password), resolve).open()),
      });
    } catch (e) {
      new Notice(`Nodra: the account was not recovered: ${String(e)}`, 0);
      return void (await this.restart());
    }
    new Notice("Nodra: the account is recovered. Every device was revoked; each one enrolls again with your login.", 0);
    await this.enroll(undefined);
  }

  signInDialog(): void {
    void this.currentLogin().then((login) => new LoginModal(this.app, login?.email ?? "", (email, password) => this.login(email, password)).open());
  }

  /** §11.3: a new session of this installation's own; sync starts again over it. */
  private async login(email: string, password: string): Promise<void> {
    await this.auth?.signIn(email, password);
    new Notice(`Nodra: signed in as ${email}.`);
    await this.restart();
  }

  /** Stops sync, then ends this installation's session; the enrolled key stays, so signing in again resumes sync. */
  async logout(): Promise<void> {
    await this.controller?.stop();
    this.controller = null;
    await this.auth?.signOut().catch(() => undefined); // the local session is dropped even when the server does not answer
    this.show({ kind: "paused", detail: "signed out" });
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
      onWaiting: () => this.show({ kind: "paused", detail: "another instance of Nodra controls this vault; waiting for it to close" }),
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

  private show(status: SyncStatus): void {
    this.statusEl?.setText(LABEL[status.kind]);
    this.statusEl?.setAttr("title", status.detail ?? LABEL[status.kind]);
  }
}

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
    const account = new Setting(containerEl).setName("Account").setDesc("Checking…");
    void this.plugin.currentLogin().then((login) => {
      if (login === null) {
        account.setDesc("Signed out. Sign in with your Nodra account; create one in Nodra Web first.");
        account.addButton((b) => b.setButtonText("Sign in").setCta().onClick(() => this.plugin.signInDialog()));
      } else {
        account.setDesc(`Signed in as ${login.email}.`);
        account.addButton((b) =>
          b.setButtonText("Sign out").onClick(async () => {
            await this.plugin.logout();
            this.display();
          }),
        );
      }
    });
    const { vaultId } = this.plugin.settings;
    new Setting(containerEl)
      .setName("Nodra vault")
      .setDesc(vaultId === "" ? "Not chosen yet: asked when sync starts if your account has several." : `${vaultId} (chosen once for this Obsidian vault).`);
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
    new Setting(containerEl)
      .setName("Restart sync")
      .setDesc("Stop and start syncing this vault again.")
      .addButton((b) => b.setButtonText("Restart").onClick(() => void this.plugin.restart()));
  }
}

/** The sign-in (§11.3) with an existing Nodra account; the password is not kept. Accounts are created in Nodra Web (§35.2). */
class LoginModal extends Modal {
  constructor(
    app: App,
    private readonly email: string,
    private readonly submit: (email: string, password: string) => Promise<void>,
  ) {
    super(app);
  }

  override onOpen(): void {
    const { contentEl } = this;
    this.setTitle("Sign in to Nodra");
    const intro = contentEl.createEl("p", { text: "Use the email and password of your Nodra account. This is not your Encryption Password. " });
    intro.appendText("No account yet? Create one at ");
    intro.createEl("a", { text: "app.nodranotes.com", href: WEB_URL });
    intro.appendText(": this plugin does not create accounts.");
    let email = this.email;
    let password = "";
    new Setting(contentEl).setName("Email").addText((t) => {
      t.inputEl.type = "email";
      t.setValue(email).onChange((v) => (email = v.trim()));
    });
    new Setting(contentEl).setName("Password").addText((t) => {
      t.inputEl.type = "password";
      t.onChange((v) => (password = v));
    });
    const error = contentEl.createEl("p", { cls: "mod-warning" });
    new Setting(contentEl).addButton((b) =>
      b.setButtonText("Sign in").setCta().onClick(() => {
        if (email === "" || password === "") return;
        b.setDisabled(true);
        this.submit(email, password).then(
          () => this.close(),
          (e: unknown) => {
            error.setText(signInProblem(e));
            b.setDisabled(false);
          },
        );
      }),
    );
  }

  override onClose(): void {
    this.contentEl.empty();
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

/** A confirmation before an operation that cannot be undone. */
class ConfirmModal extends Modal {
  constructor(
    app: App,
    private readonly heading: string,
    private readonly text: string,
    private readonly action: string,
    private readonly confirm: () => void,
  ) {
    super(app);
  }

  override onOpen(): void {
    const { contentEl } = this;
    this.setTitle(this.heading);
    contentEl.createEl("p", { text: this.text });
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
 * §35.7 REAUTH_REQUIRED: a sign-in of the last 5 minutes, as the same user. A refused password stays in
 * the dialog to try again; closing it yields null. The password is not kept.
 */
class ReloginModal extends Modal {
  private done = false;

  constructor(
    app: App,
    private readonly email: string,
    private readonly login: (password: string) => Promise<string>,
    private readonly resolve: (accessToken: string | null) => void,
  ) {
    super(app);
  }

  override onOpen(): void {
    const { contentEl } = this;
    this.setTitle("Sign in again to recover");
    contentEl.createEl("p", { text: `For your safety, recovery needs a recent sign-in: enter the password of ${this.email} again.` });
    let password = "";
    new Setting(contentEl).setName("Password").addText((t) => {
      t.inputEl.type = "password";
      t.onChange((v) => (password = v));
    });
    const error = contentEl.createEl("p", { cls: "mod-warning" });
    new Setting(contentEl)
      .addButton((b) => b.setButtonText("Cancel").onClick(() => this.close()))
      .addButton((b) =>
        b.setButtonText("Sign in and retry").setCta().onClick(() => {
          if (password === "") return;
          this.login(password).then(
            (accessToken) => {
              this.done = true;
              this.close();
              this.resolve(accessToken);
            },
            (e: unknown) => error.setText(signInProblem(e)),
          );
        }),
      );
  }

  override onClose(): void {
    this.contentEl.empty();
    if (!this.done) this.resolve(null);
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

/** Which Nodra vault this Obsidian vault syncs to: asked once, when the account has several. */
class VaultPickerModal extends Modal {
  constructor(
    app: App,
    private readonly vaults: readonly string[],
    private readonly pick: (vaultId: string) => void,
  ) {
    super(app);
  }

  override onOpen(): void {
    const { contentEl } = this;
    this.setTitle("Choose the Nodra vault");
    contentEl.createEl("p", { text: "This Obsidian vault will sync to the one you choose, for good: pointing it at another later would mix both." });
    this.vaults.forEach((vaultId, i) =>
      new Setting(contentEl).setName(`Vault ${i + 1}`).setDesc(vaultId).addButton((b) =>
        b.setButtonText("Sync to this one").onClick(() => {
          this.close();
          this.pick(vaultId);
        }),
      ),
    );
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
