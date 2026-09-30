import type { AccountSecrets } from "@nodra/sync-client";
import { ItemView, Setting, type WorkspaceLeaf } from "obsidian";
import { type PanelActionId, type PanelFacts, type PanelState, type Protection, WEB_URL, panelState } from "./panel.js";

// The Nodra panel in the right sidebar: it renders panel.ts's state and wires each control to one of
// the plugin's existing flows (PanelActions, main.ts). No decision is taken here. The Encryption Password
// and the Account Secret Key typed into it go to that one call and are cleared at once (§20.1).

export const VIEW_TYPE_NODRA = "nodra-panel";

export interface PanelActions {
  signIn(email: string, password: string): Promise<void>;
  /** §35.4 for this installation; the secrets only on a Private account. */
  connect(secrets: AccountSecrets | undefined): Promise<void>;
  chooseVault(vaultId: string): Promise<void>;
  createVault(): void;
  syncNow(): void;
  pause(): void;
  resume(): void;
  restart(): void;
  /** Drop this installation's session, so the sign-in form shows. */
  signInAgain(): void;
  signOut(): void;
  devices(): void;
  recover(): void;
}

export interface PanelSource {
  facts(): PanelFacts;
  /** The listener runs on every change of the facts; the result unsubscribes. */
  subscribe(listener: () => void): () => void;
  readonly actions: PanelActions;
}

const SYNC_TEXT = { synced: "Synced", syncing: "Syncing…", paused: "Paused", offline: "Offline" } as const;
const PROTECTION_TEXT: Record<Protection, string> = { MANAGED: "Managed", PRIVATE: "Private" };

export class NodraPanelView extends ItemView {
  /** The state last rendered (as JSON): an update to the same state leaves the DOM, and what is being typed, alone. */
  private rendered = "";
  private email = "";
  private password = "";

  constructor(
    leaf: WorkspaceLeaf,
    private readonly source: PanelSource,
  ) {
    super(leaf);
  }

  getViewType(): string {
    return VIEW_TYPE_NODRA;
  }

  getDisplayText(): string {
    return "Nodra";
  }

  override getIcon(): string {
    return "cloud";
  }

  override async onOpen(): Promise<void> {
    this.register(this.source.subscribe(() => this.render()));
    this.render();
  }

  override async onClose(): Promise<void> {
    this.contentEl.empty();
    this.rendered = "";
    this.password = "";
  }

  private render(): void {
    const state = panelState(this.source.facts());
    const key = JSON.stringify(state);
    if (key === this.rendered) return;
    this.rendered = key;
    if (state.kind !== "signed-out") this.password = "";
    if ("email" in state && state.email !== null && state.email !== "") this.email = state.email;
    const el = this.contentEl;
    el.empty();
    el.addClass("nodra-panel");
    this.screen(el, state);
  }

  private screen(el: HTMLElement, s: PanelState): void {
    const a = this.source.actions;
    switch (s.kind) {
      case "loading":
        el.createEl("p", { text: s.text, cls: "nodra-panel-muted" });
        return;
      case "signed-out":
        return this.signInForm(el, s.busy, s.problem);
      case "connect":
        this.connectForm(el, s);
        return this.account(el, s.email, s.protection, false);
      case "choose-vault":
        el.createEl("h4", { text: "Choose the Nodra vault" });
        el.createEl("p", { text: "This Obsidian vault will sync to the one you choose, for good: pointing it at another later would mix both." });
        s.vaults.forEach((vaultId, i) =>
          new Setting(el)
            .setName(`Vault ${i + 1}`)
            .setDesc(vaultId)
            .addButton((b) => b.setButtonText("Sync to this one").onClick(() => void a.chooseVault(vaultId))),
        );
        return this.account(el, s.email, null, false);
      case "no-vault": {
        el.createEl("h4", { text: "No vault yet" });
        const p = el.createEl("p", { text: "Your account has no vault yet. Finish creating it in " });
        p.createEl("a", { text: "Nodra Web", href: WEB_URL });
        p.appendText(", then try again.");
        new Setting(el).addButton((b) => b.setButtonText("Try again").setCta().onClick(() => a.restart()));
        return this.account(el, s.email, null, false);
      }
      case "connected": {
        this.status(el, `is-${s.sync}`, SYNC_TEXT[s.sync]);
        if (s.lastSynced !== null) el.createEl("p", { text: `Last synced ${s.lastSynced}`, cls: "nodra-panel-muted" });
        if (s.note !== null) el.createEl("p", { text: s.note, cls: "nodra-panel-muted" });
        const paused = s.sync === "paused";
        new Setting(el)
          .addButton((b) => b.setButtonText("Sync now").setCta().onClick(() => a.syncNow()))
          .addButton((b) => b.setButtonText(paused ? "Resume" : "Pause").onClick(() => (paused ? a.resume() : a.pause())));
        return this.account(el, s.email, s.protection, true);
      }
      case "attention": {
        this.status(el, "is-attention", s.title);
        el.createEl("p", { text: s.explanation });
        const action = s.action;
        if (action !== null) new Setting(el).addButton((b) => b.setButtonText(action.label).setCta().onClick(() => this.run(action.id)));
        if (s.email !== null) this.account(el, s.email, s.protection, true);
        return;
      }
    }
  }

  private run(id: PanelActionId): void {
    const a = this.source.actions;
    if (id === "sync-now") a.syncNow();
    else if (id === "restart") a.restart();
    else a.signInAgain();
  }

  private status(el: HTMLElement, cls: string, text: string): void {
    const row = el.createDiv("nodra-panel-status-row");
    row.createSpan({ cls: ["nodra-panel-dot", cls] });
    row.createSpan({ text, cls: "nodra-panel-status" });
  }

  private signInForm(el: HTMLElement, busy: boolean, problem: string | null): void {
    el.createEl("h4", { text: "Sign in to Nodra" });
    el.createEl("p", { text: "Use the email and password of your Nodra account. This is not your Encryption Password.", cls: "nodra-panel-muted" });
    const submit = () => {
      const email = this.email.trim();
      if (busy || email === "" || this.password === "") return;
      void this.source.actions.signIn(email, this.password);
    };
    new Setting(el).setName("Email").addText((t) => {
      t.inputEl.type = "email";
      t.setValue(this.email).onChange((v) => (this.email = v));
    });
    new Setting(el).setName("Password").addText((t) => {
      t.inputEl.type = "password";
      t.setValue(this.password).onChange((v) => (this.password = v));
      t.inputEl.addEventListener("keydown", (e) => {
        if (e.key === "Enter") submit();
      });
    });
    if (problem !== null) el.createEl("p", { text: problem, cls: ["nodra-panel-problem", "mod-warning"] });
    new Setting(el).addButton((b) =>
      b
        .setButtonText(busy ? "Signing in…" : "Sign in")
        .setCta()
        .setDisabled(busy)
        .onClick(submit),
    );
    const create = el.createEl("p", { text: "No account? ", cls: "nodra-panel-muted" });
    create.createEl("a", { text: "Create one", href: WEB_URL });
    create.appendText(" in Nodra Web: this plugin does not create accounts.");
  }

  private connectForm(el: HTMLElement, s: Extract<PanelState, { kind: "connect" }>): void {
    const label = s.again ? "Connect again" : "Connect this vault";
    el.createEl("h4", { text: label });
    if (s.again) el.createEl("p", { text: "This vault's access was revoked, so it stopped syncing. Unsent changes are kept until you connect it again." });
    else el.createEl("p", { text: "Sync this Obsidian vault with your Nodra account. Notes are encrypted on this device before they are uploaded." });
    const privateAccount = s.protection === "PRIVATE";
    const typed = { password: "", secretKey: "" };
    const inputs: HTMLInputElement[] = [];
    if (s.protection === null) el.createEl("p", { text: "Checking your account…", cls: "nodra-panel-muted" });
    else if (!privateAccount) el.createEl("p", { text: "Your account is Managed: your sign-in is enough.", cls: "nodra-panel-muted" });
    else {
      el.createEl("p", { text: "Your account is Private: type your Encryption Password and the Account Secret Key from your Setup Kit. They are used for this step only and never stored.", cls: "nodra-panel-muted" });
      new Setting(el).setName("Encryption Password").addText((t) => {
        t.inputEl.type = "password";
        inputs.push(t.inputEl);
        t.onChange((v) => (typed.password = v));
      });
      new Setting(el).setName("Account Secret Key").addText((t) => {
        inputs.push(t.inputEl);
        t.onChange((v) => (typed.secretKey = v.trim()));
      });
    }
    if (s.problem !== null) el.createEl("p", { text: s.problem, cls: ["nodra-panel-problem", "mod-warning"] });
    // The account could not be checked: check again (restart asks the root chain once more).
    if (s.protection === null && s.problem !== null) new Setting(el).addButton((b) => b.setButtonText("Try again").onClick(() => this.source.actions.restart()));
    new Setting(el).addButton((b) =>
      b
        .setButtonText(s.busy ? "Connecting…" : label)
        .setCta()
        .setDisabled(s.busy || s.protection === null)
        .onClick(() => {
          if (s.busy || s.protection === null) return;
          if (!privateAccount) return void this.source.actions.connect(undefined);
          // Handed to this one call and dropped from the form at once (§20.1).
          const secrets = { ...typed };
          typed.password = "";
          typed.secretKey = "";
          for (const i of inputs) i.value = "";
          if (secrets.password === "" || secrets.secretKey === "") return;
          void this.source.actions.connect(secrets);
        }),
    );
  }

  private account(el: HTMLElement, email: string, protection: Protection | null, connected: boolean): void {
    const a = this.source.actions;
    new Setting(el).setName("Account").setHeading();
    new Setting(el)
      .setName(protection === null ? email : `${email} · ${PROTECTION_TEXT[protection]}`)
      .addButton((b) => b.setButtonText("Sign out").onClick(() => a.signOut()));
    if (!connected) return;
    new Setting(el)
      .setName("Devices")
      .setDesc("The devices that can open your vaults. Revoke one you no longer use.")
      .addButton((b) => b.setButtonText("Manage devices").onClick(() => a.devices()));
    new Setting(el)
      .setName("New Nodra vault")
      .setDesc("For another Obsidian vault. This one keeps syncing to the vault it chose.")
      .addButton((b) => b.setButtonText("Create vault").onClick(() => a.createVault()));
    const recover = el.createEl("p", { cls: "nodra-panel-muted" });
    recover.createEl("a", { text: "Can't unlock your account?", href: "#" }).addEventListener("click", (e) => {
      e.preventDefault();
      a.recover();
    });
  }
}
