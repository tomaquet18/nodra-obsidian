// @vitest-environment happy-dom
import { InstallationOtherAccountError, SessionError, TrustError } from "@nodra/sync-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SyncDeps, SyncStatus } from "../src/controller.js";
import { VIEW_TYPE_NODRA } from "../src/panel-view.js";
import { App, Modal, Notice } from "./support/obsidian-api.js";

// main.ts over the fake `obsidian` runtime: the ribbon button and the right-sidebar view, the panel
// opened once on the first run, the clickable status bar, and the panel's controls reaching the same
// flows the commands use (sign in → connect → sync). The account operations themselves (controller.ts,
// login.ts) are mocked here: their own tests cover them against the real server code.

const m = vi.hoisted(() => ({
  trustedPlugin: vi.fn(),
  enrollPlugin: vi.fn(),
  startSync: vi.fn(),
  pluginProtection: vi.fn(),
  pluginDevices: vi.fn(),
  pluginVaultLimit: vi.fn(),
  createVaultFromPlugin: vi.fn(),
  recoverFromPlugin: vi.fn(),
  revokeFromPlugin: vi.fn(),
  pluginAuth: vi.fn(),
  pluginLocalState: vi.fn(),
  disconnectPlugin: vi.fn(),
}));
vi.mock("../src/controller.js", () => ({
  trustedPlugin: m.trustedPlugin,
  enrollPlugin: m.enrollPlugin,
  startSync: m.startSync,
  pluginProtection: m.pluginProtection,
  pluginDevices: m.pluginDevices,
  pluginVaultLimit: m.pluginVaultLimit,
  createVaultFromPlugin: m.createVaultFromPlugin,
  recoverFromPlugin: m.recoverFromPlugin,
  revokeFromPlugin: m.revokeFromPlugin,
  pluginLocalState: m.pluginLocalState,
  disconnectPlugin: m.disconnectPlugin,
  otherAccountOf: (e: unknown) => (e instanceof InstallationOtherAccountError ? e.other : null),
}));
vi.mock("../src/login.js", async (original) => ({ ...(await original<typeof import("../src/login.js")>()), pluginAuth: m.pluginAuth }));
vi.mock("../src/owner.js", () => ({ takeOwnership: async () => ({ installationId: "installation-1", release() {} }) }));

vi.stubGlobal("NODRA_ENV", "production");
vi.stubGlobal("NODRA_API_URL", "https://api.test");
vi.stubGlobal("NODRA_SUPABASE_URL", "https://auth.test");
vi.stubGlobal("NODRA_SUPABASE_ANON_KEY", "anon");
vi.stubGlobal("NODRA_OAUTH_CLIENT_ID", "3b7e2a40-5c1d-4e8f-9a6b-2d4c6e8f0a12");
if (typeof BroadcastChannel === "undefined") vi.stubGlobal("BroadcastChannel", class {});
Object.defineProperty(navigator, "locks", { value: { request: async () => undefined }, configurable: true });

const { default: NodraPlugin } = await import("../src/main.js");

async function until(cond: () => boolean, what: string, ms = 5_000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

const EMAIL = "ana@example.test";
const login = { session: { baseUrl: "https://api.test", fetch: vi.fn() }, email: EMAIL, accessToken: async () => "token" };

/** A fake login store: signed in once a browser sign-in's session is adopted (ADR-024). */
function auth(signedIn = false) {
  let current = signedIn;
  return {
    // A flow client that takes the tokens of the code exchange; adopting its session signs in.
    flowClient: vi.fn(() => ({ useTokens: async () => undefined, dispose: async () => undefined })),
    adoptSession: vi.fn(async () => ((current = true), true)),
    userId: vi.fn(async () => (current ? "01890000-0000-7000-8000-000000000001" : null)),
    accessToken: vi.fn(async () => "token"),
    current: vi.fn(async () => (current ? login : null)),
    signOut: vi.fn(async () => void (current = false)),
    dispose: vi.fn(async () => {}),
  };
}

/** ADR-024: the browser sign-in's two ends here: the URL sent to the system browser, and the protocol handler. */
const SIGN_IN = "Sign in with your browser";
const opens = () => (window.open as unknown as { mock: { calls: unknown[][] } }).mock.calls;
const handler = (plugin: unknown) => (plugin as { protocolHandlers: Map<string, (p: Record<string, string>) => unknown> }).protocolHandlers.get("nodra-auth")!;
/** The authorize URL last opened, and the callback params Nodra Web's consent would send back (`code` + this flow's `state`). */
const opened = () => {
  const url = new URL(opens().at(-1)![0] as string);
  return { url, params: { action: "nodra-auth", code: "code-1", state: url.searchParams.get("state")! } as Record<string, string> };
};
/** Supabase's token endpoint answering the code exchange (the only fetch the browser sign-in makes). */
const tokenEndpoint = () =>
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    if (!String(input).endsWith("/auth/v1/oauth/token")) throw new Error(`unexpected fetch ${String(input)}`);
    return Response.json({ access_token: "access", token_type: "bearer", expires_in: 3600, refresh_token: "refresh" });
  });

function controller() {
  let onStatus: (s: SyncStatus) => void = () => {};
  const c = { hint: vi.fn(), syncNow: vi.fn(), pause: vi.fn(async () => onStatus({ kind: "paused" })), resume: vi.fn(), stop: vi.fn(async () => {}), status: () => ({ kind: "idle" }) as SyncStatus, acknowledgeSecurityEvent: vi.fn() };
  m.startSync.mockImplementation((d: SyncDeps) => {
    onStatus = d.onStatus!;
    return c;
  });
  return { c, emit: (s: SyncStatus) => onStatus(s) };
}

let app: App;
let plugins: InstanceType<typeof NodraPlugin>[] = [];
beforeEach(() => {
  vi.resetAllMocks();
  app = new App();
  m.pluginProtection.mockResolvedValue({ mode: "MANAGED" });
  m.enrollPlugin.mockResolvedValue(undefined);
});
afterEach(() => {
  for (const p of plugins) p.onunload();
  plugins = [];
});

async function load(a = auth(), on = app, data: unknown = null) {
  m.pluginAuth.mockReturnValue(a);
  const plugin = new NodraPlugin(on as never, { id: "nodra" } as never);
  (plugin as unknown as { data: unknown }).data = data;
  plugins.push(plugin);
  await plugin.onload();
  on.workspace.layoutReady();
  return { plugin, fake: plugin as unknown as { ribbon: { icon: string; title: string; el: HTMLElement }[]; statusBar: HTMLElement[]; commands: { id: string; name: string }[] } };
}

const panels = (on = app) => on.workspace.getLeavesOfType(VIEW_TYPE_NODRA);
const panelEl = () => panels()[0]!.view!.contentEl;
const button = (text: string) => {
  const b = [...panelEl().querySelectorAll("button")].find((x) => x.textContent === text);
  if (b === undefined) throw new Error(`no button "${text}" in the panel: ${panelEl().textContent}`);
  return b;
};
const hasButton = (text: string) => panels().length > 0 && [...panelEl().querySelectorAll("button")].some((x) => x.textContent === text && !x.disabled);
const type = (name: string, value: string) => {
  const row = [...panelEl().querySelectorAll(".setting-item")].find((r) => r.querySelector(".setting-item-name")?.textContent === name);
  const i = row!.querySelector("input")!;
  i.value = value;
  i.dispatchEvent(new Event("input"));
};

describe("the Nodra button and panel", () => {
  it("a ribbon button named Nodra opens the panel in the right sidebar, once", async () => {
    m.trustedPlugin.mockResolvedValue({ replica: null, vault: { kind: "NONE" } });
    const { fake } = await load(auth(true));
    const ribbon = fake.ribbon.find((r) => r.title === "Nodra");
    expect(ribbon?.icon).toBe("cloud");
    ribbon!.el.click();
    await until(() => panels().length === 1 && app.workspace.revealed.length === 1, "the panel revealed");
    expect(app.workspace.rightLeaves).toHaveLength(1);
    ribbon!.el.click();
    await until(() => app.workspace.revealed.length === 2, "revealed again");
    expect(panels()).toHaveLength(1); // the same panel, not a second one
  });

  it("the status bar item opens the panel too, and says where sync is", async () => {
    const { fake } = await load();
    await until(() => fake.statusBar[0]!.textContent === "Nodra: signed out" && panels().length === 1, "signed out, the first run's panel open");
    app.workspace.leaves.splice(0); // the user closed it
    expect(fake.statusBar[0]!.classList.contains("mod-clickable")).toBe(true);
    fake.statusBar[0]!.click();
    await until(() => panels().length === 1, "the panel from the status bar");
  });

  it("the first run, signed out, opens the panel once; a later load does not", async () => {
    await load();
    await until(() => panels().length === 1, "the panel on the first run");
    plugins.pop()!.onunload();
    app.workspace.leaves.splice(0);
    await load();
    await new Promise((r) => setTimeout(r, 50));
    expect(panels()).toHaveLength(0);
  });

  it("the first run while already signed in does not open it", async () => {
    m.trustedPlugin.mockResolvedValue({ replica: null, vault: { kind: "NONE" } });
    await load(auth(true));
    await new Promise((r) => setTimeout(r, 50));
    expect(panels()).toHaveLength(0);
  });

  it("the commands are still there, as shortcuts", async () => {
    const { fake } = await load();
    expect(fake.commands.map((c) => c.id)).toEqual(expect.arrayContaining(["sync-now", "login", "logout", "enroll", "devices", "toggle-pause", "open-panel"]));
  });

  // Obsidian shows the plugin's name next to every command (obsidianmd/commands/no-plugin-name-in-command-name).
  it("no command name repeats the plugin's name", async () => {
    const { fake } = await load();
    const names = fake.commands.map((c) => c.name);
    expect(names.filter((n) => /nodra/i.test(n))).toEqual([]);
    expect(names).toEqual(expect.arrayContaining(["Open panel", "Create a new vault"]));
  });
});

describe("everything from the panel: sign in → connect → sync", () => {
  it("Managed: a refusal inline (Deny on the consent page), then sign in through the browser, connect with one click, sync, pause, sign out", async () => {
    vi.spyOn(window, "open").mockImplementation(() => null);
    tokenEndpoint();
    const a = auth();
    const { c, emit } = controller();
    const { fake, plugin } = await load(a);
    await until(() => hasButton(SIGN_IN), "the sign-in button");

    button(SIGN_IN).click();
    await until(() => opens().length === 1 && hasButton("Cancel"), "the browser opened");
    await handler(plugin)({ action: "nodra-auth", error: "access_denied", error_description: "User denied the request", state: opened().params.state! });
    await until(() => panelEl().textContent!.includes("You did not allow Nodra for Obsidian"), "the refusal inline");
    expect(a.adoptSession).not.toHaveBeenCalled();

    m.trustedPlugin.mockResolvedValue({ replica: null, vault: { kind: "SYNC", vaultId: "v1", remember: true } });
    button(SIGN_IN).click();
    await until(() => opens().length === 2, "the browser opened again");
    await handler(plugin)(opened().params);
    await until(() => hasButton("Connect this vault"), "the connect screen");
    expect(a.adoptSession).toHaveBeenCalledTimes(1);
    expect(panelEl().textContent).toContain(`${EMAIL} · Managed`);

    m.trustedPlugin.mockResolvedValue({ replica: { auth: {}, vaultCrypto: {}, planLimits: {} }, vault: { kind: "SYNC", vaultId: "v1", remember: true } });
    button("Connect this vault").click();
    await until(() => m.startSync.mock.calls.length === 1, "sync started");
    expect(m.enrollPlugin).toHaveBeenCalledTimes(1);
    expect(m.enrollPlugin.mock.calls[0]![0]).toMatchObject({ secrets: undefined, label: "Obsidian · Test vault", installationId: "installation-1" });

    emit({ kind: "idle" });
    await until(() => panelEl().querySelector(".nodra-panel-status")?.textContent === "Synced", "Synced");
    expect(panelEl().textContent).toContain("Last synced just now");
    expect(fake.statusBar[0]!.textContent).toBe("Nodra: synced");
    button("Sync now").click();
    expect(c.syncNow).toHaveBeenCalledTimes(1);
    button("Pause").click();
    await until(() => hasButton("Resume"), "Paused");
    button("Resume").click();
    expect(c.resume).toHaveBeenCalledTimes(1);

    emit({ kind: "idle", detail: "waiting: storage quota exceeded", code: "QUOTA_EXCEEDED" });
    await until(() => panelEl().querySelector(".nodra-panel-status")?.textContent === "Storage full", "needs attention");
    expect(fake.statusBar[0]!.textContent).toBe("Nodra: needs attention");
    button("Sync now").click();
    expect(c.syncNow).toHaveBeenCalledTimes(2);

    button("Sign out").click();
    await until(() => hasButton(SIGN_IN), "signed out");
    expect(c.stop).toHaveBeenCalled();
    expect(a.signOut).toHaveBeenCalled();
  });

  it("Private: the two secrets typed into the panel reach enrollment, for that call only", async () => {
    m.pluginProtection.mockResolvedValue({ mode: "PRIVATE" });
    m.trustedPlugin.mockResolvedValue({ replica: null, vault: { kind: "SYNC", vaultId: "v1", remember: false } });
    controller();
    await load(auth(true));
    await until(() => panels().length === 0 && m.pluginProtection.mock.calls.length > 0, "the account checked");
    button_open();
    await until(() => hasButton("Connect this vault"), "the connect screen");
    type("Encryption Password", "enc");
    type("Account Secret Key", "KEY");
    m.enrollPlugin.mockRejectedValueOnce(new Error("TrustError: wrong secrets"));
    button("Connect this vault").click();
    await until(() => panelEl().textContent!.includes("wrong secrets"), "the failure inline");
    expect(m.enrollPlugin.mock.calls[0]![0]).toMatchObject({ secrets: { password: "enc", secretKey: "KEY" } });
    expect(m.startSync).not.toHaveBeenCalled();
  });

  it("revoked while syncing: the panel offers Connect again, which enrolls again", async () => {
    m.trustedPlugin.mockResolvedValue({ replica: { auth: {}, vaultCrypto: {}, planLimits: {} }, vault: { kind: "SYNC", vaultId: "v1", remember: false } });
    const { emit } = controller();
    await load(auth(true));
    await until(() => m.startSync.mock.calls.length === 1, "syncing");
    emit({ kind: "error", detail: "revoked", code: "RECIPIENT_REVOKED", reenroll: true });
    expect(Notice.shown.some((n) => n.includes("revoked"))).toBe(true);
    button_open();
    await until(() => hasButton("Connect again"), "Connect again");
    button("Connect again").click();
    await until(() => m.enrollPlugin.mock.calls.length === 1, "enrolled again");
  });

  it("signed out on the server: Sign in again drops the session and shows the form", async () => {
    m.trustedPlugin.mockResolvedValue({ replica: { auth: {}, vaultCrypto: {}, planLimits: {} }, vault: { kind: "SYNC", vaultId: "v1", remember: false } });
    const { emit } = controller();
    const a = auth(true);
    await load(a);
    await until(() => m.startSync.mock.calls.length === 1, "syncing");
    button_open();
    emit({ kind: "error", detail: "signed out", code: "NOT_SIGNED_IN" });
    await until(() => hasButton("Sign in again"), "Sign in again");
    button("Sign in again").click();
    await until(() => hasButton(SIGN_IN), "the sign-in button");
    expect(a.signOut).toHaveBeenCalled();
  });
});

describe("ADR-024 Sign in with your browser from the panel", () => {
  it("opens Supabase's /oauth/authorize for this build's client, waits with Cancel, and the callback signs in and connects", async () => {
    vi.spyOn(window, "open").mockImplementation(() => null);
    const fetched = tokenEndpoint();
    const a = auth();
    const { plugin } = await load(a);
    await until(() => hasButton(SIGN_IN), "the sign-in button");
    expect(handler(plugin)).toBeDefined();
    button(SIGN_IN).click();
    await until(() => opens().length === 1, "the browser opened");
    const { url, params } = opened();
    expect(`${url.origin}${url.pathname}`).toBe("https://auth.test/auth/v1/oauth/authorize");
    expect(Object.fromEntries(url.searchParams)).toMatchObject({ client_id: "3b7e2a40-5c1d-4e8f-9a6b-2d4c6e8f0a12", redirect_uri: "obsidian://nodra-auth" });
    await until(() => hasButton("Cancel") && panelEl().textContent!.includes("Waiting for your browser"), "the waiting screen");

    m.trustedPlugin.mockResolvedValue({ replica: null, vault: { kind: "SYNC", vaultId: "v1", remember: true } });
    await handler(plugin)(params);
    await until(() => hasButton("Connect this vault"), "the connect screen");
    expect(fetched).toHaveBeenCalledTimes(1);
    expect(a.adoptSession).toHaveBeenCalledTimes(1);
    // A sign-in adopts any user; only a re-authentication names one.
    expect((a.adoptSession.mock.calls[0] as unknown[])[1]).toBeNull();
  });

  it("a callback this instance did not start, or with another state, changes nothing and says so", async () => {
    vi.spyOn(window, "open").mockImplementation(() => null);
    const fetched = tokenEndpoint();
    const a = auth();
    const { plugin } = await load(a);
    await until(() => hasButton(SIGN_IN), "the sign-in button");
    const before = Notice.shown.length;
    await handler(plugin)({ action: "nodra-auth", state: "nothing-pending", code: "c" });
    await until(() => Notice.shown.length > before, "the notice");
    expect(Notice.shown.slice(before)).toEqual(["Nodra: this sign-in link is not for this vault or has expired."]);
    button(SIGN_IN).click();
    await until(() => hasButton("Cancel") && opens().length === 1, "the waiting screen");
    await handler(plugin)({ ...opened().params, state: "another-flow" });
    await until(() => Notice.shown.length > before + 1, "the second notice");
    expect(Notice.shown.at(-1)).toBe("Nodra: this sign-in link is not for this vault or has expired.");
    // Cancel: back to the button, and the old flow's callback is ignored too.
    const stale = opened().params;
    button("Cancel").click();
    await until(() => hasButton(SIGN_IN), "the button again");
    await handler(plugin)(stale);
    await until(() => Notice.shown.length > before + 2, "the third notice");
    expect(a.adoptSession).not.toHaveBeenCalled();
    expect(fetched).not.toHaveBeenCalled();
  });
});

// The bug reported from production (plugin 0.6.1): signed in to an account never set up on the web (no
// root chain), the panel said "Your account could not be checked: TrustError: CHAIN_INVALID: root: EMPTY_CHAIN".
describe("signed in to an account not set up on the web yet", () => {
  const NOT_SET_UP = "This Nodra account has not been set up yet. Open Nodra on the web, sign in and choose how your account is protected; then come back and select Check again.";
  const noRoot = () => new TrustError("NO_ACCOUNT_ROOT", "this account has no root yet (§35.2)");

  it("the panel says to finish it in Nodra Web, with no error text; Check again after the setup connects as usual", async () => {
    m.trustedPlugin.mockResolvedValue({ replica: null, vault: { kind: "NONE" } });
    m.pluginProtection.mockRejectedValue(noRoot());
    const opened = vi.spyOn(window, "open").mockImplementation(() => null);
    const { fake } = await load(auth(true));
    button_open();
    await until(() => panels().length === 1 && panelEl().textContent!.includes("Finish setting up your account"), "the not-set-up screen");
    const text = panelEl().textContent!;
    expect(text).toContain(NOT_SET_UP);
    for (const leaked of ["could not be checked", "TrustError", "NO_ACCOUNT_ROOT", "CHAIN_INVALID", "EMPTY_CHAIN"]) expect(text).not.toContain(leaked);
    expect(hasButton("Connect this vault")).toBe(false);
    expect(fake.statusBar[0]!.textContent).toBe("Nodra: needs attention");
    button("Open Nodra on the web").click();
    expect(opened).toHaveBeenCalledWith("https://app.nodranotes.com");
    expect(m.enrollPlugin).not.toHaveBeenCalled();
    expect(m.startSync).not.toHaveBeenCalled();

    // Still not set up: Check again asks once more and shows the same screen.
    const checks = m.pluginProtection.mock.calls.length;
    button("Check again").click();
    await until(() => m.pluginProtection.mock.calls.length === checks + 1 && hasButton("Check again"), "checked again");
    expect(panelEl().textContent).toContain(NOT_SET_UP);

    // Set up on the web meanwhile: Check again reaches the usual connect screen, and connecting syncs.
    m.pluginProtection.mockResolvedValue({ mode: "MANAGED" });
    m.trustedPlugin.mockResolvedValue({ replica: null, vault: { kind: "SYNC", vaultId: "v1", remember: true } });
    button("Check again").click();
    await until(() => hasButton("Connect this vault"), "the connect screen");
    expect(panelEl().textContent).toContain(`${EMAIL} · Managed`);
    expect(panelEl().textContent).not.toContain(NOT_SET_UP);
    controller();
    m.trustedPlugin.mockResolvedValue({ replica: { auth: {}, vaultCrypto: {}, planLimits: {} }, vault: { kind: "SYNC", vaultId: "v1", remember: true } });
    button("Connect this vault").click();
    await until(() => m.startSync.mock.calls.length === 1, "sync started");
    expect(m.enrollPlugin).toHaveBeenCalledTimes(1);
    opened.mockRestore();
  });

  it("the Enroll command says the same in a notice, and enrolls nothing", async () => {
    m.trustedPlugin.mockResolvedValue({ replica: null, vault: { kind: "NONE" } });
    m.pluginProtection.mockRejectedValue(noRoot());
    const { fake } = await load(auth(true));
    await until(() => m.pluginProtection.mock.calls.length > 0, "the account checked");
    const notices = Notice.shown.length;
    await (fake as unknown as { commands: { id: string; callback: () => unknown }[] }).commands.find((c) => c.id === "enroll")!.callback();
    await until(() => Notice.shown.length > notices, "a notice");
    const shown = Notice.shown.slice(notices).join(" ");
    expect(shown).toContain(NOT_SET_UP);
    expect(shown).not.toContain("TrustError");
    expect(m.enrollPlugin).not.toHaveBeenCalled();
  });

  it("a real CHAIN_INVALID (a server rolling back a pinned account) is still shown as it is", async () => {
    m.trustedPlugin.mockResolvedValue({ replica: null, vault: { kind: "NONE" } });
    m.pluginProtection.mockRejectedValue(new TrustError("CHAIN_INVALID", "root: EMPTY_CHAIN"));
    await load(auth(true));
    button_open();
    await until(() => panels().length === 1 && panelEl().textContent!.includes("Your account could not be checked"), "the check failure");
    expect(panelEl().textContent).toContain("CHAIN_INVALID: root: EMPTY_CHAIN");
    expect(panelEl().textContent).not.toContain("Finish setting up your account");
  });
});

describe("this vault connected to another account (NOTES question 413)", () => {
  const OTHER = new InstallationOtherAccountError({ accountId: "01900000-0000-7000-8000-00000000000a", email: "old@example.test" });

  it("the panel says so and nothing else runs; Disconnect asks first, Cancel removes nothing, confirming disconnects and offers to connect", async () => {
    m.trustedPlugin.mockRejectedValue(OTHER);
    m.pluginLocalState.mockResolvedValue({ vaultIds: ["v-old"], unsynced: 2 });
    const settingsAtDisconnect: unknown[] = [];
    m.disconnectPlugin.mockImplementation(async () => void settingsAtDisconnect.push(plugins.at(-1)!.settings.vaultId));
    const { fake } = await load(auth(true), app, { vaultId: "v-old" });
    button_open();
    await until(() => panels().length === 1 && panelEl().textContent!.includes("connected to another Nodra account (old@example.test)"), "the other-account screen");
    expect(panelEl().textContent).toContain(`You are signed in as ${EMAIL}.`);
    expect(fake.statusBar[0]!.textContent).toBe("Nodra: needs attention");
    expect(m.pluginProtection).not.toHaveBeenCalled();
    expect(m.enrollPlugin).not.toHaveBeenCalled();
    expect(m.startSync).not.toHaveBeenCalled();

    const modals = Modal.opened.length;
    button("Disconnect this vault").click();
    await until(() => Modal.opened.length === modals + 1, "the confirmation");
    const confirm = Modal.opened.at(-1)!;
    expect(confirm.title).toBe("Disconnect this vault?");
    expect(confirm.contentEl.textContent).toContain("2 changes made here were never uploaded to old@example.test. They stay in your notes on this device");
    expect(confirm.contentEl.textContent).toContain("Your notes in this Obsidian vault are not touched.");
    const modalButton = (text: string) => [...confirm.contentEl.querySelectorAll("button")].find((b) => b.textContent === text)!;
    modalButton("Cancel").click();
    expect(m.disconnectPlugin).not.toHaveBeenCalled();
    expect(plugins.at(-1)!.settings.vaultId).toBe("v-old");

    button("Disconnect this vault").click();
    await until(() => Modal.opened.length === modals + 2, "the confirmation again");
    m.trustedPlugin.mockResolvedValue({ replica: null, vault: { kind: "SYNC", vaultId: "v-new", remember: true } });
    [...Modal.opened.at(-1)!.contentEl.querySelectorAll("button")].find((b) => b.textContent === "Disconnect")!.click();
    await until(() => hasButton("Connect this vault"), "the connect screen");
    expect(m.disconnectPlugin).toHaveBeenCalledTimes(1);
    expect(m.disconnectPlugin.mock.calls[0]![0]).toMatchObject({ installationId: "installation-1", vaultId: "v-old" });
    expect(settingsAtDisconnect).toEqual([""]); // the other account's vault was forgotten first
    expect(Notice.shown.some((n) => n.includes("disconnected"))).toBe(true);
  });

  it("a failed disconnect is shown and the screen stays; Sign out is offered too", async () => {
    m.trustedPlugin.mockRejectedValue(new InstallationOtherAccountError({ accountId: null, email: null }));
    m.pluginLocalState.mockResolvedValue({ vaultIds: [], unsynced: 0 });
    m.disconnectPlugin.mockRejectedValue(new Error("blocked"));
    const a = auth(true);
    await load(a);
    button_open();
    await until(() => hasButton("Disconnect this vault"), "the other-account screen");
    expect(panelEl().textContent).toContain("(an earlier account)");
    const modals = Modal.opened.length;
    button("Disconnect this vault").click();
    await until(() => Modal.opened.length === modals + 1, "the confirmation");
    expect(Modal.opened.at(-1)!.contentEl.textContent).not.toContain("never uploaded");
    [...Modal.opened.at(-1)!.contentEl.querySelectorAll("button")].find((b) => b.textContent === "Disconnect")!.click();
    await until(() => panelEl().textContent!.includes("Could not disconnect: Error: blocked"), "the failure");
    expect(hasButton("Disconnect this vault")).toBe(true);
    button("Sign out").click();
    await until(() => hasButton(SIGN_IN), "signed out");
    expect(a.signOut).toHaveBeenCalled();
  });
});

describe("another sync tool on this vault folder (§20.2, NOTES question 416)", () => {
  const CONFIRMED = "nodra-other-sync-confirmed";
  const SYNCING = { replica: { auth: {}, vaultCrypto: {}, planLimits: {} }, vault: { kind: "SYNC", vaultId: "v1", remember: false } };
  const adapter = () => app.vault.adapter;
  const listed = () => [...panelEl().querySelectorAll("li")].map((li) => li.textContent);
  const held = async (what: string) => {
    if (panels().length === 0) button_open();
    await until(() => panels().length === 1 && panelEl().querySelector(".nodra-panel-status")?.textContent === "Another sync tool found", what);
  };
  const modalButton = (text: string) => [...Modal.opened.at(-1)!.contentEl.querySelectorAll("button")].find((b) => b.textContent === text)!;
  const restart = () => plugins.at(-1)!.restart();

  it("a signal holds sync before it starts: the panel names it, nothing syncs", async () => {
    m.trustedPlugin.mockResolvedValue(SYNCING);
    controller();
    adapter().folders.add(".stfolder");
    const { fake } = await load(auth(true));
    await held("held by Syncthing");
    expect(listed()).toEqual(["Syncthing: The vault folder has a .stfolder marker."]);
    expect(fake.statusBar[0]!.textContent).toBe("Nodra: needs attention");
    expect(m.startSync).not.toHaveBeenCalled();
    expect(app.local.has(CONFIRMED)).toBe(false);
  });

  it("the confirmation asks first; confirmed, it is kept for exactly those signals; a new one asks again; a gone one is dropped", async () => {
    m.trustedPlugin.mockResolvedValue(SYNCING);
    controller();
    adapter().folders.add(".stfolder");
    await load(auth(true));
    await held("held");

    const modals = Modal.opened.length;
    button("This folder is not synced another way").click();
    expect(Modal.opened.length).toBe(modals + 1);
    expect(Modal.opened.at(-1)!.title).toBe("Sync this folder with Nodra only?");
    modalButton("Cancel").click();
    expect(app.local.has(CONFIRMED)).toBe(false);
    expect(m.startSync).not.toHaveBeenCalled();

    button("This folder is not synced another way").click();
    modalButton("It is not synced another way").click();
    await until(() => m.startSync.mock.calls.length === 1, "sync started once confirmed");
    expect(app.local.get(CONFIRMED)).toEqual(["syncthing"]);

    // Every load checks again; the confirmed signal does not ask again.
    plugins.pop()!.onunload();
    app.workspace.leaves.splice(0); // the old instance's panel went with it
    await load(auth(true));
    await until(() => m.startSync.mock.calls.length === 2, "sync on the next load");

    // A new signal asks again, for itself only.
    adapter().folders.add(".dropbox");
    await restart();
    await held("held by the new signal");
    expect(listed()).toEqual(["Dropbox: The vault folder has a .dropbox marker."]);
    expect(m.startSync).toHaveBeenCalledTimes(2);

    // Syncthing gone: its confirmation is dropped, and it asks again if it comes back.
    adapter().folders.delete(".stfolder");
    await restart();
    await held("still held by Dropbox");
    expect(app.local.get(CONFIRMED)).toEqual([]);
    adapter().folders.delete(".dropbox");
    adapter().folders.add(".stfolder");
    await restart();
    await held("Syncthing asks again");
    expect(listed()).toEqual(["Syncthing: The vault folder has a .stfolder marker."]);
    expect(m.startSync).toHaveBeenCalledTimes(2);
  });

  it("removed by the user: Try again starts sync", async () => {
    m.trustedPlugin.mockResolvedValue(SYNCING);
    controller();
    adapter().folders.add(".dropbox");
    await load(auth(true));
    await held("held");
    adapter().folders.delete(".dropbox");
    button("Try again").click();
    await until(() => m.startSync.mock.calls.length === 1, "sync started");
  });

  it("Obsidian Sync: turned off only when the button is clicked, then sync starts", async () => {
    m.trustedPlugin.mockResolvedValue(SYNCING);
    controller();
    adapter().files.set(".obsidian/core-plugins.json", JSON.stringify({ "file-explorer": true, sync: true }));
    const sync = { enabled: true, disable: vi.fn(async (_user: boolean) => void (sync.enabled = false)) };
    (app as unknown as { internalPlugins: unknown }).internalPlugins = { plugins: { sync } };
    await load(auth(true));
    await held("held by Obsidian Sync");
    expect(listed()).toEqual(["Obsidian Sync: The core Sync plugin is on in this vault."]);
    await new Promise((r) => setTimeout(r, 30));
    expect(sync.disable).not.toHaveBeenCalled(); // never silently
    button("Turn off Obsidian Sync for this vault").click();
    await until(() => m.startSync.mock.calls.length === 1, "sync started");
    expect(sync.disable).toHaveBeenCalledWith(true);
    expect(Notice.shown.some((n) => n.includes("Obsidian Sync is off for this vault"))).toBe(true);
  });

  it("Obsidian Sync with no internal API: the manual steps, and sync still does not start", async () => {
    m.trustedPlugin.mockResolvedValue(SYNCING);
    controller();
    adapter().files.set(".obsidian/core-plugins.json", JSON.stringify(["sync"]));
    await load(auth(true));
    await held("held by Obsidian Sync");
    button("Turn off Obsidian Sync for this vault").click();
    await until(() => panelEl().textContent!.includes("Open Settings → Core plugins, turn off Sync, then select Try again."), "the manual steps");
    expect(m.startSync).not.toHaveBeenCalled();
  });

  it("the vault folder inside Dropbox, and Git that commits on its own, are signals; a Git plugin left on defaults is not", async () => {
    m.trustedPlugin.mockResolvedValue(SYNCING);
    controller();
    adapter().basePath = String.raw`C:\Users\ana\Dropbox\Notes`;
    adapter().folders.add(".git");
    adapter().files.set(".obsidian/community-plugins.json", JSON.stringify(["obsidian-git"]));
    adapter().files.set(".obsidian/plugins/obsidian-git/data.json", JSON.stringify({ autoSaveInterval: 10 }));
    await load(auth(true));
    await held("held");
    expect(listed()).toEqual([
      "Obsidian Git: The vault is a Git repository and the Git plugin commits, pushes or pulls on its own.",
      String.raw`Dropbox: The vault is inside a Dropbox folder: C:\Users\ana\Dropbox\Notes.`,
    ]);
    adapter().basePath = String.raw`C:\Users\ana\Dropbox notes\Notes`;
    adapter().files.set(".obsidian/plugins/obsidian-git/data.json", JSON.stringify({ autoSaveInterval: 0, autoPushInterval: 0, autoPullInterval: 0, autoPullOnBoot: false }));
    await restart();
    await until(() => m.startSync.mock.calls.length === 1, "sync started");
  });
});

/** Opens the panel the way a user does: the ribbon button. */
function button_open() {
  (plugins.at(-1) as unknown as { ribbon: { el: HTMLElement }[] }).ribbon[0]!.el.click();
}
