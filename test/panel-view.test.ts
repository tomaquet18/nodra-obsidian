// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";
import type { PanelFacts, PluginPhase } from "../src/panel.js";
import { type PanelActions, type PanelSource, NodraPanelView, VIEW_TYPE_NODRA } from "../src/panel-view.js";
import { App, WorkspaceLeaf } from "./support/obsidian-api.js";

// The panel view renders panel.ts's state and wires each control to one action; nothing else. Each test
// clicks what a user clicks and checks which action ran with what.

const NOW = 1_000_000_000;
const base: PanelFacts = { phase: { kind: "signed-out" }, email: null, protection: null, busy: null, problem: null, online: true, lastSyncedAt: null, now: NOW };

function actions(): PanelActions & { [K in keyof PanelActions]: ReturnType<typeof vi.fn> } {
  return {
    signInWithBrowser: vi.fn(),
    cancelBrowserSignIn: vi.fn(),
    connect: vi.fn(async () => {}),
    chooseVault: vi.fn(async () => {}),
    createVault: vi.fn(),
    syncNow: vi.fn(),
    pause: vi.fn(),
    resume: vi.fn(),
    restart: vi.fn(),
    signInAgain: vi.fn(),
    signOut: vi.fn(),
    devices: vi.fn(),
    recover: vi.fn(),
    disconnect: vi.fn(),
    confirmNoOtherSync: vi.fn(),
    turnOffObsidianSync: vi.fn(),
    resumeAfterOtherTool: vi.fn(),
    openWeb: vi.fn(),
  } as never;
}

/** What Obsidian does when the leaf closes (the fake's `close`). */
const closeView = (v: NodraPanelView) => (v as unknown as { close(): Promise<void> }).close();
const opened: NodraPanelView[] = [];
afterEach(async () => {
  for (const v of opened.splice(0)) await closeView(v);
});

async function open(first: Partial<PanelFacts>) {
  let facts: PanelFacts = { ...base, ...first };
  const listeners = new Set<() => void>();
  const a = actions();
  const source: PanelSource = {
    facts: () => facts,
    subscribe(l) {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    actions: a,
  };
  const view = new NodraPanelView(new WorkspaceLeaf(new App().workspace) as never, source);
  await view.onOpen();
  opened.push(view);
  const el = view.contentEl;
  const buttons = () => [...el.querySelectorAll("button")];
  const button = (text: string) => {
    const b = buttons().find((x) => x.textContent === text);
    if (b === undefined) throw new Error(`no button "${text}" in: ${buttons().map((x) => x.textContent).join(", ")}`);
    return b;
  };
  const input = (name: string) => {
    const row = [...el.querySelectorAll(".setting-item")].find((r) => r.querySelector(".setting-item-name")?.textContent === name);
    const i = row?.querySelector("input");
    if (!i) throw new Error(`no field "${name}"`);
    return i as HTMLInputElement;
  };
  const type = (name: string, value: string) => {
    const i = input(name);
    i.value = value;
    i.dispatchEvent(new Event("input"));
  };
  const update = (next: Partial<PanelFacts>) => {
    facts = { ...facts, ...next };
    for (const l of listeners) l();
  };
  return { view, el, a, button, buttons, input, type, update, listeners, text: () => el.textContent ?? "" };
}
const phase = (p: PluginPhase) => p;
const syncing = (status: Extract<PluginPhase, { kind: "syncing" }>["status"]) => phase({ kind: "syncing", status });
const signedIn = { email: "ana@example.test", protection: "MANAGED" as const };

describe("the view", () => {
  it("is the Nodra panel with its icon", async () => {
    const { view } = await open({});
    expect(view.getViewType()).toBe(VIEW_TYPE_NODRA);
    expect(view.getDisplayText()).toBe("Nodra");
    expect(view.getIcon()).toBe("cloud");
  });

  it("re-renders on a change of state only: what the user is typing survives an unrelated update", async () => {
    const p = await open({ email: "ana@example.test", protection: "PRIVATE", phase: { kind: "not-enrolled" } });
    p.type("Encryption Password", "enc");
    const field = p.input("Encryption Password");
    p.update({ now: NOW + 1 }); // same screen
    expect(p.input("Encryption Password")).toBe(field);
    expect(field.value).toBe("enc");
    p.update({ phase: phase({ kind: "starting" }) });
    expect(p.text()).toContain("Starting…");
  });

  it("closing it stops listening", async () => {
    const p = await open({});
    expect(p.listeners.size).toBe(1);
    await closeView(p.view);
    opened.splice(opened.indexOf(p.view), 1);
    expect(p.listeners.size).toBe(0);
  });
});

describe("signed out (ADR-024: the login happens in Nodra Web, in the browser)", () => {
  it("one button, Sign in with your browser, no email or password field, and the link to create an account in Nodra Web", async () => {
    const p = await open({});
    expect(p.el.querySelectorAll("input")).toHaveLength(0);
    expect([...p.el.querySelectorAll("button")].map((b) => b.textContent)).toEqual(["Sign in with your browser"]);
    p.button("Sign in with your browser").click();
    expect(p.a.signInWithBrowser).toHaveBeenCalledTimes(1);
    const link = [...p.el.querySelectorAll("a")].find((x) => x.textContent === "Create one");
    expect(link?.getAttribute("href")).toBe("https://app.nodranotes.com");
  });

  it("waiting for the browser: says what to do there, and Cancel ends it; a refusal is shown with the button back", async () => {
    const p = await open({ busy: "browser" });
    expect(p.text()).toContain("Waiting for your browser…");
    expect(p.text()).toContain("allow Nodra for Obsidian");
    p.button("Cancel").click();
    expect(p.a.cancelBrowserSignIn).toHaveBeenCalledTimes(1);
    p.update({ busy: null, problem: "You did not allow Nodra for Obsidian." });
    expect(p.el.querySelector(".nodra-panel-problem")?.textContent).toBe("You did not allow Nodra for Obsidian.");
    expect(p.button("Sign in with your browser").disabled).toBe(false);
  });
});

describe("connect this vault", () => {
  it("Managed: one click, no secrets", async () => {
    const p = await open({ ...signedIn, phase: phase({ kind: "not-enrolled" }) });
    expect(p.el.querySelectorAll("input")).toHaveLength(0);
    p.button("Connect this vault").click();
    expect(p.a.connect).toHaveBeenCalledWith(undefined);
  });

  it("Private: the two secrets inline, passed to this call only and cleared from the form", async () => {
    const p = await open({ ...signedIn, protection: "PRIVATE", phase: phase({ kind: "not-enrolled" }) });
    p.type("Encryption Password", "enc");
    p.type("Account Secret Key", " A3-KEY ");
    p.button("Connect this vault").click();
    expect(p.a.connect).toHaveBeenCalledWith({ password: "enc", secretKey: "A3-KEY" });
    expect(p.input("Encryption Password").value).toBe("");
    expect(p.input("Account Secret Key").value).toBe("");
    // A second click without typing them again sends nothing.
    p.button("Connect this vault").click();
    expect(p.a.connect).toHaveBeenCalledTimes(1);
  });

  it("protection not known yet: the button waits", async () => {
    const p = await open({ ...signedIn, protection: null, phase: phase({ kind: "not-enrolled" }) });
    expect(p.button("Connect this vault").disabled).toBe(true);
  });

  it("revoked: Connect again, with the reason", async () => {
    const p = await open({ ...signedIn, phase: syncing({ kind: "error", detail: "x", code: "RECIPIENT_REVOKED", reenroll: true }) });
    expect(p.text()).toContain("revoked");
    p.button("Connect again").click();
    expect(p.a.connect).toHaveBeenCalledWith(undefined);
  });

  it("several Nodra vaults: the one clicked is chosen", async () => {
    const p = await open({ ...signedIn, phase: phase({ kind: "choose-vault", vaults: ["v1", "v2"] }) });
    p.buttons().filter((b) => b.textContent === "Sync to this one")[1]!.click();
    expect(p.a.chooseVault).toHaveBeenCalledWith("v2");
  });

  it("the account section is there before connecting: Sign out", async () => {
    const p = await open({ ...signedIn, phase: phase({ kind: "not-enrolled" }) });
    p.button("Sign out").click();
    expect(p.a.signOut).toHaveBeenCalled();
  });
});

describe("an account not set up yet (§35.2 never ran)", () => {
  it("says so in plain words; Open Nodra on the web, Check again (a restart) and Sign out; nothing to connect", async () => {
    const p = await open({ ...signedIn, protection: null, phase: phase({ kind: "not-set-up" }) });
    expect(p.text()).toContain("Finish setting up your account");
    expect(p.text()).toContain("This Nodra account has not been set up yet. Open Nodra on the web, sign in and choose how your account is protected; then come back and select Check again.");
    expect(p.buttons().map((b) => b.textContent)).toEqual(["Open Nodra on the web", "Check again", "Sign out"]);
    p.button("Open Nodra on the web").click();
    expect(p.a.openWeb).toHaveBeenCalledTimes(1);
    p.button("Check again").click();
    expect(p.a.restart).toHaveBeenCalledTimes(1);
    p.button("Sign out").click();
    expect(p.a.signOut).toHaveBeenCalledTimes(1);
    expect(p.a.connect).not.toHaveBeenCalled();
  });
});

describe("connected", () => {
  it("Synced with the last sync time; Sync now and Pause", async () => {
    const p = await open({ ...signedIn, phase: syncing({ kind: "idle" }), lastSyncedAt: NOW - 5 * 60_000 });
    expect(p.el.querySelector(".nodra-panel-status")?.textContent).toBe("Synced");
    expect(p.el.querySelector(".nodra-panel-dot")?.classList.contains("is-synced")).toBe(true);
    expect(p.text()).toContain("Last synced 5 minutes ago");
    p.button("Sync now").click();
    p.button("Pause").click();
    expect(p.a.syncNow).toHaveBeenCalled();
    expect(p.a.pause).toHaveBeenCalled();
  });

  it("Syncing…, Paused (Resume), Offline", async () => {
    const p = await open({ ...signedIn, phase: syncing({ kind: "syncing" }) });
    expect(p.el.querySelector(".nodra-panel-status")?.textContent).toBe("Syncing…");
    p.update({ phase: syncing({ kind: "paused" }) });
    expect(p.el.querySelector(".nodra-panel-status")?.textContent).toBe("Paused");
    p.button("Resume").click();
    expect(p.a.resume).toHaveBeenCalled();
    p.update({ phase: syncing({ kind: "idle" }), online: false });
    expect(p.el.querySelector(".nodra-panel-status")?.textContent).toBe("Offline");
  });

  it("the account: email · Managed, devices, a new vault, recovery and sign out", async () => {
    const p = await open({ ...signedIn, phase: syncing({ kind: "idle" }) });
    expect(p.text()).toContain("ana@example.test · Managed");
    p.button("Manage devices").click();
    p.button("Create vault").click();
    p.button("Sign out").click();
    [...p.el.querySelectorAll("a")].find((x) => x.textContent === "Can't unlock your account?")!.click();
    expect(p.a.devices).toHaveBeenCalled();
    expect(p.a.createVault).toHaveBeenCalled();
    expect(p.a.signOut).toHaveBeenCalled();
    expect(p.a.recover).toHaveBeenCalled();
  });

  it("a Private account says so", async () => {
    const p = await open({ ...signedIn, protection: "PRIVATE", phase: syncing({ kind: "idle" }) });
    expect(p.text()).toContain("ana@example.test · Private");
  });
});

describe("needs attention: the explanation and the one action", () => {
  it("another tool at run time (§20.2): the notes it brought, and \"I removed the other tool, resume\"", async () => {
    const otherSyncTool = { arrivals: [{ objectId: "o1", revisionId: "r2", path: "notes/a.md" }], renames: 0 };
    const p = await open({ ...signedIn, phase: syncing({ kind: "error", detail: "x", code: "OTHER_SYNC_TOOL", otherSyncTool }) });
    expect(p.el.querySelector(".nodra-panel-status")?.textContent).toBe("Another tool seems to be syncing this folder");
    expect(p.text()).toContain("notes/a.md");
    p.button("I removed the other tool, resume").click();
    expect(p.a.resumeAfterOtherTool).toHaveBeenCalledTimes(1);
    expect(p.a.syncNow).not.toHaveBeenCalled();
  });
  it("storage full: Sync now", async () => {
    const p = await open({ ...signedIn, phase: syncing({ kind: "idle", detail: "x", code: "QUOTA_EXCEEDED" }) });
    expect(p.el.querySelector(".nodra-panel-status")?.textContent).toBe("Storage full");
    expect(p.el.querySelector(".nodra-panel-dot")?.classList.contains("is-attention")).toBe(true);
    p.button("Sync now").click();
    expect(p.a.syncNow).toHaveBeenCalled();
  });
  it("signed out on the server: Sign in again", async () => {
    const p = await open({ ...signedIn, phase: syncing({ kind: "error", detail: "x", code: "NOT_SIGNED_IN" }) });
    p.button("Sign in again").click();
    expect(p.a.signInAgain).toHaveBeenCalled();
  });
  it("a new session: Start sync again", async () => {
    const p = await open({ ...signedIn, phase: syncing({ kind: "error", detail: "x", code: "SESSION_CHANGED" }) });
    p.button("Start sync again").click();
    expect(p.a.restart).toHaveBeenCalled();
  });
  it("rate limited: no button to press, it resumes on its own", async () => {
    const p = await open({ ...signedIn, phase: syncing({ kind: "idle", detail: "x", code: "RATE_LIMITED" }) });
    expect(p.buttons().map((b) => b.textContent)).not.toContain("Sync now");
    expect(p.text()).toContain("resumes on its own");
  });
});

describe("connected to another account (NOTES question 413)", () => {
  it("both accounts named; Disconnect this vault asks the host (which confirms first); Sign out is there too", async () => {
    const p = await open({ ...signedIn, protection: null, phase: phase({ kind: "other-account", otherEmail: "old@example.test" }) });
    expect(p.el.querySelector(".nodra-panel-status")?.textContent).toBe("Connected to another account");
    expect(p.text()).toContain("This vault is connected to another Nodra account (old@example.test). You are signed in as ana@example.test.");
    expect(p.buttons().map((b) => b.textContent)).toEqual(["Disconnect this vault", "Sign out"]);
    p.button("Disconnect this vault").click();
    expect(p.a.disconnect).toHaveBeenCalledTimes(1);
    p.button("Sign out").click();
    expect(p.a.signOut).toHaveBeenCalledTimes(1);
  });

  it("an earlier account with no recorded email; while disconnecting the button waits; a failure is shown", async () => {
    const p = await open({ ...signedIn, phase: phase({ kind: "other-account", otherEmail: null }), busy: "disconnect" });
    expect(p.text()).toContain("another Nodra account (an earlier account)");
    expect(p.button("Disconnecting…").disabled).toBe(true);
    p.button("Disconnecting…").click();
    expect(p.a.disconnect).not.toHaveBeenCalled();
    p.update({ busy: null, problem: "Could not disconnect: x" });
    expect(p.text()).toContain("Could not disconnect: x");
  });
});

describe("another sync tool on this vault folder (§20.2, NOTES question 416)", () => {
  const found = (...ids: ("obsidian-sync" | "syncthing")[]) =>
    phase({
      kind: "other-sync-tool",
      signals: ids.map((id) => (id === "syncthing" ? { id, tool: "Syncthing", evidence: "The vault folder has a .stfolder marker." } : { id, tool: "Obsidian Sync", evidence: "The core Sync plugin is on in this vault." })),
    });

  it("names each tool and what was found; Try again and the explicit confirmation, no sync controls", async () => {
    const p = await open({ ...signedIn, phase: found("syncthing") });
    expect(p.el.querySelector(".nodra-panel-status")?.textContent).toBe("Another sync tool found");
    expect([...p.el.querySelectorAll("li")].map((li) => li.textContent)).toEqual(["Syncthing: The vault folder has a .stfolder marker."]);
    expect(p.buttons().map((b) => b.textContent)).toEqual(["Try again", "This folder is not synced another way", "Sign out"]);
    p.button("Try again").click();
    expect(p.a.restart).toHaveBeenCalledTimes(1);
    p.button("This folder is not synced another way").click();
    expect(p.a.confirmNoOtherSync).toHaveBeenCalledTimes(1);
    expect(p.a.turnOffObsidianSync).not.toHaveBeenCalled();
    expect(p.a.syncNow).not.toHaveBeenCalled();
  });

  it("Obsidian Sync: the button to turn it off, which does it only when clicked; a failure shows the manual steps", async () => {
    const p = await open({ ...signedIn, phase: found("obsidian-sync", "syncthing") });
    expect(p.buttons().map((b) => b.textContent)).toEqual(["Turn off Obsidian Sync for this vault", "Try again", "This folder is not synced another way", "Sign out"]);
    expect(p.a.turnOffObsidianSync).not.toHaveBeenCalled();
    p.button("Turn off Obsidian Sync for this vault").click();
    expect(p.a.turnOffObsidianSync).toHaveBeenCalledTimes(1);
    p.update({ problem: "Obsidian Sync could not be turned off from here. Open Settings → Core plugins, turn off Sync, then select Try again." });
    expect(p.el.querySelector(".nodra-panel-problem")?.textContent).toContain("Open Settings → Core plugins");
  });
});
