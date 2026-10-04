import { describe, expect, it } from "vitest";
import { type SyncToolFacts, detectOtherSyncTools } from "../src/other-sync.js";
import { type PanelFacts, type PanelState, type PluginPhase, OTHER_SYNC_MANUAL_STEPS, disconnectConfirmation, otherSyncConfirmation, panelState, relativeTime, statusBarText, statusBarTitle } from "../src/panel.js";

// The Nodra panel's decisions, pure: which screen the panel shows for the plugin's facts, and the one
// action that fixes a stopped or held sync. The view (panel-view.ts) only renders what this returns.

const NOW = 1_000_000_000;
const facts = (phase: PluginPhase, over: Partial<PanelFacts> = {}): PanelFacts => ({
  phase,
  email: "ana@example.test",
  protection: "MANAGED",
  busy: null,
  problem: null,
  online: true,
  lastSyncedAt: null,
  now: NOW,
  ...over,
});
const syncing = (status: Extract<PluginPhase, { kind: "syncing" }>["status"], over: Partial<PanelFacts> = {}) => panelState(facts({ kind: "syncing", status }, over));
const attention = (s: PanelState) => {
  if (s.kind !== "attention") throw new Error(`expected attention, got ${s.kind}`);
  return s;
};

describe("signed out", () => {
  it("shows the sign-in form, not busy, no problem", () => {
    expect(panelState(facts({ kind: "signed-out" }, { email: null }))).toEqual({ kind: "signed-out", busy: false, waiting: false, problem: null });
  });
  it("§3.7 while GitHub is open in the browser: waiting (not the password form's busy); a failure shows with the form back", () => {
    expect(panelState(facts({ kind: "signed-out" }, { email: null, busy: "github" }))).toEqual({ kind: "signed-out", busy: false, waiting: true, problem: null });
    expect(panelState(facts({ kind: "signed-out" }, { email: null, problem: "GitHub sign-in was cancelled." }))).toMatchObject({ waiting: false, problem: "GitHub sign-in was cancelled." });
  });
  it("while signing in: busy, and the last refusal is shown", () => {
    expect(panelState(facts({ kind: "signed-out" }, { email: null, busy: "sign-in" }))).toMatchObject({ kind: "signed-out", busy: true });
    expect(panelState(facts({ kind: "signed-out" }, { email: null, problem: "Wrong email or password." }))).toMatchObject({ kind: "signed-out", busy: false, problem: "Wrong email or password." });
  });
  it("a connect action in flight does not make the sign-in form busy", () => {
    expect(panelState(facts({ kind: "signed-out" }, { email: null, busy: "connect" }))).toMatchObject({ busy: false });
  });
});

describe("signed in, this vault not connected", () => {
  it("Managed: one click, no secrets asked", () => {
    expect(panelState(facts({ kind: "not-enrolled" }))).toEqual({ kind: "connect", email: "ana@example.test", protection: "MANAGED", busy: false, problem: null, again: false });
  });
  it("Private: the panel asks for the two secrets (protection PRIVATE)", () => {
    expect(panelState(facts({ kind: "not-enrolled" }, { protection: "PRIVATE" }))).toMatchObject({ kind: "connect", protection: "PRIVATE" });
  });
  it("protection not known yet: null (the view waits before offering the button)", () => {
    expect(panelState(facts({ kind: "not-enrolled" }, { protection: null }))).toMatchObject({ kind: "connect", protection: null });
  });
  it("connecting: busy, and a failure is shown inline", () => {
    expect(panelState(facts({ kind: "not-enrolled" }, { busy: "connect" }))).toMatchObject({ kind: "connect", busy: true });
    expect(panelState(facts({ kind: "not-enrolled" }, { problem: "Could not connect: x" }))).toMatchObject({ kind: "connect", problem: "Could not connect: x" });
  });
  it("revoked (§18.3, §35.8): the connect screen again, marked as a reconnection", () => {
    expect(syncing({ kind: "error", detail: "revoked", code: "RECIPIENT_REVOKED", reenroll: true })).toMatchObject({ kind: "connect", again: true });
  });
  it("several Nodra vaults: the choice, with their ids", () => {
    expect(panelState(facts({ kind: "choose-vault", vaults: ["v1", "v2"] }))).toEqual({ kind: "choose-vault", email: "ana@example.test", vaults: ["v1", "v2"] });
  });
  it("no vault yet: finish the account in Nodra Web", () => {
    expect(panelState(facts({ kind: "no-vault" }))).toEqual({ kind: "no-vault", email: "ana@example.test" });
  });
});

describe("signed in to an account not set up yet (§35.2 never ran, so no root chain)", () => {
  const explanation = "This Nodra account has not been set up yet. Open Nodra on the web, sign in and choose how your account is protected; then come back and select Check again.";
  it("finish it in Nodra Web, then check again: no connect screen, no error text", () => {
    const s = panelState(facts({ kind: "not-set-up" }, { protection: null }));
    expect(s).toEqual({ kind: "not-set-up", email: "ana@example.test", title: "Finish setting up your account", explanation });
    expect(statusBarText(s)).toBe("Nodra: needs attention");
    expect(statusBarTitle(s)).toBe(`Finish setting up your account. ${explanation}`);
  });
});

describe("starting", () => {
  it("before the first facts: a loading line", () => {
    expect(panelState(facts({ kind: "starting" }))).toMatchObject({ kind: "loading" });
  });
});

describe("connected", () => {
  it("idle with nothing held: Synced, with the last sync time", () => {
    expect(syncing({ kind: "idle" }, { lastSyncedAt: NOW - 5 * 60_000 })).toEqual({
      kind: "connected",
      email: "ana@example.test",
      protection: "MANAGED",
      sync: "synced",
      lastSynced: "5 minutes ago",
      note: null,
    });
  });
  it("syncing", () => {
    expect(syncing({ kind: "syncing" })).toMatchObject({ kind: "connected", sync: "syncing", lastSynced: null });
  });
  it("paused by the user", () => {
    expect(syncing({ kind: "paused" })).toMatchObject({ kind: "connected", sync: "paused" });
  });
  it("offline: the device says so, or the server could not be reached (hold UNREACHABLE)", () => {
    expect(syncing({ kind: "idle" }, { online: false })).toMatchObject({ kind: "connected", sync: "offline" });
    expect(syncing({ kind: "syncing" }, { online: false })).toMatchObject({ kind: "connected", sync: "offline" });
    expect(syncing({ kind: "idle", detail: "waiting: server unreachable", code: "UNREACHABLE" })).toMatchObject({ kind: "connected", sync: "offline" });
    expect(syncing({ kind: "error", detail: "retrying: x", retrying: true }, { online: false })).toMatchObject({ kind: "connected", sync: "offline" });
  });
  it("a paused sync stays Paused while offline (Resume is the action, not a network problem)", () => {
    expect(syncing({ kind: "paused" }, { online: false })).toMatchObject({ sync: "paused" });
  });
  it("retrying after a transient error: still Syncing, with a note", () => {
    expect(syncing({ kind: "error", detail: "retrying: EBUSY", retrying: true })).toMatchObject({ kind: "connected", sync: "syncing", note: "Retrying after an error." });
  });
  it("a short server wait (upload timeout, damaged upload, upload in progress): Syncing with the status detail as note", () => {
    for (const code of ["UPLOAD_TIMEOUT", "BLOB_CORRUPT_RETRYABLE", "BAD_UPLOAD_LENGTH", "UPLOAD_IN_PROGRESS", "SOMETHING_NEW"]) {
      expect(syncing({ kind: "idle", detail: "waiting: an upload timed out", code })).toMatchObject({ kind: "connected", sync: "syncing", note: "waiting: an upload timed out" });
    }
  });
});

describe("needs attention: each held or stopped state, explained, with the one action that fixes it", () => {
  const cases: readonly [string, "idle" | "error", string | null, string | null][] = [
    // code, status kind, action id, action label
    ["QUOTA_EXCEEDED", "idle", "sync-now", "Sync now"],
    ["VAULT_DELETING", "idle", "sync-now", "Sync now"],
    ["RATE_LIMITED", "idle", null, null],
    ["PENDING_BUDGET_EXCEEDED", "idle", null, null],
    ["NOT_SIGNED_IN", "error", "sign-in-again", "Sign in again"],
    ["UNAUTHENTICATED", "error", "sign-in-again", "Sign in again"],
    ["SESSION_CHANGED", "error", "restart", "Start sync again"],
    ["VAULT_NOT_FOUND", "error", "sync-now", "Try again"],
    ["NOT_FOUND", "error", "sync-now", "Try again"],
    ["WRITE_CAPABILITY_REQUIRED", "error", "sync-now", "Try again"],
    ["SCOPE_REQUIRED", "error", "sync-now", "Try again"],
  ];
  for (const [code, kind, id, label] of cases) {
    it(`${code}: ${label ?? "no action (it resumes on its own)"}`, () => {
      const s = attention(syncing({ kind, detail: `detail of ${code}`, code }));
      expect(s.action).toEqual(id === null ? null : { id, label });
      expect(s.title).not.toBe("");
      expect(s.explanation).not.toContain(code); // plain language, never the protocol code
      expect(s.email).toBe("ana@example.test");
    });
  }
  it("OTHER_SYNC_TOOL (§20.2, NOTES question 419): names the notes another tool brought, and resumes accepting them", () => {
    const arrivals = [{ objectId: "o1", revisionId: "r2", path: "notes/a.md" }, { objectId: "o2", revisionId: "r5", path: "b.md" }];
    const s = attention(syncing({ kind: "error", detail: "another tool seems to be syncing this folder", code: "OTHER_SYNC_TOOL", otherSyncTool: { arrivals, renames: 0 } }));
    expect(s.title).toBe("Another tool seems to be syncing this folder");
    expect(s.explanation).toContain("notes/a.md and b.md");
    expect(s.explanation).not.toContain("OTHER_SYNC_TOOL");
    expect(s.action).toEqual({ id: "resume-other-tool", label: "I removed the other tool, resume" });
    expect(statusBarText(s)).toBe("Nodra: needs attention");
  });
  it("OTHER_SYNC_TOOL after renames: says files were moved by something else, same action", () => {
    const s = attention(syncing({ kind: "error", detail: "another tool seems to be syncing this folder", code: "OTHER_SYNC_TOOL", otherSyncTool: { arrivals: [], renames: 3 } }));
    expect(s.explanation).toContain("moved");
    expect(s.action).toEqual({ id: "resume-other-tool", label: "I removed the other tool, resume" });
  });
  it("a stop the panel does not know: the status detail, and Try again", () => {
    const s = attention(syncing({ kind: "error", detail: "the server refused: NEW_CODE", code: "NEW_CODE" }));
    expect(s).toMatchObject({ title: "Sync stopped", explanation: "The server refused: NEW_CODE.", action: { id: "sync-now", label: "Try again" } });
  });
  it("a persistent local error (no code, not retrying): the detail, and Try again", () => {
    const s = attention(syncing({ kind: "error", detail: "EACCES: permission denied" }));
    expect(s).toMatchObject({ title: "Sync stopped", explanation: "EACCES: permission denied.", action: { id: "sync-now", label: "Try again" } });
  });
  it("before sync starts: unsupported device (no action), another window (no action), unreachable (Try again), unreadable login (Sign in again)", () => {
    expect(attention(panelState(facts({ kind: "unsupported" })))).toMatchObject({ action: null });
    expect(attention(panelState(facts({ kind: "waiting-owner" })))).toMatchObject({ action: null });
    expect(attention(panelState(facts({ kind: "unreachable", detail: "TypeError: fetch failed" })))).toMatchObject({ title: "Offline", action: { id: "restart", label: "Try again" } });
    expect(attention(panelState(facts({ kind: "login-unreadable", detail: "x" }, { email: null })))).toMatchObject({ email: null, action: { id: "sign-in-again", label: "Sign in again" } });
  });
});

describe("relative time", () => {
  it("just now, minutes, hours, days; singular and plural", () => {
    expect(relativeTime(NOW - 10_000, NOW)).toBe("just now");
    expect(relativeTime(NOW + 5_000, NOW)).toBe("just now"); // a clock step back is not the future
    expect(relativeTime(NOW - 60_000, NOW)).toBe("1 minute ago");
    expect(relativeTime(NOW - 59 * 60_000, NOW)).toBe("59 minutes ago");
    expect(relativeTime(NOW - 60 * 60_000, NOW)).toBe("1 hour ago");
    expect(relativeTime(NOW - 23 * 3_600_000, NOW)).toBe("23 hours ago");
    expect(relativeTime(NOW - 24 * 3_600_000, NOW)).toBe("1 day ago");
    expect(relativeTime(NOW - 3 * 86_400_000, NOW)).toBe("3 days ago");
  });
});

describe("the status bar text follows the panel", () => {
  it("one short word per screen", () => {
    expect(statusBarText(panelState(facts({ kind: "signed-out" }, { email: null })))).toBe("Nodra: signed out");
    expect(statusBarText(panelState(facts({ kind: "not-enrolled" })))).toBe("Nodra: not connected");
    expect(statusBarText(panelState(facts({ kind: "choose-vault", vaults: [] })))).toBe("Nodra: not connected");
    expect(statusBarText(panelState(facts({ kind: "no-vault" })))).toBe("Nodra: not connected");
    expect(statusBarText(panelState(facts({ kind: "starting" })))).toBe("Nodra: starting");
    expect(statusBarText(syncing({ kind: "idle" }))).toBe("Nodra: synced");
    expect(statusBarText(syncing({ kind: "syncing" }))).toBe("Nodra: syncing");
    expect(statusBarText(syncing({ kind: "paused" }))).toBe("Nodra: paused");
    expect(statusBarText(syncing({ kind: "idle" }, { online: false }))).toBe("Nodra: offline");
    expect(statusBarText(syncing({ kind: "idle", detail: "x", code: "QUOTA_EXCEEDED" }))).toBe("Nodra: needs attention");
  });
});

describe("this vault connected to another account (NOTES question 413)", () => {
  it("names both accounts, the other by its recorded email or as an earlier account; disconnecting shows busy and a failure", () => {
    expect(panelState(facts({ kind: "other-account", otherEmail: "old@example.test" }))).toEqual({
      kind: "other-account",
      email: "ana@example.test",
      title: "Connected to another account",
      explanation:
        "This vault is connected to another Nodra account (old@example.test). You are signed in as ana@example.test. Disconnect this vault to connect it to ana@example.test, or sign out to sign in with the other account.",
      busy: false,
      problem: null,
    });
    expect(panelState(facts({ kind: "other-account", otherEmail: null }))).toMatchObject({ explanation: expect.stringContaining("another Nodra account (an earlier account)") });
    expect(panelState(facts({ kind: "other-account", otherEmail: null }, { busy: "disconnect", problem: "Could not disconnect: x" }))).toMatchObject({ busy: true, problem: "Could not disconnect: x" });
    expect(statusBarText(panelState(facts({ kind: "other-account", otherEmail: null })))).toBe("Nodra: needs attention");
  });

  it("the confirmation says what goes, what stays, and the changes the other account never got", () => {
    const none = disconnectConfirmation({ otherEmail: "old@example.test", email: "ana@example.test", unsynced: 0 });
    expect(none.title).toBe("Disconnect this vault?");
    expect(none.action).toBe("Disconnect");
    expect(none.text).toEqual([
      "This removes this device's connection to old@example.test: its key and the local sync data for this vault. Your notes in this Obsidian vault are not touched.",
      "Then you can connect this vault to ana@example.test: its notes are uploaded to that account. old@example.test still lists this device until you revoke it there.",
    ]);
    expect(disconnectConfirmation({ otherEmail: "old@example.test", email: "ana@example.test", unsynced: 1 }).text[1]).toBe(
      "1 change made here was never uploaded to old@example.test. It stays in your notes on this device and will not reach old@example.test.",
    );
    const unknown = disconnectConfirmation({ otherEmail: null, email: "ana@example.test", unsynced: 3 });
    expect(unknown.text[1]).toBe("3 changes made here were never uploaded to the earlier account. They stay in your notes on this device and will not reach the earlier account.");
    expect(unknown.text[2]).toContain("The earlier account still lists this device");
  });
});

describe("another sync tool on this vault folder (§20.2, NOTES question 416)", () => {
  const signals = (over: Partial<SyncToolFacts>) =>
    detectOtherSyncTools({ basePath: "/Users/ana/Notes", stfolder: false, dropboxMarker: false, git: false, coreSyncEnabled: null, corePlugins: null, communityPlugins: null, obsidianGitData: null, ...over });

  it("says sync is held, why, and each tool with what was found; the Obsidian Sync button only for Obsidian Sync", () => {
    const found = signals({ stfolder: true, basePath: "/Users/ana/Dropbox/Notes" });
    expect(panelState(facts({ kind: "other-sync-tool", signals: found }))).toEqual({
      kind: "other-sync-tool",
      email: "ana@example.test",
      protection: "MANAGED",
      title: "Another sync tool found",
      explanation:
        "Nodra has to be the only tool syncing this vault folder: if another tool copies the same files, Nodra takes its copies for your edits, which creates duplicates and conflicts. Sync does not start until you remove it and try again, or confirm that this folder is not synced another way.",
      signals: [
        { tool: "Syncthing", evidence: "The vault folder has a .stfolder marker." },
        { tool: "Dropbox", evidence: "The vault is inside a Dropbox folder: /Users/ana/Dropbox/Notes." },
      ],
      obsidianSync: false,
      problem: null,
    });
    expect(panelState(facts({ kind: "other-sync-tool", signals: signals({ coreSyncEnabled: true }) }))).toMatchObject({ obsidianSync: true });
  });

  it("a failed turn-off shows the manual steps; the status bar needs attention", () => {
    const s = panelState(facts({ kind: "other-sync-tool", signals: signals({ coreSyncEnabled: true }) }, { problem: OTHER_SYNC_MANUAL_STEPS }));
    expect(s).toMatchObject({ problem: "Obsidian Sync could not be turned off from here. Open Settings → Core plugins, turn off Sync, then select Try again." });
    expect(statusBarText(s)).toBe("Nodra: needs attention");
    expect(statusBarTitle(s)).toContain("Another sync tool found.");
  });

  it("the confirmation names every tool and says it is asked again for a new one", () => {
    const c = otherSyncConfirmation(signals({ stfolder: true, basePath: "/Users/ana/Dropbox/Notes" }));
    expect(c).toEqual({
      title: "Sync this folder with Nodra only?",
      text: [
        "Confirm only if Syncthing and Dropbox do not sync this vault folder. If one of them does, notes can be duplicated or end up in conflict copies.",
        "Nodra remembers this on this device and asks again if it finds another sync tool.",
      ],
      action: "It is not synced another way",
    });
    expect(otherSyncConfirmation(signals({ basePath: "/Users/ana/Dropbox/Notes", dropboxMarker: true })).text[0]).toMatch(/^Confirm only if Dropbox does not sync/);
  });
});
