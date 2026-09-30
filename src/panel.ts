import type { SyncStatus } from "./controller.js";

// The Nodra panel's decisions, free of the `obsidian` runtime: from the plugin's facts (where it is,
// the login, the account's protection, the controller's status) to the one screen the panel shows, and
// for a held or stopped sync the plain-language reason and the one action that fixes it. The view
// (panel-view.ts) renders the result and wires each action to the plugin's existing flows.

/** Where accounts are created (§35.2): the plugin creates none. */
export const WEB_URL = "https://app.nodranotes.com";

export type Protection = "MANAGED" | "PRIVATE";

/** Where the plugin is (main.ts `restart`): what it found, never which step it is in. */
export type PluginPhase =
  | { readonly kind: "starting" }
  | { readonly kind: "signed-out" }
  | { readonly kind: "unsupported" }
  | { readonly kind: "waiting-owner" }
  | { readonly kind: "unreachable"; readonly detail: string }
  | { readonly kind: "login-unreadable"; readonly detail: string }
  | { readonly kind: "not-enrolled" }
  /** §20.2: this installation holds another account's connection (NOTES question 413); its email when recorded. */
  | { readonly kind: "other-account"; readonly otherEmail: string | null }
  | { readonly kind: "no-vault" }
  | { readonly kind: "choose-vault"; readonly vaults: readonly string[] }
  | { readonly kind: "syncing"; readonly status: SyncStatus };

export interface PanelFacts {
  readonly phase: PluginPhase;
  /** The login's email; null when signed out. */
  readonly email: string | null;
  /** §3.6, from the verified root chain; null until known. */
  readonly protection: Protection | null;
  /** A panel action in flight. */
  readonly busy: "sign-in" | "connect" | "disconnect" | null;
  /** Why the last panel action failed, in plain language; null when it did not. */
  readonly problem: string | null;
  /** `navigator.onLine`. */
  readonly online: boolean;
  /** When the controller last reached idle with nothing held (this session); null: not yet. */
  readonly lastSyncedAt: number | null;
  readonly now: number;
}

export type PanelActionId = "sign-in-again" | "sync-now" | "restart";
export interface PanelAction {
  readonly id: PanelActionId;
  readonly label: string;
}

export type SyncWord = "synced" | "syncing" | "paused" | "offline";

export type PanelState =
  | { readonly kind: "loading"; readonly text: string }
  | { readonly kind: "signed-out"; readonly busy: boolean; readonly problem: string | null }
  | { readonly kind: "connect"; readonly email: string; readonly protection: Protection | null; readonly busy: boolean; readonly problem: string | null; readonly again: boolean }
  | { readonly kind: "choose-vault"; readonly email: string; readonly vaults: readonly string[] }
  | { readonly kind: "no-vault"; readonly email: string }
  | { readonly kind: "other-account"; readonly email: string; readonly title: string; readonly explanation: string; readonly busy: boolean; readonly problem: string | null }
  | { readonly kind: "connected"; readonly email: string; readonly protection: Protection | null; readonly sync: SyncWord; readonly lastSynced: string | null; readonly note: string | null }
  | { readonly kind: "attention"; readonly email: string | null; readonly protection: Protection | null; readonly title: string; readonly explanation: string; readonly action: PanelAction | null };

const SIGN_IN_AGAIN: PanelAction = { id: "sign-in-again", label: "Sign in again" };
const SYNC_NOW: PanelAction = { id: "sync-now", label: "Sync now" };
const TRY_AGAIN: PanelAction = { id: "sync-now", label: "Try again" };

/** Held (idle) and stopped (error) codes that need the user (retry.ts); the others resume on their own. */
const ATTENTION: Readonly<Record<string, { readonly title: string; readonly explanation: string; readonly action: PanelAction | null }>> = {
  QUOTA_EXCEEDED: { title: "Storage full", explanation: "Your storage quota is full. Changes are kept on this device and upload when there is space: free some space, then sync now.", action: SYNC_NOW },
  VAULT_DELETING: { title: "Vault scheduled for deletion", explanation: "This vault is scheduled for deletion, so changes are kept on this device but not uploaded. Cancel the deletion in Nodra Web, then sync now.", action: SYNC_NOW },
  RATE_LIMITED: { title: "Slowed down", explanation: "The server is limiting requests for a moment. Sync resumes on its own.", action: null },
  PENDING_BUDGET_EXCEEDED: { title: "Too many uploads pending", explanation: "Too many uploads are waiting on the server. Sync resumes on its own when they finish.", action: null },
  NOT_SIGNED_IN: { title: "Signed out", explanation: "This device was signed out. Sign in again to keep syncing; nothing is lost.", action: SIGN_IN_AGAIN },
  UNAUTHENTICATED: { title: "Session refused", explanation: "Nodra refused this device's session. Sign in again to keep syncing; nothing is lost.", action: SIGN_IN_AGAIN },
  SESSION_CHANGED: { title: "New session", explanation: "You signed in again, so sync has to start again with the new session.", action: { id: "restart", label: "Start sync again" } },
  VAULT_NOT_FOUND: { title: "Vault not found", explanation: "This Nodra vault no longer exists on the server. Unsent changes are kept on this device.", action: TRY_AGAIN },
  NOT_FOUND: { title: "Vault not found", explanation: "The server does not know this vault.", action: TRY_AGAIN },
  WRITE_CAPABILITY_REQUIRED: { title: "Write access refused", explanation: "The server refused this device's permission to write to this vault.", action: TRY_AGAIN },
  SCOPE_REQUIRED: { title: "Write access refused", explanation: "This device may not write to this vault.", action: TRY_AGAIN },
};

/** A status detail as a sentence: capitalized, with a final period. */
const sentence = (text: string) => {
  const t = text.trim();
  const s = t.charAt(0).toUpperCase() + t.slice(1);
  return /[.!?]$/.test(s) ? s : `${s}.`;
};

export function relativeTime(then: number, now: number): string {
  const minutes = Math.floor((now - then) / 60_000);
  const n = (count: number, unit: string) => `${count} ${unit}${count === 1 ? "" : "s"} ago`;
  if (minutes < 1) return "just now";
  if (minutes < 60) return n(minutes, "minute");
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return n(hours, "hour");
  return n(Math.floor(hours / 24), "day");
}

export function panelState(f: PanelFacts): PanelState {
  const email = f.email ?? "";
  const attention = (title: string, explanation: string, action: PanelAction | null): PanelState => ({ kind: "attention", email: f.email, protection: f.protection, title, explanation, action });
  const connect = (again: boolean): PanelState => ({ kind: "connect", email, protection: f.protection, busy: f.busy === "connect", problem: f.problem, again });
  const p = f.phase;
  switch (p.kind) {
    case "starting":
      return { kind: "loading", text: "Starting…" };
    case "signed-out":
      return { kind: "signed-out", busy: f.busy === "sign-in", problem: f.problem };
    case "unsupported":
      return attention("Device not supported", "Nodra needs Web Locks and BroadcastChannel, which this device does not have.", null);
    case "waiting-owner":
      return attention("Open in another window", "Another Obsidian window is syncing this vault. Nodra starts here when it closes.", null);
    case "unreachable":
      return attention("Offline", "Nodra could not be reached. Check your connection and try again.", { id: "restart", label: "Try again" });
    case "login-unreadable":
      return attention("Sign-in unreadable", `The saved sign-in could not be read: ${sentence(p.detail)}`, SIGN_IN_AGAIN);
    case "not-enrolled":
      return connect(false);
    case "other-account":
      return { kind: "other-account", email, ...otherAccountText(p.otherEmail, email), busy: f.busy === "disconnect", problem: f.problem };
    case "no-vault":
      return { kind: "no-vault", email };
    case "choose-vault":
      return { kind: "choose-vault", email, vaults: p.vaults };
    case "syncing":
      return fromStatus(p.status);
  }

  function fromStatus(s: SyncStatus): PanelState {
    if (s.reenroll === true) return connect(true);
    const known = s.code === undefined ? undefined : ATTENTION[s.code];
    if (known !== undefined && (s.kind === "idle" || s.kind === "error")) return attention(known.title, known.explanation, known.action);
    if (s.kind === "error" && s.retrying !== true) return attention("Sync stopped", sentence(s.detail ?? "an unknown error"), TRY_AGAIN);
    const connected = (sync: SyncWord, note: string | null = null): PanelState => ({
      kind: "connected",
      email,
      protection: f.protection,
      sync,
      lastSynced: f.lastSyncedAt === null ? null : relativeTime(f.lastSyncedAt, f.now),
      note,
    });
    if (s.kind === "paused") return connected("paused");
    if (!f.online || s.code === "UNREACHABLE") return connected("offline");
    if (s.kind === "error") return connected("syncing", "Retrying after an error.");
    if (s.kind === "syncing") return connected("syncing");
    // idle: a short wait the runner ends on its own (s.code), or a failed request it did not hold.
    if (s.code !== undefined) return connected("syncing", s.detail ?? null);
    return connected("synced", s.detail ?? null);
  }
}

/** How the other account is named: its email when this installation recorded it, otherwise plainly unknown. */
const otherName = (otherEmail: string | null) => (otherEmail === null ? "an earlier account" : otherEmail);

/** The panel's words for an installation connected to another account (NOTES question 413). */
export function otherAccountText(otherEmail: string | null, email: string): { readonly title: string; readonly explanation: string } {
  return {
    title: "Connected to another account",
    explanation: `This vault is connected to another Nodra account (${otherName(otherEmail)}). You are signed in as ${email}. Disconnect this vault to connect it to ${email}, or sign out to sign in with the other account.`,
  };
}

/**
 * The confirmation before "Disconnect this vault": what goes (this device's connection and its local
 * sync data), what stays (the notes), and, when there are any, the changes the other account never got.
 */
export function disconnectConfirmation(o: { readonly otherEmail: string | null; readonly email: string; readonly unsynced: number }): { readonly title: string; readonly text: readonly string[]; readonly action: string } {
  const other = o.otherEmail ?? "the earlier account";
  const text = [
    `This removes this device's connection to ${other}: its key and the local sync data for this vault. Your notes in this Obsidian vault are not touched.`,
    ...(o.unsynced === 0
      ? []
      : [`${o.unsynced} change${o.unsynced === 1 ? " made here was" : "s made here were"} never uploaded to ${other}. ${o.unsynced === 1 ? "It stays" : "They stay"} in your notes on this device and will not reach ${other}.`]),
    `Then you can connect this vault to ${o.email}: its notes are uploaded to that account. ${o.otherEmail ?? "The earlier account"} still lists this device until you revoke it there.`,
  ];
  return { title: "Disconnect this vault?", text, action: "Disconnect" };
}

const BAR: Record<SyncWord, string> = { synced: "synced", syncing: "syncing", paused: "paused", offline: "offline" };

/** The status bar item's text (clicking it opens the panel). */
export function statusBarText(s: PanelState): string {
  const word = s.kind === "loading" ? "starting" : s.kind === "signed-out" ? "signed out" : s.kind === "connected" ? BAR[s.sync] : s.kind === "attention" || s.kind === "other-account" ? "needs attention" : "not connected";
  return `Nodra: ${word}`;
}

/** The status bar item's tooltip: the explanation behind the word. */
export function statusBarTitle(s: PanelState): string {
  if (s.kind === "attention" || s.kind === "other-account") return `${s.title}. ${s.explanation}`;
  if (s.kind === "connected") return [s.note, s.lastSynced === null ? null : `Last synced ${s.lastSynced}`].filter((x) => x !== null).join(" · ") || "Open the Nodra panel";
  return "Open the Nodra panel";
}
