import {
  type AuthStorage,
  type LoginMethod,
  type Settings,
  type SupabaseAuth,
  type TrustSession,
  SessionError,
  loginSession,
  memoryAuthStorage,
  nativeOAuth,
  supabaseAuth,
} from "@nodra/sync-client";
import { authStorageKey } from "./auth-storage.js";

// §11.3 in the plugin: this installation's own login, a Supabase Auth session held by auth-js
// (sync-client `supabaseAuth`) in the storage auth-storage.ts gives it. Everything the plugin does with
// the Nodra API goes through a `loginSession` built from it: its fetch renews an expired token once, and
// it refuses to send a token of another session (SESSION_CHANGED), because capabilities bind the first
// one. So the plugin builds a new one after any sign-in or relogin (`current`). Accounts are created in
// Nodra Web (§35.2), never here.
//
// §3.7 (ADR-023, NOTES question 448): "Continue with GitHub" opens the system browser at Supabase's
// /authorize, with `redirectTo = obsidian://nodra-auth?vault=<id>&flow=<random>`; the callback reaches
// this instance through `registerObsidianProtocolHandler` (main.ts) and `pluginGitHub` below. The PKCE
// verifier lives in the memory of a client made for that one flow (sync-client `nativeOAuth`), never in
// secret storage or data.json; the new session then becomes this installation's login
// (`adoptSession`), for a re-authentication only when it is the same user.

export interface PluginLogin {
  readonly session: TrustSession;
  readonly email: string;
  /** The current access token of this login (the controller's `Settings.accessToken`). */
  readonly accessToken: () => Promise<string>;
}

export interface PluginAuth {
  /** The stored login as a new session; null when signed out. */
  current(): Promise<PluginLogin | null>;
  signIn(email: string, password: string): Promise<PluginLogin>;
  /** Ends this installation's session (here and on the server); the enrollment stays. */
  signOut(): Promise<void>;
  /** §35.7 REAUTH_REQUIRED: signs the same user in again with this password; the new access token. */
  relogin(password: string): Promise<string>;
  /** The signed-in user's id (`sub`); null when signed out. */
  userId(): Promise<string | null>;
  /** §3.7: how the signed-in user can authenticate again (`password`, `github`). */
  loginMethods(): Promise<readonly LoginMethod[]>;
  /** §3.7: a new auth client over memory only, for one OAuth flow (its verifier and, briefly, its session). */
  flowClient(): SupabaseAuth;
  /** §3.7: `from`'s session becomes this installation's login when its user is `expectedUserId` (null: anyone); false otherwise, and nothing changed. */
  adoptSession(from: SupabaseAuth, expectedUserId: string | null): Promise<boolean>;
  /** The access token of the current login. */
  accessToken(): Promise<string>;
  /** On unload: auth-js's renewal timer stops; the stored session stays. */
  dispose(): Promise<void>;
}

export function pluginAuth(o: {
  readonly apiUrl: string;
  readonly supabaseUrl: string;
  readonly anonKey: string;
  readonly storage: AuthStorage;
  readonly installationId: string;
  /** The fetch for the Nodra API (with the staging build's Access headers). */
  readonly api: typeof fetch;
  /** The fetch for Supabase Auth. */
  readonly authFetch: typeof fetch;
}): PluginAuth {
  const auth = supabaseAuth({ supabaseUrl: o.supabaseUrl, anonKey: o.anonKey, storage: o.storage, storageKey: authStorageKey(o.installationId), fetch: o.authFetch });
  // Its own key, so auth-js's cross-tab channel (named after the key) never reaches the stored login.
  const flowClient = () => supabaseAuth({ supabaseUrl: o.supabaseUrl, anonKey: o.anonKey, storage: memoryAuthStorage(), storageKey: "nodra-oauth-flow", fetch: o.authFetch });
  const build = async (): Promise<PluginLogin> => {
    const session = await loginSession({ serverUrl: o.apiUrl, accessToken: () => auth.accessToken(), refresh: () => auth.refresh(), fetch: o.api });
    return { session, email: (await auth.email()) ?? "", accessToken: () => auth.accessToken() };
  };
  return {
    async current() {
      try {
        return await build();
      } catch (e) {
        if (e instanceof SessionError && e.code === "NOT_SIGNED_IN") return null;
        throw e;
      }
    },
    async signIn(email, password) {
      await auth.signInWithPassword(email, password);
      return build();
    },
    signOut: () => auth.signOut(),
    async relogin(password) {
      const token = await auth.relogin(async () => password)();
      if (token === null) throw new SessionError("NOT_SIGNED_IN", "there is no login session to renew");
      return token;
    },
    userId: () => auth.userId(),
    loginMethods: () => auth.loginMethods(),
    flowClient,
    adoptSession: (from, expectedUserId) => auth.adoptSession(from, expectedUserId),
    accessToken: () => auth.accessToken(),
    dispose: () => auth.dispose(),
  };
}

/** What the controller calls take for this login: its session, and the settings over its token getter. */
export const loginConnection = (login: PluginLogin, vaultId: string): { readonly settings: Settings; readonly session: TrustSession; readonly fetch: typeof fetch } => ({
  settings: { serverUrl: login.session.baseUrl, accessToken: login.accessToken, vaultId },
  session: login.session,
  fetch: login.session.fetch,
});

/** §3.7: the plugin's callback scheme and action (`registerObsidianProtocolHandler("nodra-auth", …)`). */
export const OAUTH_ACTION = "nodra-auth";

/** The GitHub sign-in or re-authentication of one plugin instance (§3.7), over sync-client `nativeOAuth`. */
export interface PluginGitHub {
  /** Opens GitHub in the system browser; resolves once this instance's callback signed in, or "CANCELLED". */
  signIn(): Promise<"SIGNED_IN" | "CANCELLED">;
  /**
   * §35.7 REAUTH_REQUIRED for the signed-in user, with GitHub's account picker: the new access token of
   * the same user; null when cancelled. Another user → OTHER_ACCOUNT, and this installation's login is unchanged.
   */
  reauthenticate(): Promise<string | null>;
  /** Ends the pending flow (the button, or the plugin unloading); its promise resolves as cancelled. */
  cancel(): Promise<void>;
  waiting(): boolean;
  /** The protocol handler's parameters. IGNORED: not this instance's pending flow, nothing changed. */
  callback(params: Readonly<Record<string, string | undefined>>): Promise<"IGNORED" | "HANDLED">;
}

export function pluginGitHub(o: {
  readonly auth: PluginAuth;
  /** This vault's id (`app.appId`): Obsidian routes `obsidian://nodra-auth?vault=<id>` to its window. */
  readonly vault: string;
  /** Opens the system browser (`window.open`: Obsidian hands external URLs to the OS). */
  readonly open: (url: string) => void;
  readonly now?: () => number;
  readonly setTimer?: (fn: () => void, ms: number) => unknown;
  readonly clearTimer?: (handle: unknown) => void;
}): PluginGitHub {
  type Waiter = { readonly expected: string | null; readonly settle: (r: { readonly ok: true; readonly token: string | null } | { readonly ok: false; readonly error: unknown }) => void };
  let waiter: Waiter | null = null;
  const settle = (r: Parameters<Waiter["settle"]>[0]) => {
    const w = waiter;
    waiter = null;
    w?.settle(r);
  };
  const flow = nativeOAuth({
    redirectBase: `obsidian://${OAUTH_ACTION}`,
    vault: o.vault,
    newClient: () => o.auth.flowClient(),
    onExpire: () => settle({ ok: false, error: new SessionError("OAUTH_CALLBACK_INVALID", "no answer from GitHub within 10 minutes") }),
    ...(o.now === undefined ? {} : { now: o.now }),
    ...(o.setTimer === undefined ? {} : { setTimer: o.setTimer }),
    ...(o.clearTimer === undefined ? {} : { clearTimer: o.clearTimer }),
  });
  const start = async (expected: string | null, selectAccount: boolean) => {
    settle({ ok: true, token: null }); // a new start ends the previous one, as cancelled
    const url = await flow.start({ provider: "github", selectAccount });
    const result = new Promise<Parameters<Waiter["settle"]>[0]>((resolve) => (waiter = { expected, settle: resolve }));
    o.open(url);
    const r = await result;
    if (!r.ok) throw r.error;
    return r.token;
  };
  return {
    async signIn() {
      return (await start(null, false)) === null ? "CANCELLED" : "SIGNED_IN";
    },
    async reauthenticate() {
      const expected = await o.auth.userId();
      if (expected === null) throw new SessionError("NOT_SIGNED_IN", "there is no login session to authenticate again");
      return start(expected, true);
    },
    async cancel() {
      await flow.cancel();
      settle({ ok: true, token: null });
    },
    waiting: () => flow.pending(),
    async callback(params) {
      const out = await flow.callback(params);
      if (out.kind === "IGNORED") return "IGNORED";
      const w = waiter;
      if (out.kind === "FAILED") {
        settle({ ok: false, error: out.error });
        return "HANDLED";
      }
      if (w === null) {
        await out.auth.dispose();
        return "HANDLED";
      }
      try {
        // §3.7: a re-authentication must be the same user; a sign-in may be anyone.
        if (!(await o.auth.adoptSession(out.auth, w.expected))) {
          settle({ ok: false, error: new SessionError("OTHER_ACCOUNT", "the GitHub sign-in came back as another user; nothing was replaced") });
        } else {
          settle({ ok: true, token: await o.auth.accessToken() });
        }
      } catch (e) {
        settle({ ok: false, error: e });
      }
      return "HANDLED";
    },
  };
}

const PROBLEMS: Partial<Record<SessionError["code"], string>> = {
  INVALID_CREDENTIALS: "Wrong email or password.",
  EMAIL_NOT_CONFIRMED: "Confirm your email first: open the link we sent you, then sign in.",
  INVALID_EMAIL: "That email address is not valid.",
  UNREACHABLE: "Nodra could not be reached. Check your connection and try again.",
  NOT_SIGNED_IN: "You are signed out. Sign in again.",
  OAUTH_CALLBACK_INVALID: "The GitHub sign-in did not complete (or took more than 10 minutes). Try again.",
  OAUTH_REFUSED: "GitHub sign-in was cancelled. Try again, or sign in with your email.",
  OTHER_ACCOUNT: "That GitHub account is not the one of this Nodra account. Choose the GitHub account you sign in to Nodra with, then try again.",
};

/** What the sign-in dialogs say about a refusal (a SessionError's text never holds a password or a token). */
export function signInProblem(e: unknown): string {
  if (e instanceof SessionError) return PROBLEMS[e.code] ?? e.message;
  return String(e);
}
