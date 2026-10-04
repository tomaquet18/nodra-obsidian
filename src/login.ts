import { type AuthStorage, type Settings, type SupabaseAuth, type TrustSession, SessionError, loginSession, memoryAuthStorage, nativeOAuth, supabaseAuth } from "@nodra/sync-client";
import { authStorageKey } from "./auth-storage.js";

// §11.3 in the plugin: this installation's own login, a Supabase Auth session held by auth-js
// (sync-client `supabaseAuth`) in the storage auth-storage.ts gives it. Everything the plugin does with
// the Nodra API goes through a `loginSession` built from it: its fetch renews an expired token once, and
// it refuses to send a token of another session (SESSION_CHANGED), because capabilities bind the first
// one. So the plugin builds a new one after any sign-in or re-authentication (`current`). Accounts are
// created in Nodra Web (§35.2), never here.
//
// ADR-024: the only sign-in is "Sign in with your browser". The plugin is a public OAuth client of
// Supabase Auth's OAuth 2.1 server (sync-client `nativeOAuth`): the system browser opens Supabase's
// /oauth/authorize, the user signs in on Nodra Web (where the CAPTCHA is) and allows "Nodra for
// Obsidian" on its consent page, and the browser comes back to `obsidian://nodra-auth?code=…&state=…`,
// which reaches this instance through `registerObsidianProtocolHandler` (main.ts) and
// `pluginBrowserSignIn` below. The PKCE verifier lives in nativeOAuth's memory only, never in secret
// storage or data.json; the new session then becomes this installation's login (`adoptSession`), for a
// re-authentication only when it is the same user.

export interface PluginLogin {
  readonly session: TrustSession;
  readonly email: string;
  /** The current access token of this login (the controller's `Settings.accessToken`). */
  readonly accessToken: () => Promise<string>;
}

export interface PluginAuth {
  /** The stored login as a new session; null when signed out. */
  current(): Promise<PluginLogin | null>;
  /** Ends this installation's session (here and on the server); the enrollment stays. */
  signOut(): Promise<void>;
  /** The signed-in user's id (`sub`); null when signed out. */
  userId(): Promise<string | null>;
  /** A new auth client over memory only, holding a browser sign-in's session until it is adopted. */
  flowClient(): SupabaseAuth;
  /** `from`'s session becomes this installation's login when its user is `expectedUserId` (null: anyone); false otherwise, and nothing changed. */
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
    signOut: () => auth.signOut(),
    userId: () => auth.userId(),
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

/** ADR-024: the plugin's callback scheme and action (`registerObsidianProtocolHandler("nodra-auth", …)`). */
export const OAUTH_ACTION = "nodra-auth";
/** ADR-024: the OAuth client's registered redirect URI, exactly (Supabase matches it as a whole string). */
export const OAUTH_REDIRECT_URI = `obsidian://${OAUTH_ACTION}`;

/** The browser sign-in or re-authentication of one plugin instance (ADR-024), over sync-client `nativeOAuth`. */
export interface PluginBrowserSignIn {
  /** Opens Nodra's sign-in in the system browser; resolves once this instance's callback signed in, or "CANCELLED". */
  signIn(): Promise<"SIGNED_IN" | "CANCELLED">;
  /**
   * §35.7 REAUTH_REQUIRED for the signed-in user: the new access token of the same user; null when
   * cancelled. Another user → OTHER_ACCOUNT, and this installation's login is unchanged.
   */
  reauthenticate(): Promise<string | null>;
  /** Ends the pending flow (the button, or the plugin unloading); its promise resolves as cancelled. */
  cancel(): Promise<void>;
  waiting(): boolean;
  /** The protocol handler's parameters. IGNORED: not this instance's pending flow, nothing changed. */
  callback(params: Readonly<Record<string, string | undefined>>): Promise<"IGNORED" | "HANDLED">;
}

export function pluginBrowserSignIn(o: {
  readonly auth: PluginAuth;
  readonly supabaseUrl: string;
  readonly anonKey: string;
  /** This build's OAuth client id (NODRA_OAUTH_CLIENT_ID). */
  readonly clientId: string;
  /** The fetch for Supabase Auth (the code exchange). */
  readonly authFetch: typeof fetch;
  /** This vault's id (`app.appId`): a callback that names another vault is not this instance's. */
  readonly vault: string;
  /** Opens the system browser (`window.open`: Obsidian hands external URLs to the OS). */
  readonly open: (url: string) => void;
  readonly now?: () => number;
  readonly setTimer?: (fn: () => void, ms: number) => unknown;
  readonly clearTimer?: (handle: unknown) => void;
}): PluginBrowserSignIn {
  type Waiter = { readonly expected: string | null; readonly settle: (r: { readonly ok: true; readonly token: string | null } | { readonly ok: false; readonly error: unknown }) => void };
  let waiter: Waiter | null = null;
  const settle = (r: Parameters<Waiter["settle"]>[0]) => {
    const w = waiter;
    waiter = null;
    w?.settle(r);
  };
  const flow = nativeOAuth({
    supabaseUrl: o.supabaseUrl,
    anonKey: o.anonKey,
    clientId: o.clientId,
    redirectUri: OAUTH_REDIRECT_URI,
    vault: o.vault,
    newClient: () => o.auth.flowClient(),
    fetch: o.authFetch,
    onExpire: () => settle({ ok: false, error: new SessionError("OAUTH_CALLBACK_INVALID", "no answer from the browser within 10 minutes") }),
    ...(o.now === undefined ? {} : { now: o.now }),
    ...(o.setTimer === undefined ? {} : { setTimer: o.setTimer }),
    ...(o.clearTimer === undefined ? {} : { clearTimer: o.clearTimer }),
  });
  const start = async (expected: string | null) => {
    settle({ ok: true, token: null }); // a new start ends the previous one, as cancelled
    const url = await flow.start();
    const result = new Promise<Parameters<Waiter["settle"]>[0]>((resolve) => (waiter = { expected, settle: resolve }));
    o.open(url);
    const r = await result;
    if (!r.ok) throw r.error;
    return r.token;
  };
  return {
    async signIn() {
      return (await start(null)) === null ? "CANCELLED" : "SIGNED_IN";
    },
    async reauthenticate() {
      const expected = await o.auth.userId();
      if (expected === null) throw new SessionError("NOT_SIGNED_IN", "there is no login session to authenticate again");
      return start(expected);
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
        // A re-authentication must be the same user; a sign-in may be anyone.
        if (!(await o.auth.adoptSession(out.auth, w.expected))) {
          settle({ ok: false, error: new SessionError("OTHER_ACCOUNT", "the browser signed in as another user; nothing was replaced") });
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
  UNREACHABLE: "Nodra could not be reached. Check your connection and try again.",
  NOT_SIGNED_IN: "You are signed out. Sign in again.",
  OAUTH_CALLBACK_INVALID: "The sign-in did not complete (or took more than 10 minutes). Try again.",
  OAUTH_REFUSED: "You did not allow Nodra for Obsidian, so nothing changed. Sign in again when you want to connect this vault.",
  OTHER_ACCOUNT: "Your browser is signed in to Nodra Web as another account, so nothing was replaced. Sign in there as this account, then try again.",
};

/** What the sign-in screens say about a refusal (a SessionError's text never holds a token or a code). */
export function signInProblem(e: unknown): string {
  if (e instanceof SessionError) return PROBLEMS[e.code] ?? e.message;
  return String(e);
}
