import { type AuthStorage, type Settings, type TrustSession, SessionError, loginSession, supabaseAuth } from "@nodra/sync-client";
import { authStorageKey } from "./auth-storage.js";

// §11.3 in the plugin: this installation's own login, a Supabase Auth session held by auth-js
// (sync-client `supabaseAuth`) in the storage auth-storage.ts gives it. Everything the plugin does with
// the Nodra API goes through a `loginSession` built from it: its fetch renews an expired token once, and
// it refuses to send a token of another session (SESSION_CHANGED), because capabilities bind the first
// one. So the plugin builds a new one after any sign-in or relogin (`current`). Accounts are created in
// Nodra Web (§35.2), never here.

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
  const build = async (): Promise<PluginLogin> => {
    const session = await loginSession({ serverUrl: o.apiUrl, accessToken: auth.accessToken, refresh: auth.refresh, fetch: o.api });
    return { session, email: (await auth.email()) ?? "", accessToken: auth.accessToken };
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
    dispose: () => auth.dispose(),
  };
}

/** What the controller calls take for this login: its session, and the settings over its token getter. */
export const loginConnection = (login: PluginLogin, vaultId: string): { readonly settings: Settings; readonly session: TrustSession; readonly fetch: typeof fetch } => ({
  settings: { serverUrl: login.session.baseUrl, accessToken: login.accessToken, vaultId },
  session: login.session,
  fetch: login.session.fetch,
});

const PROBLEMS: Partial<Record<SessionError["code"], string>> = {
  INVALID_CREDENTIALS: "Wrong email or password.",
  EMAIL_NOT_CONFIRMED: "Confirm your email first: open the link we sent you, then sign in.",
  INVALID_EMAIL: "That email address is not valid.",
  UNREACHABLE: "Nodra could not be reached. Check your connection and try again.",
  NOT_SIGNED_IN: "You are signed out. Sign in again.",
};

/** What the sign-in dialogs say about a refusal (a SessionError's text never holds a password or a token). */
export function signInProblem(e: unknown): string {
  if (e instanceof SessionError) return PROBLEMS[e.code] ?? e.message;
  return String(e);
}
