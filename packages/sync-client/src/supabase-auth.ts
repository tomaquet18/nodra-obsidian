// §11.3 on the client: the login is a Supabase Auth session, held by `@supabase/auth-js` (the auth
// client alone, not supabase-js: Nodra never talks to PostgREST, Storage or Realtime). auth-js keeps
// the session (access + refresh token) in the storage adapter the host gives it — the plugin's secret
// storage, the web's own — and renews the access token before it expires; this module never chooses a
// storage and never logs or repeats a token or a password in an error.
//
// A host builds the sync session with `loginSession({ accessToken: auth.accessToken, refresh: auth.refresh })`
// (session.ts), whose fetch also renews a token the Worker refused as expired (one refresh, one resend).
import { GoTrueClient, isAuthApiError, isAuthRetryableFetchError, isAuthSessionMissingError, isAuthWeakPasswordError } from "@supabase/auth-js";
import { SessionError } from "./session.js";

/** Where auth-js keeps the session: the three calls of the Web Storage API, synchronous or not. */
export interface AuthStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

/** An AuthStorage in memory: tests, and a host that wants the login to end with the process. */
export function memoryAuthStorage(): AuthStorage & { readonly items: ReadonlyMap<string, string> } {
  const items = new Map<string, string>();
  return {
    items,
    getItem: (key) => items.get(key) ?? null,
    setItem: (key, value) => void items.set(key, value),
    removeItem: (key) => void items.delete(key),
  };
}

export interface SupabaseAuth {
  signInWithPassword(email: string, password: string): Promise<void>;
  /** §35.2's first step. `confirmationRequired`: the project confirms emails, and there is no session until then. */
  signUp(email: string, password: string): Promise<{ readonly confirmationRequired: boolean }>;
  /** Ends this session on the server (its refresh token dies; the Worker refuses it within its ≤ 60 s check, §11.3) and here. */
  signOut(): Promise<void>;
  /** The current access token, renewed first when it is about to expire; NOT_SIGNED_IN without a session. */
  accessToken(): Promise<string>;
  /** Renews the session now; true when there is a new access token. */
  refresh(): Promise<boolean>;
  /** The signed-in user's email (what the UI shows and the Setup Kit prints); null without a session. */
  email(): Promise<string | null>;
  /** Each sign-in, renewal and sign-out, as "signed in or not" (UI). Returns the unsubscribe. */
  onSessionChange(listener: (signedIn: boolean) => void): () => void;
  /**
   * §35.7 REAUTH_REQUIRED: `recoverManagedAccountWithRelogin`'s `relogin`. It asks the password
   * (`askPassword`; null: the user declined), signs the same user in again — a fresh primary
   * authentication, which a refresh never is — and yields the new session's access token.
   */
  relogin(askPassword: () => Promise<string | null>): () => Promise<string | null>;
  /**
   * "Forgot your password?": Supabase emails a recovery link that comes back to `redirectTo` (which the
   * host fixes, never the user; Supabase only honours it when it is in the project's Redirect URLs).
   * GoTrue answers the same whether or not the email has an account. Signs nobody in.
   */
  requestPasswordReset(email: string, redirectTo: string): Promise<void>;
  /**
   * The recovery link's session (implicit flow): the fragment the link came back with
   * (`#access_token=…&refresh_token=…&type=recovery`) becomes this client's session. Anything else — an
   * error redirect (expired or used link), another link type, no tokens — is RECOVERY_LINK_INVALID.
   */
  signInWithRecoveryLink(fragment: string): Promise<void>;
  /** The signed-in user's new login password (after a recovery link, or any session). Only the login: never the Encryption Password (§24). */
  updatePassword(newPassword: string): Promise<void>;
  /** Stops auth-js's background work (the renewal timer, its listeners); the stored session stays. */
  dispose(): Promise<void>;
}

/** GoTrue's error codes (supabase/auth `internal/api/errorcodes.go`) that the UI tells apart. */
const CODES: Readonly<Record<string, SessionError["code"]>> = {
  invalid_credentials: "INVALID_CREDENTIALS",
  email_not_confirmed: "EMAIL_NOT_CONFIRMED",
  user_already_exists: "EMAIL_TAKEN",
  email_exists: "EMAIL_TAKEN",
  weak_password: "WEAK_PASSWORD",
  email_address_invalid: "INVALID_EMAIL",
  same_password: "SAME_PASSWORD",
  over_email_send_rate_limit: "RATE_LIMITED",
  over_request_rate_limit: "RATE_LIMITED",
};

/** An auth-js error as a SessionError; its text is GoTrue's message and code, never a credential. */
function refusal(error: unknown, what: string): SessionError {
  if (isAuthSessionMissingError(error)) return new SessionError("NOT_SIGNED_IN", `there is no login session for the ${what}`);
  if (isAuthRetryableFetchError(error)) return new SessionError("UNREACHABLE", `Supabase Auth did not answer the ${what}`);
  if (isAuthWeakPasswordError(error)) return new SessionError("WEAK_PASSWORD", `Supabase Auth refused the ${what}: the password is too weak`);
  if (isAuthApiError(error)) {
    const code = error.code === undefined ? undefined : CODES[error.code];
    return new SessionError(code ?? "REFUSED", `Supabase Auth refused the ${what} (${error.code ?? `HTTP ${error.status}`})`);
  }
  return new SessionError("UNREACHABLE", `the ${what} failed`);
}

export function supabaseAuth(o: {
  /** The project URL (`https://<ref>.supabase.co`); auth-js talks to `<url>/auth/v1`. */
  readonly supabaseUrl: string;
  /** The project's public (anon / publishable) key, sent as `apikey`. */
  readonly anonKey: string;
  readonly storage: AuthStorage;
  readonly fetch: typeof fetch;
  /**
   * The key the session is kept under (auth-js default: `sb-<project ref>-auth-token`). A host whose
   * storage is shared by several logins (the plugin: one secret storage for every vault) names each one.
   */
  readonly storageKey?: string;
}): SupabaseAuth {
  const client = new GoTrueClient({
    url: `${o.supabaseUrl.replace(/\/+$/, "")}/auth/v1`,
    headers: { apikey: o.anonKey },
    storage: o.storage,
    persistSession: true,
    autoRefreshToken: true,
    // The host reads a recovery link itself (signInWithRecoveryLink); auth-js never takes a session from
    // the address bar on its own. Implicit flow (auth-js's default, stated): the link works in any
    // browser, and needs Supabase's default `{{ .ConfirmationURL }}` email template (NOTES question 418).
    detectSessionInUrl: false,
    flowType: "implicit",
    ...(o.storageKey === undefined ? {} : { storageKey: o.storageKey }),
    fetch: (input, init) => o.fetch(input, init),
  });
  const accessToken = async () => {
    const { data, error } = await client.getSession();
    if (error !== null || data.session === null) throw new SessionError("NOT_SIGNED_IN", "there is no login session");
    return data.session.access_token;
  };
  const signInWithPassword = async (email: string, password: string) => {
    const { error } = await client.signInWithPassword({ email, password });
    if (error !== null) throw refusal(error, "sign-in");
  };
  return {
    signInWithPassword,
    async signUp(email, password) {
      const { data, error } = await client.signUp({ email, password });
      if (error !== null) throw refusal(error, "sign-up");
      return { confirmationRequired: data.session === null };
    },
    async signOut() {
      // "local": this session only; the user's other devices stay signed in. auth-js drops the local
      // session even when the server does not answer (that session then lives until its token expires).
      await client.signOut({ scope: "local" });
    },
    accessToken,
    async refresh() {
      const { data, error } = await client.refreshSession().catch(() => ({ data: { session: null }, error: true }));
      return error === null && data.session !== null;
    },
    async email() {
      const { data } = await client.getSession();
      return data.session?.user.email ?? null;
    },
    onSessionChange(listener) {
      const { data } = client.onAuthStateChange((_event, session) => listener(session !== null));
      return () => data.subscription.unsubscribe();
    },
    relogin(askPassword) {
      return async () => {
        const { data } = await client.getSession();
        const email = data.session?.user.email;
        if (email === undefined) throw new SessionError("NOT_SIGNED_IN", "there is no login session to renew");
        const password = await askPassword();
        if (password === null) return null;
        await signInWithPassword(email, password);
        return accessToken();
      };
    },
    async requestPasswordReset(email, redirectTo) {
      const { error } = await client.resetPasswordForEmail(email, { redirectTo });
      if (error !== null) throw refusal(error, "password reset request");
    },
    async signInWithRecoveryLink(fragment) {
      const invalid = (why: string) => new SessionError("RECOVERY_LINK_INVALID", `the password reset link ${why}`);
      const p = new URLSearchParams(fragment.replace(/^#/, ""));
      const access_token = p.get("access_token");
      const refresh_token = p.get("refresh_token");
      if (p.has("error") || p.has("error_code")) throw invalid(`was refused (${p.get("error_code") ?? p.get("error")}): it expired or was already used`);
      if (p.get("type") !== "recovery" || access_token === null || refresh_token === null) throw invalid("is not a password recovery link");
      const { error } = await client.setSession({ access_token, refresh_token }).catch(() => ({ error: true as const }));
      if (error === null) return;
      if (error !== true && isAuthRetryableFetchError(error)) throw refusal(error, "password reset link");
      throw invalid(`was refused by Supabase Auth${error !== true && isAuthApiError(error) && error.code !== undefined ? ` (${error.code})` : ""}`);
    },
    async updatePassword(newPassword) {
      const { error } = await client.updateUser({ password: newPassword });
      if (error !== null) throw refusal(error, "password change");
    },
    dispose: () => client.dispose(),
  };
}
