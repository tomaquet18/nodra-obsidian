// §11.3 on the client: the login is a Supabase Auth session, held by `@supabase/auth-js` (the auth
// client alone, not supabase-js: Nodra never talks to PostgREST, Storage or Realtime). auth-js keeps
// the session (access + refresh token) in the storage adapter the host gives it — the plugin's secret
// storage, the web's own — and renews the access token before it expires; this module never chooses a
// storage and never logs or repeats a token or a password in an error.
//
// A host builds the sync session with `loginSession({ accessToken: auth.accessToken, refresh: auth.refresh })`
// (session.ts), whose fetch also renews a token the Worker refused as expired (one refresh, one resend).
//
// §3.7 (ADR-023): every redirect-based sign-in is PKCE (`flowType: "pkce"`): the host opens the URL of
// `startOAuth` and hands the callback's `code` to `exchangeCode`; the verifier waits in this client's
// storage until then. Email links (sign-up confirmation, password recovery) are `token_hash` +
// `verifyEmailLink`, pressed by the user, never the implicit flow: no session ever travels in a URL.
import { GoTrueClient, isAuthApiError, isAuthError, isAuthRetryableFetchError, isAuthSessionMissingError, isAuthWeakPasswordError } from "@supabase/auth-js";
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

/**
 * An AuthStorage that keeps auth-js's PKCE verifiers apart (§3.7): every key ending in `-code-verifier`
 * (auth-js names each pending flow's slot, its index and its legacy copy that way) goes to `verifiers`,
 * everything else (the session) to `rest`. The plugin keeps verifiers in memory and the session in secret
 * storage; the web's re-authentication client the other way round.
 */
export function verifierRouter(o: { readonly verifiers: AuthStorage; readonly rest: AuthStorage }): AuthStorage {
  const of = (key: string) => (key.endsWith("-code-verifier") ? o.verifiers : o.rest);
  return {
    getItem: (key) => of(key).getItem(key),
    setItem: (key, value) => of(key).setItem(key, value),
    removeItem: (key) => of(key).removeItem(key),
  };
}

/** The OAuth providers Nodra offers (§3.7): GitHub now, Google later. */
export type OAuthProvider = "github";

/** How a user can sign in (`user.identities`): an `email` identity is the password, a provider is itself. */
export type LoginMethod = "password" | OAuthProvider;

/** The two `token_hash` email links of §3.7: sign-up confirmation (`email`) and password recovery. */
export type EmailLinkType = "email" | "recovery";

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
  /** The signed-in user's id (`sub`, the account, §6); null without a session. */
  userId(): Promise<string | null>;
  /**
   * The methods the signed-in user can authenticate with (§3.7: what re-authentication offers), from
   * the server's `user.identities` (a provider linked after this session began is there too); [] without a session.
   */
  loginMethods(): Promise<readonly LoginMethod[]>;
  /**
   * §3.7: starts a PKCE sign-in with `provider`. auth-js keeps the verifier in this client's storage;
   * the host opens `url` (a top-level navigation, or the system browser) and later hands the callback's
   * `code` to `exchangeCode`. `selectAccount`: GitHub shows its account picker (re-authentication).
   * `flowId`: auth-js's own id of this flow's verifier slot, for `exchangeCode`.
   */
  startOAuth(o: { readonly provider: OAuthProvider; readonly redirectTo: string; readonly selectAccount?: boolean }): Promise<{ readonly url: string; readonly flowId: string | null }>;
  /**
   * The PKCE callback: `code` (with the verifier of `flowId`, or of the latest flow) becomes this client's
   * session. No verifier here (another browser, storage cleared), a used or expired code (5 min) or a
   * code issued for another verifier → OAUTH_CALLBACK_INVALID, and nothing changes.
   */
  exchangeCode(code: string, flowId?: string | null): Promise<void>;
  /**
   * §3.7 email links: `verifyOtp({ type, token_hash })`, which makes the link's session this client's.
   * Only ever called on a button press. A used, expired or garbled link → EMAIL_LINK_INVALID.
   */
  verifyEmailLink(type: EmailLinkType, tokenHash: string): Promise<void>;
  /**
   * Takes over `from`'s session (a sign-in or re-authentication completed in a separate client) when its
   * user is `expectedUserId` (null: any user, a plain sign-in). Another user (§3.7, a re-authentication
   * that came back as someone else): `from`'s session is signed out on the server, this client's is left
   * as it was, and the answer is false. Either way `from` holds no session afterwards and is disposed.
   */
  adoptSession(from: SupabaseAuth, expectedUserId: string | null): Promise<boolean>;
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

/** auth-js's client behind each SupabaseAuth, and where it keeps its session, for `adoptSession`. */
const clients = new WeakMap<SupabaseAuth, { readonly client: GoTrueClient; readonly storage: AuthStorage; readonly storageKey: string }>();

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
    // §3.7: the host reads every callback itself (exchangeCode, verifyEmailLink); auth-js never takes a
    // session from the address bar on its own. PKCE for every redirect sign-in; email links use
    // `token_hash` templates (apps/web DEPLOY.md), which need no verifier.
    detectSessionInUrl: false,
    flowType: "pkce",
    ...(o.storageKey === undefined ? {} : { storageKey: o.storageKey }),
    fetch: (input, init) => o.fetch(input, init),
  });
  const accessToken = async () => {
    const { data, error } = await client.getSession();
    if (error !== null || data.session === null) throw new SessionError("NOT_SIGNED_IN", "there is no login session");
    return data.session.access_token;
  };
  const storageKey = (client as unknown as { readonly storageKey: string }).storageKey;
  /**
   * Drops every PKCE verifier this client holds: auth-js keeps one slot per pending flow
   * (`<key>-flow-<id>-code-verifier`), their index (`<key>-flows-code-verifier`) and a copy of the latest
   * (`<key>-code-verifier`). A redeemed or failed callback ends them all (one sign-in at a time per client),
   * and so does a sign-up or a reset request, where PKCE writes a verifier the `token_hash` links never use.
   */
  const discardVerifiers = async () => {
    const index = await o.storage.getItem(`${storageKey}-flows-code-verifier`);
    let ids: unknown = [];
    try {
      ids = index === null ? [] : JSON.parse(index);
    } catch {
      ids = [];
    }
    for (const id of Array.isArray(ids) ? ids : []) if (typeof id === "string") await o.storage.removeItem(`${storageKey}-flow-${id}-code-verifier`);
    await o.storage.removeItem(`${storageKey}-flows-code-verifier`);
    await o.storage.removeItem(`${storageKey}-code-verifier`);
  };
  const signInWithPassword = async (email: string, password: string) => {
    const { error } = await client.signInWithPassword({ email, password });
    if (error !== null) throw refusal(error, "sign-in");
  };
  const self: SupabaseAuth = {
    signInWithPassword,
    async signUp(email, password) {
      const { data, error } = await client.signUp({ email, password });
      await discardVerifiers();
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
    async userId() {
      const { data } = await client.getSession();
      return data.session?.user.id ?? null;
    },
    async loginMethods() {
      const { data: held } = await client.getSession();
      if (held.session === null) return [];
      // The server's view first (a provider linked since this session began); the session's copy if it does not answer.
      const { data, error } = await client.getUser();
      if (error !== null && !isAuthRetryableFetchError(error)) throw refusal(error, "login method list");
      const identities = (error === null ? data.user : held.session.user).identities ?? [];
      const methods = new Set<LoginMethod>();
      for (const i of identities) {
        if (i.provider === "email") methods.add("password");
        else if (i.provider === "github") methods.add("github");
      }
      return [...methods];
    },
    async startOAuth(p) {
      const { data, error } = await client.signInWithOAuth({
        provider: p.provider,
        // The host navigates itself (the web: location.assign; the plugin: the system browser).
        options: { redirectTo: p.redirectTo, skipBrowserRedirect: true, ...(p.selectAccount === true ? { queryParams: { prompt: "select_account" } } : {}) },
      });
      if (error !== null) throw refusal(error, "sign-in");
      return { url: data.url, flowId: (data as { readonly flowId?: string | null }).flowId ?? null };
    },
    async exchangeCode(code, flowId) {
      const { error } = await client
        .exchangeCodeForSession(code, flowId === undefined || flowId === null ? undefined : { flowId })
        .catch((e: unknown) => ({ error: e }));
      await discardVerifiers();
      if (error === null) return;
      if (isAuthRetryableFetchError(error)) throw refusal(error, "sign-in");
      // A missing verifier, a used, expired or foreign code: GoTrue's code at most, never the code itself.
      const why = isAuthApiError(error) && error.code !== undefined ? ` (${error.code})` : isAuthError(error) ? ` (${error.name})` : "";
      throw new SessionError("OAUTH_CALLBACK_INVALID", `the sign-in did not complete${why}`);
    },
    async verifyEmailLink(type, tokenHash) {
      const { data, error } = await client.verifyOtp({ type, token_hash: tokenHash }).catch((e: unknown) => ({ data: null, error: e }));
      if (error === null && data?.session != null) return;
      if (error !== null && isAuthRetryableFetchError(error)) throw refusal(error, "email link");
      const why = error !== null && isAuthApiError(error) && error.code !== undefined ? ` (${error.code})` : "";
      throw new SessionError("EMAIL_LINK_INVALID", `the email link was refused${why}: it expired, was already used, or is not a link of this kind`);
    },
    async adoptSession(from, expectedUserId) {
      const source = clients.get(from);
      if (source === undefined || source.client === client) throw new SessionError("NOT_SIGNED_IN", "there is no other login session to adopt");
      try {
        const { data } = await source.client.getSession();
        const session = data.session;
        if (session === null) throw new SessionError("NOT_SIGNED_IN", "the sign-in left no session to adopt");
        if (expectedUserId !== null && session.user.id.toLowerCase() !== expectedUserId.toLowerCase()) {
          // §3.7: never another account. Its new session ends on the server too; this one stays.
          await source.client.signOut({ scope: "local" });
          return false;
        }
        const { error } = await client.setSession({ access_token: session.access_token, refresh_token: session.refresh_token });
        if (error !== null) throw refusal(error, "sign-in");
        return true;
      } finally {
        // `from` forgets the session without ending it on the server (when adopted, it is this client's now).
        await source.storage.removeItem(source.storageKey);
        await source.storage.removeItem(`${source.storageKey}-user`);
        await source.client.dispose();
      }
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
      await discardVerifiers();
      if (error !== null) throw refusal(error, "password reset request");
    },
    async updatePassword(newPassword) {
      const { error } = await client.updateUser({ password: newPassword });
      if (error !== null) throw refusal(error, "password change");
    },
    dispose: () => client.dispose(),
  };
  clients.set(self, { client, storage: o.storage, storageKey });
  return self;
}
