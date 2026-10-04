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
//
// ADR-024: Supabase Auth is also an OAuth 2.1 server, and the Obsidian plugin is its public client
// (oauth-flow.ts). The web's consent page reads and decides an authorization request here
// (`oauthAuthorization`, `decideOAuthAuthorization`); the plugin's session comes from the client's token
// endpoint (`useTokens`). Such a session carries `client_id`, and GoTrue renews it only at
// `/oauth/token` with that client: auth-js knows only `/token`, so this module's fetch sends a renewal of
// a session that carries `client_id` there instead (`clientRenewal`), and every other session as before.
import { GoTrueClient, isAuthApiError, isAuthError, isAuthRetryableFetchError, isAuthSessionMissingError, isAuthWeakPasswordError } from "@supabase/auth-js";
import { decodeJwt } from "jose";
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

/**
 * A password the user typed, with the CAPTCHA token (Cloudflare Turnstile) of the form they typed it in.
 * With Supabase's CAPTCHA protection on, GoTrue refuses a password sign-in without a fresh token
 * (CAPTCHA_FAILED); a bare string is a password with no token (a host that has no CAPTCHA to show).
 */
export type PasswordAnswer = string | { readonly password: string; readonly captchaToken: string };

/**
 * ADR-024: an authorization request of an OAuth client, as the consent page reads it. CONSENT: the user
 * decides. ALREADY_ALLOWED: the user consented to this client before, and GoTrue approved the request by
 * itself: `redirectUrl` already holds the code, and the page still asks before sending the browser there.
 */
export type OAuthAuthorization =
  | { readonly kind: "CONSENT"; readonly authorizationId: string; readonly clientName: string; readonly redirectUri: string; readonly email: string }
  | { readonly kind: "ALREADY_ALLOWED"; readonly redirectUrl: string };

/*
 * `captchaToken`: with Supabase's CAPTCHA protection on (Attack Protection), GoTrue's `verifyCaptcha`
 * guards sign-up, the password grant, the recovery email and the OTP/magic-link emails; each token is
 * redeemed once (Turnstile's siteverify). Off, GoTrue ignores the token. The code exchange, renewal,
 * email links (`/verify`) and `updateUser` never need one.
 */
export interface SupabaseAuth {
  signInWithPassword(email: string, password: string, captchaToken?: string): Promise<void>;
  /** §35.2's first step. `confirmationRequired`: the project confirms emails, and there is no session until then. */
  signUp(email: string, password: string, captchaToken?: string): Promise<{ readonly confirmationRequired: boolean }>;
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
   * (`askPassword`, with its CAPTCHA token when the host shows one; null: the user declined), signs the
   * same user in again — a fresh primary authentication, which a refresh never is — and yields the new
   * session's access token.
   */
  relogin(askPassword: () => Promise<PasswordAnswer | null>): () => Promise<string | null>;
  /**
   * "Forgot your password?": Supabase emails a recovery link that comes back to `redirectTo` (which the
   * host fixes, never the user; Supabase only honours it when it is in the project's Redirect URLs).
   * GoTrue answers the same whether or not the email has an account. Signs nobody in.
   */
  requestPasswordReset(email: string, redirectTo: string, captchaToken?: string): Promise<void>;
  /** The signed-in user's new login password (after a recovery link, or any session). Only the login: never the Encryption Password (§24). */
  updatePassword(newPassword: string): Promise<void>;
  /**
   * ADR-024: an access and refresh token pair (an OAuth client's token endpoint answer) becomes this
   * client's session; auth-js reads its user from `/user`. A refused token → NOT_SIGNED_IN.
   */
  useTokens(t: { readonly accessToken: string; readonly refreshToken: string }): Promise<void>;
  /** ADR-024, the consent page: the request `authorizationId` (Supabase's redirect gives it) for the signed-in user. */
  oauthAuthorization(authorizationId: string): Promise<OAuthAuthorization>;
  /** ADR-024, the consent page: the user's decision; the URL to send the browser to (the client's redirect URI, with `code` or `error`). */
  decideOAuthAuthorization(authorizationId: string, decision: "approve" | "deny"): Promise<string>;
  /**
   * The instant (seconds) of this session's latest primary authentication: max(`amr[].timestamp`) of its
   * access token, or `auth_time` (the dev identity provider), as the Worker reads it (§35.12 step 2); a
   * renewal keeps it. Null without a session or the claim. Read, never verified: the Worker decides.
   */
  primaryAuthAt(): Promise<number | null>;
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
  captcha_failed: "CAPTCHA_FAILED",
};

/** A JWT's claims, unverified (the client never holds a key); null when it is not a JWT. */
function claimsOf(token: string): Record<string, unknown> | null {
  try {
    return decodeJwt(token);
  } catch {
    return null;
  }
}

/** max(`amr[].timestamp`), else `auth_time`; null when neither is there. */
function primaryAuthOf(claims: Record<string, unknown>): number | null {
  const seconds = (v: unknown) => (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : null);
  let latest: number | null = null;
  for (const entry of Array.isArray(claims.amr) ? claims.amr : []) {
    const at = seconds((entry as { timestamp?: unknown } | null)?.timestamp);
    if (at !== null && (latest === null || at > latest)) latest = at;
  }
  return latest ?? seconds(claims.auth_time);
}

/**
 * ADR-024: auth-js's renewal (`POST <auth>/token?grant_type=refresh_token`, JSON `{ refresh_token }`)
 * as GoTrue's OAuth token endpoint takes it for a session of `clientId` (form-encoded, with the client),
 * and its answer as auth-js reads one: the endpoint answers no `user` (an OAuth client's answer), so the
 * user is read with the new access token from `/user`. A refusal is passed on as it came (auth-js ends
 * the session on a refused renewal, keeps it on a network error).
 */
async function clientRenewal(o: { readonly authUrl: string; readonly clientId: string; readonly fetch: typeof fetch }, init: RequestInit | undefined): Promise<Response> {
  const refreshToken = (JSON.parse(typeof init?.body === "string" ? init.body : "{}") as { refresh_token?: unknown }).refresh_token;
  const headers = new Headers(init?.headers);
  headers.set("content-type", "application/x-www-form-urlencoded");
  const body = new URLSearchParams({ grant_type: "refresh_token", refresh_token: typeof refreshToken === "string" ? refreshToken : "", client_id: o.clientId });
  const renewed = await o.fetch(`${o.authUrl}/oauth/token`, { method: "POST", headers, body: body.toString() });
  if (!renewed.ok) return renewed;
  const tokens = (await renewed.json()) as { access_token?: unknown };
  const userHeaders = new Headers(init?.headers);
  userHeaders.delete("content-type");
  userHeaders.set("authorization", `Bearer ${String(tokens.access_token)}`);
  const user = await o.fetch(`${o.authUrl}/user`, { method: "GET", headers: userHeaders });
  if (!user.ok) return user;
  return Response.json({ ...tokens, user: await user.json() });
}

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

/** The consent page's refusals: no session, the network, or the request (unknown, used, expired, another user's). */
function oauthRefusal(error: unknown): SessionError {
  if (error === null || isAuthSessionMissingError(error) || isAuthRetryableFetchError(error)) return refusal(error ?? new Error("no answer"), "sign-in request");
  const why = isAuthApiError(error) && error.code !== undefined ? ` (${error.code})` : "";
  return new SessionError("OAUTH_REQUEST_INVALID", `the sign-in request is not valid any more${why}: it expired, was already answered, or belongs to another account`);
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
  const authUrl = `${o.supabaseUrl.replace(/\/+$/, "")}/auth/v1`;
  /** The OAuth client (`client_id` claim) of the stored session, or null: a session of no client. */
  const heldClientId = async (): Promise<string | null> => {
    let held: unknown = null;
    try {
      held = JSON.parse((await o.storage.getItem(storageKey)) ?? "null");
    } catch {
      held = null;
    }
    const token = (held as { access_token?: unknown } | null)?.access_token;
    const clientId = typeof token === "string" ? claimsOf(token)?.client_id : undefined;
    return typeof clientId === "string" && clientId !== "" ? clientId : null;
  };
  const client = new GoTrueClient({
    url: authUrl,
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
    fetch: async (input, init) => {
      if (String(input instanceof Request ? input.url : input) === `${authUrl}/token?grant_type=refresh_token`) {
        const clientId = await heldClientId();
        if (clientId !== null) return clientRenewal({ authUrl, clientId, fetch: o.fetch }, init);
      }
      return o.fetch(input, init);
    },
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
  /** auth-js's `options.captchaToken`, only when there is one. */
  const captcha = (captchaToken: string | undefined) => (captchaToken === undefined ? {} : { captchaToken });
  const signInWithPassword = async (email: string, password: string, captchaToken?: string) => {
    const { error } = await client.signInWithPassword({ email, password, options: captcha(captchaToken) });
    if (error !== null) throw refusal(error, "sign-in");
  };
  const self: SupabaseAuth = {
    signInWithPassword,
    async signUp(email, password, captchaToken) {
      const { data, error } = await client.signUp({ email, password, options: captcha(captchaToken) });
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
        const answer = await askPassword();
        if (answer === null) return null;
        if (typeof answer === "string") await signInWithPassword(email, answer);
        else await signInWithPassword(email, answer.password, answer.captchaToken);
        return accessToken();
      };
    },
    async requestPasswordReset(email, redirectTo, captchaToken) {
      const { error } = await client.resetPasswordForEmail(email, { redirectTo, ...captcha(captchaToken) });
      await discardVerifiers();
      if (error !== null) throw refusal(error, "password reset request");
    },
    async updatePassword(newPassword) {
      const { error } = await client.updateUser({ password: newPassword });
      if (error !== null) throw refusal(error, "password change");
    },
    async useTokens(t) {
      const { error } = await client.setSession({ access_token: t.accessToken, refresh_token: t.refreshToken });
      if (error !== null) throw isAuthRetryableFetchError(error) ? refusal(error, "sign-in") : new SessionError("NOT_SIGNED_IN", "the sign-in's tokens were refused");
    },
    async oauthAuthorization(authorizationId) {
      const { data, error } = await client.oauth.getAuthorizationDetails(authorizationId);
      if (error !== null || data === null) throw oauthRefusal(error);
      if ("authorization_id" in data) return { kind: "CONSENT", authorizationId: data.authorization_id, clientName: data.client.name, redirectUri: data.redirect_uri, email: data.user.email };
      return { kind: "ALREADY_ALLOWED", redirectUrl: data.redirect_url };
    },
    async decideOAuthAuthorization(authorizationId, decision) {
      // skipBrowserRedirect: the page navigates itself, after the user's press.
      const { data, error } =
        decision === "approve"
          ? await client.oauth.approveAuthorization(authorizationId, { skipBrowserRedirect: true })
          : await client.oauth.denyAuthorization(authorizationId, { skipBrowserRedirect: true });
      if (error !== null || data === null) throw oauthRefusal(error);
      return data.redirect_url;
    },
    async primaryAuthAt() {
      const { data } = await client.getSession();
      const claims = data.session === null ? null : claimsOf(data.session.access_token);
      return claims === null ? null : primaryAuthOf(claims);
    },
    dispose: () => client.dispose(),
  };
  clients.set(self, { client, storage: o.storage, storageKey });
  return self;
}
