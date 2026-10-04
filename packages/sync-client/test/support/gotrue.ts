// A fake Supabase Auth (GoTrue) for unit tests: the routes `@supabase/auth-js` calls for email +
// password — `POST /auth/v1/token?grant_type=password|refresh_token`, `POST /auth/v1/signup`,
// `POST /auth/v1/logout` — for the `token_hash` email links of §3.7 (`POST /auth/v1/recover`,
// `POST /auth/v1/verify`, `GET` and `PUT /auth/v1/user`) and for a PKCE OAuth sign-in (the browser's
// visit to `/authorize`, played by `authorize`, then `POST /auth/v1/token?grant_type=pkce`) — as a
// `fetch`, with GoTrue's answer shapes and error codes. Its access tokens are unsigned JWTs with `sub`
// and `session_id` (the client never verifies a signature). The dev server's identity provider speaks
// the same routes with signed tokens, for the end-to-end tests.
//
// It is also Supabase Auth's OAuth 2.1 server (ADR-024): a registered client (`registerOAuthClient`),
// `GET /auth/v1/oauth/authorize` (redirects to the Site URL's consent page with `authorization_id`), the
// consent page's `GET /auth/v1/oauth/authorizations/<id>` and `POST …/<id>/consent` (with the user's
// session), and `POST /auth/v1/oauth/token` (authorization_code + PKCE, refresh_token), following
// supabase/auth `internal/api/oauthserver`: exact redirect URI match, PKCE required, a stored consent
// approves the next request by itself, and a session issued to a client carries `client_id` and renews
// only at `/oauth/token` with that client (`/token?grant_type=refresh_token` answers `invalid_client`).
//
// Linking follows GoTrue's automatic rule (§3.7): a provider identity joins the user whose CONFIRMED
// email equals the provider's VERIFIED email; with an unverified email it is always a new user, whose
// own email stays unconfirmed.

const part = (v: unknown) => btoa(JSON.stringify(v)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

const base64url = (bytes: ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/=+$/, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

/** GoTrue's PKCE code lifetime (`flow_state` expiry): 5 minutes. */
export const FAKE_CODE_SECONDS = 5 * 60;

interface User {
  readonly id: string;
  readonly email: string;
  password: string | null;
  confirmed: boolean;
  readonly identities: Set<string>;
}

/** Who the provider says the browser is, at `/authorize`. */
export interface ProviderAccount {
  /** The provider's own user id (GitHub's numeric id): the same id always comes back as the same identity. */
  readonly providerUserId: string;
  readonly email: string;
  readonly verified: boolean;
}

export interface FakeGoTrue {
  readonly fetch: typeof fetch;
  /** Every request, as "METHOD path?query". */
  readonly requests: string[];
  /** The emails "sent": to whom, which kind, and the link in them (the `token_hash` templates of §3.7). */
  readonly emails: Array<{ readonly email: string; readonly kind: "confirmation" | "recovery"; readonly link: string }>;
  /** The next sign-in or refresh issues access tokens that live this long. */
  tokenSeconds: number;
  /** Signups wait for an email confirmation (no session until then). */
  confirmEmail: boolean;
  /** The server is down: every request fails at the network. */
  down: boolean;
  /** `/recover` answers 429 `over_email_send_rate_limit`. */
  rateLimited: boolean;
  /**
   * CAPTCHA protection is on (Supabase Attack Protection): GoTrue's `verifyCaptcha` middleware. The routes
   * that take it need a token in `gotrue_meta_security.captcha_token`; a missing or spent one is 400
   * `captcha_failed`. Every token the fake accepts is spent (Turnstile's siteverify takes each once).
   */
  captcha: boolean;
  /** The CAPTCHA tokens GoTrue redeemed, in order. */
  readonly captchaTokens: string[];
  /** Seconds added to the fake's clock (PKCE codes expire after FAKE_CODE_SECONDS). */
  clockSkewSeconds: number;
  /** Ends a session on the server side (its refresh token stops working). */
  revoke(sessionId: string): void;
  /** Whether a session is still live on the server. */
  live(sessionId: string): boolean;
  /**
   * The browser at an `/authorize` URL auth-js built, and the provider's answer: `account` consents as
   * that provider account, "deny" cancels. The URL the provider's redirect lands on (`redirect_to` with
   * `code`, or `error`), exactly as GoTrue builds it.
   */
  authorize(url: string, account: ProviderAccount | "deny"): Promise<string>;
  /** ADR-024: registers a public OAuth client (PKCE, no secret); its id. */
  registerOAuthClient(name: string, redirectUri: string): string;
  /** The authorization requests GoTrue holds (ADR-024), by id. */
  readonly oauthAuthorizations: ReadonlyMap<string, { readonly status: string }>;
  /** The user ids and their identities' providers, and whether each email is confirmed. */
  users(): ReadonlyArray<{ readonly id: string; readonly email: string; readonly confirmed: boolean; readonly providers: readonly string[] }>;
}

export function fakeGoTrue(url: string, o: { readonly siteUrl?: string } = {}): FakeGoTrue {
  const siteUrl = o.siteUrl ?? "https://app.nodranotes.com";
  const users: User[] = [];
  const providerIdentities = new Map<string, string>(); // "github:<id>" → user id
  const refreshTokens = new Map<string, { userId: string; sessionId: string }>();
  const sessionsOf = new Map<string, Set<string>>();
  const emailTokens = new Map<string, { userId: string; type: "email" | "recovery" }>();
  const codes = new Map<string, { userId: string; challenge: string; method: string; at: number }>();
  const revoked = new Set<string>();
  const sessions = new Set<string>();
  /** ADR-024: each session's primary authentication (`amr[].timestamp`, kept by a renewal) and its OAuth client, if any. */
  const authAt = new Map<string, number>();
  const clientOf = new Map<string, string>();
  const oauthClients = new Map<string, { readonly name: string; readonly redirectUri: string }>();
  type Authorization = { readonly clientId: string; readonly redirectUri: string; readonly state: string; readonly challenge: string; readonly method: string; userId: string | null; status: string; code: string | null; readonly at: number };
  const authorizations = new Map<string, Authorization>();
  const consents = new Set<string>();
  /**
   * The routes GoTrue's `verifyCaptcha` guards (supabase/auth `internal/api/api.go`): sign-up, the password
   * grant (`isIgnoreCaptchaRoute` exempts `pkce`, `refresh_token` and `id_token`), the recovery email, the
   * OTP and magic-link emails and their resend. `/verify`, `/user` and `/logout` never ask for one.
   */
  const captchaRoutes = new Set(["/auth/v1/signup", "/auth/v1/recover", "/auth/v1/otp", "/auth/v1/magiclink", "/auth/v1/resend", "/auth/v1/token?grant_type=password"]);
  const spentCaptchas = new Set<string>();
  let n = 0;
  const id = () => `01890000-0000-7000-8000-${(++n).toString(16).padStart(12, "0")}`;
  const fail = (status: number, code: string) => Response.json({ code, msg: `refused: ${code}` }, { status, headers: { "x-supabase-api-version": "2024-01-01" } });
  const now = () => Math.floor(Date.now() / 1000) + self.clockSkewSeconds;
  const byId = (userId: string) => users.find((u) => u.id === userId)!;
  const withPassword = (email: string) => users.find((u) => u.email === email && u.identities.has("email"));
  const userJson = (u: User) => ({
    id: u.id,
    email: u.email,
    aud: "authenticated",
    ...(u.confirmed ? { email_confirmed_at: new Date(0).toISOString() } : {}),
    identities: [...u.identities].map((provider) => ({ id: `${provider}-${u.id}`, identity_id: `${provider}-${u.id}`, user_id: u.id, provider })),
  });

  const tokens = (userId: string, sessionId: string) => {
    const iat = Math.floor(Date.now() / 1000);
    if (!authAt.has(sessionId)) authAt.set(sessionId, now());
    const clientId = clientOf.get(sessionId);
    const amr = [{ method: clientId === undefined ? "password" : "oauth_provider/authorization_code", timestamp: authAt.get(sessionId)! }];
    const access = `${part({ alg: "HS256", typ: "JWT" })}.${part({ sub: userId, session_id: sessionId, aud: "authenticated", iat, exp: iat + self.tokenSeconds, amr, ...(clientId === undefined ? {} : { client_id: clientId }) })}.c2ln`;
    const refresh = `refresh-${id()}`;
    refreshTokens.set(refresh, { userId, sessionId });
    sessions.add(sessionId);
    if (!sessionsOf.has(userId)) sessionsOf.set(userId, new Set());
    sessionsOf.get(userId)!.add(sessionId);
    return { access_token: access, token_type: "bearer", expires_in: self.tokenSeconds, expires_at: iat + self.tokenSeconds, refresh_token: refresh, user: userJson(byId(userId)) };
  };
  const session = (userId: string, sessionId: string) => Response.json(tokens(userId, sessionId));
  /** The bearer's claims, or null when it is no live session. */
  const bearer = (init: RequestInit | undefined) => {
    const token = (new Headers(init?.headers).get("authorization") ?? "").replace(/^Bearer /, "");
    try {
      const claims = JSON.parse(atob(token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))) as { sub: string; session_id: string };
      return revoked.has(claims.session_id) ? null : claims;
    } catch {
      return null;
    }
  };
  const emailLink = (u: User, type: "email" | "recovery") => {
    const tokenHash = `hash-${id()}`;
    emailTokens.set(tokenHash, { userId: u.id, type });
    const path = type === "email" ? "/auth/confirm" : "/reset-password";
    self.emails.push({ email: u.email, kind: type === "email" ? "confirmation" : "recovery", link: `${siteUrl}${path}?token_hash=${tokenHash}&type=${type}` });
  };

  /** GoTrue's OAuth error answer (`apierrors.NewOAuthError`): 400 `{ error, error_description }`. */
  const oauthFail = (error: string, description: string) => Response.json({ error, error_description: description }, { status: 400 });
  /** `redirect_uri` with GoTrue's parameters added to its query. */
  const backTo = (redirectUri: string, params: Record<string, string>) => {
    const back = new URL(redirectUri);
    for (const [k, v] of Object.entries(params)) if (v !== "") back.searchParams.set(k, v);
    return back.href;
  };
  const approve = (a: Authorization) => {
    a.status = "approved";
    a.code = `oauth-code-${id()}`;
    return backTo(a.redirectUri, { code: a.code, state: a.state });
  };
  /** The authorization a consent call names, if it is pending, young enough and this user's (GoTrue's AuthorizationTTL: 10 min). */
  const pendingFor = (authorizationId: string, userId: string) => {
    const a = authorizations.get(authorizationId);
    if (a === undefined || a.status !== "pending" || now() - a.at > 600 || (a.userId !== null && a.userId !== userId)) return null;
    return a;
  };

  const self: FakeGoTrue = {
    requests: [],
    emails: [],
    tokenSeconds: 3600,
    confirmEmail: false,
    down: false,
    rateLimited: false,
    captcha: false,
    captchaTokens: [],
    clockSkewSeconds: 0,
    revoke: (sessionId) => void revoked.add(sessionId),
    live: (sessionId) => sessions.has(sessionId) && !revoked.has(sessionId),
    users: () => users.map((u) => ({ id: u.id, email: u.email, confirmed: u.confirmed, providers: [...u.identities] })),
    registerOAuthClient(name, redirectUri) {
      const clientId = crypto.randomUUID();
      oauthClients.set(clientId, { name, redirectUri });
      return clientId;
    },
    oauthAuthorizations: authorizations,
    async authorize(authorizeUrl, account) {
      const u = new URL(authorizeUrl);
      if (!u.href.startsWith(`${url}/auth/v1/authorize?`)) throw new Error(`not this GoTrue's /authorize: ${u.origin}${u.pathname}`);
      const provider = u.searchParams.get("provider") ?? "";
      const redirectTo = u.searchParams.get("redirect_to") ?? siteUrl;
      const challenge = u.searchParams.get("code_challenge");
      const method = u.searchParams.get("code_challenge_method") ?? "";
      const back = new URL(redirectTo);
      if (account === "deny") {
        back.searchParams.set("error", "access_denied");
        back.searchParams.set("error_description", "The user has denied your application access.");
        return back.href;
      }
      if (challenge === null) throw new Error("the fake speaks PKCE only: /authorize had no code_challenge");
      const key = `${provider}:${account.providerUserId}`;
      let userId = providerIdentities.get(key);
      if (userId === undefined) {
        // GoTrue's automatic linking: only a verified email joins the user whose email is confirmed.
        const match = account.verified ? users.find((x) => x.confirmed && x.email === account.email) : undefined;
        const user = match ?? { id: id(), email: account.email, password: null, confirmed: account.verified, identities: new Set<string>() };
        if (match === undefined) users.push(user);
        user.identities.add(provider);
        providerIdentities.set(key, user.id);
        userId = user.id;
      }
      const code = `code-${id()}`;
      codes.set(code, { userId, challenge, method, at: now() });
      back.searchParams.set("code", code);
      return back.href;
    },
    fetch: async (input, init) => {
      const u = new URL(String(input));
      const method = init?.method ?? "GET";
      self.requests.push(`${method} ${u.pathname}${u.search}`);
      if (self.down) throw new TypeError("fetch failed");
      if (!u.href.startsWith(`${url}/auth/v1/`)) return new Response("not found", { status: 404 });
      const raw = typeof init?.body === "string" ? init.body : "{}";
      const form = (new Headers(init?.headers).get("content-type") ?? "").includes("application/x-www-form-urlencoded");
      const body = (form ? Object.fromEntries(new URLSearchParams(raw)) : JSON.parse(raw)) as Record<string, string>;
      const path = u.pathname.slice(new URL(url).pathname.replace(/\/$/, "").length);
      const route = `${path}${u.search}`;
      if (self.captcha && method === "POST" && captchaRoutes.has(path === "/auth/v1/token" ? route : path)) {
        const token = (body as { gotrue_meta_security?: { captcha_token?: unknown } }).gotrue_meta_security?.captcha_token;
        if (typeof token !== "string" || token.trim() === "" || spentCaptchas.has(token)) return fail(400, "captcha_failed");
        spentCaptchas.add(token);
        self.captchaTokens.push(token);
      }
      if (route === "/auth/v1/signup") {
        if (!/^[^\s@]+@[^\s@]+$/.test(body.email ?? "")) return fail(400, "email_address_invalid");
        if ((body.password ?? "").length < 8) return fail(422, "weak_password");
        if (users.some((x) => x.email === body.email && (x.confirmed || x.identities.has("email")))) return fail(422, "user_already_exists");
        const user: User = { id: id(), email: body.email!, password: body.password!, confirmed: !self.confirmEmail, identities: new Set(["email"]) };
        users.push(user);
        if (self.confirmEmail) {
          emailLink(user, "email");
          return Response.json({ ...userJson(user), confirmation_sent_at: new Date().toISOString() });
        }
        return session(user.id, id());
      }
      if (route === "/auth/v1/token?grant_type=password") {
        const user = withPassword(body.email ?? "");
        if (user === undefined || user.password !== body.password) return fail(400, "invalid_credentials");
        if (!user.confirmed) return fail(400, "email_not_confirmed");
        return session(user.id, id());
      }
      if (route === "/auth/v1/token?grant_type=refresh_token") {
        const held = refreshTokens.get(body.refresh_token ?? "");
        // supabase/auth tokens.RefreshTokenGrant: a session of an OAuth client renews only with that client.
        if (held !== undefined && clientOf.has(held.sessionId)) return oauthFail("invalid_client", "Client authentication required for OAuth session");
        refreshTokens.delete(body.refresh_token ?? "");
        if (held === undefined || revoked.has(held.sessionId)) return fail(400, "refresh_token_not_found");
        return session(held.userId, held.sessionId);
      }
      if (route === "/auth/v1/token?grant_type=pkce") {
        const held = codes.get(body.auth_code ?? "");
        if (held === undefined) return fail(404, "flow_state_not_found");
        // One use, whatever the outcome (GoTrue deletes the flow state).
        codes.delete(body.auth_code!);
        if (now() - held.at > FAKE_CODE_SECONDS) return fail(400, "flow_state_expired");
        const verifier = body.code_verifier ?? "";
        const computed = held.method === "s256" ? base64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))) : verifier;
        if (verifier === "" || computed !== held.challenge) return fail(403, "bad_code_verifier");
        return session(held.userId, id());
      }
      if (path === "/auth/v1/oauth/authorize" && method === "GET") {
        const q = u.searchParams;
        const client = oauthClients.get(q.get("client_id") ?? "");
        // An unknown client or a redirect URI that is not exactly the registered one is never redirected to.
        if (client === undefined) return fail(400, "oauth_client_not_found");
        if (q.get("redirect_uri") !== client.redirectUri) return fail(400, "validation_failed");
        const state = q.get("state") ?? "";
        const challenge = q.get("code_challenge") ?? "";
        const challengeMethod = (q.get("code_challenge_method") ?? "").toLowerCase();
        if ((q.get("response_type") ?? "code") !== "code" || challenge.length < 43 || (challengeMethod !== "s256" && challengeMethod !== "plain")) {
          return new Response(null, { status: 302, headers: { location: backTo(client.redirectUri, { error: "invalid_request", error_description: "PKCE flow requires both code_challenge and code_challenge_method", state }) } });
        }
        const authorizationId = `authz-${id()}`;
        authorizations.set(authorizationId, { clientId: q.get("client_id")!, redirectUri: client.redirectUri, state, challenge, method: challengeMethod, userId: null, status: "pending", code: null, at: now() });
        return new Response(null, { status: 302, headers: { location: `${siteUrl}/oauth/consent?authorization_id=${authorizationId}` } });
      }
      const authorizationPath = /^\/auth\/v1\/oauth\/authorizations\/([^/]+)(\/consent)?$/.exec(path);
      if (authorizationPath !== null) {
        const claims = bearer(init);
        if (claims === null) return fail(403, "bad_jwt");
        const a = pendingFor(authorizationPath[1]!, claims.sub);
        if (a === null) return fail(404, "oauth_authorization_not_found");
        if (authorizationPath[2] === undefined && method === "GET") {
          a.userId = claims.sub;
          // GoTrue approves by itself when the user already consented to this client.
          if (consents.has(`${claims.sub}:${a.clientId}`)) return Response.json({ redirect_url: approve(a) });
          return Response.json({
            authorization_id: authorizationPath[1],
            redirect_uri: a.redirectUri,
            client: { id: a.clientId, name: oauthClients.get(a.clientId)!.name, uri: "", logo_uri: "" },
            user: { id: claims.sub, email: byId(claims.sub).email },
            scope: "email",
          });
        }
        if (authorizationPath[2] !== undefined && method === "POST") {
          if (a.userId !== claims.sub) return fail(404, "oauth_authorization_not_found");
          if (body.action === "approve") {
            consents.add(`${claims.sub}:${a.clientId}`);
            return Response.json({ redirect_url: approve(a) });
          }
          if (body.action === "deny") {
            a.status = "denied";
            return Response.json({ redirect_url: backTo(a.redirectUri, { error: "access_denied", error_description: "User denied the request", state: a.state }) });
          }
          return fail(400, "validation_failed");
        }
        return fail(404, "not_found");
      }
      if (path === "/auth/v1/oauth/token" && method === "POST") {
        const clientId = body.client_id ?? "";
        if (!oauthClients.has(clientId)) return oauthFail("invalid_client", "Client authentication required");
        if (body.grant_type === "authorization_code") {
          const entry = [...authorizations.entries()].find(([, a]) => a.code !== null && a.code === body.code);
          if (entry === undefined) return oauthFail("invalid_grant", "Invalid authorization code");
          const [authorizationId, a] = entry;
          if (now() - a.at > 600) return oauthFail("invalid_grant", "Authorization code has expired");
          if (a.clientId !== clientId) return oauthFail("invalid_grant", "Authorization code was not issued for this client");
          if ((body.redirect_uri ?? "") !== "" && body.redirect_uri !== a.redirectUri) return oauthFail("invalid_grant", "Invalid redirect_uri");
          const verifier = body.code_verifier ?? "";
          const computed = a.method === "s256" ? base64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))) : verifier;
          // One use, whatever the outcome.
          authorizations.delete(authorizationId);
          if (verifier === "" || computed !== a.challenge) return oauthFail("invalid_grant", "PKCE verification failed");
          const sessionId = id();
          clientOf.set(sessionId, clientId);
          const { user: _user, expires_at: _at, ...oauth } = tokens(a.userId!, sessionId);
          return Response.json(oauth);
        }
        if (body.grant_type === "refresh_token") {
          const held = refreshTokens.get(body.refresh_token ?? "");
          if (held === undefined || revoked.has(held.sessionId)) return oauthFail("invalid_grant", "Invalid Refresh Token");
          if (clientOf.get(held.sessionId) !== clientId) return oauthFail("invalid_client", "Client does not match the session's OAuth client");
          refreshTokens.delete(body.refresh_token!);
          const { user: _user, expires_at: _at, ...oauth } = tokens(held.userId, held.sessionId);
          return Response.json(oauth);
        }
        return oauthFail("unsupported_grant_type", "Unsupported grant type");
      }
      if (path === "/auth/v1/logout") {
        const claims = bearer(init);
        if (claims !== null) revoked.add(claims.session_id);
        return new Response(null, { status: 204 });
      }
      if (path === "/auth/v1/recover" && method === "POST") {
        // GoTrue answers the same whether or not the email has an account (no enumeration).
        if (self.rateLimited) return fail(429, "over_email_send_rate_limit");
        const user = users.find((x) => x.email === body.email && x.confirmed);
        if (user !== undefined) emailLink(user, "recovery");
        return Response.json({});
      }
      if (path === "/auth/v1/verify" && method === "POST") {
        const held = emailTokens.get(body.token_hash ?? "");
        if (held === undefined || held.type !== body.type) return fail(403, "otp_expired");
        emailTokens.delete(body.token_hash!);
        const user = byId(held.userId);
        if (held.type === "email") user.confirmed = true;
        return session(user.id, id());
      }
      if (path === "/auth/v1/user") {
        const claims = bearer(init);
        if (claims === null) return fail(403, "session_not_found");
        const user = byId(claims.sub);
        if (method === "PUT") {
          if ((body.password ?? "").length < 8) return fail(422, "weak_password");
          if (body.password === user.password) return fail(422, "same_password");
          user.password = body.password!;
          // GoTrue's ensureEmailIdentityForPassword: a first password adds the email identity.
          user.identities.add("email");
          // GoTrue ends every other session of the user after a password change (the current one stays).
          for (const s of sessionsOf.get(claims.sub) ?? []) if (s !== claims.session_id) revoked.add(s);
        }
        return Response.json(userJson(user));
      }
      return fail(404, "not_found");
    },
  };
  return self;
}
