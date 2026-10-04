// A fake Supabase Auth (GoTrue) for unit tests: the routes `@supabase/auth-js` calls for email +
// password — `POST /auth/v1/token?grant_type=password|refresh_token`, `POST /auth/v1/signup`,
// `POST /auth/v1/logout` — for the `token_hash` email links of §3.7 (`POST /auth/v1/recover`,
// `POST /auth/v1/verify`, `GET` and `PUT /auth/v1/user`) and for a PKCE OAuth sign-in (the browser's
// visit to `/authorize`, played by `authorize`, then `POST /auth/v1/token?grant_type=pkce`) — as a
// `fetch`, with GoTrue's answer shapes and error codes. Its access tokens are unsigned JWTs with `sub`
// and `session_id` (the client never verifies a signature). The dev server's identity provider speaks
// the same routes with signed tokens, for the end-to-end tests.
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
    const access = `${part({ alg: "HS256", typ: "JWT" })}.${part({ sub: userId, session_id: sessionId, aud: "authenticated", iat, exp: iat + self.tokenSeconds })}.c2ln`;
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

  const self: FakeGoTrue = {
    requests: [],
    emails: [],
    tokenSeconds: 3600,
    confirmEmail: false,
    down: false,
    rateLimited: false,
    clockSkewSeconds: 0,
    revoke: (sessionId) => void revoked.add(sessionId),
    live: (sessionId) => sessions.has(sessionId) && !revoked.has(sessionId),
    users: () => users.map((u) => ({ id: u.id, email: u.email, confirmed: u.confirmed, providers: [...u.identities] })),
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
      const body = JSON.parse(typeof init?.body === "string" ? init.body : "{}") as Record<string, string>;
      const path = u.pathname.slice(new URL(url).pathname.replace(/\/$/, "").length);
      const route = `${path}${u.search}`;
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
