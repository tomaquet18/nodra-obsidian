// A fake Supabase Auth (GoTrue) for unit tests: the routes `@supabase/auth-js` calls for email +
// password — `POST /auth/v1/token?grant_type=password|refresh_token`, `POST /auth/v1/signup`,
// `POST /auth/v1/logout` — and for a password reset in the implicit flow — `POST /auth/v1/recover`, the
// email link's `GET /auth/v1/verify` (a redirect with the session in the fragment), `GET /auth/v1/user`
// and `PUT /auth/v1/user` — as a `fetch`, with GoTrue's answer shapes and error codes. Its access
// tokens are unsigned JWTs with `sub` and `session_id` (the client never verifies a signature). The dev
// server's identity provider speaks the same routes with signed tokens, for the end-to-end tests.

const part = (v: unknown) => btoa(JSON.stringify(v)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

export interface FakeGoTrue {
  readonly fetch: typeof fetch;
  /** Every request, as "METHOD path?query". */
  readonly requests: string[];
  /** The recovery emails "sent": to whom, and the link in them (Supabase's `{{ .ConfirmationURL }}`). */
  readonly emails: Array<{ readonly email: string; readonly link: string }>;
  /** The next sign-in or refresh issues access tokens that live this long. */
  tokenSeconds: number;
  /** Signups wait for an email confirmation (no session until then). */
  confirmEmail: boolean;
  /** The server is down: every request fails at the network. */
  down: boolean;
  /** `/recover` answers 429 `over_email_send_rate_limit`. */
  rateLimited: boolean;
  /** Ends a session on the server side (its refresh token stops working). */
  revoke(sessionId: string): void;
}

export function fakeGoTrue(url: string): FakeGoTrue {
  const users = new Map<string, { id: string; password: string }>();
  const refreshTokens = new Map<string, { userId: string; email: string; sessionId: string }>();
  const sessionsOf = new Map<string, Set<string>>();
  const recoveries = new Map<string, string>();
  const revoked = new Set<string>();
  let n = 0;
  const id = () => `01890000-0000-7000-8000-${(++n).toString(16).padStart(12, "0")}`;
  const fail = (status: number, code: string) => Response.json({ code, msg: `refused: ${code}` }, { status, headers: { "x-supabase-api-version": "2024-01-01" } });
  const emailOf = (userId: string) => [...users].find(([, u]) => u.id === userId)?.[0] ?? "";

  const tokens = (userId: string, email: string, sessionId: string) => {
    const iat = Math.floor(Date.now() / 1000);
    const access = `${part({ alg: "HS256", typ: "JWT" })}.${part({ sub: userId, session_id: sessionId, aud: "authenticated", iat, exp: iat + self.tokenSeconds })}.c2ln`;
    const refresh = `refresh-${id()}`;
    refreshTokens.set(refresh, { userId, email, sessionId });
    if (!sessionsOf.has(userId)) sessionsOf.set(userId, new Set());
    sessionsOf.get(userId)!.add(sessionId);
    return { access_token: access, token_type: "bearer", expires_in: self.tokenSeconds, expires_at: iat + self.tokenSeconds, refresh_token: refresh, user: { id: userId, email, aud: "authenticated" } };
  };
  const session = (userId: string, email: string, sessionId: string) => Response.json(tokens(userId, email, sessionId));
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

  const self: FakeGoTrue = {
    requests: [],
    emails: [],
    tokenSeconds: 3600,
    confirmEmail: false,
    down: false,
    rateLimited: false,
    revoke: (sessionId) => void revoked.add(sessionId),
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
        if (users.has(body.email!)) return fail(422, "user_already_exists");
        const user = { id: id(), password: body.password! };
        users.set(body.email!, user);
        if (self.confirmEmail) return Response.json({ id: user.id, email: body.email, aud: "authenticated", confirmation_sent_at: new Date().toISOString() });
        return session(user.id, body.email!, id());
      }
      if (route === "/auth/v1/token?grant_type=password") {
        const user = users.get(body.email ?? "");
        if (user === undefined || user.password !== body.password) return fail(400, "invalid_credentials");
        return session(user.id, body.email!, id());
      }
      if (route === "/auth/v1/token?grant_type=refresh_token") {
        const held = refreshTokens.get(body.refresh_token ?? "");
        refreshTokens.delete(body.refresh_token ?? "");
        if (held === undefined || revoked.has(held.sessionId)) return fail(400, "refresh_token_not_found");
        return session(held.userId, held.email, held.sessionId);
      }
      if (path === "/auth/v1/logout") {
        const claims = bearer(init);
        if (claims !== null) revoked.add(claims.session_id);
        return new Response(null, { status: 204 });
      }
      if (path === "/auth/v1/recover" && method === "POST") {
        // GoTrue answers the same whether or not the email has an account (no enumeration).
        if (self.rateLimited) return fail(429, "over_email_send_rate_limit");
        if (users.has(body.email ?? "")) {
          const token = `recovery-${id()}`;
          recoveries.set(token, body.email!);
          const redirectTo = u.searchParams.get("redirect_to") ?? url;
          self.emails.push({ email: body.email!, link: `${url}/auth/v1/verify?token=${token}&type=recovery&redirect_to=${encodeURIComponent(redirectTo)}` });
        }
        return Response.json({});
      }
      if (path === "/auth/v1/verify" && method === "GET") {
        const redirectTo = u.searchParams.get("redirect_to") ?? url;
        const token = u.searchParams.get("token") ?? "";
        const email = recoveries.get(token);
        recoveries.delete(token);
        if (email === undefined || u.searchParams.get("type") !== "recovery") {
          return new Response(null, { status: 303, headers: { location: `${redirectTo}#error=access_denied&error_code=otp_expired&error_description=Email+link+is+invalid+or+has+expired` } });
        }
        const t = tokens(users.get(email)!.id, email, id());
        const fragment = new URLSearchParams({ access_token: t.access_token, expires_at: String(t.expires_at), expires_in: String(t.expires_in), refresh_token: t.refresh_token, token_type: "bearer", type: "recovery" });
        return new Response(null, { status: 303, headers: { location: `${redirectTo}#${fragment}` } });
      }
      if (path === "/auth/v1/user") {
        const claims = bearer(init);
        if (claims === null) return fail(403, "session_not_found");
        const email = emailOf(claims.sub);
        if (method === "PUT") {
          const user = users.get(email)!;
          if ((body.password ?? "").length < 8) return fail(422, "weak_password");
          if (body.password === user.password) return fail(422, "same_password");
          user.password = body.password!;
          // GoTrue ends every other session of the user after a password change (the current one stays).
          for (const s of sessionsOf.get(claims.sub) ?? []) if (s !== claims.session_id) revoked.add(s);
        }
        return Response.json({ id: claims.sub, email, aud: "authenticated" });
      }
      return fail(404, "not_found");
    },
  };
  return self;
}
