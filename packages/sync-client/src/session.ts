// §11.3 on the client: the login session. What a client holds is an access token (a Supabase JWT); it
// reads `sub` (the account, §6) and `session_id` (the `server_session_id` every capability label binds)
// off it, and sends it as the bearer of every request. The client does not verify the signature — it
// has no key, and it is the Worker's job (workers/api `jwtSessionVerifier`) — it only refuses a token
// that does not carry the two claims it needs.
//
// A frozen token is `accessTokenSession`; a login whose token renews (Supabase Auth, supabase-auth.ts)
// is `loginSession`. The DEV section below talks to the dev server's own identity routes (workers/dev-server
// identity.ts), kept for the dev demo and its tests.
import { ErrorBody } from "@nodra/protocol";
import { decodeJwt } from "jose";
import type { TrustSession } from "./trust.js";

export class SessionError extends Error {
  constructor(
    readonly code:
      | "NOT_A_SESSION"
      | "SESSION_CHANGED"
      | "NOT_SIGNED_IN"
      | "INVALID_CREDENTIALS"
      | "EMAIL_NOT_CONFIRMED"
      | "EMAIL_TAKEN"
      | "WEAK_PASSWORD"
      | "INVALID_EMAIL"
      | "SAME_PASSWORD"
      | "RATE_LIMITED"
      | "RECOVERY_LINK_INVALID"
      | "REFUSED"
      | "UNREACHABLE",
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "SessionError";
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** `sub` and `session_id` of an access token; throws NOT_A_SESSION when it lacks either. */
function claimsOf(accessToken: string): { readonly accountId: string; readonly serverSessionId: string } {
  let claims: Record<string, unknown>;
  try {
    claims = decodeJwt(accessToken);
  } catch {
    throw new SessionError("NOT_A_SESSION", "the access token is not a JWT");
  }
  if (typeof claims.sub !== "string" || !UUID.test(claims.sub) || typeof claims.session_id !== "string" || !UUID.test(claims.session_id)) {
    throw new SessionError("NOT_A_SESSION", "the access token carries no account (`sub`) or no `session_id`");
  }
  return { accountId: claims.sub.toLowerCase(), serverSessionId: claims.session_id.toLowerCase() };
}

/** The session an access token stands for; throws NOT_A_SESSION when it lacks `sub` or `session_id`. */
export function accessTokenSession(o: { readonly serverUrl: string; readonly accessToken: string; readonly fetch: typeof fetch }): TrustSession {
  const claims = claimsOf(o.accessToken);
  const bearer = { authorization: `Bearer ${o.accessToken}` };
  return { baseUrl: o.serverUrl.replace(/\/+$/, ""), fetch: o.fetch, sessionHeaders: () => bearer, ...claims };
}

/**
 * The session of a login whose access token renews (a Supabase login, `supabaseAuth`): `accessToken`
 * answers the current token at each request, and the claims are read off the first one. A refresh
 * keeps `sub` and `session_id`, so a token of another session is refused (SESSION_CHANGED) rather than
 * sent under capabilities that bind the first one (§11.3); the host builds a new session instead.
 *
 * Its `fetch` renews an expired token once: a 401 UNAUTHENTICATED from the Nodra API (the only 401 the
 * Worker answers) to a request that carried this login's bearer makes one `refresh`, and the request is
 * sent once more with the new bearer. A failed refresh, or a refused resend, is the answer the caller
 * sees, so sync stops on it as before (retry.ts). Requests refused together share one refresh, and one
 * refused after another's refresh is resent with the renewed token without refreshing again. Requests
 * are `fetch(url string, init)`, as every caller in this package sends them; anything else is not resent.
 */
export async function loginSession(o: {
  readonly serverUrl: string;
  readonly accessToken: () => string | Promise<string>;
  /** Renews the login; true when there is a new access token. */
  readonly refresh: () => Promise<boolean>;
  readonly fetch: typeof fetch;
}): Promise<TrustSession> {
  const first = claimsOf(await o.accessToken());
  const current = async () => {
    const token = await o.accessToken();
    const claims = claimsOf(token);
    if (claims.accountId !== first.accountId || claims.serverSessionId !== first.serverSessionId) {
      throw new SessionError("SESSION_CHANGED", "the login is now another session than the one this client started with");
    }
    return token;
  };
  const ours = (bearer: string | null) => {
    if (bearer === null || !bearer.startsWith("Bearer ")) return false;
    try {
      const c = claimsOf(bearer.slice("Bearer ".length));
      return c.accountId === first.accountId && c.serverSessionId === first.serverSessionId;
    } catch {
      return false;
    }
  };
  let refreshing: Promise<boolean> | null = null;
  const refreshOnce = () =>
    (refreshing ??= o
      .refresh()
      .catch(() => false)
      .finally(() => {
        refreshing = null;
      }));
  const renewing: typeof fetch = async (input, init) => {
    const res = await o.fetch(input, init);
    if (res.status !== 401 || typeof input !== "string") return res;
    const headers = new Headers(init?.headers);
    const sent = headers.get("authorization");
    if (!ours(sent)) return res;
    const refused = ErrorBody.safeParse(await res.clone().json().catch(() => null));
    if (!refused.success || refused.data.error !== "UNAUTHENTICATED") return res;
    let token = await current().catch(() => null);
    if (token !== null && sent === `Bearer ${token}`) token = (await refreshOnce()) ? await current().catch(() => null) : null;
    if (token === null || sent === `Bearer ${token}`) return res;
    headers.set("authorization", `Bearer ${token}`);
    return o.fetch(input, { ...init, headers });
  };
  return {
    baseUrl: o.serverUrl.replace(/\/+$/, ""),
    fetch: renewing,
    sessionHeaders: async () => ({ authorization: `Bearer ${await current()}` }),
    ...first,
  };
}

// --- DEV ONLY: the dev server's identity provider --------------------------------------------------

/** Must match the dev server's DEV_AUTH_ROUTES (workers/dev-server; a web test pins the two). DEV ONLY. */
export const DEV_AUTH_ROUTES = { signup: "/v1/dev/auth/signup", login: "/v1/dev/auth/login", logout: "/v1/dev/auth/logout" } as const;

/** DEV ONLY: sign up or log in with email and password; the answer is a fresh session's access token. */
export async function devSignIn(o: {
  readonly serverUrl: string;
  readonly fetch: typeof fetch;
  readonly mode: "signup" | "login";
  readonly email: string;
  readonly password: string;
}): Promise<string> {
  let res: Response;
  try {
    res = await o.fetch(`${o.serverUrl.replace(/\/+$/, "")}${DEV_AUTH_ROUTES[o.mode]}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: o.email, password: o.password }),
    });
  } catch (e) {
    throw new SessionError("UNREACHABLE", String(e));
  }
  const body = (await res.json().catch(() => null)) as { access_token?: unknown; error?: unknown } | null;
  if (res.ok && typeof body?.access_token === "string") return body.access_token;
  const code = body?.error;
  if (code === "INVALID_CREDENTIALS" || code === "EMAIL_TAKEN" || code === "WEAK_PASSWORD" || code === "INVALID_EMAIL") throw new SessionError(code, `the server refused the ${o.mode}`);
  throw new SessionError("UNREACHABLE", `the server answered ${res.status}`);
}

/** DEV ONLY: ends the session on the server (§11.3: its capabilities stop working within 60 s). */
export async function devSignOut(session: TrustSession): Promise<void> {
  await session.fetch(`${session.baseUrl}${DEV_AUTH_ROUTES.logout}`, { method: "POST", headers: await session.sessionHeaders() }).catch(() => undefined);
}
