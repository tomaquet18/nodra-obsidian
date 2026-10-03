import { describe, expect, it } from "vitest";
import { SessionError, accessTokenSession, devSignIn, loginSession } from "../src/session.js";

// §11.3 on the client: the access token is the session. The client reads `sub` and `session_id` off it
// (it cannot verify the signature; the Worker does) and refuses a token that lacks either.

const part = (v: unknown) => btoa(JSON.stringify(v)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
const jwt = (claims: Record<string, unknown>) => `${part({ alg: "HS256", typ: "JWT" })}.${part(claims)}.c2lnbmF0dXJl`;
const SUB = "01890000-0000-7000-8000-000000000001";
const SID = "01890000-0000-7000-8000-0000000000AA";
const noFetch: typeof fetch = async () => {
  throw new Error("no request expected");
};

describe("accessTokenSession", () => {
  it("reads the account from `sub` and the server session from `session_id`, and sends the token as the bearer", () => {
    const token = jwt({ sub: SUB, session_id: SID, aud: "authenticated" });
    const s = accessTokenSession({ serverUrl: "http://dev.test//", accessToken: token, fetch: noFetch });
    expect(s).toMatchObject({ baseUrl: "http://dev.test", accountId: SUB, serverSessionId: SID.toLowerCase() });
    expect(s.sessionHeaders()).toEqual({ authorization: `Bearer ${token}` });
  });

  it.each([
    ["no `session_id`", jwt({ sub: SUB })],
    ["no `sub`", jwt({ session_id: SID })],
    ["a `sub` that is not a UUID", jwt({ sub: "user-1", session_id: SID })],
    ["not a JWT (the Phase 0 shared dev bearer)", "dev-0123456789abcdef"],
  ])("refuses a token with %s", (_, token) => {
    expect(() => accessTokenSession({ serverUrl: "http://dev.test", accessToken: token, fetch: noFetch })).toThrow(SessionError);
  });
});

describe("loginSession: a login whose token renews", () => {
  const OTHER_SID = "01890000-0000-7000-8000-0000000000BB";
  const API = "http://api.test";
  /** A login: its current token, and a refresh that moves it to `next` (or fails). */
  const login = (first: string, next: string | null) => {
    let token = first;
    const refreshes: number[] = [];
    return {
      accessToken: () => token,
      refresh: async () => {
        refreshes.push(1);
        if (next === null) return false;
        token = next;
        return true;
      },
      refreshes,
    };
  };
  const t1 = jwt({ sub: SUB, session_id: SID, n: 1 });
  const t2 = jwt({ sub: SUB, session_id: SID, n: 2 });
  /** The API: `accepts` says whether a bearer is valid; `body` is what a refusal carries. */
  const api = (accepts: (bearer: string) => boolean, body: unknown = { error: "UNAUTHENTICATED" }) => {
    const bearers: string[] = [];
    const f: typeof fetch = async (_input, init) => {
      const bearer = new Headers(init?.headers).get("authorization") ?? "";
      bearers.push(bearer);
      return accepts(bearer) ? Response.json({ ok: true }) : Response.json(body, { status: 401 });
    };
    return { fetch: f, bearers };
  };
  const call = async (s: Awaited<ReturnType<typeof loginSession>>) =>
    s.fetch(`${API}/v1/x`, { method: "POST", headers: { ...(await s.sessionHeaders()), "content-type": "application/json" }, body: "{}" });

  it("reads the claims off the current token and sends the current token as the bearer", async () => {
    const l = login(t1, t2);
    const s = await loginSession({ serverUrl: API, accessToken: l.accessToken, refresh: l.refresh, fetch: noFetch });
    expect(s).toMatchObject({ accountId: SUB, serverSessionId: SID.toLowerCase() });
    expect(await s.sessionHeaders()).toEqual({ authorization: `Bearer ${t1}` });
    await l.refresh();
    expect(await s.sessionHeaders()).toEqual({ authorization: `Bearer ${t2}` });
  });

  it("a 401 UNAUTHENTICATED: one refresh, one resend with the new bearer, and the caller sees the answer to it", async () => {
    const l = login(t1, t2);
    const server = api((b) => b === `Bearer ${t2}`);
    const s = await loginSession({ serverUrl: API, accessToken: l.accessToken, refresh: l.refresh, fetch: server.fetch });
    const res = await call(s);
    expect(res.status).toBe(200);
    expect(server.bearers).toEqual([`Bearer ${t1}`, `Bearer ${t2}`]);
    expect(l.refreshes).toHaveLength(1);
  });

  it("a refresh that fails: the 401 goes back to the caller (sync stops as before), no resend", async () => {
    const l = login(t1, null);
    const server = api(() => false);
    const s = await loginSession({ serverUrl: API, accessToken: l.accessToken, refresh: l.refresh, fetch: server.fetch });
    const res = await call(s);
    expect([res.status, await res.json()]).toEqual([401, { error: "UNAUTHENTICATED" }]);
    expect(server.bearers).toHaveLength(1);
  });

  it("never loops: a refused resend is the answer, after one refresh", async () => {
    const l = login(t1, t2);
    const server = api(() => false);
    const s = await loginSession({ serverUrl: API, accessToken: l.accessToken, refresh: l.refresh, fetch: server.fetch });
    expect((await call(s)).status).toBe(401);
    expect(server.bearers).toHaveLength(2);
    expect(l.refreshes).toHaveLength(1);
  });

  it.each([
    ["a 401 that is not the Worker's (a gateway, Cloudflare Access)", 401, "Unauthorized"],
    ["a 401 with another code", 401, { error: "NOT_FOUND" }],
    ["a 403", 403, { error: "UNAUTHENTICATED" }],
  ])("does not refresh for %s", async (_, status, body) => {
    const l = login(t1, t2);
    const f: typeof fetch = async () => (typeof body === "string" ? new Response(body, { status }) : Response.json(body, { status }));
    const s = await loginSession({ serverUrl: API, accessToken: l.accessToken, refresh: l.refresh, fetch: f });
    expect((await call(s)).status).toBe(status);
    expect(l.refreshes).toHaveLength(0);
  });

  it("does not refresh for a request that carried no bearer of this login", async () => {
    const l = login(t1, t2);
    const server = api(() => false);
    const s = await loginSession({ serverUrl: API, accessToken: l.accessToken, refresh: l.refresh, fetch: server.fetch });
    expect((await s.fetch(`${API}/v1/x`, { method: "GET" })).status).toBe(401);
    expect((await s.fetch(`${API}/v1/x`, { method: "GET", headers: { authorization: "Bearer someone-else" } })).status).toBe(401);
    expect(l.refreshes).toHaveLength(0);
  });

  it("requests refused together share one refresh; one refused after another's refresh resends without refreshing again", async () => {
    const l = login(t1, t2);
    const server = api((b) => b === `Bearer ${t2}`);
    const s = await loginSession({ serverUrl: API, accessToken: l.accessToken, refresh: l.refresh, fetch: server.fetch });
    const stale = { method: "GET", headers: { authorization: `Bearer ${t1}` } };
    const answers = await Promise.all([s.fetch(`${API}/a`, stale), s.fetch(`${API}/b`, stale), s.fetch(`${API}/c`, stale)]);
    expect(answers.map((r) => r.status)).toEqual([200, 200, 200]);
    expect((await s.fetch(`${API}/d`, stale)).status).toBe(200);
    expect(l.refreshes).toHaveLength(1);
  });

  it("refuses a token of another session: every capability label binds the session it started with (§11.3)", async () => {
    const l = login(t1, jwt({ sub: SUB, session_id: OTHER_SID }));
    const s = await loginSession({ serverUrl: API, accessToken: l.accessToken, refresh: l.refresh, fetch: noFetch });
    await l.refresh();
    await expect(s.sessionHeaders()).rejects.toMatchObject({ code: "SESSION_CHANGED" });
  });

  it("refuses a first token without the claims, like accessTokenSession", async () => {
    await expect(loginSession({ serverUrl: API, accessToken: () => jwt({ sub: SUB }), refresh: async () => false, fetch: noFetch })).rejects.toMatchObject({ code: "NOT_A_SESSION" });
  });
});

describe("devSignIn (DEV)", () => {
  const answering = (status: number, body: unknown): typeof fetch => async () => Response.json(body, { status });

  it("returns the access token of a successful signup or login", async () => {
    const token = jwt({ sub: SUB, session_id: SID });
    expect(await devSignIn({ serverUrl: "http://dev.test", fetch: answering(200, { access_token: token }), mode: "login", email: "a@b.c", password: "x" })).toBe(token);
  });

  it.each(["INVALID_CREDENTIALS", "EMAIL_TAKEN", "WEAK_PASSWORD", "INVALID_EMAIL"] as const)("says %s when the provider does", async (code) => {
    await expect(devSignIn({ serverUrl: "http://dev.test", fetch: answering(400, { error: code }), mode: "signup", email: "a@b.c", password: "x" })).rejects.toMatchObject({ code });
  });

  it("an unreachable server or a gateway answer is UNREACHABLE", async () => {
    await expect(devSignIn({ serverUrl: "http://dev.test", fetch: noFetch, mode: "login", email: "a@b.c", password: "x" })).rejects.toMatchObject({ code: "UNREACHABLE" });
    await expect(devSignIn({ serverUrl: "http://dev.test", fetch: answering(502, "bad gateway"), mode: "login", email: "a@b.c", password: "x" })).rejects.toMatchObject({ code: "UNREACHABLE" });
  });
});
