import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { SessionError, loginSession } from "../src/session.js";
import { memoryAuthStorage, supabaseAuth, verifierRouter } from "../src/supabase-auth.js";
import { fakeGoTrue } from "./support/gotrue.js";

// §11.3, §35.2, §35.7, §3.7 on the client: Supabase Auth through `@supabase/auth-js`, against a fake GoTrue
// (test/support/gotrue.ts). The end-to-end proof against the Worker is the integration suite's
// `auth.http.test.ts`, through the dev server.

const URL_ = "http://supabase.test";
const EMAIL = "ana@example.test";
const PASSWORD = "correct horse battery";

const client = (o: { gotrue?: ReturnType<typeof fakeGoTrue>; storage?: ReturnType<typeof memoryAuthStorage> } = {}) => {
  const gotrue = o.gotrue ?? fakeGoTrue(URL_);
  const storage = o.storage ?? memoryAuthStorage();
  return { gotrue, storage, auth: supabaseAuth({ supabaseUrl: URL_, anonKey: "anon-key", storage, fetch: gotrue.fetch }) };
};

const claims = (token: string) => decodeJwt(token) as { sub: string; session_id: string };

describe("supabaseAuth", () => {
  it("signs up and in with email and password; the token is a session loginSession accepts", async () => {
    const { auth, gotrue } = client();
    expect(await auth.signUp(EMAIL, PASSWORD)).toEqual({ confirmationRequired: false });
    const signedUp = await auth.accessToken();
    await auth.signInWithPassword(EMAIL, PASSWORD);
    const signedIn = await auth.accessToken();
    expect(claims(signedIn).sub).toBe(claims(signedUp).sub);
    expect(claims(signedIn).session_id).not.toBe(claims(signedUp).session_id);
    const s = await loginSession({ serverUrl: "http://api.test", accessToken: auth.accessToken, refresh: auth.refresh, fetch: gotrue.fetch });
    expect(s.accountId).toBe(claims(signedIn).sub);
    expect(gotrue.requests).toEqual(["POST /auth/v1/signup", "POST /auth/v1/token?grant_type=password"]);
  });

  it("keeps the session in the storage adapter it was given, and a new client over it is still signed in", async () => {
    const { auth, gotrue, storage } = client();
    await auth.signUp(EMAIL, PASSWORD);
    expect(storage.items.size).toBe(1);
    const again = client({ gotrue, storage }).auth;
    expect(await again.accessToken()).toBe(await auth.accessToken());
  });

  it("the getter renews a token about to expire, keeping the session (§11.3: `session_id` is the same)", async () => {
    const { auth, gotrue } = client();
    gotrue.tokenSeconds = 30; // inside auth-js's 90 s margin: the next read renews it
    await auth.signUp(EMAIL, PASSWORD);
    const first = await auth.accessToken();
    gotrue.tokenSeconds = 3600;
    const second = await auth.accessToken();
    expect(second).not.toBe(first);
    expect(claims(second).session_id).toBe(claims(first).session_id);
    expect(gotrue.requests.filter((r) => r.includes("grant_type=refresh_token")).length).toBeGreaterThan(0);
  });

  it("refresh: true with a new token of the same session; false once the server ended the session", async () => {
    const { auth, gotrue } = client();
    await auth.signUp(EMAIL, PASSWORD);
    const first = await auth.accessToken();
    expect(await auth.refresh()).toBe(true);
    expect(claims(await auth.accessToken()).session_id).toBe(claims(first).session_id);
    gotrue.revoke(claims(first).session_id);
    expect(await auth.refresh()).toBe(false);
  });

  it("a signup that waits for the email confirmation says so, and there is no session yet", async () => {
    const { auth, gotrue } = client();
    gotrue.confirmEmail = true;
    expect(await auth.signUp(EMAIL, PASSWORD)).toEqual({ confirmationRequired: true });
    await expect(auth.accessToken()).rejects.toMatchObject({ code: "NOT_SIGNED_IN" });
  });

  it.each([
    ["a wrong password", "INVALID_CREDENTIALS", async (a: ReturnType<typeof client>["auth"]) => a.signInWithPassword(EMAIL, "wrong password")],
    ["an unknown email", "INVALID_CREDENTIALS", async (a: ReturnType<typeof client>["auth"]) => a.signInWithPassword("bob@example.test", PASSWORD)],
    ["a taken email", "EMAIL_TAKEN", async (a: ReturnType<typeof client>["auth"]) => a.signUp(EMAIL, "another long password")],
    ["a short password", "WEAK_PASSWORD", async (a: ReturnType<typeof client>["auth"]) => a.signUp("carl@example.test", "short")],
    ["an invalid email", "INVALID_EMAIL", async (a: ReturnType<typeof client>["auth"]) => a.signUp("not an email", PASSWORD)],
  ])("%s is %s, and the error repeats neither the password nor a token", async (_, code, act) => {
    const { auth } = client();
    await auth.signUp(EMAIL, PASSWORD);
    const token = await auth.accessToken();
    const error = await act(auth).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(SessionError);
    expect(error).toMatchObject({ code });
    const text = `${(error as Error).message} ${(error as Error).stack ?? ""}`;
    for (const secret of [PASSWORD, "wrong password", "another long password", token]) expect(text).not.toContain(secret);
  });

  it("an unreachable server is UNREACHABLE", async () => {
    const { auth, gotrue } = client();
    gotrue.down = true;
    await expect(auth.signInWithPassword(EMAIL, PASSWORD)).rejects.toMatchObject({ code: "UNREACHABLE" });
  });

  it("signOut ends the session on the server and here: the storage is empty and there is no token", async () => {
    const { auth, gotrue, storage } = client();
    await auth.signUp(EMAIL, PASSWORD);
    await auth.signOut();
    expect(gotrue.requests.at(-1)).toBe("POST /auth/v1/logout?scope=local");
    expect(storage.items.size).toBe(0);
    await expect(auth.accessToken()).rejects.toMatchObject({ code: "NOT_SIGNED_IN" });
    expect(await auth.refresh()).toBe(false);
  });

  it("onSessionChange tells a sign-in and a sign-out, and stops after unsubscribing", async () => {
    const { auth } = client();
    const changes: boolean[] = [];
    const unsubscribe = auth.onSessionChange((signedIn) => changes.push(signedIn));
    await auth.signUp(EMAIL, PASSWORD);
    expect(changes.at(-1)).toBe(true);
    await auth.signOut();
    expect(changes.at(-1)).toBe(false);
    unsubscribe();
    const told = changes.length;
    await auth.signInWithPassword(EMAIL, PASSWORD);
    expect(changes).toHaveLength(told);
  });

  it("email: the signed-in user's email, null once signed out", async () => {
    const { auth } = client();
    expect(await auth.email()).toBeNull();
    await auth.signUp(EMAIL, PASSWORD);
    expect(await auth.email()).toBe(EMAIL);
    await auth.signOut();
    expect(await auth.email()).toBeNull();
  });

  it("§35.7 relogin: asks the password, signs the same user in again and yields the new session's token; null when the user declines", async () => {
    const { auth, gotrue } = client();
    await auth.signUp(EMAIL, PASSWORD);
    const before = await auth.accessToken();
    const asked: number[] = [];
    const token = await auth.relogin(async () => {
      asked.push(1);
      return PASSWORD;
    })();
    expect(asked).toHaveLength(1);
    expect(token).toBe(await auth.accessToken());
    expect(claims(token!).sub).toBe(claims(before).sub);
    expect(claims(token!).session_id).not.toBe(claims(before).session_id);
    expect(gotrue.requests.at(-1)).toBe("POST /auth/v1/token?grant_type=password");
    expect(await auth.relogin(async () => null)()).toBeNull();
  });

  it("storageKey: two logins over one shared storage stay apart, each under its own key only", async () => {
    // The plugin's secret storage is shared by every vault of the app: each installation names its key.
    const gotrue = fakeGoTrue(URL_);
    const storage = memoryAuthStorage();
    const a = supabaseAuth({ supabaseUrl: URL_, anonKey: "anon-key", storage, fetch: gotrue.fetch, storageKey: "nodra-auth-a" });
    const b = supabaseAuth({ supabaseUrl: URL_, anonKey: "anon-key", storage, fetch: gotrue.fetch, storageKey: "nodra-auth-b" });
    await a.signUp(EMAIL, PASSWORD);
    expect([...storage.items.keys()]).toEqual(["nodra-auth-a"]);
    await expect(b.accessToken()).rejects.toMatchObject({ code: "NOT_SIGNED_IN" });
    await b.signInWithPassword(EMAIL, PASSWORD);
    expect([...storage.items.keys()].sort()).toEqual(["nodra-auth-a", "nodra-auth-b"]);
    expect(claims(await a.accessToken()).session_id).not.toBe(claims(await b.accessToken()).session_id);
    await b.signOut();
    expect([...storage.items.keys()]).toEqual(["nodra-auth-a"]);
    await a.dispose();
    await b.dispose();
  });

  describe("§3.7 email links: token_hash + verifyOtp, on a button press (no session in any URL)", () => {
    const failure = (p: Promise<unknown>) => p.then(() => null, (e: unknown) => e as Error);
    const secretFree = (e: Error | null, secrets: readonly string[]) => {
      expect(e).toBeInstanceOf(SessionError);
      const text = `${e!.message} ${e!.stack ?? ""}`;
      for (const s of secrets) expect(text).not.toContain(s);
    };
    const tokenHashOf = (link: string) => new URL(link).searchParams.get("token_hash")!;

    it("requestPasswordReset sends a token_hash link to /reset-password; an unknown email resolves just the same (no enumeration); nobody is signed in", async () => {
      const { auth, gotrue } = client();
      await auth.signUp(EMAIL, PASSWORD);
      await auth.signOut();
      await auth.requestPasswordReset(EMAIL, "https://app.nodranotes.com/reset-password");
      await auth.requestPasswordReset("nobody@example.test", "https://app.nodranotes.com/reset-password");
      expect(gotrue.requests.filter((r) => r.startsWith("POST /auth/v1/recover"))).toHaveLength(2);
      expect(gotrue.emails.map((e) => [e.email, e.kind])).toEqual([[EMAIL, "recovery"]]);
      const link = new URL(gotrue.emails[0]!.link);
      expect(link.pathname).toBe("/reset-password");
      expect(link.searchParams.get("type")).toBe("recovery");
      // The link carries no session, only a one-time hash: nothing in it signs anybody in.
      expect(link.hash).toBe("");
      expect(link.search).not.toMatch(/access_token|refresh_token/);
      await expect(auth.accessToken()).rejects.toMatchObject({ code: "NOT_SIGNED_IN" });
      expect(gotrue.requests.some((r) => r.startsWith("POST /auth/v1/verify"))).toBe(false);
    });

    it("verifyEmailLink(recovery) signs this client in; updatePassword: the old password is refused, the new one works, other sessions end", async () => {
      const { auth, gotrue } = client();
      await auth.signUp(EMAIL, PASSWORD);
      const otherDevice = client({ gotrue }).auth;
      await otherDevice.signInWithPassword(EMAIL, PASSWORD);
      await auth.signOut();

      await auth.requestPasswordReset(EMAIL, "https://app.nodranotes.com/reset-password");
      const changes: boolean[] = [];
      auth.onSessionChange((signedIn) => changes.push(signedIn));
      await auth.verifyEmailLink("recovery", tokenHashOf(gotrue.emails[0]!.link));
      expect(gotrue.requests.at(-1)).toBe("POST /auth/v1/verify");
      expect(await auth.email()).toBe(EMAIL);
      expect(changes.at(-1)).toBe(true);
      const recovered = await auth.accessToken();

      await auth.updatePassword("a brand new password");
      expect(claims(await auth.accessToken()).session_id).toBe(claims(recovered).session_id);
      expect(await otherDevice.refresh()).toBe(false);

      const fresh = client({ gotrue }).auth;
      await expect(fresh.signInWithPassword(EMAIL, PASSWORD)).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });
      await fresh.signInWithPassword(EMAIL, "a brand new password");
    });

    it.each([
      ["a used link", "used"],
      ["a link of the other kind", "kind"],
      ["a garbled hash", "garbled"],
    ])("%s is EMAIL_LINK_INVALID, signs nothing in, and the error repeats no hash", async (_, kind) => {
      const { auth, gotrue } = client();
      await auth.signUp(EMAIL, PASSWORD);
      await auth.signOut();
      await auth.requestPasswordReset(EMAIL, "https://app.nodranotes.com/reset-password");
      const hash = tokenHashOf(gotrue.emails[0]!.link);
      if (kind === "used") {
        const spender = client({ gotrue }).auth;
        await spender.verifyEmailLink("recovery", hash);
      }
      const e = await failure(kind === "kind" ? auth.verifyEmailLink("email", hash) : auth.verifyEmailLink("recovery", kind === "garbled" ? `${hash}x` : hash));
      expect(e).toMatchObject({ code: "EMAIL_LINK_INVALID" });
      secretFree(e, [hash]);
      await expect(auth.accessToken()).rejects.toMatchObject({ code: "NOT_SIGNED_IN" });
    });

    it("a sign-up confirmation link: /auth/confirm?token_hash&type=email; verifying it confirms the email (password sign-in then works)", async () => {
      const { auth, gotrue } = client();
      gotrue.confirmEmail = true;
      expect(await auth.signUp(EMAIL, PASSWORD)).toEqual({ confirmationRequired: true });
      await expect(auth.signInWithPassword(EMAIL, PASSWORD)).rejects.toMatchObject({ code: "EMAIL_NOT_CONFIRMED" });
      const mail = gotrue.emails.find((m) => m.kind === "confirmation")!;
      const link = new URL(mail.link);
      expect([link.pathname, link.searchParams.get("type")]).toEqual(["/auth/confirm", "email"]);
      const confirmer = client({ gotrue }).auth;
      await confirmer.verifyEmailLink("email", tokenHashOf(mail.link));
      expect(gotrue.users().find((u) => u.email === EMAIL)?.confirmed).toBe(true);
      await auth.signInWithPassword(EMAIL, PASSWORD);
    });

    it("updatePassword: WEAK_PASSWORD, SAME_PASSWORD, NOT_SIGNED_IN without a session; no error repeats a password or the token", async () => {
      const { auth } = client();
      await expect(auth.updatePassword("another long password")).rejects.toMatchObject({ code: "NOT_SIGNED_IN" });
      await auth.signUp(EMAIL, PASSWORD);
      const token = await auth.accessToken();
      const weak = await failure(auth.updatePassword("short"));
      expect(weak).toMatchObject({ code: "WEAK_PASSWORD" });
      const same = await failure(auth.updatePassword(PASSWORD));
      expect(same).toMatchObject({ code: "SAME_PASSWORD" });
      for (const e of [weak, same]) secretFree(e, ["short", PASSWORD, token]);
    });

    it("a refused request: RATE_LIMITED (429), UNREACHABLE", async () => {
      const { auth, gotrue } = client();
      gotrue.rateLimited = true;
      await expect(auth.requestPasswordReset(EMAIL, "https://app.nodranotes.com/reset-password")).rejects.toMatchObject({ code: "RATE_LIMITED" });
      gotrue.rateLimited = false;
      gotrue.down = true;
      await expect(auth.requestPasswordReset(EMAIL, "https://app.nodranotes.com/reset-password")).rejects.toMatchObject({ code: "UNREACHABLE" });
      await expect(auth.verifyEmailLink("recovery", "hash-1")).rejects.toMatchObject({ code: "UNREACHABLE" });
    });
  });

  describe("§3.7 OAuth sign-in with PKCE", () => {
    const CALLBACK = "https://app.nodranotes.com/auth/callback";
    const GITHUB = { providerUserId: "1001", email: EMAIL, verified: true } as const;
    const codeOf = (landing: string) => new URL(landing).searchParams.get("code")!;
    const verifierKeys = (s: ReturnType<typeof memoryAuthStorage>) => [...s.items.keys()].filter((k) => k.endsWith("-code-verifier"));

    it("startOAuth: an /authorize URL with an S256 challenge and the redirect, no request yet; the code redeems once for a session and the verifier is gone", async () => {
      const { auth, gotrue, storage } = client();
      const { url } = await auth.startOAuth({ provider: "github", redirectTo: CALLBACK });
      const u = new URL(url);
      expect(`${u.origin}${u.pathname}`).toBe(`${URL_}/auth/v1/authorize`);
      expect(u.searchParams.get("provider")).toBe("github");
      expect(u.searchParams.get("redirect_to")).toBe(CALLBACK);
      expect(u.searchParams.get("code_challenge_method")).toBe("s256");
      expect(u.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(u.searchParams.has("prompt")).toBe(false);
      expect(gotrue.requests).toEqual([]);
      expect(verifierKeys(storage).length).toBeGreaterThan(0);

      const landing = await gotrue.authorize(url, GITHUB);
      expect(landing.startsWith(`${CALLBACK}?code=`)).toBe(true);
      await auth.exchangeCode(codeOf(landing));
      expect(gotrue.requests).toContain("POST /auth/v1/token?grant_type=pkce");
      expect(await auth.email()).toBe(EMAIL);
      expect(await auth.userId()).toBe(claims(await auth.accessToken()).sub);
      expect(await auth.loginMethods()).toEqual(["github"]);
      expect(verifierKeys(storage)).toEqual([]);
    });

    it("selectAccount asks GitHub for its account picker (`prompt=select_account`)", async () => {
      const { auth } = client();
      const { url } = await auth.startOAuth({ provider: "github", redirectTo: CALLBACK, selectAccount: true });
      expect(new URL(url).searchParams.get("prompt")).toBe("select_account");
    });

    it.each([
      ["a code redeemed twice", "twice"],
      ["a code in a client that holds no verifier (another browser, storage cleared)", "elsewhere"],
      ["a code issued for another verifier", "foreign"],
      ["a code older than 5 minutes", "expired"],
    ])("%s → OAUTH_CALLBACK_INVALID, no session, and the error repeats no code", async (_, kind) => {
      const { auth, gotrue } = client();
      const { url } = await auth.startOAuth({ provider: "github", redirectTo: CALLBACK });
      let code = codeOf(await gotrue.authorize(url, GITHUB));
      let target = auth;
      if (kind === "twice") {
        await auth.exchangeCode(code);
        await auth.signOut();
        // A new flow, so a verifier is there: the server itself refuses the spent code.
        await auth.startOAuth({ provider: "github", redirectTo: CALLBACK });
      } else if (kind === "elsewhere") {
        target = client({ gotrue }).auth;
      } else if (kind === "foreign") {
        // The attacker's own flow: a code bound to the attacker's challenge, handed to this client.
        const attacker = client({ gotrue }).auth;
        const theirs = await attacker.startOAuth({ provider: "github", redirectTo: CALLBACK });
        code = codeOf(await gotrue.authorize(theirs.url, { providerUserId: "666", email: "mallory@example.test", verified: true }));
      } else {
        gotrue.clockSkewSeconds = 301;
      }
      const e = await target.exchangeCode(code).then(
        () => null,
        (x: unknown) => x as Error,
      );
      expect(e).toBeInstanceOf(SessionError);
      expect(e).toMatchObject({ code: "OAUTH_CALLBACK_INVALID" });
      expect(`${e!.message} ${e!.stack ?? ""}`).not.toContain(code);
      await expect(target.accessToken()).rejects.toMatchObject({ code: "NOT_SIGNED_IN" });
    });

    it("automatic linking only through a verified email: GitHub with the same verified email joins the password account; an unverified one is a new user, unconfirmed and unlinked", async () => {
      const { auth, gotrue } = client();
      await auth.signUp(EMAIL, PASSWORD);
      const owner = await auth.userId();
      await auth.signOut();

      const stranger = client({ gotrue }).auth;
      const s = await stranger.startOAuth({ provider: "github", redirectTo: CALLBACK });
      await stranger.exchangeCode(codeOf(await gotrue.authorize(s.url, { providerUserId: "2", email: EMAIL, verified: false })));
      expect(await stranger.userId()).not.toBe(owner);
      expect(gotrue.users().find((u) => u.id === owner)?.providers).toEqual(["email"]);
      expect(gotrue.users().find((u) => u.id !== owner)?.confirmed).toBe(false);

      const linked = client({ gotrue }).auth;
      const l = await linked.startOAuth({ provider: "github", redirectTo: CALLBACK });
      await linked.exchangeCode(codeOf(await gotrue.authorize(l.url, GITHUB)));
      expect(await linked.userId()).toBe(owner);
      expect([...(await linked.loginMethods())].sort()).toEqual(["github", "password"]);
    });

    it("a provider refusal is the host's to read: the redirect carries `error`, and no code", async () => {
      const { auth, gotrue } = client();
      const { url } = await auth.startOAuth({ provider: "github", redirectTo: CALLBACK });
      const landing = new URL(await gotrue.authorize(url, "deny"));
      expect(landing.searchParams.get("error")).toBe("access_denied");
      expect(landing.searchParams.has("code")).toBe(false);
    });
  });

  describe("ADR-024 Supabase Auth as an OAuth 2.1 server: the consent page's calls and a client's session", () => {
    const REDIRECT = "obsidian://nodra-auth";
    /** A signed-in web user and a pending authorization request of the registered client. */
    const pending = async (o: { gotrue?: ReturnType<typeof fakeGoTrue> } = {}) => {
      const c = client(o);
      const clientId = c.gotrue.registerOAuthClient("Nodra for Obsidian", REDIRECT);
      await c.auth.signUp(EMAIL, PASSWORD);
      const request = async (state = "s-1", challenge = "c".repeat(43)) => {
        const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: "plain", state });
        const location = (await c.gotrue.fetch(`${URL_}/auth/v1/oauth/authorize?${q}`)).headers.get("location")!;
        return new URL(location).searchParams.get("authorization_id")!;
      };
      return { ...c, clientId, request };
    };
    /** The session the client gets for a code (what nativeOAuth does), in a separate client. */
    const redeem = async (gotrue: ReturnType<typeof fakeGoTrue>, clientId: string, code: string, verifier = "c".repeat(43)) => {
      const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier });
      const t = (await (await gotrue.fetch(`${URL_}/auth/v1/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString() })).json()) as { access_token: string; refresh_token: string };
      const storage = memoryAuthStorage();
      const auth = supabaseAuth({ supabaseUrl: URL_, anonKey: "anon-key", storage, fetch: gotrue.fetch, storageKey: "nodra-auth-x" });
      await auth.useTokens({ accessToken: t.access_token, refreshToken: t.refresh_token });
      return { auth, storage };
    };

    it("oauthAuthorization: what the consent page shows (client name, the signed-in user's email); approve: the redirect with the code and the state", async () => {
      const { auth, request, clientId } = await pending();
      const id = await request();
      expect(await auth.oauthAuthorization(id)).toEqual({ kind: "CONSENT", authorizationId: id, clientName: "Nodra for Obsidian", redirectUri: REDIRECT, email: EMAIL });
      const landing = new URL(await auth.decideOAuthAuthorization(id, "approve"));
      expect(`${landing.protocol}//${landing.host}`).toBe(REDIRECT);
      expect(landing.searchParams.get("state")).toBe("s-1");
      expect(landing.searchParams.get("code")).toMatch(/^oauth-code-/);
      expect(clientId).toBeTruthy();
    });

    it("deny: the redirect carries access_denied and the state, and no code", async () => {
      const { auth, request } = await pending();
      const id = await request("s-2");
      await auth.oauthAuthorization(id);
      const landing = new URL(await auth.decideOAuthAuthorization(id, "deny"));
      expect([landing.searchParams.get("error"), landing.searchParams.get("state"), landing.searchParams.has("code")]).toEqual(["access_denied", "s-2", false]);
    });

    it("a user who consented before: GoTrue approves by itself and answers only the redirect (ALREADY_ALLOWED), which the page must still not follow on its own", async () => {
      const { auth, request } = await pending();
      const first = await request();
      await auth.oauthAuthorization(first);
      await auth.decideOAuthAuthorization(first, "approve");
      const second = await request("s-3");
      const again = await auth.oauthAuthorization(second);
      expect(again.kind).toBe("ALREADY_ALLOWED");
      expect(again.kind === "ALREADY_ALLOWED" && new URL(again.redirectUrl).searchParams.get("state")).toBe("s-3");
    });

    it("an unknown, used or expired request, or one taken by another user: OAUTH_REQUEST_INVALID; signed out: NOT_SIGNED_IN", async () => {
      const { auth, gotrue, request } = await pending();
      await expect(auth.oauthAuthorization("authz-nope")).rejects.toMatchObject({ code: "OAUTH_REQUEST_INVALID" });
      const used = await request();
      await auth.oauthAuthorization(used);
      await auth.decideOAuthAuthorization(used, "deny");
      await expect(auth.decideOAuthAuthorization(used, "approve")).rejects.toMatchObject({ code: "OAUTH_REQUEST_INVALID" });
      const old = await request();
      gotrue.clockSkewSeconds = 601;
      await expect(auth.oauthAuthorization(old)).rejects.toMatchObject({ code: "OAUTH_REQUEST_INVALID" });
      gotrue.clockSkewSeconds = 0;
      const taken = await request();
      await auth.oauthAuthorization(taken);
      const other = client({ gotrue }).auth;
      await other.signUp("someone@example.test", PASSWORD);
      await expect(other.oauthAuthorization(taken)).rejects.toMatchObject({ code: "OAUTH_REQUEST_INVALID" });
      await auth.signOut();
      await expect(auth.oauthAuthorization(await request())).rejects.toMatchObject({ code: "NOT_SIGNED_IN" });
    });

    it("useTokens: the client's tokens become this client's session (the user read from /user)", async () => {
      const { auth, gotrue, request, clientId } = await pending();
      const id = await request();
      await auth.oauthAuthorization(id);
      const code = new URL(await auth.decideOAuthAuthorization(id, "approve")).searchParams.get("code")!;
      const { auth: plugin, storage } = await redeem(gotrue, clientId, code);
      expect(await plugin.email()).toBe(EMAIL);
      expect(await plugin.userId()).toBe(await auth.userId());
      expect([...storage.items.keys()]).toEqual(["nodra-auth-x"]);
    });

    it("a session issued to an OAuth client renews at /oauth/token with its client_id (GoTrue refuses it at /token); a password session still renews at /token", async () => {
      const { auth, gotrue, request, clientId } = await pending();
      const id = await request();
      await auth.oauthAuthorization(id);
      const code = new URL(await auth.decideOAuthAuthorization(id, "approve")).searchParams.get("code")!;
      const { auth: plugin } = await redeem(gotrue, clientId, code);
      const before = claims(await plugin.accessToken());
      const seen = gotrue.requests.length;
      expect(await plugin.refresh()).toBe(true);
      expect(gotrue.requests.slice(seen)).toEqual(["POST /auth/v1/oauth/token", "GET /auth/v1/user"]);
      const after = claims(await plugin.accessToken());
      expect(after.session_id).toBe(before.session_id);
      expect(decodeJwt(await plugin.accessToken())).toMatchObject({ client_id: clientId });
      // The renewed session is complete: its user is there, and it renews again.
      expect(await plugin.email()).toBe(EMAIL);
      expect(await plugin.refresh()).toBe(true);

      const web = gotrue.requests.length;
      expect(await auth.refresh()).toBe(true);
      expect(gotrue.requests.slice(web)).toEqual(["POST /auth/v1/token?grant_type=refresh_token"]);
    });

    it("a refused renewal of a client's session (revoked on the server): refresh() is false, and it is never tried at /token", async () => {
      const { auth, gotrue, request, clientId } = await pending();
      const id = await request();
      await auth.oauthAuthorization(id);
      const code = new URL(await auth.decideOAuthAuthorization(id, "approve")).searchParams.get("code")!;
      const { auth: plugin } = await redeem(gotrue, clientId, code);
      gotrue.revoke(claims(await plugin.accessToken()).session_id);
      const seen = gotrue.requests.length;
      expect(await plugin.refresh()).toBe(false);
      expect(gotrue.requests.slice(seen)).toEqual(["POST /auth/v1/oauth/token"]);
    });

    it("primaryAuthAt: the session's latest amr timestamp (seconds), kept by a renewal; null when signed out", async () => {
      const { auth, gotrue } = await pending();
      const at = await auth.primaryAuthAt();
      expect(at).toBe((decodeJwt(await auth.accessToken()) as { amr: Array<{ timestamp: number }> }).amr[0]!.timestamp);
      gotrue.clockSkewSeconds = 3600;
      await auth.refresh();
      expect(await auth.primaryAuthAt()).toBe(at);
      await auth.signOut();
      expect(await auth.primaryAuthAt()).toBeNull();
    });
  });

  describe("§3.7 adoptSession: a sign-in or re-authentication completed in a separate client", () => {
    const CALLBACK = "obsidian://nodra-auth?vault=v&flow=f";
    const codeOf = (landing: string) => new URL(landing).searchParams.get("code")!;

    const githubUser = async () => {
      const { auth, gotrue, storage } = client();
      const { url } = await auth.startOAuth({ provider: "github", redirectTo: CALLBACK });
      await auth.exchangeCode(codeOf(await gotrue.authorize(url, { providerUserId: "1", email: EMAIL, verified: true })));
      return { auth, gotrue, storage };
    };
    const reauthAs = async (gotrue: ReturnType<typeof fakeGoTrue>, providerUserId: string, email: string) => {
      const storage = memoryAuthStorage();
      const fresh = supabaseAuth({ supabaseUrl: URL_, anonKey: "anon-key", storage, fetch: gotrue.fetch, storageKey: "nodra-reauth" });
      const { url } = await fresh.startOAuth({ provider: "github", redirectTo: CALLBACK, selectAccount: true });
      await fresh.exchangeCode(codeOf(await gotrue.authorize(url, { providerUserId, email, verified: true })));
      return { fresh, storage };
    };

    it("the same user: this client takes the new session (a fresh primary authentication), and the other client holds nothing", async () => {
      const { auth, gotrue } = await githubUser();
      const before = claims(await auth.accessToken());
      const { fresh, storage } = await reauthAs(gotrue, "1", EMAIL);
      const after = claims(await fresh.accessToken());
      expect(await auth.adoptSession(fresh, before.sub)).toBe(true);
      expect(claims(await auth.accessToken())).toMatchObject({ sub: before.sub, session_id: after.session_id });
      expect(gotrue.live(after.session_id)).toBe(true);
      expect(storage.items.size).toBe(0);
    });

    it("another user (§44.3): false; the new session is signed out on the server, this client's session is kept unchanged", async () => {
      const { auth, gotrue, storage } = await githubUser();
      const before = await auth.accessToken();
      const snapshot = new Map(storage.items);
      const { fresh, storage: freshStorage } = await reauthAs(gotrue, "2", "someone-else@example.test");
      const other = claims(await fresh.accessToken());
      expect(other.sub).not.toBe(claims(before).sub);
      expect(await auth.adoptSession(fresh, claims(before).sub)).toBe(false);
      expect(await auth.accessToken()).toBe(before);
      expect(storage.items).toEqual(snapshot);
      expect(gotrue.live(other.session_id)).toBe(false);
      expect(freshStorage.items.size).toBe(0);
    });

    it("a plain sign-in (no expected user) adopts whoever signed in", async () => {
      const { gotrue } = await githubUser();
      const main = client({ gotrue }).auth;
      const { fresh } = await reauthAs(gotrue, "1", EMAIL);
      expect(await main.adoptSession(fresh, null)).toBe(true);
      expect(await main.email()).toBe(EMAIL);
    });
  });

  it("verifierRouter: keys ending in -code-verifier go to one storage, the session to the other", async () => {
    const gotrue = fakeGoTrue(URL_);
    const verifiers = memoryAuthStorage();
    const rest = memoryAuthStorage();
    const auth = supabaseAuth({ supabaseUrl: URL_, anonKey: "anon-key", storage: verifierRouter({ verifiers, rest }), fetch: gotrue.fetch, storageKey: "nodra-auth-x" });
    const { url } = await auth.startOAuth({ provider: "github", redirectTo: "https://app.nodranotes.com/auth/callback" });
    expect(verifiers.items.size).toBeGreaterThan(0);
    expect([...verifiers.items.keys()].every((k) => k.endsWith("-code-verifier"))).toBe(true);
    expect(rest.items.size).toBe(0);
    await auth.exchangeCode(new URL(await gotrue.authorize(url, { providerUserId: "1", email: EMAIL, verified: true })).searchParams.get("code")!);
    expect([...rest.items.keys()]).toEqual(["nodra-auth-x"]);
    expect([...verifiers.items.keys()]).toEqual([]);
  });
  it("dispose: its listeners are not told anything more (a plugin that unloads leaves nothing running)", async () => {
    const { auth } = client();
    const changes: boolean[] = [];
    auth.onSessionChange((signedIn) => changes.push(signedIn));
    await auth.signUp(EMAIL, PASSWORD);
    const told = changes.length;
    expect(told).toBeGreaterThan(0);
    await auth.dispose();
    await auth.signInWithPassword(EMAIL, PASSWORD);
    expect(changes).toHaveLength(told);
  });
});

describe("CAPTCHA (Supabase Attack Protection, Cloudflare Turnstile)", () => {
  const RESET_TO = "https://app.nodranotes.com/reset-password";
  /** A GoTrue with CAPTCHA on, and a confirmed user who signed up before it was turned on. */
  const protectedClient = async () => {
    const c = client();
    await c.auth.signUp(EMAIL, PASSWORD);
    await c.auth.signOut();
    c.gotrue.captcha = true;
    return c;
  };

  it("the fake refuses each guarded call without a token (the check can fail): CAPTCHA_FAILED, and nothing happens", async () => {
    const { auth, gotrue } = await protectedClient();
    await expect(auth.signInWithPassword(EMAIL, PASSWORD)).rejects.toMatchObject({ code: "CAPTCHA_FAILED" });
    await expect(auth.signUp("bob@example.test", PASSWORD)).rejects.toMatchObject({ code: "CAPTCHA_FAILED" });
    await expect(auth.requestPasswordReset(EMAIL, RESET_TO)).rejects.toMatchObject({ code: "CAPTCHA_FAILED" });
    expect(gotrue.emails.filter((e) => e.kind === "recovery")).toEqual([]);
    expect(gotrue.users().map((u) => u.email)).toEqual([EMAIL]);
    await expect(auth.accessToken()).rejects.toMatchObject({ code: "NOT_SIGNED_IN" });
  });

  it("sign-in, sign-up and the reset request send their token to GoTrue (`gotrue_meta_security.captcha_token`)", async () => {
    const { auth, gotrue } = await protectedClient();
    await auth.signInWithPassword(EMAIL, PASSWORD, "token-1");
    await auth.signOut();
    await auth.signUp("bob@example.test", PASSWORD, "token-2");
    await auth.signOut();
    await auth.requestPasswordReset(EMAIL, RESET_TO, "token-3");
    expect(gotrue.captchaTokens).toEqual(["token-1", "token-2", "token-3"]);
    expect(gotrue.emails.filter((e) => e.kind === "recovery").map((e) => e.email)).toEqual([EMAIL]);
  });

  it("a token is single-use: the same one again is refused, even after a wrong password spent it", async () => {
    const { auth } = await protectedClient();
    await expect(auth.signInWithPassword(EMAIL, "wrong password", "token-1")).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });
    await expect(auth.signInWithPassword(EMAIL, PASSWORD, "token-1")).rejects.toMatchObject({ code: "CAPTCHA_FAILED" });
    await auth.signInWithPassword(EMAIL, PASSWORD, "token-2");
  });

  it("§35.7 relogin: the password and the token typed with it; a bare password (no token) is refused", async () => {
    const { auth, gotrue } = await protectedClient();
    await auth.signInWithPassword(EMAIL, PASSWORD, "token-1");
    const token = await auth.relogin(async () => ({ password: PASSWORD, captchaToken: "token-2" }))();
    expect(token).toBe(await auth.accessToken());
    expect(gotrue.captchaTokens).toEqual(["token-1", "token-2"]);
    await expect(auth.relogin(async () => PASSWORD)()).rejects.toMatchObject({ code: "CAPTCHA_FAILED" });
  });

  it("what GoTrue exempts needs no token: renewal, the PKCE code exchange, an email link, a password change", async () => {
    const { auth, gotrue } = await protectedClient();
    await auth.requestPasswordReset(EMAIL, RESET_TO, "token-1");
    const link = new URL(gotrue.emails.at(-1)!.link);
    await auth.verifyEmailLink("recovery", link.searchParams.get("token_hash")!);
    expect(await auth.refresh()).toBe(true);
    await auth.updatePassword("a brand new password");
    const { url } = await auth.startOAuth({ provider: "github", redirectTo: "https://app.nodranotes.com/auth/callback" });
    await auth.exchangeCode(new URL(await gotrue.authorize(url, { providerUserId: "1", email: EMAIL, verified: true })).searchParams.get("code")!);
    expect(gotrue.captchaTokens).toEqual(["token-1"]);
  });

  it("before CAPTCHA is turned on, a token is harmless: GoTrue ignores it", async () => {
    const { auth, gotrue } = client();
    await auth.signUp(EMAIL, PASSWORD, "token-1");
    await auth.signInWithPassword(EMAIL, PASSWORD, "token-2");
    expect(gotrue.captchaTokens).toEqual([]);
    expect(await auth.email()).toBe(EMAIL);
  });
});
