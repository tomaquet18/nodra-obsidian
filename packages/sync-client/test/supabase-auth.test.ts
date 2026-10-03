import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { SessionError, loginSession } from "../src/session.js";
import { memoryAuthStorage, supabaseAuth } from "../src/supabase-auth.js";
import { fakeGoTrue } from "./support/gotrue.js";

// §11.3, §35.2, §35.7 on the client: Supabase Auth through `@supabase/auth-js`, against a fake GoTrue
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

  describe("forgot password (implicit flow: the email link's redirect carries the session in its fragment)", () => {
    const RESET = "https://app.nodranotes.com/reset-password";
    /** Opens the email's link as a browser would (GoTrue's /verify redirects) and returns the fragment it lands with. */
    const follow = async (gotrue: ReturnType<typeof fakeGoTrue>, link: string) => {
      const res = await gotrue.fetch(link, { redirect: "manual" });
      const location = new URL(res.headers.get("location")!);
      expect(location.origin + location.pathname).toBe(RESET);
      return location.hash;
    };
    const failure = (p: Promise<unknown>) => p.then(() => null, (e: unknown) => e as Error);
    const secretFree = (e: Error | null, secrets: readonly string[]) => {
      expect(e).toBeInstanceOf(SessionError);
      const text = `${e!.message} ${e!.stack ?? ""}`;
      for (const s of secrets) expect(text).not.toContain(s);
    };

    it("requestPasswordReset sends the link to the given redirect; an unknown email resolves just the same (no enumeration)", async () => {
      const { auth, gotrue } = client();
      await auth.signUp(EMAIL, PASSWORD);
      await auth.signOut();
      await auth.requestPasswordReset(EMAIL, RESET);
      await auth.requestPasswordReset("nobody@example.test", RESET);
      expect(gotrue.requests.filter((r) => r.startsWith("POST /auth/v1/recover"))).toEqual([
        `POST /auth/v1/recover?redirect_to=${encodeURIComponent(RESET)}`,
        `POST /auth/v1/recover?redirect_to=${encodeURIComponent(RESET)}`,
      ]);
      expect(gotrue.emails.map((e) => e.email)).toEqual([EMAIL]);
      // It signs nobody in.
      await expect(auth.accessToken()).rejects.toMatchObject({ code: "NOT_SIGNED_IN" });
    });

    it("the link signs this client in; updatePassword changes the password: the old one is refused, the new one works, other sessions end", async () => {
      const { auth, gotrue } = client();
      await auth.signUp(EMAIL, PASSWORD);
      const otherDevice = client({ gotrue }).auth;
      await otherDevice.signInWithPassword(EMAIL, PASSWORD);
      await auth.signOut();

      await auth.requestPasswordReset(EMAIL, RESET);
      const fragment = await follow(gotrue, gotrue.emails[0]!.link);
      const changes: boolean[] = [];
      auth.onSessionChange((signedIn) => changes.push(signedIn));
      await auth.signInWithRecoveryLink(fragment);
      expect(await auth.email()).toBe(EMAIL);
      expect(changes.at(-1)).toBe(true);
      const recovered = await auth.accessToken();

      await auth.updatePassword("a brand new password");
      // Still signed in, in the same session.
      expect(claims(await auth.accessToken()).session_id).toBe(claims(recovered).session_id);
      // The other device's session ended with the change (GoTrue's rule; the Worker follows within §11.3's window).
      expect(await otherDevice.refresh()).toBe(false);

      const fresh = client({ gotrue }).auth;
      await expect(fresh.signInWithPassword(EMAIL, PASSWORD)).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });
      await fresh.signInWithPassword(EMAIL, "a brand new password");
    });

    it.each([
      ["a used link", "used"],
      ["an expired link (GoTrue's error redirect)", "error"],
      ["a fragment that is not a recovery", "signup"],
      ["no fragment", "empty"],
      ["a garbled token", "garbled"],
    ])("%s is RECOVERY_LINK_INVALID, signs nothing in, and the error repeats no token", async (_, kind) => {
      const { auth, gotrue } = client();
      await auth.signUp(EMAIL, PASSWORD);
      await auth.signOut();
      await auth.requestPasswordReset(EMAIL, RESET);
      const link = gotrue.emails[0]!.link;
      const good = await follow(gotrue, link);
      const params = new URLSearchParams(good.slice(1));
      const fragment =
        kind === "used"
          ? await follow(gotrue, link)
          : kind === "error"
            ? "#error=access_denied&error_code=otp_expired&error_description=Email+link+is+invalid+or+has+expired"
            : kind === "signup"
              ? good.replace("type=recovery", "type=signup")
              : kind === "empty"
                ? ""
                : `#access_token=not.a-jwt&refresh_token=${params.get("refresh_token")}&type=recovery`;
      const e = await failure(auth.signInWithRecoveryLink(fragment));
      expect(e).toMatchObject({ code: "RECOVERY_LINK_INVALID" });
      secretFree(e, [params.get("access_token")!, params.get("refresh_token")!]);
      await expect(auth.accessToken()).rejects.toMatchObject({ code: "NOT_SIGNED_IN" });
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

    it("a refused request: RATE_LIMITED (429), UNREACHABLE; neither repeats the email's password", async () => {
      const { auth, gotrue } = client();
      gotrue.rateLimited = true;
      await expect(auth.requestPasswordReset(EMAIL, RESET)).rejects.toMatchObject({ code: "RATE_LIMITED" });
      gotrue.rateLimited = false;
      gotrue.down = true;
      await expect(auth.requestPasswordReset(EMAIL, RESET)).rejects.toMatchObject({ code: "UNREACHABLE" });
      await expect(auth.updatePassword("another long password")).rejects.toMatchObject({ code: expect.stringMatching(/UNREACHABLE|NOT_SIGNED_IN/) });
    });
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
