import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { OAUTH_FLOW_MS, nativeOAuth, randomFlowId } from "../src/oauth-flow.js";
import { memoryAuthStorage, supabaseAuth } from "../src/supabase-auth.js";
import { fakeGoTrue } from "./support/gotrue.js";

// ADR-024 for a native host: the plugin is a public client of Supabase Auth's OAuth 2.1 server
// (authorization code + PKCE). One pending flow per instance, bound by a random `flow` (sent as `state`)
// and a verifier held in memory only. §44.3: a callback with no pending flow, another `state`, another
// vault, or older than 10 minutes is ignored without a request; a code issued for another verifier never
// yields a session; the user's refusal ends the flow with OAUTH_REFUSED.

const URL_ = "http://supabase.test";
const VAULT = "a1b2c3d4e5f60718";
const REDIRECT = "obsidian://nodra-auth";
const EMAIL = "ana@example.test";
const PASSWORD = "correct horse battery";

async function world() {
  const gotrue = fakeGoTrue(URL_);
  const clientId = gotrue.registerOAuthClient("Nodra for Obsidian", REDIRECT);
  const storages: Array<ReturnType<typeof memoryAuthStorage>> = [];
  let clock = 1_000_000;
  const timers: Array<{ fn: () => void; at: number; cleared: boolean }> = [];
  const expired: number[] = [];
  const newClient = () => {
    const storage = memoryAuthStorage();
    storages.push(storage);
    return supabaseAuth({ supabaseUrl: URL_, anonKey: "anon", storage, fetch: gotrue.fetch, storageKey: "nodra-oauth-flow" });
  };
  const flow = nativeOAuth({
    supabaseUrl: URL_,
    anonKey: "anon",
    clientId,
    redirectUri: REDIRECT,
    vault: VAULT,
    newClient,
    fetch: gotrue.fetch,
    now: () => clock,
    onExpire: () => expired.push(clock),
    setTimer: (fn, ms) => {
      const t = { fn, at: clock + ms, cleared: false };
      timers.push(t);
      return t;
    },
    clearTimer: (h) => void ((h as { cleared: boolean }).cleared = true),
  });
  // The web, where the user signs in (password + CAPTCHA there) and consents.
  const web = supabaseAuth({ supabaseUrl: URL_, anonKey: "anon", storage: memoryAuthStorage(), fetch: gotrue.fetch });
  await web.signUp(EMAIL, PASSWORD);
  /** The system browser at the authorize URL, then the web's consent page deciding; the redirect it lands on, as Obsidian's handler params. */
  const browser = async (url: string, decision: "approve" | "deny" = "approve") => {
    const consentPage = new URL((await gotrue.fetch(url)).headers.get("location")!);
    expect(`${consentPage.origin}${consentPage.pathname}`).toBe("https://app.nodranotes.com/oauth/consent");
    const id = consentPage.searchParams.get("authorization_id")!;
    const request = await web.oauthAuthorization(id);
    const landing = request.kind === "ALREADY_ALLOWED" ? request.redirectUrl : await web.decideOAuthAuthorization(id, decision);
    return { action: "nodra-auth", ...Object.fromEntries(new URL(landing).searchParams) } as Record<string, string>;
  };
  const advance = (ms: number) => {
    clock += ms;
    for (const t of timers)
      if (!t.cleared && t.at <= clock) {
        t.cleared = true;
        t.fn();
      }
  };
  return { gotrue, clientId, flow, web, storages, browser, advance, expired, setClock: (ms: number) => void (clock += ms) };
}

describe("nativeOAuth (OAuth 2.1 client)", () => {
  it("start: the authorize URL names the client, the exact redirect URI, an S256 challenge and a fresh 128-bit state; no request yet", async () => {
    const w = await world();
    const before = w.gotrue.requests.length;
    const url = new URL(await w.flow.start());
    expect(`${url.origin}${url.pathname}`).toBe(`${URL_}/auth/v1/oauth/authorize`);
    expect(Object.fromEntries(url.searchParams)).toMatchObject({ response_type: "code", client_id: w.clientId, redirect_uri: REDIRECT, code_challenge_method: "S256" });
    expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(url.searchParams.get("state")).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(w.gotrue.requests.length).toBe(before);
    expect(w.flow.pending()).toBe(true);
  });

  it("the approved callback becomes the flow client's session: a token of the OAuth client, for the user who consented", async () => {
    const w = await world();
    const out = await w.flow.callback(await w.browser(await w.flow.start()));
    expect(out.kind).toBe("SIGNED_IN");
    if (out.kind !== "SIGNED_IN") return;
    expect(await out.auth.email()).toBe(EMAIL);
    expect(await out.auth.userId()).toBe(await w.web.userId());
    expect(decodeJwt(await out.auth.accessToken())).toMatchObject({ client_id: w.clientId });
    expect(w.gotrue.requests).toContain("POST /auth/v1/oauth/token");
    expect(w.flow.pending()).toBe(false);
  });

  it("randomFlowId: 128 bits, base64url, never repeating", () => {
    const ids = new Set(Array.from({ length: 200 }, randomFlowId));
    expect(ids.size).toBe(200);
    for (const id of ids) expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it.each([
    ["no flow pending", "none"],
    ["another state (another instance's flow)", "other-flow"],
    ["no state", "no-state"],
    ["another vault", "other-vault"],
    ["a callback older than 10 minutes", "late"],
  ])("ignores a callback with %s: IGNORED, no token request, no session", async (_, kind) => {
    const w = await world();
    const params = await w.browser(await w.flow.start());
    if (kind === "none") await w.flow.cancel();
    if (kind === "late") w.setClock(OAUTH_FLOW_MS + 1);
    const { state: _state, ...stateless } = params;
    const forged = kind === "other-flow" ? { ...params, state: randomFlowId() } : kind === "no-state" ? stateless : kind === "other-vault" ? { ...params, vault: "another-vault" } : params;
    const before = w.gotrue.requests.length;
    expect(await w.flow.callback(forged)).toEqual({ kind: "IGNORED" });
    expect(w.gotrue.requests.slice(before)).toEqual([]);
    expect(w.storages).toEqual([]);
    // Still pending only when the flow itself was neither cancelled nor expired: the right callback then works.
    if (kind === "other-flow" || kind === "other-vault" || kind === "no-state") expect((await w.flow.callback(params)).kind).toBe("SIGNED_IN");
    else expect(w.flow.pending()).toBe(false);
  });

  it("a code issued for another verifier (an attacker's own flow, delivered with this flow's state) never yields a session", async () => {
    const w = await world();
    const ours = await w.flow.start();
    const state = new URL(ours).searchParams.get("state")!;
    // The attacker runs the same client with their own challenge and their own account.
    const theirs = new URL(ours);
    theirs.searchParams.set("code_challenge", "A".repeat(43));
    theirs.searchParams.set("state", "theirs");
    const mallory = await w.browser(theirs.href);
    const out = await w.flow.callback({ code: mallory.code!, state });
    expect(out.kind).toBe("FAILED");
    expect(out.kind === "FAILED" && out.error.code).toBe("OAUTH_CALLBACK_INVALID");
    expect(out.kind === "FAILED" && out.error.message).not.toContain(mallory.code!);
    expect(w.flow.pending()).toBe(false);
  });

  it("Deny on the consent page: FAILED with OAUTH_REFUSED (access_denied), the flow ends, no session, GoTrue's free text is not repeated", async () => {
    const w = await world();
    const out = await w.flow.callback(await w.browser(await w.flow.start(), "deny"));
    expect(out.kind).toBe("FAILED");
    if (out.kind !== "FAILED") return;
    expect(out.error.code).toBe("OAUTH_REFUSED");
    expect(out.error.message).toContain("access_denied");
    expect(out.error.message).not.toContain("User denied");
    expect(w.flow.pending()).toBe(false);
    expect(w.storages).toEqual([]);
  });

  it("a code that does not redeem (spent, or the token endpoint refuses): OAUTH_CALLBACK_INVALID; the endpoint down: UNREACHABLE; the flow ends either way", async () => {
    const w = await world();
    const params = await w.browser(await w.flow.start());
    expect((await w.flow.callback(params)).kind).toBe("SIGNED_IN");
    // The same code again, under a new flow's state: GoTrue spent it.
    const again = await w.flow.start();
    const spent = await w.flow.callback({ ...params, state: new URL(again).searchParams.get("state")! });
    expect(spent.kind === "FAILED" && spent.error.code).toBe("OAUTH_CALLBACK_INVALID");
    expect(w.flow.pending()).toBe(false);

    const next = await w.flow.start();
    const fresh = await w.browser(next);
    w.gotrue.down = true;
    const down = await w.flow.callback(fresh);
    expect(down.kind === "FAILED" && down.error.code).toBe("UNREACHABLE");
    expect(w.flow.pending()).toBe(false);
  });

  it("one pending flow: a new start ends the previous one, whose callback is then ignored", async () => {
    const w = await world();
    const first = await w.browser(await w.flow.start());
    const second = await w.flow.start();
    expect(await w.flow.callback(first)).toEqual({ kind: "IGNORED" });
    expect((await w.flow.callback(await w.browser(second))).kind).toBe("SIGNED_IN");
  });

  it("a second delivery of the same callback is ignored (the flow ended with the first)", async () => {
    const w = await world();
    const params = await w.browser(await w.flow.start());
    const [a, b] = await Promise.all([w.flow.callback(params), w.flow.callback(params)]);
    expect([a.kind, b.kind].sort()).toEqual(["IGNORED", "SIGNED_IN"]);
  });

  it("the timeout ends the flow at 10 minutes and tells the host", async () => {
    const w = await world();
    await w.flow.start();
    w.advance(OAUTH_FLOW_MS - 1);
    expect(w.flow.pending()).toBe(true);
    w.advance(1);
    expect(w.flow.pending()).toBe(false);
    expect(w.expired).toHaveLength(1);
  });
});
