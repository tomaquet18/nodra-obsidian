import { describe, expect, it } from "vitest";
import { OAUTH_FLOW_MS, nativeOAuth, randomFlowId } from "../src/oauth-flow.js";
import { memoryAuthStorage, supabaseAuth } from "../src/supabase-auth.js";
import { fakeGoTrue } from "./support/gotrue.js";

// §3.7 (ADR-023) for a native host: one pending flow per instance, bound by a random `flow` and a
// verifier in the memory of the flow's own client. §44.3: a callback with no pending flow, another
// `flow`, or older than 10 minutes is ignored without touching the session; a code issued for another
// verifier never yields a session.

const URL_ = "http://supabase.test";
const VAULT = "a1b2c3d4e5f60718";
const GITHUB = { providerUserId: "1001", email: "ana@example.test", verified: true } as const;

function world() {
  const gotrue = fakeGoTrue(URL_);
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
    redirectBase: "obsidian://nodra-auth",
    vault: VAULT,
    newClient,
    now: () => clock,
    onExpire: () => expired.push(clock),
    setTimer: (fn, ms) => {
      const t = { fn, at: clock + ms, cleared: false };
      timers.push(t);
      return t;
    },
    clearTimer: (h) => void ((h as { cleared: boolean }).cleared = true),
  });
  /** The callback Obsidian would hand over for the browser's redirect to `landing`. */
  const paramsOf = (landing: string) => Object.fromEntries(new URL(landing).searchParams);
  const advance = (ms: number) => {
    clock += ms;
    for (const t of timers) if (!t.cleared && t.at <= clock) {
      t.cleared = true;
      t.fn();
    }
  };
  return { gotrue, flow, storages, paramsOf, advance, expired, newClient, setClock: (ms: number) => void (clock += ms) };
}

describe("nativeOAuth", () => {
  it("start: the redirect names this vault and a fresh 128-bit flow; the callback for it signs the flow's client in", async () => {
    const w = world();
    const url = await w.flow.start({ provider: "github" });
    const redirect = new URL(new URL(url).searchParams.get("redirect_to")!);
    expect(`${redirect.protocol}//${redirect.host}`).toBe("obsidian://nodra-auth");
    expect(redirect.searchParams.get("vault")).toBe(VAULT);
    expect(redirect.searchParams.get("flow")).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(w.flow.pending()).toBe(true);

    const out = await w.flow.callback(w.paramsOf(await w.gotrue.authorize(url, GITHUB)));
    expect(out.kind).toBe("SIGNED_IN");
    if (out.kind !== "SIGNED_IN") return;
    expect(await out.auth.email()).toBe(GITHUB.email);
    expect(w.flow.pending()).toBe(false);
    // The verifier is gone once redeemed.
    expect([...w.storages[0]!.items.keys()].filter((k) => k.endsWith("-code-verifier"))).toEqual([]);
  });

  it("randomFlowId: 128 bits, base64url, never repeating", () => {
    const ids = new Set(Array.from({ length: 200 }, randomFlowId));
    expect(ids.size).toBe(200);
    for (const id of ids) expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it.each([
    ["no flow pending", "none"],
    ["another flow", "other-flow"],
    ["another vault", "other-vault"],
    ["a callback older than 10 minutes", "late"],
  ])("ignores a callback with %s: IGNORED, no token request, no session", async (_, kind) => {
    const w = world();
    const url = await w.flow.start({ provider: "github" });
    const params = w.paramsOf(await w.gotrue.authorize(url, GITHUB));
    if (kind === "none") await w.flow.cancel();
    if (kind === "late") w.setClock(OAUTH_FLOW_MS + 1);
    const forged = kind === "other-flow" ? { ...params, flow: randomFlowId() } : kind === "other-vault" ? { ...params, vault: "another-vault" } : params;
    const before = w.gotrue.requests.length;
    expect(await w.flow.callback(forged)).toEqual({ kind: "IGNORED" });
    expect(w.gotrue.requests.slice(before)).toEqual([]);
    expect(w.gotrue.users().length).toBe(1);
    // Still pending only when the flow itself was neither cancelled nor expired: the right callback then works.
    if (kind === "other-flow" || kind === "other-vault") expect((await w.flow.callback(params)).kind).toBe("SIGNED_IN");
    else expect(w.flow.pending()).toBe(false);
  });

  it("a code issued for another verifier (an attacker's own flow, forwarded with this flow's value) never yields a session", async () => {
    const w = world();
    const url = await w.flow.start({ provider: "github" });
    const flow = new URL(new URL(url).searchParams.get("redirect_to")!).searchParams.get("flow")!;
    const attacker = w.newClient();
    const theirs = await attacker.startOAuth({ provider: "github", redirectTo: "https://evil.example/cb" });
    const code = new URL(await w.gotrue.authorize(theirs.url, { providerUserId: "666", email: "mallory@example.test", verified: true })).searchParams.get("code")!;
    const out = await w.flow.callback({ vault: VAULT, flow, code });
    expect(out.kind).toBe("FAILED");
    expect(out.kind === "FAILED" && out.error.code).toBe("OAUTH_CALLBACK_INVALID");
    expect(w.flow.pending()).toBe(false);
  });

  it("the provider's error (the user cancelled): FAILED with OAUTH_REFUSED, the flow ends, its free text is not repeated", async () => {
    const w = world();
    const url = await w.flow.start({ provider: "github" });
    const out = await w.flow.callback(w.paramsOf(await w.gotrue.authorize(url, "deny")));
    expect(out.kind).toBe("FAILED");
    if (out.kind !== "FAILED") return;
    expect(out.error.code).toBe("OAUTH_REFUSED");
    expect(out.error.message).toContain("access_denied");
    expect(out.error.message).not.toContain("denied your application");
    expect(w.flow.pending()).toBe(false);
  });

  it("one pending flow: a new start ends the previous one, whose callback is then ignored", async () => {
    const w = world();
    const first = await w.flow.start({ provider: "github" });
    const firstParams = w.paramsOf(await w.gotrue.authorize(first, GITHUB));
    const second = await w.flow.start({ provider: "github", selectAccount: true });
    expect(new URL(second).searchParams.get("prompt")).toBe("select_account");
    expect(await w.flow.callback(firstParams)).toEqual({ kind: "IGNORED" });
    expect((await w.flow.callback(w.paramsOf(await w.gotrue.authorize(second, GITHUB)))).kind).toBe("SIGNED_IN");
  });

  it("a second delivery of the same callback is ignored (the flow ended with the first)", async () => {
    const w = world();
    const url = await w.flow.start({ provider: "github" });
    const params = w.paramsOf(await w.gotrue.authorize(url, GITHUB));
    const [a, b] = await Promise.all([w.flow.callback(params), w.flow.callback(params)]);
    expect([a.kind, b.kind].sort()).toEqual(["IGNORED", "SIGNED_IN"]);
  });

  it("the timeout ends the flow at 10 minutes and tells the host", async () => {
    const w = world();
    await w.flow.start({ provider: "github" });
    w.advance(OAUTH_FLOW_MS - 1);
    expect(w.flow.pending()).toBe(true);
    w.advance(1);
    expect(w.flow.pending()).toBe(false);
    expect(w.expired).toHaveLength(1);
  });
});
