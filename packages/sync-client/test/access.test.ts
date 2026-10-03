import { describe, expect, it } from "vitest";
import { AccessSettingsError, accessServiceToken, withAccessServiceToken } from "../src/access.js";
import { httpDirectory } from "../src/directory.js";
import { devSignIn } from "../src/session.js";

// A staging API behind Cloudflare Access (NOTES question 393): every request to the Nodra API carries
// the service token's two headers, and nothing else does. The wrapper is the one fetch every API call of
// a client goes through, so the scope check here is the only thing keeping the secret off other origins.

const BASE = "https://api-staging.nodranotes.test";
const ID = "0123456789abcdef.access";
const SECRET = "s3cr3t-0f-the-service-token-f00d";
const TOKEN = { clientId: ID, clientSecret: SECRET };

/** A fetch that records each request's URL and headers, and answers `status`. */
function recording(status = 200) {
  const seen: { url: string; headers: Headers }[] = [];
  const fetch: typeof globalThis.fetch = async (input, init) => {
    // Not `new Request(input, init)`: it refuses a URL with user info, which one case sends.
    seen.push({ url: String(input instanceof Request ? input.url : input), headers: new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined)) });
    return Response.json({}, { status });
  };
  return { seen, fetch };
}

describe("withAccessServiceToken", () => {
  it.each([
    ["the base URL itself", BASE],
    ["an API route", `${BASE}/v1/security/root-state`],
    ["a route with a query", `${BASE}/v1/vaults/x/events?after=1`],
    ["a blob", `${BASE}/v1/vaults/x/blobs/y`],
  ])("adds both headers to %s, and keeps the caller's own", async (_, url) => {
    const { seen, fetch } = recording();
    await withAccessServiceToken({ baseUrl: `${BASE}/`, token: TOKEN, fetch })(url, { method: "POST", headers: { authorization: "Bearer t" }, body: "{}" });
    expect(seen[0]!.headers.get("cf-access-client-id")).toBe(ID);
    expect(seen[0]!.headers.get("cf-access-client-secret")).toBe(SECRET);
    expect(seen[0]!.headers.get("authorization")).toBe("Bearer t");
  });

  it("adds them whatever form the request takes (a URL, a Request with its own headers)", async () => {
    const { seen, fetch } = recording();
    const api = withAccessServiceToken({ baseUrl: BASE, token: TOKEN, fetch });
    await api(new URL(`${BASE}/v1/a`));
    await api(new Request(`${BASE}/v1/b`, { headers: { authorization: "Bearer r" } }));
    for (const s of seen) expect(s.headers.get("cf-access-client-secret")).toBe(SECRET);
    expect(seen[1]!.headers.get("authorization")).toBe("Bearer r");
  });

  it("an API base URL with a path covers only that path", async () => {
    const { seen, fetch } = recording();
    const api = withAccessServiceToken({ baseUrl: `${BASE}/api`, token: TOKEN, fetch });
    await api(`${BASE}/api/v1/x`);
    await api(`${BASE}/apiary/v1/x`);
    await api(`${BASE}/v1/x`);
    expect(seen.map((s) => s.headers.get("cf-access-client-secret"))).toEqual([SECRET, null, null]);
  });

  it.each([
    ["Supabase Auth", "https://abcdefgh.supabase.co/auth/v1/token?grant_type=password"],
    ["another origin", "https://example.com/v1/security/root-state"],
    ["a look-alike host", "https://api-staging.nodranotes.test.evil.example/v1/x"],
    ["the same host over http", "http://api-staging.nodranotes.test/v1/x"],
    ["the same host on another port", "https://api-staging.nodranotes.test:8443/v1/x"],
    ["a user-info trick", "https://api-staging.nodranotes.test@evil.example/v1/x"],
  ])("never sends them to %s", async (_, url) => {
    const { seen, fetch } = recording();
    await withAccessServiceToken({ baseUrl: BASE, token: TOKEN, fetch })(url, { headers: { authorization: "Bearer t" } });
    expect(seen[0]!.headers.get("cf-access-client-id")).toBeNull();
    expect(seen[0]!.headers.get("cf-access-client-secret")).toBeNull();
  });

  it("not configured: the fetch is passed the very same request, untouched", async () => {
    const calls: unknown[][] = [];
    const fetch: typeof globalThis.fetch = async (...args) => {
      calls.push(args);
      return new Response(null);
    };
    const init = { method: "GET", headers: { authorization: "Bearer t" } };
    await withAccessServiceToken({ baseUrl: BASE, token: null, fetch })(`${BASE}/v1/x`, init);
    expect(calls).toEqual([[`${BASE}/v1/x`, init]]);
    expect(calls[0]![1]).toBe(init);
  });

  it("does not write the secret into the caller's own headers object", async () => {
    const { fetch } = recording();
    const headers = { authorization: "Bearer t" };
    await withAccessServiceToken({ baseUrl: BASE, token: TOKEN, fetch })(`${BASE}/v1/x`, { headers });
    expect(headers).toEqual({ authorization: "Bearer t" });
  });

  it("the secret appears in no error of a failing request (unreachable, refused)", async () => {
    const unreachable: typeof fetch = async () => {
      throw new TypeError("fetch failed");
    };
    const errors: string[] = [];
    await devSignIn({ serverUrl: BASE, fetch: withAccessServiceToken({ baseUrl: BASE, token: TOKEN, fetch: unreachable }), mode: "login", email: "a@b.c", password: "x" }).catch((e: unknown) =>
      errors.push(String(e), JSON.stringify(e), (e as Error).stack ?? ""),
    );
    const refused = recording(503);
    await httpDirectory({ baseUrl: BASE, fetch: withAccessServiceToken({ baseUrl: BASE, token: TOKEN, fetch: refused.fetch }), headers: () => ({}) })
      .rootState()
      .catch((e: unknown) => errors.push(String(e), JSON.stringify(e), (e as Error).stack ?? ""));
    expect(errors).toHaveLength(6);
    expect(refused.seen[0]!.headers.get("cf-access-client-secret")).toBe(SECRET); // it was sent
    for (const e of errors) expect(e).not.toContain(SECRET);
  });
});

describe("accessServiceToken (the two settings)", () => {
  it("neither set (or only spaces): no token", () => {
    expect(accessServiceToken("", "")).toBeNull();
    expect(accessServiceToken("  ", "\t")).toBeNull();
  });

  it("both set: trimmed", () => {
    expect(accessServiceToken(`  ${ID} `, ` ${SECRET}\t`)).toEqual(TOKEN);
  });

  it.each([
    ["only the client id", ID, ""],
    ["only the client secret", "", SECRET],
  ])("%s is refused", (_, id, secret) => {
    expect(() => accessServiceToken(id, secret)).toThrow(AccessSettingsError);
  });

  it.each([
    ["a CR in the secret", ID, `${SECRET}\rx-injected: 1`],
    ["an LF in the secret", ID, `${SECRET}\nx-injected: 1`],
    ["a CRLF in the id", `${ID}\r\nx-injected: 1`, SECRET],
    ["a NUL", ID, `${SECRET}\u0000`],
    ["a character outside ASCII", ID, `${SECRET}é`],
  ])("%s is refused, and the message does not repeat the value", (_, id, secret) => {
    let error: unknown;
    try {
      accessServiceToken(id, secret);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(AccessSettingsError);
    expect(String(error)).not.toContain(SECRET);
    expect(String(error)).not.toContain(ID);
  });
});
