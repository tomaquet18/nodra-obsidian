// A staging API behind Cloudflare Access (NOTES question 393). Access answers every request that lacks
// its service token before the Worker sees it, so a client pointed at such a server sends the token's
// two headers on every request to the Nodra API, and on nothing else: never to Supabase Auth or any other
// origin. `withAccessServiceToken` wraps the one fetch a client hands to every API call (the plugin's
// `apiFetch`), so the scope is decided here once. Not configured: the fetch is unchanged.
//
// The secret is a credential. No message here repeats either value, and the caller's own headers
// object is never written to (a logged request would otherwise carry it).

export interface AccessServiceToken {
  readonly clientId: string;
  readonly clientSecret: string;
}

export class AccessSettingsError extends Error {
  constructor(message: string) {
    super(`Cloudflare Access settings: ${message}`);
    this.name = "AccessSettingsError";
  }
}

/** Printable ASCII only: a CR or LF would inject a header, and `Headers` repeats a value it refuses in its error. */
const HEADER_VALUE = /^[\x20-\x7e]*$/;

/** The token from the two settings: both empty is none; one alone, or a character a header cannot carry, throws. */
export function accessServiceToken(clientId: string, clientSecret: string): AccessServiceToken | null {
  for (const [name, value] of [["client id", clientId], ["client secret", clientSecret]] as const) {
    if (!HEADER_VALUE.test(value.trim())) throw new AccessSettingsError(`the ${name} contains a character a request header cannot carry (such as a line break)`);
  }
  const id = clientId.trim();
  const secret = clientSecret.trim();
  if (id === "" && secret === "") return null;
  if (id === "" || secret === "") throw new AccessSettingsError("set both the client id and the client secret, or neither");
  return { clientId: id, clientSecret: secret };
}

/** True when `url` is the API base URL or below it: same origin, and inside its path. */
function underBase(url: string, base: URL): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.origin !== base.origin) return false;
  const prefix = base.pathname.replace(/\/+$/, "");
  return prefix === "" || u.pathname === prefix || u.pathname.startsWith(`${prefix}/`);
}

/** `fetch`, plus the service token's two headers on requests to `baseUrl`; `fetch` itself when there is no token. */
export function withAccessServiceToken(o: { readonly baseUrl: string; readonly token: AccessServiceToken | null; readonly fetch: typeof fetch }): typeof fetch {
  const { token } = o;
  if (token === null) return o.fetch;
  let base: URL | null;
  try {
    base = new URL(o.baseUrl);
  } catch {
    base = null; // not a URL: no request is under it
  }
  return (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    if (base === null || !underBase(url, base)) return o.fetch(input, init);
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    headers.set("cf-access-client-id", token.clientId);
    headers.set("cf-access-client-secret", token.clientSecret);
    // A followed redirect would carry the token to wherever it points: fetch strips only Authorization-like
    // headers across origins. The API never redirects, so a request that carries the token follows none.
    return o.fetch(input, { ...init, headers, redirect: "error" });
  };
}
