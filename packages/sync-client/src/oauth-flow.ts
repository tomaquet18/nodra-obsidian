// ADR-024 for a native host (the Obsidian plugin): a sign-in as a public client of Supabase Auth's
// OAuth 2.1 server, authorization code + PKCE (RFC 7636, S256). The host opens `start()`'s URL in the
// system browser; the user signs in on Nodra Web (with its CAPTCHA) and approves on its consent page;
// GoTrue redirects to the client's registered redirect URI (`obsidian://nodra-auth`, matched exactly, so
// it carries no parameters of ours) with `code` and `state`. Any other app may have registered that
// scheme too. What keeps the flow bound to this instance:
//
// - the PKCE verifier lives only in this module's memory, never in a storage;
// - a random `flow` value (128 bits) is the `state`; a callback whose `state` is not the pending flow's,
//   that names another vault, arrives with no flow pending, or later than OAUTH_FLOW_MS, is ignored and
//   changes nothing (a callback Obsidian hands to another vault costs a retry, never a wrong sign-in);
// - at most one flow is pending: a new start, a cancel, a callback or the timeout ends it, and its
//   verifier with it.
//
// A callback that completes leaves the session in a new client of the host (`newClient`); the host
// adopts it into its own login (`SupabaseAuth.adoptSession`), comparing the user for a re-authentication.
import { SessionError } from "./session.js";
import type { SupabaseAuth } from "./supabase-auth.js";

/** A pending flow lives 10 minutes at most (GoTrue's authorization request does too). */
export const OAUTH_FLOW_MS = 10 * 60 * 1000;

export type OAuthCallbackOutcome =
  /** Not this instance's pending flow (none, another `state` or vault, or expired): nothing changed. */
  | { readonly kind: "IGNORED" }
  /** The code became `auth`'s session (a new client of the host's): the host adopts it. */
  | { readonly kind: "SIGNED_IN"; readonly auth: SupabaseAuth }
  /** The user denied (OAUTH_REFUSED), the code did not redeem (OAUTH_CALLBACK_INVALID), or no answer (UNREACHABLE). */
  | { readonly kind: "FAILED"; readonly error: SessionError };

export interface NativeOAuth {
  /** Starts a flow (ending the pending one): the URL the host opens in the system browser. */
  start(): Promise<string>;
  /** Ends the pending flow, if any; its verifier is gone. */
  cancel(): Promise<void>;
  /** Whether a flow is pending. */
  pending(): boolean;
  /** The callback's query parameters (`registerObsidianProtocolHandler` hands them as a record). */
  callback(params: Readonly<Record<string, string | undefined>>): Promise<OAuthCallbackOutcome>;
}

const base64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/=+$/, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

/** 128 random bits, base64url. */
export function randomFlowId(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(16)));
}

export function nativeOAuth(o: {
  /** The Supabase project URL; the server is at `<url>/auth/v1/oauth`. */
  readonly supabaseUrl: string;
  /** The project's public key, sent as `apikey` to the token endpoint. */
  readonly anonKey: string;
  /** This app's OAuth client id (a public value, fixed at build). */
  readonly clientId: string;
  /** The client's registered redirect URI, exactly (`obsidian://nodra-auth`). */
  readonly redirectUri: string;
  /** This instance's vault id: a callback naming another vault is not for this instance. */
  readonly vault: string;
  /** A new auth client over memory storage only, to hold the session the code redeems for. */
  readonly newClient: () => SupabaseAuth;
  readonly fetch: typeof fetch;
  /** The flow ended by itself after OAUTH_FLOW_MS (the host stops waiting). */
  readonly onExpire?: () => void;
  readonly now?: () => number;
  readonly randomFlow?: () => string;
  readonly setTimer?: (fn: () => void, ms: number) => unknown;
  readonly clearTimer?: (handle: unknown) => void;
}): NativeOAuth {
  const now = o.now ?? Date.now;
  const setTimer = o.setTimer ?? ((fn: () => void, ms: number) => setTimeout(fn, ms));
  const clearTimer = o.clearTimer ?? ((h: unknown) => clearTimeout(h as ReturnType<typeof setTimeout>));
  const server = `${o.supabaseUrl.replace(/\/+$/, "")}/auth/v1/oauth`;
  let pending: { readonly flow: string; readonly verifier: string; readonly startedAt: number; readonly timer: unknown } | null = null;

  /** Takes the pending flow out (synchronously, so a second callback finds none) and stops its timer. */
  const take = () => {
    const p = pending;
    pending = null;
    if (p !== null) clearTimer(p.timer);
    return p;
  };

  /** The token endpoint: `code` with this flow's verifier for an access and a refresh token. */
  const redeem = async (code: string, verifier: string) => {
    const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: o.redirectUri, client_id: o.clientId, code_verifier: verifier });
    let r: Response;
    try {
      r = await o.fetch(`${server}/token`, { method: "POST", headers: { apikey: o.anonKey, "content-type": "application/x-www-form-urlencoded" }, body: body.toString() });
    } catch {
      throw new SessionError("UNREACHABLE", "Supabase Auth did not answer the sign-in");
    }
    if (r.status >= 500) throw new SessionError("UNREACHABLE", `Supabase Auth did not complete the sign-in (HTTP ${r.status})`);
    const answer = (await r.json().catch(() => null)) as { access_token?: unknown; refresh_token?: unknown; error?: unknown } | null;
    if (!r.ok || typeof answer?.access_token !== "string" || typeof answer.refresh_token !== "string") {
      // GoTrue's OAuth error code at most (`invalid_grant`), never the code itself.
      const why = typeof answer?.error === "string" ? ` (${answer.error.replace(/[^a-z_]/gi, "").slice(0, 40)})` : "";
      throw new SessionError("OAUTH_CALLBACK_INVALID", `the sign-in did not complete${why}`);
    }
    return { accessToken: answer.access_token, refreshToken: answer.refresh_token };
  };

  return {
    async start() {
      take();
      const flow = (o.randomFlow ?? randomFlowId)();
      const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
      const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
      const query = new URLSearchParams({ response_type: "code", client_id: o.clientId, redirect_uri: o.redirectUri, code_challenge: challenge, code_challenge_method: "S256", state: flow });
      const timer = setTimer(() => {
        if (pending?.flow !== flow) return;
        take();
        o.onExpire?.();
      }, OAUTH_FLOW_MS);
      pending = { flow, verifier, startedAt: now(), timer };
      return `${server}/authorize?${query}`;
    },
    async cancel() {
      take();
    },
    pending: () => pending !== null,
    async callback(params) {
      const p = pending;
      // The `state` is the binding; a `vault` that names another vault is ignored too (Obsidian may route
      // by it without passing it on, so its absence is not a reason to ignore).
      if (p === null || params.state !== p.flow || (params.vault !== undefined && params.vault !== o.vault)) return { kind: "IGNORED" };
      take();
      if (now() - p.startedAt > OAUTH_FLOW_MS) return { kind: "IGNORED" };
      if (params.error !== undefined) {
        // GoTrue's error code only (`access_denied` when the user pressed Deny); its free text stays out.
        return { kind: "FAILED", error: new SessionError("OAUTH_REFUSED", `the sign-in was refused (${params.error.replace(/[^a-z_]/gi, "").slice(0, 40)})`) };
      }
      const code = params.code;
      let auth: SupabaseAuth | null = null;
      try {
        if (code === undefined || code === "") throw new SessionError("OAUTH_CALLBACK_INVALID", "the sign-in callback carries no code");
        const tokens = await redeem(code, p.verifier);
        auth = o.newClient();
        await auth.useTokens(tokens);
        return { kind: "SIGNED_IN", auth };
      } catch (e) {
        await auth?.dispose();
        if (e instanceof SessionError) return { kind: "FAILED", error: e };
        throw e;
      }
    },
  };
}
