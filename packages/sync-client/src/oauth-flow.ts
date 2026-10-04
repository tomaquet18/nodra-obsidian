// §3.7 (ADR-023) for a native host (the Obsidian plugin): an OAuth sign-in whose callback comes back
// through a custom scheme (`obsidian://nodra-auth?vault=<id>&flow=<random>`), which any other app may
// also have registered. What keeps it bound to this instance:
//
// - the PKCE verifier lives only in the memory of a throwaway auth client made for this one flow (the
//   host's `newClient`), never in a persistent storage;
// - a random `flow` value (128 bits) names the flow in the redirect; a callback whose `flow` is not the
//   pending one's, that arrives with no flow pending, or later than OAUTH_FLOW_MS, is ignored and
//   changes nothing (a callback Obsidian hands to another vault costs a retry, never a wrong sign-in);
// - at most one flow is pending: a new start, a cancel, a callback or the timeout ends it, and the
//   throwaway client (with its verifier) goes with it.
//
// A callback that completes leaves the session in the flow's client; the host adopts it into its own
// login (`SupabaseAuth.adoptSession`), comparing the user for a re-authentication.
import { SessionError } from "./session.js";
import type { OAuthProvider, SupabaseAuth } from "./supabase-auth.js";

/** §3.7: a pending flow lives 10 minutes at most. */
export const OAUTH_FLOW_MS = 10 * 60 * 1000;

export type OAuthCallbackOutcome =
  /** Not this instance's pending flow (none, another `flow` or vault, or expired): nothing changed. */
  | { readonly kind: "IGNORED" }
  /** The code became `auth`'s session (the flow's own client): the host adopts it. */
  | { readonly kind: "SIGNED_IN"; readonly auth: SupabaseAuth }
  /** The provider refused (OAUTH_REFUSED: the user cancelled, or an error) or the code did not redeem. */
  | { readonly kind: "FAILED"; readonly error: SessionError };

export interface NativeOAuth {
  /** Starts a flow (ending the pending one): the URL the host opens in the system browser. */
  start(o: { readonly provider: OAuthProvider; readonly selectAccount?: boolean }): Promise<string>;
  /** Ends the pending flow, if any; its verifier is gone. */
  cancel(): Promise<void>;
  /** Whether a flow is pending. */
  pending(): boolean;
  /** The callback's query parameters (`registerObsidianProtocolHandler` hands them as a record). */
  callback(params: Readonly<Record<string, string | undefined>>): Promise<OAuthCallbackOutcome>;
}

/** 128 random bits, base64url (no `.` or `/`, so Supabase's `*` glob matches it in a Redirect URL). */
export function randomFlowId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes))
    .replace(/=+$/, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

export function nativeOAuth(o: {
  /** The callback's scheme and path, e.g. `obsidian://nodra-auth`. */
  readonly redirectBase: string;
  /** This instance's vault id: the `vault` parameter Obsidian routes the callback by. */
  readonly vault: string;
  /** A new auth client over memory storage only, for one flow. */
  readonly newClient: () => SupabaseAuth;
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
  let pending: { readonly flow: string; readonly startedAt: number; readonly auth: SupabaseAuth; readonly flowId: string | null; readonly timer: unknown } | null = null;

  /** Takes the pending flow out (synchronously, so a second callback finds none) and stops its timer. */
  const take = () => {
    const p = pending;
    pending = null;
    if (p !== null) clearTimer(p.timer);
    return p;
  };
  const end = async () => {
    const p = take();
    if (p !== null) await p.auth.dispose();
  };

  return {
    async start(s) {
      await end();
      const flow = (o.randomFlow ?? randomFlowId)();
      const auth = o.newClient();
      const redirectTo = `${o.redirectBase}?vault=${encodeURIComponent(o.vault)}&flow=${encodeURIComponent(flow)}`;
      try {
        const { url, flowId } = await auth.startOAuth({ provider: s.provider, redirectTo, ...(s.selectAccount === undefined ? {} : { selectAccount: s.selectAccount }) });
        const timer = setTimer(() => {
          if (pending?.flow !== flow) return;
          void end();
          o.onExpire?.();
        }, OAUTH_FLOW_MS);
        pending = { flow, startedAt: now(), auth, flowId, timer };
        return url;
      } catch (e) {
        await auth.dispose();
        throw e;
      }
    },
    cancel: end,
    pending: () => pending !== null,
    async callback(params) {
      const p = pending;
      // The `flow` is the binding; a `vault` that names another vault is ignored too (Obsidian may route
      // by it without passing it on, so its absence is not a reason to ignore).
      if (p === null || params.flow !== p.flow || (params.vault !== undefined && params.vault !== o.vault)) return { kind: "IGNORED" };
      if (now() - p.startedAt > OAUTH_FLOW_MS) {
        await end();
        return { kind: "IGNORED" };
      }
      take();
      if (params.error !== undefined) {
        await p.auth.dispose();
        // The provider's error code only (`access_denied` when the user cancelled); its free text stays out.
        return { kind: "FAILED", error: new SessionError("OAUTH_REFUSED", `the sign-in was refused (${params.error.replace(/[^a-z_]/gi, "").slice(0, 40)})`) };
      }
      const code = params.code;
      try {
        if (code === undefined || code === "") throw new SessionError("OAUTH_CALLBACK_INVALID", "the sign-in callback carries no code");
        await p.auth.exchangeCode(code, p.flowId);
        return { kind: "SIGNED_IN", auth: p.auth };
      } catch (e) {
        await p.auth.dispose();
        if (e instanceof SessionError) return { kind: "FAILED", error: e };
        throw e;
      }
    },
  };
}
