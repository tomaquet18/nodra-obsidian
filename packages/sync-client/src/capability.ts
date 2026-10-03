// §11.3 on the client: obtaining a Write Capability Token, keeping it **in memory only**, and
// proving possession again before it expires.
//
// The private key never reaches this module. What it takes is a `prove` function — the client that
// owns the key decides whether it is the `["unwrapKey"]` Session handle of a plugin or trusted
// browser, the ACCOUNT handle of a browser session, or the `["decrypt"]` key of a Recovery Kit, and
// calls the matching helper in `@nodra/key-lifecycle`. That keeps this file about the protocol: one
// round trip, one refresh rule, one place where a refusal turns into a fresh proof.
//
// §11.3: "El cliente lo mantiene solo en memoria: nunca en cookies, localStorage ni IndexedDB." The
// token lives in a closure variable and nothing here writes it anywhere.
import * as P from "@nodra/protocol";
import { writeCapabilityLabel } from "@nodra/key-lifecycle";
import type { DomainContext } from "@nodra/crypto";

export class CapabilityError extends Error {
  constructor(
    readonly code: string,
    /** REPLICA_MISMATCH: the `replica_id` the session already fixed, which the client adopts (§6). */
    readonly replicaId?: string,
  ) {
    super(code);
    this.name = "CapabilityError";
  }
}

const hex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

function fromHex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** §6: an id is 16 bytes in every context (§23.2), and a uuid string over the wire. */
const idBytes = (uuid: string) => fromHex(uuid.replaceAll("-", ""));

/** The half of §11.3 step 4/5 that needs the private key, which stays with its owner. */
export type ProveCapability = (input: {
  /** `Context("nodra/write-capability", …)`, the OAEP label the nonce was sealed under. */
  readonly label: DomainContext;
  readonly sealedNonce: Uint8Array;
  readonly challenge: Uint8Array;
}) => Promise<Uint8Array>;

export interface CapabilitySessionOptions {
  readonly baseUrl: string;
  readonly fetch: typeof fetch;
  /** The session headers (the Supabase bearer). The capability header is added by this module. */
  readonly sessionHeaders: () => Record<string, string> | Promise<Record<string, string>>;
  readonly accountId: string;
  /** The `session_id` claim of the Supabase JWT: what the label and the token both bind (§11.3). */
  readonly serverSessionId: string;
  readonly recipientId: string;
  readonly prove: ProveCapability;
  /**
   * §6: the `replica_id` an ACCOUNT client proposes. A trusted client sends none — its replica *is*
   * its `recipient_id`, and the Worker will not read a client-chosen value.
   */
  readonly replicaId?: string;
  /** Re-prove this long before `expires_at` (§11.3 "Renovación"). */
  readonly refreshMarginSeconds?: number;
  readonly now?: () => number;
}

export interface CapabilitySession {
  /** The headers of a request: the session's, plus `Nodra-Write-Capability` once one is held. */
  headers(): Promise<Record<string, string>>;
  /**
   * A write was refused for an authentication reason. Returns true when a fresh proof succeeded and
   * the request is worth sending again; false when the refusal is not ours to fix.
   */
  onAuthRefusal(code: string): Promise<boolean>;
  /** §11.3: logging out drops the token at once. */
  forget(): void;
  /** The `replica_id` in force (§6): the Worker's answer, which may differ from the one proposed. */
  replicaId(): string | undefined;
}

/** The refusals a fresh proof can plausibly fix; anything else is the caller's problem. */
const REFRESHABLE: ReadonlySet<string> = new Set(["WRITE_CAPABILITY_REQUIRED", "SCOPE_REQUIRED"]);

const DEFAULT_MARGIN = 60;

export function capabilitySession(o: CapabilitySessionOptions): CapabilitySession {
  const now = o.now ?? (() => Date.now());
  const margin = (o.refreshMarginSeconds ?? DEFAULT_MARGIN) * 1000;
  let held: { readonly value: string; readonly expiresAt: number } | null = null;
  let replica = o.replicaId;
  let inflight: Promise<void> | null = null;

  async function post<S extends import("zod").ZodType>(path: string, body: unknown, schema: S): Promise<import("zod").output<S>> {
    const res = await o.fetch(`${o.baseUrl}${path}`, {
      method: "POST",
      headers: { ...(await o.sessionHeaders()), "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const value: unknown = await res.json().catch(() => null);
    if (!res.ok) {
      const error = P.ErrorBody.safeParse(value);
      throw new CapabilityError(error.success ? error.data.error : "BAD_RESPONSE");
    }
    const parsed = schema.safeParse(value);
    if (!parsed.success) throw new CapabilityError("BAD_RESPONSE");
    return parsed.data;
  }

  /** §11.3 steps 1–6, once. Concurrent callers share the one in-flight proof. */
  function acquire(): Promise<void> {
    inflight ??= (async () => {
      try {
        const challenge = await post(
          P.capabilityRoutes.challenge,
          { recipientId: o.recipientId, ...(replica === undefined ? {} : { replicaId: replica }) } satisfies P.ChallengeRequest,
          P.ChallengeResponse,
        );
        if (!challenge.ok) throw new CapabilityError(challenge.code);
        const challengeBytes = fromHex(challenge.challenge);
        const proof = await o.prove({
          label: writeCapabilityLabel({
            accountId: idBytes(o.accountId),
            recipientId: idBytes(o.recipientId),
            rootGeneration: challenge.rootGeneration,
            serverSessionId: idBytes(o.serverSessionId),
            challenge: challengeBytes,
          }),
          sealedNonce: fromHex(challenge.sealedNonce),
          challenge: challengeBytes,
        });
        const token = await post(P.capabilityRoutes.token, { challenge: challenge.challenge, proof: hex(proof) } satisfies P.ProofRequest, P.CapabilityResponse);
        if (!token.ok) {
          // §6: the session already fixed a different replica. Adopt it; the next attempt uses it.
          if (token.code === "REPLICA_MISMATCH" && token.replicaId !== undefined) replica = token.replicaId;
          throw new CapabilityError(token.code, token.replicaId);
        }
        replica = token.replicaId ?? replica;
        held = { value: P.capabilityHeaderValue(token.tokenId, token.secret), expiresAt: now() + token.expiresInSeconds * 1000 };
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  }

  return {
    async headers() {
      if (held === null || held.expiresAt - now() <= margin) {
        held = null;
        await acquire();
      }
      return { ...(await o.sessionHeaders()), ...(held === null ? {} : { [P.CAPABILITY_HEADER]: (held as { value: string }).value }) };
    },
    async onAuthRefusal(code) {
      // §11.3: a revoked recipient must re-enrol (§18.3); proving again would only fail the same way.
      if (!REFRESHABLE.has(code)) return false;
      held = null;
      try {
        await acquire();
        return true;
      } catch {
        return false;
      }
    },
    forget() {
      held = null;
    },
    replicaId() {
      return replica;
    },
  };
}
