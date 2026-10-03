// §11.3, the proof of possession: the two contexts and the four operations that use them.
//
// The protocol is four lines long and every one of them is a place to get it wrong, so all four
// live here and nowhere else:
//
//   1. the Worker draws `nonce` (32 bytes) and `challenge` (16 bytes) and seals the nonce to the
//      recipient's public key under {@link writeCapabilityLabel} (step 3);
//   2. the client opens it — `unwrapKey` straight to an HMAC key with a `["unwrapKey"]` private
//      key (§25.1 Session handle), `decrypt` + import + zeroize with a `["decrypt"]` one (the
//      Recovery Kit) — and signs {@link writeCapabilityProofContext} (steps 4 and 5);
//   3. the Worker recomputes the same MAC from the nonce it drew and compares (step 6).
//
// The label binds account, recipient, root generation, Supabase session and challenge, so a sealed
// nonce cannot be replayed at another recipient, under another root, or in another session — which
// is exactly the property the broken-variant test attacks by moving one field.
import {
  CAPABILITY_NONCE_BYTES,
  domainContext,
  hmacSha256,
  importMacKey,
  openCapabilityNonce,
  sealCapabilityNonce,
  timingSafeEqual,
  unwrapCapabilityMacKey,
  zeroize,
} from "@nodra/crypto";
import type {
  DomainContext,
  EnvelopeOpeningKey,
  EnvelopePublicKey,
  EnvelopeUnwrapKey,
} from "@nodra/crypto";
import type { Scope } from "./operations.js";

export { CAPABILITY_NONCE_BYTES };

/** §11.3 step 2: `challenge` is 16 bytes, one-use, with a 60 s TTL. */
export const CAPABILITY_CHALLENGE_BYTES = 16;

/** §11.3: a Write Capability Token lives 30 minutes. */
export const CAPABILITY_TOKEN_SECONDS = 30 * 60;

/** §11.3 step 2: the challenge's own TTL. */
export const CAPABILITY_CHALLENGE_SECONDS = 60;

/**
 * `Context("nodra/write-capability", account_id, recipient_id, root_generation, server_session_id,
 * challenge)` (§11.3 step 3): the OAEP label the nonce is sealed under.
 */
export function writeCapabilityLabel(input: {
  readonly accountId: Uint8Array;
  readonly recipientId: Uint8Array;
  readonly rootGeneration: number;
  readonly serverSessionId: Uint8Array;
  readonly challenge: Uint8Array;
}): DomainContext {
  return domainContext(
    "nodra/write-capability",
    input.accountId,
    input.recipientId,
    input.rootGeneration,
    input.serverSessionId,
    input.challenge,
  );
}

/** `Context("nodra/write-capability-proof", challenge)` (§11.3 step 5): what the HMAC covers. */
export function writeCapabilityProofContext(challenge: Uint8Array): DomainContext {
  return domainContext("nodra/write-capability-proof", challenge);
}

export interface CapabilityChallenge {
  readonly challenge: Uint8Array;
  /** The sealed nonce the Worker sends; only the recipient's private key opens it. */
  readonly sealedNonce: Uint8Array;
  /** `HMAC(nonce, Context("nodra/write-capability-proof", challenge))`: what step 6 compares against. */
  readonly expectedProof: Uint8Array;
}

/**
 * §11.3 steps 2–3, server side. `nonce` and `challenge` are the caller's CSPRNG bytes so this stays
 * deterministic and testable; the Worker draws them with `randomBytes`.
 *
 * The nonce is not returned: once the expected proof exists the Worker has no further use for it,
 * and what it stores is a hash of that proof, never the nonce itself.
 */
export async function issueCapabilityChallenge(input: {
  readonly publicKey: EnvelopePublicKey;
  readonly accountId: Uint8Array;
  readonly recipientId: Uint8Array;
  readonly rootGeneration: number;
  readonly serverSessionId: Uint8Array;
  readonly nonce: Uint8Array;
  readonly challenge: Uint8Array;
}): Promise<CapabilityChallenge> {
  const label = writeCapabilityLabel(input);
  const sealedNonce = await sealCapabilityNonce(input.publicKey, label, input.nonce);
  return { challenge: input.challenge, sealedNonce, expectedProof: await expectedCapabilityProof(input.nonce, input.challenge) };
}

/** §11.3 step 6: the MAC the Worker computes from the nonce it drew. */
export async function expectedCapabilityProof(nonce: Uint8Array, challenge: Uint8Array): Promise<Uint8Array> {
  const key = await importMacKey(nonce);
  return hmacSha256(key, writeCapabilityProofContext(challenge));
}

/** §11.3 step 6, the comparison itself. Both values have a length the protocol fixes (§44.3). */
export const capabilityProofMatches = (a: Uint8Array, b: Uint8Array): boolean => timingSafeEqual(a, b);

/**
 * §11.3 step 4, first bullet + step 5: the normal client path. The private key is the `["unwrapKey"]`
 * Session handle of §25.1, so the nonce never becomes bytes in the client.
 */
export async function proveCapabilityWithUnwrapKey(input: {
  readonly privateKey: EnvelopeUnwrapKey;
  readonly label: DomainContext;
  readonly sealedNonce: Uint8Array;
  readonly challenge: Uint8Array;
}): Promise<Uint8Array> {
  const key = await unwrapCapabilityMacKey(input.privateKey, input.label, input.sealedNonce);
  return hmacSha256(key, writeCapabilityProofContext(input.challenge));
}

/**
 * §11.3 step 4, second bullet + step 5: the Recovery Kit path, whose key is `["decrypt"]`. The
 * nonce exists as bytes between `decrypt` and `importKey`, and is zeroized the moment it does not.
 */
export async function proveCapabilityWithDecryptKey(input: {
  readonly privateKey: EnvelopeOpeningKey;
  readonly label: DomainContext;
  readonly sealedNonce: Uint8Array;
  readonly challenge: Uint8Array;
}): Promise<Uint8Array> {
  const nonce = await openCapabilityNonce(input.privateKey, input.label, input.sealedNonce);
  try {
    return await expectedCapabilityProof(nonce, input.challenge);
  } finally {
    zeroize(nonce);
  }
}

/** The four recipient kinds §11.3's scope table is keyed by (§30.1). */
export type CapabilityRecipientType = "PLUGIN_INSTALLATION" | "TRUSTED_BROWSER" | "ACCOUNT" | "RECOVERY";

/**
 * §11.3 "Scopes", as data. The capability is not a boolean: the recipient that proved possession
 * fixes the set, and `RECOVERY_CONTROL` deliberately does **not** include `VAULT_WRITE` — the one
 * line that makes a stolen Recovery Kit unable to modify or delete a vault (§39.1).
 */
export const CAPABILITY_SCOPES: Readonly<Record<CapabilityRecipientType, readonly Scope[]>> = {
  PLUGIN_INSTALLATION: ["VAULT_WRITE", "TRUSTED_SECURITY"],
  TRUSTED_BROWSER: ["VAULT_WRITE", "TRUSTED_SECURITY"],
  ACCOUNT: ["VAULT_WRITE", "ACCOUNT_SECURITY"],
  RECOVERY: ["RECOVERY_CONTROL"],
};

/**
 * §11.3 and §6: a trusted client's `replica_id` is its own `recipient_id`; an ACCOUNT token carries
 * the session UUIDv7 the client asks for; a RECOVERY token has none, because it cannot write.
 */
export type ReplicaBinding = "RECIPIENT" | "SESSION" | "NONE";

export const capabilityReplicaBinding = (type: CapabilityRecipientType): ReplicaBinding =>
  type === "RECOVERY" ? "NONE" : type === "ACCOUNT" ? "SESSION" : "RECIPIENT";
