// The client half of §11.3, against a scripted Worker: one round trip, the refresh rule, and what
// the backend does when a write comes back refused.
//
// The proofs are real HMAC over the real contexts — `prove` here is the same computation a
// `["unwrapKey"]` handle performs, with the nonce supplied directly, so the round trip is exercised
// without paying for RSA in this package (the RSA path is covered end to end in workers/api).
import { expectedCapabilityProof, writeCapabilityProofContext } from "@nodra/key-lifecycle";
import { hmacSha256, importMacKey, randomBytes } from "@nodra/crypto";
import * as P from "@nodra/protocol";
import { describe, expect, it } from "vitest";
import { CapabilityError, capabilitySession } from "../src/capability.js";
import { devManifestCodec } from "../src/dev-crypto.js";
import { httpSyncBackend } from "../src/http-backend.js";

const ACCOUNT = "00000000-0000-7000-8000-000000000001";
const SESSION = "00000000-0000-7000-8000-000000000002";
const RECIPIENT = "00000000-0000-7000-8000-000000000003";
const VAULT = "00000000-0000-7000-8000-000000000004";

const hex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

interface Script {
  /** Every request the client made, in order. */
  readonly seen: Array<{ path: string; capability: string | null }>;
  readonly fetch: typeof fetch;
  /** The tokens the server considers live. */
  readonly live: Set<string>;
  challenges: number;
  tokens: number;
  /** Set to refuse the next write with this gateway code, once. */
  refuseWrite: string | null;
}

/** A Worker that implements §11.3 honestly and answers one write route. */
function scriptedWorker(options: { readonly sealedNonce?: Uint8Array; readonly rootGeneration?: number } = {}): Script {
  const nonce = options.sealedNonce ?? randomBytes(32);
  const pending = new Map<string, Uint8Array>();
  const script: Script = {
    seen: [],
    live: new Set(),
    challenges: 0,
    tokens: 0,
    refuseWrite: null,
    fetch: (async (url: string | URL, init?: RequestInit) => {
      const path = new URL(String(url)).pathname + new URL(String(url)).search;
      const headers = new Headers(init?.headers);
      script.seen.push({ path, capability: headers.get(P.CAPABILITY_HEADER) });
      const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

      if (path === P.capabilityRoutes.challenge) {
        script.challenges += 1;
        const challenge = new Uint8Array(16).fill(script.challenges);
        pending.set(hex(challenge), nonce);
        return json({ ok: true, challenge: hex(challenge), sealedNonce: hex(nonce), rootGeneration: options.rootGeneration ?? 1, expiresInSeconds: 60 });
      }
      if (path === P.capabilityRoutes.token) {
        const body = P.ProofRequest.parse(JSON.parse(String(init?.body)));
        const secretBytes = pending.get(body.challenge);
        pending.delete(body.challenge);
        if (secretBytes === undefined) return json({ ok: false, code: "PROOF_REJECTED" });
        if (hex(await expectedCapabilityProof(secretBytes, new Uint8Array(16).fill(script.challenges))) !== body.proof) return json({ ok: false, code: "PROOF_REJECTED" });
        script.tokens += 1;
        const tokenId = `00000000-0000-7000-8000-${script.tokens.toString(16).padStart(12, "0")}`;
        const secret = "A".repeat(43);
        script.live.add(P.capabilityHeaderValue(tokenId, secret));
        return json({ ok: true, tokenId, secret, scopes: ["VAULT_WRITE", "TRUSTED_SECURITY"], replicaId: RECIPIENT, rootGeneration: 1, expiresInSeconds: 1800 });
      }
      // The one write route this test needs.
      if (script.refuseWrite !== null) {
        const code = script.refuseWrite;
        script.refuseWrite = null;
        return json({ error: code }, 403);
      }
      const presented = headers.get(P.CAPABILITY_HEADER);
      if (presented === null || !script.live.has(presented)) return json({ error: "WRITE_CAPABILITY_REQUIRED" }, 403);
      return json({ ok: true, expiresInSeconds: 900 });
    }) as unknown as typeof fetch,
  };
  return script;
}

/** The client's side of steps 4–5 with the nonce in hand, which is what an unwrapped key gives. */
const proveWith = (nonce: Uint8Array) => async (input: { challenge: Uint8Array }) => hmacSha256(await importMacKey(nonce), writeCapabilityProofContext(input.challenge));

function session(script: Script, nonce: Uint8Array, now: () => number) {
  return capabilitySession({
    baseUrl: "https://api.test",
    fetch: script.fetch,
    sessionHeaders: () => ({ authorization: "Bearer session" }),
    accountId: ACCOUNT,
    serverSessionId: SESSION,
    recipientId: RECIPIENT,
    prove: proveWith(nonce),
    now,
  });
}

describe("§11.3 on the client", () => {
  it("obtains one capability, keeps it in memory and reuses it", async () => {
    const nonce = randomBytes(32);
    const script = scriptedWorker({ sealedNonce: nonce });
    const capability = session(script, nonce, () => 0);

    const first = await capability.headers();
    expect(first[P.CAPABILITY_HEADER]).toMatch(/^[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$/);
    expect(await capability.headers()).toEqual(first);
    // One challenge and one token for two requests: the second is served from memory.
    expect([script.challenges, script.tokens]).toEqual([1, 1]);
    expect(capability.replicaId()).toBe(RECIPIENT);
  });

  it("proves again before the token expires, and forgets it on demand", async () => {
    const nonce = randomBytes(32);
    const script = scriptedWorker({ sealedNonce: nonce });
    let clock = 0;
    const capability = session(script, nonce, () => clock);

    const first = await capability.headers();
    // Inside the margin (30 min token, 60 s margin): a fresh proof of possession.
    clock = (1800 - 30) * 1000;
    const second = await capability.headers();
    expect(second[P.CAPABILITY_HEADER]).not.toBe(first[P.CAPABILITY_HEADER]);
    expect(script.tokens).toBe(2);

    capability.forget();
    await capability.headers();
    expect(script.tokens).toBe(3);
  });

  it("a rejected proof is a typed error, and nothing is held", async () => {
    const nonce = randomBytes(32);
    const script = scriptedWorker({ sealedNonce: nonce });
    const capability = capabilitySession({
      baseUrl: "https://api.test",
      fetch: script.fetch,
      sessionHeaders: () => ({}),
      accountId: ACCOUNT,
      serverSessionId: SESSION,
      recipientId: RECIPIENT,
      // A client that does not actually hold the key.
      prove: async () => randomBytes(32),
      now: () => 0,
    });
    await expect(capability.headers()).rejects.toBeInstanceOf(CapabilityError);
    await expect(capability.headers()).rejects.toMatchObject({ code: "PROOF_REJECTED" });
  });

  it("the backend proves again once when a write is refused, and gives up on the second refusal", async () => {
    const nonce = randomBytes(32);
    const script = scriptedWorker({ sealedNonce: nonce });
    const capability = session(script, nonce, () => 0);
    const backend = httpSyncBackend({
      baseUrl: "https://api.test",
      vaultId: VAULT,
      fetch: script.fetch,
      headers: () => capability.headers(),
      onAuthRefusal: (code) => capability.onAuthRefusal(code),
      opener: { ...devManifestCodec, open: async () => new Uint8Array() },
    });

    const upload = {
      blobId: "00000000-0000-7000-8000-0000000000b1",
      epochId: "00000000-0000-7000-8000-0000000000e1",
      objectId: "00000000-0000-7000-8000-0000000000a1",
      kind: "CONTENT" as const,
      declaredSize: 1,
      ciphertextSha256: "a".repeat(64),
      forDelete: false,
    };
    expect(await backend.prepareUpload(upload)).toEqual({ ok: true, expiresInSeconds: 900 });
    expect(script.tokens).toBe(1);

    // The Worker refuses the next write the way §11.3 does; one fresh proof, one resend, success.
    script.refuseWrite = "WRITE_CAPABILITY_REQUIRED";
    expect(await backend.prepareUpload(upload)).toEqual({ ok: true, expiresInSeconds: 900 });
    expect(script.tokens).toBe(2);
    const capabilities = script.seen.filter((s) => s.path.includes("/uploads")).map((s) => s.capability);
    expect(new Set(capabilities).size).toBe(2);

    // A recipient that has been revoked is not something a new proof fixes (§18.3): no retry.
    script.refuseWrite = "RECIPIENT_REVOKED";
    await expect(backend.prepareUpload(upload)).rejects.toMatchObject({ code: "RECIPIENT_REVOKED" });
    expect(script.tokens).toBe(2);
  });

  it("REPLICA_MISMATCH is adopted: the id the session fixed becomes the client's (§6)", async () => {
    const nonce = randomBytes(32);
    const fixed = "00000000-0000-7000-8000-0000000000c9";
    const script = scriptedWorker({ sealedNonce: nonce });
    const inner = script.fetch;
    let first = true;
    const capability = capabilitySession({
      baseUrl: "https://api.test",
      fetch: (async (url: string | URL, init?: RequestInit) => {
        if (String(url).endsWith(P.capabilityRoutes.token) && first) {
          first = false;
          await inner(url as never, init as never);
          return new Response(JSON.stringify({ ok: false, code: "REPLICA_MISMATCH", replicaId: fixed }), { status: 200, headers: { "content-type": "application/json" } });
        }
        return inner(url as never, init as never);
      }) as unknown as typeof fetch,
      sessionHeaders: () => ({}),
      accountId: ACCOUNT,
      serverSessionId: SESSION,
      recipientId: RECIPIENT,
      prove: proveWith(nonce),
      replicaId: "00000000-0000-7000-8000-0000000000c1",
      now: () => 0,
    });
    await expect(capability.headers()).rejects.toMatchObject({ code: "REPLICA_MISMATCH", replicaId: fixed });
    expect(capability.replicaId()).toBe(fixed);
    // The next attempt proposes the id the session fixed rather than its own.
    await capability.headers();
    const proposals = script.seen.filter((s) => s.path === P.capabilityRoutes.challenge);
    expect(proposals).toHaveLength(2);
  });
});
