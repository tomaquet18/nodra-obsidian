// §11.3 steps 3–6 as a unit: the two contexts, the two client paths, and the one property Annex B
// asks for — with a `["unwrapKey"]` handle the client never sees the nonce in bytes.
import {
  exportEnvelopePrivateKey,
  exportEnvelopePublicKey,
  generateEnvelopeKeyPair,
  generateRecipientKeyPair,
  importEnvelopeDecryptKey,
  importEnvelopePublicKey,
  importEnvelopeUnwrapKey,
  randomBytes,
} from "@nodra/crypto";
import { describe, expect, it } from "vitest";
import {
  CAPABILITY_CHALLENGE_BYTES,
  CAPABILITY_NONCE_BYTES,
  CAPABILITY_SCOPES,
  capabilityProofMatches,
  capabilityReplicaBinding,
  expectedCapabilityProof,
  issueCapabilityChallenge,
  proveCapabilityWithDecryptKey,
  proveCapabilityWithUnwrapKey,
  writeCapabilityLabel,
} from "../src/write-capability.js";
import { filled } from "./support.js";

const ACCOUNT = filled(16, 0x11);
const RECIPIENT = filled(16, 0x22);
const SESSION = filled(16, 0x33);

const base = (challenge: Uint8Array) => ({ accountId: ACCOUNT, recipientId: RECIPIENT, rootGeneration: 3, serverSessionId: SESSION, challenge });

describe("§11.3 proof of possession", () => {
  it("a `[unwrapKey]` recipient proves possession, and the nonce never becomes bytes", async () => {
    const pair = await generateRecipientKeyPair();
    const nonce = randomBytes(CAPABILITY_NONCE_BYTES);
    const challenge = randomBytes(CAPABILITY_CHALLENGE_BYTES);
    const issued = await issueCapabilityChallenge({ publicKey: pair.publicKey, ...base(challenge), nonce, challenge });

    const proof = await proveCapabilityWithUnwrapKey({ privateKey: pair.privateKey, label: writeCapabilityLabel(base(challenge)), sealedNonce: issued.sealedNonce, challenge });
    expect(capabilityProofMatches(proof, issued.expectedProof)).toBe(true);
    // §25.1: the Session handle is `["unwrapKey"]` only, so there is no path to the nonce at all.
    expect(pair.privateKey.usages).toEqual(["unwrapKey"]);
    await expect(
      crypto.subtle.decrypt({ name: "RSA-OAEP", label: writeCapabilityLabel(base(challenge)) as BufferSource }, pair.privateKey, issued.sealedNonce as BufferSource),
    ).rejects.toThrow();
  }, 30_000);

  it("a `[decrypt]` recovery key proves possession too, and zeroizes what it read", async () => {
    const generated = await generateEnvelopeKeyPair();
    const pkcs8 = await exportEnvelopePrivateKey(generated.privateKey);
    const publicKey = await importEnvelopePublicKey(await exportEnvelopePublicKey(generated.publicKey));
    const nonce = randomBytes(CAPABILITY_NONCE_BYTES);
    const challenge = randomBytes(CAPABILITY_CHALLENGE_BYTES);
    const issued = await issueCapabilityChallenge({ publicKey, ...base(challenge), nonce, challenge });

    const proof = await proveCapabilityWithDecryptKey({
      privateKey: await importEnvelopeDecryptKey(pkcs8),
      label: writeCapabilityLabel(base(challenge)),
      sealedNonce: issued.sealedNonce,
      challenge,
    });
    expect(capabilityProofMatches(proof, await expectedCapabilityProof(nonce, challenge))).toBe(true);

    // And the same key imported as a Session handle reaches the same MAC by the other route.
    const asSession = await importEnvelopeUnwrapKey(pkcs8);
    const other = await proveCapabilityWithUnwrapKey({ privateKey: asSession, label: writeCapabilityLabel(base(challenge)), sealedNonce: issued.sealedNonce, challenge });
    expect(capabilityProofMatches(other, proof)).toBe(true);
  }, 30_000);

  it("every field of the label binds: one wrong field and the envelope does not open", async () => {
    const pair = await generateRecipientKeyPair();
    const nonce = randomBytes(CAPABILITY_NONCE_BYTES);
    const challenge = randomBytes(CAPABILITY_CHALLENGE_BYTES);
    const issued = await issueCapabilityChallenge({ publicKey: pair.publicKey, ...base(challenge), nonce, challenge });
    const wrong = [
      { ...base(challenge), accountId: filled(16, 0x99) },
      { ...base(challenge), recipientId: filled(16, 0x99) },
      { ...base(challenge), rootGeneration: 4 },
      { ...base(challenge), serverSessionId: filled(16, 0x99) },
      { ...base(challenge), challenge: filled(16, 0x99) },
    ];
    for (const input of wrong) {
      await expect(
        proveCapabilityWithUnwrapKey({ privateKey: pair.privateKey, label: writeCapabilityLabel(input), sealedNonce: issued.sealedNonce, challenge }),
      ).rejects.toThrow();
    }
  }, 30_000);

  it("a MAC over another challenge does not match, even from the right nonce", async () => {
    const nonce = randomBytes(CAPABILITY_NONCE_BYTES);
    const a = await expectedCapabilityProof(nonce, filled(16, 1));
    const b = await expectedCapabilityProof(nonce, filled(16, 2));
    expect(capabilityProofMatches(a, b)).toBe(false);
    expect(capabilityProofMatches(a, await expectedCapabilityProof(nonce, filled(16, 1)))).toBe(true);
  });

  it("§11.3's scope table: RECOVERY_CONTROL alone, and never VAULT_WRITE", () => {
    expect(CAPABILITY_SCOPES.RECOVERY).toEqual(["RECOVERY_CONTROL"]);
    expect(CAPABILITY_SCOPES.RECOVERY).not.toContain("VAULT_WRITE");
    expect([...CAPABILITY_SCOPES.PLUGIN_INSTALLATION]).toEqual(["VAULT_WRITE", "TRUSTED_SECURITY"]);
    expect([...CAPABILITY_SCOPES.TRUSTED_BROWSER]).toEqual(["VAULT_WRITE", "TRUSTED_SECURITY"]);
    expect([...CAPABILITY_SCOPES.ACCOUNT]).toEqual(["VAULT_WRITE", "ACCOUNT_SECURITY"]);
    // §6: a trusted client's replica is its recipient; an ACCOUNT's is the session's; RECOVERY has none.
    expect(["PLUGIN_INSTALLATION", "TRUSTED_BROWSER", "ACCOUNT", "RECOVERY"].map((t) => capabilityReplicaBinding(t as never))).toEqual([
      "RECIPIENT",
      "RECIPIENT",
      "SESSION",
      "NONE",
    ]);
  });
});
