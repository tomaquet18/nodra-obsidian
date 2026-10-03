// ADR-021 escrow (§3.6, §23.4, §24.2, §35.7): the client builds the slots, the Worker re-wraps one to
// the client's ephemeral key (and moves it off a retired Escrow Key), the client opens it.
// §44.3: T6 (creation: the UNLOCK slot yields the RootUnlockKey whose keys open profile and config; the
// RECOVERY slot holds both Recovery privates), T8 (retired key_id → re-wrapped, key_id updated) and T15
// (another account, key_id, slot or ephemeral key → rejected).
import fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";
import {
  domainContext,
  escrowRewrapLabel,
  exportEnvelopePublicKey,
  generateEnvelopeKeyPair,
  generateRecipientKeyPair,
  importAeadKey,
  openEscrowKey,
  randomBytes,
  seal,
  sealEscrowKey,
  unseal,
  unwrapRootUnlockBase,
} from "@nodra/crypto";
import type { DomainContext, EnvelopeKeyPair, RecipientKeyPair } from "@nodra/crypto";
import type { EscrowRewrap, EscrowSlot } from "@nodra/encoding/records";
import { accountConfigAad } from "../src/contexts.js";
import { buildEscrowBlob, openEscrowRewrap, rewrapEscrowSlot } from "../src/escrow.js";
import type { EscrowKeyStore, EscrowPublicKey } from "../src/escrow.js";
import { deriveManagedAccountKeys } from "../src/secrets.js";
import { filled, toHex } from "./support.js";

const RUNS = 8;

let escrowA: EnvelopeKeyPair; // the Escrow Key the slots were first wrapped to (later retired)
let escrowB: EnvelopeKeyPair; // the Escrow Key in force after a rotation
let ephemeral: RecipientKeyPair;
let ephemeralSpki: Uint8Array;
let otherEphemeral: RecipientKeyPair;
let otherEphemeralSpki: Uint8Array;
const KEY_A = filled(16, 0xa0);
const KEY_B = filled(16, 0xb0);

beforeAll(async () => {
  [escrowA, escrowB, ephemeral, otherEphemeral] = await Promise.all([
    generateEnvelopeKeyPair(),
    generateEnvelopeKeyPair(),
    generateRecipientKeyPair(),
    generateRecipientKeyPair(),
  ]);
  ephemeralSpki = await exportEnvelopePublicKey(ephemeral.publicKey);
  otherEphemeralSpki = await exportEnvelopePublicKey(otherEphemeral.publicKey);
}, 60_000);

const keyA = (): EscrowPublicKey => ({ keyId: KEY_A, publicKey: escrowA.publicKey });
const keyB = (): EscrowPublicKey => ({ keyId: KEY_B, publicKey: escrowB.publicKey });

/** The Worker's port over both Escrow Keys, and a log of what it was asked (never the results). */
function store(): EscrowKeyStore & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async unwrap(keyId, wrapped, label) {
      calls.push(toHex(keyId));
      const pair = toHex(keyId) === toHex(KEY_A) ? escrowA : toHex(keyId) === toHex(KEY_B) ? escrowB : null;
      if (pair === null) throw new Error("unknown key_id");
      return openEscrowKey(pair.privateKey, label as DomainContext, wrapped);
    },
  };
}

/** One key pair behind every key_id: what separates two key_ids is then the label alone. */
function singleKeyStore(): EscrowKeyStore {
  return { unwrap: async (_keyId, wrapped, label) => openEscrowKey(escrowA.privateKey, label as DomainContext, wrapped) };
}

const recoveryKeys = () => ({ recovery_encryption_private_key: randomBytes(1700), recovery_authority_private_key: randomBytes(138) });

async function rewrap(accountId: Uint8Array, slot: EscrowSlot, spki = ephemeralSpki, current?: EscrowPublicKey) {
  const out = await rewrapEscrowSlot({ accountId, slot, ephemeralSpki: spki, store: store(), ...(current ? { current } : {}) });
  if (!out.ok) throw new Error(out.failure.code);
  return out.value;
}

describe("the whole pipeline (§35.2 Managed, §24.2, §35.7)", () => {
  it("T6: UNLOCK yields a RootUnlockBase whose keys open what the RootUnlockKey sealed", async () => {
    const accountId = randomBytes(16);
    const rootUnlockKey = randomBytes(32);
    const blob = await buildEscrowBlob({ accountId, escrowKey: keyA(), rootUnlockKey });
    expect(blob.recovery).toBeUndefined();
    const { rewrap: re } = await rewrap(accountId, blob.unlock!);
    const opened = await openEscrowRewrap({ accountId, slot: "UNLOCK", ephemeralKey: ephemeral.privateKey, ephemeralSpki, rewrap: re });
    if (!opened.ok || opened.value.slot !== "UNLOCK") throw new Error("expected UNLOCK");
    const creator = await deriveManagedAccountKeys(rootUnlockKey);
    const unlocker = await deriveManagedAccountKeys(opened.value.rootUnlockBase);
    const aad = accountConfigAad(accountId, 1);
    expect(toHex(await unseal(unlocker.configKey, aad, await seal(creator.configKey, aad, new Uint8Array([9]))))).toBe("09");
    expect(opened.value.rootUnlockBase.extractable).toBe(false);
  });

  it("T6: RECOVERY carries both Recovery private keys byte for byte", async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ minLength: 16, maxLength: 16 }), async (accountId) => {
        const keys = recoveryKeys();
        const blob = await buildEscrowBlob({ accountId, escrowKey: keyA(), recoveryKeys: keys });
        expect(blob.unlock).toBeUndefined();
        const { rewrap: re } = await rewrap(accountId, blob.recovery!);
        const opened = await openEscrowRewrap({ accountId, slot: "RECOVERY", ephemeralKey: ephemeral.privateKey, ephemeralSpki, rewrap: re });
        if (!opened.ok || opened.value.slot !== "RECOVERY") throw new Error("expected RECOVERY");
        expect(opened.value.recoveryKeys).toEqual(keys);
      }),
      { numRuns: RUNS },
    );
  });

  it("the slots never carry the secrets in clear, and the payload is sealed under the slot Context", async () => {
    const accountId = randomBytes(16);
    const rootUnlockKey = randomBytes(32);
    const keys = recoveryKeys();
    const blob = await buildEscrowBlob({ accountId, escrowKey: keyA(), rootUnlockKey, recoveryKeys: keys });
    const all = toHex(blob.unlock!.wrapped_key) + toHex(blob.recovery!.wrapped_key) + toHex(blob.recovery!.payload_blob!);
    expect(all).not.toContain(toHex(rootUnlockKey));
    expect(all).not.toContain(toHex(keys.recovery_authority_private_key));
    expect(blob.unlock!.payload_blob).toBeUndefined();
  });
});

describe("T8: a slot under a retired Escrow Key is moved to the key in force", () => {
  it("returns a replacement under the new key_id that opens and re-wraps like the original", async () => {
    const accountId = randomBytes(16);
    const keys = recoveryKeys();
    const rootUnlockKey = randomBytes(32);
    const blob = await buildEscrowBlob({ accountId, escrowKey: keyA(), rootUnlockKey, recoveryKeys: keys });
    for (const slot of [blob.unlock!, blob.recovery!]) {
      const { rewrap: re, replacement } = await rewrap(accountId, slot, ephemeralSpki, keyB());
      expect(replacement).not.toBeNull();
      expect(toHex(replacement!.key_id)).toBe(toHex(KEY_B));
      expect(replacement!.slot).toBe(slot.slot);
      // The replacement is a real slot under key B: it re-wraps to the same secret.
      const again = await rewrap(accountId, replacement!, ephemeralSpki, keyB());
      expect(again.replacement).toBeNull();
      const first = await openEscrowRewrap({ accountId, slot: slot.slot, ephemeralKey: ephemeral.privateKey, ephemeralSpki, rewrap: re });
      const second = await openEscrowRewrap({ accountId, slot: slot.slot, ephemeralKey: ephemeral.privateKey, ephemeralSpki, rewrap: again.rewrap });
      if (!first.ok || !second.ok) throw new Error("both re-wraps must open");
      if (first.value.slot === "RECOVERY" && second.value.slot === "RECOVERY") {
        expect(second.value.recoveryKeys).toEqual(keys);
      }
    }
  });

  it("no replacement when the slot is already under the key in force", async () => {
    const accountId = randomBytes(16);
    const blob = await buildEscrowBlob({ accountId, escrowKey: keyA(), rootUnlockKey: randomBytes(32) });
    expect((await rewrap(accountId, blob.unlock!, ephemeralSpki, keyA())).replacement).toBeNull();
    expect((await rewrap(accountId, blob.unlock!)).replacement).toBeNull();
  });

  it("the moved RECOVERY payload is bound to the new key_id, not the old one", async () => {
    const accountId = randomBytes(16);
    const blob = await buildEscrowBlob({ accountId, escrowKey: keyA(), recoveryKeys: recoveryKeys() });
    const { replacement } = await rewrap(accountId, blob.recovery!, ephemeralSpki, keyB());
    // A replacement that kept the old key_id in its record would not open under key B's Context.
    const relabelled = { ...replacement!, key_id: KEY_A };
    const out = await rewrapEscrowSlot({ accountId, slot: relabelled, ephemeralSpki, store: store() });
    expect(out.ok).toBe(false);
  });
});

describe("T15: binding of the slots and the re-wraps (§23.3)", () => {
  type Variant = "account" | "keyId" | "slot" | "ephemeral";

  /**
   * The oracle, for a given pipeline: changing exactly one of account_id, key_id, slot or the
   * ephemeral SPKI between the writer and the reader makes the read fail.
   */
  interface Pipeline {
    seal(accountId: Uint8Array, rootUnlockKey: Uint8Array): Promise<EscrowSlot>;
    rewrap(accountId: Uint8Array, slot: EscrowSlot, spki: Uint8Array): Promise<EscrowRewrap | null>;
    open(accountId: Uint8Array, rewrap: EscrowRewrap, key: RecipientKeyPair, spki: Uint8Array): Promise<boolean>;
  }

  const real: Pipeline = {
    seal: async (accountId, rootUnlockKey) => (await buildEscrowBlob({ accountId, escrowKey: keyA(), rootUnlockKey })).unlock!,
    rewrap: async (accountId, slot, spki) => {
      const out = await rewrapEscrowSlot({ accountId, slot, ephemeralSpki: spki, store: singleKeyStore() });
      return out.ok ? out.value.rewrap : null;
    },
    open: async (accountId, re, key, spki) =>
      (await openEscrowRewrap({ accountId, slot: "UNLOCK", ephemeralKey: key.privateKey, ephemeralSpki: spki, rewrap: re })).ok,
  };

  async function bindingHolds(pipeline: Pipeline, variant: Variant, accountId: Uint8Array): Promise<boolean> {
    const other = Uint8Array.from(accountId, (b) => b ^ 0xff);
    const slot = await pipeline.seal(accountId, randomBytes(32));
    switch (variant) {
      case "account":
        // The Worker asked to open this slot for another account, and the client asked for another.
        if ((await pipeline.rewrap(other, slot, ephemeralSpki)) !== null) return false;
        {
          const re = await pipeline.rewrap(accountId, slot, ephemeralSpki);
          if (re === null) return false;
          return !(await pipeline.open(other, { ...re, account_id: other }, ephemeral, ephemeralSpki));
        }
      case "keyId":
        // The record claims another key_id: same key pair behind it, so only the label can refuse.
        return (await pipeline.rewrap(accountId, { ...slot, key_id: KEY_B }, ephemeralSpki)) === null;
      case "slot":
        // An UNLOCK slot presented as RECOVERY (payload added so the shape check does not decide).
        return (await pipeline.rewrap(accountId, { ...slot, slot: "RECOVERY", payload_blob: randomBytes(64) }, ephemeralSpki)) === null;
      case "ephemeral": {
        // Re-wrapped for one ephemeral key, opened by a client claiming another SPKI (with the right key).
        const re = await pipeline.rewrap(accountId, slot, ephemeralSpki);
        if (re === null) return false;
        return !(await pipeline.open(accountId, re, ephemeral, otherEphemeralSpki));
      }
    }
  }

  it("holds for every variant (property)", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom<Variant>("account", "keyId", "slot", "ephemeral"),
        fc.uint8Array({ minLength: 16, maxLength: 16 }),
        async (variant, accountId) => {
          expect(await bindingHolds(real, variant, accountId)).toBe(true);
        },
      ),
      { numRuns: RUNS * 2 },
    );
  });

  it("the other ephemeral key cannot open a re-wrap made for this one", async () => {
    const accountId = randomBytes(16);
    const re = await real.rewrap(accountId, await real.seal(accountId, randomBytes(32)), ephemeralSpki);
    expect(await real.open(accountId, re!, otherEphemeral, otherEphemeralSpki)).toBe(false);
    expect(await real.open(accountId, re!, ephemeral, ephemeralSpki)).toBe(true);
  });

  it("catches a pipeline whose labels drop account_id (broken variant)", async () => {
    const noAccount = (keyId: Uint8Array, slot: string) => domainContext("nodra/escrow", keyId, slot);
    const noAccountRewrap = async (spki: Uint8Array, slot: string) =>
      domainContext("nodra/escrow-rewrap", new Uint8Array(await crypto.subtle.digest("SHA-256", spki as BufferSource)), slot);
    const broken: Pipeline = {
      seal: async (_accountId, rootUnlockKey) => ({
        slot: "UNLOCK",
        key_id: KEY_A,
        wrapped_key: await sealEscrowKey(escrowA.publicKey, noAccount(KEY_A, "UNLOCK"), rootUnlockKey),
      }),
      rewrap: async (_accountId, slot, spki) => {
        try {
          const secret = await openEscrowKey(escrowA.privateKey, noAccount(slot.key_id, slot.slot), slot.wrapped_key);
          const ephemeralKey = spki === ephemeralSpki ? ephemeral.publicKey : otherEphemeral.publicKey;
          return { account_id: _accountId, slot: "UNLOCK", wrapped_key: await sealEscrowKey(ephemeralKey, await noAccountRewrap(spki, "UNLOCK"), secret) };
        } catch {
          return null;
        }
      },
      open: async (_accountId, re, key, spki) => {
        try {
          await unwrapRootUnlockBase(key.privateKey, await noAccountRewrap(spki, "UNLOCK"), re.wrapped_key);
          return true;
        } catch {
          return false;
        }
      },
    };
    expect(await bindingHolds(broken, "account", randomBytes(16))).toBe(false);
    // The same variant still binds key_id, slot and the ephemeral key: the oracle names the field.
    expect(await bindingHolds(broken, "keyId", randomBytes(16))).toBe(true);
  });
});

describe("shape and failure paths", () => {
  it("a slot with the wrong payload shape is MALFORMED_SLOT before any unwrap", async () => {
    const accountId = randomBytes(16);
    const blob = await buildEscrowBlob({ accountId, escrowKey: keyA(), rootUnlockKey: randomBytes(32), recoveryKeys: recoveryKeys() });
    const port = store();
    for (const slot of [{ ...blob.unlock!, payload_blob: randomBytes(40) }, { slot: "RECOVERY" as const, key_id: KEY_A, wrapped_key: blob.recovery!.wrapped_key }]) {
      const out = await rewrapEscrowSlot({ accountId, slot, ephemeralSpki, store: port });
      expect(out.ok ? "ok" : out.failure.code).toBe("MALFORMED_SLOT");
    }
    expect(port.calls).toEqual([]);
  });

  it("the client refuses a re-wrap of the other slot or another account (ESCROW_MISBOUND)", async () => {
    const accountId = randomBytes(16);
    const blob = await buildEscrowBlob({ accountId, escrowKey: keyA(), rootUnlockKey: randomBytes(32) });
    const { rewrap: re } = await rewrap(accountId, blob.unlock!);
    const asRecovery = await openEscrowRewrap({ accountId, slot: "RECOVERY", ephemeralKey: ephemeral.privateKey, ephemeralSpki, rewrap: re });
    expect(asRecovery.ok ? "ok" : asRecovery.failure.code).toBe("ESCROW_MISBOUND");
    const other = await openEscrowRewrap({ accountId: randomBytes(16), slot: "UNLOCK", ephemeralKey: ephemeral.privateKey, ephemeralSpki, rewrap: re });
    expect(other.ok ? "ok" : other.failure.code).toBe("ESCROW_MISBOUND");
  });

  it("a slot whose secret is not 32 bytes is ESCROW_REJECTED on the Worker", async () => {
    const accountId = randomBytes(16);
    const label = domainContext("nodra/escrow", accountId, KEY_A, "UNLOCK");
    const short = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP", label: label as BufferSource }, escrowA.publicKey, randomBytes(16) as BufferSource));
    const port: EscrowKeyStore = { unwrap: async (_k, w, l) => new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP", label: l as BufferSource }, escrowA.privateKey, w as BufferSource)) };
    const out = await rewrapEscrowSlot({ accountId, slot: { slot: "UNLOCK", key_id: KEY_A, wrapped_key: short }, ephemeralSpki, store: port });
    expect(out.ok ? "ok" : out.failure.code).toBe("ESCROW_REJECTED");
  });

  it("a RECOVERY payload that is not EscrowedRecoveryKeys is MALFORMED_PAYLOAD", async () => {
    const accountId = randomBytes(16);
    const aes = randomBytes(32);
    const label = await escrowRewrapLabel(accountId, ephemeralSpki, "RECOVERY");
    const re: EscrowRewrap = {
      account_id: accountId,
      slot: "RECOVERY",
      wrapped_key: await sealEscrowKey(ephemeral.publicKey, label, aes),
      payload_blob: await seal(await importAeadKey(aes), label, new Uint8Array([1, 2, 3])),
    };
    const out = await openEscrowRewrap({ accountId, slot: "RECOVERY", ephemeralKey: ephemeral.privateKey, ephemeralSpki, rewrap: re });
    expect(out.ok ? "ok" : out.failure.code).toBe("MALFORMED_PAYLOAD");
  });
});
