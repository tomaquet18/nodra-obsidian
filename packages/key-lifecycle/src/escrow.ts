// The ADR-021 escrow (§3.6, §23.4, §24.2, §35.7): the client wraps its `RootUnlockKey` and its Recovery
// private keys to the server's Escrow Key; the Worker re-wraps one slot at a time to a per-unlock
// ephemeral key of the client, and lazily moves a slot off a retired Escrow Key.
//
// Three functions, one per actor and moment:
//
//   buildEscrowBlob     client, §35.2 / §35.7 / §35.14   the slots a SecurityBundle replaces (key 14)
//   rewrapEscrowSlot    Worker, §24.2 step 3 / §35.7      one stored slot → an `EscrowRewrap`
//   openEscrowRewrap    client, §24.2 step 4 / §35.7      an `EscrowRewrap` → RootUnlockBase or the keys
//
// Every wrap and every AEAD is bound to `Context("nodra/escrow", account_id, key_id, slot)` or
// `Context("nodra/escrow-rewrap", account_id, SHA-256(ephemeral SPKI), slot)` (§23.3), which is what
// makes a slot useless under any other account, Escrow Key, slot or ephemeral key (§44.3).
//
// Like every builder in this package, `buildEscrowBlob` enforces no policy: which slots an operation
// must carry is §35.1.1 step 7, and lives in the bundle validator.
import {
  ESCROW_SECRET_BYTES,
  escrowLabel,
  escrowRewrapLabel,
  importAeadKey,
  importEnvelopePublicKey,
  seal,
  sealEscrowKey,
  unseal,
  unwrapEscrowPayloadKey,
  unwrapRootUnlockBase,
  zeroize,
} from "@nodra/crypto";
import type { AeadKey, EnvelopePublicKey, EnvelopeUnwrapKey, EscrowSlotName, HkdfBase } from "@nodra/crypto";
import { NceError } from "@nodra/encoding";
import { ESCROWED_RECOVERY_KEYS, RecordError, decodeRecord, encodeRecord } from "@nodra/encoding/records";
import type { EscrowBlob, EscrowRewrap, EscrowSlot, EscrowedRecoveryKeys } from "@nodra/encoding/records";
import { KeyLifecycleError } from "./errors.js";
import type { Outcome } from "./errors.js";
import { defaultPorts } from "./ports.js";
import type { KeyLifecyclePorts } from "./ports.js";

/**
 * §22 `EscrowKeyStore`, Worker only: the Escrow Key private halves behind a port that only unwraps.
 * It knows nothing of slots, AADs or re-wraps; it never persists or logs what it returns.
 */
export interface EscrowKeyStore {
  unwrap(keyId: Uint8Array, wrapped: Uint8Array, label: Uint8Array): Promise<Uint8Array>;
}

/** An Escrow Key public half with its `key_id` (§3.6: served in `getRootState`, over TLS, no pin). */
export interface EscrowPublicKey {
  readonly keyId: Uint8Array;
  readonly publicKey: EnvelopePublicKey;
}

export type EscrowFailureCode =
  /** The slot's `payload_blob` is present where it must not be, or absent where it must be (§23.4). */
  | "MALFORMED_SLOT"
  /** The re-wrap names another account or slot than the one asked for. */
  | "ESCROW_MISBOUND"
  /** A wrap or an AEAD did not open under the label it must be bound to, or opened to the wrong size. */
  | "ESCROW_REJECTED"
  /** The RECOVERY payload opened but is not a canonical `EscrowedRecoveryKeys`. */
  | "MALFORMED_PAYLOAD";

export interface EscrowFailure {
  readonly code: EscrowFailureCode;
  readonly message: string;
}

function fail(code: EscrowFailureCode, message: string): Outcome<never, EscrowFailure> {
  return { ok: false, failure: { code, message } };
}

/** §23.4: `payload_blob` present if and only if the slot is RECOVERY. */
function payloadShapeOk(slot: EscrowSlotName, payload: Uint8Array | undefined): boolean {
  return (slot === "RECOVERY") === (payload !== undefined);
}

// --- Client: building the slots -----------------------------------------------------------------------

export interface BuildEscrowBlobRequest {
  readonly accountId: Uint8Array;
  /** The Escrow Key in force, as `getRootState` served it. */
  readonly escrowKey: EscrowPublicKey;
  /** Slot UNLOCK: the 32 bytes of the `RootUnlockKey`. The caller zeroizes them afterwards. */
  readonly rootUnlockKey?: Uint8Array;
  /** Slot RECOVERY: the two Recovery private keys, PKCS#8 DER. */
  readonly recoveryKeys?: EscrowedRecoveryKeys;
  readonly ports?: KeyLifecyclePorts;
}

/**
 * The `EscrowBlob` of SecurityBundle key 14: exactly the slots given, each wrapped to the Escrow Key.
 * RECOVERY seals `NCE(EscrowedRecoveryKeys)` under a fresh random AES-256-GCM key, with the slot's own
 * Context as AAD, and wraps that key; UNLOCK wraps the `RootUnlockKey` itself (§23.4).
 */
export async function buildEscrowBlob(request: BuildEscrowBlobRequest): Promise<EscrowBlob> {
  const { accountId, escrowKey, ports = defaultPorts } = request;
  const blob: { account_id: Uint8Array; unlock?: EscrowSlot; recovery?: EscrowSlot } = { account_id: accountId };

  if (request.rootUnlockKey !== undefined) {
    const label = escrowLabel(accountId, escrowKey.keyId, "UNLOCK");
    blob.unlock = {
      slot: "UNLOCK",
      key_id: escrowKey.keyId,
      wrapped_key: await sealEscrowKey(escrowKey.publicKey, label, request.rootUnlockKey),
    };
  }

  if (request.recoveryKeys !== undefined) {
    const label = escrowLabel(accountId, escrowKey.keyId, "RECOVERY");
    const payloadKey = ports.randomBytes(ESCROW_SECRET_BYTES);
    const plaintext = encodeRecord(ESCROWED_RECOVERY_KEYS, request.recoveryKeys);
    try {
      blob.recovery = {
        slot: "RECOVERY",
        key_id: escrowKey.keyId,
        wrapped_key: await sealEscrowKey(escrowKey.publicKey, label, payloadKey),
        payload_blob: await seal(await importAeadKey(payloadKey), label, plaintext),
      };
    } finally {
      zeroize(payloadKey);
      zeroize(plaintext);
    }
  }
  return blob;
}

// --- Worker: re-wrapping one slot -------------------------------------------------------------------

export interface RewrapEscrowSlotRequest {
  /** The authenticated account (never read from the request body). */
  readonly accountId: Uint8Array;
  /** The stored slot, from `account_escrows`. */
  readonly slot: EscrowSlot;
  /** The exact SPKI DER the client sent (§24.2 step 2). */
  readonly ephemeralSpki: Uint8Array;
  readonly store: EscrowKeyStore;
  /**
   * The Escrow Key in force. When the slot was wrapped under another `key_id` (a retired key), the
   * slot is also re-wrapped to this one and returned as `replacement` (§3.6 "Rotación").
   */
  readonly current?: EscrowPublicKey;
}

export interface RewrappedSlot {
  readonly rewrap: EscrowRewrap;
  /** The slot re-wrapped to the Escrow Key in force, to store in place of the old one; null if current. */
  readonly replacement: EscrowSlot | null;
}

/**
 * §24.2 step 3 and §35.7: opens one slot with the Escrow Key private half (through the port) and
 * re-wraps it to the client's ephemeral key. The secret exists as bytes only inside this call and is
 * zeroized before it returns, whatever happens (§24.2: never persisted, never logged).
 */
export async function rewrapEscrowSlot(request: RewrapEscrowSlotRequest): Promise<Outcome<RewrappedSlot, EscrowFailure>> {
  const { accountId, slot, ephemeralSpki, store, current } = request;
  const name = slot.slot;
  if (!payloadShapeOk(name, slot.payload_blob)) {
    return fail("MALFORMED_SLOT", `a ${name} slot ${name === "RECOVERY" ? "needs" : "has no"} payload_blob (§23.4)`);
  }

  const label = escrowLabel(accountId, slot.key_id, name);
  let secret: Uint8Array;
  try {
    secret = await store.unwrap(slot.key_id, slot.wrapped_key, label);
  } catch {
    return fail("ESCROW_REJECTED", "the slot does not open under this account, key_id and slot");
  }
  let inner: Uint8Array | null = null;
  try {
    if (secret.length !== ESCROW_SECRET_BYTES) {
      return fail("ESCROW_REJECTED", `an escrow slot carries ${ESCROW_SECRET_BYTES} bytes`);
    }
    let payloadKey: AeadKey | null = null;
    if (name === "RECOVERY") {
      payloadKey = await importAeadKey(secret);
      try {
        inner = await unseal(payloadKey, label, slot.payload_blob as Uint8Array);
      } catch {
        return fail("ESCROW_REJECTED", "the RECOVERY payload does not open under its slot's Context");
      }
    }

    const ephemeral = await importEnvelopePublicKey(ephemeralSpki);
    const rewrapLabel = await escrowRewrapLabel(accountId, ephemeralSpki, name);
    const rewrap: EscrowRewrap = {
      account_id: accountId,
      slot: name,
      wrapped_key: await sealEscrowKey(ephemeral, rewrapLabel, secret),
      ...(payloadKey === null || inner === null ? {} : { payload_blob: await seal(payloadKey, rewrapLabel, inner) }),
    };

    let replacement: EscrowSlot | null = null;
    if (current !== undefined && !sameBytes(current.keyId, slot.key_id)) {
      const newLabel = escrowLabel(accountId, current.keyId, name);
      replacement = {
        slot: name,
        key_id: current.keyId,
        wrapped_key: await sealEscrowKey(current.publicKey, newLabel, secret),
        ...(payloadKey === null || inner === null ? {} : { payload_blob: await seal(payloadKey, newLabel, inner) }),
      };
    }
    return { ok: true, value: { rewrap, replacement } };
  } finally {
    zeroize(secret);
    if (inner !== null) zeroize(inner);
  }
}

// --- Client: opening a re-wrap ----------------------------------------------------------------------

export interface OpenEscrowRewrapRequest {
  /** The account this client authenticated as. */
  readonly accountId: Uint8Array;
  /** The slot this client asked for: UNLOCK (`managedUnlock`) or RECOVERY (`managedRecoveryUnlock`). */
  readonly slot: EscrowSlotName;
  /** The ephemeral private half: non-extractable, `["unwrapKey"]` only (§24.2 step 2). */
  readonly ephemeralKey: EnvelopeUnwrapKey;
  /** The exact SPKI DER this client sent. */
  readonly ephemeralSpki: Uint8Array;
  readonly rewrap: EscrowRewrap;
}

export type OpenedEscrow =
  /** §24.2 step 4: the `RootUnlockKey` as a non-extractable HKDF base; its bytes never exist here. */
  | { readonly slot: "UNLOCK"; readonly rootUnlockBase: HkdfBase }
  /** §35.7: the two Recovery private keys, to import at once (§27.2) and drop with the operation. */
  | { readonly slot: "RECOVERY"; readonly recoveryKeys: EscrowedRecoveryKeys };

/** §24.2 step 4 and §35.7: the client side of a re-wrap. */
export async function openEscrowRewrap(request: OpenEscrowRewrapRequest): Promise<Outcome<OpenedEscrow, EscrowFailure>> {
  const { accountId, slot, ephemeralKey, ephemeralSpki, rewrap } = request;
  if (!sameBytes(rewrap.account_id, accountId) || rewrap.slot !== slot) {
    return fail("ESCROW_MISBOUND", `the re-wrap is not the ${slot} slot of this account`);
  }
  if (!payloadShapeOk(slot, rewrap.payload_blob)) {
    return fail("MALFORMED_SLOT", `a ${slot} re-wrap ${slot === "RECOVERY" ? "needs" : "has no"} payload_blob (§23.4)`);
  }
  const label = await escrowRewrapLabel(accountId, ephemeralSpki, slot);

  if (slot === "UNLOCK") {
    try {
      return { ok: true, value: { slot, rootUnlockBase: await unwrapRootUnlockBase(ephemeralKey, label, rewrap.wrapped_key) } };
    } catch {
      return fail("ESCROW_REJECTED", "the UNLOCK re-wrap does not open under this account and ephemeral key");
    }
  }

  let plaintext: Uint8Array;
  try {
    const key = await unwrapEscrowPayloadKey(ephemeralKey, label, rewrap.wrapped_key);
    plaintext = await unseal(key, label, rewrap.payload_blob as Uint8Array);
  } catch {
    return fail("ESCROW_REJECTED", "the RECOVERY re-wrap does not open under this account and ephemeral key");
  }
  // Not zeroized: the decoded keys are views of these bytes, and they are what the caller asked for.
  try {
    return { ok: true, value: { slot, recoveryKeys: decodeRecord(ESCROWED_RECOVERY_KEYS, plaintext) } };
  } catch (cause) {
    if (cause instanceof NceError || cause instanceof RecordError) return fail("MALFORMED_PAYLOAD", cause.message);
    throw cause;
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) throw new KeyLifecycleError("ids must be bytes");
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
