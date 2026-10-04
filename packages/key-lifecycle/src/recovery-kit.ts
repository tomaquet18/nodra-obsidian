// The Recovery Kit (§27): the document, its self-test, and the two handles a §35 recovery
// operation reads out of it.
//
// §27 is small but it is the account's last line of defence, so three rules shape this file:
//
//   1. **The self-test reads the privates back from the serialized kit**, never from the
//      in-memory key pair that produced them (§27.3 step 1, "leída del kit serializado"). A
//      self-test against the live handles would pass on a kit whose bytes are truncated,
//      re-encoded by the printer, or assembled from the wrong pair — exactly the kit that must
//      never be shown to the user.
//   2. **The public keys come from a Root Descriptor**, not from the kit. §35.7 step 2 says why:
//      a private imported non-extractable cannot give back its public key, so the only way to
//      prove the kit belongs to a root is to encrypt and verify *under that root's* keys.
//   3. **Pending and current are different questions.** Creating or replacing a kit self-tests it
//      against the root descriptor about to be committed ({@link selfTestRecoveryKit}); "Verify
//      Recovery Kit", available at any time, tests against the root in force
//      ({@link verifyRecoveryKit}). One function with a boolean would let a caller ask the wrong
//      one by accident, and in a `RECOVERY_KIT_REPLACEMENT` the two roots hold *different*
//      recovery keys, so the wrong one silently rejects a perfectly good new kit.
//
// Pure domain: no network, no storage, no DOM. The only impure inputs are the `randomBytes` and
// `now` ports.
import {
  EPOCH_SECRET_BYTES,
  exportEnvelopePrivateKey,
  exportEnvelopePublicKey,
  exportSigningKey,
  exportVerifyingKey,
  generateEnvelopeKeyPair,
  generateSigningKeyPair,
  importEnvelopeDecryptKey,
  importEnvelopePublicKey,
  importSigningKey,
  importVerifyingKey,
  openEpochSecret,
  sealEpochSecret,
  sha256,
  signContext,
  timingSafeEqual,
  verifyContext,
  zeroize,
} from "@nodra/crypto";
import type {
  EnvelopeDecryptKey,
  EnvelopePublicKey,
  ExtractableEnvelopePrivateKey,
  ExtractableSigningKey,
  SigningKey,
  VerifyingKey,
} from "@nodra/crypto";
import { CONTEXT_VERSION, decode } from "@nodra/encoding";
import type { NceValue } from "@nodra/encoding";
import { ESCROWED_RECOVERY_KEYS, RECOVERY_KIT, decodeRecord, encodeRecord, fromNce } from "@nodra/encoding/records";
import type { EscrowedRecoveryKeys, RecoveryKit, RootDescriptor } from "@nodra/encoding/records";
import { recoveryKitContext, selfTestContext } from "./contexts.js";
import { KeyLifecycleError } from "./errors.js";
import type { Outcome } from "./errors.js";
import { defaultPorts } from "./ports.js";
import type { KeyLifecyclePorts } from "./ports.js";

/** §23.4, last bullet: "El `nonce` del self-test (§27.3) es bytes(16) aleatorios." */
export const SELF_TEST_NONCE_BYTES = 16;

/** §27.3 step 1: "un secreto aleatorio de 32 bytes" — the same width as an `epoch_secret` (§32.2). */
export const SELF_TEST_SECRET_BYTES = EPOCH_SECRET_BYTES;

const ID_BYTES = 16;
const HASH_BYTES = 32;

/** The domain of the delivered kit bytes (§23.3). */
const KIT_DOMAIN = "nodra/recovery-kit";

// --- Key material ------------------------------------------------------------------------------

/** One of the two recovery key pairs, in every form §27.1 and §28.1 need it. */
export interface RecoveryKeyMaterial<Private, Public> {
  /**
   * Extractable, because §27.1 puts the PKCS#8 DER in the kit. It MUST be dropped when the
   * operation ends (§35.2 step 17, §35.9 step 8); this package keeps no copy.
   */
  readonly privateKey: Private;
  readonly publicKey: Public;
  /** PKCS#8 DER, the bytes that go into the kit (§27.1). */
  readonly privateKeyPkcs8: Uint8Array;
  /** SPKI DER, the bytes that go into the Root Descriptor (§28.1). */
  readonly publicKeySpki: Uint8Array;
  /** `SHA-256(SPKI)` over those exact bytes, never over a re-export (§25.2). */
  readonly publicKeyHash: Uint8Array;
}

export interface RecoveryKeyPairs {
  /** RSA-OAEP-3072: the `RECOVERY` recipient of every epoch (§30.1, §32.2). */
  readonly encryption: RecoveryKeyMaterial<ExtractableEnvelopePrivateKey, EnvelopePublicKey>;
  /** ECDSA P-256: signer roles 3 and 4 of a root transition (§28.2). */
  readonly authority: RecoveryKeyMaterial<ExtractableSigningKey, VerifyingKey>;
}

/** §35.2 step 6 / §35.9 step 2: generate the two recovery key pairs. */
export async function generateRecoveryKeyPairs(): Promise<RecoveryKeyPairs> {
  const [encryptionPair, authorityPair] = await Promise.all([generateEnvelopeKeyPair(), generateSigningKeyPair()]);
  const [encryptionSpki, authoritySpki, encryptionPkcs8, authorityPkcs8] = await Promise.all([
    exportEnvelopePublicKey(encryptionPair.publicKey),
    exportVerifyingKey(authorityPair.publicKey),
    exportEnvelopePrivateKey(encryptionPair.privateKey),
    exportSigningKey(authorityPair.privateKey),
  ]);
  const [encryptionHash, authorityHash] = await Promise.all([sha256(encryptionSpki), sha256(authoritySpki)]);
  return {
    encryption: {
      privateKey: encryptionPair.privateKey,
      publicKey: encryptionPair.publicKey,
      privateKeyPkcs8: encryptionPkcs8,
      publicKeySpki: encryptionSpki,
      publicKeyHash: encryptionHash,
    },
    authority: {
      privateKey: authorityPair.privateKey,
      publicKey: authorityPair.publicKey,
      privateKeyPkcs8: authorityPkcs8,
      publicKeySpki: authoritySpki,
      publicKeyHash: authorityHash,
    },
  };
}

/** The four recovery-key fields a Root Descriptor takes from a kit's pairs (§28.1). */
export function recoveryRootKeys(keys: RecoveryKeyPairs): {
  readonly recoveryEncryption: Uint8Array;
  readonly recoveryAuthority: Uint8Array;
} {
  return { recoveryEncryption: keys.encryption.publicKeySpki, recoveryAuthority: keys.authority.publicKeySpki };
}

// --- The document ------------------------------------------------------------------------------

export interface CreateRecoveryKitRequest {
  readonly accountId: Uint8Array;
  /**
   * §27.1. At account creation this is the hash of the GENESIS descriptor being built in the very
   * same operation; at `RECOVERY_KIT_REPLACEMENT` it is the account's existing genesis hash,
   * which never changes. Either way the caller supplies it — see NOTES question 196.
   */
  readonly genesisRootHash: Uint8Array;
  /** Pre-generated pairs (§35.9 generates them before it knows the genesis hash). */
  readonly keys?: RecoveryKeyPairs;
  readonly ports?: KeyLifecyclePorts;
}

export interface CreatedRecoveryKit {
  readonly keys: RecoveryKeyPairs;
  readonly kit: RecoveryKit;
  /** The delivered bytes (§27.1): file, printable page, or QR payload. Never sent to the backend. */
  readonly serialized: Uint8Array;
}

/**
 * §35.2 step 6 / §35.9 step 2: build the kit. It is **not** usable until
 * {@link selfTestRecoveryKit} passes against the pending Root Descriptor (§27.3); this function
 * deliberately returns no "enabled" flag, so nothing can present a kit the self-test never saw.
 */
export async function createRecoveryKit(request: CreateRecoveryKitRequest): Promise<CreatedRecoveryKit> {
  assertBytes(request.accountId, ID_BYTES, "account_id");
  assertBytes(request.genesisRootHash, HASH_BYTES, "genesis_root_hash");
  const ports = request.ports ?? defaultPorts;
  const keys = request.keys ?? (await generateRecoveryKeyPairs());

  const createdAt = ports.now();
  if (!Number.isSafeInteger(createdAt) || createdAt < 0) {
    throw new KeyLifecycleError(`created_at must be a non-negative integer of Unix milliseconds, got ${createdAt}`);
  }

  const kit: RecoveryKit = {
    account_id: request.accountId,
    genesis_root_hash: request.genesisRootHash,
    recovery_encryption_private_key: keys.encryption.privateKeyPkcs8,
    recovery_authority_private_key: keys.authority.privateKeyPkcs8,
    recovery_encryption_public_key_hash: keys.encryption.publicKeyHash,
    recovery_authority_public_key_hash: keys.authority.publicKeyHash,
    created_at: createdAt,
  };
  return { keys, kit, serialized: serializeRecoveryKit(kit) };
}

/** The delivered bytes of §27.1: `Context("nodra/recovery-kit", RecoveryKit)`. */
export function serializeRecoveryKit(kit: RecoveryKit): Uint8Array {
  return recoveryKitContext(kit);
}

/**
 * The reverse. Canonicality is enforced by re-serializing and comparing: NCE is deterministic
 * (§23.2), so bytes that decode to a kit but do not encode back to themselves were tampered with
 * or produced by a non-conforming writer, and a kit is exactly the artefact where "close enough"
 * must not open.
 */
export function parseRecoveryKit(serialized: Uint8Array): Outcome<RecoveryKit, RecoveryKitFailure> {
  let decoded: NceValue;
  try {
    decoded = decode(serialized);
  } catch (error) {
    return fail("MALFORMED_KIT", `the kit is not canonical NCE: ${String(error)}`);
  }
  if (!Array.isArray(decoded) || decoded.length !== 3) {
    return fail("MALFORMED_KIT", "a serialized kit is the three-element context array of §23.3");
  }
  const [domain, version, map] = decoded as readonly NceValue[];
  const shown = (v: NceValue | undefined) => (typeof v === "object" && v !== null ? "a non-scalar value" : String(v));
  if (domain !== KIT_DOMAIN) return fail("MALFORMED_KIT", `the kit names the domain ${shown(domain)}`);
  if (version !== CONTEXT_VERSION) return fail("MALFORMED_KIT", `unsupported context version ${shown(version)}`);

  let kit: RecoveryKit;
  try {
    kit = fromNce(RECOVERY_KIT, map as NceValue);
  } catch (error) {
    return fail("MALFORMED_KIT", `the kit is not a canonical RecoveryKit: ${String(error)}`);
  }
  if (!timingSafeEqual(serializeRecoveryKit(kit), serialized)) {
    return fail("MALFORMED_KIT", "the kit bytes are not the canonical encoding of the kit they decode to");
  }
  return { ok: true, value: kit };
}

// --- Failures ----------------------------------------------------------------------------------

export type RecoveryKitFailureCode =
  /** The bytes are not a canonical `Context("nodra/recovery-kit", RecoveryKit)`. */
  | "MALFORMED_KIT"
  /** The kit names an account other than the one the caller authenticated with (§35.7 step 2). */
  | "ACCOUNT_MISMATCH"
  /** The kit's `genesis_root_hash` is not the account's (§35.7 step 2). */
  | "GENESIS_MISMATCH"
  /** A PKCS#8 DER in the kit is not an importable private key of its algorithm (§27.2). */
  | "MALFORMED_KIT_PRIVATE_KEY"
  /** An SPKI DER in the Root Descriptor is not importable — the root, not the kit, is broken. */
  | "MALFORMED_ROOT_PUBLIC_KEY"
  /** §27.3 step 1: the kit's private key did not decrypt what the root's public key encrypted. */
  | "ENCRYPTION_ROUND_TRIP_FAILED"
  /** §27.3 step 2: the kit's Recovery Authority signature did not verify under the root's key. */
  | "AUTHORITY_SIGNATURE_FAILED"
  /** §27.3 step 3: a public key hash in the kit is not the one in the Root Descriptor. */
  | "KEY_HASH_MISMATCH";

export interface RecoveryKitFailure {
  readonly code: RecoveryKitFailureCode;
  /** The §27.3 step that rejected it, when the failure belongs to one. */
  readonly step?: 1 | 2 | 3;
  readonly message: string;
}

function fail(code: RecoveryKitFailureCode, message: string, step?: 1 | 2 | 3): Outcome<never, RecoveryKitFailure> {
  return { ok: false, failure: step === undefined ? { code, message } : { code, step, message } };
}

// --- The self-test (§27.3) -----------------------------------------------------------------------

/** Which root a check was run against — the distinction §27.3 draws between its two uses. */
export type RecoveryKitScope = "PENDING" | "CURRENT";

/** What a passed check proves. There is no "enabled" boolean: the proof *is* the permission. */
export interface RecoveryKitProof {
  readonly kit: RecoveryKit;
  readonly scope: RecoveryKitScope;
  /** The bytes(16) nonce the run used, so a caller can log or re-run the exact same context. */
  readonly nonce: Uint8Array;
}

export interface RecoveryKitCheckRequest {
  /**
   * The kit exactly as delivered. §27.3 step 1 requires the private keys to be read back from
   * **these** bytes, which is the whole point of the test.
   */
  readonly serialized: Uint8Array;
  /**
   * The `account_id` the caller authenticated with — never read from the kit. Same rule as the
   * root chain (NOTES question 195): a kit stolen whole from another account is self-consistent.
   */
  readonly accountId: Uint8Array;
  /** §35.7 step 2 verifies it too; omitted at creation, where the genesis is only being born. */
  readonly genesisRootHash?: Uint8Array;
  readonly ports?: KeyLifecyclePorts;
}

/**
 * §27.3, the obligatory test at creation or replacement: steps 1–3 against the **pending** Root
 * Descriptor, the one about to be confirmed in the same commit (§35.2 step 8, §35.9 step 3).
 * Only a kit this returns `ok` for may be shown to the user.
 */
export async function selfTestRecoveryKit(
  request: RecoveryKitCheckRequest & { readonly pendingDescriptor: RootDescriptor },
): Promise<Outcome<RecoveryKitProof, RecoveryKitFailure>> {
  return runCheck(request, request.pendingDescriptor, "PENDING");
}

/**
 * "Verify Recovery Kit" (§27.3), available at any time: steps 1 and 2, and step 3 against the
 * Root Descriptor **in force**. Also §35.7 step 2, where the kit is the only credential the
 * client holds.
 */
export async function verifyRecoveryKit(
  request: RecoveryKitCheckRequest & { readonly currentDescriptor: RootDescriptor },
): Promise<Outcome<RecoveryKitProof, RecoveryKitFailure>> {
  return runCheck(request, request.currentDescriptor, "CURRENT");
}

async function runCheck(
  request: RecoveryKitCheckRequest,
  descriptor: RootDescriptor,
  scope: RecoveryKitScope,
): Promise<Outcome<RecoveryKitProof, RecoveryKitFailure>> {
  assertBytes(request.accountId, ID_BYTES, "account_id");
  const ports = request.ports ?? defaultPorts;

  const parsed = parseRecoveryKit(request.serialized);
  if (!parsed.ok) return parsed;
  const kit = parsed.value;

  // Preconditions, before any of the three steps: the label of steps 1 and 2 is built from the
  // *caller's* account_id, so a kit belonging to another account would otherwise sail through a
  // test that never looked at its own `account_id` field.
  if (!timingSafeEqual(kit.account_id, request.accountId)) {
    return fail("ACCOUNT_MISMATCH", "the kit belongs to another account");
  }
  if (!timingSafeEqual(descriptor.account_id, request.accountId)) {
    return fail("ACCOUNT_MISMATCH", "the Root Descriptor belongs to another account");
  }
  if (request.genesisRootHash !== undefined && !timingSafeEqual(kit.genesis_root_hash, request.genesisRootHash)) {
    return fail("GENESIS_MISMATCH", "the kit was issued for another root chain");
  }

  const proved = await provePrivates(kit.recovery_encryption_private_key, kit.recovery_authority_private_key, descriptor, request.accountId, ports);
  if (!proved.ok) return proved;

  // Step 3: the kit's recorded hashes against the descriptor's actual keys.
  const [encryptionHash, authorityHash] = await Promise.all([
    sha256(descriptor.recovery_encryption_public_key),
    sha256(descriptor.recovery_authority_public_key),
  ]);
  if (!timingSafeEqual(kit.recovery_encryption_public_key_hash, encryptionHash)) {
    return fail("KEY_HASH_MISMATCH", `recovery_encryption_public_key_hash does not match the ${scope} root`, 3);
  }
  if (!timingSafeEqual(kit.recovery_authority_public_key_hash, authorityHash)) {
    return fail("KEY_HASH_MISMATCH", `recovery_authority_public_key_hash does not match the ${scope} root`, 3);
  }

  return { ok: true, value: { kit, scope, nonce: proved.value } };
}

/**
 * §27.3 steps 1 and 2 over two PKCS#8 privates and a Root Descriptor's public keys. Returns the
 * nonce the run used.
 */
async function provePrivates(
  encryptionPkcs8: Uint8Array,
  authorityPkcs8: Uint8Array,
  descriptor: RootDescriptor,
  accountId: Uint8Array,
  ports: KeyLifecyclePorts,
): Promise<Outcome<Uint8Array, RecoveryKitFailure>> {
  const nonce = ports.randomBytes(SELF_TEST_NONCE_BYTES);
  if (nonce.length !== SELF_TEST_NONCE_BYTES) {
    throw new KeyLifecycleError(`the self-test nonce must be ${SELF_TEST_NONCE_BYTES} bytes (§23.4)`);
  }
  const context = selfTestContext(accountId, nonce);

  // Step 1: encrypt under the root's Recovery Encryption Public Key, decrypt with the private
  // read from the serialized kit.
  let publicKey: EnvelopePublicKey;
  try {
    publicKey = await importEnvelopePublicKey(descriptor.recovery_encryption_public_key);
  } catch (error) {
    return fail("MALFORMED_ROOT_PUBLIC_KEY", `recovery_encryption_public_key: ${String(error)}`, 1);
  }
  let decryptKey: EnvelopeDecryptKey;
  try {
    decryptKey = await importEnvelopeDecryptKey(encryptionPkcs8);
  } catch (error) {
    return fail("MALFORMED_KIT_PRIVATE_KEY", `recovery_encryption_private_key: ${String(error)}`, 1);
  }
  const secret = ports.randomBytes(SELF_TEST_SECRET_BYTES);
  try {
    const ciphertext = await sealEpochSecret(publicKey, context, secret);
    const plaintext = await openEpochSecret(decryptKey, context, ciphertext);
    const same = timingSafeEqual(plaintext, secret);
    zeroize(plaintext);
    if (!same) {
      return fail("ENCRYPTION_ROUND_TRIP_FAILED", "the kit decrypted the self-test secret to other bytes", 1);
    }
  } catch (error) {
    return fail("ENCRYPTION_ROUND_TRIP_FAILED", `the kit could not decrypt the self-test secret: ${String(error)}`, 1);
  } finally {
    zeroize(secret);
  }

  // Step 2: sign the same context with the kit's Recovery Authority private key, verify with the
  // public key of the root this check is about.
  let signingKey: SigningKey;
  try {
    signingKey = await importSigningKey(authorityPkcs8);
  } catch (error) {
    return fail("MALFORMED_KIT_PRIVATE_KEY", `recovery_authority_private_key: ${String(error)}`, 2);
  }
  let verifyingKey: VerifyingKey;
  try {
    verifyingKey = await importVerifyingKey(descriptor.recovery_authority_public_key);
  } catch (error) {
    return fail("MALFORMED_ROOT_PUBLIC_KEY", `recovery_authority_public_key: ${String(error)}`, 2);
  }
  const signature = await signContext(signingKey, context);
  if (!(await verifyContext(verifyingKey, context, signature))) {
    return fail("AUTHORITY_SIGNATURE_FAILED", "the kit's Recovery Authority key is not the root's", 2);
  }
  return { ok: true, value: nonce };
}

// --- The Managed escrow form (§35.2, §35.7, §35.14; ADR-021) -------------------------------------

/** `NCE(EscrowedRecoveryKeys)` (§23.4): what the RECOVERY escrow slot carries instead of a kit. */
export function serializeEscrowedRecoveryKeys(keys: RecoveryKeyPairs): Uint8Array {
  return encodeRecord(ESCROWED_RECOVERY_KEYS, escrowedRecoveryKeysOf(keys));
}

export function escrowedRecoveryKeysOf(keys: RecoveryKeyPairs): EscrowedRecoveryKeys {
  return {
    recovery_encryption_private_key: keys.encryption.privateKeyPkcs8,
    recovery_authority_private_key: keys.authority.privateKeyPkcs8,
  };
}

/**
 * §35.2 (Managed) and §35.14 step 5: "el self-test de §27.3 se hace sobre esa serialización" —
 * steps 1 and 2 with the privates read back from the `EscrowedRecoveryKeys` bytes, against the
 * pending Root Descriptor. There is no step 3: the record carries no public key hashes, and steps
 * 1 and 2 already bind the privates to that descriptor's public keys.
 */
export async function selfTestEscrowedRecoveryKeys(request: {
  readonly serialized: Uint8Array;
  readonly accountId: Uint8Array;
  readonly pendingDescriptor: RootDescriptor;
  readonly ports?: KeyLifecyclePorts;
}): Promise<Outcome<Uint8Array, RecoveryKitFailure>> {
  assertBytes(request.accountId, ID_BYTES, "account_id");
  let keys: EscrowedRecoveryKeys;
  try {
    keys = decodeRecord(ESCROWED_RECOVERY_KEYS, request.serialized);
  } catch (error) {
    return fail("MALFORMED_KIT", `not a canonical EscrowedRecoveryKeys: ${String(error)}`);
  }
  if (!timingSafeEqual(request.pendingDescriptor.account_id, request.accountId)) {
    return fail("ACCOUNT_MISMATCH", "the Root Descriptor belongs to another account");
  }
  return provePrivates(
    keys.recovery_encryption_private_key,
    keys.recovery_authority_private_key,
    request.pendingDescriptor,
    request.accountId,
    request.ports ?? defaultPorts,
  );
}

/**
 * §35.7 (Managed) steps 1–2: the Recovery privates the RECOVERY escrow slot returned, proved
 * against the root in force (§27.3 steps 1–2) and only then imported as the §27.2 handles.
 */
export async function openEscrowedRecoveryKeys(request: {
  readonly keys: EscrowedRecoveryKeys;
  readonly accountId: Uint8Array;
  readonly currentDescriptor: RootDescriptor;
  readonly ports?: KeyLifecyclePorts;
}): Promise<Outcome<Pick<RecoveryHandles, "encryptionKey" | "authorityKey">, RecoveryKitFailure>> {
  assertBytes(request.accountId, ID_BYTES, "account_id");
  if (!timingSafeEqual(request.currentDescriptor.account_id, request.accountId)) {
    return fail("ACCOUNT_MISMATCH", "the Root Descriptor belongs to another account");
  }
  const { recovery_encryption_private_key: encryption, recovery_authority_private_key: authority } = request.keys;
  const proved = await provePrivates(encryption, authority, request.currentDescriptor, request.accountId, request.ports ?? defaultPorts);
  if (!proved.ok) return proved;
  const [encryptionKey, authorityKey] = await Promise.all([importEnvelopeDecryptKey(encryption), importSigningKey(authority)]);
  return { ok: true, value: { encryptionKey, authorityKey } };
}

// --- Reading a kit (§27.2) ------------------------------------------------------------------------

/**
 * The two handles of the §27.2 table, both imported from PKCS#8 as **non-extractable**. This is
 * everything §35.7 and §35.9 get from a kit: `RECOVERY_CONTROL` and nothing more (§11.3). There
 * is no way back from these handles to the kit's bytes.
 */
export interface RecoveryHandles {
  readonly kit: RecoveryKit;
  /** `["decrypt"]`: opens the `RECOVERY` envelope of an epoch (§33.2, §35.7 step 5). */
  readonly encryptionKey: EnvelopeDecryptKey;
  /** `["sign"]`: signer role 3 of a `RECOVERY_RESET` (§28.2, §35.7 step 6). */
  readonly authorityKey: SigningKey;
}

/**
 * §35.7 steps 1–2, and nothing beyond them: import the kit's privates and prove they belong to
 * the root in force. The operation itself is `recoveryReset` (§35.7), which takes these handles;
 * §35.9 needs no kit at all, and says so.
 *
 * It runs the full "Verify Recovery Kit" first on purpose. Importing first and checking later
 * would hand a caller usable handles for a kit that does not match the root, and §35.7 step 2 is
 * the only thing standing between "this file decrypts something" and "this file controls this
 * account".
 */
export async function openRecoveryKit(
  request: RecoveryKitCheckRequest & { readonly currentDescriptor: RootDescriptor },
): Promise<Outcome<RecoveryHandles, RecoveryKitFailure>> {
  const proof = await verifyRecoveryKit(request);
  if (!proof.ok) return proof;
  const kit = proof.value.kit;
  const [encryptionKey, authorityKey] = await Promise.all([
    importEnvelopeDecryptKey(kit.recovery_encryption_private_key),
    importSigningKey(kit.recovery_authority_private_key),
  ]);
  return { ok: true, value: { kit, encryptionKey, authorityKey } };
}

function assertBytes(value: Uint8Array, length: number, what: string): void {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new KeyLifecycleError(`${what} must be ${length} bytes`);
  }
}
