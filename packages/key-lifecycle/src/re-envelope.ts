// Privileged re-enveloping (§33.2): the only place in Nodra where an `epoch_secret` that was not
// just generated exists as bytes, and the only way a public key that did not exist when an epoch
// was created can ever read it (§34.2).
//
// §33.2 is four rules, and all four are load-bearing:
//
//   1. **Verify before re-enveloping.** The commitment is derived from the decrypted secret and
//      compared with the signed descriptor *before* the new envelope is sealed, so a broken or
//      substituted source envelope is never propagated to a second recipient.
//   2. **Round-trip every new envelope.** The Worker can only check presence (§32.3), so the
//      client that creates a coverage envelope is the only party that ever proves it opens. §33.2
//      makes this mandatory in every coverage operation, and {@link buildCoverage} therefore has
//      no way to skip it: the prover is a required argument.
//   3. **Zeroize.** The bytes are cleared in a `finally`, even when the seal throws. JavaScript
//      does not guarantee erasure; §33.2 says so itself and calls it best effort.
//   4. **Abort the whole operation on any failure.** Nothing partial is returned: the first bad
//      epoch stops the build, so a `SecurityBundle` is never assembled around an envelope whose
//      round-trip did not pass.
//
// The module is pure domain plus Web Crypto through `@nodra/crypto`: no network, no storage, and
// nothing here is ever persisted (§33.2: "nunca se persiste").
import {
  importHkdfBase,
  openEpochSecret,
  sealEpochSecret,
  importEnvelopePublicKey,
  timingSafeEqual,
  zeroize,
} from "@nodra/crypto";
import type { EnvelopeOpeningKey, EnvelopeUnwrapKey } from "@nodra/crypto";
import type { EpochDescriptor, EpochEnvelope } from "@nodra/encoding/records";
import { envelopeLabelContext } from "./contexts.js";
import type { RequiredEpoch } from "./coverage.js";
import {
  ENVELOPE_ALGORITHM_VERSION,
  deriveEpochCommitment,
  idKey,
  openEpoch,
  sealEnvelope,
} from "./epoch.js";
import type { EnvelopeRecipient, RecipientIdentity } from "./epoch.js";
import type { Outcome } from "./errors.js";

export type ReEnvelopeFailureCode =
  /** The source envelope names another vault, epoch, recipient or `algorithm_version` (§32.3). */
  | "ENVELOPE_MISBOUND"
  /** §33.2: the source did not decrypt, or its commitment is not the descriptor's (§32.3). */
  | "BROKEN_OR_WRONG_ENVELOPE"
  /** §33.2: the envelope just created does not open under the target's own private key. */
  | "ROUND_TRIP_FAILED"
  /**
   * The caller gave no source envelope for an epoch of the `RequiredEpochSet`. Not a §35.1.1 code:
   * the operation cannot be built at all, and sending it would earn `COVERAGE_STALE` (§34.2).
   */
  | "MISSING_SOURCE_ENVELOPE";

export interface ReEnvelopeFailure {
  readonly code: ReEnvelopeFailureCode;
  readonly vaultId?: Uint8Array;
  readonly epochId?: Uint8Array;
  readonly message: string;
}

/** One epoch a coverage operation must re-envelope: its signed descriptor and a readable envelope. */
export interface EnvelopeSource {
  /** A descriptor whose signature and chain `verifyEpochChain` already accepted (§34.3). */
  readonly descriptor: EpochDescriptor;
  /** The envelope this client can open: ACCOUNT during §35.4, RECOVERY during §35.7. */
  readonly envelope: EpochEnvelope;
}

/**
 * How the target proves it can open what was just sealed for it (§33.2, "Round-trip del envelope
 * nuevo"). The two cases are the two private-key shapes the spec names, and they produce the same
 * commitment: `["unwrapKey"]` takes the normal path of §33.1, while the recovery kit's
 * `["decrypt"]` key goes through `decrypt` → `importKey("raw", …, "HKDF")` → `deriveBits`.
 */
export type EnvelopeProver =
  | { readonly kind: "UNWRAP"; readonly privateKey: EnvelopeUnwrapKey }
  | { readonly kind: "DECRYPT"; readonly privateKey: EnvelopeOpeningKey };

export interface ReEnvelopeRequest {
  readonly source: EnvelopeSource;
  /** Whose envelope the source is, as the client knows itself — never read from the envelope. */
  readonly sourceRecipient: RecipientIdentity;
  /** §25.1 Operation handle (`["decrypt"]`), or the kit's Recovery Encryption private key. */
  readonly openingKey: EnvelopeOpeningKey;
  readonly target: EnvelopeRecipient;
}

function fail(
  code: ReEnvelopeFailureCode,
  message: string,
  epoch?: { readonly vaultId: Uint8Array; readonly epochId: Uint8Array },
): Outcome<never, ReEnvelopeFailure> {
  return {
    ok: false,
    failure: epoch === undefined ? { code, message } : { code, vaultId: epoch.vaultId, epochId: epoch.epochId, message },
  };
}

/**
 * §33.2 for one epoch: decrypt under the source label, check the commitment against the signed
 * descriptor, seal under the target label, zeroize. The result is **not** yet usable as coverage —
 * §33.2 requires the round-trip of {@link proveEnvelope} before the bundle is sent, which is why
 * {@link buildCoverage}, not this function, is what an operation calls.
 */
export async function reEnvelope(request: ReEnvelopeRequest): Promise<Outcome<EpochEnvelope, ReEnvelopeFailure>> {
  const { descriptor, envelope } = request.source;
  const vaultId = descriptor.vault_id;
  const epochId = descriptor.epoch_id;
  const where = { vaultId, epochId };

  const misbound = describeSourceMisbinding(envelope, vaultId, epochId, request.sourceRecipient);
  if (misbound !== null) return fail("ENVELOPE_MISBOUND", misbound, where);

  const sourceLabel = envelopeLabelContext(
    vaultId,
    epochId,
    request.sourceRecipient.recipientId,
    request.sourceRecipient.type,
  );

  let secret: Uint8Array;
  try {
    secret = await openEpochSecret(request.openingKey, sourceLabel, envelope.ciphertext);
  } catch {
    return fail("BROKEN_OR_WRONG_ENVELOPE", "the source envelope did not decrypt under this key and label", where);
  }
  try {
    const base = await importHkdfBase(secret);
    const commitment = await deriveEpochCommitment(base, vaultId, epochId);
    if (!timingSafeEqual(commitment, descriptor.epoch_commitment)) {
      return fail(
        "BROKEN_OR_WRONG_ENVELOPE",
        "the source envelope's commitment does not match the signed descriptor",
        where,
      );
    }
    // §32.2 sealed with the *target's* label: nothing of the source label survives into the copy.
    return { ok: true, value: await sealEnvelope(request.target, vaultId, epochId, secret) };
  } finally {
    zeroize(secret);
  }
}

/**
 * The round-trip of §33.2: opens a freshly created envelope with the target's own private key and
 * re-derives the commitment. This is the only cryptographic validation a new coverage envelope
 * ever receives, so a failure here aborts the operation rather than downgrading it.
 */
export async function proveEnvelope(
  descriptor: EpochDescriptor,
  envelope: EpochEnvelope,
  recipient: RecipientIdentity,
  prover: EnvelopeProver,
): Promise<Outcome<true, ReEnvelopeFailure>> {
  const where = { vaultId: descriptor.vault_id, epochId: descriptor.epoch_id };
  if (prover.kind === "UNWRAP") {
    const opened = await openEpoch({ descriptor, envelope, recipient, privateKey: prover.privateKey });
    if (!opened.ok) return fail("ROUND_TRIP_FAILED", opened.failure.message, where);
    return { ok: true, value: true };
  }

  const label = envelopeLabelContext(descriptor.vault_id, descriptor.epoch_id, recipient.recipientId, recipient.type);
  let secret: Uint8Array;
  try {
    secret = await openEpochSecret(prover.privateKey, label, envelope.ciphertext);
  } catch {
    return fail("ROUND_TRIP_FAILED", "the new envelope did not decrypt under the target's private key", where);
  }
  try {
    const commitment = await deriveEpochCommitment(await importHkdfBase(secret), descriptor.vault_id, descriptor.epoch_id);
    if (!timingSafeEqual(commitment, descriptor.epoch_commitment)) {
      return fail("ROUND_TRIP_FAILED", "the new envelope opens but yields another epoch commitment", where);
    }
    return { ok: true, value: true };
  } finally {
    zeroize(secret);
  }
}

export interface BuildCoverageRequest {
  /** From {@link requiredEpochSet} over the client's verified chains (§34.3). Drives the loop. */
  readonly required: readonly RequiredEpoch[];
  /** One readable envelope per required epoch; order is irrelevant, identity is not. */
  readonly sources: readonly EnvelopeSource[];
  readonly sourceRecipient: RecipientIdentity;
  readonly openingKey: EnvelopeOpeningKey;
  /** The key being activated: §35.4's new recipient, §35.7's new ACCOUNT, §35.9's new RECOVERY. */
  readonly target: EnvelopeRecipient;
  /** The target's own private key. Required: §33.2 makes the round-trip obligatory. */
  readonly prover: EnvelopeProver;
}

/**
 * §34.2 as a builder: exactly one envelope for every epoch of the `RequiredEpochSet`, each one
 * re-enveloped from a verified source and each one round-tripped.
 *
 * The loop is driven by `required`, never by `sources`: a client that iterated over the envelopes
 * the server happened to hand it would silently omit an epoch whose envelope was withheld and earn
 * `COVERAGE_STALE` with no idea why. Driving it from the required set turns that into a local
 * `MISSING_SOURCE_ENVELOPE` naming the epoch, before anything is sent.
 */
export async function buildCoverage(
  request: BuildCoverageRequest,
): Promise<Outcome<readonly EpochEnvelope[], ReEnvelopeFailure>> {
  const byEpoch = new Map<string, EnvelopeSource>();
  for (const source of request.sources) {
    byEpoch.set(`${idKey(source.descriptor.vault_id)}/${idKey(source.descriptor.epoch_id)}`, source);
  }

  const identity: RecipientIdentity = { recipientId: request.target.recipientId, type: request.target.type };
  // Fail fast if the SPKI is not importable, before any secret is decrypted.
  await importEnvelopePublicKey(request.target.publicKey);

  const envelopes: EpochEnvelope[] = [];
  for (const epoch of request.required) {
    const source = byEpoch.get(`${idKey(epoch.vaultId)}/${idKey(epoch.epochId)}`);
    if (source === undefined) {
      return fail(
        "MISSING_SOURCE_ENVELOPE",
        "no readable envelope was supplied for an epoch of the RequiredEpochSet",
        epoch,
      );
    }
    const created = await reEnvelope({
      source,
      sourceRecipient: request.sourceRecipient,
      openingKey: request.openingKey,
      target: request.target,
    });
    if (!created.ok) return created;

    const proved = await proveEnvelope(source.descriptor, created.value, identity, request.prover);
    if (!proved.ok) return proved;
    envelopes.push(created.value);
  }
  return { ok: true, value: envelopes };
}

function describeSourceMisbinding(
  envelope: EpochEnvelope,
  vaultId: Uint8Array,
  epochId: Uint8Array,
  recipient: RecipientIdentity,
): string | null {
  if (!timingSafeEqual(envelope.vault_id, vaultId)) return "the source envelope names another vault";
  if (!timingSafeEqual(envelope.epoch_id, epochId)) return "the source envelope names another epoch";
  if (!timingSafeEqual(envelope.recipient_id, recipient.recipientId)) {
    return "the source envelope names another recipient";
  }
  if (envelope.recipient_type !== recipient.type) return "the source envelope names another recipient type";
  if (envelope.algorithm_version !== ENVELOPE_ALGORITHM_VERSION) {
    return `unsupported envelope algorithm_version ${envelope.algorithm_version}`;
  }
  return null;
}
