// §35.3, §35.4 and §35.8: how a client becomes — or becomes again — a trusted recipient.
//
// §35.3 is a client that enrols nothing: it unlocks a Session handle, reads, and consumes no slot.
// The only artefact it produces that outlives the session is the key pair of §35.4 step 2, which
// is why {@link prepareEnrollment} stands on its own: the pair must exist (and its private half
// must be storable, non-extractable, in IndexedDB) before any bundle is built, and the same pair
// is what §33.2's round-trip is later proved against.
//
// §35.4 is then one bundle: a registry with the recipient ACTIVE, a coverage envelope for every
// epoch of the `RequiredEpochSet`, and a rewritten config. The coverage is not copied from an
// existing envelope — an envelope is sealed to one public key under a label naming one recipient
// (§32.2), so a copy would be a ciphertext the new client cannot open and the Worker cannot
// detect (§32.3). {@link enrollClient} therefore goes through §33.2 for every epoch, including
// the mandatory round-trip, and refuses to produce a bundle if any of them fails.
//
// §35.8 is not a bundle at all: it is what a client does to *itself* after a reset it accepted,
// before running §35.4 again with the new secrets.
import { generateRecipientKeyPair, exportEnvelopePublicKey, timingSafeEqual } from "@nodra/crypto";
import type { EnvelopeUnwrapKey } from "@nodra/crypto";
import { SECURITY_BUNDLE, encodeRecord } from "@nodra/encoding/records";
import type { AccountSecurityConfig, EpochEnvelope, Registry, SecurityBundle } from "@nodra/encoding/records";
import { assembleBundle } from "./bundle-build.js";
import type { AccountView, ClientPins, OperationFailure, OperationKeys } from "./client-state.js";
import { expectedOf, sealNextConfig } from "./client-state.js";
import { requiredEpochSet } from "./coverage.js";
import { rootRecipients } from "./epoch.js";
import type { EnvelopeRecipient, RecipientIdentity } from "./epoch.js";
import type { Outcome } from "./errors.js";
import { buildCoverage } from "./re-envelope.js";
import type { EnvelopeProver, EnvelopeSource, ReEnvelopeFailureCode } from "./re-envelope.js";
import { nextRegistry, registryHash, signRegistry } from "./registry.js";
import type { NewRecipient, RecipientType } from "./registry.js";

// --- §35.4 step 2: the new client's key pair -----------------------------------------------------

export interface EnrollmentKeys {
  /** The public half, in the form the Registry stores and an envelope is sealed to (§29, §30.1). */
  readonly recipient: NewRecipient;
  /** §35.4 step 6: persisted as a non-extractable `CryptoKey` in IndexedDB, never as bytes. */
  readonly privateKey: EnvelopeUnwrapKey;
  /** The same key as §33.2's round-trip needs it: `["unwrapKey"]`, so the normal path of §33.1. */
  readonly prover: EnvelopeProver;
}

export interface PrepareEnrollmentRequest {
  /** UUIDv7 (§30.1). The caller's, like every other id in this package. */
  readonly recipientId: Uint8Array;
  readonly type: RecipientType;
  /** What the device list of §35.1 will show for this client. */
  readonly label: string;
}

/**
 * §35.4 step 2 / §35.2 step 11: generate the recipient pair. The private key is non-extractable
 * and `["unwrapKey"]`-only (§30.1), so it can open an envelope into an `EpochKey` and can never
 * hand the `epoch_secret` back as bytes — §30.2 is honest that this is not a defence against
 * same-origin malicious code, only against this package's own mistakes.
 */
export async function prepareEnrollment(request: PrepareEnrollmentRequest): Promise<EnrollmentKeys> {
  const pair = await generateRecipientKeyPair();
  const spki = await exportEnvelopePublicKey(pair.publicKey);
  return {
    recipient: {
      recipientId: request.recipientId,
      type: request.type,
      publicKey: spki,
      label: request.label,
    },
    privateKey: pair.privateKey,
    prover: { kind: "UNWRAP", privateKey: pair.privateKey },
  };
}

// --- §35.4: the ENROLL_CLIENT bundle -------------------------------------------------------------

export type EnrollClientFailureCode = ReEnvelopeFailureCode;

export type EnrollClientFailure = OperationFailure<EnrollClientFailureCode>;

export interface EnrollClientRequest {
  /** The verified state the operation is prepared over (§26, §28.3, §29, §34.3). */
  readonly view: AccountView;
  readonly bundleId: Uint8Array;
  /** The public half from {@link prepareEnrollment}, or from the client asking to be trusted. */
  readonly recipient: NewRecipient;
  /** That client's private key. §33.2 makes the round-trip obligatory, so this is not optional. */
  readonly prover: EnvelopeProver;
  /** §25.1: the Operation handle for §33.2, the Signing handle, and the `AccountConfigKey`. */
  readonly keys: OperationKeys;
  /**
   * The ACCOUNT envelope of every epoch of the `RequiredEpochSet`, from `listEpochEnvelopes`
   * (§22). Each one is verified against its signed descriptor before it is re-enveloped (§33.2).
   */
  readonly sources: readonly EnvelopeSource[];
}

export interface EnrolledClient {
  readonly bundle: SecurityBundle;
  /** §35.4 step 6: the exact bytes to persist as PENDING before the bundle is sent. */
  readonly serializedBundle: Uint8Array;
  /** §35.4 step 6/8: the id whose PENDING private key step 8 resolves. */
  readonly pendingRecipientId: Uint8Array;
  readonly registry: Registry;
  readonly registryHash: Uint8Array;
  readonly config: AccountSecurityConfig;
  readonly configBlob: Uint8Array;
  readonly configVersion: number;
  readonly coverageEnvelopes: readonly EpochEnvelope[];
  /** §35.4 step 8: the pins to persist once the result comes back applied. */
  readonly pins: ClientPins;
}

/**
 * §35.4 steps 3–5, in that order, returning what steps 6–8 need.
 *
 * The coverage loop is driven by the `RequiredEpochSet` computed from the client's own verified
 * chains (§34.3), not by the envelopes the server offered: an epoch whose source envelope is
 * missing stops the operation here, with the epoch named, instead of earning a `COVERAGE_STALE`
 * the client cannot explain (§34.2).
 */
export async function enrollClient(
  request: EnrollClientRequest,
): Promise<Outcome<EnrolledClient, EnrollClientFailure>> {
  const { view, keys } = request;

  // Step 3: the registry that activates the recipient. Its root generation does not move (§29).
  const registry = await signRegistry(
    await nextRegistry(view.registry, { add: [request.recipient] }),
    keys.signingKey,
  );
  const rHash = await registryHash(registry);

  // Step 4: §33.2 for every epoch of the RequiredEpochSet, each one round-tripped.
  const account = (await rootRecipients(view.root))[0] as EnvelopeRecipient;
  const target: EnvelopeRecipient = {
    recipientId: request.recipient.recipientId,
    type: request.recipient.type,
    publicKey: request.recipient.publicKey,
  };
  const sourceRecipient: RecipientIdentity = { recipientId: account.recipientId, type: account.type };
  const coverage = await buildCoverage({
    required: requiredEpochSet(view.vaults),
    sources: request.sources,
    sourceRecipient,
    openingKey: keys.operationKey,
    target,
    prover: request.prover,
  });
  if (!coverage.ok) {
    const { code, vaultId, epochId, message } = coverage.failure;
    return {
      ok: false,
      failure: {
        code,
        step: 4,
        ...(vaultId === undefined ? {} : { vaultId }),
        ...(epochId === undefined ? {} : { epochId }),
        message,
      },
    };
  }

  // Step 5: the config, rewritten under the same root and the new registry (§26).
  const sealed = await sealNextConfig(keys.configKey, {
    root: view.root,
    rootHash: view.rootHash,
    genesisRootHash: view.genesisRootHash,
    registryVersion: registry.registry_version,
    registryHash: rHash,
    configVersion: view.configVersion + 1,
  });

  const bundle = assembleBundle({
    operationType: "ENROLL_CLIENT",
    bundleId: request.bundleId,
    expected: expectedOf(view),
    registry,
    configBlob: sealed.blob,
    configVersion: sealed.configVersion,
    coverageEnvelopes: coverage.value,
  });

  return {
    ok: true,
    value: {
      bundle,
      serializedBundle: encodeRecord(SECURITY_BUNDLE, bundle),
      pendingRecipientId: request.recipient.recipientId,
      registry,
      registryHash: rHash,
      config: sealed.config,
      configBlob: sealed.blob,
      configVersion: sealed.configVersion,
      coverageEnvelopes: coverage.value,
      pins: {
        rootGeneration: view.root.root_generation,
        rootHash: view.rootHash,
        genesisRootHash: view.genesisRootHash,
        registryVersion: registry.registry_version,
        registryHash: rHash,
        configVersion: sealed.configVersion,
        // ENROLL_CLIENT rotates nothing (§35.1), so every vault keeps the epoch pin it had.
        epochs: view.vaults.flatMap((vault) =>
          vault.current === null
            ? []
            : [
                {
                  vaultId: vault.vaultId,
                  epochId: vault.current.epochId,
                  descriptorHash: vault.current.descriptorHash,
                },
              ],
        ),
      },
    },
  };
}

// --- §35.8: re-enrollment after a reset ----------------------------------------------------------

export type ReEnrollmentFailureCode =
  /**
   * The accepted state does not extend this client's pins: the generation it pinned is absent from
   * the replayed chain, or carries another hash. §26's "continuidad de pins" updates pins from a
   * transition the client *verified*; a fork is not one, and adopting it would be exactly the
   * rollback §26 warns about.
   */
  "PINS_NOT_CONTINUOUS";

export type ReEnrollmentFailure = OperationFailure<ReEnrollmentFailureCode>;

/** §35.8 step 2: what survives a reset. The Device Local Key is regenerated only if absent. */
export type RetainedState = "CACHE" | "OUTBOX" | "DEVICE_LOCAL_KEY";

export interface ReEnrollmentRequest {
  /** The state after the transition, already verified by `verifyRootChain` (§28.3). */
  readonly accepted: AccountView;
  /** Every root hash that replay proved, by generation — `RootState.hashes`. */
  readonly rootHashes: ReadonlyMap<number, Uint8Array>;
  /** What this client pinned before the reset. */
  readonly previous: ClientPins;
  /** §35.8 step 3: the recipient whose private key is now useless and MUST be discarded. */
  readonly recipientId: Uint8Array;
}

export interface ReEnrollmentPlan {
  /** Step 1: the pins to adopt, from the verified transition. */
  readonly pins: ClientPins;
  /** Step 2: what is kept. §18.3 keeps the outbox so unsent work is not lost by a reset. */
  readonly retained: readonly RetainedState[];
  /** Step 3: the private key to delete before anything else happens. */
  readonly discardedRecipientId: Uint8Array;
  /** Step 4: §35.4 runs next, with the new secrets and a **new** pair — never the discarded one. */
  readonly next: "ENROLL_CLIENT";
}

const RETAINED: readonly RetainedState[] = ["CACHE", "OUTBOX", "DEVICE_LOCAL_KEY"];

/**
 * §35.8 for a client that accepted the transition: the four steps as one plan, with the single
 * check the spec's step 1 implies — that the new chain really is a continuation of what this
 * client already trusted (§26, §28.3). Everything else §35.8 lists is a decision about local
 * state, which is why this returns a plan rather than performing it: the stores it names
 * (IndexedDB cache, outbox, Device Local Key) are outside this package (§22.1).
 */
export function planReEnrollment(
  request: ReEnrollmentRequest,
): Outcome<ReEnrollmentPlan, ReEnrollmentFailure> {
  const pinned = request.rootHashes.get(request.previous.rootGeneration);
  if (pinned === undefined || !timingSafeEqual(pinned, request.previous.rootHash)) {
    return {
      ok: false,
      failure: {
        code: "PINS_NOT_CONTINUOUS",
        step: 1,
        message: "the accepted root chain does not contain this client's pinned root",
      },
    };
  }
  const accepted = request.accepted;
  return {
    ok: true,
    value: {
      pins: {
        rootGeneration: accepted.root.root_generation,
        rootHash: accepted.rootHash,
        genesisRootHash: accepted.genesisRootHash,
        registryVersion: accepted.registry.registry_version,
        registryHash: accepted.registryHash,
        configVersion: accepted.configVersion,
        epochs: accepted.vaults.flatMap((vault) =>
          vault.current === null
            ? []
            : [{ vaultId: vault.vaultId, epochId: vault.current.epochId, descriptorHash: vault.current.descriptorHash }],
        ),
      },
      retained: RETAINED,
      discardedRecipientId: request.recipientId,
      next: "ENROLL_CLIENT",
    },
  };
}
