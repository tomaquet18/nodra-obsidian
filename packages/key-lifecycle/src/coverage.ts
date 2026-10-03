// The coverage rule of §34: `RequiredEpochSet`, and whether a set of envelopes covers it.
//
// §34.2 is a rule about **recipients and epochs**, not about quantity: "ninguna clave pública
// nueva … se activa sin un envelope para cada epoch de `RequiredEpochSet`". So the checker below
// matches every (recipient, vault, epoch) triple by identity and reports each gap on its own. A
// checker that compared `envelopes.length` with the size of the required set would accept a bundle
// that covers one epoch twice and another not at all — exactly the shape §34.2 calls "falta uno,
// sobra uno, duplicado", and the shape the broken-variant test exhibits.
//
// Pure set logic over already-verified data: no I/O, no crypto, no clock.
import { timingSafeEqual } from "@nodra/crypto";
import type { EpochDescriptor, EpochEnvelope } from "@nodra/encoding/records";
import type { Outcome } from "./errors.js";
import { idKey } from "./epoch.js";
import type { EnvelopeRecipientType, RecipientIdentity } from "./epoch.js";

/** `listEpochDescriptors` (§22) returns this alongside each descriptor. It is **not** signed. */
export type EpochState = "ACTIVE" | "RETIRED";

/** The vault states §34.1 distinguishes (§35.11). */
export type VaultState = "ACTIVE" | "DELETING_SCHEDULED" | "DELETED";

export interface ListedEpoch {
  readonly descriptor: EpochDescriptor;
  readonly state: EpochState;
}

/** One vault's verified descriptor chain plus the unsigned state of each epoch (§34.3). */
export interface VaultEpochs {
  readonly vaultId: Uint8Array;
  readonly state: VaultState;
  readonly epochs: readonly ListedEpoch[];
}

/** One member of the `RequiredEpochSet` (§34.1). */
export interface RequiredEpoch {
  readonly vaultId: Uint8Array;
  readonly epochId: Uint8Array;
}

/**
 * §34.1 and §34.3: every non-`RETIRED` epoch of every vault that is `ACTIVE` or
 * `DELETING_SCHEDULED`. `DELETED` vaults are not part of any `RequiredEpochSet`.
 *
 * §34.1 phrases it as "los epochs en estado `ACTIVE`" and §34.3 as "cuyo `state` … no sea
 * `RETIRED`". With the two states `listEpochDescriptors` can return those are the same set; this
 * follows §34.3's wording, so a third state added later would fail closed (still required) rather
 * than silently drop out of coverage.
 */
export function requiredEpochSet(vaults: readonly VaultEpochs[]): readonly RequiredEpoch[] {
  const required: RequiredEpoch[] = [];
  for (const vault of vaults) {
    if (vault.state === "DELETED") continue;
    for (const epoch of vault.epochs) {
      if (epoch.state === "RETIRED") continue;
      required.push({ vaultId: vault.vaultId, epochId: epoch.descriptor.epoch_id });
    }
  }
  return required;
}

export type CoverageGapCode =
  /** §34.2 "falta uno": a required epoch has no envelope for this recipient. */
  | "MISSING_ENVELOPE"
  /** §34.2 "sobra uno": an envelope for a (vault, epoch) outside the required set. */
  | "UNEXPECTED_ENVELOPE"
  /** §34.2 "duplicado": two envelopes for the same (recipient, vault, epoch). */
  | "DUPLICATE_ENVELOPE"
  /** An envelope addressed to a recipient this operation is not covering. */
  | "UNKNOWN_RECIPIENT"
  /** The right `recipient_id` with the wrong `recipient_type`: a label that will not open (§32.2). */
  | "RECIPIENT_TYPE_MISMATCH";

export interface CoverageGap {
  readonly code: CoverageGapCode;
  readonly vaultId?: Uint8Array;
  readonly epochId?: Uint8Array;
  readonly recipientId?: Uint8Array;
  readonly message: string;
}

/**
 * §34.2 and §34.4: every discrepancy is the one answer `COVERAGE_STALE`, with the gaps attached
 * so a client can log what it got wrong. The Worker sends the current `RequiredEpochSet` back with
 * it; the client recomputes and retries.
 */
export interface CoverageFailure {
  readonly code: "COVERAGE_STALE";
  readonly gaps: readonly CoverageGap[];
  readonly message: string;
}

export interface CoverageRequest {
  /** From {@link requiredEpochSet}, computed over the same data the operation will commit against. */
  readonly required: readonly RequiredEpoch[];
  /** Every new public key this operation activates (§34.2): one envelope each, per required epoch. */
  readonly recipients: readonly RecipientIdentity[];
  readonly envelopes: readonly EpochEnvelope[];
  /**
   * Vaults already `DELETED`. §34.2 exception 2: an envelope for one of the account's own deleted
   * vaults is discarded without error rather than counted as "sobra uno".
   */
  readonly deletedVaultIds?: readonly Uint8Array[];
}

export interface CoverageResult {
  /** The envelopes that matched a required (recipient, vault, epoch), in the order given. */
  readonly envelopes: readonly EpochEnvelope[];
  /** Envelopes discarded under §34.2 exception 2 — a deleted vault of this same account. */
  readonly discarded: readonly EpochEnvelope[];
}

/**
 * Answers the one question §34.2 asks: does this envelope set cover **every** recipient of the
 * operation for **every** epoch of the required set, once each?
 */
export function checkCoverage(request: CoverageRequest): Outcome<CoverageResult, CoverageFailure> {
  const gaps: CoverageGap[] = [];
  const deleted = new Set((request.deletedVaultIds ?? []).map(idKey));
  const requiredSlots = new Set<string>();
  for (const epoch of request.required) {
    for (const recipient of request.recipients) {
      requiredSlots.add(slotKey(recipient.recipientId, epoch.vaultId, epoch.epochId));
    }
  }

  const types = new Map<string, EnvelopeRecipientType>(
    request.recipients.map((recipient) => [idKey(recipient.recipientId), recipient.type]),
  );
  const seen = new Set<string>();
  const matched: EpochEnvelope[] = [];
  const discarded: EpochEnvelope[] = [];

  for (const envelope of request.envelopes) {
    if (deleted.has(idKey(envelope.vault_id))) {
      discarded.push(envelope);
      continue;
    }
    const expectedType = types.get(idKey(envelope.recipient_id));
    if (expectedType === undefined) {
      gaps.push({
        code: "UNKNOWN_RECIPIENT",
        recipientId: envelope.recipient_id,
        vaultId: envelope.vault_id,
        epochId: envelope.epoch_id,
        message: "an envelope for a recipient this operation does not activate",
      });
      continue;
    }
    if (envelope.recipient_type !== expectedType) {
      gaps.push({
        code: "RECIPIENT_TYPE_MISMATCH",
        recipientId: envelope.recipient_id,
        vaultId: envelope.vault_id,
        epochId: envelope.epoch_id,
        message: `recipient_type ${envelope.recipient_type} does not match the recipient's ${expectedType}`,
      });
      continue;
    }
    const slot = slotKey(envelope.recipient_id, envelope.vault_id, envelope.epoch_id);
    if (!requiredSlots.has(slot)) {
      gaps.push({
        code: "UNEXPECTED_ENVELOPE",
        recipientId: envelope.recipient_id,
        vaultId: envelope.vault_id,
        epochId: envelope.epoch_id,
        message: "an envelope for an epoch outside the RequiredEpochSet",
      });
      continue;
    }
    if (seen.has(slot)) {
      gaps.push({
        code: "DUPLICATE_ENVELOPE",
        recipientId: envelope.recipient_id,
        vaultId: envelope.vault_id,
        epochId: envelope.epoch_id,
        message: "two envelopes for the same recipient and epoch",
      });
      continue;
    }
    seen.add(slot);
    matched.push(envelope);
  }

  for (const epoch of request.required) {
    for (const recipient of request.recipients) {
      if (seen.has(slotKey(recipient.recipientId, epoch.vaultId, epoch.epochId))) continue;
      gaps.push({
        code: "MISSING_ENVELOPE",
        recipientId: recipient.recipientId,
        vaultId: epoch.vaultId,
        epochId: epoch.epochId,
        message: "a required epoch has no envelope for this recipient",
      });
    }
  }

  if (gaps.length > 0) {
    return {
      ok: false,
      failure: {
        code: "COVERAGE_STALE",
        gaps,
        message: `the coverage envelopes do not match the RequiredEpochSet (${gaps.length} discrepancies)`,
      },
    };
  }
  return { ok: true, value: { envelopes: matched, discarded } };
}

/** True when `vaultId` is one of the required set's vaults — the §35.1.1 step 0c question. */
export function belongsToRequiredVaults(required: readonly RequiredEpoch[], vaultId: Uint8Array): boolean {
  return required.some((epoch) => timingSafeEqual(epoch.vaultId, vaultId));
}

function slotKey(recipientId: Uint8Array, vaultId: Uint8Array, epochId: Uint8Array): string {
  return `${idKey(recipientId)}/${idKey(vaultId)}/${idKey(epochId)}`;
}
