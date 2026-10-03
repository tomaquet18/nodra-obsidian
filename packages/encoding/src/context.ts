// Contexts with domain separation (§23.3): Context(domain, fields…) = NCE([domain, version = 1, fields…]).
import { encode } from "./nce.js";
import type { NceValue } from "./nce.js";

/**
 * The domains of §23.3: the 23 of `crypto_version = 1`, then the 2 that `crypto_version = 2` adds
 * (ADR-021), then `nodra/recovery-request` (ADR-022). A new domain or field change needs a new
 * crypto_version; ADR-022's is the one documented exception (§23.3).
 */
export const NCE_DOMAINS = [
  "nodra/root-descriptor",
  "nodra/root-transition",
  "nodra/registry",
  "nodra/epoch-descriptor",
  "nodra/envelope-set",
  "nodra/envelope-label",
  "nodra/hkdf/account-keywrap",
  "nodra/hkdf/account-config",
  "nodra/aad/account-private-key",
  "nodra/aad/account-config",
  "nodra/hkdf/content",
  "nodra/hkdf/manifest",
  "nodra/hkdf/dedup",
  "nodra/hkdf/epoch-commitment",
  "nodra/aad/content",
  "nodra/aad/manifest",
  "nodra/recovery-kit",
  "nodra/self-test",
  "nodra/profile-update",
  "nodra/write-capability",
  "nodra/write-capability-proof",
  "nodra/delete-vault",
  "nodra/delete-account",
  // crypto_version = 2 (ADR-021): OAEP label and AAD of an escrow slot, and of its ephemeral re-wrap.
  "nodra/escrow",
  "nodra/escrow-rewrap",
  // ADR-022 (§35.15), valid under every crypto_version by the explicit exception of §23.3: the
  // signature of a recovery request, veto or cancellation.
  "nodra/recovery-request",
] as const;

export type NceDomain = (typeof NCE_DOMAINS)[number];

/** Context version, fixed at 1 by §23.3. */
export const CONTEXT_VERSION = 1;

/** The NCE bytes of `[domain, 1, ...fields]`. Field lists per domain are the caller's (later slices). */
export function context(domain: NceDomain, ...fields: NceValue[]): Uint8Array {
  return encode([domain, CONTEXT_VERSION, ...fields]);
}
