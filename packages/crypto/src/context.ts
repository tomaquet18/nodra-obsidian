// Domain separation (§23.3). Every AAD, HKDF `info` and OAEP `label` in this package is a
// `DomainContext`, never a raw string or ad-hoc bytes, so `Context(domain, fields…)` is the only
// way to reach a primitive that takes one (§23.0 rule 6).
import { context } from "@nodra/encoding";
import type { NceDomain, NceValue } from "@nodra/encoding";

declare const domainContextBrand: unique symbol;

/**
 * NCE bytes of `[domain, 1, …fields]`. The brand is unforgeable outside this module: a plain
 * `Uint8Array` is not assignable to it, so no caller can pass a hand-built label by mistake.
 */
export type DomainContext = Uint8Array & { readonly [domainContextBrand]: "nodra/context" };

/** `Context(domain, fields…)` of §23.3, branded for use as AAD, HKDF `info` or OAEP `label`. */
export function domainContext(domain: NceDomain, ...fields: NceValue[]): DomainContext {
  return context(domain, ...fields) as DomainContext;
}

export type { NceDomain, NceValue };
