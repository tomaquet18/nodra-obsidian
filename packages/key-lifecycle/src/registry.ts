// The Recipient Registry (§29): the signed, append-only list of `PLUGIN_INSTALLATION` and
// `TRUSTED_BROWSER` recipients. `ACCOUNT` and `RECOVERY` live in the Root Descriptor (§30.1) and
// never appear here.
//
// As with §28, the evolution rules live in exactly one place — {@link verifyRegistryChain} — and
// the builders enforce nothing, so the tests can feed the verifier correctly signed registries
// that break each rule in turn.
//
// This slice settles `packages/encoding` question 179: `recipients` ordering is a registry rule,
// not a codec one, and it is bullet 5 of §29 — strictly increasing `recipient_id`, no duplicates.
// "Increasing" is read as unsigned lexicographic order over the 16 raw bytes: a `recipient_id` is
// a UUIDv7 or the prefix of a SHA-256, so the bytes are the only total order the spec can mean
// (NOTES question 190).
import { hashContext, signContext, timingSafeEqual, verifyContext } from "@nodra/crypto";
import type { AnySigningKey, VerifyingKey } from "@nodra/crypto";
import { importVerifyingKey } from "@nodra/crypto";
import type { Registry, RegistryRecipient } from "@nodra/encoding/records";
import { registryContext } from "./contexts.js";
import type { Outcome } from "./errors.js";

/** A registry whose `signature` has not been produced yet. */
export type UnsignedRegistry = Omit<Registry, "signature">;

export type RecipientType = RegistryRecipient["type"];

/** What an enrollment adds (§35.4): everything but the version bookkeeping and the status. */
export interface NewRecipient {
  readonly recipientId: Uint8Array;
  readonly type: RecipientType;
  /** SPKI DER of the RSA-OAEP-3072 public key (§30.1). */
  readonly publicKey: Uint8Array;
  readonly label: string;
}

export type RegistryFailureCode =
  /** Nothing to verify, and no previously verified state to continue from. */
  | "EMPTY_CHAIN"
  /** A replay from nothing must start at version 1 with `previous_registry_hash` null. */
  | "NOT_INITIAL"
  /** §29: the registry names another account. */
  | "ACCOUNT_MISMATCH"
  /** §29 bullet 5: `recipients` out of order, or the same `recipient_id` twice. */
  | "UNSORTED_RECIPIENTS"
  /** A recipient contradicts itself: ACTIVE with a `revoked_version`, REVOKED without one, or
   *  versions outside `1 ≤ added_version ≤ revoked_version ≤ registry_version`. */
  | "MALFORMED_RECIPIENT"
  /** §29 bullet 1: `registry_version` is not exactly N + 1. */
  | "VERSION_NOT_CONSECUTIVE"
  /** §29 bullet 1: `previous_registry_hash` is not the hash of version N. */
  | "BROKEN_LINK"
  /** §29 bullet 2: a recipient of version N is missing from N + 1. */
  | "RECIPIENT_REMOVED"
  /** §29 bullet 2: `type`, `public_key`, `label` or `added_version` changed. */
  | "RECIPIENT_MUTATED"
  /** §29 bullet 3: any state transition other than ACTIVE → REVOKED — a revoked device returning. */
  | "ILLEGAL_STATUS_TRANSITION"
  /** §29 bullet 3: a revocation whose `revoked_version` is not N + 1, or that changed an old one. */
  | "BAD_REVOKED_VERSION"
  /** §29 bullet 4: a new recipient that does not enter ACTIVE at `added_version` = N + 1. */
  | "BAD_ADDED_VERSION"
  /** §29 bullet 6: a root transition's registry may only change `root_generation`, the signature
   *  and revocations — never add a recipient. */
  | "RECIPIENT_ADDED_ON_ROOT_TRANSITION"
  /** `root_generation` went backwards: generations only ever increase (§28.2 rule 4). */
  | "ROOT_GENERATION_REGRESSED"
  /** No Account Signing Key was supplied for this registry's `root_generation`. */
  | "UNKNOWN_ROOT_GENERATION"
  /** The signing key of that generation is not importable SPKI. */
  | "MALFORMED_PUBLIC_KEY"
  /** §29: the Account Signing signature of `root_generation` does not verify. */
  | "BAD_SIGNATURE"
  /** §29: the registry in force must carry the generation of the root in force. */
  | "STALE_ROOT_GENERATION"
  /** §29: a version below the client's pin. */
  | "PIN_ROLLBACK"
  /** §29: the pinned version is not this chain's — a forked registry history. */
  | "PIN_NOT_ANCESTOR";

export interface RegistryFailure {
  readonly code: RegistryFailureCode;
  /** The `registry_version` of the rejected registry, when the failure belongs to one. */
  readonly version?: number;
  readonly message: string;
}

/** What a trusted client pins (§28.3, §29). */
export interface RegistryPin {
  readonly registryVersion: number;
  readonly registryHash: Uint8Array;
}

export interface RegistryState {
  readonly registry: Registry;
  readonly registryHash: Uint8Array;
  /** Every registry hash the replay proved, by version — the ancestry a pin is checked against. */
  readonly hashes: ReadonlyMap<number, Uint8Array>;
}

export interface VerifyRegistryChainOptions {
  /** The `account_id` the caller authenticated with. Never read from the registry itself. */
  readonly accountId?: Uint8Array;
  /**
   * SPKI DER of the Account Signing Key of each root generation, from a chain already verified by
   * `verifyRootChain`. Data, not a port: the verifier stays pure and deterministic.
   */
  readonly accountSigningKeys: ReadonlyMap<number, Uint8Array>;
  /** A previously verified state to continue from; absent means "replay from version 1". */
  readonly from?: RegistryState;
  readonly pin?: RegistryPin;
  /** §29: the last version must carry exactly this generation. Omit to skip the check. */
  readonly currentRootGeneration?: number;
}

// --- Hashing and building -------------------------------------------------------------------

/** `registry_hash = SHA-256(Context("nodra/registry", registry sin signature))` (§29). */
export async function registryHash(registry: UnsignedRegistry): Promise<Uint8Array> {
  return hashContext(registryContext(registry));
}

/** Version 1: `previous_registry_hash` null, every recipient ACTIVE at `added_version` 1 (§29). */
export function initialRegistry(
  accountId: Uint8Array,
  rootGeneration: number,
  recipients: readonly NewRecipient[],
): UnsignedRegistry {
  return {
    account_id: accountId,
    registry_version: 1,
    previous_registry_hash: null,
    root_generation: rootGeneration,
    recipients: sortRecipients(recipients.map((r) => entering(r, 1))),
  };
}

export interface RegistryChange {
  readonly add?: readonly NewRecipient[];
  readonly revoke?: readonly Uint8Array[];
  /** Set on a root transition; omitted means "same generation" (§29 bullet 6). */
  readonly rootGeneration?: number;
}

/**
 * Version N + 1: `current` carried forward, the requested recipients added ACTIVE and the
 * requested ones marked REVOKED at N + 1. Enforces none of §29 — a caller can add on a root
 * transition, or "revoke" an id that is not there, and {@link verifyRegistryChain} will say so.
 */
export async function nextRegistry(current: Registry, change: RegistryChange = {}): Promise<UnsignedRegistry> {
  const version = current.registry_version + 1;
  const revoking = change.revoke ?? [];
  const carried = current.recipients.map((recipient) =>
    recipient.status === "ACTIVE" && revoking.some((id) => timingSafeEqual(id, recipient.recipient_id))
      ? { ...recipient, status: "REVOKED" as const, revoked_version: version }
      : recipient,
  );
  return {
    account_id: current.account_id,
    registry_version: version,
    previous_registry_hash: await registryHash(current),
    root_generation: change.rootGeneration ?? current.root_generation,
    recipients: sortRecipients([...carried, ...(change.add ?? []).map((r) => entering(r, version))]),
  };
}

/** Signs `Context("nodra/registry", registry sin signature)` with the Account Signing Key (§29). */
export async function signRegistry(draft: UnsignedRegistry, key: AnySigningKey): Promise<Registry> {
  return { ...draft, signature: await signContext(key, registryContext(draft)) };
}

function entering(recipient: NewRecipient, version: number): RegistryRecipient {
  return {
    recipient_id: recipient.recipientId,
    type: recipient.type,
    public_key: recipient.publicKey,
    label: recipient.label,
    status: "ACTIVE",
    added_version: version,
    revoked_version: null,
  };
}

/** Unsigned lexicographic order over the raw `recipient_id` bytes (§29 bullet 5). */
export function compareRecipientIds(a: Uint8Array, b: Uint8Array): number {
  const shared = Math.min(a.length, b.length);
  for (let i = 0; i < shared; i++) {
    const diff = (a[i] as number) - (b[i] as number);
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

function sortRecipients(recipients: readonly RegistryRecipient[]): readonly RegistryRecipient[] {
  return [...recipients].sort((a, b) => compareRecipientIds(a.recipient_id, b.recipient_id));
}

// --- Verification ---------------------------------------------------------------------------

function fail(code: RegistryFailureCode, message: string, version?: number): Outcome<never, RegistryFailure> {
  return { ok: false, failure: version === undefined ? { code, message } : { code, version, message } };
}

/** The checks that apply to one registry on its own, before it is compared with its predecessor. */
function checkShape(registry: Registry, accountId: Uint8Array): RegistryFailure | null {
  const version = registry.registry_version;
  if (!timingSafeEqual(accountId, registry.account_id)) {
    return { code: "ACCOUNT_MISMATCH", version, message: "the registry names another account" };
  }
  let previous: Uint8Array | null = null;
  for (const recipient of registry.recipients) {
    if (previous !== null && compareRecipientIds(previous, recipient.recipient_id) >= 0) {
      return {
        code: "UNSORTED_RECIPIENTS",
        version,
        message: "recipients must be in strictly increasing recipient_id order, without duplicates",
      };
    }
    previous = recipient.recipient_id;
    const active = recipient.status === "ACTIVE";
    if (active !== (recipient.revoked_version === null)) {
      return {
        code: "MALFORMED_RECIPIENT",
        version,
        message: `${recipient.status} recipient with revoked_version ${String(recipient.revoked_version)}`,
      };
    }
    if (recipient.added_version < 1 || recipient.added_version > version) {
      return { code: "MALFORMED_RECIPIENT", version, message: `added_version ${recipient.added_version} is not in 1..${version}` };
    }
    if (recipient.revoked_version !== null && (recipient.revoked_version < recipient.added_version || recipient.revoked_version > version)) {
      return {
        code: "MALFORMED_RECIPIENT",
        version,
        message: `revoked_version ${recipient.revoked_version} is not in ${recipient.added_version}..${version}`,
      };
    }
  }
  return null;
}

/** §29 bullets 2–4 and 6, between version N and N + 1. */
function checkEvolution(previous: Registry, next: Registry): RegistryFailure | null {
  const version = next.registry_version;
  if (version !== previous.registry_version + 1) {
    return {
      code: "VERSION_NOT_CONSECUTIVE",
      version,
      message: `expected registry_version ${previous.registry_version + 1}, got ${version}`,
    };
  }
  if (next.root_generation < previous.root_generation) {
    return {
      code: "ROOT_GENERATION_REGRESSED",
      version,
      message: `root_generation ${next.root_generation} is below ${previous.root_generation}`,
    };
  }
  const rootTransition = next.root_generation !== previous.root_generation;

  const byId = new Map<string, RegistryRecipient>();
  for (const recipient of next.recipients) byId.set(idKey(recipient.recipient_id), recipient);

  for (const before of previous.recipients) {
    const after = byId.get(idKey(before.recipient_id));
    if (after === undefined) {
      return { code: "RECIPIENT_REMOVED", version, message: "a recipient of the previous version is missing" };
    }
    byId.delete(idKey(before.recipient_id));
    if (
      after.type !== before.type ||
      after.label !== before.label ||
      after.added_version !== before.added_version ||
      !timingSafeEqual(after.public_key, before.public_key)
    ) {
      return { code: "RECIPIENT_MUTATED", version, message: "an existing recipient's immutable fields changed" };
    }
    if (before.status === "REVOKED") {
      if (after.status !== "REVOKED") {
        return { code: "ILLEGAL_STATUS_TRANSITION", version, message: "REVOKED → ACTIVE is not an allowed transition" };
      }
      if (after.revoked_version !== before.revoked_version) {
        return { code: "BAD_REVOKED_VERSION", version, message: "an existing revocation changed its revoked_version" };
      }
    } else if (after.status === "REVOKED" && after.revoked_version !== version) {
      return { code: "BAD_REVOKED_VERSION", version, message: `a revocation at version ${version} must set revoked_version = ${version}` };
    }
  }

  for (const added of byId.values()) {
    if (rootTransition) {
      return {
        code: "RECIPIENT_ADDED_ON_ROOT_TRANSITION",
        version,
        message: "a registry that changes root_generation may only change the generation, the signature and revocations",
      };
    }
    if (added.status !== "ACTIVE" || added.revoked_version !== null || added.added_version !== version) {
      return { code: "BAD_ADDED_VERSION", version, message: `a new recipient must enter ACTIVE with added_version = ${version}` };
    }
  }
  return null;
}

function idKey(id: Uint8Array): string {
  let out = "";
  for (const byte of id) out += byte.toString(16).padStart(2, "0");
  return out;
}

async function importOrNull(spki: Uint8Array): Promise<VerifyingKey | null> {
  try {
    return await importVerifyingKey(spki);
  } catch {
    return null;
  }
}

/**
 * Verifies a registry history from version 1 (or from an already verified state) up to the one in
 * force, and returns it. Pure and deterministic: the signing keys arrive as data, not as a lookup
 * the verifier performs.
 */
export async function verifyRegistryChain(
  versions: readonly Registry[],
  options: VerifyRegistryChainOptions,
): Promise<Outcome<RegistryState, RegistryFailure>> {
  let current: Registry | null = options.from?.registry ?? null;
  let currentHash: Uint8Array | null = options.from?.registryHash ?? null;
  const hashes = new Map<number, Uint8Array>(options.from?.hashes ?? []);
  let accountId: Uint8Array | null = options.accountId ?? current?.account_id ?? null;

  if (versions.length === 0 && current === null) {
    return fail("EMPTY_CHAIN", "a registry history must contain at least version 1");
  }

  for (const registry of versions) {
    const version = registry.registry_version;
    if (accountId === null) accountId = registry.account_id;

    const shape = checkShape(registry, accountId);
    if (shape !== null) return { ok: false, failure: shape };

    if (current === null) {
      if (version !== 1 || registry.previous_registry_hash !== null) {
        return fail("NOT_INITIAL", "a replay from nothing must start at version 1 with previous_registry_hash = null", version);
      }
      for (const recipient of registry.recipients) {
        if (recipient.status !== "ACTIVE" || recipient.added_version !== 1) {
          return fail("BAD_ADDED_VERSION", "every recipient of version 1 must be ACTIVE at added_version = 1", version);
        }
      }
    } else {
      const linked =
        registry.previous_registry_hash !== null &&
        currentHash !== null &&
        timingSafeEqual(currentHash, registry.previous_registry_hash);
      if (!linked) {
        return fail("BROKEN_LINK", "previous_registry_hash is not the hash of the previous version", version);
      }
      const evolution = checkEvolution(current, registry);
      if (evolution !== null) return { ok: false, failure: evolution };
    }

    const spki = options.accountSigningKeys.get(registry.root_generation);
    if (spki === undefined) {
      return fail("UNKNOWN_ROOT_GENERATION", `no Account Signing Key for root generation ${registry.root_generation}`, version);
    }
    const key = await importOrNull(spki);
    if (key === null) {
      return fail("MALFORMED_PUBLIC_KEY", `the Account Signing Key of generation ${registry.root_generation} is not importable SPKI`, version);
    }
    if (!(await verifyContext(key, registryContext(registry), registry.signature))) {
      return fail("BAD_SIGNATURE", `the Account Signing signature of generation ${registry.root_generation} does not verify`, version);
    }

    current = registry;
    currentHash = await registryHash(registry);
    hashes.set(version, currentHash);
  }

  if (current === null || currentHash === null) {
    return fail("EMPTY_CHAIN", "a registry history must contain at least version 1");
  }

  const pin = options.pin;
  if (pin !== undefined) {
    if (current.registry_version < pin.registryVersion) {
      return fail("PIN_ROLLBACK", `version ${current.registry_version} is below the pinned ${pin.registryVersion}`, current.registry_version);
    }
    const pinned = hashes.get(pin.registryVersion);
    if (pinned === undefined || !timingSafeEqual(pinned, pin.registryHash)) {
      return fail("PIN_NOT_ANCESTOR", `the pinned registry at version ${pin.registryVersion} is not on this history`);
    }
  }

  if (options.currentRootGeneration !== undefined && current.root_generation !== options.currentRootGeneration) {
    return fail(
      "STALE_ROOT_GENERATION",
      `the registry in force carries root generation ${current.root_generation}, the root in force is ${options.currentRootGeneration}`,
      current.registry_version,
    );
  }

  return { ok: true, value: { registry: current, registryHash: currentHash, hashes } };
}

/** The ACTIVE recipients of a verified registry — the only keys a client may encrypt to (§29). */
export function activeRecipients(registry: Registry): readonly RegistryRecipient[] {
  return registry.recipients.filter((recipient) => recipient.status === "ACTIVE");
}
