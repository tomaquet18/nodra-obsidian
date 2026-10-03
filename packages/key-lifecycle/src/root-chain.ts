// The root chain (§28): Root Descriptors, Root Transitions, and the replay that turns a chain
// into the current root state.
//
// §28.2 says the validation is "Worker y clientes, idéntica", so there is exactly **one**
// implementation of it here — {@link verifyRootChain} — and the builders below are deliberately
// dumb: they assemble and sign whatever they are given and enforce no policy at all. A builder
// that refused to produce an invalid transition would silently become a second, weaker copy of
// the rules, and the tests could no longer feed the verifier the structures a hostile Worker can
// actually send (correctly signed, but with a forbidden key change or a reused generation).
//
// Pure domain: no network, no storage, no DOM, no clock — §28 has no timestamps. Every function
// is async only because Web Crypto is.
import { hashContext, importVerifyingKey, signContext, timingSafeEqual, verifyContext } from "@nodra/crypto";
import type { AnySigningKey, VerifyingKey } from "@nodra/crypto";
import { TRANSITION_SIGNER_ROLES } from "@nodra/encoding/records";
import type { RootDescriptor, RootTransition } from "@nodra/encoding/records";
import { rootDescriptorContext, rootTransitionContext } from "./contexts.js";
import { KeyLifecycleError } from "./errors.js";
import type { Outcome } from "./errors.js";
import { isSupportedCryptoVersion } from "./unlock.js";

/** The five transition types the MVP accepts (§28.2). Anything else is rejected by the codec. */
export type TransitionType = RootTransition["transition_type"];

/** The four signer role codes of §28.2. */
export type SignerRole = (typeof TRANSITION_SIGNER_ROLES)[number];

/** A transition with the `signatures` still to be produced. */
export type UnsignedRootTransition = Omit<RootTransition, "signatures">;

/**
 * §28.2, column "Firmas requeridas", in ascending role order — which is also the order the
 * `signatures` collection must be in.
 */
export const REQUIRED_SIGNER_ROLES: Readonly<Record<TransitionType, readonly SignerRole[]>> = {
  GENESIS: [2, 4],
  RECOVERY_RESET: [2, 3],
  RECOVERY_KIT_REPLACEMENT: [1, 4],
  // §35.13: 1 authorizes; 2 and 4 prove possession of the new account and recovery keys.
  SWITCH_TO_PRIVATE: [1, 2, 4],
  // §35.14: 1 authorizes; 4 proves possession of the new recovery keys.
  SWITCH_TO_MANAGED: [1, 4],
};

/** The four public keys of a Root Descriptor, as SPKI DER (§28.1). */
export interface RootPublicKeys {
  readonly accountEncryption: Uint8Array;
  readonly accountSigning: Uint8Array;
  readonly recoveryEncryption: Uint8Array;
  readonly recoveryAuthority: Uint8Array;
}

/**
 * §28.2, column "Cambia", as data: the descriptor keys each transition type MUST change, and
 * therefore (by "solo cambian las claves de la columna") the ones it MUST leave identical.
 * `GENESIS` creates everything, so it has no previous descriptor to compare against.
 */
export const CHANGED_KEYS: Readonly<Record<TransitionType, readonly (keyof RootPublicKeys)[]>> = {
  GENESIS: ["accountEncryption", "accountSigning", "recoveryEncryption", "recoveryAuthority"],
  RECOVERY_RESET: ["accountEncryption", "accountSigning"],
  RECOVERY_KIT_REPLACEMENT: ["recoveryEncryption", "recoveryAuthority"],
  SWITCH_TO_PRIVATE: ["accountEncryption", "accountSigning", "recoveryEncryption", "recoveryAuthority"],
  SWITCH_TO_MANAGED: ["recoveryEncryption", "recoveryAuthority"],
};

/** §3.6: the protection mode of an account. */
export type ProtectionMode = "MANAGED" | "PRIVATE";

/**
 * §3.6 "Derivación del modo en el cliente": only GENESIS and the two switches set the mode — a
 * version-2 GENESIS or a SWITCH_TO_MANAGED makes the account Managed, a version-1 GENESIS or a
 * SWITCH_TO_PRIVATE makes it Private — and every other transition keeps it. The client never takes
 * the mode the server declares; it replays the verified chain through this.
 */
export function modeAfter(previous: ProtectionMode | null, transition: TransitionType, cryptoVersion: number): ProtectionMode {
  switch (transition) {
    case "GENESIS":
      return cryptoVersion === 2 ? "MANAGED" : "PRIVATE";
    case "SWITCH_TO_MANAGED":
      return "MANAGED";
    case "SWITCH_TO_PRIVATE":
      return "PRIVATE";
    case "RECOVERY_RESET":
    case "RECOVERY_KIT_REPLACEMENT":
      if (previous === null) throw new KeyLifecycleError(`${transition} cannot start a chain`);
      return previous;
  }
}

/** Descriptor field of each logical key, so the two tables above can drive the checks. */
const KEY_FIELD: Readonly<Record<keyof RootPublicKeys, keyof RootDescriptor>> = {
  accountEncryption: "account_encryption_public_key",
  accountSigning: "account_signing_public_key",
  recoveryEncryption: "recovery_encryption_public_key",
  recoveryAuthority: "recovery_authority_public_key",
};

const ALL_KEYS = Object.keys(KEY_FIELD) as (keyof RootPublicKeys)[];

export type RootChainFailureCode =
  /** No links to replay, and no pinned state to fall back on. */
  | "EMPTY_CHAIN"
  /** A replay that starts from nothing must start at `GENESIS`… */
  | "NOT_GENESIS"
  /** …and must never meet a second one (§28.2: `old_root_hash` is null only in GENESIS). */
  | "UNEXPECTED_GENESIS"
  /** §28.2 rule 0: the signature roles are not exactly the required set, ascending. */
  | "BAD_SIGNATURE_SET"
  /** §28.2 rule 1: a required signature does not verify under the key its role names. */
  | "BAD_SIGNATURE"
  /** An SPKI DER in a descriptor is not an importable P-256 public key. */
  | "MALFORMED_PUBLIC_KEY"
  /** §28.2 rule 2: `new_root_hash` is not the hash of the descriptor that came with it. */
  | "ROOT_HASH_MISMATCH"
  /** §28.2 rule 3: `old_root_hash`, or the new descriptor's `previous_root_hash`, breaks the link. */
  | "BROKEN_LINK"
  /** §28.2 rule 4: not exactly the current generation + 1, or not equal to the descriptor's. */
  | "GENERATION_NOT_CONSECUTIVE"
  /** §28.2 rule 5: `account_id` changed, or does not match the one the caller expects. */
  | "ACCOUNT_MISMATCH"
  /** §28.2 rule 5: `crypto_version` changed other than 1 → 2 in a SWITCH_TO_MANAGED, or a SWITCH_TO_MANAGED did not end at 2. */
  | "CRYPTO_VERSION_CHANGED"
  /** §23.0 rule 7: a `crypto_version` this client does not implement. Never degrade silently. */
  | "UNSUPPORTED_CRYPTO_VERSION"
  /** §28.2 rule 6: a key changed that this type may not change, or one that MUST change did not. */
  | "FORBIDDEN_KEY_CHANGE"
  /** §28.3: the chain ends at or below the pinned generation — a replay of an older chain. */
  | "PIN_ROLLBACK"
  /** §28.3: the pinned root is not on this chain — a fork, not a continuation. */
  | "PIN_NOT_ANCESTOR";

export interface RootChainFailure {
  readonly code: RootChainFailureCode;
  /** Generation the rejected link claimed, when the failure belongs to one link. */
  readonly generation?: number;
  readonly message: string;
}

/** One link: a transition and the Root Descriptor it installs (§28.2 rule 2, "el incluido"). */
export interface RootChainLink {
  readonly transition: RootTransition;
  readonly descriptor: RootDescriptor;
}

/** What a trusted client pins (§28.3). */
export interface RootPin {
  readonly rootGeneration: number;
  readonly rootHash: Uint8Array;
}

/** The result of a replay: the root in force, plus everything §28.3 asks a client to remember. */
export interface RootState {
  readonly descriptor: RootDescriptor;
  readonly rootHash: Uint8Array;
  readonly rootGeneration: number;
  /** Null when the replay started from a pin rather than from GENESIS. */
  readonly genesisRootHash: Uint8Array | null;
  /** Every root hash the replay proved, by generation — the ancestry a pin is checked against. */
  readonly hashes: ReadonlyMap<number, Uint8Array>;
  /** §3.6: the mode derived from the chain (carried over from `from` when the replay continues). */
  readonly mode: ProtectionMode;
}

export interface VerifyRootChainOptions {
  /** The `account_id` the caller authenticated with. Never read from the chain itself. */
  readonly accountId?: Uint8Array;
  /** A previously verified state to continue from; absent means "replay from GENESIS". */
  readonly from?: RootState;
  /** §28.3: the replayed chain must contain this exact root and end at or above it. */
  readonly pin?: RootPin;
}

// --- Hashing and building -------------------------------------------------------------------

/** `root_hash = SHA-256(Context("nodra/root-descriptor", RootDescriptor))` (§28.1). */
export async function rootHash(descriptor: RootDescriptor): Promise<Uint8Array> {
  return hashContext(rootDescriptorContext(descriptor));
}

/** The GENESIS descriptor: generation 1, `previous_root_hash` null (§28.2 rules 3–4). */
export function genesisDescriptor(
  accountId: Uint8Array,
  keys: RootPublicKeys,
  // §3.6: a version-1 GENESIS is a Private account; a version-2 one is Managed.
  cryptoVersion: number = 1,
): RootDescriptor {
  return {
    account_id: accountId,
    root_generation: 1,
    account_encryption_public_key: keys.accountEncryption,
    account_signing_public_key: keys.accountSigning,
    recovery_encryption_public_key: keys.recoveryEncryption,
    recovery_authority_public_key: keys.recoveryAuthority,
    previous_root_hash: null,
    crypto_version: cryptoVersion,
  };
}

/**
 * The next descriptor: `current` with the given keys replaced, the generation incremented and
 * `previous_root_hash` set to the hash of `current`. It does **not** check that the replacements
 * are the ones the transition type allows — {@link verifyRootChain} owns that rule.
 */
export async function nextDescriptor(
  current: RootDescriptor,
  replacements: Partial<RootPublicKeys>,
  // §35.14 step 7: a SWITCH_TO_MANAGED from a version-1 root installs a version-2 one.
  cryptoVersion: number = current.crypto_version,
): Promise<RootDescriptor> {
  const next: RootDescriptor = {
    ...current,
    root_generation: current.root_generation + 1,
    previous_root_hash: await rootHash(current),
    crypto_version: cryptoVersion,
  };
  for (const name of ALL_KEYS) {
    const replacement = replacements[name];
    if (replacement !== undefined) (next as Record<string, unknown>)[KEY_FIELD[name]] = replacement;
  }
  return next;
}

export interface SignRootTransitionRequest {
  readonly type: TransitionType;
  /** The Root Descriptor this transition installs. */
  readonly descriptor: RootDescriptor;
  /** The root in force, or null/absent for GENESIS. */
  readonly previous?: RootDescriptor | null;
  /** One handle per role code (§28.2). Roles the type does not require are ignored. */
  readonly signers: Partial<Record<SignerRole, AnySigningKey>>;
}

/**
 * Assembles a transition over `Context("nodra/root-transition", campos 1–5)` and signs it with
 * exactly the roles §28.2 requires, in ascending order. A missing required signer is a
 * programming error in the caller, so it throws rather than returning a failure.
 */
export async function signRootTransition(request: SignRootTransitionRequest): Promise<RootTransition> {
  const previous = request.previous ?? null;
  const unsigned: UnsignedRootTransition = {
    account_id: request.descriptor.account_id,
    transition_type: request.type,
    old_root_hash: previous === null ? null : await rootHash(previous),
    new_root_hash: await rootHash(request.descriptor),
    new_root_generation: request.descriptor.root_generation,
  };
  const ctx = rootTransitionContext(unsigned);
  const signatures: { code: SignerRole; value: Uint8Array }[] = [];
  for (const role of REQUIRED_SIGNER_ROLES[request.type]) {
    const key = request.signers[role];
    if (key === undefined) {
      throw new KeyLifecycleError(`${request.type} needs a signer for role ${role} (§28.2)`);
    }
    signatures.push({ code: role, value: await signContext(key, ctx) });
  }
  return { ...unsigned, signatures };
}

// --- Verification ---------------------------------------------------------------------------

function fail(code: RootChainFailureCode, message: string, generation?: number): Outcome<never, RootChainFailure> {
  return { ok: false, failure: generation === undefined ? { code, message } : { code, generation, message } };
}

/** §28.2 rule 0: exactly the required roles, no extras, no duplicates, ascending. */
function rolesAreExactly(transition: RootTransition, required: readonly SignerRole[]): boolean {
  const present = transition.signatures;
  if (present.length !== required.length) return false;
  for (let i = 0; i < present.length; i++) {
    const pair = present[i];
    if (pair === undefined || pair.code !== required[i]) return false;
    if (i > 0 && pair.code <= (present[i - 1] as { code: number }).code) return false;
  }
  return true;
}

/**
 * §28.2 rule 1: roles 1 and 3 verify against the root **in force**, roles 2 and 4 against the
 * **new** descriptor carried by the transition. GENESIS has no root in force, and the table
 * never asks it for role 1 or 3.
 */
function verifierSpki(role: SignerRole, current: RootDescriptor | null, next: RootDescriptor): Uint8Array | null {
  switch (role) {
    case 1:
      return current === null ? null : current.account_signing_public_key;
    case 2:
      return next.account_signing_public_key;
    case 3:
      return current === null ? null : current.recovery_authority_public_key;
    case 4:
      return next.recovery_authority_public_key;
  }
}

async function importOrNull(spki: Uint8Array): Promise<VerifyingKey | null> {
  try {
    return await importVerifyingKey(spki);
  } catch {
    return null;
  }
}

function keyBytes(descriptor: RootDescriptor, name: keyof RootPublicKeys): Uint8Array {
  return descriptor[KEY_FIELD[name]] as Uint8Array;
}

/**
 * Replays a root chain and returns the root in force, or the first rule it breaks.
 *
 * Pure and deterministic: same links, same options, same answer. The checks follow the numbered
 * order of §28.2 (roles, signatures, `new_root_hash`, the link, the generation, the immutable
 * fields, the allowed key changes) so that a rejection names the same rule the spec does.
 */
export async function verifyRootChain(
  links: readonly RootChainLink[],
  options: VerifyRootChainOptions = {},
): Promise<Outcome<RootState, RootChainFailure>> {
  let current: RootDescriptor | null = options.from?.descriptor ?? null;
  let currentHash: Uint8Array | null = options.from?.rootHash ?? null;
  let genesisRootHash: Uint8Array | null = options.from?.genesisRootHash ?? null;
  const hashes = new Map<number, Uint8Array>(options.from?.hashes ?? []);
  let accountId: Uint8Array | null = options.accountId ?? current?.account_id ?? null;
  let mode: ProtectionMode | null = options.from?.mode ?? null;

  if (links.length === 0 && current === null) {
    return fail("EMPTY_CHAIN", "a root chain must contain at least the GENESIS transition");
  }

  for (const link of links) {
    const { transition, descriptor } = link;
    const generation = transition.new_root_generation;
    const isGenesis = transition.transition_type === "GENESIS";

    if (current === null && !isGenesis) {
      return fail("NOT_GENESIS", `a replay from nothing must start at GENESIS, got ${transition.transition_type}`, generation);
    }
    if (current !== null && isGenesis) {
      return fail("UNEXPECTED_GENESIS", "a second GENESIS cannot extend an existing root", generation);
    }

    // 0. Exactly the required roles, ascending, no extras and no duplicates.
    const required = REQUIRED_SIGNER_ROLES[transition.transition_type];
    if (!rolesAreExactly(transition, required)) {
      return fail(
        "BAD_SIGNATURE_SET",
        `${transition.transition_type} requires exactly roles ${required.join("+")}, got ${transition.signatures.map((s) => s.code).join(",") || "none"}`,
        generation,
      );
    }

    // 1. Every required signature verifies under the key its role names.
    const ctx = rootTransitionContext(transition);
    for (const pair of transition.signatures) {
      const spki = verifierSpki(pair.code as SignerRole, current, descriptor);
      if (spki === null) {
        return fail("BAD_SIGNATURE_SET", `role ${pair.code} needs a root in force`, generation);
      }
      const key = await importOrNull(spki);
      if (key === null) {
        return fail("MALFORMED_PUBLIC_KEY", `the key that verifies role ${pair.code} is not importable SPKI`, generation);
      }
      if (!(await verifyContext(key, ctx, pair.value))) {
        return fail("BAD_SIGNATURE", `the role ${pair.code} signature does not verify`, generation);
      }
    }

    // 2. `new_root_hash` is the hash of the descriptor that came with the transition.
    const nextHash = await rootHash(descriptor);
    if (!timingSafeEqual(nextHash, transition.new_root_hash)) {
      return fail("ROOT_HASH_MISMATCH", "new_root_hash is not the hash of the included Root Descriptor", generation);
    }

    // 3. The link: `old_root_hash` is the root in force, and the new descriptor points back at it.
    const expectedOld = currentHash;
    const oldMatches =
      expectedOld === null
        ? transition.old_root_hash === null
        : transition.old_root_hash !== null && timingSafeEqual(expectedOld, transition.old_root_hash);
    if (!oldMatches) {
      return fail("BROKEN_LINK", "old_root_hash is not the hash of the root in force", generation);
    }
    const previousMatches =
      transition.old_root_hash === null
        ? descriptor.previous_root_hash === null
        : descriptor.previous_root_hash !== null && timingSafeEqual(transition.old_root_hash, descriptor.previous_root_hash);
    if (!previousMatches) {
      return fail("BROKEN_LINK", "the new descriptor's previous_root_hash is not old_root_hash", generation);
    }

    // 4. Generation continuity. This is what rejects a gap, a reuse and a same-generation fork.
    const expectedGeneration = current === null ? 1 : current.root_generation + 1;
    if (generation !== expectedGeneration || descriptor.root_generation !== generation) {
      return fail(
        "GENERATION_NOT_CONSECUTIVE",
        `expected generation ${expectedGeneration}, transition says ${generation} and the descriptor says ${descriptor.root_generation}`,
        generation,
      );
    }

    // 5. `account_id` never changes; `crypto_version` only changes 1 → 2, and only in a SWITCH_TO_MANAGED,
    //    which MUST end at version 2.
    if (accountId === null) accountId = descriptor.account_id;
    if (!timingSafeEqual(accountId, descriptor.account_id) || !timingSafeEqual(accountId, transition.account_id)) {
      return fail("ACCOUNT_MISMATCH", "the transition or descriptor names another account", generation);
    }
    if (!isSupportedCryptoVersion(descriptor.crypto_version)) {
      return fail(
        "UNSUPPORTED_CRYPTO_VERSION",
        `crypto_version ${descriptor.crypto_version} is not implemented by this client`,
        generation,
      );
    }
    if (current !== null) {
      // SWITCH_TO_MANAGED MUST end at version 2 (§35.14 step 7); every other type keeps the version.
      const allowed = transition.transition_type === "SWITCH_TO_MANAGED" ? 2 : current.crypto_version;
      if (descriptor.crypto_version !== allowed) {
        return fail(
          "CRYPTO_VERSION_CHANGED",
          `${transition.transition_type} cannot take crypto_version from ${current.crypto_version} to ${descriptor.crypto_version}`,
          generation,
        );
      }
    }

    // 6. Only the keys of the "Cambia" column change, and all of them do.
    if (current !== null) {
      const mustChange = new Set(CHANGED_KEYS[transition.transition_type]);
      for (const name of ALL_KEYS) {
        const same = timingSafeEqual(keyBytes(current, name), keyBytes(descriptor, name));
        if (mustChange.has(name) === same) {
          return fail(
            "FORBIDDEN_KEY_CHANGE",
            mustChange.has(name)
              ? `${transition.transition_type} must change ${KEY_FIELD[name]}`
              : `${transition.transition_type} must not change ${KEY_FIELD[name]}`,
            generation,
          );
        }
      }
    }

    if (current === null) genesisRootHash = nextHash;
    mode = modeAfter(mode, transition.transition_type, descriptor.crypto_version);
    current = descriptor;
    currentHash = nextHash;
    hashes.set(generation, nextHash);
  }

  // §28.3: a new root is accepted only over the pin, and only when the pin is on this chain.
  const pin = options.pin;
  if (pin !== undefined && current !== null && currentHash !== null) {
    if (current.root_generation < pin.rootGeneration) {
      return fail(
        "PIN_ROLLBACK",
        `generation ${current.root_generation} is below the pinned ${pin.rootGeneration}`,
        current.root_generation,
      );
    }
    const pinned = hashes.get(pin.rootGeneration);
    if (pinned === undefined || !timingSafeEqual(pinned, pin.rootHash)) {
      return fail("PIN_NOT_ANCESTOR", `the pinned root at generation ${pin.rootGeneration} is not on this chain`);
    }
  }

  if (current === null || currentHash === null || mode === null) {
    return fail("EMPTY_CHAIN", "a root chain must contain at least the GENESIS transition");
  }
  return {
    ok: true,
    value: {
      descriptor: current,
      rootHash: currentHash,
      rootGeneration: current.root_generation,
      genesisRootHash,
      hashes,
      mode,
    },
  };
}
