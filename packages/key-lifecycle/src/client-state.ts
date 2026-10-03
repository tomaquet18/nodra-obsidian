// What a client holds *before* a §35 operation, and what it must keep *after* one.
//
// Every operation in §35.2–§35.5 reads the same three things — the root in force, the registry in
// force, and the vaults with their verified epoch chains — and writes the same two: a rebuilt
// Account Security Config (§26) and a new set of pins. Rather than repeat those shapes in each
// operation module, they live here once, so "what a client must have verified before it may build
// a bundle" is a single type a caller can be pointed at.
//
// The view is *verified* input, not raw server data: `verifyRootChain`, `verifyRegistryChain` and
// `verifyEpochChain` produce it. Nothing in this package re-verifies it — §35.1 requires the
// operations that create envelopes for other recipients to run on a trusted client precisely
// because a client with no pins cannot tell a rolled-back config from a current one (§26).
import { sha256 } from "@nodra/crypto";
import type { AeadKey, AnySigningKey, EnvelopeOpeningKey } from "@nodra/crypto";
import type {
  AccountSecurityConfig,
  BundleExpected,
  Registry,
  RootDescriptor,
} from "@nodra/encoding/records";
import type { ListedEpoch, VaultState } from "./coverage.js";
import type { PreviousEpoch } from "./epoch.js";
import { sealAccountSecurityConfig } from "./keyset.js";

/** One vault as a client sees it after verifying its descriptor chain (§34.3). */
export interface ClientVault {
  readonly vaultId: Uint8Array;
  readonly state: VaultState;
  /** The verified chain plus each epoch's unsigned `state` from `listEpochDescriptors` (§22). */
  readonly epochs: readonly ListedEpoch[];
  /** The head of the chain: what a new epoch links back to (§32.1). Null for a vault with none. */
  readonly current: PreviousEpoch | null;
}

/** The verified account state an operation is prepared over (§26, §28.3, §29, §34.3). */
export interface AccountView {
  /** The `account_id` the client authenticated with — never read from a downloaded structure. */
  readonly accountId: Uint8Array;
  readonly root: RootDescriptor;
  readonly rootHash: Uint8Array;
  /** §26: pinned from GENESIS and never changed by a transition. */
  readonly genesisRootHash: Uint8Array;
  readonly registry: Registry;
  readonly registryHash: Uint8Array;
  /** §23.4 key 6: the server's plaintext copy, which is what "vigente + 1" counts from (§26). */
  readonly configVersion: number;
  readonly vaults: readonly ClientVault[];
}

/** What a trusted client pins (§26 "continuidad de pins", §28.3, §29, §32.1). */
export interface ClientPins {
  readonly rootGeneration: number;
  readonly rootHash: Uint8Array;
  readonly genesisRootHash: Uint8Array;
  readonly registryVersion: number;
  readonly registryHash: Uint8Array;
  readonly configVersion: number;
  /** §32.1: the last `descriptor_hash` of each vault, one entry per vault. */
  readonly epochs: readonly VaultEpochPin[];
}

export interface VaultEpochPin {
  readonly vaultId: Uint8Array;
  readonly epochId: Uint8Array;
  readonly descriptorHash: Uint8Array;
}

/**
 * The handles a §35 operation runs with (§25.1). An operation takes exactly the ones its row of
 * §35.1 names: a revocation never sees `operationKey`, because it re-envelopes nothing.
 */
export interface SigningKeys {
  /** §25.1 Signing: Account Signing, `["sign"]`. Signs the registry and every new descriptor. */
  readonly signingKey: AnySigningKey;
  /** §24: `AccountConfigKey`, to rewrite the config in the same commit (§26). */
  readonly configKey: AeadKey;
}

/** {@link SigningKeys} plus the Operation handle §33.2 needs to read an `epoch_secret` as bytes. */
export interface OperationKeys extends SigningKeys {
  /** §25.1 Operation: Account Encryption, `["decrypt"]`. Only privileged re-enveloping uses it. */
  readonly operationKey: EnvelopeOpeningKey;
}

/**
 * A step of the numbered §35 flow that could not be completed on the client. It is deliberately
 * *not* a `BundleFailureCode`: nothing has been sent, so there is no Worker answer to report, and
 * conflating the two would make a local key mistake look like a server rejection.
 */
export interface OperationFailure<C extends string> {
  readonly code: C;
  /** The step number of the operation's own list in §35.2 / §35.4 / §35.5 / §35.8. */
  readonly step: number;
  readonly vaultId?: Uint8Array;
  readonly epochId?: Uint8Array;
  readonly message: string;
}

/** §35.1.1 step 0d: the CAS triple a bundle prepared over this view must carry. */
export function expectedOf(view: AccountView): BundleExpected {
  return {
    root_generation: view.root.root_generation,
    registry_version: view.registry.registry_version,
    config_version: view.configVersion,
  };
}

export interface AccountConfigRequest {
  /** The **pending** root of the bundle: the new one if it installs one, else the one in force. */
  readonly root: RootDescriptor;
  readonly rootHash: Uint8Array;
  readonly genesisRootHash: Uint8Array;
  readonly registryVersion: number;
  readonly registryHash: Uint8Array;
  /** §26: the server's plaintext copy in force + 1. The caller computes it; nothing infers it. */
  readonly configVersion: number;
}

/**
 * §26: the config as it must look after this operation. The four key hashes are taken with
 * `SHA-256` over the **exact SPKI bytes stored in the pending Root Descriptor** (§25.2), never
 * over a re-export, which is why this reads them from the descriptor rather than from key handles.
 */
export async function buildAccountConfig(request: AccountConfigRequest): Promise<AccountSecurityConfig> {
  const root = request.root;
  const [accountEncryption, accountSigning, recoveryEncryption, recoveryAuthority] = await Promise.all([
    sha256(root.account_encryption_public_key),
    sha256(root.account_signing_public_key),
    sha256(root.recovery_encryption_public_key),
    sha256(root.recovery_authority_public_key),
  ]);
  return {
    account_id: root.account_id,
    config_version: request.configVersion,
    root_generation: root.root_generation,
    root_hash: request.rootHash,
    genesis_root_hash: request.genesisRootHash,
    account_encryption_public_key_hash: accountEncryption,
    account_signing_public_key_hash: accountSigning,
    recovery_encryption_public_key_hash: recoveryEncryption,
    recovery_authority_public_key_hash: recoveryAuthority,
    registry_version: request.registryVersion,
    registry_hash: request.registryHash,
    // §23.1: the config carries the account's version, which is the pending root's.
    crypto_version: root.crypto_version,
  };
}

export interface SealedAccountConfig {
  readonly config: AccountSecurityConfig;
  readonly blob: Uint8Array;
  readonly configVersion: number;
}

/** {@link buildAccountConfig} sealed under the `AccountConfigKey` (§26), ready for a bundle. */
export async function sealNextConfig(
  configKey: AeadKey,
  request: AccountConfigRequest,
): Promise<SealedAccountConfig> {
  const config = await buildAccountConfig(request);
  return {
    config,
    blob: await sealAccountSecurityConfig(configKey, config),
    configVersion: request.configVersion,
  };
}
