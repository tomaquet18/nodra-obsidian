// Fixtures for the §35.2–§35.8 suites.
//
// Unlike `bundle-support.ts`, which hand-builds each structure so a validator test can break one
// thing at a time, this world is built by the operation under test: {@link operationWorld} runs
// the real §35.2 and then holds the account exactly as a Worker that applied that bundle would.
// That is deliberate — an enrollment test that ran against a hand-made account could pass while
// `createAccount` produced something no client could use.
//
// Everything expensive (Argon2id, RSA-3072 generation, the whole account) is built once per
// process and shared read-only; the tests that must mutate take copies.
import { exportEnvelopePublicKey, generateEnvelopeKeyPair, importEnvelopeDecryptKey } from "@nodra/crypto";
import type { EnvelopeOpeningKey } from "@nodra/crypto";
import type { EpochDescriptor, EpochEnvelope, RecoveryKit } from "@nodra/encoding/records";
import { createAccount } from "../src/account-creation.js";
import type { CreatedAccount } from "../src/account-creation.js";
import type { AccountView, ClientVault, OperationKeys } from "../src/client-state.js";
import type { BundleState, BundleVault } from "../src/bundle.js";
import type { RecoveryRequestKind, Scope } from "../src/operations.js";
import { createEpoch, epochRecipients, idKey, rootRecipientId } from "../src/epoch.js";
import type { CreatedEpoch, RecipientIdentity } from "../src/epoch.js";
import { verifyEpochChain } from "../src/epoch-chain.js";
import type { EpochChainState } from "../src/epoch-chain.js";
import { prepareEnrollment } from "../src/enrollment.js";
import type { EnrollmentKeys } from "../src/enrollment.js";
import { registryHash, verifyRegistryChain } from "../src/registry.js";
import { verifyRootChain } from "../src/root-chain.js";
import type { EnvelopeSource } from "../src/re-envelope.js";
import { filled, memoPorts } from "./support.js";
import type { KeyLifecyclePorts } from "../src/ports.js";

export const ACCOUNT_ID = filled(16, 0x11);
export const VAULT_A = filled(16, 0x21);
export const VAULT_B = filled(16, 0x22);
export const EPOCH_A1 = filled(16, 0x41);
export const EPOCH_B1 = filled(16, 0x42);
export const FIRST_CLIENT_ID = filled(16, 0x31);
export const CREATE_BUNDLE_ID = filled(16, 0x71);
export const PASSWORD = "correct horse battery staple";

export interface OperationWorld {
  readonly ports: KeyLifecyclePorts;
  readonly accountId: Uint8Array;
  /** The §35.2 result: bundle, kits, pins, and the handles the operation must later discard. */
  readonly created: CreatedAccount;
  /** The recipient pair of the client that created the account (§35.2 step 11). */
  readonly client: EnrollmentKeys;
  /** A second vault, so "one new epoch per vault" and coverage have more than one case. */
  readonly vaultB: CreatedEpoch;
  /** The account as a verified client sees it once `CREATE_ACCOUNT` and vault B are applied. */
  readonly view: AccountView;
  /** The same account as the Worker holds it, for `validateSecurityBundle`. */
  readonly state: BundleState;
  /** §25.1 handles taken from the created keyset: Operation, Signing, and the `AccountConfigKey`. */
  readonly keys: OperationKeys;
  /** The ACCOUNT recipient of the root in force (§30.1). */
  readonly account: RecipientIdentity;
  /** The RECOVERY recipient of the root in force (§30.1): what §35.7 re-envelopes *from*. */
  readonly recovery: RecipientIdentity;
  /** The ACCOUNT envelope of every epoch: the source §35.4 and §35.9 re-envelope from (§33.2). */
  readonly sources: readonly EnvelopeSource[];
  /** The RECOVERY envelope of every epoch: the only source §35.7 can open (§35.7 step 5). */
  readonly recoverySources: readonly EnvelopeSource[];
  readonly recoveryKit: RecoveryKit;
}

let world: Promise<OperationWorld> | null = null;

/** The shared world. Built once: §35.2 runs Argon2id and generates four RSA-3072 pairs. */
export function operationWorld(): Promise<OperationWorld> {
  world ??= build();
  return world;
}

async function build(): Promise<OperationWorld> {
  const ports = memoPorts();
  const client = await prepareEnrollment({
    recipientId: FIRST_CLIENT_ID,
    type: "PLUGIN_INSTALLATION",
    label: "first plugin",
  });

  const outcome = await createAccount({
    accountId: ACCOUNT_ID,
    password: PASSWORD,
    bundleId: CREATE_BUNDLE_ID,
    vaultId: VAULT_A,
    epochId: EPOCH_A1,
    recipient: client.recipient,
    ports,
  });
  if (!outcome.ok) throw new Error(`world §35.2: ${outcome.failure.code} ${outcome.failure.message}`);
  const created = outcome.value;

  // A second vault, as §35.10 would leave it: same root, same registry, its own E1.
  const vaultB = await createEpoch({
    vaultId: VAULT_B,
    epochId: EPOCH_B1,
    previous: null,
    root: { generation: created.root.root_generation, hash: created.rootHash, cryptoVersion: created.root.crypto_version },
    registry: { version: created.registry.registry_version, hash: created.registryHash },
    recipients: await epochRecipients(created.root, created.registry),
    signingKey: created.keyset.signing.privateKey,
    ports,
  });

  const rootReplay = await verifyRootChain(
    [{ transition: created.rootTransition, descriptor: created.root }],
    { accountId: ACCOUNT_ID },
  );
  if (!rootReplay.ok) throw new Error(`world root: ${rootReplay.failure.code}`);
  const registryReplay = await verifyRegistryChain([created.registry], {
    accountId: ACCOUNT_ID,
    accountSigningKeys: new Map([[1, created.keyset.signing.publicKeySpki]]),
  });
  if (!registryReplay.ok) throw new Error(`world registry: ${registryReplay.failure.code}`);

  const chains = new Map<string, EpochChainState>();
  const vaults: BundleVault[] = [];
  const clientVaults: ClientVault[] = [];
  for (const epoch of [created.epoch, vaultB]) {
    const replay = await verifyEpochChain([epoch.descriptor], {
      vaultId: epoch.descriptor.vault_id,
      accountSigningKeys: new Map([[1, created.keyset.signing.publicKeySpki]]),
      rootHashes: new Map([[1, created.rootHash]]),
      rootCryptoVersions: new Map([[1, created.root.crypto_version]]),
      registryHashes: new Map([[1, created.registryHash]]),
    });
    if (!replay.ok) throw new Error(`world epoch: ${replay.failure.code}`);
    chains.set(idKey(epoch.descriptor.vault_id), replay.value);
    vaults.push({
      vaultId: epoch.descriptor.vault_id,
      state: "ACTIVE",
      currentEpoch: replay.value,
      epochs: [{ descriptor: epoch.descriptor, state: "ACTIVE" }],
    });
    clientVaults.push({
      vaultId: epoch.descriptor.vault_id,
      state: "ACTIVE",
      epochs: [{ descriptor: epoch.descriptor, state: "ACTIVE" }],
      current: { epochId: epoch.descriptor.epoch_id, descriptorHash: replay.value.currentHash },
    });
  }

  const view: AccountView = {
    accountId: ACCOUNT_ID,
    root: created.root,
    rootHash: created.rootHash,
    genesisRootHash: created.rootHash,
    registry: created.registry,
    registryHash: created.registryHash,
    configVersion: created.config.config_version,
    vaults: clientVaults,
  };

  const state: BundleState = {
    authorization: { authenticated: true, token: { scopes: ["VAULT_WRITE", "TRUSTED_SECURITY"] } },
    accountId: ACCOUNT_ID,
    accountState: "ACTIVE",
    root: rootReplay.value,
    registry: registryReplay.value,
    configVersion: created.config.config_version,
    vaults,
    escrow: null,
  };

  const account: RecipientIdentity = {
    recipientId: await rootRecipientId(created.root.account_encryption_public_key),
    type: "ACCOUNT",
  };
  const recovery: RecipientIdentity = {
    recipientId: await rootRecipientId(created.root.recovery_encryption_public_key),
    type: "RECOVERY",
  };

  return {
    ports,
    accountId: ACCOUNT_ID,
    created,
    client,
    vaultB,
    view,
    state,
    keys: {
      // §25.1 Operation: the account encryption private key with `["decrypt"]`. Here it is the
      // extractable original of §25.2, which §35.2 still holds when the operation ends.
      operationKey: created.keyset.encryption.privateKey,
      signingKey: created.keyset.signing.privateKey,
      configKey: created.keyset.derived.configKey,
    },
    account,
    recovery,
    sources: [created.epoch, vaultB].map((epoch) => ({
      descriptor: epoch.descriptor,
      envelope: envelopeFor(epoch.envelopes, account.recipientId),
    })),
    recoverySources: [created.epoch, vaultB].map((epoch) => ({
      descriptor: epoch.descriptor,
      envelope: envelopeFor(epoch.envelopes, recovery.recipientId),
    })),
    recoveryKit: created.recoveryKit.kit,
  };
}

/**
 * The same account state with another Write Capability token (§11.3). Each §35 operation needs its
 * own scope — `RECOVERY_CONTROL` for §35.7, `TRUSTED_SECURITY` for §35.9 — and the shared world
 * carries only one, so a suite narrows it here instead of rebuilding the account.
 */
export function withScopes(state: BundleState, scopes: readonly Scope[]): BundleState {
  return { ...state, authorization: { authenticated: true, token: { scopes } } };
}

/**
 * §35.15: the same Private account with one live request of `kind` at its generation, matured a
 * second ago, and the database clock that makes it so. The phase-2 bundle of §35.7, §35.9 or §35.14
 * is validated against this; without it step 0c answers `RECOVERY_REQUEST_REQUIRED`.
 */
export function withMaturedRequest(state: BundleState, kind: RecoveryRequestKind): BundleState {
  const now = 1_900_000_000_000;
  return {
    ...state,
    now,
    recoveryRequests: [
      { requestId: filled(16, 0x9b), kind, rootGeneration: state.root?.rootGeneration ?? 0, state: "PENDING", maturesAt: now - 1000, expiresAt: now + 7 * 86_400_000 },
    ],
  };
}

/** The envelope of one recipient inside an epoch's envelope set. Throws if it is not there. */
export function envelopeFor(envelopes: readonly EpochEnvelope[], recipientId: Uint8Array): EpochEnvelope {
  const found = envelopes.find((envelope) => idKey(envelope.recipient_id) === idKey(recipientId));
  if (found === undefined) throw new Error(`no envelope for recipient ${idKey(recipientId)}`);
  return found;
}

/** Whether an envelope set addresses a recipient at all — what a revocation must make false. */
export function hasEnvelopeFor(envelopes: readonly EpochEnvelope[], recipientId: Uint8Array): boolean {
  return envelopes.some((envelope) => idKey(envelope.recipient_id) === idKey(recipientId));
}

/** The RECOVERY private key as §27.2 imports it: non-extractable, `["decrypt"]`. */
export async function recoveryDecryptKey(kit: RecoveryKit): Promise<EnvelopeOpeningKey> {
  return importEnvelopeDecryptKey(kit.recovery_encryption_private_key);
}

/** A throwaway RSA-OAEP public key, for "the target is not who the prover is" cases. */
export async function strangerSpki(): Promise<Uint8Array> {
  stranger ??= generateEnvelopeKeyPair().then((pair) => exportEnvelopePublicKey(pair.publicKey));
  return stranger;
}
let stranger: Promise<Uint8Array> | null = null;

/** A descriptor with one field replaced, for the "broken source" cases. */
export function withDescriptor(descriptor: EpochDescriptor, patch: Partial<EpochDescriptor>): EpochDescriptor {
  return { ...descriptor, ...patch };
}

export { registryHash };
