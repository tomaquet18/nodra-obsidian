// Fixtures for the §35.1.1 suites.
//
// One world, and a *valid* bundle of every `operation_type` the applicability table covers. Every
// negative case in `bundle.test.ts` takes one of those, breaks exactly one thing (and re-signs
// whatever that invalidates), and asserts the step and code that must answer. A rejection then
// proves the rule it names rather than proving that ECDSA works.
//
// The world is deliberately the awkward shape rather than the easy one: **two** vaults, each with
// its own epoch chain, so "uno nuevo por vault" and `VAULT_SET_STALE` have something to be wrong
// about, and a registry with two ACTIVE recipients so a revocation leaves one behind.
import {
  ARGON2_PARAMS_V1,
  exportEnvelopePublicKey,
  generateEnvelopeKeyPair,
} from "@nodra/crypto";
import type {
  AccountSecurityProfile,
  BundleEpoch,
  EpochEnvelope,
  EscrowBlob,
  Registry,
  RootDescriptor,
  SecurityBundle,
} from "@nodra/encoding/records";
import { assembleBundle, signDeletion, signProfileUpdate, signRecoveryRecord } from "../src/bundle-build.js";
import type { BundleParts } from "../src/bundle-build.js";
import type { BundleState, BundleVault } from "../src/bundle.js";
import { createEpoch, epochRecipients, rootRecipientId } from "../src/epoch.js";
import type { CreatedEpoch, EnvelopeRecipient } from "../src/epoch.js";
import { verifyEpochChain } from "../src/epoch-chain.js";
import type { EpochChainState } from "../src/epoch-chain.js";
import type { OperationType, RecoveryRecordOperation, RecoveryRequestKind } from "../src/operations.js";
import type { StoredRecoveryRequest } from "../src/recovery-request-state.js";
import { activeRecipients, initialRegistry, nextRegistry, registryHash, signRegistry } from "../src/registry.js";
import type { RegistryState } from "../src/registry.js";
import { nextDescriptor, genesisDescriptor, rootHash, signRootTransition, verifyRootChain } from "../src/root-chain.js";
import type { RootState } from "../src/root-chain.js";
import { toArgon2ParamsRecord } from "../src/secrets.js";
import { makeSigner } from "./chain-support.js";
import type { Signer } from "./chain-support.js";
import { filled } from "./support.js";

// --- RSA economy --------------------------------------------------------------------------------

/**
 * Six RSA-OAEP-3072 SPKI, generated once per process. Six is the minimum this slice needs: the
 * ACCOUNT and RECOVERY keys of generation 1, the two registry recipients that appear in every
 * epoch's envelope set, and the replacement ACCOUNT / RECOVERY keys that `RECOVERY_RESET` and
 * `RECOVERY_KIT_REPLACEMENT` install. A recipient that never receives an epoch envelope (the one
 * `ENROLL_CLIENT` adds) gets filler SPKI, because nothing imports it.
 */
const POOL_SIZE = 6;
let pool: Promise<readonly Uint8Array[]> | null = null;

export function rsaSpkiPool(): Promise<readonly Uint8Array[]> {
  pool ??= Promise.all(
    Array.from({ length: POOL_SIZE }, async () => exportEnvelopePublicKey((await generateEnvelopeKeyPair()).publicKey)),
  );
  return pool;
}

// --- The world -----------------------------------------------------------------------------------

export interface BundleWorld {
  readonly accountId: Uint8Array;
  /** Generation 1: Account Signing and Recovery Authority. */
  readonly as1: Signer;
  readonly ra1: Signer;
  /** The replacements a transition installs: `as2` for a reset, `ra2` for a kit replacement. */
  readonly as2: Signer;
  readonly ra2: Signer;
  /** A valid signing key that belongs to no generation of this account. */
  readonly stranger: Signer;
  readonly accountEncryption: Uint8Array;
  readonly recoveryEncryption: Uint8Array;
  readonly newAccountEncryption: Uint8Array;
  readonly newRecoveryEncryption: Uint8Array;
  readonly root: RootDescriptor;
  readonly rootHash: Uint8Array;
  readonly rootState: RootState;
  /** Version 1, two ACTIVE recipients (one plugin, one browser). */
  readonly registry: Registry;
  readonly registryState: RegistryState;
  readonly vaults: readonly BundleVault[];
  /** The two vaults' current epochs, in `vaults` order. */
  readonly currentEpochs: readonly CreatedEpoch[];
  /** The baseline state: root generation 1, registry version 1, config version 1, both vaults ACTIVE. */
  readonly state: BundleState;
}

/** §35.15: the database clock of the world (Unix ms), and the delays the Worker holds by default. */
export const NOW = 1_900_000_000_000;
export const DELAY_MS = 72 * 60 * 60 * 1000;
export const TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const REQUEST_ID = filled(16, 0x9a);

/**
 * A `recovery_requests` row of the world's generation, filed `ageMs` before {@link NOW}: by default
 * one that matured exactly one second ago and is far from expiring.
 */
export function storedRequest(
  kind: RecoveryRequestKind,
  overrides: Partial<StoredRecoveryRequest> & { readonly ageMs?: number } = {},
): StoredRecoveryRequest {
  const { ageMs = DELAY_MS + 1000, ...rest } = overrides;
  const requestedAt = NOW - ageMs;
  return {
    requestId: REQUEST_ID,
    kind,
    rootGeneration: 1,
    state: "PENDING",
    maturesAt: requestedAt + DELAY_MS,
    expiresAt: requestedAt + DELAY_MS + TTL_MS,
    ...rest,
  };
}

export const VAULT_A = filled(16, 0x21);
export const VAULT_B = filled(16, 0x22);
export const NEW_VAULT = filled(16, 0x2f);
const PLUGIN_ID = filled(16, 0x31);
const BROWSER_ID = filled(16, 0x32);
export const ENROLLED_ID = filled(16, 0x33);

export async function makeBundleWorld(): Promise<BundleWorld> {
  const [accountEncryption, recoveryEncryption, pluginKey, browserKey, newAccountEncryption, newRecoveryEncryption] =
    (await rsaSpkiPool()) as readonly Uint8Array[] as [Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array];
  const accountId = filled(16, 0x11);
  const [as1, ra1, as2, ra2, stranger] = await Promise.all([
    makeSigner(),
    makeSigner(),
    makeSigner(),
    makeSigner(),
    makeSigner(),
  ]);

  const root = genesisDescriptor(accountId, {
    accountEncryption,
    accountSigning: as1.spki,
    recoveryEncryption,
    recoveryAuthority: ra1.spki,
  });
  const hash = await rootHash(root);
  const genesis = await signRootTransition({
    type: "GENESIS",
    descriptor: root,
    signers: { 2: as1.privateKey, 4: ra1.privateKey },
  });
  const replay = await verifyRootChain([{ transition: genesis, descriptor: root }], { accountId });
  if (!replay.ok) throw new Error(`world root: ${replay.failure.code}`);

  const registry = await signRegistry(
    initialRegistry(accountId, 1, [
      { recipientId: PLUGIN_ID, type: "PLUGIN_INSTALLATION", publicKey: pluginKey, label: "plugin" },
      { recipientId: BROWSER_ID, type: "TRUSTED_BROWSER", publicKey: browserKey, label: "browser" },
    ]),
    as1.privateKey,
  );
  const rHash = await registryHash(registry);
  const registryState: RegistryState = { registry, registryHash: rHash, hashes: new Map([[1, rHash]]) };

  const recipients = await epochRecipients(root, registry);
  const currentEpochs: CreatedEpoch[] = [];
  const vaults: BundleVault[] = [];
  for (const [i, vaultId] of [VAULT_A, VAULT_B].entries()) {
    const epoch = await createEpoch({
      vaultId,
      epochId: filled(16, 0x41 + i),
      previous: null,
      root: { generation: 1, hash, cryptoVersion: 1 },
      registry: { version: 1, hash: rHash },
      recipients,
      signingKey: as1.privateKey,
    });
    currentEpochs.push(epoch);
    vaults.push({
      vaultId,
      state: "ACTIVE",
      currentEpoch: await chainStateOf(vaultId, epoch, hash, rHash, as1),
      epochs: [{ descriptor: epoch.descriptor, state: "ACTIVE" }],
    });
  }

  const state: BundleState = {
    authorization: { authenticated: true, emailConfirmed: true, token: { scopes: ["VAULT_WRITE", "TRUSTED_SECURITY"] } },
    accountId,
    accountState: "ACTIVE",
    root: replay.value,
    registry: registryState,
    configVersion: 1,
    vaults,
    escrow: null,
    // §35.15: the database clock under the account lock, and no recovery request yet.
    now: NOW,
    recoveryRequests: [],
  };

  return {
    accountId,
    as1,
    ra1,
    as2,
    ra2,
    stranger,
    accountEncryption,
    recoveryEncryption,
    newAccountEncryption,
    newRecoveryEncryption,
    root,
    rootHash: hash,
    rootState: replay.value,
    registry,
    registryState,
    vaults,
    currentEpochs,
    state,
  };
}

/** A vault's `EpochChainState`, produced the only way a Worker legitimately could: by verifying. */
async function chainStateOf(
  vaultId: Uint8Array,
  epoch: CreatedEpoch,
  rootHashValue: Uint8Array,
  registryHashValue: Uint8Array,
  signer: Signer,
): Promise<EpochChainState> {
  const replay = await verifyEpochChain([epoch.descriptor], {
    vaultId,
    accountSigningKeys: new Map([[1, signer.spki]]),
    rootHashes: new Map([[1, rootHashValue]]),
    rootCryptoVersions: new Map([[1, 1]]),
    registryHashes: new Map([[1, registryHashValue]]),
  });
  if (!replay.ok) throw new Error(`world epoch: ${replay.failure.code}`);
  return replay.value;
}

// --- Profiles and coverage envelopes --------------------------------------------------------------

/**
 * A profile at a given `config_version`. Its wrapped keys and config blob are filler: §35.1.1 never
 * opens them — step 7 checks `kdf_salt`, the Argon2 parameters and the `account_id`, nothing else.
 */
export function makeProfile(accountId: Uint8Array, configVersion: number): AccountSecurityProfile {
  return {
    account_id: accountId,
    kdf_salt: filled(16, 0x5a),
    argon2_params: toArgon2ParamsRecord(ARGON2_PARAMS_V1),
    wrapped_account_encryption_key: { key_role: "ACCOUNT_ENCRYPTION", blob: filled(80, 0x01) },
    wrapped_account_signing_key: { key_role: "ACCOUNT_SIGNING", blob: filled(80, 0x02) },
    config_version: configVersion,
    config_blob: filled(64, 0x03),
  };
}

/** §23.4: a Managed profile omits `kdf_salt` and `argon2_params`. */
export function makeManagedProfile(accountId: Uint8Array, configVersion: number): AccountSecurityProfile {
  const { kdf_salt: _salt, argon2_params: _params, ...managed } = makeProfile(accountId, configVersion);
  return managed;
}

/**
 * An `EscrowBlob` with the given slots, well formed and filler inside: §35.1.1 never opens the
 * escrow, it only checks which slots travel and their shape (key 14).
 */
export function makeEscrow(accountId: Uint8Array, slots: { unlock?: boolean; recovery?: boolean }): EscrowBlob {
  return {
    account_id: accountId,
    ...(slots.unlock === true ? { unlock: { slot: "UNLOCK" as const, key_id: filled(16, 0xe1), wrapped_key: filled(384, 0xe2) } } : {}),
    ...(slots.recovery === true
      ? { recovery: { slot: "RECOVERY" as const, key_id: filled(16, 0xe1), wrapped_key: filled(384, 0xe3), payload_blob: filled(1900, 0xe4) } }
      : {}),
  };
}

/** The world's state as a Managed account: its `account_escrows` row, with both slots (§23.4). */
export function managedState(world: BundleWorld, state: BundleState = world.state): BundleState {
  return { ...state, escrow: makeEscrow(world.accountId, { unlock: true, recovery: true }) };
}

/**
 * One coverage envelope per (vault, epoch) of the world's `RequiredEpochSet`, for one recipient.
 * The ciphertext is filler on purpose: §34.2 is a set-matching rule and `checkCoverage` opens
 * nothing — §32.3 says only the client that opens an envelope proves it cryptographically.
 */
export function coverageFor(
  world: BundleWorld,
  recipientId: Uint8Array,
  recipientType: EpochEnvelope["recipient_type"],
): EpochEnvelope[] {
  return world.vaults.flatMap((vault) =>
    vault.epochs.map((epoch) => ({
      vault_id: vault.vaultId,
      epoch_id: epoch.descriptor.epoch_id,
      recipient_id: recipientId,
      recipient_type: recipientType,
      ciphertext: filled(384, 0x77),
      algorithm_version: 1,
    })),
  );
}

// --- Valid bundles, one per operation_type ----------------------------------------------------

export interface Scenario {
  readonly bundle: SecurityBundle;
  readonly state: BundleState;
}

const BUNDLE_ID = filled(16, 0x7b);

/** `expected` matching a state: the CAS of step 0d passes for a bundle prepared over it. */
export function expectedOf(state: BundleState): BundleParts["expected"] {
  return {
    root_generation: state.root?.rootGeneration ?? 0,
    registry_version: state.registry?.registry.registry_version ?? 0,
    config_version: state.configVersion,
  };
}

/** A new epoch for one vault, chained onto its current one, under the pending root and registry. */
export async function rotate(
  world: BundleWorld,
  vault: BundleVault,
  tag: number,
  pending: { root: RootDescriptor; rootHash: Uint8Array; registry: Registry; registryHash: Uint8Array; signer: Signer },
): Promise<BundleEpoch> {
  const previousDescriptor = vault.currentEpoch?.current ?? null;
  const created = await createEpoch({
    vaultId: vault.vaultId,
    epochId: filled(16, tag),
    previous:
      previousDescriptor === null || vault.currentEpoch === null
        ? null
        : { epochId: previousDescriptor.epoch_id, descriptorHash: vault.currentEpoch.currentHash },
    root: { generation: pending.root.root_generation, hash: pending.rootHash, cryptoVersion: pending.root.crypto_version },
    registry: { version: pending.registry.registry_version, hash: pending.registryHash },
    recipients: await epochRecipients(pending.root, pending.registry),
    signingKey: pending.signer.privateKey,
  });
  return { descriptor: created.descriptor, envelopes: [...created.envelopes] };
}

/** One new epoch for every live vault of the world, tagged from `0x51`. */
export async function rotateAll(
  world: BundleWorld,
  pending: { root: RootDescriptor; rootHash: Uint8Array; registry: Registry; registryHash: Uint8Array; signer: Signer },
  vaults: readonly BundleVault[] = world.vaults,
): Promise<BundleEpoch[]> {
  const out: BundleEpoch[] = [];
  for (const [i, vault] of vaults.entries()) {
    if (vault.state === "DELETED") continue;
    out.push(await rotate(world, vault, 0x51 + i, pending));
  }
  return out;
}

export async function createAccountScenario(world: BundleWorld): Promise<Scenario> {
  // CREATE_ACCOUNT's registry is version 1 with exactly **one** ACTIVE recipient, so it is not the
  // world's two-recipient registry: the world models an account that has already enrolled a second.
  const registry = await signRegistry(
    initialRegistry(world.accountId, 1, [
      { recipientId: PLUGIN_ID, type: "PLUGIN_INSTALLATION", publicKey: await onlyPluginKey(), label: "plugin" },
    ]),
    world.as1.privateKey,
  );
  const rHash = await registryHash(registry);
  const genesis = await signRootTransition({
    type: "GENESIS",
    descriptor: world.root,
    signers: { 2: world.as1.privateKey, 4: world.ra1.privateKey },
  });
  const epoch = await createEpoch({
    vaultId: NEW_VAULT,
    epochId: filled(16, 0x61),
    previous: null,
    root: { generation: 1, hash: world.rootHash, cryptoVersion: 1 },
    registry: { version: 1, hash: rHash },
    recipients: await epochRecipients(world.root, registry),
    signingKey: world.as1.privateKey,
  });
  const state: BundleState = {
    authorization: { authenticated: true, emailConfirmed: true },
    accountId: world.accountId,
    accountState: "ACTIVE",
    root: null,
    registry: null,
    configVersion: 0,
    vaults: [],
    escrow: null,
  };
  return {
    state,
    bundle: assembleBundle({
      operationType: "CREATE_ACCOUNT",
      bundleId: BUNDLE_ID,
      expected: { root_generation: 0, registry_version: 0, config_version: 0 },
      rootTransition: genesis,
      rootDescriptor: world.root,
      registry,
      profile: makeProfile(world.accountId, 1),
      epochs: [{ descriptor: epoch.descriptor, envelopes: [...epoch.envelopes] }],
    }),
  };
}

async function onlyPluginKey(): Promise<Uint8Array> {
  return (await rsaSpkiPool())[2] as Uint8Array;
}

export async function enrollClientScenario(world: BundleWorld): Promise<Scenario> {
  const registry = await signRegistry(
    await nextRegistry(world.registry, {
      add: [{ recipientId: ENROLLED_ID, type: "TRUSTED_BROWSER", publicKey: filled(48, 0x33), label: "new browser" }],
    }),
    world.as1.privateKey,
  );
  return {
    state: world.state,
    bundle: assembleBundle({
      operationType: "ENROLL_CLIENT",
      bundleId: BUNDLE_ID,
      expected: expectedOf(world.state),
      registry,
      configBlob: filled(64, 0x04),
      configVersion: 2,
      coverageEnvelopes: coverageFor(world, ENROLLED_ID, "TRUSTED_BROWSER"),
    }),
  };
}

export async function createVaultScenario(world: BundleWorld): Promise<Scenario> {
  const epoch = await createEpoch({
    vaultId: NEW_VAULT,
    epochId: filled(16, 0x62),
    previous: null,
    root: { generation: 1, hash: world.rootHash, cryptoVersion: 1 },
    registry: { version: 1, hash: world.registryState.registryHash },
    recipients: await epochRecipients(world.root, world.registry),
    signingKey: world.as1.privateKey,
  });
  return {
    state: world.state,
    bundle: assembleBundle({
      operationType: "CREATE_VAULT",
      bundleId: BUNDLE_ID,
      expected: expectedOf(world.state),
      epochs: [{ descriptor: epoch.descriptor, envelopes: [...epoch.envelopes] }],
    }),
  };
}

export async function revokeClientScenario(world: BundleWorld): Promise<Scenario> {
  const registry = await signRegistry(
    await nextRegistry(world.registry, { revoke: [BROWSER_ID] }),
    world.as1.privateKey,
  );
  const pending = {
    root: world.root,
    rootHash: world.rootHash,
    registry,
    registryHash: await registryHash(registry),
    signer: world.as1,
  };
  return {
    state: world.state,
    bundle: assembleBundle({
      operationType: "REVOKE_CLIENT",
      bundleId: BUNDLE_ID,
      expected: expectedOf(world.state),
      registry,
      configBlob: filled(64, 0x05),
      configVersion: 2,
      epochs: await rotateAll(world, pending),
    }),
  };
}

export async function changeSecretsScenario(world: BundleWorld): Promise<Scenario> {
  const profile = makeProfile(world.accountId, 2);
  return {
    state: world.state,
    bundle: assembleBundle({
      operationType: "CHANGE_SECRETS",
      bundleId: BUNDLE_ID,
      expected: expectedOf(world.state),
      profile,
      profileSignature: await signProfileUpdate(world.as1.privateKey, world.accountId, 1, profile),
    }),
  };
}

export async function recoveryResetScenario(world: BundleWorld): Promise<Scenario> {
  const newRoot = await nextDescriptor(world.root, {
    accountEncryption: world.newAccountEncryption,
    accountSigning: world.as2.spki,
  });
  const transition = await signRootTransition({
    type: "RECOVERY_RESET",
    descriptor: newRoot,
    previous: world.root,
    // §28.2: role 2 = the **new** Account Signing, role 3 = the **current** Recovery Authority.
    signers: { 2: world.as2.privateKey, 3: world.ra1.privateKey },
  });
  const registry = await signRegistry(
    await nextRegistry(world.registry, {
      revoke: activeRecipients(world.registry).map((r) => r.recipient_id),
      rootGeneration: 2,
    }),
    world.as2.privateKey,
  );
  const pending = {
    root: newRoot,
    rootHash: await rootHash(newRoot),
    registry,
    registryHash: await registryHash(registry),
    signer: world.as2,
  };
  return {
    state: {
      ...world.state,
      authorization: { authenticated: true, emailConfirmed: true, token: { scopes: ["RECOVERY_CONTROL"] } },
      // §35.15: a Private reset applies only with a matured request of its kind.
      recoveryRequests: [storedRequest("RECOVERY_RESET")],
    },
    bundle: assembleBundle({
      operationType: "RECOVERY_RESET",
      bundleId: BUNDLE_ID,
      expected: expectedOf(world.state),
      rootTransition: transition,
      rootDescriptor: newRoot,
      registry,
      profile: makeProfile(world.accountId, 2),
      epochs: await rotateAll(world, pending),
      coverageEnvelopes: coverageFor(world, await rootRecipientId(world.newAccountEncryption), "ACCOUNT"),
    }),
  };
}

export async function kitReplacementScenario(world: BundleWorld): Promise<Scenario> {
  const newRoot = await nextDescriptor(world.root, {
    recoveryEncryption: world.newRecoveryEncryption,
    recoveryAuthority: world.ra2.spki,
  });
  const transition = await signRootTransition({
    type: "RECOVERY_KIT_REPLACEMENT",
    descriptor: newRoot,
    previous: world.root,
    // §28.2: role 1 = the current Account Signing, role 4 = the **new** Recovery Authority.
    signers: { 1: world.as1.privateKey, 4: world.ra2.privateKey },
  });
  // "lista idéntica": only version, root_generation, previous hash and signature move.
  const registry = await signRegistry(
    await nextRegistry(world.registry, { rootGeneration: 2 }),
    world.as1.privateKey,
  );
  const pending = {
    root: newRoot,
    rootHash: await rootHash(newRoot),
    registry,
    registryHash: await registryHash(registry),
    signer: world.as1,
  };
  return {
    state: { ...world.state, recoveryRequests: [storedRequest("RECOVERY_KIT_REPLACEMENT")] },
    bundle: assembleBundle({
      operationType: "RECOVERY_KIT_REPLACEMENT",
      bundleId: BUNDLE_ID,
      expected: expectedOf(world.state),
      rootTransition: transition,
      rootDescriptor: newRoot,
      registry,
      configBlob: filled(64, 0x06),
      configVersion: 2,
      epochs: await rotateAll(world, pending),
      coverageEnvelopes: coverageFor(world, await rootRecipientId(world.newRecoveryEncryption), "RECOVERY"),
    }),
  };
}

/**
 * §35.13 on a Managed account: all four keys new (roles 1 + 2 + 4), the identical recipient list, a
 * Private profile, a new epoch per vault and coverage for both new reading keys. No `escrow`.
 */
export async function switchToPrivateScenario(world: BundleWorld): Promise<Scenario> {
  const newRoot = await nextDescriptor(world.root, {
    accountEncryption: world.newAccountEncryption,
    accountSigning: world.as2.spki,
    recoveryEncryption: world.newRecoveryEncryption,
    recoveryAuthority: world.ra2.spki,
  });
  const transition = await signRootTransition({
    type: "SWITCH_TO_PRIVATE",
    descriptor: newRoot,
    previous: world.root,
    signers: { 1: world.as1.privateKey, 2: world.as2.privateKey, 4: world.ra2.privateKey },
  });
  // §35.13 step 8: signed with the **new** Account Signing Key.
  const registry = await signRegistry(await nextRegistry(world.registry, { rootGeneration: 2 }), world.as2.privateKey);
  const pending = { root: newRoot, rootHash: await rootHash(newRoot), registry, registryHash: await registryHash(registry), signer: world.as2 };
  const state = managedState(world);
  return {
    state,
    bundle: assembleBundle({
      operationType: "SWITCH_TO_PRIVATE",
      bundleId: BUNDLE_ID,
      expected: expectedOf(state),
      rootTransition: transition,
      rootDescriptor: newRoot,
      registry,
      profile: makeProfile(world.accountId, 2),
      epochs: await rotateAll(world, pending),
      coverageEnvelopes: [
        ...coverageFor(world, await rootRecipientId(world.newAccountEncryption), "ACCOUNT"),
        ...coverageFor(world, await rootRecipientId(world.newRecoveryEncryption), "RECOVERY"),
      ],
    }),
  };
}

/**
 * §35.14 on the (version-1, Private) world: new recovery keys (roles 1 + 4), crypto_version 1 → 2,
 * the identical list, a Managed profile with its `profile_signature`, a new epoch per vault, coverage
 * for the new RECOVERY key and both escrow slots.
 */
export async function switchToManagedScenario(world: BundleWorld): Promise<Scenario> {
  const newRoot = await nextDescriptor(world.root, { recoveryEncryption: world.newRecoveryEncryption, recoveryAuthority: world.ra2.spki }, 2);
  const transition = await signRootTransition({
    type: "SWITCH_TO_MANAGED",
    descriptor: newRoot,
    previous: world.root,
    signers: { 1: world.as1.privateKey, 4: world.ra2.privateKey },
  });
  const registry = await signRegistry(await nextRegistry(world.registry, { rootGeneration: 2 }), world.as1.privateKey);
  const pending = { root: newRoot, rootHash: await rootHash(newRoot), registry, registryHash: await registryHash(registry), signer: world.as1 };
  const profile = makeManagedProfile(world.accountId, 2);
  return {
    state: { ...world.state, recoveryRequests: [storedRequest("SWITCH_TO_MANAGED")] },
    bundle: assembleBundle({
      operationType: "SWITCH_TO_MANAGED",
      bundleId: BUNDLE_ID,
      expected: expectedOf(world.state),
      rootTransition: transition,
      rootDescriptor: newRoot,
      registry,
      profile,
      profileSignature: await signProfileUpdate(world.as1.privateKey, world.accountId, 1, profile),
      epochs: await rotateAll(world, pending),
      coverageEnvelopes: coverageFor(world, await rootRecipientId(world.newRecoveryEncryption), "RECOVERY"),
      escrow: makeEscrow(world.accountId, { unlock: true, recovery: true }),
    }),
  };
}

/** §35.2 in Managed: a version-2 GENESIS, a Managed profile and both escrow slots. */
export async function managedCreateAccountScenario(world: BundleWorld): Promise<Scenario> {
  const base = await createAccountScenario(world);
  const root = { ...world.root, crypto_version: 2 };
  const genesis = await signRootTransition({ type: "GENESIS", descriptor: root, signers: { 2: world.as1.privateKey, 4: world.ra1.privateKey } });
  const registry = base.bundle.registry as Registry;
  const epoch = await createEpoch({
    vaultId: NEW_VAULT,
    epochId: filled(16, 0x61),
    previous: null,
    root: { generation: 1, hash: await rootHash(root), cryptoVersion: 2 },
    registry: { version: 1, hash: await registryHash(registry) },
    recipients: await epochRecipients(root, registry),
    signingKey: world.as1.privateKey,
  });
  return {
    state: base.state,
    bundle: patch(base.bundle, {
      root_transition: genesis,
      root_descriptor: root,
      profile: makeManagedProfile(world.accountId, 1),
      epochs: [{ descriptor: epoch.descriptor, envelopes: [...epoch.envelopes] }],
      escrow: makeEscrow(world.accountId, { unlock: true, recovery: true }),
    }),
  };
}

/** §35.7 in Managed: the reset of the world, on a Managed account, with only the new UNLOCK slot. */
export async function managedRecoveryResetScenario(world: BundleWorld): Promise<Scenario> {
  const base = await recoveryResetScenario(world);
  return {
    // §35.15: a Managed account has no requests; its reset is exempt from the delay.
    state: { ...managedState(world, base.state), recoveryRequests: [] },
    bundle: patch(base.bundle, {
      profile: makeManagedProfile(world.accountId, 2),
      escrow: makeEscrow(world.accountId, { unlock: true }),
    }),
  };
}

/** §35.12 in Managed: DELETE_ACCOUNT with a primary authentication `age` seconds old. */
export async function managedDeleteAccountScenario(world: BundleWorld, age: number | undefined): Promise<Scenario> {
  const base = await deletionScenario(world, "DELETE_ACCOUNT");
  const state = managedState(world, base.state);
  return {
    bundle: base.bundle,
    state: { ...state, authorization: { ...state.authorization, ...(age === undefined ? {} : { primaryAuthAgeSeconds: age }) } },
  };
}

export async function deletionScenario(
  world: BundleWorld,
  operationType: "DELETE_VAULT" | "CANCEL_DELETE_VAULT" | "DELETE_ACCOUNT" | "CANCEL_DELETE_ACCOUNT",
): Promise<Scenario> {
  const isVault = operationType.endsWith("_VAULT");
  const scheduled = operationType.startsWith("CANCEL_");
  const state: BundleState = isVault
    ? {
        ...world.state,
        vaults: world.vaults.map((v, i) =>
          i === 0 && scheduled ? { ...v, state: "DELETING_SCHEDULED" as const } : v,
        ),
      }
    : { ...world.state, accountState: scheduled ? "DELETING_SCHEDULED" : "ACTIVE" };
  return {
    state,
    bundle: assembleBundle({
      operationType,
      bundleId: BUNDLE_ID,
      expected: expectedOf(state),
      deletion: await signDeletion(world.as1.privateKey, {
        operationType,
        accountId: world.accountId,
        ...(isVault ? { vaultId: VAULT_A } : {}),
        rootGeneration: 1,
        nonce: filled(16, 0x90),
      }),
    }),
  };
}

/**
 * §35.15: a valid record of each kind of operation. The request asks for a kit replacement (role 1,
 * TRUSTED_SECURITY); the veto stops a live reset (role 1, ACCOUNT_SECURITY is enough); the cancel
 * takes back a live reset (role 3, RECOVERY_CONTROL) — between them every signer and scope column.
 */
export async function recoveryRecordScenario(world: BundleWorld, operationType: RecoveryRecordOperation): Promise<Scenario> {
  const spec = {
    RECOVERY_REQUEST: { kind: "RECOVERY_KIT_REPLACEMENT", signer: world.as1, scopes: ["VAULT_WRITE", "TRUSTED_SECURITY"], live: [] },
    RECOVERY_VETO: { kind: "RECOVERY_RESET", signer: world.as1, scopes: ["VAULT_WRITE", "ACCOUNT_SECURITY"], live: [storedRequest("RECOVERY_RESET", { ageMs: 1000 })] },
    RECOVERY_CANCEL: { kind: "RECOVERY_RESET", signer: world.ra1, scopes: ["RECOVERY_CONTROL"], live: [storedRequest("RECOVERY_RESET", { ageMs: 1000 })] },
  } as const;
  const { kind, signer, scopes, live } = spec[operationType];
  const state: BundleState = {
    ...world.state,
    authorization: { authenticated: true, emailConfirmed: true, token: { scopes } },
    recoveryRequests: live,
  };
  return {
    state,
    bundle: assembleBundle({
      operationType,
      bundleId: BUNDLE_ID,
      expected: expectedOf(state),
      recovery: await signRecoveryRecord(signer.privateKey, {
        operationType,
        accountId: world.accountId,
        requestId: REQUEST_ID,
        kind,
        rootGeneration: 1,
        rootHash: world.rootHash,
      }),
    }),
  };
}

/** Every operation the applicability table covers, with a bundle that must pass. */
export async function allScenarios(world: BundleWorld): Promise<ReadonlyMap<OperationType, Scenario>> {
  const entries: (readonly [OperationType, Scenario])[] = [
    ["CREATE_ACCOUNT", await createAccountScenario(world)],
    ["ENROLL_CLIENT", await enrollClientScenario(world)],
    ["CREATE_VAULT", await createVaultScenario(world)],
    ["REVOKE_CLIENT", await revokeClientScenario(world)],
    ["CHANGE_SECRETS", await changeSecretsScenario(world)],
    ["RECOVERY_RESET", await recoveryResetScenario(world)],
    ["RECOVERY_KIT_REPLACEMENT", await kitReplacementScenario(world)],
    ["DELETE_VAULT", await deletionScenario(world, "DELETE_VAULT")],
    ["CANCEL_DELETE_VAULT", await deletionScenario(world, "CANCEL_DELETE_VAULT")],
    ["DELETE_ACCOUNT", await deletionScenario(world, "DELETE_ACCOUNT")],
    ["CANCEL_DELETE_ACCOUNT", await deletionScenario(world, "CANCEL_DELETE_ACCOUNT")],
    ["SWITCH_TO_PRIVATE", await switchToPrivateScenario(world)],
    ["SWITCH_TO_MANAGED", await switchToManagedScenario(world)],
    ["RECOVERY_REQUEST", await recoveryRecordScenario(world, "RECOVERY_REQUEST")],
    ["RECOVERY_VETO", await recoveryRecordScenario(world, "RECOVERY_VETO")],
    ["RECOVERY_CANCEL", await recoveryRecordScenario(world, "RECOVERY_CANCEL")],
  ];
  return new Map(entries);
}

/** A shallow copy of a bundle with fields replaced or (with `undefined`) removed. */
export function patch(bundle: SecurityBundle, changes: Record<string, unknown>): SecurityBundle {
  const copy: Record<string, unknown> = { ...bundle };
  for (const [key, value] of Object.entries(changes)) {
    if (value === undefined) delete copy[key];
    else copy[key] = value;
  }
  return copy as unknown as SecurityBundle;
}

export { PLUGIN_ID, BROWSER_ID, BUNDLE_ID };
export type { EnvelopeRecipient };
