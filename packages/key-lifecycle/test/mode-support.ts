// Fixtures for the ADR-021 operation suites: an Escrow Key with its Worker-side port, and a Managed
// account built by the real §35.2 (Managed), held as a verified client and as the Worker would.
import { exportEnvelopePublicKey, generateEnvelopeKeyPair, generateRecipientKeyPair, openEscrowKey, openEpochSecret } from "@nodra/crypto";
import type { DomainContext, EnvelopeKeyPair, EnvelopeOpeningKey, RecipientKeyPair } from "@nodra/crypto";
import type { EpochEnvelope, EscrowBlob, EscrowSlot, RootDescriptor, RootTransition } from "@nodra/encoding/records";
import { createManagedAccount } from "../src/account-creation.js";
import type { AssembledAccount, CreatedManagedAccount } from "../src/account-creation.js";
import type { BundleState, BundleVault } from "../src/bundle.js";
import type { AccountView, ClientVault } from "../src/client-state.js";
import { envelopeLabelContext } from "../src/contexts.js";
import { createEpoch, epochRecipients, idKey, rootRecipientId } from "../src/epoch.js";
import type { CreatedEpoch } from "../src/epoch.js";
import { verifyEpochChain } from "../src/epoch-chain.js";
import { openEscrowRewrap, rewrapEscrowSlot } from "../src/escrow.js";
import type { EscrowKeyStore, EscrowPublicKey, OpenedEscrow } from "../src/escrow.js";
import { prepareEnrollment } from "../src/enrollment.js";
import type { EnrollmentKeys } from "../src/enrollment.js";
import type { KeyLifecyclePorts } from "../src/ports.js";
import type { EnvelopeSource } from "../src/re-envelope.js";
import { verifyRegistryChain } from "../src/registry.js";
import { verifyRootChain } from "../src/root-chain.js";
import { filled, memoPorts } from "./support.js";

export const MANAGED_ACCOUNT_ID = filled(16, 0x61);
export const M_VAULT_A = filled(16, 0x62);
export const M_VAULT_B = filled(16, 0x63);
const ESCROW_KEY_ID = filled(16, 0xe0);

export interface EscrowWorld {
  readonly pair: EnvelopeKeyPair;
  readonly escrowKey: EscrowPublicKey;
  readonly store: EscrowKeyStore;
  /** A client's per-unlock ephemeral pair (§24.2 step 2). */
  readonly ephemeral: RecipientKeyPair;
  readonly ephemeralSpki: Uint8Array;
}

let escrow: Promise<EscrowWorld> | null = null;

export function escrowWorld(): Promise<EscrowWorld> {
  escrow ??= (async () => {
    const [pair, ephemeral] = await Promise.all([generateEnvelopeKeyPair(), generateRecipientKeyPair()]);
    return {
      pair,
      escrowKey: { keyId: ESCROW_KEY_ID, publicKey: pair.publicKey },
      store: { unwrap: async (_keyId, wrapped, label) => openEscrowKey(pair.privateKey, label as DomainContext, wrapped) },
      ephemeral,
      ephemeralSpki: await exportEnvelopePublicKey(ephemeral.publicKey),
    };
  })();
  return escrow;
}

/** §24.2 / §35.7 end to end: the Worker re-wraps one stored slot and the client opens it. */
export async function unwrapSlot(accountId: Uint8Array, slot: EscrowSlot): Promise<OpenedEscrow> {
  const e = await escrowWorld();
  const re = await rewrapEscrowSlot({ accountId, slot, ephemeralSpki: e.ephemeralSpki, store: e.store });
  if (!re.ok) throw new Error(`rewrap: ${re.failure.code}`);
  const opened = await openEscrowRewrap({
    accountId,
    slot: slot.slot,
    ephemeralKey: e.ephemeral.privateKey,
    ephemeralSpki: e.ephemeralSpki,
    rewrap: re.value.rewrap,
  });
  if (!opened.ok) throw new Error(`open: ${opened.failure.code}`);
  return opened.value;
}

export interface HeldAccount {
  readonly view: AccountView;
  readonly state: BundleState;
  /** The ACCOUNT and RECOVERY envelope of every epoch (§33.2 sources). */
  readonly sources: readonly EnvelopeSource[];
  readonly recoverySources: readonly EnvelopeSource[];
  readonly epochs: readonly CreatedEpoch[];
}

/**
 * An account as a verified client and the Worker hold it after its creation bundle and one more
 * vault were applied. `transition` + `root` are the chain so far (GENESIS only).
 */
export async function holdAccount(input: {
  readonly accountId: Uint8Array;
  readonly created: AssembledAccount;
  readonly signingSpki: Uint8Array;
  readonly extraVault: CreatedEpoch;
  readonly escrow: EscrowBlob | null;
  readonly chain: readonly { transition: RootTransition; descriptor: RootDescriptor }[];
}): Promise<HeldAccount> {
  const { accountId, created } = input;
  const root = await verifyRootChain(input.chain, { accountId });
  if (!root.ok) throw new Error(`root: ${root.failure.code}`);
  const registry = await verifyRegistryChain([created.registry], {
    accountId,
    accountSigningKeys: new Map([[1, input.signingSpki]]),
  });
  if (!registry.ok) throw new Error(`registry: ${registry.failure.code}`);

  const epochs = [created.epoch, input.extraVault];
  const vaults: BundleVault[] = [];
  const clientVaults: ClientVault[] = [];
  for (const epoch of epochs) {
    const replay = await verifyEpochChain([epoch.descriptor], {
      vaultId: epoch.descriptor.vault_id,
      accountSigningKeys: new Map([[1, input.signingSpki]]),
      rootHashes: new Map([[1, created.rootHash]]),
      rootCryptoVersions: new Map([[1, created.root.crypto_version]]),
      registryHashes: new Map([[1, created.registryHash]]),
    });
    if (!replay.ok) throw new Error(`epoch: ${replay.failure.code}`);
    const listed = [{ descriptor: epoch.descriptor, state: "ACTIVE" as const }];
    vaults.push({ vaultId: epoch.descriptor.vault_id, state: "ACTIVE", currentEpoch: replay.value, epochs: listed });
    clientVaults.push({
      vaultId: epoch.descriptor.vault_id,
      state: "ACTIVE",
      epochs: listed,
      current: { epochId: epoch.descriptor.epoch_id, descriptorHash: replay.value.currentHash },
    });
  }
  const account = await rootRecipientId(created.root.account_encryption_public_key);
  const recovery = await rootRecipientId(created.root.recovery_encryption_public_key);
  return {
    view: {
      accountId,
      root: created.root,
      rootHash: created.rootHash,
      genesisRootHash: created.rootHash,
      registry: created.registry,
      registryHash: created.registryHash,
      configVersion: created.config.config_version,
      vaults: clientVaults,
    },
    state: {
      authorization: { authenticated: true, token: { scopes: ["VAULT_WRITE", "TRUSTED_SECURITY"] } },
      accountId,
      accountState: "ACTIVE",
      root: root.value,
      registry: registry.value,
      configVersion: created.config.config_version,
      vaults,
      escrow: input.escrow,
    },
    sources: epochs.map((e) => ({ descriptor: e.descriptor, envelope: envelopeOf(e.envelopes, account) })),
    recoverySources: epochs.map((e) => ({ descriptor: e.descriptor, envelope: envelopeOf(e.envelopes, recovery) })),
    epochs,
  };
}

export interface ManagedWorld extends HeldAccount {
  readonly ports: KeyLifecyclePorts;
  readonly created: CreatedManagedAccount;
  readonly client: EnrollmentKeys;
}

let managed: Promise<ManagedWorld> | null = null;

/** A Managed account created by §35.2 (Managed), with a second vault. Built once per process. */
export function managedWorld(): Promise<ManagedWorld> {
  managed ??= (async () => {
    const ports = memoPorts();
    const e = await escrowWorld();
    const client = await prepareEnrollment({ recipientId: filled(16, 0x64), type: "PLUGIN_INSTALLATION", label: "managed plugin" });
    const outcome = await createManagedAccount({
      accountId: MANAGED_ACCOUNT_ID,
      bundleId: filled(16, 0x65),
      vaultId: M_VAULT_A,
      epochId: filled(16, 0x66),
      recipient: client.recipient,
      escrowKey: e.escrowKey,
      ports,
    });
    if (!outcome.ok) throw new Error(`managed §35.2: ${outcome.failure.code}`);
    const created = outcome.value;
    const extraVault = await createEpoch({
      vaultId: M_VAULT_B,
      epochId: filled(16, 0x67),
      previous: null,
      root: { generation: 1, hash: created.rootHash, cryptoVersion: created.root.crypto_version },
      registry: { version: 1, hash: created.registryHash },
      recipients: await epochRecipients(created.root, created.registry),
      signingKey: created.keyset.signing.privateKey,
      ports,
    });
    const held = await holdAccount({
      accountId: MANAGED_ACCOUNT_ID,
      created,
      signingSpki: created.keyset.signing.publicKeySpki,
      extraVault,
      escrow: created.escrow,
      chain: [{ transition: created.rootTransition, descriptor: created.root }],
    });
    return { ...held, ports, created, client };
  })();
  return managed;
}

export function envelopeOf(envelopes: readonly EpochEnvelope[], recipientId: Uint8Array): EpochEnvelope {
  const found = envelopes.find((e) => idKey(e.recipient_id) === idKey(recipientId));
  if (found === undefined) throw new Error(`no envelope for ${idKey(recipientId)}`);
  return found;
}

/**
 * §44.5 "todo blob actual es descifrable por ACCOUNT y por RECOVERY", as an oracle over one epoch:
 * whether `key` opens *some* envelope of the epoch under the label of the recipient it claims.
 */
export async function opensEpoch(
  envelopes: readonly EpochEnvelope[],
  key: EnvelopeOpeningKey,
): Promise<boolean> {
  for (const envelope of envelopes) {
    try {
      const label = envelopeLabelContext(envelope.vault_id, envelope.epoch_id, envelope.recipient_id, envelope.recipient_type);
      await openEpochSecret(key, label, envelope.ciphertext);
      return true;
    } catch {
      // not this one
    }
  }
  return false;
}
