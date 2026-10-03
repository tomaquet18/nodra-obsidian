// Fixtures for the §31–§34 suites.
//
// One economy dominates: RSA-OAEP-3072 keygen costs hundreds of milliseconds, so the five pairs
// every suite needs are generated **once** per process and reused. Nothing in §32–§34 cares which
// modulus a recipient holds, only that the right private key opens the right envelope, so sharing
// them removes no assertion. ECDSA pairs are cheap but shared for the same reason.
//
// The world below is one account, one root generation, one registry with a revoked recipient, and
// a vault whose epoch chain the tests extend. It is deliberately *valid*: every negative case is
// built by breaking one thing in a copy of it and re-signing, so a rejection proves the rule and
// not that ECDSA works.
import {
  exportEnvelopePrivateKey,
  exportEnvelopePublicKey,
  generateEnvelopeKeyPair,
  importEnvelopeUnwrapKey,
} from "@nodra/crypto";
import type { EnvelopeUnwrapKey } from "@nodra/crypto";
import type { EpochDescriptor, Registry, RootDescriptor, RootTransition } from "@nodra/encoding/records";
import { epochRecipients, idKey, rootRecipientId, signEpochDescriptor } from "../src/epoch.js";
import type { CreateEpochRequest, CreatedEpoch, EnvelopeRecipient } from "../src/epoch.js";
import { createEpoch, epochDescriptorHash } from "../src/epoch.js";
import { genesisDescriptor, rootHash } from "../src/root-chain.js";
import { initialRegistry, nextRegistry, registryHash, signRegistry } from "../src/registry.js";
import type { NewRecipient } from "../src/registry.js";
import { makeSigner, signRoles, unsignedFor } from "./chain-support.js";
import type { Signer } from "./chain-support.js";
import { filled } from "./bytes-support.js";

export interface RsaPair {
  readonly spki: Uint8Array;
  readonly unwrapKey: EnvelopeUnwrapKey;
}

const POOL_SIZE = 5;
let pool: Promise<readonly RsaPair[]> | null = null;

/** Five RSA-OAEP-3072 pairs, generated once per process (see the note at the top). */
export function rsaPool(): Promise<readonly RsaPair[]> {
  pool ??= Promise.all(
    Array.from({ length: POOL_SIZE }, async () => {
      const pair = await generateEnvelopeKeyPair();
      return {
        spki: await exportEnvelopePublicKey(pair.publicKey),
        // `["unwrapKey"]` only: the normal read path of §33.1, and §44.3 wants it unable to decrypt.
        unwrapKey: await importEnvelopeUnwrapKey(await exportEnvelopePrivateKey(pair.privateKey)),
      };
    }),
  );
  return pool;
}

export interface EpochWorld {
  readonly accountId: Uint8Array;
  readonly vaultId: Uint8Array;
  /** Account Signing Key of generation 1 — the one every descriptor here is signed with. */
  readonly signer: Signer;
  /** A second, valid signing key that belongs to no generation of this account. */
  readonly stranger: Signer;
  readonly root: RootDescriptor;
  readonly rootHash: Uint8Array;
  /** §28.2: the GENESIS transition that installed generation 1, so the chain can be served whole. */
  readonly genesis: RootTransition;
  /** Both signed versions, in order: version 1, then version 2 (§29). */
  readonly registries: readonly Registry[];
  /** Version 2: recipient `0x33` revoked, so `epochRecipients` must leave it out. */
  readonly registry: Registry;
  readonly registryHash: Uint8Array;
  /** The revoked recipient, for the "envelope for a revoked recipient" cases. */
  readonly revoked: EnvelopeRecipient;
  /** ACCOUNT + RECOVERY of the root, plus the two ACTIVE registry recipients (§36.1 step 2). */
  readonly recipients: readonly EnvelopeRecipient[];
  /** The `["unwrapKey"]` handle of each recipient, by `recipient_id` hex. */
  readonly privateKeys: ReadonlyMap<string, EnvelopeUnwrapKey>;
  readonly accountSigningKeys: ReadonlyMap<number, Uint8Array>;
  readonly rootHashes: ReadonlyMap<number, Uint8Array>;
  readonly rootCryptoVersions: ReadonlyMap<number, number>;
  readonly registryHashes: ReadonlyMap<number, Uint8Array>;
}

const REGISTRY_TAGS = [0x31, 0x32, 0x33] as const;

export async function makeWorld(): Promise<EpochWorld> {
  const keys = await rsaPool();
  const [accountKey, recoveryKey, ...recipientKeys] = keys as readonly RsaPair[];
  if (accountKey === undefined || recoveryKey === undefined) throw new Error("rsa pool too small");

  const accountId = filled(16, 0x11);
  const vaultId = filled(16, 0x21);
  const signer = await makeSigner();
  const recoveryAuthority = await makeSigner();
  const stranger = await makeSigner();

  const root = genesisDescriptor(accountId, {
    accountEncryption: accountKey.spki,
    accountSigning: signer.spki,
    recoveryEncryption: recoveryKey.spki,
    recoveryAuthority: recoveryAuthority.spki,
  });
  const hash = await rootHash(root);
  const genesis = await signRoles(await unsignedFor("GENESIS", root, null), [
    [2, signer.privateKey],
    [4, recoveryAuthority.privateKey],
  ]);

  const newRecipients: NewRecipient[] = REGISTRY_TAGS.map((tag, i) => ({
    recipientId: filled(16, tag),
    type: i % 2 === 0 ? "PLUGIN_INSTALLATION" : "TRUSTED_BROWSER",
    publicKey: (recipientKeys[i] as RsaPair).spki,
    label: `device ${tag.toString(16)}`,
  }));
  const v1 = await signRegistry(initialRegistry(accountId, 1, newRecipients), signer.privateKey);
  const v2 = await signRegistry(await nextRegistry(v1, { revoke: [filled(16, REGISTRY_TAGS[2])] }), signer.privateKey);

  const recipients = await epochRecipients(root, v2);
  const privateKeys = new Map<string, EnvelopeUnwrapKey>([
    [idKey(await rootRecipientId(accountKey.spki)), accountKey.unwrapKey],
    [idKey(await rootRecipientId(recoveryKey.spki)), recoveryKey.unwrapKey],
    ...REGISTRY_TAGS.map(
      (tag, i) => [idKey(filled(16, tag)), (recipientKeys[i] as RsaPair).unwrapKey] as const,
    ),
  ]);

  const revokedTag = REGISTRY_TAGS[2];
  return {
    accountId,
    vaultId,
    signer,
    stranger,
    root,
    rootHash: hash,
    genesis,
    registries: [v1, v2],
    registry: v2,
    registryHash: await registryHash(v2),
    revoked: {
      recipientId: filled(16, revokedTag),
      type: "PLUGIN_INSTALLATION",
      publicKey: (recipientKeys[2] as RsaPair).spki,
    },
    recipients,
    privateKeys,
    accountSigningKeys: new Map([[1, signer.spki]]),
    rootHashes: new Map([[1, hash]]),
    rootCryptoVersions: new Map([[1, 1]]),
    registryHashes: new Map([
      [1, await registryHash(v1)],
      [2, await registryHash(v2)],
    ]),
  };
}

/** The verifier options a valid world produces. */
export function chainOptions(world: EpochWorld): {
  vaultId: Uint8Array;
  accountSigningKeys: ReadonlyMap<number, Uint8Array>;
  rootHashes: ReadonlyMap<number, Uint8Array>;
  rootCryptoVersions: ReadonlyMap<number, number>;
  registryHashes: ReadonlyMap<number, Uint8Array>;
} {
  return {
    vaultId: world.vaultId,
    accountSigningKeys: world.accountSigningKeys,
    rootHashes: world.rootHashes,
    rootCryptoVersions: world.rootCryptoVersions,
    registryHashes: world.registryHashes,
  };
}

export interface EpochLink {
  readonly created: CreatedEpoch;
  readonly previous: { readonly epochId: Uint8Array; readonly descriptorHash: Uint8Array } | null;
}

/** One epoch of the world's vault, chained onto `previous`. */
export async function makeEpoch(
  world: EpochWorld,
  tag: number,
  previous: CreatedEpoch | null,
  overrides: Partial<CreateEpochRequest> = {},
): Promise<CreatedEpoch> {
  return createEpoch({
    vaultId: world.vaultId,
    epochId: filled(16, tag),
    previous:
      previous === null
        ? null
        : { epochId: previous.descriptor.epoch_id, descriptorHash: previous.descriptorHash },
    root: { generation: 1, hash: world.rootHash, cryptoVersion: 1 },
    registry: { version: 2, hash: world.registryHash },
    recipients: world.recipients,
    signingKey: world.signer.privateKey,
    ...overrides,
  });
}

/** A chain of `length` epochs over the world's vault, tagged 0x41, 0x42, … */
export async function makeEpochChain(world: EpochWorld, length: number): Promise<readonly CreatedEpoch[]> {
  const out: CreatedEpoch[] = [];
  let previous: CreatedEpoch | null = null;
  for (let i = 0; i < length; i++) {
    previous = await makeEpoch(world, 0x41 + i, previous);
    out.push(previous);
  }
  return out;
}

/** A descriptor with fields replaced and re-signed, so a test exercises the rule it names. */
export async function resignDescriptor(
  descriptor: EpochDescriptor,
  patch: Partial<Omit<EpochDescriptor, "signature">>,
  signer: Signer,
): Promise<EpochDescriptor> {
  const { signature: _signature, ...draft } = descriptor;
  return signEpochDescriptor({ ...draft, ...patch }, signer.privateKey);
}

export { epochDescriptorHash };
