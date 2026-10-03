// §35.2: account creation, the one operation that starts from nothing.
//
// The numbered list in §35.2 is an *order*, not a menu, and two of its orderings are security
// properties rather than conveniences:
//
//   - the Recovery Kit is built (step 6) and self-tested against the **pending** Root Descriptor
//     (step 8) before the GENESIS transition is signed (step 9), so a kit that cannot open what it
//     is about to become responsible for is never shown to a user (§27.3);
//   - everything the client must keep — the recipient's private key, its `recipient_id` and the
//     exact bundle bytes — is producible *before* the bundle is sent (step 15), because a lost
//     response must never leave an ACTIVE recipient whose private key nobody has (§35.4 step 6).
//
// This builder performs steps 2–14 and hands the caller everything steps 15–17 need. It enforces
// no §35.1.1 rule: `validateSecurityBundle` is the one place those live, and a builder that
// quietly corrected its own output would hide a client bug instead of surfacing it.
import { SECURITY_BUNDLE, encodeRecord } from "@nodra/encoding/records";
import type {
  AccountSecurityConfig,
  AccountSecurityProfile,
  Registry,
  RootDescriptor,
  RootTransition,
  SecurityBundle,
} from "@nodra/encoding/records";
import { zeroize } from "@nodra/crypto";
import type { Argon2Params } from "@nodra/crypto";
import type { Argon2Params as Argon2ParamsRecord, EscrowBlob } from "@nodra/encoding/records";
import { buildEscrowBlob } from "./escrow.js";
import type { EscrowPublicKey } from "./escrow.js";
import { assembleBundle } from "./bundle-build.js";
import type { ClientPins } from "./client-state.js";
import { sealNextConfig } from "./client-state.js";
import { createEpoch, epochRecipients } from "./epoch.js";
import type { CreatedEpoch } from "./epoch.js";
import type { OperationFailure } from "./client-state.js";
import type { Outcome, UnlockFailureCode } from "./errors.js";
import { buildAccountSecurityProfile, createAccountRootKeyset, createManagedAccountKeyset } from "./keyset.js";
import type { AccountKeyset, CreatedAccountRootKeyset, CreatedManagedKeyset } from "./keyset.js";
import { defaultPorts } from "./ports.js";
import type { KeyLifecyclePorts } from "./ports.js";
import {
  createRecoveryKit,
  escrowedRecoveryKeysOf,
  generateRecoveryKeyPairs,
  recoveryRootKeys,
  selfTestEscrowedRecoveryKeys,
  selfTestRecoveryKit,
  serializeEscrowedRecoveryKeys,
} from "./recovery-kit.js";
import type { CreatedRecoveryKit, RecoveryKeyPairs, RecoveryKitFailureCode } from "./recovery-kit.js";
import { initialRegistry, registryHash, signRegistry } from "./registry.js";
import type { NewRecipient } from "./registry.js";
import { genesisDescriptor, rootHash, signRootTransition } from "./root-chain.js";
import type { AccountSecretKeyInput } from "./secrets.js";

/** Whatever stopped §35.2: a keyset failure of §24/§25, or a Recovery Kit self-test of §27.3. */
export type CreateAccountFailureCode = UnlockFailureCode | RecoveryKitFailureCode;

export type CreateAccountFailure = OperationFailure<CreateAccountFailureCode>;

/** What both modes of §35.2 take. */
export interface CreateAccountBase {
  /** The account the client authenticated as (Supabase Auth), step 1. */
  readonly accountId: Uint8Array;
  /** UUIDv7s the caller generated (§23.2): this package has no id generator. */
  readonly bundleId: Uint8Array;
  /** Step 12: MUST NOT exist in `vaults` nor in `retired_ids` (§35.1.1 step 0c). */
  readonly vaultId: Uint8Array;
  readonly epochId: Uint8Array;
  /**
   * Step 11: this client's own recipient, whose pair was generated `extractable = false` with the
   * private half `["unwrapKey"]` (§30.1) — see `prepareEnrollment` in `enrollment.ts`.
   */
  readonly recipient: NewRecipient;
  readonly ports?: KeyLifecyclePorts;
}

/** §35.2 with the two secrets of §24: a Private, `crypto_version = 1` account. */
export interface CreateAccountRequest extends CreateAccountBase {
  /** Step 2: the Encryption Password the user chose. */
  readonly password: string;
  /** Step 3 generates one when omitted; §35.6 supplies one when it changes. */
  readonly secretKey?: AccountSecretKeyInput;
  readonly argon2Params?: Argon2Params;
  readonly kdfSalt?: Uint8Array;
}

/** §35.2 in Managed: the Escrow Key in force, as `getRootState` served it (§3.6, over TLS, no pin). */
export interface CreateManagedAccountRequest extends CreateAccountBase {
  readonly escrowKey: EscrowPublicKey;
}

/** What both modes of §35.2 produce. */
export interface AssembledAccount {
  readonly bundle: SecurityBundle;
  /** Step 15: the exact bytes to persist as PENDING, so a lost response can resend them verbatim. */
  readonly serializedBundle: Uint8Array;
  /** Step 15: persisted with the recipient's private key, and closed out in step 17. */
  readonly pendingRecipientId: Uint8Array;
  readonly rootTransition: RootTransition;
  readonly root: RootDescriptor;
  readonly rootHash: Uint8Array;
  readonly registry: Registry;
  readonly registryHash: Uint8Array;
  readonly config: AccountSecurityConfig;
  readonly profile: AccountSecurityProfile;
  /** E1 of the first vault, with its Epoch Key ready to use — the creator never re-opens it. */
  readonly epoch: CreatedEpoch;
  /** Step 17: what to pin once the bundle comes back applied. */
  readonly pins: ClientPins;
}

export interface CreatedAccount extends AssembledAccount {
  /** Step 3: the Setup Kit. Shown once, stored nowhere (§3.3); the caller zeroizes the bytes. */
  readonly setupKit: { readonly accountSecretKey: Uint8Array; readonly accountSecretKeyText: string };
  /** Step 8: only present because the self-test passed — §27.3 forbids showing any other kit. */
  readonly recoveryKit: CreatedRecoveryKit;
  /**
   * Step 17: every handle that must be discarded when the operation ends — the extractable account
   * privates (§25.2), the derived keys (§24.1) and the kit's privates (§27.2). Returned rather than
   * hidden because only the caller knows when its operation is over.
   */
  readonly keyset: CreatedAccountRootKeyset;
}

/** §35.2 in Managed: no Setup Kit and no Recovery Kit are ever shown (§3.6, §27). */
export interface CreatedManagedAccount extends AssembledAccount {
  /** SecurityBundle key 14, already in `bundle`: both slots, wrapped to the Escrow Key. */
  readonly escrow: EscrowBlob;
  /** The Recovery pairs, to discard with the operation; their privates live only in the escrow. */
  readonly recoveryKeys: RecoveryKeyPairs;
  /** The derived keys and account privates to discard; `rootUnlockKey` is already zeroized. */
  readonly keyset: CreatedManagedKeyset;
}

/**
 * §35.2 steps 2–14. The result carries everything steps 15–17 need and nothing the client must
 * not keep: the `epoch_secret` is already gone (§31.1) and no private key is persisted here.
 */
export async function createAccount(
  request: CreateAccountRequest,
): Promise<Outcome<CreatedAccount, CreateAccountFailure>> {
  const ports = request.ports ?? defaultPorts;
  const accountId = request.accountId;

  // Steps 3–5 and 10: secrets, derived keys, the two account pairs, and the wrapped keyset.
  const created = await createAccountRootKeyset({
    accountId,
    password: request.password,
    ...(request.secretKey === undefined ? {} : { secretKey: request.secretKey }),
    ...(request.argon2Params === undefined ? {} : { argon2Params: request.argon2Params }),
    ...(request.kdfSalt === undefined ? {} : { kdfSalt: request.kdfSalt }),
    ports,
  });
  if (!created.ok) {
    return { ok: false, failure: { code: created.failure.code, step: 3, message: created.failure.message } };
  }
  const keyset = created.value;

  // Steps 6–7: the recovery pairs, then the pending Root Descriptor they complete.
  const recoveryKeys = await generateRecoveryKeyPairs();
  const root = genesisDescriptor(accountId, {
    accountEncryption: keyset.encryption.publicKeySpki,
    accountSigning: keyset.signing.publicKeySpki,
    ...recoveryRootKeys(recoveryKeys),
  });
  const hash = await rootHash(root);

  // Step 6 (the document) and step 8 (the test that makes it showable).
  const recoveryKit = await createRecoveryKit({ accountId, genesisRootHash: hash, keys: recoveryKeys, ports });
  const selfTest = await selfTestRecoveryKit({
    serialized: recoveryKit.serialized,
    accountId,
    pendingDescriptor: root,
    ports,
  });
  if (!selfTest.ok) {
    return { ok: false, failure: { code: selfTest.failure.code, step: 8, message: selfTest.failure.message } };
  }

  const assembled = await assembleAccount({
    request,
    keyset,
    recoveryKeys,
    root,
    hash,
    kdf: { kdfSalt: keyset.kdfSalt, argon2Params: keyset.argon2Params },
    ports,
  });
  return {
    ok: true,
    value: {
      ...assembled,
      setupKit: {
        accountSecretKey: keyset.accountSecretKey,
        accountSecretKeyText: keyset.accountSecretKeyText,
      },
      recoveryKit,
      keyset,
    },
  };
}

/**
 * §35.2 in Managed (ADR-021, PROVISIONAL): no secrets and no kit. A random `RootUnlockKey` replaces
 * the two secrets (step 4), the Recovery privates are serialized as `EscrowedRecoveryKeys` and
 * self-tested there (steps 6 and 8), the root is `crypto_version = 2`, the profile has no KDF
 * fields, and both escrow slots travel in the same `CREATE_ACCOUNT` (§3.6). Nothing secret leaves
 * the client unwrapped.
 */
export async function createManagedAccount(
  request: CreateManagedAccountRequest,
): Promise<Outcome<CreatedManagedAccount, CreateAccountFailure>> {
  const ports = request.ports ?? defaultPorts;
  const accountId = request.accountId;
  const keyset = await createManagedAccountKeyset({ accountId, ports });
  try {
    const recoveryKeys = await generateRecoveryKeyPairs();
    const root = genesisDescriptor(
      accountId,
      {
        accountEncryption: keyset.encryption.publicKeySpki,
        accountSigning: keyset.signing.publicKeySpki,
        ...recoveryRootKeys(recoveryKeys),
      },
      // §23.1: new accounts are version 2, and a version-2 GENESIS is a Managed account (§3.6).
      2,
    );
    const hash = await rootHash(root);
    const selfTest = await selfTestEscrowedRecoveryKeys({
      serialized: serializeEscrowedRecoveryKeys(recoveryKeys),
      accountId,
      pendingDescriptor: root,
      ports,
    });
    if (!selfTest.ok) {
      return { ok: false, failure: { code: selfTest.failure.code, step: 8, message: selfTest.failure.message } };
    }
    const escrow = await buildEscrowBlob({
      accountId,
      escrowKey: request.escrowKey,
      rootUnlockKey: keyset.rootUnlockKey,
      recoveryKeys: escrowedRecoveryKeysOf(recoveryKeys),
      ports,
    });
    const assembled = await assembleAccount({ request, keyset, recoveryKeys, root, hash, kdf: null, escrow, ports });
    return { ok: true, value: { ...assembled, escrow, recoveryKeys, keyset } };
  } finally {
    // §24: the bytes exist only to be derived from and wrapped to the Escrow Key.
    zeroize(keyset.rootUnlockKey);
  }
}

interface AssembleAccountRequest {
  readonly request: CreateAccountBase;
  readonly keyset: AccountKeyset;
  readonly recoveryKeys: RecoveryKeyPairs;
  readonly root: RootDescriptor;
  readonly hash: Uint8Array;
  /** Private: the §24 KDF fields of the profile. Managed: null (§23.4). */
  readonly kdf: { readonly kdfSalt: Uint8Array; readonly argon2Params: Argon2ParamsRecord } | null;
  readonly escrow?: EscrowBlob;
  readonly ports: KeyLifecyclePorts;
}

/** §35.2 steps 9 and 11–14, identical in both modes (§3.6). */
async function assembleAccount(input: AssembleAccountRequest): Promise<AssembledAccount> {
  const { request, keyset, recoveryKeys, root, hash, ports } = input;
  const accountId = request.accountId;

  // Step 9: GENESIS, signed with roles 2 (new Account Signing) and 4 (new Recovery Authority).
  const rootTransition = await signRootTransition({
    type: "GENESIS",
    descriptor: root,
    signers: { 2: keyset.signing.privateKey, 4: recoveryKeys.authority.privateKey },
  });

  // Step 11: Registry v1 with exactly this client (§35.1.1, "Forma del registry").
  const registry = await signRegistry(
    initialRegistry(accountId, root.root_generation, [request.recipient]),
    keyset.signing.privateKey,
  );
  const rHash = await registryHash(registry);

  // Steps 12–13: the first vault's E1, with envelopes for ACCOUNT, RECOVERY and this client.
  const epoch = await createEpoch({
    vaultId: request.vaultId,
    epochId: request.epochId,
    previous: null,
    root: { generation: root.root_generation, hash, cryptoVersion: root.crypto_version },
    registry: { version: registry.registry_version, hash: rHash },
    recipients: await epochRecipients(root, registry),
    signingKey: keyset.signing.privateKey,
    ports,
  });

  // Step 14: the config and the profile that carries it. Before GENESIS the version in force is 0.
  const sealed = await sealNextConfig(keyset.derived.configKey, {
    root,
    rootHash: hash,
    genesisRootHash: hash,
    registryVersion: registry.registry_version,
    registryHash: rHash,
    configVersion: 1,
  });
  const profile = buildAccountSecurityProfile({
    accountId,
    ...(input.kdf ?? {}),
    wrappedEncryptionKey: keyset.encryption.wrapped,
    wrappedSigningKey: keyset.signing.wrapped,
    configVersion: sealed.configVersion,
    configBlob: sealed.blob,
  });

  const bundle = assembleBundle({
    operationType: "CREATE_ACCOUNT",
    bundleId: request.bundleId,
    // §35.1.1 step 7: before GENESIS the three `expected` values are 0.
    expected: { root_generation: 0, registry_version: 0, config_version: 0 },
    rootTransition,
    rootDescriptor: root,
    registry,
    profile,
    epochs: [{ descriptor: epoch.descriptor, envelopes: [...epoch.envelopes] }],
    ...(input.escrow === undefined ? {} : { escrow: input.escrow }),
  });

  return {
    bundle,
    serializedBundle: encodeRecord(SECURITY_BUNDLE, bundle),
    pendingRecipientId: request.recipient.recipientId,
    rootTransition,
    root,
    rootHash: hash,
    registry,
    registryHash: rHash,
    config: sealed.config,
    profile,
    epoch,
    pins: {
      rootGeneration: root.root_generation,
      rootHash: hash,
      genesisRootHash: hash,
      registryVersion: registry.registry_version,
      registryHash: rHash,
      configVersion: sealed.configVersion,
      epochs: [
        {
          vaultId: request.vaultId,
          epochId: request.epochId,
          descriptorHash: epoch.descriptorHash,
        },
      ],
    },
  };
}
