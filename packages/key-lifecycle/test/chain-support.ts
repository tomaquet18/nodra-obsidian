// Fixtures shared by the §28 root-chain and §29 registry suites.
//
// Two economies keep the runtime sane. ECDSA P-256 pairs are generated once and reused across
// cases: §28 never cares *which* key a role holds, only that the right one signed. And recipient
// public keys are filler bytes, because §29 treats them as opaque SPKI — nothing in the registry
// verifier imports them, so paying for RSA-3072 keygen would buy no assertion.
import { exportVerifyingKey, generateSigningKeyPair, signContext } from "@nodra/crypto";
import type { ExtractableSigningKey } from "@nodra/crypto";
import { decodeRecord, encodeRecord } from "@nodra/encoding/records";
import type { AnyRecordSchema, Registry, RootDescriptor, RootTransition } from "@nodra/encoding/records";
import { rootTransitionContext } from "../src/contexts.js";
import { genesisDescriptor, nextDescriptor, rootHash } from "../src/root-chain.js";
import type { RootChainLink, RootPublicKeys, SignerRole, UnsignedRootTransition } from "../src/root-chain.js";
import { initialRegistry, nextRegistry, signRegistry } from "../src/registry.js";
import type { NewRecipient, RegistryChange, UnsignedRegistry } from "../src/registry.js";
import { filled } from "./bytes-support.js";

export interface Signer {
  readonly spki: Uint8Array;
  readonly privateKey: ExtractableSigningKey;
}

export async function makeSigner(): Promise<Signer> {
  const pair = await generateSigningKeyPair();
  return { spki: await exportVerifyingKey(pair.publicKey), privateKey: pair.privateKey };
}

export async function makeSigners(count: number): Promise<Signer[]> {
  return Promise.all(Array.from({ length: count }, () => makeSigner()));
}

/** The four descriptor keys: two real P-256 SPKI, two opaque (§28 never imports the encryption keys). */
export function rootKeys(accountSigning: Signer, recoveryAuthority: Signer, tag: number): RootPublicKeys {
  return {
    accountEncryption: filled(32, tag),
    accountSigning: accountSigning.spki,
    recoveryEncryption: filled(32, tag ^ 0x80),
    recoveryAuthority: recoveryAuthority.spki,
  };
}

/** Signs an arbitrary unsigned transition with an arbitrary role list, in the order given. */
export async function signRoles(
  unsigned: UnsignedRootTransition,
  signers: readonly (readonly [SignerRole, ExtractableSigningKey])[],
): Promise<RootTransition> {
  const ctx = rootTransitionContext(unsigned);
  const signatures = [];
  for (const [code, key] of signers) signatures.push({ code, value: await signContext(key, ctx) });
  return { ...unsigned, signatures };
}

export interface ChainFixture {
  readonly accountId: Uint8Array;
  /** `[account signing, recovery authority]` of each generation, in order. */
  readonly signers: readonly (readonly [Signer, Signer])[];
  readonly links: readonly RootChainLink[];
}

/**
 * A GENESIS plus one `RECOVERY_RESET` (new account keys) plus one `RECOVERY_KIT_REPLACEMENT`
 * (new recovery keys) — one link of every type the MVP allows.
 */
export async function makeChain(accountId: Uint8Array, pool: readonly Signer[]): Promise<ChainFixture> {
  const [as1, ra1, as2, ra3] = pool as [Signer, Signer, Signer, Signer];

  const g1 = genesisDescriptor(accountId, rootKeys(as1, ra1, 0x11));
  const t1 = await signRoles(await unsignedFor("GENESIS", g1, null), [
    [2, as1.privateKey],
    [4, ra1.privateKey],
  ]);

  const g2 = await nextDescriptor(g1, { accountEncryption: filled(32, 0x22), accountSigning: as2.spki });
  const t2 = await signRoles(await unsignedFor("RECOVERY_RESET", g2, g1), [
    [2, as2.privateKey],
    [3, ra1.privateKey],
  ]);

  const g3 = await nextDescriptor(g2, { recoveryEncryption: filled(32, 0x33), recoveryAuthority: ra3.spki });
  const t3 = await signRoles(await unsignedFor("RECOVERY_KIT_REPLACEMENT", g3, g2), [
    [1, as2.privateKey],
    [4, ra3.privateKey],
  ]);

  return {
    accountId,
    signers: [
      [as1, ra1],
      [as2, ra1],
      [as2, ra3],
    ],
    links: [
      { transition: t1, descriptor: g1 },
      { transition: t2, descriptor: g2 },
      { transition: t3, descriptor: g3 },
    ],
  };
}

/** The `campos 1–5` of a transition, derived from the descriptors it joins (§28.2). */
export async function unsignedFor(
  type: RootTransition["transition_type"],
  descriptor: RootDescriptor,
  previous: RootDescriptor | null,
): Promise<UnsignedRootTransition> {
  return {
    account_id: descriptor.account_id,
    transition_type: type,
    old_root_hash: previous === null ? null : await rootHash(previous),
    new_root_hash: await rootHash(descriptor),
    new_root_generation: descriptor.root_generation,
  };
}

/** SPKI of the Account Signing Key of each generation, as `verifyRegistryChain` wants it. */
export function signingKeysOf(chain: ChainFixture): Map<number, Uint8Array> {
  return new Map(chain.signers.map(([accountSigning], i) => [i + 1, accountSigning.spki]));
}

export function recipient(tag: number, label = `device ${tag}`): NewRecipient {
  return { recipientId: filled(16, tag), type: tag % 2 === 0 ? "TRUSTED_BROWSER" : "PLUGIN_INSTALLATION", publicKey: filled(48, tag), label };
}

export async function makeRegistry(
  accountId: Uint8Array,
  rootGeneration: number,
  recipients: readonly NewRecipient[],
  signer: Signer,
): Promise<Registry> {
  return signRegistry(initialRegistry(accountId, rootGeneration, recipients), signer.privateKey);
}

export async function evolve(current: Registry, change: RegistryChange, signer: Signer): Promise<Registry> {
  return signRegistry(await nextRegistry(current, change), signer.privateKey);
}

/** Re-signs a hand-edited draft, so a test exercises the rule it names and not the signature. */
export async function resignRegistry(draft: UnsignedRegistry, signer: Signer): Promise<Registry> {
  return signRegistry(draft, signer.privateKey);
}

/**
 * A record with one byte of its canonical encoding flipped, decoded back. `null` means the
 * mutation produced bytes the codec refuses — which is itself a rejection.
 */
export function mutateRecord<T>(schema: AnyRecordSchema, value: T, byteIndex: number): T | null {
  const bytes = encodeRecord(schema as never, value as never);
  const copy = Uint8Array.from(bytes);
  const i = ((byteIndex % copy.length) + copy.length) % copy.length;
  copy[i] = (copy[i] as number) ^ 0x01;
  try {
    return decodeRecord(schema as never, copy) as T;
  } catch {
    return null;
  }
}

export function encodedLength<T>(schema: AnyRecordSchema, value: T): number {
  return encodeRecord(schema as never, value as never).length;
}
