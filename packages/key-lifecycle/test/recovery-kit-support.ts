// Fixtures for the §27 Recovery Kit suites.
//
// One economy dominates: an RSA-OAEP-3072 key pair costs hundreds of milliseconds to generate, so
// the two recovery key sets are built **once** per suite and reused. Nothing in §27 cares which
// key a kit holds, only that the kit's private matches the root's public, so reuse costs no
// assertion. The account keys of the descriptors are filler bytes: §27 never imports them.
import { randomBytes } from "@nodra/crypto";
import type { RecoveryKit, RootDescriptor } from "@nodra/encoding/records";
import { createRecoveryKit, generateRecoveryKeyPairs, recoveryRootKeys } from "../src/recovery-kit.js";
import type { CreatedRecoveryKit, RecoveryKeyPairs } from "../src/recovery-kit.js";
import { genesisDescriptor, nextDescriptor, rootHash } from "../src/root-chain.js";
import { serializeRecoveryKit } from "../src/recovery-kit.js";
import type { KeyLifecyclePorts } from "../src/ports.js";
import { FIXED_NOW, filled } from "./support.js";

/** Ports with a fixed clock: `created_at` is the only thing that could vary between runs. */
export const kitPorts: KeyLifecyclePorts = {
  randomBytes,
  now: FIXED_NOW,
  derivePasswordKey: () => {
    throw new Error("§27 never derives a password key");
  },
};

export interface KitFixture {
  readonly accountId: Uint8Array;
  readonly genesisRootHash: Uint8Array;
  /** Generation 1: the root in force, whose recovery keys belong to {@link KitFixture.kitA}. */
  readonly currentDescriptor: RootDescriptor;
  /**
   * Generation 2 of a `RECOVERY_KIT_REPLACEMENT` (§28.2): the **pending** descriptor, holding the
   * recovery keys of {@link KitFixture.kitB} and the same account keys.
   */
  readonly pendingDescriptor: RootDescriptor;
  readonly keysA: RecoveryKeyPairs;
  readonly keysB: RecoveryKeyPairs;
  readonly kitA: CreatedRecoveryKit;
  readonly kitB: CreatedRecoveryKit;
}

/**
 * A genesis root with kit A, plus the pending root of a kit replacement with kit B. That pair is
 * what makes "pending" and "current" distinguishable at all: kit B is correct for the pending
 * descriptor and wrong for the current one, and kit A the other way round.
 */
export async function makeKitFixture(accountId: Uint8Array = filled(16, 0x11)): Promise<KitFixture> {
  const [keysA, keysB] = await Promise.all([generateRecoveryKeyPairs(), generateRecoveryKeyPairs()]);

  const currentDescriptor = genesisDescriptor(accountId, {
    accountEncryption: filled(64, 0x41),
    accountSigning: filled(48, 0x42),
    ...recoveryRootKeys(keysA),
  });
  const genesisRootHash = await rootHash(currentDescriptor);
  const pendingDescriptor = await nextDescriptor(currentDescriptor, recoveryRootKeys(keysB));

  const [kitA, kitB] = await Promise.all([
    createRecoveryKit({ accountId, genesisRootHash, keys: keysA, ports: kitPorts }),
    createRecoveryKit({ accountId, genesisRootHash, keys: keysB, ports: kitPorts }),
  ]);

  return { accountId, genesisRootHash, currentDescriptor, pendingDescriptor, keysA, keysB, kitA, kitB };
}

/** A kit with one field replaced, re-serialized — so a test exercises the rule it names. */
export function withKit(kit: RecoveryKit, patch: Partial<RecoveryKit>): Uint8Array {
  return serializeRecoveryKit({ ...kit, ...patch });
}
