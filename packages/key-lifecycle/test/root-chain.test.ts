// §28: the root chain. One negative case per numbered rule of §28.2, plus the §28.3 pinning
// rules and the §44.3 lines that name this area.
import { beforeAll, describe, expect, it } from "vitest";
import { signContext, verifyContext, importVerifyingKey } from "@nodra/crypto";
import { ROOT_DESCRIPTOR, ROOT_TRANSITION } from "@nodra/encoding/records";
import type { RootDescriptor, RootTransition } from "@nodra/encoding/records";
import { rootDescriptorContext, rootTransitionContext } from "../src/contexts.js";
import {
  CHANGED_KEYS,
  REQUIRED_SIGNER_ROLES,
  genesisDescriptor,
  nextDescriptor,
  rootHash,
  signRootTransition,
  verifyRootChain,
} from "../src/root-chain.js";
import type { RootChainLink, SignerRole } from "../src/root-chain.js";
import { KeyLifecycleError } from "../src/errors.js";
import { makeChain, makeSigners, rootKeys, signRoles, unsignedFor } from "./chain-support.js";
import type { ChainFixture, Signer } from "./chain-support.js";
import { filled } from "./support.js";

const ACCOUNT = filled(16, 0x11);

let pool: Signer[];
let chain: ChainFixture;

beforeAll(async () => {
  pool = await makeSigners(6);
  chain = await makeChain(ACCOUNT, pool);
});

/** The chain with one link replaced. */
function withLink(links: readonly RootChainLink[], index: number, link: RootChainLink): RootChainLink[] {
  const copy = [...links];
  copy[index] = link;
  return copy;
}

async function rejects(links: readonly RootChainLink[], code: string, options = {}) {
  const outcome = await verifyRootChain(links, { accountId: ACCOUNT, ...options });
  expect(outcome.ok).toBe(false);
  if (!outcome.ok) expect(outcome.failure.code).toBe(code);
  return outcome;
}

describe("a valid chain", () => {
  it("replays GENESIS plus one transition of every allowed type", async () => {
    const outcome = await verifyRootChain(chain.links, { accountId: ACCOUNT });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.value.rootGeneration).toBe(3);
    expect(outcome.value.descriptor).toEqual(chain.links[2]?.descriptor);
    expect(outcome.value.genesisRootHash).toEqual(await rootHash(chain.links[0]!.descriptor));
    expect([...outcome.value.hashes.keys()]).toEqual([1, 2, 3]);
  });

  it("accepts GENESIS alone, with old_root_hash and previous_root_hash null (§44.3)", async () => {
    const outcome = await verifyRootChain(chain.links.slice(0, 1), { accountId: ACCOUNT });
    expect(outcome.ok).toBe(true);
    expect(chain.links[0]?.transition.old_root_hash).toBeNull();
    expect(chain.links[0]?.descriptor.previous_root_hash).toBeNull();
  });

  it("continues from a previously verified state instead of replaying from genesis", async () => {
    const first = await verifyRootChain(chain.links.slice(0, 2), { accountId: ACCOUNT });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const rest = await verifyRootChain(chain.links.slice(2), { accountId: ACCOUNT, from: first.value });
    expect(rest.ok).toBe(true);
    if (!rest.ok) return;
    expect(rest.value.rootGeneration).toBe(3);
  });

  it("a role-2 or role-4 signature verifies against the NEW root (§44.3)", async () => {
    // Generation 2 is signed by the *new* Account Signing key, which the generation-1 root does
    // not name. Verification must therefore read it from the descriptor the transition carries.
    const link = chain.links[1]!;
    const newKey = await importVerifyingKey(link.descriptor.account_signing_public_key);
    const role2 = link.transition.signatures.find((s) => s.code === 2)!;
    expect(await verifyContext(newKey, rootTransitionContext(link.transition), role2.value)).toBe(true);
    const oldKey = await importVerifyingKey(chain.links[0]!.descriptor.account_signing_public_key);
    expect(await verifyContext(oldKey, rootTransitionContext(link.transition), role2.value)).toBe(false);
  });

  it("the required role sets are exactly the §28.2 table", () => {
    expect(REQUIRED_SIGNER_ROLES).toEqual({
      GENESIS: [2, 4],
      RECOVERY_RESET: [2, 3],
      RECOVERY_KIT_REPLACEMENT: [1, 4],
      SWITCH_TO_PRIVATE: [1, 2, 4],
      SWITCH_TO_MANAGED: [1, 4],
    });
  });

  it("the changed keys are exactly the §28.2 'Cambia' column and rule 6", () => {
    expect(CHANGED_KEYS).toEqual({
      GENESIS: ["accountEncryption", "accountSigning", "recoveryEncryption", "recoveryAuthority"],
      RECOVERY_RESET: ["accountEncryption", "accountSigning"],
      RECOVERY_KIT_REPLACEMENT: ["recoveryEncryption", "recoveryAuthority"],
      SWITCH_TO_PRIVATE: ["accountEncryption", "accountSigning", "recoveryEncryption", "recoveryAuthority"],
      SWITCH_TO_MANAGED: ["recoveryEncryption", "recoveryAuthority"],
    });
  });
});

describe("§28.2 rule 0 — exactly the required signature roles", () => {
  it("rejects a missing signature", async () => {
    const link = chain.links[0]!;
    const transition: RootTransition = { ...link.transition, signatures: link.transition.signatures.slice(0, 1) };
    await rejects([{ ...link, transition }], "BAD_SIGNATURE_SET");
  });

  it("rejects an extra role (§44.3 'roles extra o duplicados')", async () => {
    const [as1, ra1, as2] = pool as [Signer, Signer, Signer];
    const g1 = chain.links[0]!.descriptor;
    const transition = await signRoles(await unsignedFor("GENESIS", g1, null), [
      [2, as1.privateKey],
      [3, as2.privateKey],
      [4, ra1.privateKey],
    ]);
    await rejects([{ transition, descriptor: g1 }], "BAD_SIGNATURE_SET");
  });

  it("rejects a duplicated role", async () => {
    const [as1, ra1] = pool as [Signer, Signer];
    const g1 = chain.links[0]!.descriptor;
    const transition = await signRoles(await unsignedFor("GENESIS", g1, null), [
      [2, as1.privateKey],
      [2, ra1.privateKey],
    ]);
    await rejects([{ transition, descriptor: g1 }], "BAD_SIGNATURE_SET");
  });

  it("rejects the required roles in descending order", async () => {
    const [as1, ra1] = pool as [Signer, Signer];
    const g1 = chain.links[0]!.descriptor;
    const transition = await signRoles(await unsignedFor("GENESIS", g1, null), [
      [4, ra1.privateKey],
      [2, as1.privateKey],
    ]);
    await rejects([{ transition, descriptor: g1 }], "BAD_SIGNATURE_SET");
  });

  it("rejects the right number of signatures under the wrong roles", async () => {
    // RECOVERY_KIT_REPLACEMENT needs 1 + 4; this offers 2 + 3, both correctly signed.
    const link = chain.links[2]!;
    const [, ra1, as2] = pool as [Signer, Signer, Signer];
    const transition = await signRoles(await unsignedFor("RECOVERY_KIT_REPLACEMENT", link.descriptor, chain.links[1]!.descriptor), [
      [2, as2.privateKey],
      [3, ra1.privateKey],
    ]);
    await rejects(withLink(chain.links, 2, { ...link, transition }), "BAD_SIGNATURE_SET");
  });

  it("builders refuse to sign without the roles the type requires", async () => {
    await expect(
      signRootTransition({ type: "GENESIS", descriptor: chain.links[0]!.descriptor, signers: {} }),
    ).rejects.toBeInstanceOf(KeyLifecycleError);
  });
});

describe("§28.2 rule 1 — the signatures verify under the roles' keys", () => {
  it("rejects a signature made with the wrong key", async () => {
    const [as1, , , , other] = pool as Signer[];
    const g1 = chain.links[0]!.descriptor;
    const transition = await signRoles(await unsignedFor("GENESIS", g1, null), [
      [2, as1!.privateKey],
      [4, other!.privateKey],
    ]);
    await rejects([{ transition, descriptor: g1 }], "BAD_SIGNATURE");
  });

  it("rejects a signature over the wrong context domain", async () => {
    const [as1, ra1] = pool as [Signer, Signer];
    const g1 = chain.links[0]!.descriptor;
    const unsigned = await unsignedFor("GENESIS", g1, null);
    // Signed over `nodra/root-descriptor` rather than `nodra/root-transition` — the same account,
    // the same keys, a domain that exists. Domain separation is what must reject it.
    const wrongDomain = await signContext(ra1.privateKey, rootDescriptorContext(g1));
    const transition: RootTransition = {
      ...unsigned,
      signatures: [
        { code: 2, value: await signContext(as1.privateKey, rootTransitionContext(unsigned)) },
        { code: 4, value: wrongDomain },
      ],
    };
    await rejects([{ transition, descriptor: g1 }], "BAD_SIGNATURE");
  });

  it("rejects a signature over the wrong structure of the right domain", async () => {
    // A valid generation-3 signature, replayed onto the generation-2 transition.
    const link = chain.links[1]!;
    const borrowed = chain.links[2]!.transition.signatures.find((s) => s.code === 1)!;
    const transition: RootTransition = {
      ...link.transition,
      signatures: [{ code: 2, value: borrowed.value }, link.transition.signatures[1]!],
    };
    await rejects(withLink(chain.links, 1, { ...link, transition }), "BAD_SIGNATURE");
  });

  it("rejects a descriptor whose verifying key is not importable SPKI", async () => {
    const [as1, ra1] = pool as [Signer, Signer];
    const descriptor = genesisDescriptor(ACCOUNT, { ...rootKeys(as1, ra1, 0x11), recoveryAuthority: filled(40, 0x7f) });
    const transition = await signRoles(await unsignedFor("GENESIS", descriptor, null), [
      [2, as1.privateKey],
      [4, ra1.privateKey],
    ]);
    await rejects([{ transition, descriptor }], "MALFORMED_PUBLIC_KEY");
  });
});

describe("§28.2 rule 2 — new_root_hash is the hash of the included descriptor", () => {
  it("rejects a transition whose descriptor was swapped", async () => {
    // Caught at rule 1, not rule 2: roles 2 and 4 verify against the *included* descriptor, so
    // swapping it also swaps the keys the signatures are checked with. Either way it never
    // reaches a caller — the next case isolates rule 2 with the signatures left intact.
    const link = chain.links[0]!;
    await rejects([{ transition: link.transition, descriptor: chain.links[1]!.descriptor }], "BAD_SIGNATURE");
  });

  it("rejects a re-signed transition that announces another hash", async () => {
    const [as1, ra1] = pool as [Signer, Signer];
    const g1 = chain.links[0]!.descriptor;
    const unsigned = { ...(await unsignedFor("GENESIS", g1, null)), new_root_hash: filled(32, 0x5a) };
    const transition = await signRoles(unsigned, [
      [2, as1.privateKey],
      [4, ra1.privateKey],
    ]);
    await rejects([{ transition, descriptor: g1 }], "ROOT_HASH_MISMATCH");
  });
});

describe("§28.2 rule 3 — the link back to the root in force", () => {
  it("rejects a transition whose old_root_hash is not the root in force", async () => {
    const [, ra1, as2] = pool as [Signer, Signer, Signer];
    const link = chain.links[1]!;
    const unsigned = { ...(await unsignedFor("RECOVERY_RESET", link.descriptor, chain.links[0]!.descriptor)), old_root_hash: filled(32, 0x5a) };
    const transition = await signRoles(unsigned, [
      [2, as2.privateKey],
      [3, ra1.privateKey],
    ]);
    await rejects(withLink(chain.links, 1, { ...link, transition }), "BROKEN_LINK");
  });

  it("rejects a descriptor whose previous_root_hash disagrees with old_root_hash", async () => {
    const [, ra1, as2] = pool as [Signer, Signer, Signer];
    const descriptor: RootDescriptor = { ...chain.links[1]!.descriptor, previous_root_hash: filled(32, 0x5a) };
    const unsigned = {
      ...(await unsignedFor("RECOVERY_RESET", descriptor, chain.links[0]!.descriptor)),
      old_root_hash: await rootHash(chain.links[0]!.descriptor),
    };
    const transition = await signRoles(unsigned, [
      [2, as2.privateKey],
      [3, ra1.privateKey],
    ]);
    await rejects(withLink(chain.links, 1, { transition, descriptor }), "BROKEN_LINK");
  });

  it("rejects a chain that does not start at GENESIS", async () => {
    await rejects(chain.links.slice(1), "NOT_GENESIS");
  });

  it("rejects a second GENESIS", async () => {
    await rejects([chain.links[0]!, chain.links[0]!], "UNEXPECTED_GENESIS");
  });
});

describe("§28.2 rule 4 — generation continuity", () => {
  async function resignAtGeneration(generation: number): Promise<RootChainLink> {
    const [, ra1, as2] = pool as [Signer, Signer, Signer];
    const descriptor: RootDescriptor = { ...chain.links[1]!.descriptor, root_generation: generation };
    const unsigned = await unsignedFor("RECOVERY_RESET", descriptor, chain.links[0]!.descriptor);
    const transition = await signRoles(unsigned, [
      [2, as2.privateKey],
      [3, ra1.privateKey],
    ]);
    return { transition, descriptor };
  }

  it("rejects a gap", async () => {
    await rejects([chain.links[0]!, await resignAtGeneration(3)], "GENERATION_NOT_CONSECUTIVE");
  });

  it("rejects a reused generation", async () => {
    await rejects([chain.links[0]!, await resignAtGeneration(1)], "GENERATION_NOT_CONSECUTIVE");
  });

  it("rejects a transition and descriptor that disagree about the generation", async () => {
    const [, ra1, as2] = pool as [Signer, Signer, Signer];
    const link = chain.links[1]!;
    const unsigned = { ...(await unsignedFor("RECOVERY_RESET", link.descriptor, chain.links[0]!.descriptor)), new_root_generation: 5 };
    const transition = await signRoles(unsigned, [
      [2, as2.privateKey],
      [3, ra1.privateKey],
    ]);
    await rejects([chain.links[0]!, { ...link, transition }], "GENERATION_NOT_CONSECUTIVE");
  });

  it("rejects a second, different transition at the same generation (a fork)", async () => {
    const [, ra1, , , forkKey] = pool as Signer[];
    const forked = await nextDescriptor(chain.links[0]!.descriptor, {
      accountEncryption: filled(32, 0x99),
      accountSigning: forkKey!.spki,
    });
    const transition = await signRoles(await unsignedFor("RECOVERY_RESET", forked, chain.links[0]!.descriptor), [
      [2, forkKey!.privateKey],
      [3, ra1!.privateKey],
    ]);
    // Each branch verifies on its own…
    expect((await verifyRootChain([chain.links[0]!, { transition, descriptor: forked }], { accountId: ACCOUNT })).ok).toBe(true);
    // …but they cannot both be in one chain: the fork still points back at generation 1, which
    // rule 3 catches before rule 4 ever compares generations.
    await rejects([chain.links[0]!, chain.links[1]!, { transition, descriptor: forked }], "BROKEN_LINK");
    await rejects([chain.links[0]!, { transition, descriptor: forked }], "PIN_NOT_ANCESTOR", {
      pin: { rootGeneration: 2, rootHash: await rootHash(chain.links[1]!.descriptor) },
    });
  });
});

describe("§28.2 rule 5 — account_id and crypto_version never change", () => {
  it("rejects a chain that names another account", async () => {
    await rejects(chain.links, "ACCOUNT_MISMATCH", { accountId: filled(16, 0x22) });
  });

  it("rejects a transition whose account_id differs from its descriptor's", async () => {
    const link = chain.links[0]!;
    const [as1, ra1] = pool as [Signer, Signer];
    const unsigned = { ...(await unsignedFor("GENESIS", link.descriptor, null)), account_id: filled(16, 0x22) };
    const transition = await signRoles(unsigned, [
      [2, as1.privateKey],
      [4, ra1.privateKey],
    ]);
    await rejects([{ transition, descriptor: link.descriptor }], "ACCOUNT_MISMATCH");
  });

  it("rejects a crypto_version this client does not implement (§23.1: only 1 and 2)", async () => {
    const [as1, ra1] = pool as [Signer, Signer];
    for (const version of [0, 3]) {
      const descriptor = genesisDescriptor(ACCOUNT, rootKeys(as1, ra1, 0x11), version);
      const transition = await signRoles(await unsignedFor("GENESIS", descriptor, null), [
        [2, as1.privateKey],
        [4, ra1.privateKey],
      ]);
      await rejects([{ transition, descriptor }], "UNSUPPORTED_CRYPTO_VERSION");
    }
  });

  it("accepts a version-2 GENESIS (ADR-021: every new account)", async () => {
    const [as1, ra1] = pool as [Signer, Signer];
    const descriptor = genesisDescriptor(ACCOUNT, rootKeys(as1, ra1, 0x11), 2);
    const transition = await signRoles(await unsignedFor("GENESIS", descriptor, null), [
      [2, as1.privateKey],
      [4, ra1.privateKey],
    ]);
    const result = await verifyRootChain([{ transition, descriptor }], { accountId: ACCOUNT });
    expect(result.ok).toBe(true);
  });
});

describe("§28.2 rule 6 — only the 'Cambia' keys change", () => {
  it("rejects a RECOVERY_RESET that also replaces a recovery key (§44.3)", async () => {
    const [, ra1, as2, ra3] = pool as [Signer, Signer, Signer, Signer];
    const descriptor = await nextDescriptor(chain.links[0]!.descriptor, {
      accountEncryption: filled(32, 0x22),
      accountSigning: as2.spki,
      recoveryAuthority: ra3.spki,
    });
    const transition = await signRoles(await unsignedFor("RECOVERY_RESET", descriptor, chain.links[0]!.descriptor), [
      [2, as2.privateKey],
      [3, ra1.privateKey],
    ]);
    await rejects([chain.links[0]!, { transition, descriptor }], "FORBIDDEN_KEY_CHANGE");
  });

  it("rejects a RECOVERY_RESET that leaves an account key unchanged", async () => {
    const [, ra1, as2] = pool as [Signer, Signer, Signer];
    const descriptor = await nextDescriptor(chain.links[0]!.descriptor, { accountSigning: as2.spki });
    const transition = await signRoles(await unsignedFor("RECOVERY_RESET", descriptor, chain.links[0]!.descriptor), [
      [2, as2.privateKey],
      [3, ra1.privateKey],
    ]);
    await rejects([chain.links[0]!, { transition, descriptor }], "FORBIDDEN_KEY_CHANGE");
  });

  it("rejects a RECOVERY_KIT_REPLACEMENT that touches an account key", async () => {
    const [, , as2, ra3, other] = pool as Signer[];
    const descriptor = await nextDescriptor(chain.links[1]!.descriptor, {
      recoveryEncryption: filled(32, 0x33),
      recoveryAuthority: ra3!.spki,
      accountEncryption: filled(32, 0x44),
    });
    const transition = await signRoles(await unsignedFor("RECOVERY_KIT_REPLACEMENT", descriptor, chain.links[1]!.descriptor), [
      [1, as2!.privateKey],
      [4, ra3!.privateKey],
    ]);
    expect(other).toBeDefined();
    await rejects([chain.links[0]!, chain.links[1]!, { transition, descriptor }], "FORBIDDEN_KEY_CHANGE");
  });
});

describe("§28.3 — pinning", () => {
  it("accepts a chain that contains the pin and extends it", async () => {
    const outcome = await verifyRootChain(chain.links, {
      accountId: ACCOUNT,
      pin: { rootGeneration: 2, rootHash: await rootHash(chain.links[1]!.descriptor) },
    });
    expect(outcome.ok).toBe(true);
  });

  it("rejects a replay of an older chain (§44.3 rollback below the pin)", async () => {
    await rejects(chain.links.slice(0, 1), "PIN_ROLLBACK", {
      pin: { rootGeneration: 2, rootHash: await rootHash(chain.links[1]!.descriptor) },
    });
  });

  it("rejects a pinned root the chain never contained", async () => {
    await rejects(chain.links, "PIN_NOT_ANCESTOR", { pin: { rootGeneration: 2, rootHash: filled(32, 0x5a) } });
  });

  it("rejects an empty chain", async () => {
    await rejects([], "EMPTY_CHAIN");
  });
});

describe("broken-variant proofs", () => {
  /**
   * A verifier identical to ours except that it never checks *which* roles signed — it only
   * requires that every signature present verifies. Exactly the shortcut §28.2 rule 0 forbids.
   */
  async function verifySkippingRoleSet(links: readonly RootChainLink[]): Promise<boolean> {
    let current: RootDescriptor | null = null;
    for (const { transition, descriptor } of links) {
      const ctx = rootTransitionContext(transition);
      for (const pair of transition.signatures) {
        const spki =
          pair.code === 1
            ? current?.account_signing_public_key
            : pair.code === 2
              ? descriptor.account_signing_public_key
              : pair.code === 3
                ? current?.recovery_authority_public_key
                : descriptor.recovery_authority_public_key;
        if (spki === undefined) return false;
        if (!(await verifyContext(await importVerifyingKey(spki), ctx, pair.value))) return false;
      }
      current = descriptor;
    }
    return true;
  }

  it("a verifier that skips the role-set check accepts a GENESIS signed only by role 2", async () => {
    const [as1] = pool as [Signer];
    const g1 = chain.links[0]!.descriptor;
    const transition = await signRoles(await unsignedFor("GENESIS", g1, null), [[2, as1.privateKey]]);
    const links = [{ transition, descriptor: g1 }];

    expect(await verifySkippingRoleSet(links)).toBe(true);
    await rejects(links, "BAD_SIGNATURE_SET");
  });

  it("…and it also accepts a RECOVERY_KIT_REPLACEMENT signed with the RECOVERY_RESET role set", async () => {
    const [, ra1, as2] = pool as [Signer, Signer, Signer];
    const link = chain.links[2]!;
    const transition = await signRoles(await unsignedFor("RECOVERY_KIT_REPLACEMENT", link.descriptor, chain.links[1]!.descriptor), [
      [2, as2.privateKey],
      [3, ra1.privateKey],
    ]);
    const links = withLink(chain.links, 2, { ...link, transition });
    expect(await verifySkippingRoleSet(links)).toBe(true);
    await rejects(links, "BAD_SIGNATURE_SET");
  });
});

describe("schemas stay in step with the verifier", () => {
  it("a transition and its descriptor survive a codec round trip", async () => {
    const { decodeRecord, encodeRecord } = await import("@nodra/encoding/records");
    for (const link of chain.links) {
      expect(decodeRecord(ROOT_TRANSITION, encodeRecord(ROOT_TRANSITION, link.transition))).toEqual(link.transition);
      expect(decodeRecord(ROOT_DESCRIPTOR, encodeRecord(ROOT_DESCRIPTOR, link.descriptor))).toEqual(link.descriptor);
    }
  });

  it("every declared signer role is one the verifier can place", () => {
    const placed = new Set<SignerRole>();
    for (const roles of Object.values(REQUIRED_SIGNER_ROLES)) for (const role of roles) placed.add(role);
    expect([...placed].sort()).toEqual([1, 2, 3, 4]);
  });
});
