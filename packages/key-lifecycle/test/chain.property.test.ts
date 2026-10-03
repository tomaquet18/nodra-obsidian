// Property runs over §28 and §29.
//
// Two shapes. First: a random but *valid* chain or registry history always verifies — the
// generators build only legal sequences, so a failure here means the verifier refuses something
// the spec allows. Second, and the one that carries the weight of §44.3 "firma … manipulada":
// flipping any single byte of any signed structure or of any signature must make verification
// fail. Never silently accept.
import { beforeAll, describe, expect, it } from "vitest";
import fc from "fast-check";
import { REGISTRY, ROOT_DESCRIPTOR, ROOT_TRANSITION } from "@nodra/encoding/records";
import type { Registry, RootDescriptor, RootTransition } from "@nodra/encoding/records";
import { nextDescriptor, verifyRootChain } from "../src/root-chain.js";
import type { RootChainLink, TransitionType } from "../src/root-chain.js";
import { nextRegistry, signRegistry, verifyRegistryChain } from "../src/registry.js";
import type { NewRecipient } from "../src/registry.js";
import {
  encodedLength,
  makeRegistry,
  makeSigners,
  mutateRecord,
  recipient,
  rootKeys,
  signRoles,
  unsignedFor,
} from "./chain-support.js";
import type { Signer } from "./chain-support.js";
import { genesisDescriptor } from "../src/root-chain.js";
import { filled } from "./support.js";

const ACCOUNT = filled(16, 0x11);
const RUNS = { numRuns: 40 } as const;

let pool: Signer[];

beforeAll(async () => {
  // Reused across every run: §28 never cares which key a role holds, only that the right one
  // signed, so a fresh keygen per case would buy no assertion and cost the whole suite.
  pool = await makeSigners(8);
});

interface BuiltChain {
  readonly links: RootChainLink[];
  /** SPKI of the Account Signing Key in force at each generation. */
  readonly signingKeys: Map<number, Uint8Array>;
}

/** Builds a legal chain: GENESIS plus one link per requested type, with fresh keys each time. */
async function buildChain(types: readonly Exclude<TransitionType, "GENESIS">[]): Promise<BuiltChain> {
  let accountSigning = 0;
  let recoveryAuthority = 1;
  let next = 2;
  let tag = 0x10;

  let descriptor = genesisDescriptor(ACCOUNT, rootKeys(pool[accountSigning]!, pool[recoveryAuthority]!, tag));
  const links: RootChainLink[] = [
    {
      transition: await signRoles(await unsignedFor("GENESIS", descriptor, null), [
        [2, pool[accountSigning]!.privateKey],
        [4, pool[recoveryAuthority]!.privateKey],
      ]),
      descriptor,
    },
  ];
  const signingKeys = new Map<number, Uint8Array>([[1, pool[accountSigning]!.spki]]);

  for (const type of types) {
    const previous = descriptor;
    tag += 1;
    const fresh = next++ % pool.length;
    if (type === "RECOVERY_RESET") {
      accountSigning = fresh;
      descriptor = await nextDescriptor(previous, { accountEncryption: filled(32, tag), accountSigning: pool[fresh]!.spki });
    } else {
      recoveryAuthority = fresh;
      descriptor = await nextDescriptor(previous, { recoveryEncryption: filled(32, tag), recoveryAuthority: pool[fresh]!.spki });
    }
    const unsigned = await unsignedFor(type, descriptor, previous);
    links.push({
      transition:
        type === "RECOVERY_RESET"
          ? await signRoles(unsigned, [
              [2, pool[accountSigning]!.privateKey],
              [3, pool[recoveryAuthority]!.privateKey],
            ])
          : await signRoles(unsigned, [
              [1, pool[accountSigning]!.privateKey],
              [4, pool[recoveryAuthority]!.privateKey],
            ]),
      descriptor,
    });
    signingKeys.set(descriptor.root_generation, pool[accountSigning]!.spki);
  }
  return { links, signingKeys };
}

const transitionTypes = fc.constantFrom<Exclude<TransitionType, "GENESIS">>("RECOVERY_RESET", "RECOVERY_KIT_REPLACEMENT");

describe("§28 — property", () => {
  it("every legal chain verifies, and its state is the last link", async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(transitionTypes, { maxLength: 4 }), async (types) => {
        const { links } = await buildChain(types);
        const outcome = await verifyRootChain(links, { accountId: ACCOUNT });
        expect(outcome.ok).toBe(true);
        if (!outcome.ok) return;
        expect(outcome.value.rootGeneration).toBe(types.length + 1);
        expect(outcome.value.descriptor).toEqual(links[links.length - 1]!.descriptor);
      }),
      RUNS,
    );
  });

  it("verification is deterministic and pins are honoured at every generation", async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(transitionTypes, { maxLength: 3 }), async (types) => {
        const { links } = await buildChain(types);
        const first = await verifyRootChain(links, { accountId: ACCOUNT });
        const again = await verifyRootChain(links, { accountId: ACCOUNT });
        expect(again).toEqual(first);
        if (!first.ok) return;
        for (const [generation, hash] of first.value.hashes) {
          expect((await verifyRootChain(links, { accountId: ACCOUNT, pin: { rootGeneration: generation, rootHash: hash } })).ok).toBe(true);
          // Truncating below the pin is a replay of an older chain.
          const truncated = links.slice(0, generation - 1);
          if (truncated.length > 0) {
            const rolled = await verifyRootChain(truncated, { accountId: ACCOUNT, pin: { rootGeneration: generation, rootHash: hash } });
            expect(rolled.ok).toBe(false);
          }
        }
      }),
      { numRuns: 20 },
    );
  });

  it("any single-byte change to a transition or a descriptor is rejected", async () => {
    const { links } = await buildChain(["RECOVERY_RESET", "RECOVERY_KIT_REPLACEMENT"]);
    await fc.assert(
      fc.asyncProperty(fc.nat(links.length - 1), fc.nat(4096), fc.boolean(), async (index, byte, inTransition) => {
        const link = links[index]!;
        const mutated: RootChainLink | null = inTransition
          ? mutateOne<RootTransition>(ROOT_TRANSITION, link.transition, byte, (t) => ({ ...link, transition: t }))
          : mutateOne<RootDescriptor>(ROOT_DESCRIPTOR, link.descriptor, byte, (d) => ({ ...link, descriptor: d }));
        if (mutated === null) return; // the codec already refused the bytes
        const copy = [...links];
        copy[index] = mutated;
        const outcome = await verifyRootChain(copy, { accountId: ACCOUNT });
        expect(outcome.ok).toBe(false);
      }),
      { numRuns: 200 },
    );
  });

  it("the mutation generator actually reaches every byte of both structures", async () => {
    const { links } = await buildChain(["RECOVERY_RESET"]);
    expect(encodedLength(ROOT_TRANSITION, links[1]!.transition)).toBeLessThan(4096);
    expect(encodedLength(ROOT_DESCRIPTOR, links[1]!.descriptor)).toBeLessThan(4096);
  });
});

function mutateOne<T>(
  schema: typeof ROOT_TRANSITION | typeof ROOT_DESCRIPTOR | typeof REGISTRY,
  value: T,
  byte: number,
  wrap: (mutated: T) => RootChainLink,
): RootChainLink | null {
  const mutated = mutateRecord<T>(schema as never, value, byte);
  if (mutated === null) return null;
  return wrap(mutated);
}

// --- §29 ---------------------------------------------------------------------------------------

type RegistryOp = { readonly kind: "add" } | { readonly kind: "revoke"; readonly which: number };

const registryOps = fc.array(
  fc.oneof(fc.constant<RegistryOp>({ kind: "add" }), fc.nat(7).map((which): RegistryOp => ({ kind: "revoke", which }))),
  { maxLength: 6 },
);

/** Builds a legal registry history under a single root generation. */
async function buildHistory(ops: readonly RegistryOp[], signer: Signer): Promise<Registry[]> {
  let tag = 0x20;
  const history: Registry[] = [await makeRegistry(ACCOUNT, 1, [recipient(tag)], signer)];
  for (const op of ops) {
    const current = history[history.length - 1]!;
    if (op.kind === "add") {
      tag += 1;
      const added: NewRecipient = recipient(tag);
      history.push(await signRegistry(await nextRegistry(current, { add: [added] }), signer.privateKey));
    } else {
      const active = current.recipients.filter((r) => r.status === "ACTIVE");
      if (active.length === 0) continue;
      const target = active[op.which % active.length]!;
      history.push(await signRegistry(await nextRegistry(current, { revoke: [target.recipient_id] }), signer.privateKey));
    }
  }
  return history;
}

describe("§29 — property", () => {
  it("every legal history verifies, and no recipient is ever lost or revived", async () => {
    await fc.assert(
      fc.asyncProperty(registryOps, async (ops) => {
        const signer = pool[0]!;
        const history = await buildHistory(ops, signer);
        const outcome = await verifyRegistryChain(history, {
          accountId: ACCOUNT,
          accountSigningKeys: new Map([[1, signer.spki]]),
          currentRootGeneration: 1,
        });
        expect(outcome.ok).toBe(true);
        if (!outcome.ok) return;
        const last = outcome.value.registry;
        for (const version of history) {
          for (const before of version.recipients) {
            const after = last.recipients.find((r) => r.recipient_id.join() === before.recipient_id.join());
            expect(after).toBeDefined();
            if (before.status === "REVOKED") expect(after?.status).toBe("REVOKED");
          }
        }
        // §29 bullet 5 holds by construction of every version the builder produced.
        for (const version of history) {
          const ids = version.recipients.map((r) => r.recipient_id.join(","));
          expect([...ids].sort()).toEqual(ids);
        }
      }),
      RUNS,
    );
  });

  it("any single-byte change to any version of the history is rejected", async () => {
    const signer = pool[0]!;
    const history = await buildHistory([{ kind: "add" }, { kind: "revoke", which: 0 }, { kind: "add" }], signer);
    const accountSigningKeys = new Map([[1, signer.spki]]);
    await fc.assert(
      fc.asyncProperty(fc.nat(history.length - 1), fc.nat(4096), async (index, byte) => {
        const mutated = mutateRecord<Registry>(REGISTRY, history[index]!, byte);
        if (mutated === null) return;
        const copy = [...history];
        copy[index] = mutated;
        const outcome = await verifyRegistryChain(copy, { accountId: ACCOUNT, accountSigningKeys });
        expect(outcome.ok).toBe(false);
      }),
      { numRuns: 200 },
    );
  });

  it("the mutation generator reaches every byte of a registry", async () => {
    const history = await buildHistory([{ kind: "add" }], pool[0]!);
    expect(encodedLength(REGISTRY, history[1]!)).toBeLessThan(4096);
  });
});
