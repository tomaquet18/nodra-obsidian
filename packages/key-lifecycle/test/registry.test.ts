// §29: the Recipient Registry. One negative case per bullet of the "evolución permitida" list,
// plus the signing rule, the ordering rule (encoding question 179) and the pin rules.
import { beforeAll, describe, expect, it } from "vitest";
import { signContext } from "@nodra/crypto";
import type { Registry, RegistryRecipient } from "@nodra/encoding/records";
import { registryContext } from "../src/contexts.js";
import {
  activeRecipients,
  compareRecipientIds,
  initialRegistry,
  nextRegistry,
  registryHash,
  signRegistry,
  verifyRegistryChain,
} from "../src/registry.js";
import type { UnsignedRegistry } from "../src/registry.js";
import { evolve, makeChain, makeRegistry, makeSigners, recipient, signingKeysOf } from "./chain-support.js";
import type { ChainFixture, Signer } from "./chain-support.js";
import { filled } from "./support.js";

const ACCOUNT = filled(16, 0x11);

let pool: Signer[];
let chain: ChainFixture;
let keys: Map<number, Uint8Array>;
/** v1: one plugin. v2: adds a browser. v3: revokes the plugin. */
let history: Registry[];

beforeAll(async () => {
  pool = await makeSigners(6);
  chain = await makeChain(ACCOUNT, pool);
  keys = signingKeysOf(chain);
  const g1 = chain.signers[0]![0];
  const v1 = await makeRegistry(ACCOUNT, 1, [recipient(0x31)], g1);
  const v2 = await evolve(v1, { add: [recipient(0x42)] }, g1);
  const v3 = await evolve(v2, { revoke: [filled(16, 0x31)] }, g1);
  history = [v1, v2, v3];
});

async function rejects(versions: readonly Registry[], code: string, options: Record<string, unknown> = {}) {
  const outcome = await verifyRegistryChain(versions, { accountId: ACCOUNT, accountSigningKeys: keys, ...options });
  expect(outcome.ok).toBe(false);
  if (!outcome.ok) expect(outcome.failure.code).toBe(code);
  return outcome;
}

/** Re-signs an edited draft, so a case exercises its rule and not the signature. */
async function resigned(draft: UnsignedRegistry, signer = chain.signers[0]![0]): Promise<Registry> {
  return signRegistry(draft, signer.privateKey);
}

function unsign(registry: Registry): UnsignedRegistry {
  const { signature, ...rest } = registry;
  void signature;
  return rest;
}

describe("a registry that evolves", () => {
  it("verifies through an add and a revoke", async () => {
    const outcome = await verifyRegistryChain(history, {
      accountId: ACCOUNT,
      accountSigningKeys: keys,
      currentRootGeneration: 1,
    });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.value.registry.registry_version).toBe(3);
    expect(activeRecipients(outcome.value.registry).map((r) => r.label)).toEqual(["device 66"]);
    const revoked = outcome.value.registry.recipients.find((r) => r.status === "REVOKED");
    expect(revoked?.revoked_version).toBe(3);
    expect(revoked?.added_version).toBe(1);
  });

  it("keeps every recipient of every earlier version (append-only)", async () => {
    expect(history[2]!.recipients).toHaveLength(2);
    expect(history[2]!.recipients.map((r) => r.added_version)).toEqual([1, 2]);
  });

  it("continues from a previously verified state", async () => {
    const first = await verifyRegistryChain(history.slice(0, 2), { accountId: ACCOUNT, accountSigningKeys: keys });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const rest = await verifyRegistryChain(history.slice(2), {
      accountId: ACCOUNT,
      accountSigningKeys: keys,
      from: first.value,
    });
    expect(rest.ok).toBe(true);
  });

  it("accepts the new-generation registry a root transition must carry", async () => {
    // §29: "Toda transición de raíz incluye un Registry nuevo firmado por la clave de la nueva
    // generación", and it may revoke while doing so (the RECOVERY_RESET case).
    const v4 = await evolve(history[2]!, { rootGeneration: 2, revoke: [filled(16, 0x42)] }, chain.signers[1]![0]);
    const outcome = await verifyRegistryChain([...history, v4], {
      accountId: ACCOUNT,
      accountSigningKeys: keys,
      currentRootGeneration: 2,
    });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(activeRecipients(outcome.value.registry)).toHaveLength(0);
  });

  it("builds recipients in strictly increasing recipient_id order whatever the input order", async () => {
    const built = initialRegistry(ACCOUNT, 1, [recipient(0x99), recipient(0x02), recipient(0x55)]);
    expect(built.recipients.map((r) => r.recipient_id[0])).toEqual([0x02, 0x55, 0x99]);
  });
});

describe("§29 bullet 1 — version and previous_registry_hash", () => {
  it("rejects a version that is not N + 1", async () => {
    const skipped = await resigned({ ...unsign(history[2]!), registry_version: 4 });
    await rejects([history[0]!, history[1]!, skipped], "VERSION_NOT_CONSECUTIVE");
  });

  it("rejects a previous_registry_hash that is not the hash of version N", async () => {
    const broken = await resigned({ ...unsign(history[1]!), previous_registry_hash: filled(32, 0x5a) });
    await rejects([history[0]!, broken], "BROKEN_LINK");
  });

  it("rejects a first version that is not version 1 with a null previous hash", async () => {
    await rejects(history.slice(1), "NOT_INITIAL");
    const notNull = await resigned({ ...unsign(history[0]!), previous_registry_hash: filled(32, 0x5a) });
    await rejects([notNull], "NOT_INITIAL");
  });

  it("registry_hash is the hash of the registry without its signature", async () => {
    const hash = await registryHash(history[0]!);
    expect(hash).toEqual(await registryHash(unsign(history[0]!)));
    const reSigned = await resigned(unsign(history[0]!), chain.signers[0]![0]);
    expect(await registryHash(reSigned)).toEqual(hash);
  });
});

describe("§29 bullet 2 — append-only", () => {
  it("rejects a version that drops a recipient (§44.3 'omite un recipient')", async () => {
    const dropped = await resigned({ ...unsign(history[1]!), recipients: history[1]!.recipients.slice(1) });
    await rejects([history[0]!, dropped], "RECIPIENT_REMOVED");
  });

  it("rejects a swapped public key", async () => {
    const mutated = history[1]!.recipients.map((r) =>
      r.added_version === 1 ? { ...r, public_key: filled(48, 0x77) } : r,
    );
    await rejects([history[0]!, await resigned({ ...unsign(history[1]!), recipients: mutated })], "RECIPIENT_MUTATED");
  });

  it("rejects a relabelled or retyped recipient", async () => {
    for (const patch of [{ label: "renamed" }, { type: "TRUSTED_BROWSER" as const }, { added_version: 2 }]) {
      const mutated = history[1]!.recipients.map((r) => (r.added_version === 1 ? { ...r, ...patch } : r));
      await rejects([history[0]!, await resigned({ ...unsign(history[1]!), recipients: mutated })], "RECIPIENT_MUTATED");
    }
  });
});

describe("§29 bullet 3 — only ACTIVE → REVOKED", () => {
  it("rejects a revoked recipient that returns to ACTIVE (§44.3 'lo reactiva')", async () => {
    const revived = history[2]!.recipients.map((r) =>
      r.status === "REVOKED" ? { ...r, status: "ACTIVE" as const, revoked_version: null } : r,
    );
    const v4 = await resigned({
      ...unsign(history[2]!),
      registry_version: 4,
      previous_registry_hash: await registryHash(history[2]!),
      recipients: revived,
    });
    await rejects([...history, v4], "ILLEGAL_STATUS_TRANSITION");
  });

  it("rejects a revocation stamped with a version other than N + 1", async () => {
    const wrong = history[2]!.recipients.map((r) => (r.status === "REVOKED" ? { ...r, revoked_version: 2 } : r));
    await rejects([history[0]!, history[1]!, await resigned({ ...unsign(history[2]!), recipients: wrong })], "BAD_REVOKED_VERSION");
  });

  it("rejects an existing revocation whose revoked_version is rewritten", async () => {
    const v4draft = await nextRegistry(history[2]!);
    const rewritten = v4draft.recipients.map((r) => (r.status === "REVOKED" ? { ...r, revoked_version: 4 } : r));
    await rejects([...history, await resigned({ ...v4draft, recipients: rewritten })], "BAD_REVOKED_VERSION");
  });

  it("rejects a recipient whose status and revoked_version contradict each other", async () => {
    const contradictory: RegistryRecipient[] = history[0]!.recipients.map((r) => ({ ...r, revoked_version: 1 }));
    await rejects([await resigned({ ...unsign(history[0]!), recipients: contradictory })], "MALFORMED_RECIPIENT");
  });
});

describe("§29 bullet 4 — new recipients enter ACTIVE at N + 1", () => {
  it("rejects an addition stamped with the wrong added_version", async () => {
    const draft = await nextRegistry(history[2]!, { add: [recipient(0x60)] });
    const wrong = draft.recipients.map((r) => (r.added_version === 4 ? { ...r, added_version: 2 } : r));
    await rejects([...history, await resigned({ ...draft, recipients: wrong })], "BAD_ADDED_VERSION");
  });

  it("rejects an addition that enters REVOKED", async () => {
    const draft = await nextRegistry(history[2]!, { add: [recipient(0x60)] });
    const wrong = draft.recipients.map((r) =>
      r.added_version === 4 ? { ...r, status: "REVOKED" as const, revoked_version: 4 } : r,
    );
    await rejects([...history, await resigned({ ...draft, recipients: wrong })], "BAD_ADDED_VERSION");
  });

  it("rejects a version 1 that already contains a REVOKED recipient", async () => {
    const revoked = history[0]!.recipients.map((r) => ({ ...r, status: "REVOKED" as const, revoked_version: 1 }));
    await rejects([await resigned({ ...unsign(history[0]!), recipients: revoked })], "BAD_ADDED_VERSION");
  });
});

describe("§29 bullet 5 — recipients ordered by recipient_id (encoding question 179)", () => {
  it("rejects a reordered list (§44.3 'desordena la lista')", async () => {
    const reordered = [...history[1]!.recipients].reverse();
    await rejects([history[0]!, await resigned({ ...unsign(history[1]!), recipients: reordered })], "UNSORTED_RECIPIENTS");
  });

  it("rejects the same recipient_id twice", async () => {
    const duplicated = [history[0]!.recipients[0]!, history[0]!.recipients[0]!];
    await rejects([await resigned({ ...unsign(history[0]!), recipients: duplicated })], "UNSORTED_RECIPIENTS");
  });

  it("orders ids as unsigned bytes, not as signed ones", () => {
    expect(compareRecipientIds(filled(16, 0x7f), filled(16, 0x80))).toBeLessThan(0);
    expect(compareRecipientIds(filled(16, 0xff), filled(16, 0x00))).toBeGreaterThan(0);
  });
});

describe("§29 bullet 6 — a root transition may only change the generation and revoke", () => {
  it("rejects a generation change that also enrolls a recipient", async () => {
    const draft = await nextRegistry(history[2]!, { rootGeneration: 2, add: [recipient(0x60)] });
    await rejects([...history, await resigned(draft, chain.signers[1]![0])], "RECIPIENT_ADDED_ON_ROOT_TRANSITION");
  });

  it("rejects a root_generation that goes backwards", async () => {
    const v4 = await evolve(history[2]!, { rootGeneration: 2 }, chain.signers[1]![0]);
    const v5draft = await nextRegistry(v4, { rootGeneration: 1 });
    await rejects([...history, v4, await resigned(v5draft, chain.signers[0]![0])], "ROOT_GENERATION_REGRESSED");
  });
});

describe("§29 — the signing rule", () => {
  it("rejects a registry signed by the wrong key (§44.3 'firma manipulada')", async () => {
    const wrongSigner = chain.signers[1]![0];
    const forged = await signRegistry(unsign(history[1]!), wrongSigner.privateKey);
    await rejects([history[0]!, forged], "BAD_SIGNATURE");
  });

  it("rejects a signature over the wrong structure of the right domain", async () => {
    const borrowed = await signContext(chain.signers[0]![0].privateKey, registryContext(history[0]!));
    await rejects([history[0]!, { ...history[1]!, signature: borrowed }], "BAD_SIGNATURE");
  });

  it("rejects a registry whose root_generation names a key the client does not have", async () => {
    const orphan = await resigned({ ...unsign(history[0]!), root_generation: 9 });
    await rejects([orphan], "UNKNOWN_ROOT_GENERATION");
  });

  it("rejects a generation whose signing key is not importable SPKI", async () => {
    await rejects(history, "MALFORMED_PUBLIC_KEY", { accountSigningKeys: new Map([[1, filled(40, 0x7f)]]) });
  });

  it("rejects a registry that names another account", async () => {
    await rejects(history, "ACCOUNT_MISMATCH", { accountId: filled(16, 0x22) });
  });

  it("rejects a registry in force whose root_generation is not the root's (§44.3)", async () => {
    await rejects(history, "STALE_ROOT_GENERATION", { currentRootGeneration: 2 });
  });
});

describe("§29 — pinning", () => {
  it("accepts a history that contains the pin", async () => {
    const outcome = await verifyRegistryChain(history, {
      accountId: ACCOUNT,
      accountSigningKeys: keys,
      pin: { registryVersion: 2, registryHash: await registryHash(history[1]!) },
    });
    expect(outcome.ok).toBe(true);
  });

  it("rejects a version below the pin (§44.3 'rollback de Registry')", async () => {
    await rejects(history.slice(0, 1), "PIN_ROLLBACK", {
      pin: { registryVersion: 2, registryHash: await registryHash(history[1]!) },
    });
  });

  it("rejects a forked history that never contained the pin", async () => {
    await rejects(history, "PIN_NOT_ANCESTOR", { pin: { registryVersion: 2, registryHash: filled(32, 0x5a) } });
  });

  it("rejects an empty history", async () => {
    await rejects([], "EMPTY_CHAIN");
  });
});

describe("broken-variant proofs", () => {
  /**
   * A verifier identical to ours except that it compares recipients by id instead of insisting
   * on the order they arrive in — the natural shortcut, and exactly what §29 bullet 5 forbids.
   */
  function acceptsAnyOrder(previous: Registry, next: Registry): boolean {
    const before = new Map(previous.recipients.map((r) => [r.recipient_id.join(","), r]));
    for (const after of next.recipients) {
      const match = before.get(after.recipient_id.join(","));
      if (match === undefined) continue;
      if (match.status === "REVOKED" && after.status === "ACTIVE") return false;
      before.delete(after.recipient_id.join(","));
    }
    return before.size === 0;
  }

  it("a verifier that ignores order accepts a reordered list that ours rejects", async () => {
    const reordered = await resigned({ ...unsign(history[1]!), recipients: [...history[1]!.recipients].reverse() });
    expect(acceptsAnyOrder(history[0]!, reordered)).toBe(true);
    await rejects([history[0]!, reordered], "UNSORTED_RECIPIENTS");
  });

  it("…and it also accepts a duplicated recipient", async () => {
    const duplicated = await resigned({
      ...unsign(history[0]!),
      recipients: [history[0]!.recipients[0]!, history[0]!.recipients[0]!],
    });
    expect(acceptsAnyOrder(history[0]!, duplicated)).toBe(true);
    await rejects([duplicated], "UNSORTED_RECIPIENTS");
  });
});
