// ADR-021 in the root chain (§28.2, §3.6): the SWITCH_TO_PRIVATE and SWITCH_TO_MANAGED rows, rule 5's
// single exception (SWITCH_TO_MANAGED must end at crypto_version 2) and the client's mode derivation.
// §44.3: T10 (SWITCH_TO_MANAGED keeps the account keys, new Recovery keys, 1 → 2, the old kit no longer
// authorizes transitions), T12 (any other transition changing crypto_version → rejected) and T16
// (SWITCH_TO_PRIVATE keeping a key, or without roles 1 + 2 + 4 → rejected).
import fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";
import type { RootDescriptor, RootTransition } from "@nodra/encoding/records";
import { genesisDescriptor, modeAfter, nextDescriptor, verifyRootChain } from "../src/root-chain.js";
import type { ProtectionMode, RootChainFailureCode, RootChainLink, RootPublicKeys, SignerRole, TransitionType } from "../src/root-chain.js";
import { makeSigners, rootKeys, signRoles, unsignedFor } from "./chain-support.js";
import type { Signer } from "./chain-support.js";
import { filled } from "./support.js";

const ACCOUNT = filled(16, 0x11);
let pool: Signer[];

beforeAll(async () => {
  pool = await makeSigners(8);
});

/** Where a chain stands: its last descriptor and the private halves of its two signing keys. */
interface Head {
  readonly descriptor: RootDescriptor;
  readonly accountSigning: Signer;
  readonly recoveryAuthority: Signer;
}

function genesis(version: number, as = pool[0]!, ra = pool[1]!): { head: Head; link: Promise<RootChainLink> } {
  const descriptor = genesisDescriptor(ACCOUNT, rootKeys(as, ra, 0x11), version);
  return {
    head: { descriptor, accountSigning: as, recoveryAuthority: ra },
    link: (async () => ({
      transition: await signRoles(await unsignedFor("GENESIS", descriptor, null), [
        [2, as.privateKey],
        [4, ra.privateKey],
      ]),
      descriptor,
    }))(),
  };
}

/** Signs `type` from `head` to `descriptor` with exactly `roles`, each by the key its role names. */
async function link(
  type: TransitionType,
  head: Head,
  descriptor: RootDescriptor,
  roles: readonly SignerRole[],
  next: { as: Signer; ra: Signer },
): Promise<RootChainLink> {
  const keyFor = (role: SignerRole) =>
    role === 1 ? head.accountSigning : role === 2 ? next.as : role === 3 ? head.recoveryAuthority : next.ra;
  const transition: RootTransition = await signRoles(
    await unsignedFor(type, descriptor, head.descriptor),
    roles.map((role) => [role, keyFor(role).privateKey] as const),
  );
  return { transition, descriptor };
}

async function outcome(links: readonly RootChainLink[]) {
  return verifyRootChain(links, { accountId: ACCOUNT });
}

async function expectFailure(links: readonly RootChainLink[], code: RootChainFailureCode): Promise<void> {
  const result = await outcome(links);
  expect(result.ok ? "ok" : result.failure.code).toBe(code);
}

const ALL: (keyof RootPublicKeys)[] = ["accountEncryption", "accountSigning", "recoveryEncryption", "recoveryAuthority"];

/** Replacements for the named keys: new signers where the key signs, filler where it encrypts. */
function replacing(names: readonly (keyof RootPublicKeys)[], as: Signer, ra: Signer, tag: number): Partial<RootPublicKeys> {
  const all: RootPublicKeys = {
    accountEncryption: filled(32, tag),
    accountSigning: as.spki,
    recoveryEncryption: filled(32, tag ^ 0x80),
    recoveryAuthority: ra.spki,
  };
  return Object.fromEntries(names.map((name) => [name, all[name]]));
}

describe("SWITCH_TO_PRIVATE (§28.2, §35.13)", () => {
  async function toPrivate(roles: readonly SignerRole[] = [1, 2, 4], keep: readonly (keyof RootPublicKeys)[] = []) {
    const g = genesis(2);
    // A kept signing key keeps signing its role, so the rule that answers is rule 6, not rule 1.
    const as = keep.includes("accountSigning") ? g.head.accountSigning : pool[2]!;
    const ra = keep.includes("recoveryAuthority") ? g.head.recoveryAuthority : pool[3]!;
    const descriptor = await nextDescriptor(g.head.descriptor, replacing(ALL.filter((k) => !keep.includes(k)), as, ra, 0x21));
    return [await g.link, await link("SWITCH_TO_PRIVATE", g.head, descriptor, roles, { as, ra })];
  }

  it("changes all four keys, signed by roles 1 + 2 + 4, and makes the account Private", async () => {
    const result = await outcome(await toPrivate());
    if (!result.ok) throw new Error(result.failure.code);
    expect(result.value.mode).toBe("PRIVATE");
    expect(result.value.descriptor.crypto_version).toBe(2);
  });

  it("T16: a switch that keeps any one key is FORBIDDEN_KEY_CHANGE", async () => {
    for (const kept of ALL) await expectFailure(await toPrivate([1, 2, 4], [kept]), "FORBIDDEN_KEY_CHANGE");
  });

  it("T16: any role set other than exactly 1 + 2 + 4 is BAD_SIGNATURE_SET", async () => {
    for (const roles of [[1, 2], [1, 4], [2, 4], [1, 2, 3, 4], [1, 3, 4], [1, 2, 2, 4]] as SignerRole[][]) {
      await expectFailure(await toPrivate(roles), "BAD_SIGNATURE_SET");
    }
  });
});

describe("SWITCH_TO_MANAGED (§28.2, §35.14)", () => {
  async function toManaged(from: number, to: number, keys: readonly (keyof RootPublicKeys)[] = ["recoveryEncryption", "recoveryAuthority"]) {
    const g = genesis(from);
    const ra = keys.includes("recoveryAuthority") ? pool[4]! : g.head.recoveryAuthority;
    const as = pool[5]!;
    const descriptor = await nextDescriptor(g.head.descriptor, replacing(keys, as, ra, 0x31), to);
    const next = { as, ra };
    return { g, next, descriptor, links: [await g.link, await link("SWITCH_TO_MANAGED", g.head, descriptor, [1, 4], next)] };
  }

  it("T10: same account keys, new Recovery keys, crypto_version 1 → 2, and the account is Managed", async () => {
    const { links } = await toManaged(1, 2);
    const result = await outcome(links);
    if (!result.ok) throw new Error(result.failure.code);
    expect(result.value.mode).toBe("MANAGED");
    expect(result.value.descriptor.crypto_version).toBe(2);
  });

  it("from a version-2 Private account the version stays 2", async () => {
    const g = genesis(2);
    const [as, ra] = [pool[2]!, pool[3]!];
    const privateRoot = await nextDescriptor(g.head.descriptor, replacing(ALL, as, ra, 0x21));
    const toPrivate = await link("SWITCH_TO_PRIVATE", g.head, privateRoot, [1, 2, 4], { as, ra });
    const head: Head = { descriptor: privateRoot, accountSigning: as, recoveryAuthority: ra };
    const ra2 = pool[6]!;
    const managedRoot = await nextDescriptor(privateRoot, replacing(["recoveryEncryption", "recoveryAuthority"], as, ra2, 0x41));
    const toManaged = await link("SWITCH_TO_MANAGED", head, managedRoot, [1, 4], { as, ra: ra2 });
    const result = await outcome([await g.link, toPrivate, toManaged]);
    if (!result.ok) throw new Error(result.failure.code);
    expect(result.value.mode).toBe("MANAGED");
  });

  it("T10: a switch that changes an account key, or keeps a recovery key, is FORBIDDEN_KEY_CHANGE", async () => {
    for (const keys of [ALL, ["recoveryEncryption"], ["recoveryAuthority"], ["recoveryEncryption", "recoveryAuthority", "accountEncryption"]] as (keyof RootPublicKeys)[][]) {
      const { links } = await toManaged(1, 2, keys);
      await expectFailure(links, "FORBIDDEN_KEY_CHANGE");
    }
  });

  it("T10: after the switch the old Recovery Authority no longer authorizes a transition", async () => {
    const { g, next, descriptor, links } = await toManaged(1, 2);
    const head: Head = { descriptor, accountSigning: g.head.accountSigning, recoveryAuthority: next.ra };
    const as2 = pool[6]!;
    const reset = await nextDescriptor(descriptor, replacing(["accountEncryption", "accountSigning"], as2, next.ra, 0x51));
    // Role 3 signed by the kit's key of generation 1, not by the Recovery Authority in force.
    const staleKit = await link("RECOVERY_RESET", { ...head, recoveryAuthority: g.head.recoveryAuthority }, reset, [2, 3], { as: as2, ra: next.ra });
    await expectFailure([...links, staleKit], "BAD_SIGNATURE");
    const current = await link("RECOVERY_RESET", head, reset, [2, 3], { as: as2, ra: next.ra });
    expect((await outcome([...links, current])).ok).toBe(true);
  });

  it("rule 5 (§35.14 step 7): a switch from version 1 that keeps version 1 is CRYPTO_VERSION_CHANGED", async () => {
    const { links } = await toManaged(1, 1);
    await expectFailure(links, "CRYPTO_VERSION_CHANGED");
  });

  it("wrong roles are BAD_SIGNATURE_SET", async () => {
    const { g, next, descriptor } = await toManaged(1, 2);
    for (const roles of [[1], [4], [1, 2, 4], [1, 3, 4], [3, 4]] as SignerRole[][]) {
      await expectFailure([await g.link, await link("SWITCH_TO_MANAGED", g.head, descriptor, roles, next)], "BAD_SIGNATURE_SET");
    }
  });
});

describe("T12: rule 5 — only SWITCH_TO_MANAGED changes crypto_version, and only 1 → 2", () => {
  const ROWS: [TransitionType, (keyof RootPublicKeys)[], SignerRole[]][] = [
    ["RECOVERY_RESET", ["accountEncryption", "accountSigning"], [2, 3]],
    ["RECOVERY_KIT_REPLACEMENT", ["recoveryEncryption", "recoveryAuthority"], [1, 4]],
    ["SWITCH_TO_PRIVATE", ALL, [1, 2, 4]],
    ["SWITCH_TO_MANAGED", ["recoveryEncryption", "recoveryAuthority"], [1, 4]],
  ];

  it("every other transition that moves the version, in either direction, is CRYPTO_VERSION_CHANGED", async () => {
    for (const [type, keys, roles] of ROWS) {
      for (const [from, to] of [[1, 2], [2, 1]]) {
        if (type === "SWITCH_TO_MANAGED" && from === 1) continue; // the one allowed move
        const g = genesis(from!);
        const [as, ra] = [pool[2]!, pool[3]!];
        const descriptor = await nextDescriptor(g.head.descriptor, replacing(keys, as, ra, 0x61), to);
        await expectFailure([await g.link, await link(type, g.head, descriptor, roles, { as, ra })], "CRYPTO_VERSION_CHANGED");
      }
    }
  });
});

describe("§3.6 mode derivation from the verified chain", () => {
  type Step = "RECOVERY_RESET" | "RECOVERY_KIT_REPLACEMENT" | "SWITCH_TO_PRIVATE" | "SWITCH_TO_MANAGED";
  const STEP_KEYS: Record<Step, (keyof RootPublicKeys)[]> = {
    RECOVERY_RESET: ["accountEncryption", "accountSigning"],
    RECOVERY_KIT_REPLACEMENT: ["recoveryEncryption", "recoveryAuthority"],
    SWITCH_TO_PRIVATE: ALL,
    SWITCH_TO_MANAGED: ["recoveryEncryption", "recoveryAuthority"],
  };
  const STEP_ROLES: Record<Step, SignerRole[]> = {
    RECOVERY_RESET: [2, 3],
    RECOVERY_KIT_REPLACEMENT: [1, 4],
    SWITCH_TO_PRIVATE: [1, 2, 4],
    SWITCH_TO_MANAGED: [1, 4],
  };

  /** The spec's sentence, transcribed: the last mode-setting transition decides. */
  function specMode(genesisVersion: number, steps: readonly Step[]): ProtectionMode {
    for (let i = steps.length - 1; i >= 0; i--) {
      if (steps[i] === "SWITCH_TO_MANAGED") return "MANAGED";
      if (steps[i] === "SWITCH_TO_PRIVATE") return "PRIVATE";
    }
    return genesisVersion === 2 ? "MANAGED" : "PRIVATE";
  }

  async function build(genesisVersion: number, steps: readonly Step[]): Promise<RootChainLink[]> {
    const g = genesis(genesisVersion);
    let head = g.head;
    const links = [await g.link];
    for (const [i, step] of steps.entries()) {
      // A fresh signer is any pool key that neither current role holds.
      const fresh = pool.filter((k) => k !== head.accountSigning && k !== head.recoveryAuthority);
      const as = STEP_KEYS[step].includes("accountSigning") ? fresh[i % fresh.length]! : head.accountSigning;
      const ra = STEP_KEYS[step].includes("recoveryAuthority") ? fresh[(i + 1) % fresh.length]! : head.recoveryAuthority;
      const version = step === "SWITCH_TO_MANAGED" ? 2 : head.descriptor.crypto_version;
      const descriptor = await nextDescriptor(head.descriptor, replacing(STEP_KEYS[step], as, ra, 0x70 + i), version);
      links.push(await link(step, head, descriptor, STEP_ROLES[step], { as, ra }));
      head = { descriptor, accountSigning: as, recoveryAuthority: ra };
    }
    return links;
  }

  const steps = fc.array(fc.constantFrom<Step>("RECOVERY_RESET", "RECOVERY_KIT_REPLACEMENT", "SWITCH_TO_PRIVATE", "SWITCH_TO_MANAGED"), { maxLength: 6 });

  it("the replayed mode is the last mode-setting transition's, from GENESIS and from any prefix (property)", async () => {
    await fc.assert(
      fc.asyncProperty(fc.constantFrom(1, 2), steps, fc.nat(), async (version, chainSteps, cut) => {
        const links = await build(version, chainSteps);
        const whole = await outcome(links);
        if (!whole.ok) throw new Error(whole.failure.code);
        expect(whole.value.mode).toBe(specMode(version, chainSteps));
        // Continuing from a verified prefix carries the mode across.
        const k = 1 + (cut % links.length);
        const prefix = await outcome(links.slice(0, k));
        if (!prefix.ok) throw new Error(prefix.failure.code);
        expect(prefix.value.mode).toBe(specMode(version, chainSteps.slice(0, k - 1)));
        const rest = await verifyRootChain(links.slice(k), { accountId: ACCOUNT, from: prefix.value });
        if (!rest.ok) throw new Error(rest.failure.code);
        expect(rest.value.mode).toBe(whole.value.mode);
      }),
      { numRuns: 40 },
    );
  });

  it("broken variant: a derivation where RECOVERY_RESET resets the mode to Private is caught", () => {
    const broken = (previous: ProtectionMode | null, t: TransitionType, v: number): ProtectionMode =>
      t === "RECOVERY_RESET" ? "PRIVATE" : modeAfter(previous, t, v);
    const fold = (derive: typeof modeAfter, version: number, chainSteps: readonly Step[]) =>
      chainSteps.reduce<ProtectionMode>((mode, step) => derive(mode, step, 2), derive(null, "GENESIS", version));
    // The oracle agrees with the real fold on every sequence, and disagrees with the broken one on some.
    const counter = fc.check(
      fc.property(fc.constantFrom(1, 2), steps, (version, chainSteps) => fold(broken, version, chainSteps) === specMode(version, chainSteps)),
    );
    expect(counter.failed).toBe(true);
    fc.assert(fc.property(fc.constantFrom(1, 2), steps, (version, chainSteps) => fold(modeAfter, version, chainSteps) === specMode(version, chainSteps)));
  });

  it("broken variant: a derivation that ignores the GENESIS version is caught", () => {
    const broken = (previous: ProtectionMode | null, t: TransitionType, v: number): ProtectionMode =>
      t === "GENESIS" ? "PRIVATE" : modeAfter(previous, t, v);
    expect(broken(null, "GENESIS", 2)).not.toBe(specMode(2, []));
  });
});
