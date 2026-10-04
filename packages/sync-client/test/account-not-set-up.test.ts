import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { v7 as uuidv7 } from "uuid";
import { describe, expect, it } from "vitest";
import { installationStore } from "../src/installation.js";
import { uuidToBytes } from "../src/manifest.js";
import { accountProtection } from "../src/protection.js";
import { type AccountPins, type AccountTransport, ACCOUNT, PINS, TrustError, accountNotSetUp, provedRoot, unlockAccount } from "../src/trust.js";

// The bug reported from production (plugin 0.6.1): an account signed up but never set up on the web
// (§35.2 never ran, so no GENESIS) showed "TrustError: CHAIN_INVALID: root: EMPTY_CHAIN". Without pins
// for the account, an empty root chain is that account, not set up yet: NO_ACCOUNT_ROOT, which the UI
// can say in plain words. With pins (§28.3), this installation knows the account has a root, so an
// empty chain is the server rolling it back: still CHAIN_INVALID.

const PINNED: AccountPins = { rootGeneration: 1, rootHash: "aa".repeat(32), genesisRootHash: "aa".repeat(32), registryVersion: 1, registryHash: "bb".repeat(32), configVersion: 1 };

/** A server with no root for the account: an empty chain, and getRootState before GENESIS. Every other request fails the test. */
function noRootServer() {
  const calls: string[] = [];
  const transport = new Proxy({} as AccountTransport, {
    get(_, name: string) {
      return async () => {
        calls.push(name);
        if (name === "rootChain") return { kind: "ROOT_CHAIN", links: [] };
        if (name === "rootState") return { kind: "ROOT_STATE", profile: null, configBlob: null, configVersion: null, vaults: [] };
        throw new Error(`unexpected request: ${name}`);
      };
    },
  });
  return { transport, calls };
}

function session() {
  const accountId = uuidv7();
  const idb = { indexedDB: new IDBFactory(), IDBKeyRange };
  const installNs = `plugin:${uuidv7().replaceAll("-", "")}`;
  const store = installationStore({ installNs, ...idb });
  const o = { baseUrl: "http://unused.test", fetch: () => Promise.reject(new Error("no fetch")), sessionHeaders: () => ({}), accountId, serverSessionId: "s", installNs, ...idb };
  return { o, store, accountId };
}

const rows = async (store: ReturnType<typeof installationStore>) => {
  const snap = await store.read([ACCOUNT, PINS, "recipient", "security_bundle", "security_events"]);
  return { version: snap.version, rows: [...snap.rows] };
};

describe("an account whose §35.2 never ran (not set up on the web)", () => {
  it("provedRoot without pins: NO_ACCOUNT_ROOT, never CHAIN_INVALID", async () => {
    const { transport, calls } = noRootServer();
    const e = await provedRoot(transport, uuidToBytes(uuidv7()), undefined).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(TrustError);
    expect(e).toMatchObject({ code: "NO_ACCOUNT_ROOT" });
    expect(accountNotSetUp(e)).toBe(true);
    expect(calls).toEqual(["rootChain"]);
  });

  it("accountProtection (the plugin's account check): NO_ACCOUNT_ROOT after the chain fetch alone, and nothing written", async () => {
    const { transport, calls } = noRootServer();
    const { o, store } = session();
    const before = await rows(store);
    const e = await accountProtection({ ...o, transport }).catch((x: unknown) => x);
    expect(e).toMatchObject({ code: "NO_ACCOUNT_ROOT" });
    expect(String(e)).not.toContain("CHAIN_INVALID");
    expect(calls).toEqual(["rootChain"]);
    expect(await rows(store)).toEqual(before);
  });

  it("unlockAccount (the start of enrollment) without pins: NO_ACCOUNT_ROOT after getRootState alone", async () => {
    const { transport, calls } = noRootServer();
    await expect(unlockAccount(transport, uuidv7(), undefined, undefined)).rejects.toMatchObject({ code: "NO_ACCOUNT_ROOT" });
    expect(calls).toEqual(["rootState"]);
  });
});

describe("§28.3: an installation that holds pins for the account, and a server serving no root", () => {
  it("provedRoot: still CHAIN_INVALID (root: EMPTY_CHAIN), never 'not set up'", async () => {
    const { transport } = noRootServer();
    const e = await provedRoot(transport, uuidToBytes(uuidv7()), PINNED).catch((x: unknown) => x);
    expect(e).toMatchObject({ code: "CHAIN_INVALID", message: "CHAIN_INVALID: root: EMPTY_CHAIN" });
    expect(accountNotSetUp(e)).toBe(false);
  });

  it("accountProtection with this account's pins stored: CHAIN_INVALID, and the pins stay", async () => {
    const { transport } = noRootServer();
    const { o, store, accountId } = session();
    expect(await store.commit((await store.read([ACCOUNT, PINS])).version, { [ACCOUNT]: { accountId, email: null }, [PINS]: PINNED })).toBe(true);
    const before = await rows(store);
    const e = await accountProtection({ ...o, transport }).catch((x: unknown) => x);
    expect(e).toMatchObject({ code: "CHAIN_INVALID" });
    expect(accountNotSetUp(e)).toBe(false);
    expect(await rows(store)).toEqual(before);
  });

  it("unlockAccount (enrolling again after a revocation): getRootState before GENESIS is CHAIN_INVALID, never NO_ACCOUNT_ROOT", async () => {
    const { transport } = noRootServer();
    const e = await unlockAccount(transport, uuidv7(), undefined, PINNED).catch((x: unknown) => x);
    expect(e).toMatchObject({ code: "CHAIN_INVALID" });
    expect(accountNotSetUp(e)).toBe(false);
  });
});

describe("accountNotSetUp", () => {
  it("is true for NO_ACCOUNT_ROOT only", () => {
    expect(accountNotSetUp(new TrustError("NO_ACCOUNT_ROOT", "x"))).toBe(true);
    expect(accountNotSetUp(new TrustError("CHAIN_INVALID", "root: EMPTY_CHAIN"))).toBe(false);
    expect(accountNotSetUp(new Error("NO_ACCOUNT_ROOT"))).toBe(false);
    expect(accountNotSetUp(null)).toBe(false);
  });
});
