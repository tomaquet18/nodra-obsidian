import { afterEach, describe, expect, it, vi } from "vitest";
import { localVaultIds } from "../src/store.js";

// A host that passes no `indexedDB` gets the runtime's global one (a browser, Obsidian); a runtime with
// none (Node, a Worker) lists nothing and keeps only the vaults the host knows.

afterEach(() => vi.unstubAllGlobals());

const PREFIX = "nodra:plugin:abc:";

describe("localVaultIds without an injected indexedDB", () => {
  it("lists through the runtime's global indexedDB", async () => {
    vi.stubGlobal("indexedDB", { databases: async () => [{ name: `${PREFIX}v1` }, { name: "other" }] });
    expect(await localVaultIds({ installNs: "plugin:abc" })).toEqual(["v1"]);
  });

  it("with no global indexedDB, only the known vaults", async () => {
    vi.stubGlobal("indexedDB", undefined);
    expect(await localVaultIds({ installNs: "plugin:abc", known: ["v2"] })).toEqual(["v2"]);
  });
});
