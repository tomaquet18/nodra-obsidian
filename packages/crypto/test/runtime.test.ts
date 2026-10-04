import { afterEach, describe, expect, it, vi } from "vitest";
import { randomBytes } from "../src/bytes.js";
import { assertSecureCryptoCapabilities, subtle } from "../src/runtime.js";

// §23.0 rule 7: a runtime without Web Crypto is an `unsupported secure client`, found through the
// global `crypto` of whatever runtime this is (browser, Obsidian, Node, a Worker).

afterEach(() => vi.unstubAllGlobals());

describe("a runtime without Web Crypto", () => {
  it("has the global crypto here, so the functions work", async () => {
    expect(randomBytes(4)).toHaveLength(4);
    expect(subtle()).toBe(crypto.subtle);
    await expect(assertSecureCryptoCapabilities()).resolves.toBeUndefined();
  });

  it("is refused as UNSUPPORTED_SECURE_CLIENT when the global crypto is missing", async () => {
    vi.stubGlobal("crypto", undefined);
    expect(() => randomBytes(4)).toThrow(expect.objectContaining({ code: "UNSUPPORTED_SECURE_CLIENT" }));
    expect(() => subtle()).toThrow(expect.objectContaining({ code: "UNSUPPORTED_SECURE_CLIENT" }));
    await expect(assertSecureCryptoCapabilities()).rejects.toMatchObject({ code: "UNSUPPORTED_SECURE_CLIENT" });
  });
});
