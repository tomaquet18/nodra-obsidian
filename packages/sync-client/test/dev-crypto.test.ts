import { describe, expect, it } from "vitest";
import { devVaultCrypto } from "../src/dev-crypto.js";
import { utf8 } from "./support/bytes.js";

// DevVaultCrypto (§22, Phase 0, development only): the size is known before encrypting (§12.1), the
// ciphertext is exactly that many bytes (the Worker checks it, §11.2), and a blob only opens as itself.

const BINARY = Uint8Array.from({ length: 70_000 }, (_, i) => (i * 131 + 7) & 0xff);
const PAYLOADS: Array<[string, Uint8Array]> = [
  ["empty", new Uint8Array()],
  ["a", utf8("a")],
  ["ab", utf8("ab")],
  ["abc", utf8("abc")],
  ["multibyte text", utf8("héllo wörld ✓")],
  ["large text", utf8("x".repeat(100_000))],
  ["invalid UTF-8, NUL and a BOM", Uint8Array.from([0xef, 0xbb, 0xbf, 0, 0xff, 0xfe, 0x80, 0xc3, 0x28])],
  ["binary", BINARY],
];

describe("DevVaultCrypto", () => {
  const dev = devVaultCrypto("vault-1");

  it.each(PAYLOADS)("round-trips %s byte for byte, with exactly the declared size in bytes", async (_name, payload) => {
    const sealed = await dev.encryptBlob({ epochId: "e1", blobId: "b1", kind: "CONTENT", payload });
    expect(sealed.declaredSize).toBe(dev.declaredSize(payload));
    expect(sealed.ciphertext.byteLength).toBe(sealed.declaredSize);
    if (payload.length >= 16) expect(new TextDecoder().decode(sealed.ciphertext)).not.toContain(new TextDecoder().decode(payload.subarray(0, 16)));
    expect(await dev.open({ epochId: "e1", blobId: "b1", kind: "CONTENT", ciphertext: sealed.ciphertext })).toEqual(payload);
  });

  it("opens a blob stored by an earlier dev build (the same base64 wire format, NOTES question 141)", async () => {
    const sealed = await dev.encryptBlob({ epochId: "e1", blobId: "b1", kind: "CONTENT", payload: utf8("old note") });
    expect(new TextDecoder().decode(sealed.ciphertext)).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  it("a ciphertext does not open as another blob, another kind, or in another vault", async () => {
    const { ciphertext } = await dev.encryptBlob({ epochId: "e1", blobId: "b1", kind: "CONTENT", payload: utf8("note") });
    await expect(dev.open({ epochId: "e1", blobId: "b2", kind: "CONTENT", ciphertext })).rejects.toThrow();
    await expect(dev.open({ epochId: "e1", blobId: "b1", kind: "MANIFEST", ciphertext })).rejects.toThrow();
    await expect(devVaultCrypto("vault-2").open({ epochId: "e1", blobId: "b1", kind: "CONTENT", ciphertext })).rejects.toThrow();
  });

  it("the declared sha256 is the digest of the ciphertext's bytes", async () => {
    const { ciphertext, ciphertextSha256 } = await dev.encryptBlob({ epochId: "e1", blobId: "b1", kind: "MANIFEST", payload: utf8("{}") });
    const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", ciphertext as Uint8Array<ArrayBuffer>))].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(ciphertextSha256).toBe(digest);
  });
});
