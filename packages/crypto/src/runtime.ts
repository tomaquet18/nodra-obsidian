// Web Crypto access. §23.0 rule 3: only native Web Crypto (plus an audited Argon2id).
// §23.0 rule 7: a runtime without a mandatory capability is an `unsupported secure client`;
// there is no fallback implementation anywhere in this package.
import { CryptoError } from "./errors.js";

/**
 * The runtime's global `crypto` (browser, Obsidian, Node, Workers), or undefined where there is none.
 * Named directly, not through `globalThis`, which Obsidian's plugin review rejects (obsidianmd/no-global-this).
 */
export const runtimeCrypto = (): Crypto | undefined => (typeof crypto === "undefined" ? undefined : crypto);

/** The runtime's `crypto.subtle`, or `UNSUPPORTED_SECURE_CLIENT`. */
export function subtle(): SubtleCrypto {
  const c = runtimeCrypto();
  if (c?.subtle === undefined) {
    throw new CryptoError("UNSUPPORTED_SECURE_CLIENT", "crypto.subtle is not available");
  }
  return c.subtle;
}

/**
 * Checks the capabilities this package needs, so a client can fail loudly at startup
 * instead of half way through a security operation (§23.0 rule 7).
 */
export async function assertSecureCryptoCapabilities(): Promise<void> {
  const c = runtimeCrypto();
  if (c === undefined || typeof c.getRandomValues !== "function") {
    throw new CryptoError("UNSUPPORTED_SECURE_CLIENT", "crypto.getRandomValues is not available");
  }
  const s = subtle();
  const required: Promise<unknown>[] = [
    s.importKey("raw", new Uint8Array(32), "HKDF", false, ["deriveKey", "deriveBits"]),
    s.importKey("raw", new Uint8Array(32), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]),
    s.importKey("raw", new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    s.digest("SHA-256", new Uint8Array(0)),
  ];
  try {
    await Promise.all(required);
  } catch (cause) {
    throw new CryptoError("UNSUPPORTED_SECURE_CLIENT", `a crypto_version = 1 primitive is missing: ${String(cause)}`);
  }
}

/** Wraps a Web Crypto rejection that can only mean "authentication failed". */
export async function decrypting<T>(what: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (cause) {
    throw new CryptoError("DECRYPT_FAILED", `${what} failed: wrong key, context or tampered ciphertext (${String(cause)})`);
  }
}
