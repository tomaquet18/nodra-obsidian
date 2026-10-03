import type { DeviceLocalCrypto, LocalCompareHasher } from "./ports.js";

// Web Crypto adapters for the two local keys of §20.1. Both keys are generated non-extractable and
// can be persisted as CryptoKey in IndexedDB (structured clone). Nothing here runs inside a Dexie
// transaction: callers encrypt and hash first, then open the transaction (CLAUDE.md "Persistencia").

const IV_BYTES = 12;

/** Device Local Key: AES-GCM-256, extractable = false. */
export function generateDeviceLocalKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

/** LocalCompareKey: HMAC-SHA-256, extractable = false, per installation and vault. */
export function generateLocalCompareKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

/** Output: 12-byte random IV followed by the AES-GCM ciphertext and tag. */
export function webCryptoDeviceLocal(key: CryptoKey): DeviceLocalCrypto {
  return {
    async encrypt(plaintext) {
      const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
      const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext as Uint8Array<ArrayBuffer>));
      const out = new Uint8Array(IV_BYTES + sealed.length);
      out.set(iv);
      out.set(sealed, IV_BYTES);
      return out;
    },
    async decrypt(ciphertext) {
      const iv = ciphertext.slice(0, IV_BYTES);
      const opened = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext.slice(IV_BYTES));
      return new Uint8Array(opened);
    },
  };
}

const hex = (bytes: ArrayBuffer) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");

/** local_compare_hash as lowercase hex of HMAC-SHA-256(LocalCompareKey, plaintext bytes). */
export function webCryptoLocalCompare(key: CryptoKey): LocalCompareHasher {
  return {
    async hash(plaintext) {
      return hex(await crypto.subtle.sign("HMAC", key, plaintext as Uint8Array<ArrayBuffer>));
    },
  };
}
