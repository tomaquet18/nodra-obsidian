import type { ReplicaAuth, Settings } from "./controller.js";
import type { BlobOpener } from "./http-backend.js";
import type { InstallationState } from "./installation.js";
import type { ManifestInput } from "./manifest.js";
import type { BlobCrypto, ManifestBinding, ManifestCodec } from "./ports.js";

// ============================================================================================
// DEVELOPMENT ONLY — NEVER FOR PRODUCTION (§22: "NO DEBE salir de entornos de desarrollo").
// ============================================================================================
// DevVaultCrypto (§22, Phase 0 of §42): one local key per vault, DERIVED FROM THE VAULT ID, so anybody
// who knows the vault id can read every blob. The demo no longer uses it: the plugin and the web enroll
// (trust.ts) and run the real VaultCrypto. It stays for the suites that exercise sync behaviour without
// an account (sync-client's e2e and simulations, the plugin's controller reactions); see NOTES question 281.
//
// Ciphertext: the ASCII bytes of base64(iv ‖ AES-GCM-256(payload, aad)). sync-core carries ciphertext
// as bytes (NOTES question 52); the base64 wire format is kept so that blobs stored by earlier dev
// builds still open (NOTES question 141). Its size is still exact and known before encrypting.
//
// It mirrors the SHAPE of the real thing even where it cannot mirror the strength: the manifest AAD
// names the revision (§31.3), a content blob carries a fingerprint (§31.4), and the §9 check on the
// way down is the same check. A demo that skipped them would let the sync path drift away from the
// one the real crypto imposes, and the drift would only surface at the switch-over.

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const IV = 12;
const TAG = 16;

const hex = (bytes: ArrayBuffer) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

const fromBase64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/**
 * DEVELOPMENT ONLY. The Phase 0 manifest: UTF-8 JSON of the §8 fields, not the NCE map of §23.4.
 * It exists so the demo and the test doubles can carry ids that are not UUIDv7 (§6); the real
 * codec, `nceManifestCodec`, refuses those on purpose.
 */
export const devManifestCodec: ManifestCodec = {
  encodeManifest: (input) => encoder.encode(JSON.stringify(input)),
  decodeManifest: (payload) => {
    const value = JSON.parse(decoder.decode(payload)) as Partial<ManifestInput>;
    if (typeof value.path !== "string") throw new Error("not a manifest");
    // Phase 0 manifests written by older dev builds, and by the control-plane contract's model,
    // carry the path alone. The missing fields become "declares nothing", never a wrong value.
    return { objectId: "", revisionId: "", parentRevisionId: null, mtimeMs: 0, deleted: false, ...value, path: value.path };
  },
};

/** DEVELOPMENT ONLY: the §31.3 AADs, in the shape the real crypto uses (vault, blob, kind, revision). */
function aad(vaultId: string, blobId: string, kind: string, binding: ManifestBinding | undefined): Uint8Array {
  const revision = binding === undefined ? "" : `|${binding.objectId}|${binding.revisionId}|${binding.parentRevisionId ?? ""}`;
  return encoder.encode(`${vaultId}|${blobId}|${kind}${revision}`);
}

/** DEVELOPMENT ONLY: the upload (BlobCrypto) and download (BlobOpener) halves of a dev VaultCrypto. */
export function devVaultCrypto(vaultId: string): BlobCrypto & BlobOpener {
  const key = crypto.subtle
    .digest("SHA-256", encoder.encode(`nodra-dev-vault-crypto:v0:${vaultId}`))
    .then((raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]));
  const dedup = crypto.subtle
    .digest("SHA-256", encoder.encode(`nodra-dev-dedup:v0:${vaultId}`))
    .then((raw) => crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]));
  const declaredSize = (payload: Uint8Array) => 4 * Math.ceil((IV + payload.byteLength + TAG) / 3);

  /**
   * DEVELOPMENT ONLY stand-in for §31.4. The real one keys the HMAC with the DEDUP KEY OF THE
   * EPOCH; this one has no epochs, so it keys it with the vault and takes the epoch id in as data.
   * The property the sync path depends on — "the same bytes under the same epoch give the same
   * fingerprint, a different epoch gives a different one" — is preserved; the confidentiality is not.
   */
  const fingerprint = async (epochId: string, payload: Uint8Array) => {
    const scoped = new Uint8Array(encoder.encode(`${epochId}|`).length + payload.byteLength);
    scoped.set(encoder.encode(`${epochId}|`));
    scoped.set(payload, encoder.encode(`${epochId}|`).length);
    return hex(await crypto.subtle.sign("HMAC", await dedup, scoped));
  };

  return {
    ...devManifestCodec,
    declaredSize,
    async encryptBlob({ epochId, blobId, kind, payload, binding }) {
      const iv = crypto.getRandomValues(new Uint8Array(IV));
      const sealed = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(vaultId, blobId, kind, kind === "MANIFEST" ? binding : undefined) as Uint8Array<ArrayBuffer> }, await key, payload as Uint8Array<ArrayBuffer>),
      );
      const bytes = new Uint8Array(IV + sealed.length);
      bytes.set(iv);
      bytes.set(sealed, IV);
      const ciphertext = encoder.encode(toBase64(bytes));
      return {
        ciphertext,
        ciphertextSha256: hex(await crypto.subtle.digest("SHA-256", ciphertext)),
        declaredSize: declaredSize(payload),
        ...(kind === "CONTENT" ? { fingerprint: await fingerprint(epochId, payload) } : {}),
      };
    },
    async open({ epochId, blobId, kind, ciphertext, binding, expectFingerprint }) {
      const bytes = fromBase64(decoder.decode(ciphertext));
      const opened = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: bytes.subarray(0, IV), additionalData: aad(vaultId, blobId, kind, kind === "MANIFEST" ? binding : undefined) as Uint8Array<ArrayBuffer> },
          await key,
          bytes.subarray(IV),
        ),
      );
      // §9 step 2, in the dev path too: nothing is handed back that the manifest does not vouch for.
      if (kind === "CONTENT" && expectFingerprint !== undefined && (await fingerprint(epochId, opened)) !== expectFingerprint) {
        throw new Error("CORRUPTION_OR_MISBINDING");
      }
      return opened;
    },
  };
}

/** Must match the dev server's REPLICA_HEADER (workers/dev-server; a test checks it). DEV ONLY. */
export const DEV_REPLICA_HEADER = "x-nodra-dev-replica";

/**
 * DEV ONLY, TESTS ONLY: the dev server's stand-in for a Write Capability — a session bearer plus a
 * replica id the client makes up. The demo no longer uses it (it enrolls and proves possession,
 * trust.ts); it is kept for the controller tests that exercise sync behaviour, not keys. It needs
 * a valid session (any user's JWT): the shared dev bearer is gone (slice 19).
 */
export const devReplicaAuth =
  (settings: Pick<Settings, "accessToken">) =>
  (installation: Pick<InstallationState, "replicaId">): ReplicaAuth => ({
    replicaId: installation.replicaId,
    headers: async () => {
      const token = typeof settings.accessToken === "string" ? settings.accessToken : await settings.accessToken();
      return { authorization: `Bearer ${token}`, [DEV_REPLICA_HEADER]: installation.replicaId };
    },
  });

