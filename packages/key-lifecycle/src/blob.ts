// The two blobs of §31.3 — content and manifest — sealed and opened under the Epoch Key, plus the
// content fingerprint of §31.4.
//
// Everything that makes these four functions safe is in their arguments, not in their bodies:
//
//   1. **The key is derived per blob, from the blob's own id** (§31.2). `deriveContentKey` and
//      `deriveManifestKey` take the `blob_id`, so re-encrypting the same revision in another upload
//      attempt uses another key. A caller cannot reuse a key across blobs because it never holds one.
//   2. **The AAD is built here, never passed in.** §31.3 fixes two AADs, and `@nodra/crypto` only
//      accepts a branded `DomainContext`, so a caller cannot substitute its own or forget one. The
//      vault and epoch come out of the {@link EpochKey} handle rather than from arguments, which is
//      what makes "the AAD names the epoch this key belongs to" true by construction.
//   3. **The nonce is never a parameter.** `seal` generates a fresh random one per call (§23.1), so
//      two blobs cannot share one even when a caller loops over the same key.
//
// §31.4's fingerprint lives here too, and takes an {@link EpochKey} rather than a dedup key, so the
// "always the epoch of the *content* blob, never the manifest's" rule of §31.4 is expressed as the
// argument the caller has to choose.
import { hmacSha256, seal, unseal } from "@nodra/crypto";
import { contentBlobAad, manifestBlobAad } from "./contexts.js";
import type { ManifestBinding } from "./contexts.js";
import { deriveContentKey, deriveDedupKey, deriveManifestKey } from "./epoch.js";
import type { EpochKey } from "./epoch.js";

export type { ManifestBinding } from "./contexts.js";

/** §31.3: `nonce (12) ‖ AES-GCM ciphertext‖tag`, under the content key and AAD of this blob. */
export async function sealContentBlob(epoch: EpochKey, blobId: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const key = await deriveContentKey(epoch, blobId);
  return seal(key, contentBlobAad(epoch.vaultId, epoch.epochId, blobId), plaintext);
}

/** The inverse of {@link sealContentBlob}; throws `CryptoError` when the blob does not authenticate. */
export async function openContentBlob(epoch: EpochKey, blobId: Uint8Array, blob: Uint8Array): Promise<Uint8Array> {
  const key = await deriveContentKey(epoch, blobId);
  return unseal(key, contentBlobAad(epoch.vaultId, epoch.epochId, blobId), blob);
}

/** §31.3 for a manifest: the AAD names the revision, so a manifest only opens where it belongs. */
export async function sealManifestBlob(
  epoch: EpochKey,
  blobId: Uint8Array,
  binding: ManifestBinding,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const key = await deriveManifestKey(epoch, blobId);
  return seal(key, manifestBlobAad(epoch.vaultId, epoch.epochId, blobId, binding), plaintext);
}

/** The inverse of {@link sealManifestBlob}; throws `CryptoError` when the blob does not authenticate. */
export async function openManifestBlob(
  epoch: EpochKey,
  blobId: Uint8Array,
  binding: ManifestBinding,
  blob: Uint8Array,
): Promise<Uint8Array> {
  const key = await deriveManifestKey(epoch, blobId);
  return unseal(key, manifestBlobAad(epoch.vaultId, epoch.epochId, blobId, binding), blob);
}

/**
 * `content_fingerprint = HMAC-SHA-256(DedupKey del epoch del content blob, plaintext)` (§31.4).
 *
 * `epoch` MUST be the epoch of the content blob (`content_epoch_id`, §8), which after a rotation is
 * not the manifest's. Passing the manifest's epoch produces a fingerprint that the §9 check on
 * download will reject, which is the failure mode §31.4 intends: dedup scope is `vault_id + epoch_id`.
 */
export async function contentFingerprint(epoch: EpochKey, plaintext: Uint8Array): Promise<Uint8Array> {
  return hmacSha256(await deriveDedupKey(epoch), plaintext);
}
