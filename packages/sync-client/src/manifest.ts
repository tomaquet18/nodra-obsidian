import { REVISION_MANIFEST, decodeRecord, encodeRecord } from "@nodra/encoding/records";
import type { RevisionManifest } from "@nodra/encoding/records";

// The §8 Revision Manifest: the NCE map that binds a revision's identity, its logical path and its
// content, encrypted whole as the manifest blob of §31.3.
//
// Two things make this file more than an encoder.
//
//   1. **Ids are 16 bytes here and uuid strings everywhere else.** sync-core carries ids as opaque
//      strings (§6 calls them UUIDv7); §23.2 fixes them at 16 bytes inside NCE. {@link uuidToBytes}
//      is the only crossing, and it REFUSES anything that is not a uuid instead of padding or
//      hashing it: a manifest whose `object_id` is not the object's id would open, verify and mean
//      the wrong thing, which is the one failure §8 exists to prevent.
//   2. **`mime` is derived from the logical path, not supplied.** §8 requires the field and §19
//      forbids leaking more than the protocol needs; the extension is already inside the encrypted
//      `path`, so deriving it adds nothing the manifest does not already carry. See NOTES question 255.

export type { RevisionManifest };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export class ManifestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ManifestError";
  }
}

/** The 16 bytes of a uuid string (§6, §23.2). Throws on anything else — never a silent coercion. */
export function uuidToBytes(id: string): Uint8Array {
  if (!UUID.test(id)) throw new ManifestError(`not a uuid: ${id}`);
  const hex = id.replaceAll("-", "");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** The uuid string of 16 bytes; the inverse of {@link uuidToBytes}. */
export function bytesToUuid(id: Uint8Array): string {
  if (id.length !== 16) throw new ManifestError(`an id is 16 bytes, got ${id.length}`);
  let hex = "";
  for (const byte of id) hex += byte.toString(16).padStart(2, "0");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export const uuidOrNull = (id: string | null): Uint8Array | null => (id === null ? null : uuidToBytes(id));

/** Lowercase hex of bytes (fingerprints travel as hex through the ports, like `ciphertextSha256`). */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * `mime` of §8, from the logical path's extension. Markdown is the only type the client treats
 * specially (§17 merges it); everything else is an attachment carried as bytes (§2.1), so the table
 * stays short and anything unknown is `application/octet-stream`.
 */
const MIME: Readonly<Record<string, string>> = {
  md: "text/markdown",
  markdown: "text/markdown",
  txt: "text/plain",
  canvas: "application/json",
  json: "application/json",
  pdf: "application/pdf",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  svg: "image/svg+xml",
  avif: "image/avif",
  mp3: "audio/mpeg",
  m4a: "audio/mp4",
  wav: "audio/wav",
  ogg: "audio/ogg",
  webm: "video/webm",
  mp4: "video/mp4",
  mov: "video/quicktime",
};

export const DEFAULT_MIME = "application/octet-stream";

export function mimeForPath(path: string): string {
  const name = path.slice(path.lastIndexOf("/") + 1);
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return DEFAULT_MIME;
  return MIME[name.slice(dot + 1).toLowerCase()] ?? DEFAULT_MIME;
}

/** What the client knows about a revision when it builds its manifest. */
export interface ManifestInput {
  readonly objectId: string;
  readonly revisionId: string;
  readonly parentRevisionId: string | null;
  readonly path: string;
  readonly mtimeMs: number;
  readonly deleted: boolean;
  /** Absent for a delete: §8 nulls every content field, and §8 says a delete references no content. */
  readonly content?: {
    readonly blobId: string;
    readonly epochId: string;
    /** `content_fingerprint` (§31.4) as lowercase hex, taken with the dedup key of `epochId`. */
    readonly fingerprint: string;
    readonly plaintextSize: number;
  };
}

/** The §8 map of a revision. A delete carries no content fields at all (§8, §10.6). */
export function revisionManifest(input: ManifestInput): RevisionManifest {
  const content = input.deleted ? undefined : input.content;
  if (!input.deleted && content === undefined) throw new ManifestError("a live revision needs its content");
  return {
    object_id: uuidToBytes(input.objectId),
    revision_id: uuidToBytes(input.revisionId),
    parent_revision_id: uuidOrNull(input.parentRevisionId),
    path: input.path,
    mime: mimeForPath(input.path),
    mtime_ms: Math.max(0, Math.trunc(input.mtimeMs)),
    content_blob_id: content === undefined ? null : uuidToBytes(content.blobId),
    content_fingerprint: content === undefined ? null : fromHex(content.fingerprint),
    content_plaintext_size: content === undefined ? null : content.plaintextSize,
    deleted: input.deleted,
    content_epoch_id: content === undefined ? null : uuidToBytes(content.epochId),
  };
}

export const encodeManifest = (manifest: RevisionManifest): Uint8Array => encodeRecord(REVISION_MANIFEST, manifest);

/** Decodes a manifest's plaintext; throws `RecordError` on anything that is not one. */
export const decodeManifest = (plaintext: Uint8Array): RevisionManifest => decodeRecord(REVISION_MANIFEST, plaintext);

/** The §8 map back in the string-shaped form the client works in. */
export function manifestFields(manifest: RevisionManifest): ManifestInput {
  const live = !manifest.deleted && manifest.content_blob_id !== null && manifest.content_epoch_id !== null && manifest.content_fingerprint !== null;
  return {
    objectId: bytesToUuid(manifest.object_id),
    revisionId: bytesToUuid(manifest.revision_id),
    parentRevisionId: manifest.parent_revision_id === null ? null : bytesToUuid(manifest.parent_revision_id),
    path: manifest.path,
    mtimeMs: manifest.mtime_ms,
    deleted: manifest.deleted,
    ...(live
      ? {
          content: {
            blobId: bytesToUuid(manifest.content_blob_id as Uint8Array),
            epochId: bytesToUuid(manifest.content_epoch_id as Uint8Array),
            fingerprint: toHex(manifest.content_fingerprint as Uint8Array),
            plaintextSize: manifest.content_plaintext_size ?? 0,
          },
        }
      : {}),
  };
}

/**
 * The §8 codec as the `VaultCrypto` port exposes it (ports.ts `ManifestCodec`): the real one, used
 * wherever the real §31 crypto is. `encodeManifest` refuses an id that is not a uuid, so a client
 * that has not been given real §6 ids fails here rather than sealing a manifest that means nothing.
 */
export const nceManifestCodec = {
  encodeManifest: (input: ManifestInput): Uint8Array => encodeManifest(revisionManifest(input)),
  decodeManifest: (payload: Uint8Array): ManifestInput => manifestFields(decodeManifest(payload)),
};
