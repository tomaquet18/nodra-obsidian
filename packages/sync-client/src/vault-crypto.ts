import { CryptoError } from "@nodra/crypto";
import type { EnvelopeUnwrapKey } from "@nodra/crypto";
import type { EpochDescriptor, EpochEnvelope } from "@nodra/encoding/records";
import {
  contentFingerprint,
  idKey,
  openContentBlob,
  openEpoch,
  openManifestBlob,
  sealContentBlob,
  sealManifestBlob,
  verifyEpochChain,
} from "@nodra/key-lifecycle";
import type { EpochChainState, EpochKey, RecipientIdentity } from "@nodra/key-lifecycle";
import { bytesToUuid, nceManifestCodec, toHex, uuidOrNull, uuidToBytes } from "./manifest.js";
import type { BlobCrypto, ManifestBinding, OpenBlobInput, SealedBlob } from "./ports.js";
import type { BlobOpener } from "./http-backend.js";

// The real `VaultCrypto` of §22: §31 crypto on the sync path, for the plugin and the web alike.
//
// It is deliberately two objects, not one.
//
//   * {@link EpochAccess} answers "what is the Epoch Key of this `epoch_id`?" and nothing else. It
//     owns the §32.1 chain replay, the §32.3 envelope opening and the §34 coverage answer, it caches
//     what it proved, and it is the only place that can say `EPOCH_NOT_COVERED`.
//   * {@link vaultCrypto} turns that into the `BlobCrypto`/`BlobOpener` pair the upload and download
//     paths already speak, adding nothing but §31.3 framing, §31.4 fingerprints and the §9 check.
//
// Three properties come out of that split rather than out of discipline:
//
//   1. **A key is never chosen by the crypto, only resolved.** Every seal and open names an
//      `epoch_id` that came from a fact — the write epoch the server last told the client (§12.7),
//      or `content_epoch_id` / `manifest_epoch_id` off a revision (§8, §13.1). There is no "current
//      epoch" inside this module to fall out of date after a rotation.
//   2. **An epoch the replica cannot open is a typed refusal, never a fallback.** §34's coverage
//      rule is what makes a replica able to read old data; a client that quietly sealed under some
//      other epoch would write content nobody can read. So `EPOCH_NOT_COVERED` travels up and the
//      upload does not happen.
//   3. **A rotation needs no new object.** A write after `EPOCH_STALE`, or a read of a revision
//      written under an epoch this process has not seen, asks the {@link EpochDirectory} once for a
//      longer chain and verifies it as an extension of the one already proved (§32.1 pinning).

export type VaultCryptoFailureCode =
  /** §32.1: the vault's descriptor chain did not verify, or does not extend the one already proved. */
  | "EPOCH_CHAIN_INVALID"
  /** The `epoch_id` is not in the vault's verified chain, even after asking the directory again. */
  | "EPOCH_UNKNOWN"
  /** §34: the chain has this epoch, but this replica holds no envelope for it — it cannot read or write it. */
  | "EPOCH_NOT_COVERED"
  /** §32.3: the envelope did not unwrap under this recipient's key and label, or the commitment failed. */
  | "BROKEN_OR_WRONG_ENVELOPE"
  /** §9: a blob that did not authenticate, an epoch that does not match the manifest, or a wrong fingerprint. */
  | "CORRUPTION_OR_MISBINDING"
  /** A manifest blob sealed or opened without the §31.3 binding, or a payload that is not a manifest. */
  | "MISSING_MANIFEST_BINDING";

export class VaultCryptoError extends Error {
  constructor(
    readonly code: VaultCryptoFailureCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "VaultCryptoError";
  }
}

/**
 * §22 `listEpochDescriptors` as this module needs it: the vault's descriptor chain in order, and the
 * envelopes addressed to this replica's recipient. The HTTP shape of it is a later slice; a test or
 * the demo supplies it directly.
 */
export interface EpochDirectory {
  list(): Promise<{ readonly descriptors: readonly EpochDescriptor[]; readonly envelopes: readonly EpochEnvelope[] }>;
}

export interface EpochAccessOptions {
  readonly vaultId: string;
  readonly directory: EpochDirectory;
  /** Who this replica is (§32.3): the label of every open is built from this, never from an envelope. */
  readonly recipient: RecipientIdentity;
  /** The Session handle of §25.1 — `["unwrapKey"]` only, so no `epoch_secret` ever becomes bytes (§33.1). */
  readonly privateKey: EnvelopeUnwrapKey;
  /** SPKI of the Account Signing Key per root generation, from a verified root chain (§28). */
  readonly accountSigningKeys: ReadonlyMap<number, Uint8Array>;
  readonly rootHashes: ReadonlyMap<number, Uint8Array>;
  /** `crypto_version` of each root generation, from the same verified chain (§32.1 (b)). */
  readonly rootCryptoVersions: ReadonlyMap<number, number>;
  readonly registryHashes: ReadonlyMap<number, Uint8Array>;
  /** §32.1: the last `descriptor_hash` this client accepted for the vault, if it has one. */
  readonly pin?: { readonly epochId: Uint8Array; readonly descriptorHash: Uint8Array };
  /**
   * Called with the chain state the moment a replay proves it, and awaited before any key derived
   * from that chain is handed out. That is how the §32.1 pin becomes durable: a pin written
   * best-effort would leave a window in which this client had already accepted a longer history
   * but could still be served a truncated one after a restart, which is the exact rollback §32.1
   * exists to refuse.
   */
  readonly onChainProved?: (state: EpochChainState) => void | Promise<void>;
}

export interface EpochAccess {
  readonly vaultId: string;
  /** The Epoch Key of `epochId` (a uuid string), proving the chain and opening the envelope on the way. */
  epochKey(epochId: string): Promise<EpochKey>;
  /** The chain state last proved, so the caller can advance its §32.1 pin. */
  chain(): EpochChainState | null;
}

/**
 * Resolves epoch ids to Epoch Keys for one vault. The chain is fetched and replayed lazily, at most
 * once per unknown epoch id, and every later fetch is verified as an EXTENSION of what was already
 * proved (`from`), so a server that answers with a shorter or forked history is rejected rather
 * than believed.
 */
export function epochAccess(o: EpochAccessOptions): EpochAccess {
  const vaultIdBytes = uuidToBytes(o.vaultId);
  const keys = new Map<string, Promise<EpochKey>>();
  const envelopes = new Map<string, EpochEnvelope>();
  const descriptors = new Map<string, EpochDescriptor>();
  let state: EpochChainState | null = null;
  let loading: Promise<void> | null = null;

  async function load(): Promise<void> {
    const listed = await o.directory.list();
    const known = new Set(state?.epochIds.map(idKey) ?? []);
    const fresh = listed.descriptors.filter((d) => !known.has(idKey(d.epoch_id)));
    const verified = await verifyEpochChain(fresh, {
      vaultId: vaultIdBytes,
      accountSigningKeys: o.accountSigningKeys,
      rootHashes: o.rootHashes,
      rootCryptoVersions: o.rootCryptoVersions,
      registryHashes: o.registryHashes,
      ...(state === null ? {} : { from: state }),
      ...(o.pin === undefined ? {} : { pin: o.pin }),
    });
    if (!verified.ok) {
      throw new VaultCryptoError("EPOCH_CHAIN_INVALID", `${verified.failure.code}: ${verified.failure.message}`);
    }
    state = verified.value;
    await o.onChainProved?.(verified.value);
    for (const d of listed.descriptors) descriptors.set(idKey(d.epoch_id), d);
    for (const e of listed.envelopes) {
      // Only envelopes addressed to this replica are worth keeping: §32.3 builds the label from the
      // client's own identity, so any other one could not open anyway.
      if (idKey(e.recipient_id) === idKey(o.recipient.recipientId) && e.recipient_type === o.recipient.type) {
        envelopes.set(idKey(e.epoch_id), e);
      }
    }
  }

  /** One in-flight load at a time; a failure is not cached, so the next call asks again. */
  function loadOnce(): Promise<void> {
    loading ??= load().finally(() => {
      loading = null;
    });
    return loading;
  }

  async function open(epochId: string): Promise<EpochKey> {
    const key = idKey(uuidToBytes(epochId));
    // One refresh, then decide. An epoch missing from the chain is a rotation this process has not
    // seen; a descriptor without an envelope may be a coverage gap a §35 operation has since closed
    // (§34.2). Both are answered by asking the directory again — once.
    if (!descriptors.has(key) || !envelopes.has(key)) await loadOnce();
    const descriptor = descriptors.get(key);
    if (descriptor === undefined) {
      throw new VaultCryptoError("EPOCH_UNKNOWN", `epoch ${epochId} is not in this vault's verified chain`);
    }
    const envelope = envelopes.get(key);
    if (envelope === undefined) {
      // §34.2: a replica with no envelope for an epoch cannot read it and MUST NOT write under it.
      throw new VaultCryptoError("EPOCH_NOT_COVERED", `this replica holds no envelope for epoch ${epochId}`);
    }
    const opened = await openEpoch({ descriptor, envelope, recipient: o.recipient, privateKey: o.privateKey });
    if (!opened.ok) {
      const code = opened.failure.code === "ENVELOPE_MISBOUND" ? "BROKEN_OR_WRONG_ENVELOPE" : opened.failure.code;
      throw new VaultCryptoError(code, opened.failure.message);
    }
    return opened.value;
  }

  return {
    vaultId: o.vaultId,
    chain: () => state,
    epochKey(epochId) {
      const key = idKey(uuidToBytes(epochId));
      const cached = keys.get(key);
      if (cached !== undefined) return cached;
      // A failed open is not cached: a coverage gap closed by a §35 operation must become readable
      // without restarting the client.
      const pending = open(epochId).catch((e: unknown) => {
        keys.delete(key);
        throw e;
      });
      keys.set(key, pending);
      return pending;
    },
  };
}

const NONCE_BYTES = 12;
const TAG_BYTES = 16;

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>)));
}

function bindingBytes(kind: string, binding: ManifestBinding | undefined) {
  if (binding === undefined) throw new VaultCryptoError("MISSING_MANIFEST_BINDING", `a ${kind} blob needs its §31.3 revision binding`);
  return {
    objectId: uuidToBytes(binding.objectId),
    revisionId: uuidToBytes(binding.revisionId),
    parentRevisionId: uuidOrNull(binding.parentRevisionId),
  };
}

/** The real VaultCrypto of §22: the upload (`BlobCrypto`) and download (`BlobOpener`) halves. */
export function vaultCrypto(access: EpochAccess): BlobCrypto & BlobOpener {
  return {
    // The real §8 codec: uuid ids, the frozen NCE key table of §23.4.
    ...nceManifestCodec,

    /** §31.3 framing: a 12-byte nonce, the plaintext and a 16-byte tag. Exact and known before encrypting. */
    declaredSize: (payload) => NONCE_BYTES + payload.byteLength + TAG_BYTES,

    async encryptBlob(input): Promise<SealedBlob> {
      const epoch = await access.epochKey(input.epochId);
      const blobId = uuidToBytes(input.blobId);
      if (input.kind === "MANIFEST") {
        const ciphertext = await sealManifestBlob(epoch, blobId, bindingBytes("MANIFEST", input.binding), input.payload);
        return { ciphertext, ciphertextSha256: await sha256Hex(ciphertext), declaredSize: ciphertext.byteLength };
      }
      const ciphertext = await sealContentBlob(epoch, blobId, input.payload);
      return {
        ciphertext,
        ciphertextSha256: await sha256Hex(ciphertext),
        declaredSize: ciphertext.byteLength,
        // §31.4 with the dedup key of THIS epoch — the one the blob is sealed under, which is what
        // `content_epoch_id` will record and what §9 recomputes with on the way back.
        fingerprint: toHex(await contentFingerprint(epoch, input.payload)),
      };
    },

    async open(input: OpenBlobInput): Promise<Uint8Array> {
      const epoch = await access.epochKey(input.epochId);
      const blobId = uuidToBytes(input.blobId);
      let plaintext: Uint8Array;
      try {
        plaintext =
          input.kind === "MANIFEST"
            ? await openManifestBlob(epoch, blobId, bindingBytes("MANIFEST", input.binding), input.ciphertext)
            : await openContentBlob(epoch, blobId, input.ciphertext);
      } catch (e) {
        if (e instanceof CryptoError) {
          // §9: nothing is written locally, and the client cannot tell corruption from misbinding.
          throw new VaultCryptoError("CORRUPTION_OR_MISBINDING", `the ${input.kind.toLowerCase()} blob ${input.blobId} did not authenticate`);
        }
        throw e;
      }
      if (input.kind === "CONTENT" && input.expectFingerprint !== undefined) {
        // §9 step 2: recompute with the dedup key of the blob's OWN epoch and compare.
        const actual = toHex(await contentFingerprint(epoch, plaintext));
        if (actual !== input.expectFingerprint) {
          throw new VaultCryptoError("CORRUPTION_OR_MISBINDING", `content blob ${input.blobId} does not match the manifest's content_fingerprint`);
        }
      }
      return plaintext;
    },
  };
}

export { bytesToUuid, uuidToBytes };
