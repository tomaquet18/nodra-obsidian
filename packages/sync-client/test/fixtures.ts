import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { type ClientFacts, EMPTY_OTHER_SYNC_FACTS, emptyFacts, emptyIntentState } from "@nodra/sync-core";
import { webCryptoDeviceLocal, generateDeviceLocalKey } from "../src/crypto.js";
import type { VaultState } from "../src/state.js";
import { type StoreOptions } from "../src/store.js";
import { utf8 } from "./support/bytes.js";

/** A fresh, isolated IndexedDB per test (fake-indexeddb): closing and reopening simulates a crash. */
export const freshIdb = (): Pick<StoreOptions, "indexedDB" | "IDBKeyRange"> => ({ indexedDB: new IDBFactory(), IDBKeyRange });

export async function deviceLocal() {
  return webCryptoDeviceLocal(await generateDeviceLocalKey());
}

export const emptyVault = (): VaultState => ({
  leaderEpoch: 0,
  facts: emptyFacts("vault-1", "replica-1", "e1"),
  observations: new Map(),
  journal: null,
  hashes: new Map(),
  intents: [],
  intentState: emptyIntentState(),
  fileStats: new Map(),
  otherSync: EMPTY_OTHER_SYNC_FACTS,
});

export const SECRET_TEXT = "secret note body";
export const SECRET = utf8(SECRET_TEXT);

/** One value of every persisted fact (§12.2 table, §15, §20.1, §20.2). */
export function richVault(leaderEpoch = 0): VaultState {
  const rev = (revisionId: string, sequence: number, path: string, hash: string | null = `h-${revisionId}`) => ({
    revisionId,
    sequence,
    path,
    localCompareHash: hash,
    deleted: false,
    createdSequence: 1,
  });
  const facts: ClientFacts = {
    ...emptyFacts("vault-1", "replica-1", "e2"),
    synced: new Map([
      ["o1", rev("r1", 1, "a.md")],
      ["o2", { ...rev("r2", 2, "b.md", null), deleted: true }],
    ]),
    remote: new Map([["o1", rev("r3", 3, "a.md")]]),
    outbox: [
      {
        mutationId: "m1",
        commitSent: true,
        objects: [
          { objectId: "o1", revisionId: "r4", expectedHeadRevisionId: "r1", path: "a.md", deleted: false, localCompareHash: "h-local", plaintext: SECRET, newBlobBytes: 40 },
          { objectId: "o2", revisionId: "r5", expectedHeadRevisionId: "r2", path: "b.md", deleted: true, localCompareHash: null, plaintext: null, newBlobBytes: 20 },
        ],
      },
      { mutationId: "m0", commitSent: false, objects: [{ objectId: "o3", revisionId: "r6", expectedHeadRevisionId: null, path: "c.md", deleted: false, localCompareHash: "h-c", plaintext: utf8("other"), newBlobBytes: 9 }] },
    ],
    attempts: [
      {
        attemptId: "a1",
        mutationId: "m1",
        replicaId: "replica-1",
        epochId: "e2",
        blobs: [{ blobId: "b1", kind: "CONTENT", objectId: "o1", declaredSize: 40, ciphertextSha256: "sha", ciphertext: utf8("opaque-ciphertext"), forDelete: false, expiresAt: 17 }],
      },
    ],
    cleanup: [{ vaultId: "vault-1", replicaId: "replica-1", blobId: "b0" }],
    blocked: [{ objectId: "o3", localCompareHash: "h-big", reason: "BLOB_TOO_LARGE" }],
    invalidBatchCounts: new Map([["o1|h-local", 1]]),
    uploadFailures: new Map([["o3|h-c", 2]]),
    byteCaps: new Map([["o3", 512]]),
    cursor: 42,
  };
  return {
    leaderEpoch,
    facts,
    observations: new Map([
      ["o1", { kind: "PRESENT", logicalPath: "a.md", physicalPath: "a.md", hash: "h-local" }],
      ["o2", { kind: "ABSENT", logicalPath: "b.md" }],
      ["o4", { kind: "NOT_MATERIALIZED" }],
    ]),
    journal: {
      objectId: "o1",
      kind: "WRITE",
      sourcePath: null,
      destPath: "a.md",
      tmpName: "nodra-tmp-0000abcd",
      expectedPrevFp: "h-local",
      finalFp: "h-r3",
      newSynced: rev("r3", 3, "a.md"),
      recordedLogicalPath: "a.md",
      tmpCreated: true,
      content: SECRET,
      marksNotMaterialized: false,
    },
    hashes: new Map([["r1", "h-r1"], ["r3", "h-r3"]]),
    intents: [
      { intentId: "i1", contextId: "ctx", intentSeq: 1, objectId: "o1", viewVersion: 3, viewFp: "fp", afterIntentId: null, change: { kind: "CONTENT", path: "a.md", content: SECRET } },
      { intentId: "i2", contextId: "ctx", intentSeq: 2, objectId: "o1", viewVersion: 3, viewFp: "fp", afterIntentId: "i1", change: { kind: "DELETE", path: "a.md", content: null } },
    ],
    intentState: {
      localVersion: new Map([["o1", 3]]),
      lastIntent: new Map([["o1", { intentId: "i0", version: 3 }]]),
      copyLinks: new Map([["ctx", { intentId: "i0", copyObjectId: "o9", version: 1 }]]),
    },
    fileStats: new Map([["a.md", { size: 3, mtime: 7, hash: "h-a", readAt: 12_000 }]]),
    otherSync: { explainedWrites: new Map([["o1", "h-r0"]]), acknowledged: new Map([["o1", "r3"]]) },
  };
}
