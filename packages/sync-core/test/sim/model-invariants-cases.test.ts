import { describe, expect, it } from "vitest";
import { attachBlobs, modelInvariants, newServer, preSwitchBlobs, remoteCommit, reencrypt, switchToPrivate } from "./server.js";

// Every check of `modelInvariants` and `preSwitchBlobs` (the oracles of the §35.13 fault runs) fires on
// a model corrupted in exactly its way, and none fires on an honest one.

function world() {
  const s = newServer({ pendingBudgetBytes: 20000, maxBlobBytes: 5000, uploadWindow: 40 });
  remoteCommit(s, "a", { path: "a.md", content: "alpha", deleted: false });
  remoteCommit(s, "a", { path: "b.md", content: "alpha", deleted: false }); // shares the content blob
  remoteCommit(s, "c", { path: "c.md", content: "gamma", deleted: false });
  attachBlobs(s);
  const ledger = new Map<string, string>();
  expect(modelInvariants(s, ledger)).toEqual([]);
  return { s, ledger, a1: s.revisions.get("a@1")!, c: s.heads.get("c")! };
}

describe("the model's §44.5 oracles detect their violation", () => {
  it("references: a revision pointing to a DELETING blob", () => {
    const { s, ledger, c } = world();
    s.blobs.get(c.contentBlobId!)!.state = "DELETING";
    expect(modelInvariants(s, ledger).some((v) => v.startsWith("references:"))).toBe(true);
  });

  it("refcount: a count that is not the number of unpruned references", () => {
    const { s, ledger, a1 } = world();
    s.blobs.get(a1.contentBlobId!)!.refcount = 1; // two revisions share it
    expect(modelInvariants(s, ledger).some((v) => v.startsWith("refcount:"))).toBe(true);
  });

  it("immutable: a CONFIRMED blob whose bytes change", () => {
    const { s, ledger, c } = world();
    s.blobs.get(c.contentBlobId!)!.payload = `${c.contentBlobId}|rewritten`;
    expect(modelInvariants(s, ledger).some((v) => v.startsWith("immutable:"))).toBe(true);
  });

  it("plaintext and path: a revision whose blobs carry another content, or another path", () => {
    const { s, ledger, a1, c } = world();
    s.revisions.set(a1.revisionId, { ...a1, contentBlobId: c.contentBlobId! });
    s.blobs.get(c.contentBlobId!)!.refcount++;
    s.blobs.get(a1.contentBlobId!)!.refcount--;
    const found = modelInvariants(s, ledger);
    expect(found.some((v) => v.startsWith("plaintext:"))).toBe(true);
    s.revisions.set(a1.revisionId, { ...a1, path: "elsewhere.md" });
    expect(modelInvariants(s, new Map()).some((v) => v.startsWith("path:"))).toBe(true);
  });

  it("preSwitchBlobs: an old blob still stored after the switch, and nothing once every one is swapped and collected", () => {
    const { s } = world();
    switchToPrivate(s);
    expect(preSwitchBlobs(s).length).toBeGreaterThan(0);
    for (const r of [...s.revisions.values()]) {
      const m = `new-m-${r.revisionId}`;
      const content = r.contentBlobId === "rb-a@1-c" && s.blobs.has("new-c-a") ? "new-c-a" : `new-c-${r.revisionId}`;
      for (const [id, kind] of [
        [m, "MANIFEST"],
        [content, "CONTENT"],
      ] as const) {
        if (s.blobs.has(id)) continue;
        s.blobs.set(id, { blobId: id, owner: "me", epochId: s.epoch, kind, declaredSize: 1, sha: id, forDelete: false, forReencrypt: r.revisionId, state: "PENDING", refcount: 0, stateChangedAt: s.now, payload: `${id}|${kind === "MANIFEST" ? JSON.stringify({ path: r.path }) : r.content}`, expiresAt: s.now + 40 });
      }
      expect(reencrypt(s, "me", { revisionId: r.revisionId, expectedManifestBlobId: r.manifestBlobId!, newManifestBlobId: m, newContentBlobId: content })).toEqual({ ok: true });
    }
    for (const b of s.blobs.values()) if (b.state === "DELETING") b.state = "DELETED";
    expect(preSwitchBlobs(s)).toEqual([]);
    expect(modelInvariants(s, new Map())).toEqual([]);
  });
});
