import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { newServer } from "@nodra/sync-core/test-support/server";
import type { ChangeMarker, LocalCompareHasher, PrepareUploadInput, Stat, SyncBackend } from "../src/ports.js";
import { type Client, newMemory, observeDisk, tick } from "../src/runner.js";
import { CLOCK_SLACK_MS, type FileStatEntry, cachedHash, displacedPairs, statEntry } from "../src/stat-cache.js";
import { devBlobCrypto, memBackend } from "./support/backend.js";
import { utf8 } from "./support/bytes.js";
import { CHANGE_MARKER_CASE, FS_CONFORMANCE_CASES } from "./support/fs-conformance.js";
import { type MemMtime, memFs } from "./support/memfs.js";
import { type Rig, rig, testHasher } from "./support/shell.js";

// The observation cache (NOTES questions 57, 146, 147): the decision rule, the stale-cache oracle with its
// broken variants, a property over edits that keep size and mtime, renames, deletes and restarts, the
// hash counts, and rule 8 before sealing (max_blob_bytes).

const COUNTER: ChangeMarker = { kind: "counter" };
const G = 2000;
const COARSE: ChangeMarker = { kind: "clock", granularityMs: G };
const MARGIN = G + CLOCK_SLACK_MS;
const NONE = new Set<string>();
const file = (size: number, mtime?: number) => (mtime === undefined ? { type: "file" as const, size } : { type: "file" as const, size, mtime });
const entry = (size: number, mtime: number, readAt: number | null, hash = "h:old"): FileStatEntry => ({ size, mtime, hash, readAt });

describe("the cache decision rule (stat-cache.ts)", () => {
  it("counter marker: equal size and marker reuse the hash; anything else hashes again", () => {
    const e = entry(3, 7, null);
    expect(cachedHash(e, file(3, 7), COUNTER, null, NONE)).toBe("h:old");
    expect(cachedHash(e, file(3, 8), COUNTER, null, NONE)).toBeNull();
    expect(cachedHash(e, file(4, 7), COUNTER, null, NONE)).toBeNull();
    expect(cachedHash(e, file(3), COUNTER, null, NONE)).toBeNull(); // the adapter gave no mtime
    expect(cachedHash(e, file(3, 7), undefined, null, NONE)).toBeNull(); // no marker at all
    expect(cachedHash(e, { type: "folder", size: 3, mtime: 7 }, COUNTER, null, NONE)).toBeNull();
    expect(cachedHash(undefined, file(3, 7), COUNTER, null, NONE)).toBeNull();
  });

  it("clock marker: only an entry older than granularity + slack at its read is trusted", () => {
    const mtime = 10_000;
    expect(cachedHash(entry(3, mtime, mtime + MARGIN), file(3, mtime), COARSE, mtime + MARGIN, NONE)).toBe("h:old");
    // Racy: read within the margin of its mtime, a later same-granule edit keeps (size, mtime).
    expect(cachedHash(entry(3, mtime, mtime + MARGIN - 1), file(3, mtime), COARSE, 99_999, NONE)).toBeNull();
    expect(cachedHash(entry(3, mtime, mtime), file(3, mtime), COARSE, 99_999, NONE)).toBeNull();
    // The wall clock went back behind the read: nothing is trusted.
    expect(cachedHash(entry(3, mtime, 50_000), file(3, mtime), COARSE, 49_999, NONE)).toBeNull();
    expect(cachedHash(entry(3, mtime, null), file(3, mtime), COARSE, 50_000, NONE)).toBeNull();
    expect(cachedHash(entry(3, mtime, 50_000), file(3, mtime), COARSE, null, NONE)).toBeNull();
  });

  it("a displaced (size, mtime) pair is never trusted: a file moved over the path would match it", () => {
    const prior = new Map([
      ["a.md", entry(2, 10_000, 20_000, "h:aa")],
      ["b.md", entry(2, 10_000, 20_000, "h:bb")],
    ]);
    // b.md was moved over a.md: a.md shows b's (size, mtime), which is also a's.
    const now = new Map([["a.md", file(2, 10_000)]]);
    const displaced = displacedPairs(prior, now);
    expect(displaced).toEqual(new Set(["2:10000"]));
    expect(cachedHash(prior.get("a.md"), now.get("a.md")!, COARSE, 30_000, displaced)).toBeNull();
    // Broken variant: without the displaced pairs the stale hash of a.md would stand for b's bytes.
    expect(cachedHash(prior.get("a.md"), now.get("a.md")!, COARSE, 30_000, NONE)).toBe("h:aa");
    // Confirmed entries displace nothing; a changed stat or a folder does.
    expect(displacedPairs(prior, new Map([["a.md", file(2, 10_000)], ["b.md", file(2, 10_000)]]))).toEqual(new Set());
    expect(displacedPairs(prior, new Map([["a.md", file(2, 10_000)], ["b.md", file(2, 12_000)]]))).toEqual(new Set(["2:10000"]));
    expect(displacedPairs(prior, new Map<string, Stat>([["a.md", file(2, 10_000)], ["b.md", { type: "folder", size: 0 }]]))).toEqual(new Set(["2:10000"]));
  });

  it("an entry is recorded only for bytes of the stat's size, with readAt for a clock marker only", () => {
    expect(statEntry(file(3, 7), utf8("abc"), "h:abc", COUNTER, 123)).toEqual({ size: 3, mtime: 7, hash: "h:abc", readAt: null });
    expect(statEntry(file(3, 7), utf8("abc"), "h:abc", COARSE, 123)).toEqual({ size: 3, mtime: 7, hash: "h:abc", readAt: 123 });
    expect(statEntry(file(3, 7), utf8("abcd"), "h:abcd", COUNTER, 123)).toBeNull(); // written between stat and read
    expect(statEntry(file(3, 7), utf8("abc"), "h:abc", COARSE, null)).toBeNull();
    expect(statEntry(file(3, 7), utf8("abc"), "h:abc", undefined, 123)).toBeNull();
    expect(statEntry(file(3), utf8("abc"), "h:abc", COUNTER, 123)).toBeNull();
  });
});

describe("the FileSystem conformance case for a counter marker", () => {
  const markerCase = FS_CONFORMANCE_CASES.find((c) => c.name === CHANGE_MARKER_CASE)!;

  it("memfs passes it", async () => {
    await markerCase.run(memFs().fs);
  });

  it("broken variant: a per-file counter that starts again after a remove fails it", async () => {
    const m = memFs();
    const writes = new Map<string, number>();
    const fs = {
      ...m.fs,
      write: async (p: string, d: Uint8Array) => {
        await m.fs.write(p, d);
        writes.set(p, (writes.get(p) ?? 0) + 1);
      },
      remove: async (p: string) => {
        await m.fs.remove(p);
        writes.delete(p);
      },
      stat: async (p: string) => {
        const st = await m.fs.stat(p);
        return st === null ? null : { ...st, mtime: writes.get(p) ?? 0 };
      },
    };
    await expect(markerCase.run(fs)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Through the runner's observation.

const NO_BACKEND = {} as SyncBackend;

interface Counted {
  readonly hasher: LocalCompareHasher;
  count: number;
}
const counting = (): Counted => {
  const c: Counted = {
    count: 0,
    hasher: {
      hash: async (plaintext) => {
        c.count++;
        return testHasher.hash(plaintext);
      },
    },
  };
  return c;
};

const clientOf = (r: Rig, h: Counted, wall: () => number, backend = NO_BACKEND, extra: Partial<Client> = {}): Client => {
  r.shell = { ...r.shell, hasher: h.hasher };
  return { shell: r.shell, backend, blobs: devBlobCrypto(), now: () => 0, wallClock: wall, pendingBudgetBytes: 20000, memory: newMemory(), ...extra };
};

/** The hash the last observation recorded for the file at `path`. */
const observedAt = (r: Rig, path: string): string | null | undefined => {
  for (const o of r.shell.state.observations.values()) if (o.kind === "PRESENT" && o.physicalPath === path) return o.hash;
  return undefined;
};

/** A coarse disk that lies: its clock mtime declared a counter (the naive (size, mtime) cache). */
const lying = (r: Rig) => {
  (r.disk.fs as { changeMarker?: ChangeMarker }).changeMarker = COUNTER;
};

describe("a stale cache never hides a user edit (coarse mtime)", () => {
  const coarse = (clock: () => number): MemMtime => ({ granularityMs: G, clock });

  async function sameGranuleEdit(naive: boolean) {
    let now = 30_000;
    const r = await rig(undefined, coarse(() => now));
    if (naive) lying(r);
    const h = counting();
    const c = clientOf(r, h, () => now);
    r.disk.userWrite("a.md", "two");
    await observeDisk(c);
    expect(observedAt(r, "a.md")).toBe("h:two");
    const before = await r.disk.fs.stat("a.md");
    now = 31_000; // the same 2 s granule
    r.disk.files.get("a.md")!.content = "six";
    expect(await r.disk.fs.stat("a.md")).toEqual(before); // same size, same mtime: only the bytes differ
    await observeDisk(c);
    return observedAt(r, "a.md");
  }

  it("an edit within the mtime granule of the last hash is seen (the entry was racy)", async () => {
    expect(await sameGranuleEdit(false)).toBe("h:six");
  });

  it("broken variant: a naive (size, mtime) cache loses that edit", async () => {
    expect(await sameGranuleEdit(true)).toBe("h:two");
  });

  it("an old file is hashed once, then trusted across observations and a restart", async () => {
    let now = 10_000;
    const r = await rig(undefined, coarse(() => now));
    r.disk.userWrite("a.md", "one");
    now = 20_000;
    const h = counting();
    let c = clientOf(r, h, () => now);
    await observeDisk(c);
    await observeDisk(c);
    expect(h.count).toBe(1);
    await r.restart();
    c = clientOf(r, h, () => now);
    await observeDisk(c);
    expect(h.count).toBe(1);
    expect(observedAt(r, "a.md")).toBe("h:one");
  });

  it("a file moved over another with the same (size, mtime) while no instance ran is hashed again", async () => {
    let now = 10_000;
    const r = await rig(undefined, coarse(() => now));
    r.disk.userWrite("a.md", "aa");
    r.disk.userWrite("b.md", "bb");
    now = 20_000;
    await observeDisk(clientOf(r, counting(), () => now));
    await r.restart();
    const b = r.disk.files.get("b.md")!;
    r.disk.files.delete("b.md");
    r.disk.files.set("a.md", b);
    await observeDisk(clientOf(r, counting(), () => now));
    expect(observedAt(r, "a.md")).toBe("h:bb");
  });
});

// ---------------------------------------------------------------------------
// Property: edits keeping size and mtime, renames (onto free or taken paths), deletes and restarts; after
// every observation, every file on disk is observed with the hash of its bytes.

const PATHS = ["a.md", "b.md", "c.md"] as const;
const CONTENTS = ["aa", "ab", "ba", "bb", "a", "abc"] as const;
type Op =
  | { readonly k: "write"; readonly path: string; readonly content: string }
  | { readonly k: "advance"; readonly ms: number }
  | { readonly k: "move"; readonly from: string; readonly to: string }
  | { readonly k: "delete"; readonly path: string }
  | { readonly k: "restart" }
  | { readonly k: "observe" };
const pathArb = fc.constantFrom(...PATHS);
const opArb: fc.Arbitrary<Op> = fc.oneof(
  { weight: 4, arbitrary: fc.record({ k: fc.constant("write" as const), path: pathArb, content: fc.constantFrom(...CONTENTS) }) },
  { weight: 3, arbitrary: fc.record({ k: fc.constant("advance" as const), ms: fc.constantFrom(0, 400, 1000, 2000, 5000) }) },
  { weight: 2, arbitrary: fc.record({ k: fc.constant("move" as const), from: pathArb, to: pathArb }) },
  { weight: 1, arbitrary: fc.record({ k: fc.constant("delete" as const), path: pathArb }) },
  { weight: 1, arbitrary: fc.constant({ k: "restart" as const }) },
  { weight: 4, arbitrary: fc.constant({ k: "observe" as const }) },
);
const modeArb = fc.constantFrom("counter" as const, "coarse" as const);

async function misses(mode: "counter" | "coarse", ops: readonly Op[], naive: boolean): Promise<string[]> {
  let now = 1_000_000;
  const r = await rig(undefined, mode === "counter" ? "counter" : { granularityMs: G, clock: () => now });
  if (naive) lying(r);
  let c = clientOf(r, counting(), () => now);
  const out: string[] = [];
  const check = async (i: number) => {
    await observeDisk(c);
    for (const [path, f] of r.disk.files) {
      if (observedAt(r, path) !== `h:${f.content}`) out.push(`op ${i}: ${path} holds ${f.content}, observed ${observedAt(r, path)}`);
    }
  };
  for (const [i, op] of ops.entries()) {
    switch (op.k) {
      case "write":
        r.disk.userWrite(op.path, op.content);
        break;
      case "advance":
        now += op.ms;
        break;
      case "move": {
        const f = r.disk.files.get(op.from);
        if (f === undefined || op.from === op.to) break;
        r.disk.files.delete(op.from);
        r.disk.files.set(op.to, f); // over a taken path too: size and mtime move with the file
        break;
      }
      case "delete":
        r.disk.files.delete(op.path);
        break;
      case "restart":
        await r.restart();
        c = clientOf(r, counting(), () => now);
        break;
      case "observe":
        await check(i);
        break;
    }
  }
  await check(ops.length);
  return out;
}

describe("property: the observation cache never misses an edit", () => {
  const property = (naive: boolean) =>
    fc.asyncProperty(modeArb, fc.array(opArb, { maxLength: 40 }), async (mode, ops) => {
      expect(await misses(mode, ops, naive)).toEqual([]);
    });

  it("holds on exact and coarse markers, with renames over taken paths, deletes and restarts", async () => {
    await fc.assert(property(false), { numRuns: 150 });
  }, 120_000);

  it("broken variant: the naive (size, mtime) cache fails it", async () => {
    await expect(fc.assert(property(true), { numRuns: 300, seed: 20260922 })).rejects.toThrow();
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Counts, not timings (question 147).

async function syncedRig(mtime: MemMtime, n: number, afterWrite = () => {}) {
  const server = newServer({ pendingBudgetBytes: 1_000_000, maxBlobBytes: 5000, uploadWindow: 40 });
  const r = await rig(undefined, mtime);
  for (let i = 0; i < n; i++) {
    r.disk.userWrite(`n${String(i).padStart(2, "0")}.md`, `note ${i % 10}`);
    afterWrite();
  }
  const net = memBackend(server, "replica-1", devBlobCrypto(), () => 0.99, async () => new Set(), () => {
    throw new Error("no crash here");
  });
  return { server, r, net };
}

/** Ticks until rest; the hashes of each tick. */
async function ticksToRest(c: Client, h: Counted, server: { now: number }, wall?: { now: number }): Promise<number[]> {
  const perTick: number[] = [];
  for (let i = 0; i < 2000; i++) {
    const before = h.count;
    const busy = await tick(c);
    perTick.push(h.count - before);
    server.now++;
    if (wall) wall.now += 1000;
    if (!busy) return perTick;
  }
  throw new Error("no rest");
}

describe("hash counts", () => {
  it("N files, one edited: after warm-up exactly one hash in the tick that sees it, none otherwise", async () => {
    const { server, r, net } = await syncedRig("counter", 20);
    const h = counting();
    const c = clientOf(r, h, () => 0, net.backend, { now: () => server.now });
    await ticksToRest(c, h, server);
    expect(server.heads.size).toBe(20);
    expect(await ticksToRest(c, h, server)).toEqual([0]); // warm: an idle tick hashes nothing
    r.disk.files.get("n07.md")!.content = "note X"; // same size
    const perTick = await ticksToRest(c, h, server);
    expect(perTick[0]).toBe(1); // observed once; the upload compares the bytes it kept (no second hash)
    expect(perTick.slice(1).every((n) => n === 0)).toBe(true);
    expect([...server.heads.values()].some((v) => v.content === "note X")).toBe(true);
  }, 60_000);

  it("clock marker: an edited file is hashed again only until it is older than granularity + slack", async () => {
    const wall = { now: 1_000_000 };
    // One granule apart: files sharing (size, mtime) with an edited one are hashed once more (displaced pairs).
    const { server, r, net } = await syncedRig({ granularityMs: G, clock: () => wall.now }, 20, () => (wall.now += G));
    const h = counting();
    const c = clientOf(r, h, () => wall.now, net.backend, { now: () => server.now });
    await ticksToRest(c, h, server, wall);
    wall.now += 10_000;
    await ticksToRest(c, h, server, wall);
    expect(await ticksToRest(c, h, server, wall)).toEqual([0]);
    r.disk.files.get("n03.md")!.content = "note Y";
    const hashes: number[] = [];
    for (let i = 0; i < 8; i++) {
      const before = h.count;
      await tick(c);
      hashes.push(h.count - before);
      server.now++;
      wall.now += 1000;
    }
    // Racy while younger than G + slack (the first observation at +0 s, then +1, +2, +3 s), hashed once per tick; then trusted.
    expect(hashes).toEqual([1, 1, 1, 1, 0, 0, 0, 0]);
    expect([...server.heads.values()].some((v) => v.content === "note Y")).toBe(true);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// Rule 8 before sealing: max_blob_bytes (§11.2) limits the file, not its sealed blob (§40, control-plane
// NOTES question 381): a file of exactly max_blob_bytes syncs, one byte more is blocked.

describe("files over max_blob_bytes", () => {
  it("are blocked (BLOB_TOO_LARGE, surfaced in the log) without a seal or a prepare; the rest of the vault syncs", async () => {
    const server = newServer({ pendingBudgetBytes: 1_000_000, maxBlobBytes: 5000, uploadWindow: 40 });
    const r = await rig();
    r.disk.userWrite("big.md", "x".repeat(6000)); // plaintext well over the limit
    r.disk.userWrite("edge.md", "y".repeat(5001)); // one byte over it
    r.disk.userWrite("exact.md", "z".repeat(5000)); // exactly the limit: its blob is larger, and it syncs
    r.disk.userWrite("small.md", "fine");
    const net = memBackend(server, "replica-1", devBlobCrypto(), () => 0.99, async () => new Set(), () => {
      throw new Error("no crash here");
    });
    const prepares: PrepareUploadInput[] = [];
    const backend = net.backend as { prepareUpload: SyncBackend["prepareUpload"] };
    const prepare = backend.prepareUpload.bind(backend);
    backend.prepareUpload = async (input) => {
      prepares.push(input);
      return prepare(input);
    };
    const blobs = devBlobCrypto();
    const sealed: number[] = [];
    const encrypt = blobs.encryptBlob.bind(blobs);
    blobs.encryptBlob = async (input) => {
      sealed.push(input.payload.length);
      return encrypt(input);
    };
    const events: string[] = [];
    const h = counting();
    const c = clientOf(r, h, () => 0, net.backend, { now: () => server.now, blobs, maxBlobBytes: 5000, log: (e) => (e.kind === "blocked" ? events.push(e.detail ?? "") : undefined) });
    await ticksToRest(c, h, server);
    expect([...server.heads.values()].map((v) => v.path).sort()).toEqual(["exact.md", "small.md"]);
    expect(prepares.filter((p) => p.kind === "CONTENT").every((p) => p.declaredSize <= 5000 + 28)).toBe(true);
    expect(sealed.every((n) => n <= 5000)).toBe(true);
    expect(events.sort()).toEqual(["BLOB_TOO_LARGE big.md", "BLOB_TOO_LARGE edge.md"]);
    expect(r.shell.state.facts.blocked.map((b) => b.reason)).toEqual(["BLOB_TOO_LARGE", "BLOB_TOO_LARGE"]);
    // Rule 8: changing the content lifts the block.
    r.disk.files.get("big.md")!.content = "now small";
    await ticksToRest(c, h, server);
    expect([...server.heads.values()].map((v) => v.path).sort()).toEqual(["big.md", "exact.md", "small.md"]);
  });
});
