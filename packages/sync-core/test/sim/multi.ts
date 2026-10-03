// Several replicas sharing one server (§44.5 multi-replica simulation). Each replica has its own
// disk, persisted facts, crashes and faults; a seeded scheduler interleaves them in rounds.

import fc from "fast-check";
import { DEFAULT_SERVER, type Scenario, build, scenarioArb } from "./scenario.js";
import type { Server, ServerConfig } from "./server.js";
import { type Faults, type Variant, type World, hash, restingProjection, tick } from "./simulator.js";

export interface Cluster {
  readonly server: Server;
  readonly replicas: World[];
  rng: number;
  rounds: number;
}

const replicaOverrideArb = (objects: number) =>
  fc.record({
    perObject: fc.array(
      fc.record({
        replica: fc.constantFrom("unseen", "rev1", "head", "head"),
        mod: fc.constantFrom("none", "none", "edit", "move", "delete"),
        editContent: fc.constantFrom("", "a", "one line"),
      }),
      { minLength: objects, maxLength: objects },
    ),
    localCreate: fc.option(fc.constantFrom("n.md", "N.md", "new.md", "d/1.md", "foo"), { nil: null }),
  });

/** A shared server history (from a base scenario) and 2-4 replicas with their own local state. */
export const clusterArb = scenarioArb.chain((base) =>
  fc.record({
    base: fc.constant(base),
    replicas: fc.array(replicaOverrideArb(base.objects.length), { minLength: 2, maxLength: 4 }),
    seed: fc.integer(),
  }),
);
export type ClusterSpec = typeof clusterArb extends fc.Arbitrary<infer T> ? T : never;

function replicaScenario(spec: ClusterSpec, i: number): Scenario {
  const o = spec.replicas[i]!;
  return {
    ...spec.base,
    objects: spec.base.objects.map((obj, k) => ({ ...obj, ...o.perObject[k]! })),
    localCreates: o.localCreate ? [{ path: o.localCreate, content: `created offline by replica ${i}` }] : [],
    untracked: i === 0 ? spec.base.untracked : [],
  };
}

export function buildCluster(spec: ClusterSpec, faults: Faults, server: ServerConfig = DEFAULT_SERVER): Cluster {
  const first = build(replicaScenario(spec, 0), faults, spec.seed, server);
  const replicas = [first.world];
  for (let i = 1; i < spec.replicas.length; i++) {
    replicas.push(build(replicaScenario(spec, i), faults, spec.seed + i * 7919, server, { server: first.world.server, index: i }).world);
  }
  return { server: first.world.server, replicas, rng: spec.seed, rounds: 0 };
}

function random(c: Cluster): number {
  c.rng = (Math.imul(c.rng, 1103515245) + 12345) | 0;
  return ((c.rng >>> 8) & 0xffffff) / 0x1000000;
}

/**
 * Runs rounds (each replica ticks once, in a seeded random order) until a whole round is idle, or
 * `maxRounds`. `onStep` sees the cluster after every tick; returning true stops. Returns the rounds, or null.
 */
export function runCluster(c: Cluster, variant: Variant, maxRounds: number, onStep?: (c: Cluster, w: World) => boolean | void): number | null {
  for (; c.rounds < maxRounds; c.rounds++) {
    const order = c.replicas.map((_, i) => i);
    for (let i = order.length - 1; i > 0; i--) {
      const j = Math.floor(random(c) * (i + 1));
      [order[i], order[j]] = [order[j]!, order[i]!];
    }
    let busy = false;
    for (const i of order) {
      const w = c.replicas[i]!;
      if (tick(w, variant)) busy = true;
      if (onStep?.(c, w) === true) return null;
    }
    if (!busy) return c.rounds;
  }
  return null;
}

const blockedHere = (w: World, id: string) => {
  const p = w.bound.get(id);
  return p !== undefined && w.facts.blocked.some((b) => b.objectId === id && b.localCompareHash === hash(w.files.get(p)!.content));
};

/**
 * Property (m) at rest: every replica has L = R = S for every object, with the same heads, and the
 * same content for every object materialized on two replicas; each disk matches its projection.
 * Returns the violations (empty when the cluster converged).
 */
export function restingViolations(c: Cluster): string[] {
  const out: string[] = [];
  const contents = new Map<string, string>();
  for (const w of c.replicas) {
    if (w.facts.outbox.length > 0) out.push(`${w.replica} outbox not empty`);
    if (w.facts.cleanup.length > 0) out.push(`${w.replica} cleanup not empty`);
    if (w.journal !== null) out.push(`${w.replica} journal open`);
    const projection = restingProjection(w);
    for (const [id, head] of c.server.heads) {
      if (blockedHere(w, id)) continue;
      if (w.facts.synced.get(id)?.revisionId !== head.revisionId) out.push(`${w.replica} S ${id}`);
      if ((w.facts.remote.get(id) ?? w.facts.synced.get(id))?.revisionId !== head.revisionId) out.push(`${w.replica} R ${id}`);
      const p = w.bound.get(id);
      const projected = projection.files.get(id);
      if (head.deleted || !projected || projected.notMaterialized !== null) {
        if (p !== undefined) out.push(`${w.replica} ${id} should not be on disk`);
        continue;
      }
      if (p !== projected.physicalPath) {
        out.push(`${w.replica} ${id} at ${p}, not at its projected path ${projected.physicalPath}`);
        continue;
      }
      const content = w.files.get(p)!.content;
      if (content !== head.content) out.push(`${w.replica} ${id} content is not the head's`);
      const other = contents.get(id);
      if (other !== undefined && content !== other) out.push(`${id} differs between replicas`);
      contents.set(id, content);
    }
    // Rule 8: while L carries a blocked content no upload is planned, so a new object whose content is
    // blocked rests unconfirmed, like a blocked edit of a confirmed object above.
    for (const id of w.bound.keys()) if (!c.server.heads.has(id) && !blockedHere(w, id)) out.push(`${w.replica} ${id} never confirmed`);
  }
  return out;
}
