import { type ProjectionObject, physicalToLogical, planRenames, project } from "@nodra/path-projection";
import { type Decision, decideObject, hasLocalChange } from "./decide.js";
import type { Action, LocalEntry, ObjectId, PlanInput } from "./types.js";

// Planner (§12.2). Pure, deterministic, whole-tree. The client runs only the first action
// and re-plans. Per-object logical decisions come from decide.ts; this module adds the
// whole-tree parts: rule 12 (physical → logical), rule 7 (projection, §16.3) and the
// physical plan (§16.7), then orders everything by a fixed priority (NOTES.md).
//
// Deferred:
// TODO(§12.2 rules 10-11): rename pairing after restart (ABSENT object + untracked file).
// TODO(§12.1): batching of uploads into mutations by size / time budget.
// TODO(§12.2 rule 13, §12.6): upload attempts, pending_upload_cleanup, retry policy.
// Physical actions and writes run through the apply journal (journal.ts, §15) in the executor.
// TODO(§15, §16.3): importing untracked files (recovery notes, new user files) as objects.

type Present = Extract<LocalEntry, { kind: "PRESENT" }>;

const byId = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** Priority of the first action (see NOTES.md, "Action priority"). Lower runs first. */
const RANK: Record<Action["kind"], number> = {
  fetchContent: 0,
  advanceSynced: 1,
  forgetUnconfirmedCreate: 1,
  markNotMaterialized: 1,
  conflictCopy: 2,
  resolve: 2,
  discardLocalRename: 2,
  upload: 3,
  movePhysical: 4, // physical plan: its own order (frees paths before creates)
  removePhysical: 4,
  applyRemote: 5, // in place; materializations are part of the physical plan (rank 4)
};

export interface ResolvedLocal {
  readonly local: ReadonlyMap<ObjectId, LocalEntry>;
  /** Moved files whose new physical path cannot be turned into a logical path: left untouched. */
  readonly unrepresentable: ReadonlySet<ObjectId>;
}

/**
 * Rule 12 / §16.4: a PRESENT file that moved (observed physical ≠ recorded physical) takes its
 * logical path from the physical → logical rule, against the folder table of the current
 * projection. A file that did not move keeps its recorded logical path.
 */
export function resolveLocalPaths(input: PlanInput): ReadonlyMap<ObjectId, LocalEntry> {
  return resolveLocal(input).local;
}

/** resolveLocalPaths plus the moved files whose logical path is not representable (frozen by plan). */
export function resolveLocal(input: PlanInput): ResolvedLocal {
  const { folders } = project({ objects: viewObjects(input, new Map()), untrackedFiles: input.untrackedFiles });
  const local = new Map(input.local);
  const unrepresentable = new Set<ObjectId>();
  for (const [id, l] of input.local) {
    if (l.kind !== "PRESENT" || l.physicalPath === l.recordedPhysicalPath) continue;
    const r = physicalToLogical(
      {
        objectId: id,
        currentLogicalPath: l.path,
        currentPhysicalPath: l.recordedPhysicalPath,
        newPhysicalPath: l.physicalPath,
      },
      folders,
    );
    if (r.ok) local.set(id, { ...l, path: r.path });
    else unrepresentable.add(id);
  }
  return { local, unrepresentable };
}

/**
 * Local view projected by §16.3: L's path while the file carries a pending local state
 * (including in-flight entries), R's once the decision is to apply R, and R's (or S's) for
 * objects that are not on disk. Deleted or absent objects are not projected.
 */
function viewObjects(input: PlanInput, decisions: ReadonlyMap<ObjectId, Decision>): ProjectionObject[] {
  const ids = new Set([...input.local.keys(), ...input.remote.keys(), ...input.synced.keys()]);
  const out: ProjectionObject[] = [];
  for (const id of ids) {
    const s = input.synced.get(id);
    const r = input.remote.get(id) ?? s;
    const l = input.local.get(id);
    const applying = decisions.get(id)?.kind === "applyRemote";
    const remotePath = r !== undefined && !r.deleted ? r.path : null;
    const path =
      l?.kind === "PRESENT"
        ? applying
          ? remotePath
          : l.path
        : l?.kind === "ABSENT"
          ? applying
            ? remotePath
            : null
          : remotePath;
    if (path !== null) out.push({ objectId: id, logicalPath: path, createdSequence: r?.createdSequence ?? null });
  }
  return out;
}

/** Plans every object of the tree. */
export function plan(input: PlanInput): Action[] {
  const inFlight = new Set<ObjectId>();
  for (const entry of input.outbox) for (const o of entry.objects) inFlight.add(o.objectId);

  const { local, unrepresentable } = resolveLocal(input);
  const effective: PlanInput = { ...input, local };
  const ids = [...new Set([...local.keys(), ...input.remote.keys(), ...input.synced.keys()])].sort(byId);

  // Per-object logical decisions. Rule 9: an in-flight object receives no action at all.
  const decisions = new Map<ObjectId, Decision>();
  for (const id of ids) {
    if (inFlight.has(id)) continue;
    const d = decideObject(id, effective);
    if (d) decisions.set(id, d);
  }

  // Rule 7 / §16.3: project the desired local view of all objects at once.
  const projection = project({ objects: viewObjects(effective, decisions), untrackedFiles: input.untrackedFiles });

  // §16.7: physical plan from the current disk to the projection.
  const current = new Map<ObjectId, string>();
  const desired = new Map<ObjectId, string | null>();
  const materialize = new Map<ObjectId, string>(); // object → revision to write
  for (const id of ids) {
    const l = local.get(id);
    const projected = projection.files.get(id);
    const d = decisions.get(id);
    if (l?.kind === "PRESENT") {
      current.set(id, l.physicalPath);
      if (projected) desired.set(id, projected.notMaterialized === null ? projected.physicalPath : null);
    } else if (d?.kind === "applyRemote" && projected && projected.notMaterialized === null) {
      desired.set(id, projected.physicalPath);
      materialize.set(id, d.revisionId);
    }
  }
  const frozen = new Set([...inFlight, ...unrepresentable]);
  const pending = new Set([...frozen, ...ids.filter((id) => hasLocalChange(local.get(id), input.synced.get(id)))]);
  const physical = planRenames({
    current,
    desired,
    untrackedFiles: input.untrackedFiles,
    inFlight: frozen,
    pending,
    tmpHex: input.tmpHex,
  });

  const logical: Action[] = [];
  for (const [id, d] of decisions) {
    if (d.kind !== "applyRemote") {
      logical.push(d);
      continue;
    }
    const l = local.get(id);
    if (l?.kind === "PRESENT") {
      logical.push({ ...d, physicalPath: (l as Present).physicalPath });
    } else if (!materialize.has(id)) {
      // Projected path not materializable (§16.2): the object is marked NOT_MATERIALIZED with
      // S := R. Never written, never deleted; an ABSENT object stops reading as a local delete (5c).
      // (Objects whose projected path is only occupied for now are in `materialize` and wait.)
      const s = input.synced.get(id);
      if (l?.kind !== "NOT_MATERIALIZED") logical.push({ kind: "markNotMaterialized", objectId: id, revisionId: d.revisionId });
      else if (s?.revisionId !== d.revisionId) logical.push({ kind: "advanceSynced", objectId: id, revisionId: d.revisionId });
    }
  }
  const physicalActions: Action[] = physical.actions.map((a) =>
    a.kind === "rename"
      ? { kind: "movePhysical", objectId: a.objectId, from: a.from, to: a.to }
      : a.kind === "remove"
        ? { kind: "removePhysical", objectId: a.objectId, from: a.from }
        : { kind: "applyRemote", objectId: a.objectId, revisionId: materialize.get(a.objectId)!, physicalPath: a.to },
  );

  // Stable by rank: logical actions are already in object-id order; the physical plan keeps its order.
  const ranked = [...logical.map((a) => [RANK[a.kind], a] as const), ...physicalActions.map((a) => [4, a] as const)];
  return ranked
    .map(([rank, a], i) => ({ rank, a, i }))
    .sort((x, y) => x.rank - y.rank || x.i - y.i)
    .map(({ a }) => a);
}
