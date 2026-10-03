import { type KeyFn, type ObjectId, comparisonKey } from "./paths.js";

// §16.7 physical application of the projection. Pure: the whole ordered sequence is derived;
// the client executes only the first action (through the journal, §15) and re-plans.

export interface RenamePlanInput {
  /** Observed physical path of every bound object on disk. */
  readonly current: ReadonlyMap<ObjectId, string>;
  /** Projected physical path; null when the object is NOT_MATERIALIZED (§16.2). */
  readonly desired: ReadonlyMap<ObjectId, string | null>;
  /** Untracked files on disk: never moved, never overwritten. */
  readonly untrackedFiles: readonly string[];
  /** Objects with an outbox entry: no physical action at all (§16.7 rule 5). */
  readonly inFlight: ReadonlySet<ObjectId>;
  /** Objects with anything pending (L ≠ S): a NOT_MATERIALIZED one keeps its file (§16.2). */
  readonly pending: ReadonlySet<ObjectId>;
  /** Candidate 8-hex names for parking (randomness is an input). Used in order. */
  readonly tmpHex: readonly string[];
}

export type PhysicalAction =
  | { readonly kind: "rename"; readonly objectId: ObjectId; readonly from: string; readonly to: string }
  /** Write the object's content at `to` (materialization). */
  | { readonly kind: "create"; readonly objectId: ObjectId; readonly to: string }
  /** NOT_MATERIALIZED with nothing pending: its (confirmed) file leaves the disk. */
  | { readonly kind: "remove"; readonly objectId: ObjectId; readonly from: string };

export interface RenamePlan {
  readonly actions: readonly PhysicalAction[];
  /** Objects that cannot reach their projected path now (occupied by an untracked or immovable file). */
  readonly blocked: readonly ObjectId[];
}

const dirOf = (p: string) => p.slice(0, p.lastIndexOf("/") + 1);
const nameOf = (p: string) => p.slice(p.lastIndexOf("/") + 1);
const byId = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

// TODO(§16.3 "Estabilidad", §15): a change of a folder's physical spelling must be applied as a
// single folder rename; v1 emits one rename per file.
export function planRenames(input: RenamePlanInput, key: KeyFn = comparisonKey): RenamePlan {
  // Disk model: owner of each file (object id, or null for untracked).
  const disk = new Map<string, { path: string; owner: ObjectId | null }>();
  for (const p of input.untrackedFiles) disk.set(key(p), { path: p, owner: null });
  for (const [id, p] of input.current) disk.set(key(p), { path: p, owner: id });

  /** Files that make `target` unusable for `self`: same key, inside it, or one of its ancestors. */
  const blockers = (target: string, self: ObjectId) => {
    const k = key(target);
    const out: Array<ObjectId | null> = [];
    for (const [fk, f] of disk) {
      if (f.owner === self) continue;
      if (fk === k || fk.startsWith(`${k}/`) || k.startsWith(`${fk}/`)) out.push(f.owner);
    }
    return out;
  };

  /** A file that is an ancestor of its own target, or that lies inside the folder its target names. */
  const selfBlocked = (from: string, to: string) => {
    const fk = key(from);
    const tk = key(to);
    return tk.startsWith(`${fk}/`) || fk.startsWith(`${tk}/`);
  };

  const actions: PhysicalAction[] = [];
  const at = new Map(input.current);
  const move = (id: ObjectId, from: string | undefined, to: string) => {
    if (from !== undefined) disk.delete(key(from));
    disk.set(key(to), { path: to, owner: id });
    at.set(id, to);
  };

  const ids = [...new Set([...input.current.keys(), ...input.desired.keys()])].sort(byId);
  for (const id of ids) {
    const from = input.current.get(id);
    if (input.inFlight.has(id) || from === undefined) continue;
    if (input.desired.get(id) === null && !input.pending.has(id)) {
      actions.push({ kind: "remove", objectId: id, from });
      disk.delete(key(from));
      at.delete(id);
    }
  }

  const todo = () =>
    ids.filter((id) => {
      const to = input.desired.get(id);
      return !input.inFlight.has(id) && typeof to === "string" && at.get(id) !== to;
    });

  const usedTmp = new Set<string>();
  const nextTmp = (dir: string): string | null => {
    const names = new Set([...disk.values()].map((f) => key(nameOf(f.path))));
    for (const hex of input.tmpHex) {
      const name = `nodra-tmp-${hex}`;
      // Exclusive in the whole vault (§15), never reused within a plan.
      if (!usedTmp.has(name) && !names.has(key(name))) {
        usedTmp.add(name);
        return dir + name;
      }
    }
    return null;
  };

  for (;;) {
    const pendingMoves = todo();
    if (pendingMoves.length === 0) break;
    let progress = false;
    for (const id of pendingMoves) {
      const to = input.desired.get(id) as string;
      if (blockers(to, id).length > 0) continue;
      const from = at.get(id);
      if (from !== undefined && selfBlocked(from, to)) {
        // Q74/Q75: the file blocks its own target (`g` → `g/f.md`, or `Foo/y.md` → `foo`), so no single
        // rename can do it. Park it outside both (the target's folder when leaving the source's folder),
        // then move it on; the emptied folder is cleared by the executor when the target is written.
        const tmp = nextTmp(key(from).startsWith(`${key(to)}/`) ? dirOf(to) : dirOf(from));
        if (tmp === null) continue;
        actions.push({ kind: "rename", objectId: id, from, to: tmp });
        move(id, from, tmp);
        progress = true;
        continue;
      }
      actions.push(from === undefined ? { kind: "create", objectId: id, to } : { kind: "rename", objectId: id, from, to });
      move(id, from, to);
      progress = true;
    }
    if (progress) continue;

    // Stuck: break a cycle of renames by parking one member (§16.7 rule 3).
    const cycleMember = findCycle(pendingMoves, (id) => blockers(input.desired.get(id) as string, id), at);
    if (cycleMember === null) break;
    const from = at.get(cycleMember)!;
    // Parking in the same folder frees the file's path, but not its folder: when another move of the
    // cycle is blocked by that folder (a file target such as "foo" vs the folder "Foo/"), park at the root.
    const fromKey = key(from);
    const folderBlocks = pendingMoves.some((id) => {
      const target = input.desired.get(id);
      return typeof target === "string" && fromKey.startsWith(`${key(target)}/`);
    });
    const tmp = nextTmp(folderBlocks ? "" : dirOf(from));
    if (tmp === null) break;
    actions.push({ kind: "rename", objectId: cycleMember, from, to: tmp });
    move(cycleMember, from, tmp);
  }

  return { actions, blocked: todo() };
}

/**
 * Returns the smallest object id on a cycle of renames blocked only by each other, or null.
 * A move depends on the moves of the objects occupying its target; an untracked or
 * non-moving blocker makes it a dead end.
 */
function findCycle(
  moves: readonly ObjectId[],
  blockersOf: (id: ObjectId) => Array<ObjectId | null>,
  at: ReadonlyMap<ObjectId, string>,
): ObjectId | null {
  const moving = new Set(moves.filter((id) => at.has(id)));
  const edges = new Map<ObjectId, ObjectId[] | null>();
  for (const id of moving) {
    const bs = blockersOf(id);
    edges.set(id, bs.every((b): b is ObjectId => b !== null && moving.has(b)) ? bs : null);
  }
  const onCycle: ObjectId[] = [];
  for (const start of moving) {
    // Is `start` reachable from itself?
    const seen = new Set<ObjectId>();
    const stack = [...(edges.get(start) ?? [])];
    while (stack.length > 0) {
      const n = stack.pop()!;
      if (n === start) {
        onCycle.push(start);
        break;
      }
      if (seen.has(n)) continue;
      seen.add(n);
      stack.push(...(edges.get(n) ?? []));
    }
  }
  return onCycle.length === 0 ? null : onCycle.sort(byId)[0]!;
}
