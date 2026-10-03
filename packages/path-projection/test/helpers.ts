import { comparisonKey } from "../src/paths.js";
import type { PhysicalAction, RenamePlanInput } from "../src/rename-plan.js";
import type { ProjectionObject } from "../src/project.js";

/** UUIDv7-shaped id whose last 8 hex chars (the label) are given. */
export const oid = (n: number, label = n.toString(16).padStart(8, "0")) =>
  `0190a1b2-${n.toString(16).padStart(4, "0")}-7000-8000-0000${label}`;

export const obj = (objectId: string, logicalPath: string, createdSequence: number | null): ProjectionObject => ({
  objectId,
  logicalPath,
  createdSequence,
});

/**
 * Independent disk simulator (case-insensitive, NFC-insensitive, like the worst platform).
 * Throws on any write onto an occupied path, including hierarchical conflicts.
 */
export function simulate(input: RenamePlanInput, actions: readonly PhysicalAction[]): Map<string, string> {
  const files = new Map<string, string>(); // key → owner ("?" for untracked)
  const at = new Map<string, string>();
  for (const p of input.untrackedFiles) files.set(comparisonKey(p), "?");
  for (const [id, p] of input.current) {
    files.set(comparisonKey(p), id);
    at.set(id, p);
  }
  const occupied = (p: string, self: string) => {
    const k = comparisonKey(p);
    for (const [fk, owner] of files) {
      if (owner === self) continue;
      if (fk === k || fk.startsWith(`${k}/`) || k.startsWith(`${fk}/`)) return true;
    }
    return false;
  };
  for (const a of actions) {
    if (a.kind === "remove") {
      if (at.get(a.objectId) !== a.from) throw new Error(`remove of a file not at ${a.from}`);
      files.delete(comparisonKey(a.from));
      at.delete(a.objectId);
      continue;
    }
    if (occupied(a.to, a.objectId)) throw new Error(`overwrite: ${a.kind} ${a.objectId} → ${a.to}`);
    if (a.kind === "rename") {
      // A file cannot become its own ancestor or descendant in one rename: the folder `g/` cannot be
      // created while the file `g` exists, and `foo` cannot be written while `Foo/` holds the file.
      const fk = comparisonKey(a.from);
      const tk = comparisonKey(a.to);
      if (tk.startsWith(`${fk}/`) || fk.startsWith(`${tk}/`)) throw new Error(`self-blocked: rename ${a.objectId} ${a.from} to ${a.to}`);
      if (at.get(a.objectId) !== a.from) throw new Error(`rename source mismatch for ${a.objectId}`);
      files.delete(comparisonKey(a.from));
    } else if (at.has(a.objectId)) throw new Error(`create of an object already on disk: ${a.objectId}`);
    files.set(comparisonKey(a.to), a.objectId);
    at.set(a.objectId, a.to);
  }
  return at;
}

export const planInput = (p: Partial<RenamePlanInput>): RenamePlanInput => ({
  current: new Map(),
  desired: new Map(),
  untrackedFiles: [],
  inFlight: new Set(),
  pending: new Set(),
  tmpHex: ["00000001", "00000002", "00000003", "00000004", "00000005", "00000006"],
  ...p,
});
