import { type CanonicalPath, type ObjectId, canonicalizePath, conflictSuffix, objectLabel, splitExtension } from "./paths.js";

// §16.4 physical → logical rule, applied ONLY to a file that moved (§12.2 rule 12).

export interface MovedFile {
  readonly objectId: ObjectId;
  readonly currentLogicalPath: string;
  /** The object's current projected physical path. */
  readonly currentPhysicalPath: string;
  /** The new physical path chosen by the user. */
  readonly newPhysicalPath: string;
}

const lastSegment = (p: string) => p.slice(p.lastIndexOf("/") + 1);

/**
 * 1. deepest projected folder that is a prefix of the new path (exact bytes);
 * 2. that part becomes the folder's logical path; 3. remaining folder segments are literal;
 * 4. an unchanged file name keeps the current logical name; a changed one is literal, minus a
 *    final projection suffix only if it is exactly this object's label or full id.
 */
export function physicalToLogical(file: MovedFile, folders: ReadonlyMap<string, string>): CanonicalPath {
  const segments = file.newPhysicalPath.split("/");
  const name = segments.pop()!;
  let depth = segments.length;
  while (depth > 0 && !folders.has(segments.slice(0, depth).join("/"))) depth--;
  const prefix = depth > 0 ? folders.get(segments.slice(0, depth).join("/"))! : "";
  const logicalName =
    name === lastSegment(file.currentPhysicalPath) ? lastSegment(file.currentLogicalPath) : stripOwnSuffix(name, file.objectId);
  return canonicalizePath([prefix, ...segments.slice(depth), logicalName].filter((s) => s !== "").join("/"));
}

function stripOwnSuffix(name: string, objectId: ObjectId): string {
  const [base, ext] = splitExtension(name);
  for (const tag of [objectLabel(objectId), objectId]) {
    const suffix = conflictSuffix(tag);
    if (base.endsWith(suffix)) return base.slice(0, -suffix.length) + ext;
    if (name.endsWith(suffix)) return name.slice(0, -suffix.length);
  }
  return name;
}

/**
 * §12.2 rule 12: a file that did not move keeps its logical path, even if the projection has
 * not renamed it yet; only a moved file goes through the physical → logical rule.
 */
export function observedLogicalPath(
  file: MovedFile & { readonly previousObservedPhysicalPath: string },
  folders: ReadonlyMap<string, string>,
): CanonicalPath {
  if (file.newPhysicalPath === file.previousObservedPhysicalPath) return { ok: true, path: file.currentLogicalPath };
  return physicalToLogical(file, folders);
}
