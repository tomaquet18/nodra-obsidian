import type { ObjectId, RemoteEntry } from "./types.js";

/**
 * R never regresses (§12.2 rule 3, §13.4): a head whose sequence is less than or equal
 * to the one recorded for that object is ignored. Returns the same map when nothing changes.
 */
export function recordRemoteHead(
  remote: ReadonlyMap<ObjectId, RemoteEntry>,
  objectId: ObjectId,
  head: RemoteEntry,
): ReadonlyMap<ObjectId, RemoteEntry> {
  const known = remote.get(objectId);
  if (known !== undefined && head.sequence <= known.sequence) return remote;
  return new Map(remote).set(objectId, head);
}
