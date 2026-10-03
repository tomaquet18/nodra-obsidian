import type { LocalEntry, PlanInput, RevisionEntry } from "../src/types.js";

type PlannerOutboxEntry = PlanInput["outbox"][number];

export const rev = (
  revisionId: string,
  sequence: number,
  path: string,
  localCompareHash: string | null,
  deleted = false,
  createdSequence = 1,
): RevisionEntry => ({ revisionId, sequence, path, localCompareHash, deleted, createdSequence });

export const del = (revisionId: string, sequence: number, path = "x.md"): RevisionEntry =>
  rev(revisionId, sequence, path, null, true);

/** A file observed at `physicalPath` (default: its logical path), recorded at `recordedPhysicalPath`. */
export const present = (
  path: string,
  localCompareHash: string,
  physicalPath = path,
  recordedPhysicalPath = physicalPath,
): LocalEntry => ({ kind: "PRESENT", path, physicalPath, recordedPhysicalPath, localCompareHash });
export const ABSENT: LocalEntry = { kind: "ABSENT" };
export const UNBOUND: LocalEntry = { kind: "UNBOUND" };
export const NOT_MATERIALIZED: LocalEntry = { kind: "NOT_MATERIALIZED", reason: "LOCAL_FS_REJECTED" };

export const inFlight = (objectId: string): PlannerOutboxEntry & { mutationId: string } => ({
  mutationId: `m-${objectId}`,
  objects: [{ objectId }],
});

export interface OneObject {
  l?: LocalEntry;
  s?: RevisionEntry;
  r?: RevisionEntry;
}

/** Builds a PlanInput for a single object "o" (text, not pruned unless overridden). */
export function input1(o: OneObject, extra: Partial<PlanInput> = {}): PlanInput {
  return {
    local: new Map(o.l ? [["o", o.l]] : []),
    synced: new Map(o.s ? [["o", o.s]] : []),
    remote: new Map(o.r ? [["o", o.r]] : []),
    outbox: [],
    blocked: [],
    textObjects: new Set(["o"]),
    prunedRevisions: new Set(),
    untrackedFiles: [],
    tmpHex: ["0000000a", "0000000b", "0000000c"],
    ...extra,
  };
}
