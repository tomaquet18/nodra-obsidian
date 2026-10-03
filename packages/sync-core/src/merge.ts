import { diff3Merge } from "node-diff3";

export type Merge3Result = { readonly kind: "resolved"; readonly text: string } | { readonly kind: "conflict" };

/**
 * Line-based three-way merge policy (§17, §12.2 rule 4). node-diff3 computes the regions;
 * Nodra only decides: any conflicting region → conflict (the caller makes a conflict copy).
 * Conflict markers are never produced. Lines split on "\n" so the text round-trips exactly
 * (a trailing newline becomes a final empty line; "\r" stays inside its line).
 * Pinned library behavior: see test/merge.test.ts.
 */
export function merge3(base: string, local: string, remote: string): Merge3Result {
  const regions = diff3Merge(local.split("\n"), base.split("\n"), remote.split("\n"), {
    excludeFalseConflicts: true,
  });
  const lines: string[] = [];
  for (const region of regions) {
    if (region.conflict || !region.ok) return { kind: "conflict" };
    lines.push(...region.ok);
  }
  return { kind: "resolved", text: lines.join("\n") };
}

/**
 * §17 "ambas ramas son texto": a Markdown path (case-insensitive `.md`). Every other file, whatever its
 * bytes, is binary: concurrent edits make a conflict copy. The executor additionally merges only when
 * base, local and remote all decode as strict UTF-8, so a misnamed binary is never merged (NOTES question 140).
 */
export const isMergeablePath = (path: string): boolean => /\.md$/i.test(path);
