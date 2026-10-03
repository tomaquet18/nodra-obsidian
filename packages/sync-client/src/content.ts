import { type Content, isMergeablePath, merge3 } from "@nodra/sync-core";

// Content is bytes everywhere (sync-core `Content`); only the merge of §17 reads it as text. A file is
// merged line by line only if base, local and remote ALL decode as strict UTF-8, so a binary that the
// path rule (`isMergeablePath`) took for text is never decoded lossily and re-encoded (NOTES question 140).

const strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();

/** The text of valid UTF-8 bytes (a BOM is kept as U+FEFF, so encoding gives the same bytes back); null otherwise. */
export function decodeText(bytes: Content): string | null {
  try {
    return strict.decode(bytes);
  } catch {
    return null;
  }
}

export const encodeText = (text: string): Content => encoder.encode(text);

/**
 * The text a note shows and edits as (the web editor): a Markdown path whose bytes are valid UTF-8, the
 * same rule as the merge. Anything else is an attachment, carried as bytes and never edited as text.
 */
export const markdownText = (path: string, content: Content): string | null => (isMergeablePath(path) ? decodeText(content) : null);

export type MergeContentResult = { readonly kind: "resolved"; readonly content: Content } | { readonly kind: "conflict" };

/** §17 three-way merge over bytes: a conflict (→ conflict copy) whenever any side is not UTF-8 text. */
export function mergeContent(base: Content, local: Content, remote: Content): MergeContentResult {
  const b = decodeText(base);
  const l = decodeText(local);
  const r = decodeText(remote);
  if (b === null || l === null || r === null) return { kind: "conflict" };
  const m = merge3(b, l, r);
  return m.kind === "conflict" ? m : { kind: "resolved", content: encodeText(m.text) };
}
