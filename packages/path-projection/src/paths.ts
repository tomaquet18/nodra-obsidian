// §16.2 normalization, comparison keys and portable sanitization. Pure string functions.

import { caseFoldFull, toNFC } from "./unicode.js";

export type ObjectId = string;

/** §16.2 item 5: a longer logical path is not synced. */
export const MAX_LOGICAL_PATH_BYTES = 4096;
/** §16.2 item 6 (initial value, calibrated in ADR-013). */
export const MAX_PORTABLE_PHYSICAL_PATH_BYTES = 1024;
/** §16.3: no physical segment exceeds 255 UTF-8 bytes. */
export const MAX_SEGMENT_BYTES = 255;

// §16.2 / ADR-013: NFC and case folding come from the pinned Unicode tables (src/unicode.ts),
// never from the runtime, so every platform computes the same keys.
export function nfc(s: string): string {
  return toNFC(s);
}

/** Full case folding (CaseFolding.txt statuses C + F, locale-independent). */
export function caseFold(s: string): string {
  return caseFoldFull(s);
}

/** §16.2 item 4: comparison key = Unicode case fold of the NFC path. */
export function comparisonKey(path: string): string {
  return nfc(caseFold(nfc(path)));
}

export type KeyFn = (path: string) => string;

export type CanonicalPath =
  | { readonly ok: true; readonly path: string }
  | { readonly ok: false; readonly reason: "EMPTY" | "DOT_DOT_SEGMENT" | "TOO_LONG" };

/**
 * §16.2 canonicalizePath: NFC, "\" → "/", no trailing slash, no empty or "." segments.
 * A ".." segment is rejected, not resolved (conservative: its meaning is ambiguous).
 */
export function canonicalizePath(raw: string): CanonicalPath {
  const segments = nfc(raw)
    .replaceAll("\\", "/")
    .split("/")
    .filter((s) => s !== "" && s !== ".");
  if (segments.includes("..")) return { ok: false, reason: "DOT_DOT_SEGMENT" };
  if (segments.length === 0) return { ok: false, reason: "EMPTY" };
  const path = segments.join("/");
  if (utf8Length(path) > MAX_LOGICAL_PATH_BYTES) return { ok: false, reason: "TOO_LONG" };
  return { ok: true, path };
}

export function utf8Length(s: string): number {
  let n = 0;
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    n += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
  }
  return n;
}

/** Truncates by whole code points so the result fits in `maxBytes` UTF-8 bytes. */
export function truncateToBytes(s: string, maxBytes: number): string {
  let out = "";
  let n = 0;
  for (const ch of s) {
    const len = utf8Length(ch);
    if (n + len > maxBytes) break;
    out += ch;
    n += len;
  }
  return out;
}

// eslint-disable-next-line no-control-regex -- the control characters U+0000–U+001F are exactly what this rejects
const FORBIDDEN_CHARS = /[<>:"\\|?*\u0000-\u001f]/g;
const RESERVED_WINDOWS = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;

/** §16.2 portable sanitization of one segment, identical on every platform. */
export function sanitizeSegment(segment: string): string {
  let s = segment.replace(FORBIDDEN_CHARS, "_");
  if (/[. ]$/.test(s)) s += "_";
  // Reserved with or without extension: Windows looks at the part before the first dot,
  // ignoring trailing spaces (conservative, case-insensitive).
  if (RESERVED_WINDOWS.test(s.split(".")[0]!.trimEnd())) s = `_${s}`;
  return s;
}

/** Extension = from the last dot, when the dot is not the first character. */
export function splitExtension(segment: string): [base: string, ext: string] {
  const i = segment.lastIndexOf(".");
  return i > 0 ? [segment.slice(0, i), segment.slice(i)] : [segment, ""];
}

/** §16.3 label: the last 8 characters of the object_id (random part of the UUIDv7), never the first. */
export function objectLabel(objectId: ObjectId): string {
  return objectId.slice(-8);
}

export function conflictSuffix(tag: string): string {
  return ` (Nodra conflict ${tag})`;
}

/**
 * Builds a physical segment ≤ 255 UTF-8 bytes: the base is truncated by whole characters,
 * keeping the suffix and the extension. A truncation that ends in "." or " " gets "_" again.
 */
export function fitSegment(base: string, suffix: string, ext: string): string {
  const budget = MAX_SEGMENT_BYTES - utf8Length(suffix) - utf8Length(ext);
  // An extension too long to keep is treated as part of the base.
  if (budget < 1) return fitSegment(base + ext, suffix, "");
  const segment = truncateToBytes(base, budget) + suffix + ext;
  return /[. ]$/.test(segment) ? `${truncateToBytes(base, budget - 1)}_${suffix}${ext}` : segment;
}
