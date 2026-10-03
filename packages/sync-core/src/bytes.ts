import type { Content } from "./types.js";

// Byte comparisons for content (types.ts `Content`). `===` on two Uint8Array compares references, so
// every content equality in the client goes through these.

export function bytesEqual(a: Content, b: Content): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** `prefix` is a prefix of `bytes` (the empty content is a prefix of everything). */
export function bytesStartWith(bytes: Content, prefix: Content): boolean {
  return prefix.length <= bytes.length && bytesEqual(bytes.subarray(0, prefix.length), prefix);
}
