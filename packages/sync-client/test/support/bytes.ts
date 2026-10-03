// The test harnesses (memfs, the in-memory server of sync-core, the e2e oracles) keep content as strings.
// Real content is bytes, so they store it in a MODEL encoding, a bijection between bytes and the strings
// the harness produces: valid UTF-8 is its text (so every existing text test reads the same), anything
// else is "\0b64:" + base64. Any string equality in an oracle is therefore byte equality.

const MARK = "\0b64:";
/** Its own strict decoder: the harness does not rely on the code under test (src/content.ts). */
const strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
function decodeText(bytes: Uint8Array): string | null {
  try {
    return strict.decode(bytes);
  } catch {
    return null;
  }
}
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

export function base64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

export const isBinaryModel = (s: string) => s.startsWith(MARK) && B64.test(s.slice(MARK.length));

/** Bytes → model string. */
export function toModel(bytes: Uint8Array): string {
  const text = decodeText(bytes);
  return text !== null && !isBinaryModel(text) ? text : MARK + base64(bytes);
}

/** Model string → bytes (inverse of toModel on every string toModel produces, and on any text). */
export function fromModel(s: string): Uint8Array {
  return isBinaryModel(s) ? Uint8Array.from(atob(s.slice(MARK.length)), (c) => c.charCodeAt(0)) : utf8(s);
}

