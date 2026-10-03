// UTF-8 at the boundary between the test models (string content) and sync-core (byte content). The
// package's lib has no TextEncoder types (sync-core stays free of host APIs), so this uses the
// standard percent-encoding round trip. Test harness only.

export const utf8 = (text: string): Uint8Array => Uint8Array.from(unescape(encodeURIComponent(text)), (c) => c.charCodeAt(0));

export function text(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return decodeURIComponent(escape(binary));
}
