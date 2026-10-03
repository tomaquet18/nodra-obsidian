// The byte helpers every suite uses, in a module that imports nothing from Node — so a browser-only
// package (sync-client, whose tsconfig has `types: []`) can reuse the §31–§34 fixtures without
// pulling `node:fs` into its type graph. `support.ts` re-exports them, so no test had to move.

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** A copy with one byte flipped — the "any single changed byte is rejected" assertion. */
export function flipByte(bytes: Uint8Array, index: number): Uint8Array {
  const copy = Uint8Array.from(bytes);
  const i = ((index % copy.length) + copy.length) % copy.length;
  copy[i] = (copy[i] as number) ^ 0x01;
  return copy;
}

export function filled(length: number, value: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}
