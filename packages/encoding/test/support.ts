import { readFileSync } from "node:fs";
import type { NceDomain, NceValue } from "../src/index.js";

// Language-neutral value notation of vectors/nce.json.
export type JsonValue =
  | { int: string }
  | { bytes: string }
  | { text: string }
  | { bool: boolean }
  | { null: null }
  | { array: JsonValue[] }
  | { map: [number, JsonValue][] };

export interface Vectors {
  positive: { name: string; value: JsonValue; hex: string }[];
  contexts: { name: string; domain: NceDomain; fields: JsonValue[]; hex: string }[];
  negative: { name: string; hex: string; error: string }[];
}

export const vectors: Vectors = JSON.parse(
  readFileSync(new URL("../vectors/nce.json", import.meta.url), "utf8"),
) as Vectors;

/** Canonical integer form: number when safe, bigint otherwise (what decode returns). */
export function canonicalInt(b: bigint): number | bigint {
  return b >= BigInt(Number.MIN_SAFE_INTEGER) && b <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(b) : b;
}

export function fromJson(v: JsonValue): NceValue {
  if ("int" in v) return canonicalInt(BigInt(v.int));
  if ("bytes" in v) return fromHex(v.bytes);
  if ("text" in v) return v.text;
  if ("bool" in v) return v.bool;
  if ("null" in v) return null;
  if ("array" in v) return v.array.map(fromJson);
  return new Map(v.map.map(([k, x]) => [k, fromJson(x)]));
}

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
