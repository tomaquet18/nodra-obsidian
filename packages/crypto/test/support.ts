import { readFileSync } from "node:fs";
import type { DomainContext } from "../src/context.js";

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Returns a copy with one byte flipped, for "a changed byte must be rejected" assertions. */
export function flipByte(bytes: Uint8Array, index: number): Uint8Array {
  const copy = Uint8Array.from(bytes);
  const i = ((index % copy.length) + copy.length) % copy.length;
  copy[i] = (copy[i] as number) ^ 0x01;
  return copy;
}

/**
 * Only tests may forge a `DomainContext` from arbitrary bytes: the point of the brand is that
 * production code cannot. Used for mutated contexts and for AAD-free known-answer vectors.
 */
export function asContext(bytes: Uint8Array): DomainContext {
  return bytes as DomainContext;
}

export interface HkdfVector {
  name: string;
  ikm: string;
  salt: string;
  info: string;
  okmBytes: number;
  okm: string;
}

export interface Argon2Vector {
  name: string;
  password: string;
  salt: string;
  secret: string;
  associatedData: string;
  memoryKib: number;
  iterations: number;
  parallelism: number;
  tagBytes: number;
  algorithmVersion: number;
  tag: string;
}

export interface AesGcmVector {
  tcId: number;
  comment?: string;
  key: string;
  nonce: string;
  aad: string;
  plaintext: string;
  ciphertext: string;
  tag: string;
  result: "valid" | "invalid" | "acceptable";
}

export interface RsaOaepVector {
  tcId: number;
  comment?: string;
  label: string;
  ciphertext: string;
  plaintext: string;
  result: "valid" | "invalid" | "acceptable";
}

export interface EcdsaVector {
  tcId: number;
  comment?: string;
  message: string;
  signature: string;
  result: "valid" | "invalid" | "acceptable";
}

export interface HmacVector {
  tcId: number;
  key: string;
  message: string;
  tag: string;
}

export interface PrimitiveVectors {
  hkdf: HkdfVector[];
  argon2id: Argon2Vector[];
  aesGcm: AesGcmVector[];
  rsaOaep: { privateKeyPkcs8: string; tests: RsaOaepVector[] };
  ecdsaP1363: { publicKeySpki: string; tests: EcdsaVector[] };
  hmacSha256: HmacVector[];
}

export const vectors: PrimitiveVectors = JSON.parse(
  readFileSync(new URL("../vectors/primitives.json", import.meta.url), "utf8"),
) as PrimitiveVectors;
