// Account Secret Key codec (§24): 20 random bytes (160 bits) shown as 32 Crockford Base32
// characters in groups of 4 separated by hyphens. On input, spaces and hyphens are ignored, the
// text is upper-cased, `I`/`L` become `1` and `O` becomes `0`, and it must decode to exactly 20
// bytes; otherwise it is an error. The HKDF salt is those 20 decoded bytes, never the text.

/** Crockford Base32 (Douglas Crockford, 2002): no `I`, `L`, `O` or `U`. */
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** 160 bits (§24). */
export const ACCOUNT_SECRET_KEY_BYTES = 20;
/** 20 bytes × 8 / 5 bits per character, exactly — no padding and no room for a check symbol. */
export const ACCOUNT_SECRET_KEY_CHARS = 32;
/** Display grouping of §24. */
export const ACCOUNT_SECRET_KEY_GROUP = 4;
export const ACCOUNT_SECRET_KEY_SEPARATOR = "-";

export type SecretKeyErrorCode =
  | "NOT_TEXT"
  | "INVALID_CHARACTER" // a character that is not Crockford Base32 after normalization
  | "WRONG_LENGTH" // not exactly 32 significant characters (truncated, padded, or a check symbol)
  | "WRONG_BYTE_LENGTH"; // encode: input is not 20 bytes

export class SecretKeyError extends Error {
  readonly code: SecretKeyErrorCode;
  constructor(code: SecretKeyErrorCode, detail: string) {
    super(`Account Secret Key ${code}: ${detail}`);
    this.name = "SecretKeyError";
    this.code = code;
  }
}

/** Per-character ASCII normalization. Deliberately not `toUpperCase()`, which maps characters such
 * as `ſ` onto `S` and would silently accept text the user never typed. */
function normalizeChar(c: string): string | undefined {
  if (c === " " || c === ACCOUNT_SECRET_KEY_SEPARATOR) return undefined; // ignored (§24)
  const upper = c >= "a" && c <= "z" ? String.fromCharCode(c.charCodeAt(0) - 32) : c;
  if (upper === "I" || upper === "L") return "1"; // §24
  if (upper === "O") return "0"; // §24
  return upper;
}

/**
 * The 32 canonical characters of a typed key, without separators. Applies the §24 normalization
 * and rejects anything outside the alphabet or of the wrong length — but does not decode.
 */
export function normalizeAccountSecretKey(input: string): string {
  if (typeof input !== "string") throw new SecretKeyError("NOT_TEXT", "expected a string");
  let out = "";
  for (const c of input) {
    const normalized = normalizeChar(c);
    if (normalized === undefined) continue;
    if (!ALPHABET.includes(normalized))
      throw new SecretKeyError("INVALID_CHARACTER", `${JSON.stringify(c)} is not Crockford Base32`);
    out += normalized;
  }
  if (out.length !== ACCOUNT_SECRET_KEY_CHARS)
    throw new SecretKeyError("WRONG_LENGTH", `expected ${ACCOUNT_SECRET_KEY_CHARS} characters, got ${out.length}`);
  return out;
}

/** Decodes a typed Account Secret Key to exactly 20 bytes (§24). */
export function decodeAccountSecretKey(input: string): Uint8Array {
  const chars = normalizeAccountSecretKey(input);
  const out = new Uint8Array(ACCOUNT_SECRET_KEY_BYTES);
  let acc = 0;
  let bits = 0;
  let i = 0;
  for (const c of chars) {
    acc = (acc << 5) | ALPHABET.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[i++] = (acc >>> bits) & 0xff;
      acc &= (1 << bits) - 1;
    }
  }
  // 32 × 5 = 160 = 20 × 8: the loop consumes every bit, so nothing is left over.
  return out;
}

/** The 32 characters of a 20-byte key, without separators. */
export function encodeAccountSecretKey(key: Uint8Array): string {
  if (!(key instanceof Uint8Array) || key.length !== ACCOUNT_SECRET_KEY_BYTES)
    throw new SecretKeyError("WRONG_BYTE_LENGTH", `expected ${ACCOUNT_SECRET_KEY_BYTES} bytes`);
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const byte of key) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET.charAt((acc >>> bits) & 0x1f);
      acc &= (1 << bits) - 1;
    }
  }
  return out;
}

/** The Setup Kit form of §24: 32 characters in groups of 4 separated by hyphens. */
export function formatAccountSecretKey(key: Uint8Array): string {
  const chars = encodeAccountSecretKey(key);
  const groups: string[] = [];
  for (let i = 0; i < chars.length; i += ACCOUNT_SECRET_KEY_GROUP)
    groups.push(chars.slice(i, i + ACCOUNT_SECRET_KEY_GROUP));
  return groups.join(ACCOUNT_SECRET_KEY_SEPARATOR);
}
