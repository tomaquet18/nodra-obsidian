import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  ACCOUNT_SECRET_KEY_BYTES,
  ACCOUNT_SECRET_KEY_CHARS,
  SecretKeyError,
  decodeAccountSecretKey,
  encodeAccountSecretKey,
  formatAccountSecretKey,
  normalizeAccountSecretKey,
} from "../src/secret-key.js";
import { secretKeyVectors } from "./record-support.js";
import { fromHex, toHex } from "./support.js";

describe("Account Secret Key vectors (§24)", () => {
  for (const vector of secretKeyVectors.canonical) {
    it(`${vector.name}: encodes, formats and decodes`, () => {
      const key = fromHex(vector.bytes);
      expect(key.length).toBe(ACCOUNT_SECRET_KEY_BYTES);
      expect(encodeAccountSecretKey(key)).toBe(vector.chars);
      expect(vector.chars.length).toBe(ACCOUNT_SECRET_KEY_CHARS);
      expect(formatAccountSecretKey(key)).toBe(vector.display);
      expect(toHex(decodeAccountSecretKey(vector.display))).toBe(vector.bytes);
      expect(toHex(decodeAccountSecretKey(vector.chars))).toBe(vector.bytes);
    });
  }

  it("the display form is eight groups of four", () => {
    for (const vector of secretKeyVectors.canonical) {
      const groups = vector.display.split("-");
      expect(groups).toHaveLength(8);
      for (const group of groups) expect(group).toHaveLength(4);
    }
  });

  it("uses the Crockford alphabet, which excludes I, L, O and U", () => {
    expect(secretKeyVectors.alphabet).toBe("0123456789ABCDEFGHJKMNPQRSTVWXYZ");
    for (const c of "ILOU") expect(secretKeyVectors.alphabet).not.toContain(c);
  });
});

describe("normalization (§24)", () => {
  for (const vector of secretKeyVectors.normalization) {
    it(vector.name, () => {
      expect(toHex(decodeAccountSecretKey(vector.input))).toBe(vector.bytes);
    });
  }

  it("every normalization vector reaches the same 32 canonical characters", () => {
    const canonical = new Set(secretKeyVectors.normalization.map((v) => normalizeAccountSecretKey(v.input)));
    expect(canonical).toEqual(new Set(["0123456789ABCDEFGHJKMNPQRSTVWXYZ"]));
  });

  it("the HKDF salt is the decoded bytes, not the text (§24)", () => {
    // Two different spellings of the same key must produce the identical 20 bytes.
    const a = decodeAccountSecretKey("0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ");
    const b = decodeAccountSecretKey("oi23 4567 89ab cdef ghjk mnpq rstv wxyz");
    expect(toHex(b)).toBe(toHex(a));
  });
});

describe("malformed keys are refused (§24)", () => {
  for (const vector of secretKeyVectors.invalid) {
    it(vector.name, () => {
      try {
        decodeAccountSecretKey(vector.input);
      } catch (e) {
        expect(e).toBeInstanceOf(SecretKeyError);
        expect((e as SecretKeyError).code).toBe(vector.error);
        return;
      }
      expect.unreachable(`expected ${vector.error} for ${JSON.stringify(vector.input)}`);
    });
  }

  it("truncation at every length but 32 is refused", () => {
    const full = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    for (let n = 0; n < full.length; n++)
      expect(() => decodeAccountSecretKey(full.slice(0, n))).toThrow(SecretKeyError);
    expect(() => decodeAccountSecretKey(full)).not.toThrow();
  });

  it("encoding refuses anything that is not 20 bytes", () => {
    for (const n of [0, 19, 21, 32]) expect(() => encodeAccountSecretKey(new Uint8Array(n))).toThrow(SecretKeyError);
  });
});

describe("Account Secret Key properties", () => {
  const arbKey = fc.uint8Array({ minLength: ACCOUNT_SECRET_KEY_BYTES, maxLength: ACCOUNT_SECRET_KEY_BYTES });

  it("decode(format(k)) === k, and the text is always 32 characters", () => {
    fc.assert(
      fc.property(arbKey, (key) => {
        const display = formatAccountSecretKey(key);
        expect(normalizeAccountSecretKey(display)).toHaveLength(ACCOUNT_SECRET_KEY_CHARS);
        expect(toHex(decodeAccountSecretKey(display))).toBe(toHex(key));
      }),
      { numRuns: 1000 },
    );
  });

  it("encode(decode(text)) === text for every canonical text", () => {
    fc.assert(
      fc.property(arbKey, (key) => {
        const chars = encodeAccountSecretKey(key);
        expect(encodeAccountSecretKey(decodeAccountSecretKey(chars))).toBe(chars);
      }),
      { numRuns: 1000 },
    );
  });

  it("case, separators and I/L/O confusions never change the derived bytes", () => {
    fc.assert(
      fc.property(
        arbKey,
        fc.array(fc.constantFrom(" ", "-", ""), { minLength: 32, maxLength: 32 }),
        fc.boolean(),
        (key, separators, lower) => {
          const chars = [...encodeAccountSecretKey(key)];
          const typed = chars
            .map((c, i) => {
              // Type the ambiguous characters the way a user might: 0 as O, 1 as I or L.
              const confused = c === "0" ? "O" : c === "1" ? (i % 2 === 0 ? "I" : "L") : c;
              return (lower ? confused.toLowerCase() : confused) + separators[i];
            })
            .join("");
          expect(toHex(decodeAccountSecretKey(typed))).toBe(toHex(key));
        },
      ),
      { numRuns: 1000 },
    );
  });

  it("changing one character changes the bytes (there is no silent repair)", () => {
    const alphabet = secretKeyVectors.alphabet;
    fc.assert(
      fc.property(arbKey, fc.nat({ max: 31 }), fc.nat({ max: 30 }), (key, at, shift) => {
        const chars = [...encodeAccountSecretKey(key)];
        const original = chars[at]!;
        const replacement = alphabet[(alphabet.indexOf(original) + 1 + shift) % alphabet.length]!;
        chars[at] = replacement;
        expect(toHex(decodeAccountSecretKey(chars.join("")))).not.toBe(toHex(key));
      }),
      { numRuns: 1000 },
    );
  });
});
