import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SOURCE_FILES, generateModule, sha256 } from "../scripts/ucd.mjs";
import { UNICODE_TABLES_VERSION } from "../src/unicode.js";

const ROOT = join(import.meta.dirname, "..");
const UCD = join(ROOT, "ucd", "16.0.0");

describe("vendored UCD 16.0.0 (ADR-013)", () => {
  it("every vendored file matches SHA256SUMS", () => {
    const sums = readFileSync(join(UCD, "SHA256SUMS"), "utf8").trim().split("\n");
    expect(sums.length).toBe(4);
    for (const line of sums) {
      const [hash, file] = line.split(/\s+/) as [string, string];
      expect(sha256(UCD, file)).toBe(hash);
    }
  });

  it("the generated module is byte-identical to a fresh generation (determinism)", () => {
    const onDisk = readFileSync(join(ROOT, "src", "generated", "unicode-16.0.0.ts"), "utf8");
    expect(generateModule(UCD)).toBe(onDisk);
    expect(generateModule(UCD)).toBe(generateModule(UCD));
  });

  it("the generated header records the source hashes", () => {
    const onDisk = readFileSync(join(ROOT, "src", "generated", "unicode-16.0.0.ts"), "utf8");
    for (const f of SOURCE_FILES) expect(onDisk).toContain(`${f} sha256 ${sha256(UCD, f)}`);
  });

  it("exports the pinned version", () => {
    expect(UNICODE_TABLES_VERSION).toBe("16.0.0");
  });
});

describe("§16.2: src never delegates Unicode to the runtime", () => {
  const FORBIDDEN = [".normalize(", "toLowerCase", "toUpperCase", "localeCompare", "toLocaleLowerCase", "toLocaleUpperCase", "Intl."];
  const files = (dir: string): string[] =>
    readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
      e.isDirectory() ? files(join(dir, e.name)) : e.name.endsWith(".ts") ? [join(dir, e.name)] : [],
    );

  it("no source file uses normalize, case mapping, localeCompare or Intl", () => {
    const hits = files(join(ROOT, "src")).flatMap((f) => {
      const text = readFileSync(f, "utf8");
      return FORBIDDEN.filter((token) => text.includes(token)).map((token) => `${f}: ${token}`);
    });
    expect(hits).toEqual([]);
  });

  it("evidence: the scan detects a forbidden call", () => {
    const text = "const k = path.normalize(\"NFC\").toLowerCase();";
    expect(FORBIDDEN.filter((token) => text.includes(token))).toEqual([".normalize(", "toLowerCase"]);
  });
});
