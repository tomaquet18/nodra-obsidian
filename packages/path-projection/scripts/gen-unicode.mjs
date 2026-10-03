// Writes src/generated/unicode-16.0.0.ts from the vendored UCD files. Usage: pnpm gen:unicode
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { UNICODE_VERSION, generateModule } from "./ucd.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "src", "generated", `unicode-${UNICODE_VERSION}.ts`);
mkdirSync(dirname(out), { recursive: true });
const text = generateModule(join(root, "ucd", UNICODE_VERSION));
writeFileSync(out, text);
console.log(`wrote ${out} (${Buffer.byteLength(text)} bytes)`);
