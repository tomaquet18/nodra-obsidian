import type { EncodedTables } from "../src/unicode.js";

export declare const UNICODE_VERSION: string;
export declare const SOURCE_FILES: readonly string[];
export declare function encodeTables(dir: string, options?: { applyExclusions?: boolean }): EncodedTables;
export declare function generateModule(dir: string, options?: { applyExclusions?: boolean }): string;
export declare function sha256(dir: string, file: string): string;
