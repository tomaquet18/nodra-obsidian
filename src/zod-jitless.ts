import { config } from "zod";

// zod compiles its object parsers with `new Function` unless it is jitless, and checks whether it may
// when a schema is created, which the client packages do as their modules load. A plugin's main.js must
// not evaluate code from strings (Obsidian's review), so this module is main.ts's FIRST import: it runs
// before any module that creates a schema (test/build.test.ts loads the bundle with `Function` trapped).
config({ jitless: true });
