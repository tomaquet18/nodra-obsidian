import { defineConfig } from "eslint/config";
import obsidianmd from "eslint-plugin-obsidianmd";

// Obsidian's official plugin linter, as its review runs it: the recommended config (ESLint core,
// typescript-eslint type-checked, and the Obsidian rules). Type information comes from each package's
// tsconfig.json; typescript-eslint reads it with TypeScript 6 (see .pnpmfile.cjs).
export default defineConfig([
  ...obsidianmd.configs.recommended,
  {
    languageOptions: {
      parserOptions: { projectService: { allowDefaultProject: ["eslint.config.*"] } },
      // The build's constants (src/globals.d.ts), replaced by esbuild's `define`.
      globals: { NODRA_ENV: "readonly", NODRA_API_URL: "readonly", NODRA_SUPABASE_URL: "readonly", NODRA_SUPABASE_ANON_KEY: "readonly" },
    },
  },
]);
