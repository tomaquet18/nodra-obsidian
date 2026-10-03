import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  // The `obsidian` package ships types only: its runtime is the app. Tests that load main.ts or the
  // panel view get the fake in test/support/obsidian-api.ts.
  resolve: { alias: { obsidian: fileURLToPath(new URL("./test/support/obsidian-api.ts", import.meta.url)) } },
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
