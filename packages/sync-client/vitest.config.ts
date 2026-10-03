import { defineConfig } from "vitest/config";

// Fast suite (`pnpm test`): unit tests, store tests and a few seeded end-to-end cases.
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    provide: { nodraSim: false },
    // Property runs take well over the 5 s default when the whole monorepo tests in parallel.
    testTimeout: 60_000,
  },
});
