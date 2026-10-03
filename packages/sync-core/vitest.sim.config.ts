import { defineConfig } from "vitest/config";

// Long fault-injection simulations (`pnpm test:sim`): the same properties with full numRuns.
export default defineConfig({
  test: {
    include: ["test/sim/**/*.test.ts"],
    provide: { nodraSim: true },
    testTimeout: 1_800_000,
  },
});
