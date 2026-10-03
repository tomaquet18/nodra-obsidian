import { defineConfig } from "vitest/config";

// Long end-to-end fault runs (`pnpm test:sim`): the runner over Dexie, the in-memory disk and backend.
export default defineConfig({
  test: {
    include: ["test/sim/**/*.test.ts"],
    provide: { nodraSim: true },
    testTimeout: 1_800_000,
  },
});
