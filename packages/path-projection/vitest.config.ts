import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Property tests run many cases; under turbo's parallel load the 5 s default was hit once (5.4 s).
    testTimeout: 60_000,
  },
});
