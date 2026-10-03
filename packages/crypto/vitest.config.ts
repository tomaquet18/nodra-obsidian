import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Argon2id and RSA-3072 keygen are deliberately slow; property runs multiply that.
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
