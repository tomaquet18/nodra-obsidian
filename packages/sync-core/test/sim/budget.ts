import { inject } from "vitest";

declare module "vitest" {
  export interface ProvidedContext {
    /** True under vitest.sim.config.ts (`pnpm test:sim`). */
    nodraSim: boolean;
  }
}

/** The one knob: the long simulation config provides nodraSim = true. */
export const SIM = inject("nodraSim") === true;

/** numRuns for a property: modest in the fast suite, full in `test:sim`. */
export const runs = (fast: number, full: number) => (SIM ? full : fast);

/**
 * Broken-variant proofs use a fixed seed: the proof is that a counterexample exists, and a fixed
 * seed makes it reproducible (runs of the real client keep random seeds).
 */
export const BROKEN_SEED = 20260921;

/**
 * Settings for proving a broken variant fails: one counterexample is enough, so no shrinking
 * (a broken run often lasts until the step bound, and shrinking would repeat it many times).
 */
export const brokenRuns = (fast: number, full: number) => ({ numRuns: runs(fast, full), endOnFailure: true, seed: BROKEN_SEED });
