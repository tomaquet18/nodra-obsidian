import type { Timers } from "../../src/debounce.js";

/** Node's timers as the plugin's `Timers` (Obsidian passes `window`), so fake timers (vi.useFakeTimers) apply. */
export const nodeTimers: Timers = {
  setTimeout: (handler, ms) => globalThis.setTimeout(handler, ms) as unknown as number,
  clearTimeout: (id) => globalThis.clearTimeout(id),
};
