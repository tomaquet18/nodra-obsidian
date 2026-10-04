// A trailing-edge debounce with a maximum wait: the §14 hint debouncer. It replaces lodash's
// `debounce(fn, wait, { maxWait })` (lodash finds its global object with `Function("return this")`, which
// a plugin bundle must not contain). Two timers, no clock: a quiet timer restarted by every call, and a
// maximum-wait timer started by the first call of a burst and never restarted; whichever ends first
// fires once and ends the burst.

/** Whose timers: Obsidian's `window` (main.ts; popout windows, obsidianmd/prefer-window-timers), or a test's. */
export interface Timers {
  setTimeout(handler: () => void, ms: number): number;
  clearTimeout(id: number | undefined): void;
}

export interface Debounced {
  (): void;
  /** Drops the pending call, if any, and its burst: the next call starts a new one. */
  cancel(): void;
}

export function debounce(fn: () => void, waitMs: number, options: { readonly maxWait: number; readonly timers: Timers }): Debounced {
  const { timers } = options;
  let quiet: number | undefined;
  let max: number | undefined;

  const cancel = () => {
    timers.clearTimeout(quiet);
    timers.clearTimeout(max);
    quiet = undefined;
    max = undefined;
  };
  const fire = () => {
    cancel();
    fn();
  };
  function debounced() {
    timers.clearTimeout(quiet);
    quiet = timers.setTimeout(fire, waitMs);
    max ??= timers.setTimeout(fire, options.maxWait);
  }
  debounced.cancel = cancel;
  return debounced;
}
