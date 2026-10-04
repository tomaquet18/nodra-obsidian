import { vi } from "vitest";

/**
 * Runs `f` with a `window` of its own whose timers are spies (delegating to the real ones), so a test
 * tells `window.setTimeout` from the bare global `setTimeout` (obsidianmd/prefer-window-timers).
 */
export async function withOwnWindow<T>(f: (timers: { setTimeout: ReturnType<typeof vi.fn>; clearTimeout: ReturnType<typeof vi.fn> }) => T | Promise<T>): Promise<T> {
  const g = globalThis as { window?: unknown };
  const saved = g.window;
  const timers = {
    setTimeout: vi.fn((fn: () => void, ms?: number) => globalThis.setTimeout(fn, ms)),
    clearTimeout: vi.fn((id?: ReturnType<typeof globalThis.setTimeout>) => globalThis.clearTimeout(id)),
  };
  g.window = timers;
  try {
    return await f(timers);
  } finally {
    g.window = saved;
  }
}
