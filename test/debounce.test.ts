import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { debounce } from "../src/debounce.js";
import { nodeTimers } from "./support/timers.js";

// The §14 hint debouncer (replaces lodash's `debounce(fn, wait, { maxWait })`, the one use the plugin had):
// trailing edge only, a quiet period after the last call, and a maximum wait from the first call of a
// burst after which it fires even if calls never stop.

const WAIT = 3_000;
const MAX = 30_000;

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("debounce with maxWait", () => {
  it("a single call fires once, a quiet period later (trailing edge, never at the call)", () => {
    const fire = vi.fn();
    const d = debounce(fire, WAIT, { maxWait: MAX, timers: nodeTimers });
    d();
    expect(fire).not.toHaveBeenCalled();
    vi.advanceTimersByTime(WAIT - 1);
    expect(fire).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(fire).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(10 * MAX);
    expect(fire).toHaveBeenCalledTimes(1);
  });

  it("a burst fires once, a quiet period after its last call", () => {
    const fire = vi.fn();
    const d = debounce(fire, WAIT, { maxWait: MAX, timers: nodeTimers });
    for (const at of [0, 1_000, 1_000, 1_000, 500]) {
      vi.advanceTimersByTime(at);
      d();
    }
    vi.advanceTimersByTime(WAIT - 1);
    expect(fire).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(fire).toHaveBeenCalledTimes(1);
  });

  it("calls that never stop fire at maxWait from the first call of each burst, again and again", () => {
    const fire = vi.fn();
    const d = debounce(fire, WAIT, { maxWait: MAX, timers: nodeTimers });
    d();
    for (let t = 1; t <= 29; t++) {
      vi.advanceTimersByTime(1_000);
      d();
    }
    vi.advanceTimersByTime(1_000); // 30 s: maxWait from the first call
    expect(fire).toHaveBeenCalledTimes(1);
    d(); // a new burst starts at 30 s
    for (let t = 1; t <= 29; t++) {
      vi.advanceTimersByTime(1_000);
      d();
    }
    expect(fire).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1_000); // 60 s
    expect(fire).toHaveBeenCalledTimes(2);
  });

  it("cancel drops the pending call and its maxWait window; the next call starts afresh", () => {
    const fire = vi.fn();
    const d = debounce(fire, WAIT, { maxWait: MAX, timers: nodeTimers });
    for (let t = 0; t < 20; t++) {
      d();
      vi.advanceTimersByTime(1_000);
    }
    d.cancel();
    vi.advanceTimersByTime(10 * MAX);
    expect(fire).not.toHaveBeenCalled();
    // A fresh burst after cancel: its maxWait counts from its own first call, not the cancelled one's.
    d();
    for (let t = 1; t <= 29; t++) {
      vi.advanceTimersByTime(1_000);
      d();
    }
    expect(fire).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1_000);
    expect(fire).toHaveBeenCalledTimes(1);
  });

  it("cancel with nothing pending is harmless, and after a firing the next call waits a full quiet period", () => {
    const fire = vi.fn();
    const d = debounce(fire, WAIT, { maxWait: MAX, timers: nodeTimers });
    d.cancel();
    d();
    vi.advanceTimersByTime(WAIT);
    expect(fire).toHaveBeenCalledTimes(1);
    d();
    vi.advanceTimersByTime(WAIT - 1);
    expect(fire).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1);
    expect(fire).toHaveBeenCalledTimes(2);
  });

  it("runs on the timers it is given (Obsidian's window, for popout windows), never the bare globals", () => {
    const timers = { setTimeout: vi.fn(nodeTimers.setTimeout), clearTimeout: vi.fn(nodeTimers.clearTimeout) };
    const d = debounce(() => {}, WAIT, { maxWait: MAX, timers });
    d();
    d();
    d.cancel();
    expect(timers.setTimeout).toHaveBeenCalledTimes(3); // quiet, maxWait, quiet again
    expect(timers.clearTimeout).toHaveBeenCalled();
  });
});
