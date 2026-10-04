// owner.ts runs in Obsidian's renderer, where `window` is the global object, and uses `window.setTimeout`
// (obsidianmd/prefer-window-timers, for popout windows). A test in Node imports this for the same: `window`
// is the global object. Not a global setup: with a `window`, PGlite (the server tests) believes it is in
// a browser.
if (typeof window === "undefined") Object.defineProperty(globalThis, "window", { value: globalThis, configurable: true, writable: true });
