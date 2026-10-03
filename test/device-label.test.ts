import { DEVICE_LABEL_MAX } from "@nodra/sync-client";
import { describe, expect, it } from "vitest";
import { type PlatformLike, obsidianOs, pluginLabel } from "../src/device-label.js";

// §29: the label the plugin enrolls with, from Obsidian's `Platform` flags and the vault's name.

describe("obsidianOs: the OS family from Obsidian's Platform", () => {
  it.each([
    [{ isMacOS: true }, "macOS"],
    [{ isWin: true }, "Windows"],
    [{ isLinux: true }, "Linux"],
    // Obsidian sets isMacOS on iPhones and iPads ("command-key hotkeys"): the app flag decides.
    [{ isIosApp: true, isMacOS: true }, "iPhone"],
    [{ isIosApp: true, isMacOS: true, isTablet: true }, "iPad"],
    [{ isAndroidApp: true, isLinux: true }, "Android"],
    [{}, null],
  ] as [PlatformLike, string | null][])("%j → %s", (platform, os) => {
    expect(obsidianOs(platform)).toBe(os);
  });
});

describe("pluginLabel", () => {
  it("names the app, the OS family and the vault", () => {
    expect(pluginLabel({ isMacOS: true }, "Notes")).toBe("Obsidian on macOS · Notes");
    expect(pluginLabel({ isIosApp: true, isMacOS: true }, "Notes")).toBe("Obsidian on iPhone · Notes");
    expect(pluginLabel({}, "Notes")).toBe("Obsidian · Notes");
  });

  it("stays within the label's bounds whatever the vault is called", () => {
    const label = pluginLabel({ isWin: true }, "x".repeat(1000));
    expect([...label].length).toBeLessThanOrEqual(DEVICE_LABEL_MAX);
    expect(label.startsWith("Obsidian on Windows · ")).toBe(true);
  });
});
