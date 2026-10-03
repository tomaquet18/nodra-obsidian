import { type OsFamily, pluginDeviceLabel } from "@nodra/sync-client";

// §29: the label this installation enrolls with, "Obsidian on macOS · Notes": the OS family from
// Obsidian's `Platform` (no permission, no version) and the vault's name, which it carried before.

/** The flags of Obsidian's `Platform` this reads; every one may be missing. */
export interface PlatformLike {
  readonly isIosApp?: boolean;
  readonly isAndroidApp?: boolean;
  readonly isTablet?: boolean;
  readonly isMacOS?: boolean;
  readonly isWin?: boolean;
  readonly isLinux?: boolean;
}

/**
 * The OS family. The mobile apps first: Obsidian sets `isMacOS` on iPhones and iPads too (it means
 * "uses command-key hotkeys"), and Android is a Linux.
 */
export function obsidianOs(p: PlatformLike): OsFamily | null {
  if (p.isIosApp) return p.isTablet ? "iPad" : "iPhone";
  if (p.isAndroidApp) return "Android";
  if (p.isMacOS) return "macOS";
  if (p.isWin) return "Windows";
  if (p.isLinux) return "Linux";
  return null;
}

export const pluginLabel = (platform: PlatformLike, vaultName: string): string => pluginDeviceLabel(obsidianOs(platform), vaultName);
