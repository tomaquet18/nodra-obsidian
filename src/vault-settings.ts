import { type AdapterPort, NODRA_FOLDER } from "./fs.js";

// The vault settings this plugin publishes for the other clients (§20.3): today only Obsidian's
// "Default location for new attachments", so that Nodra Web puts a pasted image where this Obsidian
// would. `.obsidian/` does not sync, so the value is written to `.nodra/vault-settings.json`, an ordinary
// file of the vault: it syncs like a note, encrypted end to end (content blob, path inside the manifest,
// §31), and the server never sees it. Nothing else from `.obsidian/` is ever published.
//
// No ping-pong between devices whose Obsidian settings differ: a device writes only when ITS setting
// differs from the last value it published (kept on the device), or when the file is missing. A value
// another device published is left alone until this device's own setting changes.

export const VAULT_SETTINGS_PATH = `${NODRA_FOLDER}/vault-settings.json`;
/** Local storage key (per vault and device): the last value this device published. */
export const PUBLISHED_KEY = "nodra-attachment-folder-published";

/** Obsidian's default: the vault root. */
export const OBSIDIAN_DEFAULT_ATTACHMENT_FOLDER = "/";

/**
 * `app.vault.getConfig("attachmentFolderPath")` (internal API, not in obsidian.d.ts): "/" the vault root,
 * "./" the note's folder, "./sub" a subfolder of it, "path" a fixed folder. Unset or not a string: "/".
 */
export function attachmentFolderSetting(vault: unknown): string {
  const getConfig = (vault as { getConfig?: unknown }).getConfig;
  if (typeof getConfig !== "function") return OBSIDIAN_DEFAULT_ATTACHMENT_FOLDER;
  const value: unknown = getConfig.call(vault, "attachmentFolderPath");
  return typeof value === "string" && value !== "" ? value : OBSIDIAN_DEFAULT_ATTACHMENT_FOLDER;
}

/** The file's exact bytes: one key, nothing else from Obsidian's configuration. */
export const encodeVaultSettings = (attachmentFolderPath: string): Uint8Array => new TextEncoder().encode(`${JSON.stringify({ attachmentFolderPath })}\n`);

const same = (a: Uint8Array, b: Uint8Array) => a.byteLength === b.byteLength && a.every((x, i) => x === b[i]);

/** Writes the setting when this device's value changed since it last published it, or the file is missing. True when it wrote. */
export async function publishVaultSettings(d: {
  readonly adapter: Pick<AdapterPort, "stat" | "mkdir" | "readBinary" | "writeBinary">;
  readonly setting: string;
  readonly lastPublished: string | null;
  readonly remember: (value: string) => void;
}): Promise<boolean> {
  const bytes = encodeVaultSettings(d.setting);
  const existing = await d.adapter.stat(VAULT_SETTINGS_PATH);
  if (existing?.type === "file") {
    if (d.lastPublished === d.setting) return false;
    if (same(new Uint8Array(await d.adapter.readBinary(VAULT_SETTINGS_PATH)), bytes)) {
      d.remember(d.setting);
      return false;
    }
  }
  if ((await d.adapter.stat(NODRA_FOLDER)) === null) await d.adapter.mkdir(NODRA_FOLDER);
  await d.adapter.writeBinary(VAULT_SETTINGS_PATH, bytes.slice().buffer as ArrayBuffer);
  d.remember(d.setting);
  return true;
}
