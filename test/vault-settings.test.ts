import { describe, expect, it } from "vitest";
import { OBSIDIAN_DEFAULT_ATTACHMENT_FOLDER, VAULT_SETTINGS_PATH, attachmentFolderSetting, encodeVaultSettings, publishVaultSettings } from "../src/vault-settings.js";
import { fakeObsidianVault } from "./support/fake-obsidian.js";

// The plugin publishes Obsidian's attachment folder setting (and nothing else) to `.nodra/vault-settings.json`,
// a synced, end-to-end encrypted file (§20.3), so the web puts new images where this Obsidian would.

const text = (b: Uint8Array | undefined) => (b === undefined ? undefined : new TextDecoder().decode(b));

function device(initial: string | null = null) {
  const vault = fakeObsidianVault();
  let last = initial;
  const publish = (setting: string) => publishVaultSettings({ adapter: vault.adapter, setting, lastPublished: last, remember: (v) => (last = v) });
  const writes = () => vault.calls.filter((c) => c === "write").length;
  return { vault, publish, writes, last: () => last };
}

describe("reading Obsidian's setting", () => {
  it.each([["/"], ["./"], ["./assets"], ["Attachments/Images"]])("%s is read as is", (value) => {
    expect(attachmentFolderSetting({ getConfig: (k: string) => (k === "attachmentFolderPath" ? value : "other") })).toBe(value);
  });

  it("unset, empty, not a string, or no getConfig: Obsidian's default, the vault root", () => {
    for (const v of [{ getConfig: () => undefined }, { getConfig: () => "" }, { getConfig: () => 3 }, {}]) expect(attachmentFolderSetting(v)).toBe(OBSIDIAN_DEFAULT_ATTACHMENT_FOLDER);
  });
});

describe("publishing it", () => {
  it.each([["/"], ["./"], ["./assets"], ["Attachments/Images"]])("%s → .nodra/vault-settings.json holds that one key", async (value) => {
    const d = device();
    expect(await d.publish(value)).toBe(true);
    expect(JSON.parse(text(d.vault.bytes(VAULT_SETTINGS_PATH))!)).toEqual({ attachmentFolderPath: value });
    expect(d.vault.folders.has(".nodra")).toBe(true);
    expect(d.last()).toBe(value);
  });

  it("unchanged: no second write", async () => {
    const d = device();
    await d.publish("./assets");
    const before = d.writes();
    expect(await d.publish("./assets")).toBe(false);
    expect(d.writes()).toBe(before);
  });

  it("a file already holding this value (another device, same setting) is not rewritten", async () => {
    const d = device();
    d.vault.userWrite(VAULT_SETTINGS_PATH, encodeVaultSettings("./"));
    expect(await d.publish("./")).toBe(false);
    expect(d.writes()).toBe(0);
    expect(d.last()).toBe("./");
  });

  it("no ping-pong: a value another device published stays while this device's own setting is unchanged", async () => {
    const d = device();
    await d.publish("/");
    d.vault.userWrite(VAULT_SETTINGS_PATH, encodeVaultSettings("Attachments")); // synced from another device
    const before = d.writes();
    expect(await d.publish("/")).toBe(false);
    expect(d.writes()).toBe(before);
    expect(text(d.vault.bytes(VAULT_SETTINGS_PATH))).toBe(`{"attachmentFolderPath":"Attachments"}\n`);
  });

  it("the user changes the setting on this device: published", async () => {
    const d = device();
    await d.publish("/");
    expect(await d.publish("./img")).toBe(true);
    expect(text(d.vault.bytes(VAULT_SETTINGS_PATH))).toBe(`{"attachmentFolderPath":"./img"}\n`);
  });

  it("the file was deleted: published again", async () => {
    const d = device();
    await d.publish("./");
    d.vault.userDelete(VAULT_SETTINGS_PATH);
    expect(await d.publish("./")).toBe(true);
    expect(d.vault.bytes(VAULT_SETTINGS_PATH)).toBeDefined();
  });
});
