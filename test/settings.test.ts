import { describe, expect, it } from "vitest";
import { type PluginSettings, DEFAULT_SETTINGS, loadSettings } from "../src/settings.js";

// data.json lives inside the vault folder: it is synced, backed up and shared along with the notes. The
// login session (access and refresh tokens) is never kept there (auth-storage.ts keeps it outside the
// vault), and a data.json written by the development builds, which did keep a token there, is scrubbed.

const ID = "0123456789abcdef.access";
const SECRET = "s3cr3t-0f-the-service-token-f00d";

describe("plugin settings (data.json)", () => {
  it("round-trip with exactly the vault choice and the two Access settings, nothing else", () => {
    const settings: PluginSettings = { vaultId: "0190a4c2-0000-7000-8000-000000000001", accessClientId: ID, accessClientSecret: SECRET };
    const saved = JSON.parse(JSON.stringify(settings)) as unknown;
    expect(loadSettings(saved)).toEqual({ settings, rewrite: false });
    expect(Object.keys(settings).sort()).toEqual(["accessClientId", "accessClientSecret", "vaultId"]);
  });

  it("none, or one from before the Access settings, loads with the defaults", () => {
    expect(loadSettings(null)).toEqual({ settings: DEFAULT_SETTINGS, rewrite: false });
    expect(loadSettings({ vaultId: "v" })).toEqual({ settings: { ...DEFAULT_SETTINGS, vaultId: "v" }, rewrite: false });
  });

  it("a development build's data.json with a session token: the token, the email and the server are dropped, and data.json is rewritten", () => {
    const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";
    const old = { serverUrl: "http://127.0.0.1:8787", accessToken: token, email: "ana@example.test", vaultId: "v", accessClientId: "", accessClientSecret: "" };
    const { settings, rewrite } = loadSettings(old);
    expect(rewrite).toBe(true);
    expect(settings).toEqual({ ...DEFAULT_SETTINGS, vaultId: "v" });
    // What main.ts then writes back to data.json.
    const written = JSON.stringify(settings);
    for (const gone of [token, "accessToken", "ana@example.test", "127.0.0.1"]) expect(written).not.toContain(gone);
  });

  it("anything else in data.json, or a field of the wrong type, is dropped and rewritten too", () => {
    expect(loadSettings({ vaultId: 7, refresh_token: "r", accessClientId: ID, accessClientSecret: SECRET })).toEqual({
      settings: { vaultId: "", accessClientId: ID, accessClientSecret: SECRET },
      rewrite: true,
    });
    expect(loadSettings("not an object")).toEqual({ settings: DEFAULT_SETTINGS, rewrite: true });
  });
});
