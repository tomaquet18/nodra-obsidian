import { accessServiceToken, withAccessServiceToken } from "@nodra/sync-client";

/**
 * What the plugin keeps in its data.json: the Nodra vault chosen once (empty: not yet), and, for the
 * staging build only, the Cloudflare Access service token's id and secret (both empty: none; NOTES
 * question 393). data.json is inside the vault folder, so the login session is never kept here
 * (auth-storage.ts), and the server is fixed at build (src/globals.d.ts).
 */
export interface PluginSettings {
  readonly vaultId: string;
  readonly accessClientId: string;
  readonly accessClientSecret: string;
}

export const DEFAULT_SETTINGS: PluginSettings = { vaultId: "", accessClientId: "", accessClientSecret: "" };

/**
 * The settings from `loadData()`. Only the known fields are kept; `rewrite` says data.json holds
 * something else, which the caller writes away at once: above all the session token, the email and the
 * server URL that the development builds kept there. A token is never carried over (NOTES question 407).
 */
export function loadSettings(data: unknown): { readonly settings: PluginSettings; readonly rewrite: boolean } {
  if (data === null || data === undefined) return { settings: DEFAULT_SETTINGS, rewrite: false };
  if (typeof data !== "object" || Array.isArray(data)) return { settings: DEFAULT_SETTINGS, rewrite: true };
  const d = data as Record<string, unknown>;
  const pick = (key: keyof PluginSettings) => (typeof d[key] === "string" ? d[key] : DEFAULT_SETTINGS[key]);
  const settings: PluginSettings = { vaultId: pick("vaultId"), accessClientId: pick("accessClientId"), accessClientSecret: pick("accessClientSecret") };
  const rewrite = Object.entries(d).some(([k, v]) => !(k in DEFAULT_SETTINGS) || typeof v !== "string");
  return { settings, rewrite };
}

/**
 * The fetch every request of the plugin to the Nodra API goes through: the service token's two headers
 * on requests to the API, read from the settings at each request. Invalid Access settings reject the
 * request (`AccessSettingsError`, which never repeats a value); nothing is sent. Staging build only.
 */
export function apiFetch(apiUrl: string, settings: () => Pick<PluginSettings, "accessClientId" | "accessClientSecret">, fetch: typeof window.fetch): typeof window.fetch {
  return async (input, init) => {
    const s = settings();
    return withAccessServiceToken({ baseUrl: apiUrl, token: accessServiceToken(s.accessClientId, s.accessClientSecret), fetch })(input, init);
  };
}
