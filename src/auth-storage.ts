import { type AuthStorage, memoryAuthStorage, verifierRouter } from "@nodra/sync-client";

// Where the login session (auth-js's access and refresh tokens, §11.3) is kept: never data.json, which
// is inside the vault folder and travels with it. Obsidian's secret storage (`app.secretStorage`, since
// 1.11.4) is one store for every vault of the app, so each installation (§20.2, one per vault and device)
// keeps its session under its own key; without it, the vault's local storage (`app.saveLocalStorage`,
// per vault and device, outside the vault folder). NOTES question 407.
//
// §3.7 (ADR-023): auth-js's PKCE verifiers (every key ending in `-code-verifier`) never reach either: they
// stay in this process's memory (`verifierRouter`). A verifier is good for one code, and a restart
// mid-flow simply restarts the flow. Since ADR-024 the plugin's own sign-in keeps its verifier outside
// auth-js (sync-client `nativeOAuth`); the router stays as the guarantee for anything auth-js writes.

/** `app.secretStorage` as the plugin uses it (obsidian.d.ts 1.11.4: ids of a-z, 0-9 and dashes; no delete). */
export interface SecretStore {
  getSecret(id: string): string | null;
  setSecret(id: string, secret: string): void;
}

/** `app.loadLocalStorage` / `app.saveLocalStorage` (null clears the entry). */
export interface LocalStore {
  load(key: string): unknown;
  save(key: string, value: unknown): void;
}

/** auth-js's storage key for this installation's login: also a valid secret id. */
export function authStorageKey(installationId: string): string {
  if (!/^[0-9a-f-]+$/.test(installationId)) throw new Error("the installation id is not a UUID");
  return `nodra-auth-${installationId}`;
}

export function pluginAuthStorage(o: { readonly secrets: SecretStore | undefined; readonly local: LocalStore }): AuthStorage {
  return verifierRouter({ verifiers: memoryAuthStorage(), rest: persistent(o) });
}

/** The session's storage: secret storage, or the vault's local storage without it. */
function persistent(o: { readonly secrets: SecretStore | undefined; readonly local: LocalStore }): AuthStorage {
  const { secrets, local } = o;
  if (secrets !== undefined) {
    return {
      // An emptied secret is an absent one: SecretStorage cannot delete.
      getItem: (key) => secrets.getSecret(key) || null,
      setItem: (key, value) => secrets.setSecret(key, value),
      removeItem: (key) => secrets.setSecret(key, ""),
    };
  }
  return {
    getItem: (key) => {
      const value = local.load(key);
      return typeof value === "string" ? value : null;
    },
    setItem: (key, value) => local.save(key, value),
    removeItem: (key) => local.save(key, null),
  };
}
