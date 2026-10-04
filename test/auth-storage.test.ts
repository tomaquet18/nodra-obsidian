import { supabaseAuth } from "@nodra/sync-client";
import { fakeGoTrue } from "@nodra/sync-client/test-support/gotrue";
import { describe, expect, it } from "vitest";
import { type LocalStore, type SecretStore, authStorageKey, pluginAuthStorage } from "../src/auth-storage.js";

// Where the plugin keeps the login session (auth-js's access and refresh tokens): Obsidian's secret
// storage (`app.secretStorage`, since 1.11.4), which is shared by every vault of the app, so each
// installation keeps it under its own key; without it, the vault's local storage (`app.saveLocalStorage`,
// per vault and device). Never data.json, which is inside the vault folder.

/** Obsidian's SecretStorage as its typings describe it: ids are lower-case letters, digits and dashes; no delete. */
function fakeSecrets(): SecretStore & { readonly items: Map<string, string> } {
  const items = new Map<string, string>();
  return {
    items,
    getSecret: (id) => items.get(id) ?? null,
    setSecret(id, secret) {
      if (!/^[a-z0-9-]+$/.test(id)) throw new Error(`invalid secret id: ${id}`);
      items.set(id, secret);
    },
  };
}

function fakeLocal(): LocalStore & { readonly items: Map<string, unknown> } {
  const items = new Map<string, unknown>();
  return {
    items,
    load: (key) => items.get(key) ?? null,
    save: (key, value) => void (value === null ? items.delete(key) : items.set(key, value)),
  };
}

const A = "0190a4c2-7b1e-7c3d-8e4f-000000000001";
const B = "0190a4c2-7b1e-7c3d-8e4f-000000000002";
const SESSION = JSON.stringify({ access_token: "a.b.c", refresh_token: "r" });

describe("pluginAuthStorage", () => {
  it("the storage key names the installation, and is a valid secret id", () => {
    expect(authStorageKey(A)).toBe(`nodra-auth-${A}`);
    expect(authStorageKey(A)).toMatch(/^[a-z0-9-]+$/);
    expect(authStorageKey(A)).not.toBe(authStorageKey(B));
    expect(() => authStorageKey("Not An Id")).toThrow();
  });

  it("with secret storage: kept there, under the installation's key; local storage stays empty", async () => {
    const secrets = fakeSecrets();
    const local = fakeLocal();
    const s = pluginAuthStorage({ secrets, local });
    await s.setItem(authStorageKey(A), SESSION);
    expect(await s.getItem(authStorageKey(A))).toBe(SESSION);
    expect(secrets.items.get(authStorageKey(A))).toBe(SESSION);
    expect(local.items.size).toBe(0);
    expect(await s.getItem(authStorageKey(B))).toBeNull();
  });

  it("removeItem: secret storage has no delete, so the secret is emptied and reads as absent", async () => {
    const secrets = fakeSecrets();
    const s = pluginAuthStorage({ secrets, local: fakeLocal() });
    await s.setItem(authStorageKey(A), SESSION);
    await s.removeItem(authStorageKey(A));
    expect(await s.getItem(authStorageKey(A))).toBeNull();
    expect(secrets.items.get(authStorageKey(A))).toBe("");
  });

  // §44.3: "plugin: el code_verifier nunca se escribe en secret storage ni en data.json (falla si el
  // almacenamiento persiste claves -code-verifier)". auth-js writes three keys per flow, all ending so.
  it.each([
    ["secret storage", true],
    ["local storage", false],
  ])("§3.7 a GitHub sign-in's PKCE verifier stays in memory: never in %s; the session is stored as before", async (_, withSecrets) => {
    const secrets = fakeSecrets();
    const local = fakeLocal();
    const writes: string[] = [];
    const watchedSecrets: SecretStore = { getSecret: (id) => secrets.getSecret(id), setSecret: (id, v) => (writes.push(id), secrets.setSecret(id, v)) };
    const watchedLocal: LocalStore = { load: (k) => local.load(k), save: (k, v) => (writes.push(k), local.save(k, v)) };
    const storage = pluginAuthStorage({ secrets: withSecrets ? watchedSecrets : undefined, local: watchedLocal });
    const gotrue = fakeGoTrue("http://supabase.test");
    const auth = supabaseAuth({ supabaseUrl: "http://supabase.test", anonKey: "anon", storage, fetch: gotrue.fetch, storageKey: authStorageKey(A) });
    const { url } = await auth.startOAuth({ provider: "github", redirectTo: "obsidian://nodra-auth?vault=v&flow=f" });
    // The verifier exists (in memory): the code redeems.
    const code = new URL(await gotrue.authorize(url, { providerUserId: "1", email: "ana@example.test", verified: true })).searchParams.get("code")!;
    await auth.exchangeCode(code);
    expect(writes.filter((k) => k.endsWith("-code-verifier"))).toEqual([]);
    expect([...secrets.items.keys(), ...local.items.keys()]).toEqual([authStorageKey(A)]);
    expect(await auth.email()).toBe("ana@example.test");
    await auth.dispose();
  });

  it("the check can fail: the same flow over the persistent storage alone writes the verifier there", async () => {
    const secrets = fakeSecrets();
    const gotrue = fakeGoTrue("http://supabase.test");
    const direct = { getItem: (k: string) => secrets.getSecret(k) || null, setItem: (k: string, v: string) => secrets.setSecret(k, v), removeItem: (k: string) => secrets.setSecret(k, "") };
    const auth = supabaseAuth({ supabaseUrl: "http://supabase.test", anonKey: "anon", storage: direct, fetch: gotrue.fetch, storageKey: authStorageKey(A) });
    await auth.startOAuth({ provider: "github", redirectTo: "obsidian://nodra-auth?vault=v&flow=f" });
    expect([...secrets.items.keys()].some((k) => k.endsWith("-code-verifier"))).toBe(true);
    await auth.dispose();
  });

  it("without secret storage: the vault's local storage, and removeItem clears it", async () => {
    const local = fakeLocal();
    const s = pluginAuthStorage({ secrets: undefined, local });
    await s.setItem(authStorageKey(A), SESSION);
    expect(await s.getItem(authStorageKey(A))).toBe(SESSION);
    expect(local.items.get(authStorageKey(A))).toBe(SESSION);
    await s.removeItem(authStorageKey(A));
    expect(await s.getItem(authStorageKey(A))).toBeNull();
    expect(local.items.size).toBe(0);
  });
});
