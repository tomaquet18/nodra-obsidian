# Nodra for Obsidian

End-to-end encrypted sync for your Obsidian vaults with a [Nodra](https://app.nodranotes.com) account.
Notes and attachments are encrypted on your device before they leave it; the Nodra server stores
ciphertext only, never your note text or file names.

> **Beta.** Nodra is in beta. Keep a backup of any vault you sync with it.

## Requirements

- **A Nodra account.** Create it at [app.nodranotes.com](https://app.nodranotes.com). The plugin
  signs in to an existing account; it does not create accounts.
- **Obsidian desktop** 1.11.4 or later (Windows, macOS, Linux). Mobile is not supported yet.

## Getting started

1. Create your account at [app.nodranotes.com](https://app.nodranotes.com).
2. Install and enable the plugin (Settings → Community plugins).
3. Run **Nodra: Sign in** from the command palette with your Nodra email and password.
4. Run **Nodra: Enroll this vault** once. On a Managed account your sign-in is enough; on a Private
   account, type your Encryption Password and the Account Secret Key from your Setup Kit (used for
   this one step and never stored).

Sync then runs in the background. The status bar shows `Nodra: idle`, `syncing`, `paused` or `error`;
hover it for details. Other commands: **Sync now**, **Pause or resume sync**, **Manage devices**,
**Create a new Nodra vault**, **Recover the account** (Managed accounts) and **Sign out**. Signing out
stops sync; signing in again resumes it without enrolling again.

Every file of the vault is synced, attachments included. Hidden files and the `.obsidian` folder are
not. Concurrent edits of one note are merged when they do not overlap; otherwise a conflict copy
appears next to the note, and your file never gets conflict markers.

## End-to-end encryption

Each vault is encrypted with keys that only your trusted devices hold. When you enroll this vault, the
plugin creates its own device key, which stays non-extractable in Obsidian's local storage (IndexedDB),
and your account grants it access. You can list and revoke devices at any time; a revoked device gets
nothing new.

- **Managed** (the default): your sign-in unlocks the account on a new device. Nodra can help you
  recover it if you lose access, so Nodra's service is part of what protects your keys.
- **Private**: new devices also need your Encryption Password and your Account Secret Key. Nodra cannot
  unlock or recover your account; only your Recovery Kit can.

## Network use

The plugin connects only to:

- `api.nodranotes.com`: the Nodra API, which stores and serves your encrypted vault.
- `zlsckqzllncgreukxhqt.supabase.co`: Nodra's sign-in service (Supabase Auth), for your email and
  password and to renew your session.

It sends no telemetry and no analytics.

## Your data on this device

- The sign-in session is kept in Obsidian's secret storage, outside your vault folder, separately for
  each vault. It is never written to the plugin's `data.json`, which lives inside the vault.
- `data.json` holds only which Nodra vault this Obsidian vault syncs to.
- Your Encryption Password and Account Secret Key are never stored.

## Source and license

This plugin's own source code is MIT licensed (see `LICENSE`). The released `main.js` also bundles
Nodra's sync and encryption libraries, which are built from a private repository, are not open source
and are not covered by that license. The bundled `main.js` is not
obfuscated, so you can inspect exactly what runs.

## Building

The environment is fixed at build time:

```sh
pnpm --filter @nodra/obsidian-plugin build          # production
pnpm --filter @nodra/obsidian-plugin build:staging  # staging (adds the Cloudflare Access fields)
pnpm --filter @nodra/obsidian-plugin build:dev      # the local dev server (pnpm dev:server)
pnpm --filter @nodra/obsidian-plugin dev            # the same, rebuilt on every change
```

Production and staging read `NODRA_API_URL`, `NODRA_SUPABASE_URL` and `NODRA_SUPABASE_ANON_KEY` from the
environment, or from `.env.production` / `.env.staging` next to `package.json` (git ignored). For
production:

```sh
NODRA_API_URL=https://api.nodranotes.com
NODRA_SUPABASE_URL=https://zlsckqzllncgreukxhqt.supabase.co
NODRA_SUPABASE_ANON_KEY=<the project's publishable or anon key>
```

The build refuses to run when any is missing, not https, not a bare origin, or when the key is a secret
key. The development build needs nothing and talks to `http://127.0.0.1:8787`.

Releases: `pnpm --filter @nodra/obsidian-plugin run version <x.y.z>` bumps `manifest.json`,
`versions.json` and `package.json` together; attach `main.js` and `manifest.json` to a GitHub release
named after the version.

## Development

```sh
pnpm --filter @nodra/obsidian-plugin test
pnpm --filter @nodra/obsidian-plugin typecheck
```

`src/fs.ts` is the file-system port over `DataAdapter`; `src/controller.ts` wires sync without the
`obsidian` runtime so it runs in tests; `src/login.ts` and `src/auth-storage.ts` are the sign-in and
where its session is kept; `src/main.ts` is the Obsidian UI. Assumptions about Obsidian that the tests
cannot verify are listed in `NOTES.md`.
