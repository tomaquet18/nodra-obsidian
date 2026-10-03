# Nodra for Obsidian

Encrypted sync for your Obsidian vaults with a [Nodra](https://app.nodranotes.com) account, with access
from any browser. Notes and attachments are encrypted on your device before they leave it. Turn on
Private mode and the sync is end-to-end encrypted. In Managed mode, the default, Nodra keeps an escrow of
your account key so it can help you recover access (see below).

> **Beta.** Nodra is in beta. Keep a backup of any vault you sync with it.

## Requirements

- **A Nodra account.** Create it at [app.nodranotes.com](https://app.nodranotes.com). The plugin
  signs in to an existing account; it does not create accounts.
- **Obsidian desktop** 1.11.4 or later (Windows, macOS, Linux). Mobile is not supported yet.

## Getting started

Everything is done from the **Nodra panel** in the right sidebar; no command is needed.

1. Create your account at [app.nodranotes.com](https://app.nodranotes.com).
2. Install and enable the plugin (Settings → Community plugins). The Nodra panel opens by itself the
   first time. Later, open it with the **Nodra** button in the left ribbon or by clicking the Nodra
   item in the status bar.
3. **Sign in** in the panel with your Nodra email and password (not your Encryption Password).
4. Click **Connect this vault**. On a Managed account your sign-in is enough; on a Private account the
   panel asks for your Encryption Password and the Account Secret Key from your Setup Kit, used for this
   one step and never stored. If your account has several Nodra vaults, the panel asks which one this
   Obsidian vault syncs to (chosen once).

Sync then runs in the background. The panel shows **Synced**, **Syncing…**, **Paused**, **Offline** or
**Needs attention**, and when it last synced, with **Sync now** and **Pause** / **Resume**. When something
needs you (storage full, signed out, the vault's access revoked…), the panel says what happened in plain
words and offers the one action that fixes it. Its account section shows your email and whether the
account is Managed or Private, and has **Manage devices** (list and revoke), **Create vault** (for another
Obsidian vault), **Can't unlock your account?** (recovery, Managed accounts) and **Sign out**. Signing out
stops sync; signing in again resumes it without connecting again.

The commands (**Open the Nodra panel**, **Sync now**, **Pause or resume sync**, **Manage devices**, **Create
a new Nodra vault**, **Recover the account**, **Sign out**…) are shortcuts for the same actions.

Every file of the vault is synced, attachments included. Hidden files and the `.obsidian` folder are
not. Concurrent edits of one note are merged when they do not overlap; otherwise a conflict copy
appears next to the note, and your file never gets conflict markers.

## Nodra must be the only sync on the vault folder

Do not sync the same vault folder with Nodra and another tool (Obsidian Sync, iCloud Drive, Dropbox,
OneDrive, Syncthing, a Git plugin that commits on its own…): Nodra would take the other tool's copies for
your edits and create duplicates and conflicts. To use a vault on several devices, install Nodra on each
one.

Every time sync starts, the plugin looks for known signs of another tool, locally and without sending
anything:

- Obsidian's core **Sync** plugin turned on in this vault;
- a `.stfolder` (Syncthing) or `.dropbox` marker in the vault folder;
- a `.git` folder with the **Obsidian Git** plugin enabled and set to commit, push or pull automatically;
- the vault folder inside iCloud Drive (`Mobile Documents`), a `Dropbox` folder or a `OneDrive` folder.

If it finds one, sync does not start and the panel says what it found. Remove it and select **Try
again**, or select **This folder is not synced another way** and confirm. For Obsidian Sync the panel
also offers **Turn off Obsidian Sync for this vault**, which turns it off only when you select it (or tells
you where to do it yourself). Your confirmation is remembered on this device for this vault, outside the
vault folder; the plugin asks again if it finds a new sign, and forgets a confirmation once its sign is
gone.

While syncing, the plugin also notices another tool at work even without a known sign: if a change made
on another device is already in this vault folder before Nodra brings it (a note with exactly that
content, or files moved exactly the way the other device moved them, three times in a row), sync pauses
and sends nothing. The panel shows **Another tool seems to be syncing this folder** with the notes
concerned. Turn off the other tool for this folder, then select **I removed the other tool, resume**:
those changes are taken as they are, and the check goes on watching. Until you do, the pause stays, also
after restarting Obsidian. A note emptied on both sides never counts, and Nodra's own writes never do,
even after a crash in the middle of one.

## Encryption and protection modes

Each vault is encrypted on your devices with keys your trusted devices hold. When you enroll this vault, the
plugin creates its own device key, which stays non-extractable in Obsidian's local storage (IndexedDB),
and your account grants it access. You can list and revoke devices at any time; a revoked device gets
nothing new.

- **Managed** (the default): your sign-in unlocks the account on a new device. Nodra keeps an escrow of
  your account key so it can help you recover access, which also means Nodra could technically decrypt
  a Managed vault. Your notes are encrypted in transit and at rest.
- **Private**: new devices also need your Encryption Password and your Account Secret Key. In Private
  mode Nodra cannot read your notes or unlock or recover your account; only your Recovery Kit can.

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
`versions.json` and `package.json` together; attach `main.js`, `manifest.json` and `styles.css` to a
GitHub release named after the version.

## Development

```sh
pnpm --filter @nodra/obsidian-plugin test
pnpm --filter @nodra/obsidian-plugin typecheck
```

`src/fs.ts` is the file-system port over `DataAdapter`; `src/controller.ts` wires sync without the
`obsidian` runtime so it runs in tests; `src/login.ts` and `src/auth-storage.ts` are the sign-in and
where its session is kept; `src/panel.ts` decides what the Nodra panel shows (pure), `src/panel-view.ts`
renders it and `styles.css` styles it; `src/main.ts` wires the plugin to Obsidian. Assumptions about Obsidian that the tests
cannot verify are listed in `NOTES.md`.
