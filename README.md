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

## Plans and payments

Nodra is a service with a free plan: 1 vault, 500 MB, 2 plugin installations and 7 days of version history.
Paid plans (Pro, Max) add storage, vaults, unlimited plugin installations and longer history; see
[nodranotes.com/#pricing](https://nodranotes.com/#pricing). Payments are handled on nodranotes.com by Paddle,
Nodra's reseller; the plugin never asks for payment details.

## Getting started

Everything is done from the **Nodra panel** in the right sidebar; no command is needed.

1. Create your account at [app.nodranotes.com](https://app.nodranotes.com), and finish its setup there
   (choose how your account is protected): the plugin connects only to an account that is set up.
2. Install and enable the plugin (Settings → Community plugins). The Nodra panel opens by itself the
   first time. Later, open it with the **Nodra** button in the left ribbon or by clicking the Nodra
   item in the status bar.
3. **Sign in** in the panel with **Sign in with your browser**. The plugin opens Nodra Web in your web
   browser: sign in there the way you always do (email and password, or GitHub; the plugin never sees
   your password), then **Allow** "Nodra for Obsidian". For your safety, Nodra Web asks you to sign in
   again first if your last sign-in there is more than 5 minutes old. The browser then sends you back to
   Obsidian (it may ask to open Obsidian) and the panel signs in by itself. While it waits, the panel
   offers **Cancel**; after 10 minutes it stops waiting. **Deny** in the browser signs nothing in.
   With several vaults open, start from the vault you want to sign in, and keep it the last Obsidian
   window you used: the browser's answer goes to one window, and only the vault that started the sign-in
   accepts it; any other says "This sign-in link is not for this vault or has expired", and nothing
   changes (try again from the right window). On Linux the browser can only send you back if Obsidian is
   registered for `obsidian://` links (Obsidian's own setup does this; some installs, such as an AppImage
   without a desktop entry, do not).
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

The commands (**Nodra: Open panel**, **Nodra: Sync now**, **Nodra: Pause or resume sync**, **Nodra: Manage
devices**, **Nodra: Create a new vault**, **Nodra: Recover the account**, **Nodra: Sign out**…) are shortcuts for
the same actions.

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
- `zlsckqzllncgreukxhqt.supabase.co`: Nodra's sign-in service (Supabase Auth), to finish the browser
  sign-in (it exchanges a one-time code for this vault's session) and to renew your session.

The sign-in itself happens in your web browser, on Nodra Web (and GitHub, if you sign in with it); the
plugin never sees your password and never talks to GitHub.

It sends no telemetry and no analytics.

Like any online service, Nodra's servers see your account, your requests (IP address and time) and your synced vault data, stored encrypted; what they record, why and for how long is in Nodra's [privacy policy](https://nodranotes.com/privacy).

## Your data on this device

- The sign-in session is kept in Obsidian's secret storage, outside your vault folder, separately for
  each vault. It is never written to the plugin's `data.json`, which lives inside the vault.
- `data.json` holds only which Nodra vault this Obsidian vault syncs to.
- Your Encryption Password and Account Secret Key are never stored.
- A browser sign-in's one-time secret (its PKCE verifier) lives only in memory while the plugin waits for
  the browser; it is never written to secret storage or `data.json`.

## Source and license

The plugin and the sync and encryption libraries bundled into the released `main.js` are MIT licensed
(see `LICENSE`). Their source is published at
[github.com/tomaquet18/nodra-obsidian](https://github.com/tomaquet18/nodra-obsidian), from which you can
rebuild `main.js` and compare its SHA-256 with the release notes. The bundled `main.js` is not
obfuscated, so you can inspect exactly what runs.

## Building

The environment is fixed at build time:

```sh
pnpm --filter @nodra/obsidian-plugin build          # production
pnpm --filter @nodra/obsidian-plugin build:staging  # staging (adds the Cloudflare Access fields)
pnpm --filter @nodra/obsidian-plugin build:dev      # the local dev server (pnpm dev:server)
pnpm --filter @nodra/obsidian-plugin dev            # the same, rebuilt on every change
```

Production and staging read `NODRA_API_URL`, `NODRA_SUPABASE_URL`, `NODRA_SUPABASE_ANON_KEY` and
`NODRA_OAUTH_CLIENT_ID` from the environment, or from `.env.production` / `.env.staging` next to
`package.json` (git ignored). For production:

```sh
NODRA_API_URL=https://api.nodranotes.com
NODRA_SUPABASE_URL=https://zlsckqzllncgreukxhqt.supabase.co
NODRA_SUPABASE_ANON_KEY=<the project's publishable or anon key>
NODRA_OAUTH_CLIENT_ID=<the client id of "Nodra for Obsidian" in Supabase → Authentication → OAuth Apps>
```

The build refuses to run when any is missing, not https, not a bare origin, when the key is a secret
key, or when the client id is not a UUID (or is the dev server's). All four are public: they are in every
released `main.js`. The development build needs nothing and talks to `http://127.0.0.1:8787` and its dev
OAuth client.

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
cannot verify are pinned by the fake adapter in `test/support/fake-obsidian.ts` and its tests in `test/fs.test.ts`.

## About this repository

This repository is generated from Nodra's private monorepo by an export script, and is not developed
here directly. It contains:

- the Obsidian plugin, at the root: `src/`, `styles.css`, `manifest.json`, `versions.json`, the build
  configuration and the plugin's tests that run without the server;
- the client packages bundled into `main.js`, under `packages/`: `sync-client`, `sync-core`, `crypto`,
  `key-lifecycle`, `encoding`, `path-projection` and `protocol`, with their tests.

Nodra's server (API, database and storage) is not included. The plugin tests that run against it stay in
the private repository. Everything here is MIT licensed (see `LICENSE`).

### Build and verify a release

```sh
pnpm install --frozen-lockfile && pnpm build
sha256sum main.js
```

`pnpm build` is the release build. It reads `production.env`: the Nodra API, the Supabase project and its
publishable key, all public (they are in every released `main.js`). The hash must equal the `main.js`
SHA-256 in the release notes. The `verify` workflow (`.github/workflows/verify.yml`) typechecks, tests
and builds every push and pull request, and for each release compares the built `main.js` with the
release asset.

### Issues and pull requests

Issues are welcome. Pull requests are welcome too, but they are not merged here: changes are applied by
hand to the private monorepo and arrive with the next export.
