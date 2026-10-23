# Changelog

## Unreleased

### Upgrade notes

- `docker-compose.yml` no longer trusts every private network as a reverse proxy: the
  `TRUSTED_PROXY_CIDRS` default is now empty. Set it in `.env` to your proxy's own address (for
  example `TRUSTED_PROXY_CIDRS=172.20.0.5/32`) before upgrading. Otherwise every user shares the
  proxy's login rate-limit bucket, and an SSO callback or KySignOn pairing URL derived from the
  request (no redirect URI configured) uses KyNotes' own scheme and host. `GET
  /api/v1/installer/network` shows whether the proxy is trusted.
- `X-Forwarded-Proto` and `X-Forwarded-Host` now count only from a trusted proxy, like
  `X-Forwarded-For`. Before, any client could choose the SSO callback host and the state cookie's
  `Secure` flag when no redirect URI was configured.

### Changes

- Security: the image is built with Go 1.27.3 (was 1.27.2) for GO-2026-6809: `crypto/x509` now
  distrusts compromised intermediate certificates. `go.mod` sets `toolchain go1.27.3` so
  `go build` from source uses it too.
- The apply-setup and `--check` handover adds `blobTargetConfigured`. `false` means KyNotes
  copies no note ciphertext itself, so the capsule alone is not a full backup.

- New: "Export notebook" downloads the open notebook as a zip of Markdown pages, canvas pages and
  attachments. The browser decrypts and builds it; the server sees nothing new. The file is not
  encrypted, and the browser asks before writing it. `docs/EXPORT.md` describes the layout.
- Tasks can carry dates in their text: `due:2026-11-01`, `repeat:weekly` (also `daily`, `monthly`,
  `yearly`, `every-3-days`, `every-2-weeks`) and `remind:2026-11-01T09:00`, in your browser's time.
  The work queue groups open tasks into Overdue, Today, Upcoming, Later and No date, and shows each
  due date and whether it repeats. Ticking a repeating checklist item adds the next one below it. Turn
  on "Show reminders while KyNotes is open" in Settings to get a notification while a KyNotes tab is
  open; it says only "A task is due" unless you also turn on "Show task text in reminders". Reminders
  that passed with no tab open show as missed in the work queue. Dates and reminders stay inside your
  encrypted pages; the server learns nothing new.
- Optional push reminders: add `push:yes` beside a `remind:` time and turn on "Also remind me when
  KyNotes is closed" in Settings. The browser then sends the server only each reminder's time and an id
  the server cannot link to a task, and at that time the server sends an empty push through your
  browser's push service; the notification says only "A reminder is due". Off by default; the setting
  names what the server and the push service learn. Reminder settings are now per account. The server
  creates `secrets/vapid.key` on first start (migration 0028 adds two tables) and needs outbound HTTPS to
  the browser push services for this feature.
- New: `kynotes-mcp`, a local MCP server that lets an AI agent read one notebook, and with the
  editor role add pages and append text, as its own KyNotes account. It decrypts on your machine;
  the server still sees only ciphertext. It cannot delete or change existing text. Removing the
  agent from the team revokes it. `docs/MCP.md` describes setup.
- Fixed: after restoring your key with a recovery code (or linking this browser, or resetting
  your key), notebooks and pages that could not be read before now appear without a reload.
- The recovery-code text now says when you need the code: no browser holds your key and your
  password cannot open it, as after an administrator resets your password, and always on a single
  sign-on account.
- Fixed: the admin console opens at its top after first-run setup instead of partway down.

## 0.4.2 — 2026-10-16

### Upgrading from 0.4.x

- Back up the data directory first. Migrations 0021 to 0025 run on first start; restore that backup to go back.
- Notebook data written with a password-derived key no longer opens. Start such installs from a fresh data directory.
- Comment endpoints are gone (`PUT /api/v1/comments/{id}`, `GET /api/v1/containers/{id}/legacy`). Remove any client or script that calls them.
- Each browser clears its local note cache and unsent edits once on first load. Send pending edits before upgrading.
- Administrators that also held notes become everyday accounts. If the log then shows `no_active_admin`, run `kynotes-server user add --admin`.
- Stop the server before `user add`, `quota set`, `bootstrap-admin`, `integrity-check` or `consistency-check`.
- Source installs without `docker-compose.build.yml` in `COMPOSE_FILE`: run the snippet in that file once before `up -d`.

### Changes

- Fixed: two concurrent account recoveries with one code could both succeed; now only the first does.
  Resolving a conflict now reaches other clients' sync. A sync page, conflict list, notification list
  or pending-sync list with a row the server cannot read now fails instead of quietly leaving it out,
  and a conflicting save whose copy fails to store answers 500 instead of reporting a kept copy.
- A server killed by SIGKILL, out-of-memory or a crash no longer leaves a lock that stops it from
  starting again. `user add`, `quota set`, `bootstrap-admin`, `integrity-check` and `consistency-check`
  now refuse to run beside the server: stop it first. `restore-data-dir` checks its input and the
  copied database before touching the data directory and keeps the previous contents in
  `.restore-previous-*`; `copy-data-dir` refuses a non-empty destination or one inside the data
  directory. `gc --now` refuses a `--retention` it cannot parse instead of treating it as zero. A sealed
  capsule restore now also revokes paired devices, share links and pending invitations. The container
  health check no longer writes into `/data`.
- Administrator accounts are now separate from everyday accounts. An administrator account manages users,
  teams, single sign-on, backups and the audit log, and cannot open notes; an everyday account cannot reach
  administration. First-run setup creates one of each. A password an administrator set must be changed at
  first sign-in before anything else. Teams an administrator creates belong to an everyday owner, who names
  the notebook, and people an administrator adds receive a team's keys only after one of its owners approves
  them. With single sign-on, the `kynotes.admin` role signs in only to an administrator account. Upgrading
  turns any administrator that also held notes into an everyday account with its notes intact; if that leaves
  no administrator, the server logs `no_active_admin` and `kynotes-server user add --admin` creates one.
- Notebooks are keyed only by their own encryption keys, from the moment they are created; no notebook
  content is ever sealed or opened with a key derived from your password (KyNotes was never released, so
  this is not a migration). The server refuses to store content, a name, an envelope or an upload for a
  notebook until its first key exists, and creating a notebook no longer accepts a name. Every write now
  carries `X-Kynotes-Key-Scheme: shared-v2`. `GET /api/v1/containers/{id}/legacy` and
  `PUT /api/v1/comments/{id}` are removed. Development data: rows written by earlier builds with a
  password-derived key no longer open (start from a fresh data directory), and each browser clears its
  local note cache, unsent-edit queue and pending uploads once on its first load of this version
  (IndexedDB v6), so development browsers lose unsent local edits once. `kynotes-probe` now creates a
  password-wrapped encryption key for its account and keys its notebook before writing.
- Team keys phase 5: personal notebooks now get their own encryption keys, like team notebooks, so the
  server can no longer read them and changing your password no longer makes them unreadable. Each
  notebook gets its key when you create it. A one-time recovery code, shown once in your browser, gets your
  key back on a new browser when no other browser has it; the server keeps only a copy it cannot open.
  An administrator password reset no longer deletes your encryption key. If you lose every browser and
  the code, Settings can reset your key, and your personal notebooks are lost. Writing now needs your
  encryption key on that browser: accounts still on an administrator-set password change it first, and
  single sign-on accounts save a recovery code before their personal notebooks get keys. Single sign-on
  no longer asks for a "master password": nothing it would unlock exists. An account linked to KySignOn
  never gets a password copy of its key, including through a reset from a local session. An administrator
  password reset also revokes the account's paired device credentials. Team member management and "New
  team notebook" show only to team owners and admins. The creator of a notebook whose key or name failed
  to set up can delete it at any time, as long as it holds nothing. Creating a notebook in a team with
  other members no longer fails. After a reset, edits that were waiting for a notebook's key are never
  sent; Settings lists them under Unsent edits for export. A reset whose answer never reached the browser
  is explained on the next load. Database migration 0025.
- Team keys phase 3c: link a new browser to your account from one you already use. Both screens
  show a six-digit check code; you type the code from the new browser into the one you already use,
  and your encryption key moves only after you confirm it matches on both. KyNotes relays it
  encrypted. Accounts that sign in only through single sign-on can now set up an encryption key
  (confirmed with KySignOn), receive team keys, and, as team owners, share them with "Share keys".
  Browsers on HTTPS store your key encrypted under a browser key that pages cannot export; this does
  not protect it from someone who can read the browser's profile on disk, so use "Forget this device"
  on shared computers (plain-HTTP sites store it unencrypted, and Settings says so). "Forget this
  device" keeps unsent edits until they are sent or discarded. A failed local cache write no longer
  blocks sending an edit. On an account that signs in through KySignOn, changing a password an
  administrator set needs a KySignOn confirmation. Changing your password signs out your other
  sessions and revokes your paired device credentials. Link requests are limited at the device-pairing
  rate (`ratelimit.pairing_per_hour`, own bucket), and collect polls by the new
  `ratelimit.link_poll_per_minute` (default 60; `KYNOTES_RATELIMIT_LINK_POLL_PER_MINUTE`). Migration
  `0024` adds `link_requests` and the step-up scope.
- Team keys phase 3b: invitations send a one-time link, and an invitation from someone who can see
  your encryption key carries the team's keys, so you can read at once. Team member lists show who
  has a key, who is waiting and who has none yet; a member waiting for a key can send an owner a
  request. Settings lists the colleague keys your browser trusts, with fingerprints, and re-trusts a
  changed one; it also exports (as an unencrypted file) or discards edits stranded for a notebook you
  lost. A removed member can be invited again, and removal cancels their pending invitations; a team
  admin can remove an admin it invited; invitation expiry is checked as the invitation is accepted;
  invitation creation and, in a separate bucket, invitation accepts are rate-limited per account
  (`ratelimit.invitation_per_hour`, default 30); expired
  invitations' keys are cleaned up. Refused accepts and admin adds are audited. Migration `0023`
  adds `memberships.invited_by`. The browser's local note cache and save queue are now kept per
  account, so two accounts signed in on one browser never overwrite or read each other's unsent edits.
- Team keys phase 3a: team notebooks are shared end to end. When an owner or admin opens a team
  notebook whose members all have encryption keys, their browser creates the notebook key and
  shares it; members added later get the notebook's history; removing a member replaces the key
  for new content. A member waiting for a key sees the notebook read-only; edits made meanwhile
  wait on the device and are saved under the new key when it arrives. Keys are accepted only from
  an authenticated sender. Browsers remember colleagues' key fingerprints and ask before trusting
  a changed one (Settings shows your own).
  `GET /api/v1/containers` reports `sharedGeneration`; `PATCH /api/v1/containers/{id}` takes
  `keyGeneration` (required on a shared notebook, `409 already_exists` unless current); conflict
  listings report `keyGeneration`.
- Team keys phase 2 (server rules): `POST /api/v1/containers/{id}/key-rotations`, insert-only
  envelopes (own identity re-wrap only), member-self envelope writes, envelope writes and rotations
  behind a local password step-up (SSO sessions refused), the identity-based save gate for rotated
  containers (migration 0022), invitation envelopes and
  `GET /api/v1/users/{id}/identity`. `DELETE /api/v1/admin/teams/{id}/members/{userID}` now
  rotates like owner removal and answers `404 not_found` for a user who is not an active
  non-owner member (it answered 204 before). `kynotes-probe` keeps a random device key in the user
  cache dir (`-device-key` overrides) and revokes its device at the end of each run.
- Team keys phase 1: each local-password user gets an X25519 identity key, created silently at
  login or `/setup` and wrapped under a key derived from the password (migration 0021). Password
  change now re-wraps it; a web bundle from before this release cannot change the password of a
  user who has an identity (`409 identity_rewrap_required`): reload to get the current bundle.
  Accounts whose password an administrator or operator set (admin create or reset,
  `BOOTSTRAP_ADMIN_*`, `user add`) get their identity only after their own password change.
  `POST /api/v1/setup` no longer accepts a plaintext `password`
  (send `authSecret`), and password change shares the step-up lockout.
- `apply-setup --file BUNDLE` configures SSO, SSO-bound admins and backups on a running server
  through the local admin socket `<data_dir>/admin.sock` (mode 0600). It is create-only and
  prints a JSON report. See `docs/INSTALLER.md`.
- `deposit` and `backup-drill` run inside a running server over the same socket and print a JSON
  result; with the server stopped they keep the offline path. An unreachable SSO issuer is now a
  retryable `failed` (exit 1) in `apply-setup`, not `invalid`.
- `docker-compose.yml` names the published, attested image and no longer builds. A source install
  keeps building only if `docker-compose.build.yml` is in its `COMPOSE_FILE` chain; installs from
  before this change have no such line and must run the snippet in `docker-compose.build.yml`
  once before their first `up -d` on this revision, then confirm with `docker compose config
  --images` (`kynotes-server:local` is source; the `ghcr.io` name is published).
- KyNotes Server implementation through the current protocol and deployment
  hardening work.
- Local verification image digest: `sha256:57803753d9700377401a857b10f51e78e767e0b4aecfe73ba6fca2b86f2d36e7`.
