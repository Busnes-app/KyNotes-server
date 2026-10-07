# Changelog

## Unreleased

- Team keys phase 1: each local-password user gets an X25519 identity key, created silently at
  login or `/setup` and wrapped under a key derived from the password (migration 0021). Password
  change now re-wraps it; a web bundle from before this release cannot change the password of a
  user who has an identity (`409 identity_rewrap_required`): reload to get the current bundle.
  Recovery and administrator password reset delete the identity. SSO-only users get none yet.
  Accounts whose password an administrator or operator set (admin create or reset,
  `BOOTSTRAP_ADMIN_*`, `user add`) get their identity only after their own password change.
  Changing the password still makes existing notes unreadable; the form now says so and requires
  an explicit acknowledgement. `POST /api/v1/setup` no longer accepts a plaintext `password`
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
