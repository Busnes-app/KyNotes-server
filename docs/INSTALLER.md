# KyNotes for the suite installer

KyQuickStart's KyNotes manifest lives in KyQuickStart. This page lists what it must declare
and how it configures KyNotes with `apply-setup`.

## Manifest

- **Image:** `ghcr.io/busnes-app/kynotes-server@<digest>`, never a tag. Verify the digest
  against its build attestation with the command in the pin block of `docker-compose.yml`
  before deploying.
- **Port:** the container listens on 8080 (`PORT`/`KYNOTES_PORT`). Publish it only to the
  reverse proxy.
- **Volumes:** `/data` (database, secrets, blob store, the admin socket) and `/backups` for
  local sealed capsules.
- **Stop timeout:** at least 17 minutes (`stop_grace_period: 17m` in `docker-compose.yml`,
  `terminationGracePeriodSeconds: 1020` in Kubernetes). See [Shutdown](#shutdown).
- **Environment** the installer sets:
  - `TRUSTED_PROXY_CIDRS`: the reverse proxy's address only. Setting it also turns on
    `X-Forwarded-For` handling.
  - `KYNOTES_BACKUP_DIR=/backups` and `KYNOTES_BACKUP_KEEP=<n>`. These are deployment
    settings read at start; `apply-setup` cannot change them. It compares them with the
    bundle and reports `conflict` when they differ.
  - `KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY=true` only for a KyRecovery on a private address
    behind a TLS proxy. Loopback stays refused.
- **Health:** `GET /healthz`, or `/kynotes-server healthcheck` inside the container.
- **OIDC client (confidential) in KyIdentity:**
  - Redirect URI `https://<host>/api/v1/auth/oidc/callback`.
  - Back-channel logout URI `https://<host>/api/v1/auth/oidc/backchannel-logout`.
  - Application role `kynotes.admin`, assigned only to the administrator identity, never to
    an everyday identity.
- **SCIM:** the directory connector posts to `https://<host>/api/v1/sync/events`, signed
  with the HMAC secret passed as `directoryHmacSecretFile`. `docs/SSO.md` owns the wire
  contract.
- **restic:** back up the blob store, `/data/blobs`, only. The SQLite database
  (`/data/kynotes.sqlite*`) and secrets are excluded: the sealed capsule holds them.
- **Upgrades:** take a capsule (`deposit`, or wait for a scheduled run) before upgrading.
  Never roll the image back after a migration has run; restore the capsule instead.

## apply-setup

Run it after the health check passes:

    docker exec <container> /kynotes-server apply-setup --file /run/secrets/kynotes_setup.json

(`kubectl exec` works the same way.) The command talks to the running server over
`/data/admin.sock` (mode 0600, server uid or root only, never a network listener). It fails
with exit 1 if the server is not running.

Bundle, version 1. Every section is optional; unknown fields are rejected:

    {"version":1,
     "sso":{"issuerUrl":"https://id.example","clientId":"kynotes",
            "clientSecretFile":"/run/secrets/kynotes_oidc",
            "redirectUri":"https://notes.example/api/v1/auth/oidc/callback",
            "directoryHmacSecretFile":"/run/secrets/kynotes_scim_hmac"},
     "admins":[{"issuer":"https://id.example","subject":"<sub>","username":"owner-admin"}],
     "backup":{"dir":"/backups","keep":7,"depositInterval":"24h",
               "recovery":{"url":"https://kyrecovery.example",
                           "pairingCodeFile":"/run/secrets/kynotes_pair"}}}

- Secrets are absolute paths to files of at most 4 KiB inside the container. Inline secrets
  are rejected, and no secret is ever printed.
- URLs must be HTTPS. Private address literals need
  `KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY`; loopback and link-local are always refused.
- Admin issuers must equal the SSO issuer, from the bundle or already configured.
- `sso` is stored only when no SSO settings exist, after an issuer discovery probe.
- `admins` creates or promotes the account bound to issuer+subject, with no password. A
  username held by another account is a conflict; accounts are never adopted by username.
  Sign-in as admin also needs the `kynotes.admin` claim. Creating an admin closes the
  first-run web setup.
- `backup.dir` and `backup.keep` are only compared with the environment above.
- `backup.depositInterval` is set only when no interval is stored.
- `backup.recovery` is `present` when this instance is already paired to the same URL with
  a pinned key, and `conflict` when paired to another URL. Otherwise it claims the one-time
  code, even if a key was pinned by hand: the claim then succeeds only if KyRecovery returns
  that same key. A different key is a `conflict`, the pin is unchanged and the code is spent.

Output on stdout:

    {"version":1,"results":[{"section":"sso","status":"created"}, ...],
     "handover":{"url":"https://notes.example","adminUsernames":["owner-admin"],
                 "recoveryKeyFingerprint":"<key id>","backupDir":"/backups","version":"<sha>"}}

Statuses are `created`, `present`, `conflict`, `invalid` and `failed`. Exit codes, highest
precedence first:

- 2: invalid input.
- 1: any other error.
- 3: a conflict, left unchanged.
- 0: all created or present.

Rerunning the same bundle reports `present` for every section and writes no audit rows.
Each change writes one audit row with actor `system` and request ID `apply-setup`.

## Shutdown

On stop, the server drains a running `apply-setup` (a KyRecovery claim can take up to the
16-minute backup operation timeout) before SQLite closes, for at most 17 minutes. A
container or init stop timeout shorter than that kills the process mid-apply; rerun the
bundle after restart.
