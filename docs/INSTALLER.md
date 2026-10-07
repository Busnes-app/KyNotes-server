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
  with the HMAC secret passed as `directoryHmacSecretFile`. See [Offboarding](#offboarding).
- **Backups and upgrades:** see [Backups](#backups) and [Upgrades](#upgrades).

## Identity

- The admin `subject` in the bundle is the administrator identity's subject as KyIdentity
  issues it, taken from KyIdentity's own `apply-setup` output. Never guess it from a username.
- Admin access needs both gates: the local grant (`admins` creates it) and the
  `kynotes.admin` role claim at sign-in. Either alone gives no admin access.
- Verify the everyday identity has none: sign in as it, then
  `GET https://<host>/api/v1/admin/backup/status` must answer 403. The same request as the
  administrator identity answers 200.

## Offboarding

KyIdentity's directory connector posts signed events (`syncauth` HMAC with the
`directoryHmacSecretFile` secret) straight to `/api/v1/sync/events`. No bridge holds a KyNotes
credential, so the installer's KyNotes deprovision step only verifies: disable a test user in
KyIdentity and confirm its sessions and paired devices stop working. An inactive event
disables the account and revokes its sessions and device credentials; its encrypted data and
keys stay. `docs/SSO.md` owns the wire contract.

## Backups

- **Capsule:** the sealed capsule holds the database (`/data/kynotes.sqlite*`), secrets and
  the blob inventory. It goes to KyRecovery and `/backups` on the schedule, or on demand with
  `docker exec <container> /kynotes-server deposit` (JSON result; exit 0 ok, 1 failed).
  `backup-drill` the same way proves a restore with a throwaway key.
- **restic:** back up `/data/blobs` only. Skip `/data/tmp`, the database and `/data/secrets`:
  the capsule holds them. Take the restic snapshot right after a successful `deposit`, so
  every blob the capsule's inventory names is in it.
- **K8up:** the image is distroless (no shell, no `tar`), so a `k8up.io/backupcommand` cannot
  run in the KyNotes pod. K8up then backs up the whole `/data` volume, which also holds a
  live copy of the database and the secrets under the restic repository key. Never restore
  the database from that snapshot. Whether K8up can exclude paths is unproven.
- **Offsite blob mirror:** `KYNOTES_BLOB_TARGET` makes KyNotes copy ciphertext blobs itself
  after each capsule run, and `fetch-blobs` restores from it. It is an alternative to the
  restic blob path; with both, restore from whichever holds every digest in the inventory.
- **Restore order:** first the capsule (`restore --in --to`, custodian shares on stdin, see
  `docs/RESTORE.md`), then the blobs into the restored directory's `blobs/` (restic restore,
  or `fetch-blobs`), then start the server.
- **Key fingerprint:** `handover.recoveryKeyFingerprint` is the pinned key ID, the lowercase
  hex SHA-256 of the public key. The KyRecovery ceremony page shows the same value as
  "Key ID". Print both in the handover record and have the owner compare them; a mismatch
  means a swapped key at pairing.
- **Pin by hand:** pasting the suite public key is only in the admin UI (Backups screen), not
  in the bundle. The bundle pairs with a one-time code.

## Upgrades

1. `docker exec <container> /kynotes-server deposit`; require exit 0 and, when paired, a
   `receipt` in the result (the client has already checked its digest against the bytes
   sent). Record `manifest.capsule_id`.
2. Take the restic snapshot of `/data/blobs`.
3. Deploy the new image by digest.

Migrations run forward only, in order, at start. Never roll the image back after one has run;
restore the capsule into a new data directory instead. Upgrades that cross migration
`0016_sso_logout.sql` or `0018_sso_app_roles.sql` revoke some SSO sessions and device
credentials once: users sign in again.

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
- Every bundle should carry an `admins` entry: until an admin exists the first-run web setup
  stays open. Route the reverse proxy to KyNotes only after `apply-setup` exits 0.
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

Rerunning the same bundle, with the same secret files, reports `present` for every section and
writes no audit rows. A regenerated client or HMAC secret is a `conflict`.
Each change writes one audit row with actor `system` and request ID `apply-setup`.

## Shutdown

On stop, the server drains a running `apply-setup` (a KyRecovery claim can take up to the
16-minute backup operation timeout) before SQLite closes, for at most 17 minutes. A
container or init stop timeout shorter than that kills the process mid-apply; rerun the
bundle after restart.
