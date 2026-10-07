# KyNotes `apply-setup` for the suite installer

Status: approved direction 2026-10-07 (C → B → T → A list). This spec covers B only.

## Goal

KyQuickStart configures KyNotes end to end without a person at the admin UI. The installer runs
`kynotes-server apply-setup --file <bundle>` inside the running container (`docker exec` or
`kubectl exec`), as for every other Ky product. The command:

- creates only what is missing;
- never overwrites existing settings;
- writes one audit row per change;
- reports what it did as JSON;
- exposes no network credential.

## Decisions (owner, 2026-10-07)

- KyNotes is a first-party Ky product with `apply-setup`, not a catalog adapter.
- The installer registers a **confidential** OIDC client in KyIdentity and passes its issuer, client ID and secret. Manual KySignOn pairing (public client `kynotes`) stays for hand installs.
- Bulk data (attachment and note-version blobs) is backed up by the installer's **restic** job to the append-only rest-server. The sealed capsule keeps covering the database and secrets.

## Design

### Transport: a local socket, not a second writer

The CLI takes the same exclusive data-directory lock as the server, so it cannot run beside the live server. Instead:

- **Socket.** The server listens on a Unix socket, `<data_dir>/admin.sock`, with mode 0600, owned by the server's uid and accepting only that uid or root, created at startup and removed at shutdown. It is never bound to a network address.
- **Shutdown.** The server drains a running apply for up to the backup operation timeout (16 minutes) plus a minute before SQLite closes. A container or init stop timeout shorter than that cuts it off; `docker-compose.yml` sets `stop_grace_period: 17m`.
- **Client.** `apply-setup --file F [--config PATH]` reads and validates the bundle, sends it over the socket, and prints the server's JSON report to stdout.
- **Exit codes.** 0 when everything applied or was already present. 3 when something conflicts with existing settings and was left unchanged. 2 for invalid input. 1 for other errors. Precedence: invalid, then other errors, then conflict.
- **Live backup operations.** The same socket serves `deposit` and `backup-drill`: when the server runs, those CLI commands ask it to run its backup service and print the JSON result (exit 0 ok, 1 failed); when it is stopped they keep the offline path under the data-directory lock.
- **Server not running.** The command fails with a clear message. The installer runs it after the health check.
- **Rationale.** The server applies the bundle with its own machinery: audit rows, writer lock, cached settings, the backup service and the pairing client. Nothing races it, and access to the socket already implies container access, so this grants nothing new.

### Bundle (JSON, version 1)

```json
{
  "version": 1,
  "sso": {
    "issuerUrl": "https://id.example",
    "clientId": "kynotes",
    "clientSecretFile": "/run/secrets/kynotes_oidc",
    "redirectUri": "https://notes.example/api/v1/auth/oidc/callback",
    "directoryHmacSecretFile": "/run/secrets/kynotes_scim_hmac"
  },
  "admins": [{ "issuer": "https://id.example", "subject": "…", "username": "owner-admin" }],
  "backup": {
    "dir": "/backups", "keep": 7, "depositInterval": "24h",
    "recovery": { "url": "https://kyrecovery.example", "pairingCodeFile": "/run/secrets/kynotes_pair" }
  }
}
```

Every section is optional.

- **Secrets** arrive only as file paths inside the container, never inline, and are never echoed in the report.
- **Validation** happens at the boundary:
  - URLs must be HTTPS. Private address literals are refused unless the server's existing allow-private-recovery setting applies; loopback and link-local are always refused.
  - Admin issuers must equal the SSO issuer, from the bundle or already configured.
  - Usernames follow the existing rules.
  - Unknown fields are rejected.

### Per section

- **`sso`.** When no SSO settings exist, store them, through the same validation and audit as the admin route, including the issuer metadata probe. An unreachable issuer (transport error, 5xx, 429) is `failed` and retryable; a definite bad document is `invalid`. When identical settings exist, report `present`. When they differ, report `conflict` and leave them unchanged.
- **`admins`.**
  - For each identity, ensure a user bound to `issuer`+`subject` with the local admin grant and no password.
  - An existing binding with the admin grant reports `present`. An existing binding without it gets the grant, with an audit row.
  - A username taken by an unrelated account is a `conflict`. Bindings are never adopted by username, which is the existing rule.
  - Admin access still also needs the `kynotes.admin` claim at sign-in, so both gates hold.
- **`backup`.**
  - The local directory and keep count are deployment settings (`KYNOTES_BACKUP_DIR`, `KYNOTES_BACKUP_KEEP`) fixed at start. They are only compared: equal is `present`, different is `conflict`.
  - Set the interval only when no admin setting exists.
  - Pair with KyRecovery using the one-time code. This is the existing claim → pin → token flow, unchanged.
  - Already paired to the same URL with a pinned key is `present`; paired to another URL is `conflict`. A key pinned by hand without pairing still claims and spends the code: the same key returned succeeds, a different key is `conflict` and the pin is never overwritten.

### Report

```json
{"version":1,"results":[{"section":"sso","status":"created|present|conflict|invalid|failed","detail":"…"}],
 "handover":{"url":"…","adminUsernames":[…],"recoveryKeyFingerprint":"…","backupDir":"…","version":"…"}}
```

The handover block carries only non-secret facts that the installer's handover record prints. Secrets are referenced by the file path the installer already owns.

### Installer documentation

`docs/INSTALLER.md` lists what KyQuickStart's KyNotes manifest must declare. The manifest itself lives in KyQuickStart and is a follow-up there. KyNotes needs:

- **Images** by digest, verified against the published attestation.
- **Ports.**
- **Volumes:** data, and `/backups` for local capsules.
- **`TRUSTED_PROXY_CIDRS`** set to the reverse proxy address.
- **Health:** `GET /healthz`.
- **OIDC:** redirect and back-channel logout URIs, and the role `kynotes.admin`, assigned only to the admin identity.
- **SCIM:** the connector and its HMAC secret.
- **restic paths:** the blob store directory. The SQLite database is excluded because the capsule holds it.
- **Upgrade rules:** take a capsule before upgrading; no image rollback after a migration.

## Out of scope

- Admin/everyday separation (sub-project A).
- Team keys (sub-project T).
- The KyQuickStart manifest and adapter code.

## Verification

- Go tests for bundle validation (including hostile input: inline secrets, HTTP URLs, unknown fields, oversize files), each section's created/present/conflict path, audit rows, the socket's permission and lifecycle, the CLI exit codes, and secrets never appearing in the report or logs.
- An end-to-end test runs the real server, runs `apply-setup` twice, and checks the second run is all `present`.
- A container check: `docker exec <c> /kynotes-server apply-setup --file …` against a local container.
