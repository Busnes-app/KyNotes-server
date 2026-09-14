# KyNotes Server

KyNotes stores encrypted notes and attachments; browsers own content decryption.
See [deployment](docs/DEPLOYMENT.md) for setup and configuration, including the `COMPOSE_FILE`
line a source build must set so `docker compose` never swaps in the published image.

See [SSO setup and upgrade](docs/SSO.md) for session-aware logout and the required
re-login/re-pairing of linked accounts after migration 0016.

Administrators can pin a recovery public key, pair KyRecovery, schedule backups, retain
local sealed copies, download capsules and run synthetic restore drills. Capsules hold
the database and deployment secrets, while ciphertext blobs require separate recovery.
Read the [restore runbook](docs/RESTORE.md) before relying on a backup.

TLS protects the public key received at pairing, the deposit token and receipts even
though the capsule is sealed. Pin the suite public key by hand or compare its fingerprint
out of band. A product process never holds recovery private keys or custodian shares.

Local plaintext maintenance commands are `copy-data-dir --out` and
`restore-data-dir --in`; they require a stopped service. The sealed recovery commands are
`deposit`, `export-capsule --out`, `backup-drill`, and `restore --in --to` (shares on stdin).
Use the admin UI for operations while the server is running.

Ciphertext blobs have their own mirror: configure `KYNOTES_BLOB_TARGET`, then use Admin
**Mirror now**, scheduled backups, or the offline `mirror-blobs --config PATH` command.
`test-blob-target` verifies connectivity; `fetch-blobs` restores missing/corrupt ciphertext
after capsule restore. See [deployment](docs/DEPLOYMENT.md#ciphertext-blob-mirror) for
S3, pinned SFTP, SMB and local-mount settings and [restore](docs/RESTORE.md) for the order.
