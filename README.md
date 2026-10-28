# KyNotes Server

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15926/badge)](https://www.bestpractices.dev/projects/15926)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Busnes-app/KyNotes-server/badge)](https://scorecard.dev/viewer/?uri=github.com/Busnes-app/KyNotes-server)

KyNotes is a browser-based notebook for encrypted text, handwriting, attachments and tasks, with shared team notebooks. Content is decrypted in the browser; an administrator manages accounts and the service rather than reading people’s notes.

**Start here:** [Standalone installation](INSTALL.md), [deployment settings](docs/DEPLOYMENT.md), [SSO](docs/SSO.md), [complete recovery](docs/RESTORE.md).
Local administrator and everyday accounts work without KyIdentity. A complete backup needs both the sealed capsule and a separate ciphertext blob mirror.

## Features

- Notebooks and pages with text and ink, attachments, and task/work-queue views.
- Encrypted content and team sharing with browser-held content keys.
- Separate administrator/everyday accounts, optional KyIdentity SSO and access synchronization.
- Sealed recovery capsules plus a separately configured encrypted-blob mirror.
- MCP integration: [capabilities and access setup](docs/MCP.md).

## Operation and recovery

KyNotes stores encrypted notes and attachments; browsers own content decryption.
See [deployment](docs/DEPLOYMENT.md) for setup and configuration, including the `COMPOSE_FILE`
line a source build must set so `docker compose` never swaps in the published image.

See [SSO setup and upgrade](docs/SSO.md) for session-aware logout and the required
re-login/re-pairing of linked accounts after migration 0016.

Administrators can pin a recovery public key, pair KyRecovery, schedule backups, retain
local sealed copies, download capsules and run synthetic restore drills. Capsules hold
the database and deployment secrets, while ciphertext blobs require separate recovery.
Read the [restore runbook](docs/RESTORE.md) before relying on a backup.

To check that a release image came from this repository's release workflow, and to rebuild its
binary to the same bytes, see [verifying releases](docs/VERIFYING-RELEASES.md). The security
argument as a whole is in the [assurance case](docs/ASSURANCE-CASE.md); key sizes and the optional
strong-key profile are in [docs/STRONG-CRYPTO.md](docs/STRONG-CRYPTO.md).

TLS protects the public key received at pairing, the deposit token and receipts even
though the capsule is sealed. Pin the suite public key by hand or compare its fingerprint
out of band. A product process never holds recovery private keys or custodian shares.

Local plaintext maintenance commands are `copy-data-dir --out` and
`restore-data-dir --in`; they require a stopped service. The sealed recovery commands are
`deposit`, `export-capsule --out`, `backup-drill`, and `restore --in --to` (shares on stdin).
`deposit` and `backup-drill` also work while the server runs (`docker exec`); use the admin
UI for the other operations then.

Ciphertext blobs have their own mirror: configure `KYNOTES_BLOB_TARGET`, then use Admin
**Mirror now**, scheduled backups, or the offline `mirror-blobs --config PATH` command.
`test-blob-target` verifies connectivity; `fetch-blobs` restores missing/corrupt ciphertext
after capsule restore. See [deployment](docs/DEPLOYMENT.md#ciphertext-blob-mirror) for
S3, pinned SFTP, SMB and local-mount settings and [restore](docs/RESTORE.md) for the order.
SFTP destinations need strong keys and modern negotiation; read the deployment guide before
upgrading an old target or selecting legacy SMB/NTLM compatibility.

## Health probes

`GET /healthz` is public `ky.health/1` JSON. It returns 200 when startup is
ready and SQLite responds to a ping, or 503 when either check fails. The
shared handler caches each evaluation for five seconds and bounds each check
to two seconds. Its response exposes fixed check names and statuses, never
database errors or user data. `GET /livez` preserves the former alive-only
`200 {"status":"ok"}` response. `GET /readyz` retains its startup-readiness
response. A router created without a database checks startup only.

## Development and test scope

Use Go matching `go.mod` and Node 26 as pinned by CI. From the repository root:

```sh
npm ci --prefix web
npm test --prefix web
npm run build --prefix web
go build ./...
go vet ./...
go test -race -count=1 ./...
```

These checks are not the complete release gate. CI also runs browser regressions, fuzz
checks, the Docker/installer probe and vulnerability checks; see
[the workflow](.github/workflows/ci.yml). Browser fixtures do not prove a live KyIdentity
rollout or complete recovery. Test the real blob mirror and actual capsule-plus-blob
restore separately before relying on them.

## License

KyNotes Server is released under the [MIT License](LICENSE.txt).

[![OctoCounts](https://api.octocounts.com/badge/Busnes-app/KyNotes-server/branch/master)](https://octocounts.com/github/Busnes-app/KyNotes-server/tree/master)

## Documentation

- [Standalone installation](INSTALL.md) — set up a new independent installation.
- [Deployment](docs/DEPLOYMENT.md) — run the container behind an HTTPS reverse proxy.
- [Suite installer](docs/INSTALLER.md) — what KyQuickStart's KyNotes manifest must declare.
- [SSO](docs/SSO.md) — SSO sessions, logout and directory provisioning.
- [Agent access (MCP)](docs/MCP.md) — give an AI agent access to one notebook.
- [Notebook export](docs/EXPORT.md) — export a notebook as a zip.
- [Restore](docs/RESTORE.md) — restore KyNotes from a recovery capsule.
- [Logging](LOGGING.md) — the structured, privacy-safe log format.
- [Key strength](docs/STRONG-CRYPTO.md) — key sizes KyNotes accepts and the Go TLS profile.
- [Verifying releases](docs/VERIFYING-RELEASES.md) — check a release image's signature and source.
- [Assurance case](docs/ASSURANCE-CASE.md) — threat model, trust boundaries, and why the security requirements are met.
- [Design](DESIGN.md) — how the zero-knowledge note service is built.
- [Contributing](CONTRIBUTING.md) — how to propose a change and what it must pass.
- [Security policy](SECURITY.md) — how to report a vulnerability privately.
- [Release notes](CHANGELOG.md) — what changed in each release, and its upgrade impact.
