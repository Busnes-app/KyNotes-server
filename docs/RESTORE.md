# Restore KyNotes

A capsule contains the metadata database, original deployment secrets, recovery public
key, effective configuration, and blob inventory. Note-version ciphertext and attachment
ciphertext live in the blob store and are **not in the capsule**. Full recovery also needs
a ciphertext blob mirror or the original blob directory. Database integrity alone does
not establish that notes can be read.

This runbook runs the image directly with `docker run`, so Compose and `COMPOSE_FILE` do not
apply here. Restore with the image you actually run: `kynotes-server:local` for a source install
(built by the `COMPOSE_FILE` step in [deployment](DEPLOYMENT.md)), or the published image pinned
by a digest you have verified with `gh attestation verify` (recipe in `docker-compose.yml`).
Do not restore onto a floating `:latest`: a restore is the one step where the binary must match
the data.

## 1. Preserve the source and prepare an empty target

Stop the damaged deployment, preserve its entire volume separately, and keep the old
issuer, recovery fingerprint, capsule receipt and image revision. Download the capsule
using the KyRecovery operator account; the product deposit token cannot download it.
Compare the capsule ID, digest and deposit time with the recorded receipt. Work in a
private directory outside `/tmp`. Never replace the only old volume during a drill.

```bash
mkdir -m 700 "$PWD/recovery-work"
sha256sum /absolute/path/KyNotes.kycap
kynotes-server restore --in /absolute/path/KyNotes.kycap --to "$PWD/recovery-work/restored"
```

Enter the required custodian shares, one per line, directly on stdin; finish with EOF
(Ctrl-D). Shares are never command arguments, environment variables, chat messages or
shared files. A duplicate share is not another custodian. Use synthetic shares for
routine automation; testing real cards is a separate custodian-supervised operation.

The command refuses a nonempty target, wrong service, insufficient/invalid shares and
tampered ciphertext. It verifies the authenticated recipe, table counts,
original secrets, key pin and blob inventory, and reassembles a database that a large server
split into ordered members (`kynotes.sqlite.000`, `.001`, ...) before checking its integrity.
A capsule from a server with no active administrator still restores; the command says so and
names `kynotes-server user add --admin` to create one. It relocates `data_dir` in the restored
`kynotes.yaml`. In one transaction it revokes every restored web session, paired device,
share link and sealed share link, and deletes pending invitations, so nothing revoked after
the snapshot comes back; account encryption identities are kept. It also turns scheduled
deposits off and prints that it did, so a drill or a second host never deposits to KyRecovery as
the original service: Backups shows the schedule off until the administrator turns it back on
once this server is the one in service. Failure after extraction leaves
the target for inspection; preserve it and use another empty target for another attempt.

For Docker, use the image you run (see the note at the top) and a writable target owned by the
invoking user:

```bash
IMAGE=kynotes-server:local   # or ghcr.io/busnes-app/kynotes-server@sha256:<verified digest>
mkdir -m 700 "$PWD/recovery-work"
docker run --rm -i --user "$(id -u):$(id -g)" \
  -v /absolute/path/KyNotes.kycap:/input/capsule.kycap:ro \
  -v "$PWD/recovery-work:/restore" "$IMAGE" \
  restore --in /input/capsule.kycap --to /restore/restored
```

The restored configuration names the path seen by the restore process. For a later
container mounting the recovered directory at `/data`, set `KYNOTES_DATA_DIR=/data`.
Keep the other restored settings. Remove stale secret overrides from the deployment
or make them equal to the recovered secrets; an override takes precedence over files.

## 2. Restore ciphertext blobs

Preserve the snapshot's `blob-inventory.json`. Obtain every digest recorded in its
`blobs` table from the original store or matching mirror, then run:

```bash
kynotes-server fetch-blobs --config /absolute/path/restored/kynotes.yaml
kynotes-server integrity-check --config /absolute/path/restored/kynotes.yaml
kynotes-server consistency-check --config /absolute/path/restored/kynotes.yaml
```

`fetch-blobs` reads the restored database inventory and the restored mirror settings,
ignoring historical replica acknowledgements. It verifies size and SHA-256 before
publishing each recovered file, skips intact local files, and repairs corrupt ones.
A nonzero exit means incomplete recovery: `missing` counts absent remote objects;
other failures mean transport, credentials, local I/O or digest verification failed.
An unavailable target is not evidence that its objects are missing. Fix the cause and
retry; intact recovered blobs are skipped. Never start with unresolved missing content.
If no mirror exists, copy the original ciphertext `blobs/` directory into the stopped
restored target, then run the same checks. Never upload the plaintext directory copy
to a ciphertext-only mirror target. Preserve the source and remote history during recovery.

## 3. Start and check identity

Start from the recovered volume and configuration. Log in again; old sessions are
revoked. Pair devices again, re-create share links and re-send invitations. Verify account access, device envelopes, a decrypted note and an attachment
in a trusted browser. Confirm the original recovery key ID and issuer before depositing, then turn the
schedule back on under Backups.
A successful deposit is recorded with capsule ID, digest, receipt time and local result.
Do not re-pair simply to hide a failed token-decryption or key-pin check.

Deployment secrets are restored unchanged: **do not rotate the server salt key** as a
recovery step; it derives login salts and opens the paired recovery token. Preserve the
pairing secret and device envelope material too. This release has no safe bulk key-
rotation command. Rotate a compromised KyRecovery credential through product Unpair,
KyRecovery-admin revoke, then pairing to the same pinned key. Real credential changes
must follow their owning provider's procedure, not direct edits to encrypted rows.

## Proof

`go test ./cmd/kynotes-server -run TestRestoreCapsuleWithStdinSharesPreservesLoginAndRevokesSessions`
runs an actual synthetic 2-of-3 restore, verifies the original login verifier and secrets,
retrieves note-version and attachment ciphertext from a local mirror, checks revocation of sessions, devices, share links and invitations, and exercises occupied target, missing shares, tampering and
foreign-service refusal. `go test ./internal/backup` proves WAL snapshot and opened-recipe
checks. These are code/fixture proof; they do not claim access to real custodian cards or
prove a deployment's remote blob coverage.


## Cleanup-slot upgrade preflight

Migration 0031 must fund future comment-deletion and sealed-link-revocation audit
slots within the existing backup budget. Startup runs the conversion in a private
copy before changing the live schema/data; if it cannot fit, it refuses the
upgrade with the budget/required bytes and source counts. Keep a stopped-server
pre-upgrade data-directory copy and the old release. Reduce unneeded pages,
notebooks or share links using that release, then retry; do not bypass migration.
New capsule recipes count cleanup slots and ordinary audits, and restore checks
their counts and pending-source bindings. See [cleanup capacity](CLEANUP-CAPACITY.md).

If a capsule restore reaches that capacity refusal, its extracted target is left
with snapshot credentials revoked and scheduled deposits off, preserving the
legacy data for cleanup with the old release. If those safety steps fail, do not
start any release on that target; restore into a fresh target using the release
that wrote the capsule. Ordinary startup refusal leaves the original instance's
credentials and schedule unchanged.


## Back up and restore PostgreSQL in multi mode (tenancy preparation)

Hosted startup is still refused in this release. `pg-backup` and `pg-restore` are the
multi-mode database transport (tenancy open question 3). They have no 256 MiB capsule limit.
Both read the database URL from `KYNOTES_DB_DSN` and the backup key from
`KYNOTES_PG_BACKUP_KEY_FILE`, a regular file holding 64 hex characters (32 random bytes, e.g.
`openssl rand -hex 32`). Keep the key apart from the archives: without it no archive opens,
and with it every archive does.

```bash
kynotes-server pg-backup --out /backups/kynotes-2026-11-25.pgb
```

The backup reads every table in one `REPEATABLE READ` snapshot of the live database, so the
`blobs` rows (the org-qualified object references) agree with the notes that use them. The
archive is sealed in AES-256-GCM frames; a changed, reordered, cut or extended archive does
not open. The file must not exist yet and is removed if the backup fails. Ciphertext objects
are not copied: GC deletes an object only after `gc.retention` with no reference, so keep no
archive you mean to restore longer than that retention (default 168 h). No command checks
blob coverage yet; confirm the referenced objects exist before a hosted release serves.

To restore, stop **every** replica, create a new, empty database and run the release that
wrote the archive:

```bash
kynotes-server pg-restore --in /backups/kynotes-2026-11-25.pgb --confirm-stopped
```

It creates this release's schema, refuses a target that holds any data or another schema
version, and loads every row in one transaction together with the restore fence described
below (revocations, deposits off, orgs stale). It also writes the replay gate: until the elected worker
has read the org and erased-subject feeds from zero and found nothing more, no customer org
serves, so every erasure and org deletion since the backup is applied again before anyone is
served. The worker then purges the deleted orgs again. If anything fails, nothing is loaded.

## Prepare a native PostgreSQL restored target (tenancy preparation)

Hosted startup is still refused in this release. This command prepares a database restored
by a separate native PostgreSQL recovery procedure; it neither recovers backup bytes nor
establishes blob coverage or hosted readiness. The tenancy spec's large-database backup
transport remains open question 3. Do not substitute a SQLite capsule or a private S3 client.

1. Keep the original deployment preserved. Stop **every** replica of the restored target.
2. Recover into a separate PostgreSQL database using the selected native backup procedure.
   Retain the original deployment secrets, recovery pin and object-store identity.
3. Use the exact KyNotes release matching that database schema. Provide its target URL in
   `KYNOTES_DB_DSN` through your protected environment file, never a command argument:

   ```bash
   kynotes-server prepare-postgres-restore --confirm-restored
   ```

The command refuses an uninitialized, older/newer or single-mode target without migrating it.
One transaction revokes web sessions, paired devices, share/sealed links and pending invitations;
keeps encryption identities; turns scheduled deposits off; makes customer orgs stale at revision
zero; clears old grants, directory cursors, replica ephemeral state and probe pointers; and
records a platform audit. It also writes the replay gate described above. Erasure fences, permanent store ID, keys and sealed recovery pairing
remain. A schedule/audit/reset failure rolls everything back: keep the target stopped, fix the
cause and repeat with its matching release.

Before a future supported hosted release serves the target, reconcile the complete org and
erased-subject feeds from zero, re-purge/re-erase their notices, verify every required ciphertext
object and the shared store identity, then verify staff access and restore tasks. An org absent
from the full listing remains stale and unserved. Turn deposits back on only after verifying
which deployment is authoritative. This preparation command never lifts the startup refusal.
