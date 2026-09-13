# Restore KyNotes

A capsule contains the metadata database, original deployment secrets, recovery public
key, effective configuration, and blob inventory. Note-version ciphertext and attachment
ciphertext live in the blob store and are **not in the capsule**. Full recovery also needs
a ciphertext blob mirror or the original blob directory. Database integrity alone does
not establish that notes can be read.

The `docker compose` commands below use the base file alone, which runs the published
image. If this server was installed from source, `COMPOSE_FILE=docker-compose.yml:docker-compose.build.yml`
must be in `.env` (the README install step writes it); otherwise a restore silently pulls a
different binary than the one you built and are running. A published-image install reuses the
image already on the host; run `docker compose pull` first to restore onto the newest attested one.

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
tampered ciphertext. It verifies the authenticated recipe, table counts, active admin,
original secrets, key pin and blob inventory. It relocates `data_dir` in the restored
`kynotes.yaml` and revokes every restored web session. Failure after extraction leaves
the target for inspection; preserve it and use another empty target for another attempt.

For Docker, use the exact tested image and a writable target owned by the invoking user:

```bash
mkdir -m 700 "$PWD/recovery-work"
docker run --rm -i --user "$(id -u):$(id -g)" \
  -v /absolute/path/KyNotes.kycap:/input/capsule.kycap:ro \
  -v "$PWD/recovery-work:/restore" kynotes-server:tested \
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
revoked. Verify account access, device envelopes, a decrypted note and an attachment
in a trusted browser. Confirm the original recovery key ID and issuer before depositing.
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
retrieves note-version and attachment ciphertext from a local mirror, checks session revocation, and exercises occupied target, missing shares, tampering and
foreign-service refusal. `go test ./internal/backup` proves WAL snapshot and opened-recipe
checks. These are code/fixture proof; they do not claim access to real custodian cards or
prove a deployment's remote blob coverage.
