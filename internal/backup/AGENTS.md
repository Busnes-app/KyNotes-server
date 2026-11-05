# Purpose

KyNotes adapters over `ky-primitives/recoveryclient`: collection, verification,
service operations, blob mirror orchestration, and audit. Shared transport and capsule mechanics stay in the library.

# Local Contracts

- Capsules carry `kynotes.sqlite`, effective secrets, `recovery.pub`, configuration,
  and blob inventory. A snapshot over `capsule.MaxFileBytes` is split into ordered members
  `kynotes.sqlite.000`, `.001`, ... (`partBytes`); `Checks` accepts both recipe shapes, refuses
  any other order and reassembles the parts into `kynotes.sqlite` before its integrity check
  (restore and drill alike). A capsule over `capsule.MaxExpandedBytes` fails as
  `database_too_large`; `Status` reports `database_bytes` and `capsule_limit_bytes`, and Backups
  warns at 80%. ky-primitives limits stay unchanged. Verify `TestLargeSnapshotIsSplitAndReassembled`.
  Sealing and drilling hold the snapshot several times in memory (measured peak 1.55 GB for 250 MiB of
  incompressible data with `GOMEMLIMIT=1536MiB`), so `docker-compose.yml` caps the container at 2g, not 512m.
- Capsule restore revokes extracted-target credentials and turns deposits off even
  when cleanup-capacity migration refuses; a failed safety step forbids starting that
  target. Ordinary startup refusal preserves the original instance.
- Capsule restore turns scheduled deposits off (`DisableSchedule`) and says so; the administrator
  turns them back on (`TestRestoreCapsuleWithStdinSharesPreservesLoginAndRevokesSessions`). Note-version and attachment blob bytes are recovered separately.
- New recipes count `audit_events` and `cleanup_audit_slots` when present; restore
  verifies both counts and live-source pending slots. Legacy recipes remain readable.
  Read `../../docs/CLEANUP-CAPACITY.md` when changing cleanup metadata or its restore checks.
- Snapshot the live SQLite handle. Collect recipe counts and inventory from that snapshot.
  Capsule-triggered mirroring receives that exact inventory even if live GC removed rows.
  Capsule and mirror results are independent; a receipt never proves blob coverage.
- `TokenLabel` and effective deployment secret bytes are compatibility contracts.
- Service operations serialize pin/pair/run/export/drill; CLI takes the same directory
  lock as the server, or runs `deposit`/`backup-drill` in it over `admin.sock` when it is up. Close waits for bounded operations before SQLite closes.
- Export uses POST with admin, step-up and CSRF; a GET cannot trigger collection.
- HTTP deposit ("Back up now") needs admin and CSRF only, like the rest of the Ky suite: it seals to the
  already-pinned key and destinations, so it cannot redirect or reveal data. Every other backup mutation
  keeps step-up. Verify `TestBackupDepositNeedsAdminNotStepUp`.
- Pinned recoveryclient v0.5.1 stamps attempts before checking key/destination or collecting.
  An enabled schedule with no attempt is due immediately, without comparing two clocks.
  Failure-schedule tests cover remote/local failures, missing key/destination and restart.
- Audit uses stable codes and safe metadata; an unaudited export returns no bytes.
- `Checks` validates the opened manifest and requires all fixed files, tables, counts,
  usable secrets, recovery pin, and matching blob inventory. A missing active admin passes
  with a note naming `user add --admin`.
- Only `cmd/kynotes-server/backup.go:restoreCapsule` may open suite capsules or combine
  shares. Drills use library-generated throwaway keys and protected scratch.
- `ApplySetup` claims a pairing code only when the instance is not paired (a hand-pinned
  key alone still claims; a different returned key is a conflict and the code is spent),
  never re-pins a key, and sets the interval only when no admin setting exists. Dir and
  keep are env-fixed and only compared.

# Verification

`go test -race ./internal/backup ./internal/storage ./internal/httpapi ./cmd/kynotes-server`
proves snapshot, token compatibility, destination outcomes, route hardening, synthetic
restore, and decrypt boundary. Prove the guard once per boundary change by planting a
forbidden production call and removing it after the expected failure.
