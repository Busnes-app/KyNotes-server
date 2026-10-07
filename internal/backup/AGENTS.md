# Purpose

KyNotes adapters over `ky-primitives/recoveryclient`: collection, verification,
service operations, blob mirror orchestration, and audit. Shared transport and capsule mechanics stay in the library.

# Local Contracts

- Capsules carry `kynotes.sqlite`, effective secrets, `recovery.pub`, configuration,
  and blob inventory. Note-version and attachment blob bytes are recovered separately.
- Snapshot the live SQLite handle. Collect recipe counts and inventory from that snapshot.
  Capsule-triggered mirroring receives that exact inventory even if live GC removed rows.
  Capsule and mirror results are independent; a receipt never proves blob coverage.
- `TokenLabel` and effective deployment secret bytes are compatibility contracts.
- Service operations serialize pin/pair/run/export/drill; CLI takes the same directory
  lock as the server, or runs `deposit`/`backup-drill` in it over `admin.sock` when it is up. Close waits for bounded operations before SQLite closes.
- Export uses POST with admin, step-up and CSRF; a GET cannot trigger collection.
- Pinned recoveryclient v0.5.1 stamps attempts before checking key/destination or collecting.
  An enabled schedule with no attempt is due immediately, without comparing two clocks.
  Failure-schedule tests cover remote/local failures, missing key/destination and restart.
- Audit uses stable codes and safe metadata; an unaudited export returns no bytes.
- `Checks` validates the opened manifest and requires all fixed files, tables, counts,
  usable secrets, an active admin, recovery pin, and matching blob inventory.
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
