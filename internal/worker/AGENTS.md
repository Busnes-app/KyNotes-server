# PostgreSQL scheduled worker

## Purpose

Elect one multi-tenant scheduler without an external coordination service.

## Ownership

- `Run` owns session-lock election, one-second connection probes, job cancellation and retry.
- The application owns schedule contents and drain ordering; single mode retains its app loops.

## Local Contracts

- Ownership lasts only while the pinned PostgreSQL session lives; session pooling is required.
- Jobs honor the owned context and tolerate interruption/retry. Election is not exactly-once.
- Heartbeats use the otherwise idle worker-lock connection. Request leases never run heartbeat
  SQL concurrently with their own transactions.
- Release a worker lock only after its job and heartbeat have drained.

## Work Guidance

- Use `storage.SessionLock`; do not add a lease table or another coordinator.
- Keep network work outside the global write transaction. Reminder delivery additionally claims rows.

## Verification

- `KYNOTES_TEST_DATABASE_URL=<isolated PG17 database> go test -race -count=1 ./internal/worker`
- `TestReplicaWorkerExclusionCancellationAndTakeover`
- `TestReplicaWorkerCancelsOnLostConnection` terminates only its schema-specific test lock session.

## Child DOX Index

None.
