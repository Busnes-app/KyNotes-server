# Blob storage

## Purpose

Own opaque blob streams, single-volume compatibility and the tenancy blob seam.

## Ownership

- `Backend`/`Temporary` are the product's storage seam; they do not expose filesystem handles.
- `Store`/`Temp` retain the single-tenant volume implementation and paths.
- Key helpers own validation of org/blob/part path components.
- `VerifySharedIdentity` owns N15 control-file identity/probe decisions; the real object adapter
  binds its read/create-exclusive callbacks only through the shared primary-object client.

## Local Contracts

- Single mode always constructs the volume store; volume prefix purge is unsupported.
- No hosted-volume fallback, private S3 signing/client copy or speculative shared-client interface.
- Conditional control-object creation must publish complete contents atomically and return
  `fs.ErrExist` for an existing key. Marker/probe I/O never runs under the global writer lock.
- A refused replica never advances `blob_probe`; a CAS loser must read the winner's probe.
- Retry a missing probe only when the database pointer changed, at most three times.
- Retired-probe metadata uses database time. Never remove a current probe or one retired under
  an hour ago; actual object cleanup remains with the primary backend/worker adapter.
- Restore retains `blob_store_id` and clears ephemeral probe pointers.
- The local control-file test fixture is not a production shared-volume backend.

## Work Guidance

- Keep the existing ciphertext hashing, size checks, seekable reads and abort behavior.
- Bind org keys only from verified/resolved org identities, never from an arbitrary request field.

## Verification

- `go test -race -count=1 ./internal/blobstore`
- PostgreSQL CI runs `TestReplicaStoreIdentity*` against isolated schemas.
- The full HTTPAPI suite and `TestSingleTenantUpgradeGolden` pin existing behavior.

## Child DOX Index

None.
