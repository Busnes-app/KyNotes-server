# Blob storage

## Purpose

Own opaque blob streams, single-volume compatibility and the tenancy blob seam.

## Ownership

- `Backend`/`Temporary` are the product's storage seam; they do not expose filesystem handles.
- `Objects` owns the prepared per-org permanent ciphertext and numbered upload-part I/O
  through the exported shared S3 client. It is not yet the complete `Backend`/`Temporary`
  runtime adapter: exclusive control creation, age metadata and route wiring remain gated.
  `storage.RunObjectGC` and the purge's prefix step call it from the elected worker.
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
- `Objects` callers authorize/bind the org before construction. Hold the org/digest session
  lock through PUT/claim or reference-drop/DELETE, and the upload lock through part/counter
  updates. Object I/O never holds N3; one pinned connection serves each short claim transaction.
- Treat object/part GET bytes as opaque even with provider Content-Encoding metadata. The
  shared client must request identity encoding so GET/HEAD lengths and ciphertext hashes agree.
- Bound transfers by configured maximum and declared size. Hash permanent ciphertext before
  publishing seekable bytes; every private file is 0600 and removed on Close/error. No persistent
  content cache or storage fallback. Identical writes reuse verified bytes; parts remain live
  until explicit post-commit/cancel/expiry cleanup. Tail removal validates every index first.
- Delete/Purge are explicit unreferenced-key/org erasure, including physical versions/markers.
  No scheduled pruning or orphan deletion is enabled. Unknown-object cleanup needs provider age
  proof; store-ID creation still requires the shared client's create-exclusive operation.
- New shared-client dependencies must point to its reviewed upstream implementation, with no
  copied signing/transport or invented client contract. Provider qualification is separate from
  the local TLS S3 wire fixture.

## Work Guidance

- Keep the existing ciphertext hashing, size checks, seekable reads and abort behavior.
- Bind org keys only from verified/resolved org identities, never from an arbitrary request field.

## Verification

- `go test -race -count=1 ./internal/blobstore`
- `TestObjectGC*`/`TestPurgeDeletesOnlyTheDeletedOrgsPrefix` drive storage's GC and purge through
  the real shared client on PostgreSQL.
- `TestObjects*`/`TestObjectParts*` use the actual shared client and a local verified TLS fixture.
- PostgreSQL CI runs `TestReplicaStoreIdentity*` against isolated schemas.
- The full HTTPAPI suite and `TestSingleTenantUpgradeGolden` pin existing behavior.

## Child DOX Index

None.
