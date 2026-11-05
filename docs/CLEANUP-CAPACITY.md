# Cleanup capacity and upgrade

Comment and share-link admission retains the server-wide limit of 90% of
`capsule.MaxExpandedBytes` (256 MiB). The remaining ten percent covers other
database records and capsule members; sealing still enforces the actual library
limits. This is separate from owner/team content quota.

## Future audit storage is allocated on creation

Migration 0031 adds `cleanup_audit_slots`. Every live comment and unrevoked sealed
link has a pending slot. Its source ID, audit ID, kind and container are immutable.
The payload is a fixed-size BLOB containing `null` plus spaces until cleanup,
encoded in the database's UTF-8/UTF-16 encoding so SQLite's BLOB-to-TEXT cast
interprets the same JSON. UTF-16 slots double the conservative encoded-byte bound;
their fill preserves exactly the original physical byte length. Restore checks
decode those bytes before checking UTF-8 request-ID lengths.
Slot size covers the maximum existing user-ID byte width (at least minted 30),
128 request-ID bytes, a 20-character operation timestamp, JSON syntax and six-byte
escaping; it rounds up to 64 bytes. Ordinary UTF-8 slots are 1024 bytes before SQLite/index
overhead. This is a size calculation, not a guaranteed comment count capacity.

Deletion/revocation fills only that BLOB, in the same immediate transaction as
authorization and source changes. No new ordinary audit row or mutable actor/time
index entry is inserted. Completed slots are immutable. Pending slots disappear
when their source is physically removed; completed records survive it.
`audit_history` merges them with unchanged `audit_events`, hides pending slots,
and orders the administrator's view by operation time then audit ID. A slot's
mint time is not the event time.

Trusted proxy request IDs are stripped of CR/LF and accepted up to128 bytes.
Longer IDs are replaced with the normal generated request ID, echoed and audited;
the request itself is not rejected. Untrusted peers keep the generated-ID rule.

## Source rows must fit their existing leaf cells

Comments and containers initially receive 64 zero-padding bytes, sealed links 40.
This funds timestamp and counter growth, including legacy UTF-16 databases.
The cleanup code measures strings in the database encoding and signed counters
in SQLite's actual serial widths. Container padding retains the unspent future
counter/timestamp reserve.

Shrinking a record alone is insufficient. SQLite table-leaf payloads above
`usable_page_bytes-35` spill to overflow pages. A smaller replacement crossing
that threshold can put nearly a page back into an already crowded leaf. Cleanup
therefore chooses the smallest padding for which **both the on-leaf cell and the
overflow-page count do not increase**, with total payload no greater than before.
Record-header and payload-varint widths are included; rowids and indexed keys
stay unchanged. The candidate search is bounded by one usable page plus 18 bytes
beyond the remaining mandatory reserve. It reads the SQLite page header through
the pinned driver's read-only `sqlite_dbpage` table; it does not write raw pages.

Comment ciphertext becomes empty and content quota is released immediately.
At most one page plus 18 bytes of layout padding remains in its tombstone; an
entire large ciphertext is never replaced by equal-length zeros. Whole overflow
pages become reusable. A small comment may leave the same physical page count:
its tombstone and the permanent audit history still take space.

This argument depends on the pinned SQLite file format and insert behavior:
`sqlite3BtreeInsert` overwrites equal-size payloads; otherwise `dropCell` and
`insertCellFast` reuse the old cell's space, and balancing is required only if
an overflow cell remains. The replacement's cell fits the space it releases,
and its overflow chain uses no additional pages. Secondary index keys are
unchanged. Recheck this boundary when upgrading the SQLite dependency or changing
the source tables, their column types or cleanup indexes.

## Existing instances and restore

Before changing a legacy database, startup makes a private snapshot and runs all
pending migrations there. It allocates slots for all live comments and every
unrevoked sealed link, including expired/orphaned liabilities, and materializes
source padding. Capacity is decided using actual nonfree pages, not a logical
byte multiplier. The live migrations then recheck and commit together.

If the conversion cannot fit, startup refuses the upgrade before changing the
live schema/data, reports the required bytes/budget and source counts, and removes
the staged copy. A capacity refusal during capsule restore is different from
ordinary startup: the extracted target's credentials are revoked and its deposits
turned off even when migration refuses, before an operator can run the old release
on it. If that safety work fails, the error explicitly forbids starting the target.
The original running instance is never changed by this restore refusal.
Keep the old release available: use its existing page/notebook
and share-link cleanup to reduce the dataset, then retry. Do not bypass the
migration or increase capsule limits. Make a pre-upgrade data-directory copy
with the documented stopped-server `copy-data-dir` workflow first.

Backup recipes count ordinary audits and cleanup slots when present. Restore
checks their counts and pending-source invariants. Older recipes/databases retain
their existing restore path and undergo the staged migration before normal use.

## Executable evidence

- `TestCommentDeletionDoesNotGrowAtSQLiteOverflowCliff`: authenticated real DELETE,
  a crowded legacy wide-ID row at the spill boundary, actual nonfree pages and
  `recoveryclient.SQLiteSnapshot` (`VACUUM INTO`) before/after.
- `TestCleanupRowsReleaseOverflowWithoutGrowingLeafCells`:512/4096/65536-byte
  pages and UTF-8/UTF-16 encodings (asserted after opening the active database),
  header/counter/body-width boundaries, forward,
  reverse and deterministic permuted deletions, checking each partial snapshot.
- `TestCleanupRecordSizeMatchesSQLite`: compare record sizing with actual `dbstat`
  payloads, Unicode encodings and signed-integer/header boundaries.
- `TestCleanupReservationKeepsCompactSnapshotsWithinBudget`: actual creation to 507,
  real authorized deletion/retry at full ordinary capacity, then renewed admission.
- `TestCleanupUpgrade*`, `TestCleanupSlotFixedOverwriteIsImmutableAfterCommit`,
  `TestCleanupHistoryUsesOperationTimeAndSurvivesSourceRemoval`,
  `TestCommentDeletionAuthorityAuditAndRollback`,
  `TestCommentDeletionAuditUsesTheBoundedReplyRequestID`, and
  `TestCapsulePreservesCleanupHistoryAndPendingReservations`.

These cover the named cleanup paths. Other metadata writes can still grow the
database; this change does not claim a bound for all possible server operations.

- `TestCapacityRefusedRestoreStillRevokesCredentialsAndStopsDeposits`: an authentic
  custodian-opened schema30 capsule with250000 tiny comments that cannot fund
  new slots; preserves legacy contents and the source instance while fencing the
  extracted target's sessions, devices, links, invitations and scheduled deposits.
- `TestNativeUTF16CleanupIsAuthorizedAuditedAndSizeStable` and
  `TestCleanupUpgradeAndHistoryUseTheActualDatabaseEncoding`: verified native
  files, migration, real authorized DELETE and administrator audit reads.

The initial fixture labels did not establish physical encoding/page sizes. Their
old passing logs are historical; use the asserted-layout regressions above.
