# KyNotes ciphertext blob mirror (Plan C, reconciled)

This plan supersedes the original copied-transport sketches. The binding execution order
is [Myslop 290 execution](2026-09-05-kynotes-myslop-290-execution.md): auth, capsules,
then this mirror. Both note-version and attachment ciphertext require replication.

- Reuse `github.com/Busness-app/ky-primitives/offsite@v0.1.0` (nested repository tag
  `offsite/v0.1.0`); no transport fallback copies or new transport interfaces.
- Map `backup.blob_target` and six environment settings onto shared `offsite.Config`.
  Production requires a verified SFTP fingerprint; the rejecting CLI probe can discover it.
- Migration 0015 owns per-digest replica acknowledgements for one destination. Include
  endpoint/bucket/prefix and account-relative namespace/host identity in its target key.
- Stream Sync from the supplied capsule snapshot inventory and Fetch from restored DB
  inventory. Record only success, verify existing SMB content, close readers, abort
  partial staging, and verify source and fetched size/hash. Never delete remote history.
- Expose offline `mirror-blobs`, `fetch-blobs`, `test-blob-target` with `--config PATH`;
  admin mirror action/status and capsule-triggered mirroring share existing service locks.
- Preserve independent capsule and mirror outcomes. Missing objects differ from unavailable
  targets. Snapshot/GC timing gaps and the 16-minute retry budget are explicit limitations.
- Verify local/SFTP round trips, target changes, retry, corruption/interruption, GC races,
  data over the capsule member cap, and synthetic capsule-plus-blob restore. Run repository
  race/build/vet/fuzz/probe/vulnerability checks and frontend tests/build before delivery.

Implementation and operator instructions live in `internal/mirror/AGENTS.md`,
`docs/DEPLOYMENT.md` and `docs/RESTORE.md`. Live deployment and real custodian proof
remain distinct from synthetic fixture checks; merging remains a human decision.
