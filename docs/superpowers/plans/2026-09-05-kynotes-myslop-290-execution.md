# KyNotes: authentication repair, recovery capsules, and blob recovery

**Repo:** kynotes-server
**PRs:** #7 auth, #8 capsules; blob mirror branch awaiting its PR. #6 is the merged prerequisite.
**Worktrees:** `.claude/worktrees/sso-verification`, `kyrecovery-deposit`, `blob-mirror`. Original master and existing worktrees preserved.

Prepared 2026-09-05 for Myslop #290. Owner: `copperfinch`, claimed in #297 in
`kynotes-kyrecovery-deposit`. Implementation authorized by Yoshi after claim and planning.

## Starting point and precedence

Fetched `origin/master`: `f136cb4b99063a14add81244529d8b82b06f7dec`.
Local master remains `ec27a92`; existing untracked `docs/superpowers/` and locked
`feat/adopt-ky-primitives` worktree remain untouched. Plan A has merged: settings,
snapshot, secrets, audit outcome, step-up, and backup configuration prerequisites exist.
That starting revision had no `internal/backup` package or recoveryclient integration.

This is the execution entry point for #290. For this work it supersedes conflicting
API, dependency, sequencing, and transport-copy instructions in the older
[Plan B](2026-09-04-kynotes-kyrecovery-backup.md) and
[Plan C](2026-09-05-kynotes-blob-mirror.md). Retain those documents as task references;
reconcile the relevant document in its implementation PR. Their embedded API listings
are historical, not specifications. No additional agent framework is needed to execute.

Follow parent and owning AGENTS.md, DESIGN.md, and frozen Phase 0 contracts in
IMPLEMENTATION_PLAN.md. Change a frozen contract only with the required design/plan
updates in the same PR. The wire authority is the KyRecovery repository's
`zero_code_pairing_handoff_spec.md` v2.0.0. KySignOn's current `internal/backup`,
backup handlers, and `docs/RESTORE.md` are the reference adapter and runbook.

## 0. Prepare an isolated implementation branch

- [x] Recheck Myslop ownership and new posts, fetch origin, and inspect worktree/status.
  Create `fix/sso-verification` in an unused worktree from fetched master; preserve
  existing plans and locked worktrees. Carry this plan into the implementation branch.
- [x] Read current owning docs and the shared-library handoff's reviewer findings.
  Resolve APIs against the tagged sources with `go doc`, not sibling working-tree HEAD.
  Use `github.com/Busness-app/ky-primitives@v0.5.1`; local tags include this release.
- [x] Establish the existing test baseline and record the source SHA. Keep existing
  issuer configuration, accounts, device data, deployment keys and token formats.

Done when the branch and baseline are recorded and prerequisite changes are present.

## 1. PR: verify SSO tokens and directory events

Files: `internal/sso/sso.go`, its tests, `internal/httpapi/sso_routes.go`, SSO route
tests, and the owning documentation. Add a migration only if required by replay storage.

- [x] Replace `ParseClaims`' unverified JWS decoding with a reusable
  `oidcverify.Verifier.VerifyWithNonce`. Bind configured issuer, client audience, and
  trusted discovery JWKS URL. Add an independently random nonce to the PKCE login
  transaction and authorization request; validate and consume the transaction in the
  callback. Exercise all three existing login/callback route aliases.
- [x] Require a verified ID token before account/session mutation. If userinfo remains
  for profile enrichment, require its subject to equal the verified subject; it must
  not rescue a failed token or substitute an identity. Keep verifier caching scoped to
  issuer/client settings so reconfiguration cannot reuse the wrong trust context.
- [x] Trace subject lookup, username adoption, provisioning, and role assignment.
  Preserve established subject links. Reject conflicting subject rebinding; require
  explicit authenticated linking or trusted directory provisioning for adopting a
  local username. Test disabled users, auto-provision-off, username collisions, and
  database failures. Do not treat every SQL error as a missing user.
- [x] Replace body-only HMAC with `syncauth.Middleware` on every webhook alias. Load
  the configured secret without changing its byte representation. Dispatch using the
  verified event metadata and reject conflicting payload ID/type. Bound request bodies,
  reject missing/stale metadata and unavailable secrets, and propagate application errors.
- [x] Wire one shared replay guard across aliases and requests. Prove duplicate events
  cannot repeat mutations. Before selecting persistence, inspect library admission
  timing versus transaction failure and sender retries; choose an explicit recovery
  path for a verified request whose database application fails. If using the bounded
  memory guard, document its restart limit with `ponytail:` and the persistent upgrade
  path; do not claim restart-safe exactly-once delivery.

Acceptance: TLS test issuer/JWKS and a real library-signed webhook succeed end to end;
forged/unsigned tokens, wrong issuer/audience/nonce, expiry, unknown key, altered body,
missing or mismatched event metadata, replay, and account collisions fail before an
unauthorized mutation. Reconfiguration and signing-key refresh have runnable coverage.
Existing password login, device unlock, and SSO account flows continue to pass.

## 2. PR: Plan B sealed capsules and restore

Stack on the authentication repair for review; merge in dependency order. Reconcile Plan B to v0.5.1; remove obsolete
wait conditions. Reuse recoveryclient through product adapters, keeping transport,
pairing, retention, and schedule implementations in the library.

- [x] Add `internal/backup` settings/sealer glue, collector, shared service, drill
  checks, and decrypt guard. Reuse `storage.ErrNotFound`, the live database snapshot
  adapter, current config, and audit outcome helper. Fix shared audit ownership only
  as needed for HTTP, CLI, and scheduled callers.
- [x] Seal a live SQLite snapshot, all effective deployment secrets (including values
  supplied through config rather than files), `recovery.pub`, and restore/config
  metadata. Refuse missing keys and oversized payloads before claiming success.
  Keep secret material inside the sealed payload and out of public recipe metadata.
- [x] Inventory every blob referenced by the snapshot. Important correction from code:
  `object_versions.blob_digest` also references `blobs`, so excluded blob data can
  contain note-version ciphertext as well as attachments. UI/runbook coverage must say
  that database restore alone does not prove notes or attachments can be read. Keep
  all content-addressed blob payloads out of capsules and recover them in Phase 3.
- [x] Bind the token sealer to the existing deployment secret with a stable,
  domain-separated label. Test stored token restart compatibility and wrong-key/label
  refusal. Keep `service_name` exactly `config.AppName` (`KyNotes`) through claim/seal.
- [x] Implement pin, pair, unpair, schedule, status, export, run and drill operations.
  One run seals once and attempts every configured destination. Preserve digest-checked
  receipts and independent local/remote results. Retention is at least one; interval is
  off or 900 seconds through the library upper bound, counted from the last attempt.
  Missing key or destination is an explained precondition error. Lost pinned key on
  a previously paired instance is an audited failure, not an unpaired skip.
- [x] Wire `internal/httpapi/backup_routes.go`, CLI, and `internal/app/serve.go`.
  Admin reads require sessions/roles; mutations require admin, CSRF and step-up.
  Resolve the acting admin before asynchronous work. Export requires a successful
  audit. Apply bounded operation contexts and the deposit write deadline; shutdown
  must wait for active work before closing its database. Serialize competing drill
  entry points under the same data-directory ownership rules.
- [x] Add `backup-drill`, `export-capsule`, `deposit`, and sealed `restore` commands.
  Label retained plaintext operations `copy-data-dir` and `restore-data-dir`, preserving
  stopped-server safety. Restore requires an empty target, expected service and shares
  on stdin. It must not print keys or silently regenerate missing deployment secrets.
- [x] Build the admin backup screen from existing UI patterns: key, remote, local and
  schedule facts; action row; schedule form; pairing/unpair; key-by-hand; coverage and
  precondition messages. Use existing step-up helper and rebuild checked-in embed.
  Preserve private-recovery opt-in and LAN DNS compose override.
- [x] Implement v0.5.1 drill callback
  `func(dir string, opened capsule.Manifest) []recoveryclient.Check`. Read the opened
  recipe, validate JSON list types and clean confined paths, and require every expected
  key/table/account check. Missing or malformed recipe fields must fail. Use protected
  scratch under the data directory and remove it afterward.

Acceptance: live-handle snapshot includes an uncheckpointed WAL row; synthetic
2-of-3 capsule restores required tables/accounts and original deployment secrets.
Exercise local-only backup, all destination outcomes, pin conflict, unpair retention,
schedule boundaries, audit failure, and malformed recipes. Prove the absolute-root
decrypt guard detects a planted forbidden `capsule.Open` call, then remove the probe.
Write and execute `docs/RESTORE.md` against a disposable fixture, including wrong shares,
wrong service, tampering, occupied target, and session revocation. Record code proof
separately from live deposit and custodian-card proof.

## 3. PR: Plan C ciphertext blob mirror and fetch

Start after the capsule/restore contract is stable. Reconcile Plan C's stale library
installation and remove its copied-transport fallback and obsolete parallel build order.

- [x] Add `github.com/Busness-app/ky-primitives/offsite@v0.1.0` (repository tag
  `offsite/v0.1.0`). Map product config onto `offsite.Config`; reuse `Parse`, `Key`,
  `Put`, `Get`, `Test`. Product config owns credentials; status and audits redact them.
- [x] Add the next unused migration for replica inventory, with digest foreign key and
  target identity. For the single configured target, a digest row may upsert the new
  identity after successful verification; query pending rows by the current identity.
  Test endpoint/bucket/prefix changes and credential changes separately. Inspect SFTP
  and SMB user-relative namespaces: `offsite.Key` strips userinfo, so product identity
  must distinguish changes of storage namespace where username affects the remote root.
- [x] Implement `internal/mirror` sync/fetch over every required blob digest. Reuse
  `blobstore.Open` to verify local source content and `Temp.Finalize` to validate fetched
  content. Use unique temporary IDs per transfer, close every Get reader, and abort
  interrupted/corrupt writes. A stat result alone does not establish digest integrity.
- [x] Record a replica only after successful transfer; for SMB `ErrObjectExists`, read
  and verify existing digest and size before counting durability. Failed row writes
  remain safely retryable. Report partial failures and distinguish absent remote data
  from an unavailable target. Keep remote deletion outside this change.
- [x] Wire mirror/fetch/test-target CLI, scheduled/manual runs, mirror-only admin route,
  status, and the additional blob coverage card. Keep capsule and mirror outcomes
  independently visible. Restore uses the snapshot's inventory even if its replica
  rows predate the mirror; replica rows are optimization, not restore authority.
- [x] Document config/env/compose settings, SFTP pin verification, library SMB limits,
  target identity, and capsule -> fetch-blobs -> consistency-check restore order.
  Explain backup timing gaps and retain a recoverable inventory if live GC races a run.

Acceptance: local and one remote target round-trip required blobs after capsule restore;
repeat run skips verified replicas; failures retry; target changes re-upload; corrupt
or interrupted transfers never finalize. Include a streaming fixture larger than the
capsule member cap (without changing production upload limits). Validate restored note
content and attachments in the browser where practical, not just database integrity.

## Gates and delivery

For each implementation PR run the repository's current CI: build, vet, gofmt, race
suite, all four 60-second fuzz targets from `.github/workflows/ci.yml`, Docker probe,
and govulncheck. For UI changes run `npm test` and `npm run build` in `web/` and verify
the committed `internal/web/dist` bundle. Update owning DOX documents and design/plan
contracts affected by the implementation. Obtain current-head reviewer clearance;
report exact tested SHA and any unperformed live proof before human merge.

Deployment proof uses the existing volume/issuer/keys/pairing. Verify readiness and
the same pinned key ID, successful deposit receipt (ID, digest, time), and local result.
For source builds use `up -d --build`; explicitly include the LAN DNS override when
needed. Compare recovery fingerprint out of band. First pairing is recorded as first
pairing. Synthetic restore proof can run autonomously; real custodian shares are entered
locally on stdin, never chat, argv, or the board. A remote target and custodian access
are prerequisites for those live proofs, not blockers to implementation or fixture tests.

## Execution checkpoint

Auth PR #7 at `ea7a6f5` and capsule PR #8 at `f3499d0` are pushed and CI green.
Mirror implementation is complete in `feat/blob-mirror`, pending its commit/PR and
final CI. Build, vet, gofmt, full race suite, vulnerability scan (zero reachable findings),
frontend tests/build and 12-step Docker probe pass. The four final 60-second fuzz runs
are in progress. Current-head autonomous reviewer clearance is still absent on #7/#8.

Fixture evidence includes signed OIDC/webhook refusal cases, synthetic 2-of-3 capsule
restore preserving login secrets and revoking sessions, local plus pinned SFTP blob
recovery, interrupted/corrupt transfer refusal, GC race reporting, and a streamed blob
over the capsule member cap. Browser proof covers password step-up, public-key pinning,
local capsule creation, synthetic drill, and encrypted note/attachment creation.

No production deployment or real KyRecovery deposit/custodian-card proof is claimed.
Those need the deployment target and custodian access. Merging remains a human decision.
The folder stays claimed by `copperfinch` while final checks and review are outstanding.
This checkpoint and reconciled Plan C are mirrored to Myslop before session close.
