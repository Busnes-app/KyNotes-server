# KyNotes Server

KyNotes Server is a web-based note management app.
Please see the css directory and fonts directory for look and feel.

# Ponytail, lazy senior dev mode

Use the smallest correct change.

1. Reuse what already exists.
2. Prefer stdlib and native platform APIs.
3. Add dependencies only when they remove meaningful code.
4. Fix shared root causes, not one caller.
5. If a shortcut has a limit, mark it with `ponytail:` and name the upgrade path.

Non-trivial logic must include one runnable check (unit test or minimal self-check).

# DOX framework

## Core Contract

- AGENTS.md files are binding contracts for their subtree.
- Read from root to nearest AGENTS.md before editing.
- The nearest AGENTS.md controls local details; parent docs keep global rules.

## Update After Editing

- Run a DOX pass for every meaningful change.
- Update nearest owning AGENTS.md when behavior, responsibilities, or verification changes.
- Keep Child DOX Index entries current and delete stale rules.

## User Preferences

- Best-effort 90-second keyword refresh policy (foreground cadence; background catch-up on resume).
- DOX hierarchy scope is app-only.

## Design

- `DESIGN.md` is the current product and server architecture design.
- Keep implementation changes aligned with its encryption, sync, storage, and
  self-hosting contracts; update the design when those contracts change.
- `IMPLEMENTATION_PLAN.md` is the binding build order. Its Phase 0 contracts
  (module path, crypto formats, API and error schema, IDs, schema, limits) are
  frozen: implement them, do not re-decide them. Changing a frozen contract
  requires updating `DESIGN.md` and the plan in the same change.

## Verification

- CI (`.github/workflows/ci.yml`, `verify`) builds, vets, tests, runs the Docker probe and govulncheck on every push and pull request.
- On a push to `master` that passes every job, `publish` pushes the exact image the Docker check ran against (handed over as an artifact, no rebuild) to `ghcr.io/busness-app/kynotes-server:<commit sha>`, attests it and verifies the attestation pinned to this workflow on `master`; `promote` then moves `:latest` to that digest, only at the tip of `master`, and asserts the tag resolves to the attested digest. `docker-compose.yml` names the published image and never builds; source installs add `docker-compose.build.yml` to the `COMPOSE_FILE` chain in `.env` (overlay tags `kynotes-server:local`) so every compose command, recovery docs included, uses the local build.

## Child DOX Index

- `internal/httpapi`: opaque routing ciphertext, role-gated mutations, and
  device-validated envelope writes are covered by the package integration
  tests; password/OIDC login, password change, step-up, recover, device, pairing, and upload
  endpoints use in-memory token buckets. Upload retries are byte-checked, and preview uploads remain
  content-addressed without creating an attachment row. Admin settings/users,
  audit metadata, team membership, and encrypted comment reads/writes are
  session- and role-gated here.
- `internal/app` owns the `.kynotes.lock` data-directory lock and automatic first-run
  admin bootstrap (`first-run-password.txt` or `BOOTSTRAP_ADMIN_PASS`/`BOOTSTRAP_ADMIN_USER`);
  maintenance backup refuses to copy a live data directory and restore runs an integrity
  check after replacement.
- `internal/storage/migrations/0008_frozen_contract_columns.sql` exposes the
  frozen audit and idempotency-key schema on databases created by the earlier
  implementation migrations.
- `cmd/kynotes-probe` is the live 12-step client interoperability acceptance
  path; it uses the same session, pairing, envelope, sync, upload, and GC
  contracts as external clients.
- `FRONTEND_IMPLEMENTATION_PLAN.md` defines the separate responsive web MVP,
  browser crypto/local-storage boundaries, sync state machine, and mobile
  reuse path; it does not alter the frozen server plan.
- `web/` is the browser client; keep plaintext in browser memory only, send
  CSRF headers on mutations, and run its `npm test` plus `npm run build` checks.
- `web/` also contains the encrypted local save queue, client-only search,
  contextual resurfacing, graph projections, and a lazy-loaded BlockNote JSON
  editor with built-in formatting and file controls plus encrypted section
  anchors for comments. Attachment payloads and metadata are encrypted in the
  browser, and pending chunked uploads are persisted in the IndexedDB vault for
  reload recovery, with visible progress, retry, and cancel controls. Inline
  images use encrypted attachment payloads and attachment-backed image blocks.
  The document loader converts the prior encrypted Tiptap JSON envelope to
  BlockNote blocks on read so existing formatting survives editor remounts.
  The workspace surface
  labels personal workbooks explicitly, and the admin surface uses tabbed
  server, users, teams, and audit sections. The save queue is kept in the
  existing IndexedDB vault, drains on startup/online recovery and every 15
  seconds, and uses a ciphertext-only BroadcastChannel hint for other tabs.
- `web/` exposes a client-only work queue for open checklist items across
  personal workspaces; task parsing remains browser-side because the server
  never sees plaintext. Inbox folders still require the planned folder-object
  client path.
- `web/` shows server commit receipts as a short `Last Committed Ns ago` toast
  that expires after 15 seconds.
- `web/` persists local zero-knowledge device keys in the IndexedDB keys vault upon
  password login/setup to enable seamless 1-click SSO returns on trusted devices,
  while providing explicit "Forget this device" controls to clear stored secrets;
  sessions without a cached device key prompt for the master password once.
- `web/` surfaces server-confirmed save times and treats `version_conflict`
  responses separately from offline failures, preserving the encrypted local
  draft without endlessly retrying a stale version.
- `internal/httpapi` commit receipts are deterministic SHA-256 commitments over
  opaque object/version metadata and ciphertext digest; share links store only
  token hashes and serve ciphertext without the URL-fragment decryption key.
  Browser-sealed links use a dedicated random content key and never reuse the
  authentication or workspace key.
- `internal/httpapi` exposes authenticated object attachment listings; the web
  client encrypts attachment bytes and metadata before chunked upload and
  decrypts them only for the current browser session.
- `internal/httpapi` presence is TTL-only in memory and membership-gated;
  notifications expose mention metadata only and use the existing 90-second
  foreground refresh cadence in the browser.
- `POST /api/v1/admin/teams` is the explicit admin team-creation path; it
  creates the owner membership and records `admin.team.create`. Team names are
  encrypted in the browser using the team ID before metadata is updated; the
  admin list returns ciphertext for browser-side decryption.
- Team workspaces are child containers linked by `team_id`; their membership
  is copied from the parent team and membership changes propagate to children.
- `internal/storage/migrations/0011_sealed_share_links.sql` stores browser-sealed
  ciphertext separately from object-backed share links.
- `internal/storage/migrations/0012_sso.sql` adds `sso_subject` to users for KySignOn
  and OpenID Connect single sign-on integration.
- `internal/sso` and `internal/httpapi` handle OpenID Connect PKCE authentication,
  automated account provisioning, KySignOn system pairing (`POST /api/v1/admin/sso/pair`),
  and directory synchronization webhooks (`POST /api/v1/sync/events`). ID tokens use
  `oidcverify` with issuer/audience/nonce binding and a one-use server-side PKCE transaction.
  Login never adopts an existing username; trusted directory sync can link an unbound
  local account but refuses a conflicting issuer/subject. `syncauth` verifies every webhook
  alias; migration `0017_sso_directory.sql` commits replay admission and durable
  issuer/subject revisions with account changes, credential revocation and audit.
  Apply audits retain the subject in object_id and revision/activity/event ID in
  reason_code independently of subsequent revisions or replay pruning.
  Bare versioned SCIM replaces the legacy envelope; inactive delivery preserves
  accounts and keys, and SQL guards prevent activation through an inactive fence.
  A retained login-proof cutoff blocks pre-disable callbacks after re-enablement;
  session admission checks verified issuance time under the writer lock.
  Identical retries acknowledge without reapplying; stale/conflicting writes return
  422 because the sender treats create/409 as success. Signed `user.readback`
  binds purpose and subject in the body and audits the subject/event ID; sender
  automation remains unsupported. Configuration storage errors return 500;
  only a successful probe proving changed settings returns 422. Deactivation
  revokes sessions/device credentials; existing share links retain their expiry.
  Preserve local roles until explicit app-role mapping. `docs/SSO.md` owns the
  wire/upgrade contract; verify `TestDirectory*`. Tests cover real TLS/JWKS signatures,
  forged claims, metadata tampering, concurrent/restarted replay, and rollback.
- Migration `0016_sso_logout.sql` binds users by issuer/subject and SSO sessions
  by issuer/client/subject/sid/issued-at. The canonical back-channel logout POST
  uses `oidcverify@v0.7.0`; replay admission, pending-callback fences, session/device
  revocation and audit commit together. Audit names the JWT ID and counts sessions
  and devices actually revoked. Verified tokens bypass IP abuse throttling; only
  malformed/unverifiable requests consume that bucket. Logout with both sid/sub
  covers matching older sid-less sessions and callbacks. Key failures recheck a
  changed JWKS URI with discovery refresh limited to once per minute per client.
  Already-cancelled verification does no shared work; admitted login/logout
  metadata verification has a detached 30-second budget so caller disconnects
  cannot poison discovery/JWKS cooldowns. Session mutations retain request context.
  Callback admission rechecks account,
  configuration and original deadline under the writer lock. SSO-derived device
  credentials require a live parent session on every request. Upgrade revokes
  untraceable linked-account credentials once and preserves encrypted data.
  `docs/SSO.md` owns setup, migration and staged-adoption limitations. Verify with
  `TestSSOLogout*`, `TestSSOLoginRequiresAtomicAuditAndSessionIdentity`,
  `TestSSOConfigurationRevocationIsAtomic` and
  `TestSSOUpgradeRevokesOnlyUntraceableCredentials`.
- `internal/backup/AGENTS.md` owns sealed capsule collection, service operations,
  token compatibility and authenticated restore checks. Cross-server workspace migration
  remains deferred to v2.
- `internal/web` embeds the production `web/dist` bundle into the server image;
  update the checked-in embed after frontend bundle changes.
- Verification for server changes: `go test -race ./...`, `go vet ./...`, and
  `gofmt -l .`.
- Backups use `ky-primitives/recoveryclient` through `internal/backup`; HTTP admin,
  CSRF and step-up checks gate mutations, and export requires an audit write. The CLI
  owns the same data-directory lock as the server; `restore --in --to` is the only
  custodian-share/capsule-open entry point and revokes restored sessions. Legacy local
  plaintext commands are `copy-data-dir` and `restore-data-dir`. Capsules exclude all
  blob bytes, including note versions; full recovery needs the separate blob store.
  See `docs/RESTORE.md` and `docs/DEPLOYMENT.md`. The scheduler polls each minute,
  counts from last attempt and drains active work before SQLite closes.
- Passwords and recovery codes are Argon2id PHC strings via `ky-primitives/password`
  (scrypt verifiers are refused); login secrets derive through `ky-primitives/derive`
  with label `kynotes/auth/v1`; recovery codes come from `ky-primitives/recoverycode`
  and are minted by the server (`user add` prints one; `POST /api/v1/auth/recover`
  returns the replacement); key files under `<data>/secrets` load through
  `ky-primitives/keyfile` and an undecodable file is a startup error. Password and derive
  admission-control failures surface as `auth.ErrBusy` and answer 503, never a lockout strike.
  The login dummy verifier retries a failed mint; it must never cache or use an empty hash.
- Destructive admin routes sit behind `auth.RequireStepUp`: the browser re-proves the
  derived login secret at `POST /api/v1/auth/step-up` (`web/src/stepup.ts`) and the
  grant lasts `auth.StepUpWindow`. Routes answer `403 step_up_required` until then.

- `internal/mirror/AGENTS.md` owns streaming ciphertext replication and recovery over
  `ky-primitives/offsite@v0.1.0`. Migration `0015_blob_replicas.sql` tracks the single
  destination identity; credentials remain in deployment configuration and sealed capsules.
  Admin mirror status/actions share backup authorization. Capsule-triggered runs use
  snapshot inventory; restore fetch uses the restored database regardless of replica rows.
- Admin settings grid content must allow shrinking (`min-width: 0`); backup inputs
  stay within their card. Verify the backup surface at 390px and desktop after layout edits.

- OIDC login aliases share a per-IP token bucket. Pending login state stays bounded
  at 1024 entries and evicts the oldest expiry rather than refusing every new user;
  expired/evicted/consumed callbacks fail closed. Verify with
  `TestSSOLoginSurvivesPendingFlood` and `TestSSOTransactionExpiryAndCapacity`.
- CLI server mode accepts flags only. Removed `backup` names `copy-data-dir`/`deposit`
  in its error; unknown commands and trailing positional arguments exit before loading
  configuration or starting the server. `TestUnknownSubcommandIsRejected` covers dispatch.

- All IP-keyed rate limits honor X-Forwarded-For only with behind_proxy enabled and
  a trusted immediate peer. Walk the chain from the right to the first untrusted IP;
  malformed suffixes fall back to the socket peer. Preserve IPv6 /64 grouping and
  existing authenticated-user bucket overrides. Verify direct/proxied flood isolation
  and spoofed/malformed/multiple-header cases in the HTTP API tests.
