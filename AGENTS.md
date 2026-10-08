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

- Web themes default to the Busnes.app cream/light and charcoal/dark palettes with orange accents, following the OS until a browser-local choice is saved. Preserve existing named themes and saved choices.
- The workspace keeps its list/editor layout, but surfaces and selected navigation states must consume the shared theme tokens; selected pages use a slim accent rail.

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

- CI (`.github/workflows/ci.yml`, `verify`) builds, vets, tests, runs the browser team keys check (`npm run e2e`), the Docker probe, the apply-setup container check (same image) and govulncheck on every push and pull request.
- On a push to `master` that passes every job, `publish` pushes the exact image the Docker check ran against (handed over as an artifact, no rebuild) to `ghcr.io/busnes-app/kynotes-server:<commit sha>`, attests it and verifies the attestation pinned to this workflow on `master`; `promote` then moves `:latest` to that digest, only at the tip of `master`, and asserts the tag resolves to the attested digest. `docker-compose.yml` names the published image and never builds; source installs add `docker-compose.build.yml` to the `COMPOSE_FILE` chain in `.env` (overlay tags `kynotes-server:local`) so every compose command, recovery docs included, uses the local build.

## Shared browser UI

- `web/src/ky-ui/` is generated from Busnes-app/ky-ui, pinned by `VERSION` file hashes. Change shared colors, navigation states and storage helpers upstream, then run its consumer sync with an explicit worktree map; do not hand-edit vendored files.
- Products own layout, routes, saved choice keys and named palettes. Busnes aliases consume shared tokens; mark primary navigation with `ky-nav-item` while preserving current-page semantics.
- Verify vendored files with `node web/src/ky-ui/check-vendor.mjs` from this document's directory. Builds/CI run that check. Rendered evidence and capture limitations are recorded in the repository-root `UI-VERIFICATION.md`.

## Child DOX Index

- `internal/httpapi`: opaque routing ciphertext, role-gated mutations, and
  device-validated envelope writes are covered by the package integration
  tests; password/OIDC login, password change, step-up, recover, device, pairing, and upload
  endpoints use in-memory token buckets. Upload retries are byte-checked, and preview uploads remain
  content-addressed without creating an attachment row. Admin settings/users,
  audit metadata, team membership, and encrypted comment reads/writes are
  session- and role-gated here.
- `internal/app` owns the `.kynotes.lock` data-directory lock and first-run
  admin bootstrap (`BOOTSTRAP_ADMIN_USER`/`BOOTSTRAP_ADMIN_PASS` seed the admin only when
  no users exist; otherwise the web UI prompts, or use `user add`);
  maintenance backup refuses to copy a live data directory and restore runs an integrity
  check after replacement.
- `internal/storage/migrations/0008_frozen_contract_columns.sql` exposes the
  frozen audit and idempotency-key schema on databases created by the earlier
  implementation migrations.
- `cmd/kynotes-probe` is the live 13-step client interoperability acceptance
  path; it uses the same session, pairing, envelope, sync, upload, and GC
  contracts as external clients. Its X25519 device key is random, persisted 0600
  (`-device-key`, default under the user cache dir per server URL and username),
  never derived from `authSecret`; the device is revoked at the end of every run.
  An operator-set password (`password_change_required` on an empty envelope PUT,
  before pairing) is changed to a random one through `POST /api/v1/auth/password`
  and set back to `-password` after the device is revoked, clearing the admin-known
  flag so re-runs skip it. The temporary password sits beside the device key
  (`.takeover`, 0600) until restored; the next run restores it first.
- `FRONTEND_IMPLEMENTATION_PLAN.md` defines the separate responsive web MVP,
  browser crypto/local-storage boundaries, sync state machine, and mobile
  reuse path; it does not alter the frozen server plan.
- `web/` is the browser client; keep plaintext in browser memory only, send
  CSRF headers on mutations, and run its `npm test` plus `npm run build` checks; team notebooks use
  shared container keys (`keyring.ts`).
- `web/` also contains the encrypted local save queue, client-only search,
  contextual resurfacing, graph projections, and a lazy-loaded canvas page (`CanvasPage.tsx`): positioned BlockNote boxes and
  `perfect-freehand` ink in the `kynotes.canvas.v1` body (`document.ts` parses and caps it,
  `canvas.ts` holds pure edits). Legacy bodies open as one box and are not rewritten until
  edited. Pages reflow to a text column at <=800px and never persist a phone-fitted width.
  `knowledge.ts` caches text/task projections per note object, so note objects must be
  replaced, never mutated. Verify `document.test.ts`, `canvas.test.ts`, `knowledge.test.ts`,
  `ink.test.ts` and the canvas checks in `UI-VERIFICATION.md`.
  Encrypted section anchors for comments remain. Attachment payloads and metadata are encrypted in the
  browser, and pending chunked uploads are persisted in the IndexedDB vault for
  reload recovery, with visible progress, retry, and cancel controls. Inline
  images use encrypted attachment payloads and attachment-backed image blocks.
  The document loader converts the prior encrypted Tiptap JSON envelope to
  BlockNote blocks on read so existing formatting survives editor remounts.
  The workspace surface
  labels notebooks explicitly, and the admin surface uses tabbed
  server, users, teams, and audit sections. The save queue is kept in the
  existing IndexedDB vault, drains on startup/online recovery and every 15
  seconds, and uses a ciphertext-only BroadcastChannel hint for other tabs.
- `web/` presents containers as notebooks with colored section tabs (`folder` objects) and
  manually ordered pages. Placement lives in each page's encrypted payload
  (`pages.ts`, `order.ts`); decrypted payloads pass `parseObjectPayload` before use.
  Deep links use `#/<container>/<section|quick>/<page>`. The in-memory page list is the
  newest local copy: edits and placement patch it, saves carry only the version forward
  (`notes.ts`), and moves write from it, except that another tab's cached draft at an equal or
  newer version wins (`newestCopy`). Cache writes run in call order. Leaving the open page
  goes through `flushOpenPage`, which re-saves until the open page matches what was sent
  (`flushUntilStable`, at most 5 rounds); otherwise the page stays open and dirty, the error
  says why, and a refused hash navigation restores the URL with `replaceState`. A notebook switch clears
  the previous notebook's state, drops superseded loads and reapplies versions saved during
  the read (`carryAll` for pages, `carryVersions` for sections and groups; `writeObject`
  records every write made during a load). Verify `order.test.ts`, `pages.test.ts`, `notes.test.ts`
  and the section/page browser checks in `UI-VERIFICATION.md`.
- `web/` subpages: `outline.ts` derives display levels from each page's `level` without
  writing (legacy pages open with no PUT); indent and outdent use Ctrl+Alt+] / Ctrl+Alt+[
  (not Tab, by recorded ruling) or the editor's Indent/Outdent buttons, and reveal the page's collapsed ancestors.
  Pages never nest under a page from a different stored section, so Quick Notes orphans start at
  level 0. Rows carry visually hidden subpage-level and collapsed/expanded text.
  A parent moves with its block (drag, Alt+Arrow, section change), all through `moveChain`,
  with levels clamped at the target. Collapse state is browser-local per user and notebook.
- `web/` section groups are `folder` objects of type `group`; `groupParents` resolves the
  `group` fields (missing parent, cycle or over-depth falls back to the root). Group tabs nest
  under a breadcrumb (`aria-current="location"`; the open section tab keeps `page`). Deleting a
  group reparents its children first and stops before the delete on any failed write. An
  open group without sections shows no page list and disables new pages. "Move to section"
  labels sections with their group path (`sectionTargets`). Verify `outline.test.ts`.
- `web/` exposes a client-only work queue for open checklist items across
  personal notebooks; task parsing remains browser-side because the server
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
  draft without endlessly retrying a stale version. Server-kept conflicting
  versions are recovered as `(conflicting copy)` pages next to the original, one
  per distinct text (text equal to the server is resolved without a copy); the original
  reloads to the server version and a conflict is resolved only after its copy saves.
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
  reason_code independently of subsequent revisions or replay pruning (including
  the mapped app role).
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
  `docs/SSO.md` owns the
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
  update the checked-in embed after frontend bundle changes. The embed test rejects
  merge-conflict markers so generated chunks are never hand-merged into a broken bundle.
  After `npm run build --prefix web`, synchronize the complete generated asset set
  into `internal/web/dist`; CI runs frontend tests/build and `diff -qr web/dist internal/web/dist`
  to reject missing, stale or extra assets. The app CSP (`embed.go`) allows `img-src 'self' data: blob:` so decrypted images render.
- `kynotes-server healthcheck [--config PATH] [--url URL]` is the container HEALTHCHECK
  (distroless has no curl): GET `/healthz` on the configured bind port, 3 s timeout, exit 0
  only on 200, loopback hosts only, no redirects. `version` is set by
  `-ldflags "-X main.version=..."`; the Dockerfile takes `ARG VERSION` (CI passes the commit SHA).
- Verification for server changes: `go test -race ./...`, `go vet ./...`, and
  `gofmt -l .`.
- `internal/httpapi` serves public `GET /healthz` as cached `ky.health/1`: startup
  readiness and SQLite ping determine 200/503; the response exposes fixed check
  names and statuses only. `GET /livez` keeps the alive-only 200 response, and
  `/readyz` keeps its existing startup-readiness response. A router without a
  database checks startup only. Unlabelled routes, including probes, bypass
  session resolution in the rate-limit middleware even when sent a cookie.
- Backups use `ky-primitives/recoveryclient` through `internal/backup`; HTTP admin,
  CSRF and step-up checks gate mutations, and export requires an audit write. The CLI
  owns the same data-directory lock as the server, except `deposit`/`backup-drill`, which
  go through `admin.sock` when the server runs; `restore --in --to` is the only
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
- Backup/recovery mutations, `POST /api/v1/admin/users` and
  `POST /api/v1/admin/users/{id}/password` use `auth.RequireStepUp`, so a stolen admin
  cookie cannot mint local credentials. Local sessions re-prove their
  derived login secret at `POST /api/v1/auth/step-up` for `auth.StepUpWindow`.
  SSO sessions require a single-use challenge bound to session/method/URI/content-type/body,
  with fresh signed auth_time and ordinary assurance through the existing PKCE callback.
  Migration 0019 stores one expiring challenge per session; a started one is never replaced (`409 step_up_pending`),
  and minting uses a per-account `challenge` bucket at the login rate; creation, verification,
  cancellation and consumption are audited atomically. Challenges are `admin` or `user` scope
  (`sso_stepup.scope`, 0024); a grant opens only its own scope. Cancellation requires the owning session and CSRF,
  validates the rea ID before SQL, and audits only an owned row actually deleted;
  absent/foreign/repeated valid IDs are unaudited 204 no-ops. Grant admission rechecks local
  admin/token ceiling, session/configuration and directory/logout fences, including the
  proof sid. The operation follows committed admission. `web/src/reauth.ts` keeps the
  request in memory, uses a native dialog/sign-in window, and cancels abandoned challenges;
  `actionFetch` retries JSON and capsule requests once. No SSO callback replaces the session.
  Other admin routes keep their existing guards. `docs/SSO.md` owns the protocol and limits.
  Verify `TestSSOStepUp*`, `web/src/reauth.test.ts`, npm test/build, and the real browser dialog.

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
  `apply-setup` is the one subcommand that needs the server running: it talks to it over
  `<data_dir>/admin.sock`.

- All IP-keyed rate limits honor X-Forwarded-For only with behind_proxy enabled and
  a trusted immediate peer. Walk the chain from the right to the first untrusted IP;
  malformed suffixes fall back to the socket peer. Preserve IPv6 /64 grouping and
  existing authenticated-user bucket overrides. Verify direct/proxied flood isolation
  and spoofed/malformed/multiple-header cases in the HTTP API tests.

- Migration `0018_sso_app_roles.sql` removes unproven linked-account admin roles,
  except active local grants when no unlinked active admin exists; retention is audited.
  It revokes old SSO sessions once and audits each affected identity. Keep an unlinked
  local administrator through upgrade; resync explicit `kynotes.admin` assignments.
  OIDC ignores singular/global role claims and stores a verified app-admin ceiling
  on each session. `auth.SessionRole` is shared by admin guards and session responses;
  SSO admin needs both that ceiling and local account permission. Directory roles
  map only exact `kynotes.admin` from strings or SCIM value objects to admin;
  unrelated/missing/malformed role data grants nothing, never blocks login or deactivation.
  Active demotion retains the last active admin's local grant with `admin_retained=true`
  in the audit, but still revokes credentials and requires the OIDC ceiling. Inactive
  events always disable/revoke, and never preserve an active administrator.
  Changes revoke sessions/devices and advance the callback cutoff atomically with
  audit. `revokeForRoleChange` (directory and apply-setup grants) upserts the cutoff into
  `sso_login_cutoffs` (migration 0020), independent of directory state, so auto-provisioned
  subjects are fenced too; `checkSSOIdentityTx` enforces it with the directory cutoff.
  Readback includes the local role. Verify `TestSSOAppRoles*`,
  `TestDirectoryAppRoleShapes`, `TestDirectoryDeactivationIgnoresRoles`,
  `TestDirectoryRetainsLastActiveAdminGrant`, `TestSSOAppRoleUpgradeDoesNotPreserveGlobalAdmin`
  and existing directory race/rollback checks. OIDC step-up uses the separate
  action-bound proof path above; local password step-up never authorizes an SSO action.

- `internal/reqid` carries only the middleware-established request ID through context.
  `httpapi.RequestID` and SSO step-up start/consume audits read it without falling back
  to raw headers. Verify `TestSSOStepUpAuditUsesTrustedRequestID` and request-ID contracts.
  The SSO sign-in popup clears its own opener before navigation while retaining the
  parent's handle for polling/cleanup; `web/src/reauth.test.ts` checks that ordering.

- Product PNGs (`/favicon.png`, `/app-icon.png`, `/app-icon-192.png`, `/app-icon-512.png`) must pass the router allowlist to reach the embedded files. `TestProductIconsReachEmbeddedFiles` checks the public response type and dimensions.

- `internal/applysetup` owns the apply-setup contract: bundle (secrets only by file path,
  unknown fields rejected), socket request, create/present/conflict decisions, report and
  exit codes 0/3/2/1 (precedence invalid > failed > conflict). `internal/httpapi/apply_setup.go`
  applies SSO through the router's shared `sso.Store` after a discovery probe (issuer
  transport/5xx/429 is `failed`, `sso.ErrIssuerUnavailable`; a bad document is `invalid`), and admins
  bound by issuer+subject (never by username; a grant revokes credentials through
  `revokeForRoleChange`). `backup.Service.ApplySetup` compares env-fixed dir/keep, sets the
  interval only when unset and claims a pairing only when unpaired. `internal/app` owns
  `admin.sock`: 0600, peer uid or root, created after the data-dir lock, never a network
  listener; shutdown drains a running apply for up to `backup.OperationTimeout` plus a
  minute before SQLite closes, then removes the socket (compose `stop_grace_period: 17m`
  covers it). One audit row per change (actor `system`, request `apply-setup`). The same
  socket serves `POST /v1/deposit` and `/v1/backup-drill` through `backup.Service.Run`/`Drill`
  (actor `system`, request `admin-socket`), one operation at a time with the same drain;
  answers are `{"result","error_code"}` and the CLI exits 1 on any error code.
  `docs/INSTALLER.md` is the installer contract. Verify `go test ./internal/applysetup`,
  `TestApply*`, `TestSetupHandler*`, `TestAdminSocket*`, `TestServeOwnsAdminSocketLifecycle`,
  `TestApplySetupTwiceEndToEnd`, `TestDepositAndDrillOfflineAndLive` and
  `scripts/apply-setup-container-check.sh`.
- Team keys P1: `internal/httpapi/identity_routes.go` serves `GET`/`PUT /api/v1/me/identity`
  (create-only, `auth.RequireUserActionStepUp`: a local password step-up creates `aes-256-gcm`, an SSO KySignOn confirmation creates device-only `wrap_alg='none'`). `GET`
  is public-only; the wrapped key rides only in local login/step-up bodies. The identity is a
  `devices` row with `platform='identity'` and an unusable `secret_hash` (migration 0021,
  `user_identities`); device auth, device list/revoke/selection, directory deactivation and role
  changes, register and the save gate exclude it. Password change must carry `identityDeviceId`
  and `wrappedIdentityKey` when a password-wrapped one exists (`409 identity_rewrap_required`), clears every session's
  step-up and shares the step-up lockout; recovery and admin reset delete it with an audit row.
  `PUT` and password change recheck inside their write transaction (`auth.RecheckUserStepUpTx`,
  `auth.RecheckSessionTx`, `TestRecheckTxSeesCommitsAfterMiddleware`): a session revoked (401)
  or a password/step-up changed (403 for `PUT`) after the middleware writes nothing.
  Login (`auth.MintPasswordSession`) and step-up mint the session or set `stepup_at` and load the
  wrapped identity in one transaction bound to the hash they verified; a change in between gets
  401, no cookie, no step-up and no wrapped key (`Test*RejectsConcurrentPasswordChange`).
  `users.password_admin_known` (admin create/reset, bootstrap, `user add`; cleared by own change or
  recovery) makes `PUT` and every local identity-action step-up (`auth.RecheckUserStepUpTx`: envelope `PUT`, rotation,
  invitation keys) answer `409 password_change_required`; the browser then creates the identity
  after the user's own password change. Any new path that sets a password for someone else must
  set the flag. `/setup` accepts only `authSecret`. Until shared keys land, the password form warns
  that existing notes become unreadable and needs an acknowledgement (`web/src/passwordChange.ts`).
  `web/src/teamKeys.ts` holds the envelope/identity primitives on `@noble/curves`/`@noble/ciphers`
  (exact pins); `web/src/identity.ts` creates the identity silently after a local password login
  or `/setup`, never replaces one it cannot open, and caches it in the IndexedDB vault
  ("Forget this device" clears it). SSO sessions create device-only identities (P3c).
  `internal/teamkeys` regenerates `testdata/protocol/envelope_vectors.json` (`-update`);
  `web/src/teamKeys.test.ts` replays it. Verify `TestIdentity*`, `TestUserActionStepUpRefusesUngrantedSSOSession`,
  `TestRegisterCannotClaimIdentity`, `TestPasswordChangeRewrapsIdentityAtomically`,
  `TestRecoveryAndAdminResetDeleteIdentity`, `TestAdminKnownPasswordGatesIdentityUntilOwnChange`,
  `TestDirectoryRevocationsSpareIdentity`, `TestPasswordChangeSharesStepUpLockout`,
  `TestUserAddFlagsOperatorKnownPassword`, `TestEnvelopeVectors` and `npm test` (which also keeps
  `*ForVector` exports out of non-test sources).
- Team keys P2: `internal/httpapi/teamkeys_routes.go` owns the shared-key rules. `insertEnvelopeTx`
  makes envelopes insert-only per container/generation/recipient; a member's own identity envelope
  is re-wrap only (stewards or an accepted invitation write it first). Members wrap for their own
  devices, stewards for any member; recipients must be live devices or identities of active members.
  `PUT .../envelopes` and `POST .../key-rotations` use `auth.RequireUserActionStepUp` plus
  `RecheckUserActionTx` (SSO stewards confirm each request with KySignOn; invitation envelopes stay local-password). Rotation compares and increments `key_generation`, sets
  `containers.shared_generation` (migration 0022) once, and requires the caller and every active
  member identity. `checkWriteGate` serves object saves, comment create/rewrite and attachment
  finalize, before streaming and inside the transaction (object saves also recheck role there):
  live membership, current generation, then the legacy device rule while `shared_generation=0` or
  the writer's own identity envelope after. `removeMemberTx` serves owner/admin and server-admin
  removal (children revoked, generations bumped, envelopes, selections and the removed user's
  pending invitations deleted, audited in the same transaction). Invitations may carry identity
  envelopes (`invitation_envelopes`, moved on accept only at their generation and only while the
  inviter is still a steward); creating one with envelopes needs `auth.HasUserStepUp` plus
  `RecheckUserStepUpTx`, while accept only moves envelopes authorized at insertion. `PUT /comments/{id}` is author-only; `GET /users/{id}/identity`
  answers self, live co-members and an inviting steward, else a uniform 404;
  `object_versions.author_user_id` is written, not yet read. Shared 409 `already_exists` covers
  moved generations, duplicates and incomplete rotations. Known limits are listed in
  `IMPLEMENTATION_PLAN.md` §9. The probe seals and opens a real envelope with `internal/teamkeys`
  (never linked into the server). Verify `TestEnvelope*`, `TestKeyRotation*`,
  `TestOwnIdentityWriteIsRewrapOnly`, `TestConcurrentRotationsCannotSplitAGeneration`,
  `TestLegacyContainersKeepTheDeviceGate`, `TestNewContentRefusedUntilRotationEnvelopesExist`,
  `TestSaveRacing*`, `TestAdminMemberRemovalRotatesLikeOwnerRemoval`,
  `TestRemovedMemberCannotWriteAnywhereInTheTeam`, `TestCollaboratorRemovalRulesAndAcceptOutcomes`,
  `TestInvitation*`, `TestCommentRewriteIsAuthorOnly`, `TestUserIdentityVisibility`,
  `TestOpenEnvelopeAgreesWithVectors` and the probe.
- Team keys P3a (web): `web/src/keyring.ts` (pure: envelopes → generation keys, write key, exact-generation
  read key, steward sweep plan), `web/src/keyService.ts` (one sweep against an injected API: mint via
  rotation, backfill wraps, one retry on 409) and `web/src/pins.ts` (add-only TOFU pins in the vault
  record, local fingerprints; trust rules in the next bullet). Trust prompts and key notices name people
  only through `displayName(username, userId)`: one sanitized line, `<userId> · <name>`, ID first so a name
  cannot pose as it, name capped at 64 characters. Reads: at or above `sharedGeneration`
  only that generation's key, below it and personal the legacy key, malformed generation no key.
  `main.tsx` reaches the login key only through
  `legacyKeyRef` (two call sites, test-gated) and writes shared containers only with the current key; with
  keys missing every mutation handler returns on `readOnlyForKeys()` and its control is disabled (no empty
  objects), and in-progress edits queue at generation 0, resealed on arrival, never uploaded at 0. The
  drain uploads an entry only through `readyToSend` (`web/src/drain.ts`): as is only when sealed for the
  current `writeKeyFor` generation and not a `legacyRow` under the floor, otherwise re-sealed from its own
  generation's key first, or kept queued while no write key exists. Every container-key or login-key
  ciphertext upload (object saves, attachment start/chunks/finalize, comments, container names) goes
  through the `web/src/outbound.ts` gate, which re-checks the sealing generation against `floorOf` and
  the workspace's `writeKeyFor` right before the request; pending attachments pass `attachmentStep`
  (wait or reseal payload and metadata) before the first chunk, and `outbound.test.ts` fails if any other
  module calls those API functions; queue
  replacements go through `replaceQueuedSave` (compare-and-set). A password change re-seals them
  (`resealWaitingEdits`). Legacy-key rows in a shared container (`legacyRow`) are server-forgeable until
  the device closes them (Team keys P4 below): `readKeys` and the label share that one decision (generation 0 included), and `api.ts`
  `serverGeneration` turns malformed server generations into `undefined`. Labelled rows are re-sealed only
  by an explicit edit or move of that row (`placePage`/`updateStructure` `explicit`, which report a
  skip); block moves carrying a labelled subpage are refused (`movesLabelledSubpage`); legacy conflict
  versions are never copied (`copyableConflicts`). The first mint re-seals the shown name and says so.
  Rollback rule: `KeyState` also keeps the highest `shared`/`generation` the server reported (add-only,
  persisted by `syncContainerKeys` before use); `writeKey`/`readKeys`/`legacyRow` require that floor and
  `guardContainer` applies it, `main.tsx` passes it only through `floorFor`, a thin lookup for every
  container (no loaded floor, no key; `ensureFloor` before first use; every server container read
  passes the observer (`web/src/observe.ts`: list, current, create, admin team list/create), which
  raises the stored and in-memory floor before the row is used, and `observe.test.ts` fails if
  `main.tsx` imports a raw container fetcher; the in-memory floor is one tab-wide store
  (`web/src/floors.ts`, add-only, cleared on sign-out) that every component and key decision reads at
  decision time, with no per-component floor map; each raise is broadcast on the `kynotes-floors`
  BroadcastChannel (`{containerID, shared, generation}`, numbers only) and other tabs merge it add-only
  into a floor they already hold after validating the ID pattern and non-negative safe integers, and `syncContainerKeys` raises it through `onFloor` before any
  envelope fetch and again the moment `rotate` succeeds; the post-mint ring opens from the accepted
  rows, never a re-fetch, so a pass that later throws still pauses writes), and a lower report is plan
  `rollback`: writes paused, never the login key. `kind`/`teamId` are server claims for layout only:
  `keysAllowed` refuses keys for a seen-shared container reported personal, and they may add a key pass
  (`needsKeyPass`) but never skip one.
  `storePins` is atomic and returns `{ ok: false, conflicts }` for a member pinned to another key; the
  pass then stops before upload (plan `untrusted`). A pass that stops on a pin it could not keep
  (declined, unsaved or conflicting) re-opens against the stored pins (`persistedOnly`) and returns, and
  saves key memory from, only that; if a first-contact pin is still unstored it returns only held keys
  matching the stored digests and re-saves the prior key memory with the raised floor, so a refused
  sender's key is never adopted or remembered and `keyStateSaved` reports that save.
  Server: containers report `sharedGeneration`; shared containers refuse writes without
  `X-Kynotes-Key-Scheme: shared-v1`; meta `PATCH` must carry the current `keyGeneration` and checks role
  and `baseVersion` in its transaction; conflict
  listings report `keyGeneration`; envelope `PUT` backfills existing shared generations and never mints
  (`putGenerationTx`). Verify `TestSharedContainerRefusesStaleClientWrites`,
  `TestStewardBackfillsSharedHistoryOnly`, `TestSharedGenerationIsMintedOnlyByRotation`,
  `TestContainersReportSharedGeneration`, `TestSharedNameNeedsCurrentGeneration`,
  `TestConflictListingReportsKeyGeneration`, `TestConcurrentRenamesFromOneBaseOneWins`,
  `TestMetaPatchRechecksInsideTheTransaction` and `npm test` (keyring, keyService, pins, crypto, storage,
  passwordChange).
  `npm run e2e --prefix web` (`web/e2e/team-keys.e2e.ts`) runs owner, editor and newcomer in three
  Chromium contexts, plus one where another account signs in over an opened invitation link and one
  second browser of the editor's account, against
  `web/e2e/server.sh` (throwaway `/tmp` data on `127.0.0.1:18080`, login limit raised because every
  person shares one loopback IP; serves the embedded bundle: build and sync `internal/web/dist` first).
  It checks server bytes: shared rows open
  with the container key and not the writer's login key, a newcomer gets history, removal re-mints at once
  (generation N+2 holds envelopes for the remaining members only, before anyone writes), and a
  write without the key-scheme header gets 409. P3b steps: an invitation sealed for the invitee opens
  the team before any owner reopens it, refuses another account and a pre-removal invitation, a link
  pasted into an open tab joins, a re-invited member waits and asks, a declined changed key is never
  sealed, re-trust in Settings, unsent edits export and discard, and a click during the automatic load
  (held at its last request) leaves the list loaded when it stops being busy. P3c steps: newcomer Cancel,
  either side leaving Settings, and approver "Codes differ" each delete the request (collect answers 404);
  a reload mid-attempt sends a keepalive cancel, so the request is gone (collect answers 404); a relay
  swapping the approver key (rewritten collect) keeps Approve disabled with the newcomer's code typed and
  sends nothing; the honest link needs the typed code, keeps the collected bundle unopened until the
  newcomer's "Codes match", stores the same identity sealed and non-extractable, refuses a second collect,
  opens the team with one fingerprint; a cache that refuses writes still sends with the no-local-copy text;
  Forget asks with its exact text and empties the vault. Every browser dialog must
  be expected by the test; expected confirms are matched on their text.
  `KYNOTES_E2E_URL` points it at a running server; only ever a throwaway one.
- Team keys P3a client trust (`web/src/keyring.ts`, `web/src/pins.ts`): envelopes are v2 only
  (sender-authenticated, spec §1); `openKeyring` accepts a key only from this identity or a current
  owner/admin whose key matches its pin (first contact pins and is surfaced, mismatch refused), or,
  below this device's vault high-water mark (`getKeyState`/`storeKeyState`, never from the server), an
  identity already pinned here; the first key per generation wins, across reloads via stored key
  digests (`conflicts`); pins are only added (`storePins` merges) or replaced with a
  `PinConfirmation` (`storeConfirmedPin`);
  `sealFor` pins first-seen recipients and throws `FingerprintChangedError` until
  `confirmFingerprintChange`; `readKeys` opens rows at or above `sharedGeneration` only with their own
  generation's CK. Callers persist returned pins with `storePins` and tell the user when it returns
  false. Verify `npm test` (`keyring`, `pins`, `teamKeys` suites) and `go test ./internal/teamkeys`.
- Team keys P3b: invitations and membership keys. Server: `POST /api/v1/invitations/{id}/accept` reads
  the invitation (token, invitee, pending, unexpired, inviter still a steward) inside its transaction and
  audits `container.member_accept`; a refused accept or server-admin add is audited after its rolled-back
  transaction (`auditRefusal`: outcome `denied`, or `failure` for a 500, reason = the response code only);
  `admitMemberTx` (accept and the server-admin add route, which answers
  400/404/409/500 distinctly) reactivates rows a removal revoked, restores no keys and records
  `memberships.invited_by` (migration `0023_membership_inviter.sql`; older rows are empty and fail closed;
  child workspaces copy it); a team admin removes another admin only when it invited that membership;
  removal deletes the member's pending invitations, child workspaces included; `ratelimit.invitation_per_hour`
  limits invitation creation per account, and accepts per account in a separate bucket at the same rate
  (invalid or negative is a startup error); `storage.RunGC` deletes
  envelopes of expired invitations; the container list is 500, never a partial 200. Web: one-time links
  `#/invite/<id>/<token>` (`web/src/invitations.ts`) are stashed in session storage (in memory for the page
  load when storage is refused) and cleared from the address bar, also in an open tab; the token goes only
  in the accept body; a failed accept drops the invitation only on 404 `not_found`, 409 `already_exists` or
  410 and otherwise (any 403 included) keeps it for a retry; `replaceState` clears only this
  tab's history. `inviteWithKeys` (`keyService.ts`) seals only the chosen team's current key (never
  children picked by `teamId`), gated by `keysAllowed` against this device's loaded floor and an accepted
  key matching the stored digest, for a visible invitee; a changed pin needs confirmation (stored
  compare-and-swap against the pin the dialog showed, as in the sweep and re-trust) and a first-seen
  pin goes through `storePins` (a conflict sends no keys) before the step-up; anything else sends a keyless
  invitation with copy saying why; re-invited members receive history like any newcomer;
  `memberKeyStatus` labels member rows (informational). Settings colleague keys (`components/PinnedKeys.tsx`,
  names via `displayName`, re-trust re-fetches the key and stores it compare-and-swap against the "Was" pin,
  only via `confirmFingerprintChange` → `storeConfirmedPin`) and unsent edits (`components/UnsentEdits.tsx`,
  `stuckEdits.ts`): edits are bound to the account; the note cache and save queue are keyed by
  `[owner, id]` (IndexedDB v5 re-keys older rows to owner-unknown `""`), so no save, replace, clear or
  read touches another account's entry, and an owner-unknown cached page is read only once the user's own
  legacy key opens it (then claimed), and one only a notebook key opens is listed in Unsent edits as
  "Draft, owner unknown", export-only (`unknownDrafts`); an unstamped edit is stamped once the user's own legacy
  key proves it, team-key-only owner-unknown edits are export-only and never drained or discarded, export is
  plaintext and marked unencrypted, the drain uploads only this account's edits. `loadGate.ts` lets only the
  newest notebook load finish. Verify `TestAcceptChecksExpiryAndInviteeInsideItsTransaction`,
  `TestRemovedMemberIsReadmittedByReactivation`, `TestTeamAdminRemovesOnlyAdminsItInvited`,
  `TestRemovalVoidsPendingInvitationsToTheRemovedMember`, `TestAcceptAndAdminAddAreAudited`,
  `TestRefusedAcceptAndAdminAddAreAuditedWithTheResponseCodeOnly`,
  `TestAdminAddMapsOnlyConflictsTo409`, `TestContainerListFailsRatherThanReturningPartialList`,
  `TestInvitationCreationIsRateLimitedPerCaller`, `TestRetryAfterFollowsRefillInterval`,
  `TestGCDeletesEnvelopesOfExpiredInvitations`, `npm test` (keyring, keyService, pins, invitations,
  stuckEdits, loadGate) and `npm run e2e --prefix web`.
- Team keys P3c: device linking and SSO identities. Server: `auth.RequireUserActionStepUp` (local password
  step-up, or a `user`-scope KySignOn grant bound to action and body, single use, fresh `auth_time`;
  `sso_stepup.scope`, migration `0024_device_linking.sql`) gates `PUT /me/identity` (SSO sessions create
  device-only `wrap_alg='none'` identities; a password never unlocks or re-wraps them), envelope `PUT` and
  key rotations. Step-up start, poll and cancel need a session, not an admin; challenge creation has a
  per-account `challenge` bucket; the 409 codes are `step_up_pending` (with the challenge ID),
  `sso_step_up_required`, `sso_sign_in_required` and `password_change_required`; the action body is capped at 64 KiB
  (`413 payload_too_large`, JSON). `password_admin_known` refuses every local action step-up and the link steps create, claim, reveal, approve and
  collect (list and cancel accept it); on an SSO-linked account `POST /auth/password` then needs a fresh KySignOn
  confirmation. Every password change revokes the account's other sessions and non-identity device credentials in
  its transaction (audit `sessions_revoked=N,devices_revoked=N`). `internal/httpapi/link_routes.go` relays
  `/api/v1/me/link-requests` (seven routes: create with a commitment, list, claim, reveal, approve after
  step-up, collect, cancel). Collect is `POST …/collect` with CSRF and `no-store`, once; the relay holds
  ciphertext only; per user, 10-minute TTL checked in the transaction, 3 live, both sessions live,
  session-only, audited `identity.link.*` (collect misses are not audited), GC'd, deleted with the identity.
  Rate limits: own `link` bucket at `pairing_per_hour`, `link-step` at `login_per_minute`, collect at
  `ratelimit.link_poll_per_minute` (default 60; the newcomer polls every 4 s, so the 3 live requests make 45 a
  minute).
  Web: `linking.ts` (commitment, six-digit check code, 61-byte bundle, frozen branded confirmations;
  `testdata/protocol/link_vectors.json` from `internal/teamkeys`), `linkFlow.ts` (newcomer pins the approver
  key before revealing, a failed reveal ends the attempt, no auto-retry with a new key; `awaitLinkBundle` keeps the
  attempt through a 429 or network error and backs off to 30 s, ending on a 404 or a streak past the TTL; a create
  404 is `LinkNoIdentityError`; the approver types the newcomer's code,
  NFKC with spaces ignored, there is no "Codes match" on the approver; the newcomer opens a bundle only after its
  own confirmation and only for the listed identity), `outbound.ts` `sendLinkBundle` and `collectLinkBundle`
  (only with a typed confirmation, only while the attempt's one-time key is live), `api.ts` `cancelSSOStepUp`
  (cancels an open confirmation, also after `step_up_pending`), `storage.ts` (identity under a non-extractable
  device key in the vault record, labels "wrapped"/"plain"; not at-rest protection; plain HTTP unwrapped with a
  Settings warning; no IndexedDB, no identity; compare-and-swap writes), `identity.ts` (`settlePasswordIdentity` stores compare-and-swap against the copy read first; `settleSSOIdentity`
  keeps a pending key before the PUT and never overwrites a held identity without "Replace"; `currentCopy` uses
  the vault copy only while the server lists it), `keyService.ts` `KySync.deferred` (SSO stewards share on a
  "Share keys" click), `components/DeviceLink.tsx` (a row another tab claimed shows "Being approved in another tab", no Approve), the Forget-this-device confirmation (the encrypted save
  queue stays), the SSO set-up banners, and N1: a failed local cache write still sends the edit, with copy that
  says the browser could not keep its copy. The P3a limit "SSO users block sharing" is gone. Verify `TestSSOUserStepUp*`,
  `TestSSOStepUpScopeIsBoundToTheGrant`, `TestSSOSessionCreatesDeviceOnlyIdentity`,
  `TestDeviceOnlyIdentityIsNeverWrappedByAPassword`, `TestSSOStewardSharesKeysAfterActionStepUp`,
  `TestSSOGrantIsRecheckedInTheWriteTransaction`, `TestAdminKnownPasswordChangeNeedsKySignOn`,
  `TestBackgroundChallengeLeavesAStartedConfirmationAlone`, `TestSSOChallengeCreationIsRateLimitedPerAccount`,
  `TestLink*`, `TestSSOAccountLinksASecondBrowser`, `TestGCDeletesExpiredLinkRequests`,
  `TestLinkPollLimitEnvAndValidation`, `go test ./internal/teamkeys`, `npm test` (linking, linkFlow, storage,
  identity, keyService, outbound, DeviceLink) and `npm run e2e --prefix web`.

- Team keys P4: legacy review and per-device closure. Server: read-only `GET /api/v1/containers/{id}/legacy`
  (`teamkeys_routes.go`; any live member, session only; rows below `shared_generation`; unknown and foreign
  containers get one 404, a storage error 500; 1000 per kind with `complete`; `no-store`; per-account bucket
  at `link_poll_per_minute`, `ponytail:` upgrade a `legacy_per_minute` key; comments and conflicts scan
  without an index, `ponytail:` upgrade indexes). No migration; `0025` is unused. Web: `KeyFloor.closed` only
  rises (`keyring.ts` `mergeFloor`/`closedOf`, `storage.ts` `storeKeyState`, the `floors.ts` channel; a
  malformed value counts as closed) and is set only by `observe.ts` `closeLegacy`. `readKeys` returns no login
  key for any server row once closed; `localReadKeysFor`/`localReadKeys` (closure ignored) serve only this
  browser's owner-stamped queue entries, pending uploads and cache entries (the cache never holds server
  bytes). `migration.ts`: `reviewLegacy` opens each listed row only with the key `readKeys` picks and is bound
  to the sharing floor it covered (incomplete on any failed fetch or row without a valid generation; a comment
  naming another author is refused); `checkLegacyRows` auto-closes only on a complete successful response
  listing nothing of the user's, `sharedGeneration` above 0, an unchanged floor and no reopen mark (a 429, 500,
  network error or `complete:false` never closes); `migrateLegacy` re-seals only the ticked rows of a branded,
  single-use `MigrationApproval` (frozen copy of what the dialog showed, bound to user, container, floor and a
  `reviewLegacy` review, minted only by `components/LegacyReview.tsx`), detaches and resolves only after the
  matching re-seal, and closes only when the review was complete, nothing failed, the floor is unchanged and the
  user confirmed the hidden count. The dialog shows real content, labels every item "not end-to-end verified",
  pre-ticks nothing and disables Share until something is ticked. `reopenLegacy` (`storage.ts`, with a
  single-use `ReopenConfirmation` minted only from the "Show pre-sharing items again" confirm) lowers the
  closure and persists a reopen mark that blocks auto-close in every tab and across reloads; Stop or a
  completed confirmed share clears it, and `floors.ts` `reopenFloorIn` makes other tabs re-read storage.
  `main.tsx` calls `setClosureReader` at sign-in and reloads the open notebook when its closure changes;
  `outbound.ts` `sendCommentRewrite` is the comment re-seal. Limits: auto-close trusts the server's list, a
  forged row ticked by the user is sealed, viewers cannot share their pre-sharing rows, rows of removed authors
  stay opaque, pre-P4 tabs ignore a reopen until reloaded, administrator-owned teams wait for sub-project A.
  Verify `TestLegacyRows*`, `npm test` (keyring, storage, floors, observe, drain, api, outbound, migration,
  legacyWiring, LegacyReview).