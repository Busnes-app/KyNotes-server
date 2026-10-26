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
- Settings → Appearance shows Match system and the ky-ui suite catalog as the shared native radio cards (`ky-appearance`), applied at once with no Apply button and saved by name under `kynotes-theme`; names saved by earlier versions still select their theme. Another tab's choice re-checks the matching card (a `storage` listener, as KyCalendar does; `e2e/appearance-cross-tab.e2e.ts`), and Match system reads "Follows device" like the other products. The section sits flat on the settings page, not in a card, and on phones 16px from the screen edge so two shared cards fit at 390px.
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

- On phones, `Notebooks and account` expands the complete notebook sidebar; desktop keeps it visible. The disclosure never changes the selected notebook, note, keys or saved settings. `web/e2e/mobile-navigation.e2e.ts` verifies those actions remain reachable.

- In the note editor, ':' opens the emoji menu only where it starts a word (start of text or after whitespace) and two letters follow (`web/src/emoji.ts`), so `due:` and `10:30` never open it; `web/e2e/task-dates.e2e.ts` checks both and that Enter still picks an emoji.

- CI (`.github/workflows/ci.yml`, `verify`) builds, vets, proves the release binary is repeatable (two `git archive` builds with `-trimpath` must be byte-identical), tests, runs the browser checks (`npm run e2e`: team keys, `web/e2e/admin-separation.e2e.ts`, `web/e2e/task-dates.e2e.ts` and `web/e2e/migration.e2e.ts`), the Docker probe, the apply-setup container check (same image) and govulncheck on every push and pull request.
- On a push to `master` that passes every job, `publish` pushes the exact image the Docker check ran against (handed over as an artifact, no rebuild) to `ghcr.io/busnes-app/kynotes-server:<commit sha>`, attests it and verifies the attestation pinned to this workflow on `master`; `promote` then moves `:latest` to that digest, only at the tip of `master`, and asserts the tag resolves to the attested digest. `docker-compose.yml` names the published image and never builds; source installs add `docker-compose.build.yml` to the `COMPOSE_FILE` chain in `.env` (overlay tags `kynotes-server:local`) so every compose command, recovery docs included, uses the local build.
- The version has one source: `internal/appversion/VERSION` (`X.Y.Z`, the release line; `web/package.json` has no version). Go code (`kynotes-server`, `kynotes-mcp`) calls `appversion.String()`; the Dockerfile's `VERSION` build arg sets `-ldflags -X …/internal/appversion.release`, so release images report `X.Y.Z` or `X.Y.Z.N`, CI images the commit SHA, and source builds the line.
- Publishing a GitHub release `vX.Y.Z` or `vX.Y.Z.N` runs `release-image.yml` (a dispatch on a published release's tag runs it too). It refuses a malformed tag, a tag whose `X.Y.Z` disagrees with `internal/appversion/VERSION`, and any commit on which a ci.yml job in its `REQUIRED` list (`test`) did not pass. It then builds `:X.Y.Z[.N]` with provenance and SBOM, attests and verifies it (identity `release-image.yml@refs/tags/<tag>`), and moves `:stable` to that digest only for the highest non-prerelease. It never moves `:latest`; `master` CI owns that. A job added to ci.yml must be added to `REQUIRED` too.
- `dependency-release.yml` runs daily at 23:00 UTC: if Dependabot commits landed on `master` since the newest release on the current line and the push CI run on `master`'s tip succeeded, it publishes the next `vX.Y.Z.N` (one per day however many PRs merged) and dispatches `release-image.yml` on it, since a `GITHUB_TOKEN` release raises no release event. Run by hand, it releases `master` without the Dependabot condition. It waits while the line in `VERSION` has no `vX.Y.Z` release: bump `VERSION` and publish `vX.Y.Z` by hand for a new line.

## Shared browser UI

- `web/src/ky-ui/` is generated from Busnes-app/ky-ui, pinned by `VERSION` file hashes. Change shared colors, navigation states and storage helpers upstream, then run its consumer sync with an explicit worktree map; do not hand-edit vendored files.
- Products own layout, routes, saved choice keys and named palettes. Busnes aliases consume shared tokens; mark primary navigation with `ky-nav-item` while preserving current-page semantics.
- Verify vendored files with `node web/src/ky-ui/check-vendor.mjs` from this document's directory. Builds/CI run that check. Rendered evidence and capture limitations are recorded in the repository-root `UI-VERIFICATION.md`.

## Child DOX Index

- `internal/httpapi`: opaque routing ciphertext, role-gated mutations, and
  device-validated envelope writes are covered by the package integration
  tests; password/OIDC login, password change, step-up, recover, device, pairing, and upload
  endpoints use in-memory token buckets. Upload retries are byte-checked, and preview uploads remain
  content-addressed without creating an attachment row. Chunks read their body before taking a
  per-session lock (`lockUpload`); chunk and finalize re-check an editor-or-higher role
  (`checkUploader`) and the 24-hour session cap (`uploadLive`). `quotaExceeded` charges object
  saves, upload starts and finalizes to the target container's owner and team, counting live
  pending sessions. Admin settings/users,
  audit metadata, team membership, and encrypted comment reads/writes are
  session- and role-gated here.
- `internal/app` owns the `.kynotes.lock` data-directory lock (`storage.LockDirectory`: an `flock`
  held for the process lifetime; the file stays and is never copied or replaced, a dead holder never
  blocks; `TestDirectoryLock*`) and first-run
  bootstrap: only when no users exist, `BOOTSTRAP_ADMIN_USER`/`BOOTSTRAP_ADMIN_PASS` seed the administrator
  account and the optional `BOOTSTRAP_EVERYDAY_USER`/`BOOTSTRAP_EVERYDAY_PASS` the everyday account (different
  usernames, both flagged, one transaction); otherwise web `/setup` creates both accounts unflagged, or use
  `user add [--admin | --everyday]` (default everyday, flagged). Start-up logs `no_active_admin` with the
  CLI remedy in the message when accounts exist but no active administrator account does (`WarnWithoutAdmin`,
  `TestServeWarnsWithoutAdmin`). The probe refuses an administrator account at login;
  maintenance backup refuses to copy a live data directory and restore runs an integrity
  check after replacement.
- Migration `0026_account_kinds.sql`: `users.account_kind` (`user`/`admin`, fixed) and
  `memberships.approved`; triggers refuse the admin grant on an everyday account and any membership,
  owned container, device or `user_identities` row (whose device must be the same everyday account's)
  for anything but an existing everyday account, on insert and re-point. Upgrade keeps mixed administrators' content and drops their grant. Every path
  that creates an administrator sets `account_kind='admin'`. Verify `TestAccountKinds*`,
  `TestMixedAdminsKeepTheirNotesAndDropAdmin`, `TestAdminCreatesATeamForAnEverydayOwner`.
- Account kinds in `internal/auth` (default-deny): `RequireSession`, `RequireEither` and device
  credentials admit everyday accounts only (`403 admin_account`); `RequireAdmin`/`RequireStepUp` admit
  admin accounts only; `RequireAccount` (session, logout, logout-all, password change, step-ups) admits
  both; `RequireEveryday` serves only `GET /me/identity`. A password session on a password someone else
  set (`password_admin_known`) gets `409 password_change_required` everywhere but those account routes
  and the identity read. A new route needs a class: route functions register on `RouteMux`, `buildRoutes`
  records every pattern actually registered, and `internal/httpapi/account_kinds_test.go` fails on any
  pattern without a standard method or with a host (catch-alls `/`, `/api/`, `/api/v1/` excepted) and
  drives every other one, API or not, with both kinds and fenced sessions; public, account and device
  routes are listed there. Verify `TestEveryServedRouteIsClassified`, `TestEveryRouteRefusesTheOtherKind`,
  `TestEveryAccountRouteServesBothKindsUnfenced`, `TestPasswordChangeIsForcedAtFirstSignIn`,
  `TestAdminAccountsCannotPairDevices`, `TestKindGatesHoldWithoutTheTriggers`, `TestRefuseSessionKeepsKindsApart`.
- `internal/storage/migrations/0008_frozen_contract_columns.sql` exposes the
  frozen audit and idempotency-key schema on databases created by the earlier
  implementation migrations.
- `cmd/kynotes-probe` is the live 14-step client interoperability acceptance path: same session,
  identity, rotation, pairing, envelope, sync, upload and GC contracts as external clients. It
  unwraps or creates a password-wrapped identity (`teamkeys.UserKEK`/`SealIdentity`/`OpenIdentity`),
  stops on one without a password copy, and keys its notebook by a first rotation (generation 2).
  Its X25519 device key is random, persisted 0600 (`-device-key`, default under the user cache dir
  per server URL and username), never derived from `authSecret`; the device is revoked every run.
  An operator-set password (`password_change_required` on identity create, before pairing) is
  changed to a random one through `POST /api/v1/auth/password` and set back to `-password` after
  the device is revoked, re-wrapping the identity each time; re-runs skip it. The temporary
  password sits beside the device key (`.takeover`, 0600) until restored; the next run restores it.
- `FRONTEND_IMPLEMENTATION_PLAN.md` defines the separate responsive web MVP,
  browser crypto/local-storage boundaries, sync state machine, and mobile
  reuse path; it does not alter the frozen server plan.
- `web/` is the browser client; keep plaintext in browser memory only, send
  CSRF headers on mutations, and run its `npm test` plus `npm run build` checks; team notebooks use
  shared container keys (`keyring.ts`). It needs WebCrypto (HTTPS or localhost) and shows `NEEDS_HTTPS`
  otherwise: no hand-rolled cipher, KDF or `Math.random` fallback; sync SHA-256/HKDF come from
  `@noble/hashes`. Content is sealed v2, bound by AAD to container, object (or page) and kind; v1 is
  read only until a notebook migrates (see Content v2 migration below). Login iterations below `LOGIN_ITERATIONS` (600 000) are refused, except that an account this browser has
  not pinned may sign in at `LEGACY_LOGIN_ITERATIONS` (the server's 100 000) once: login then re-derives at 600 000
  and swaps the verifier and password copy through `POST /auth/login-upgrade` (`loginUpgrade.ts`), and a sign-in
  at 600 000 pins the username in `localStorage`. Verify `loginUpgrade.test.ts`, `TestLoginUpgradeReplacesALegacyVerifierOnce`.
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
  labels notebooks explicitly, and the administrator console (`components/AdminConsole.tsx`) uses tabbed
  server, users, teams, and audit sections. The save queue is kept in the
  existing IndexedDB vault, drains on startup/online recovery and every 15
  seconds, and uses a ciphertext-only BroadcastChannel hint for other tabs. The drain runs in
  the same `chained` queue as live saves and structure writes; a landed save clears only the
  queued copy this tab wrote (`clearQueuedSave` compares `updatedAt`). A page in conflict is not
  autosaved; its edits reach the server as conflict copies on leave/hide or "Keep the other
  version". A load reports objects it could not read (`unreadableNotice`). Verify
  `workspaceWiring.test.ts` (save queue wiring) and `storage.test.ts`.
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
- `web/` notebook export (`exportNotebook.ts`, `zip.ts`, docs/EXPORT.md `kynotes.export.v1`): the browser reads the
  notebook through `readContainerObjects` and attachments with `readKeysFor`, converts pages with BlockNote's
  `blocksToMarkdownLossy` (lazy-loaded) and downloads a stored zip; it sends nothing. Names pass `safeName`
  (no path escapes or clashes); unreadable items are counted, not fatal. Verify `exportNotebook.test.ts`,
  `zip.test.ts` and `web/e2e/export.e2e.ts` (real browser: GET-only requests, zip read back).
- `web/` exposes a client-only work queue for open checklist items across
  personal notebooks; task parsing remains browser-side because the server
  never sees plaintext. Inbox folders still require the planned folder-object
  client path. Items carry plain-word dates in their text (`taskDates.ts`: `due:YYYY-MM-DD`,
  `repeat:daily|weekly|monthly|yearly|every-N-days|every-N-weeks`, `remind:YYYY-MM-DDTHH:MM`, local
  time; invalid tokens stay text) and the queue groups them Overdue / Today / Upcoming (7 days) /
  Later / No date. Ticking a `repeat:` checklist item adds the next unchecked occurrence after it and
  drops `repeat:` from the done one in the same edit (`recurrenceEdits`, applied in
  `BlockNoteEditor.tsx`), so a re-check or reload never repeats it. Reminders (`reminders.tsx`) are
  in-tab notifications only, opt-in from Settings, saying "A task is due" unless task text is turned
  on; reminders passed before the tab opened fire nothing and show as missed. Reminder preferences are
  per account (`readReminderPrefs(userID)`). Verify `taskDates.test.ts` and `web/e2e/task-dates.e2e.ts`.
- Reminder push (opt-in, `IMPLEMENTATION_PLAN.md` "Reminder push extension"): `push:yes` beside `remind:`
  opts a task in; the Settings checkbox "Also remind me when KyNotes is closed" registers `web/public/sw.js`
  (shows a fixed "A reminder is due", opens `/#/`; no cache, fetch or storage; `/sw.js` is on the router
  allowlist) and PUTs the endpoint. Ids are `reminderID` (`reminderPush.ts`, HMAC under `reminderIDKey` in
  `keyring.ts`, not a content key); `main.tsx` reconciles `{id, at}` only after a work-queue load that read
  every personal notebook and object (`planReconcile` does nothing on a partial load), deletes before puts.
  Sign-out drops the browser's subscription; an account with push off drops one another account left.
  Server: `internal/httpapi/reminder_routes.go` (everyday session, CSRF, caps 10/500, `409 already_exists`),
  `internal/webpush` (endpoint allowlist `ParseEndpoint` checked at PUT and before every send; VAPID key
  `secrets/vapid.key`; `Fire` once a minute from `internal/app`, drained before SQLite closes). Never send a
  payload or log/audit an endpoint URL. Verify `TestReminder*`, `TestSubscriptionsRefuse*`,
  `TestServiceWorkerReachesEmbeddedFile`, `TestReminderRowsAreEverydayOnly`, `go test ./internal/webpush`,
  `npm test` (reminderPush, taskDates) and `web/e2e/task-dates.e2e.ts` (push subscribe is stubbed there).
- `web/` shows server commit receipts as a short `Last Committed Ns ago` toast
  that expires after 15 seconds.
- `web/` keeps a vault record per account in IndexedDB (`openVault`) holding the identity, pins and
  key memory, never a login secret: nothing on the device can sign in or step up. IndexedDB v7
  drops the `authSecret` earlier builds kept. A reopened password session holds no login secret in
  memory; its first step-up asks for the password (`stepUpAsking`) and background key passes defer
  rather than ask (`workspaceWiring.test.ts`). "Forget this device" clears the record. KySignOn
  sessions are never asked for a password; a refused password lets no one in.
- `web/` surfaces server-confirmed save times and treats `version_conflict`
  responses separately from offline failures, preserving the encrypted local
  draft without endlessly retrying a stale version. Server-kept conflicting
  versions are recovered as `(conflicting copy)` pages next to the original, one
  per distinct text (text equal to the server is resolved without a copy); the original
  reloads to the server version and a conflict is resolved only after its copy saves.
- `internal/httpapi` change feeds and listings answer 500 on any unreadable row rather than
  omit it, `hasMore` reads one row past the page, and conflict resolve takes a fresh
  `change_seq`. Verify `TestChangesNeverSkipAnUnreadableRow`, `TestResolvedConflictReachesSync`,
  `TestConflictSaveThatFailsToCommitIsNotAConflict`, `TestListingsFailRatherThanDropARow`.
- `internal/httpapi` commit receipts are deterministic SHA-256 commitments over
  opaque object/version metadata and ciphertext digest; share links store only
  token hashes and serve ciphertext without the URL-fragment decryption key.
  Browser-sealed links use a dedicated random content key and never reuse the
  authentication or workspace key.
- `internal/httpapi` exposes authenticated object attachment listings; the web
  client encrypts attachment bytes and metadata before chunked upload and
  decrypts them only for the current browser session.
- Blob writes go through `claimBlob` (clears the GC mark, confirms the file in the write
  transaction); `storage.sweepBlob` re-checks and deletes file then row in one transaction.
  A note delete tombstones only attachments it referenced; linking refuses deleted attachments
  and notes; re-uploading a deleted attachment revives it. Verify `TestGCSweep*`, `TestGCKeeps*`,
  `TestGCDeletesUnreferencedBlobAndItsExpiredTombstones` and `blob_lifecycle_test.go`.
- `internal/httpapi` presence is TTL-only in memory and membership-gated;
  notifications expose mention metadata only and use the existing 90-second
  foreground refresh cadence in the browser. The web client sends the user IDs of
  the members a comment names as `@username` (`web/src/mentions.ts`); a mention of
  anyone who is not a current member refuses the comment (`400`,
  `TestCommentMentionsOnlyMembers`).
- `POST /api/v1/admin/teams {"ownerUserId"}` (admin step-up) is the explicit admin team-creation path; the
  team belongs to that active everyday account (the administrator gets no membership) and records
  `admin.team.create` (object = owner). It takes no name; the owner's browser seals one after the first
  key. `GET /admin/teams` carries no name ciphertext. The admin member add (step-up) takes an active everyday
  account as `editor`, `commenter` or `viewer` only. `POST /admin/users` takes `accountKind`; `PATCH` refuses
  the grant on an everyday account (`409 account_kind_mismatch`). Verify `TestAdminUserRoutesKeepKindsApart`,
  `TestAdminTeamAccessNeedsStepUpAndListsNoNames`.
- Steward approval: administrator-added members have `memberships.approved=0` and the `viewer` role, the requested
  role in `pending_role` (`0027_pending_viewer.sql` triggers keep the three consistent), so no write or delete reaches
  them; attach, detach and conflict resolve need owner, admin or editor (`TestOnlyWritersAttachDetachAndResolve`) (child workspaces copy it;
  readmission resets it) and get no envelope, are not required by rotation and retire nothing on a key reset
  until an approved owner or admin of the team calls `POST /containers/{id}/members/{userID}/approve`
  (audit `container.member_approve`). The members list reports `approved`; the browser's `planSweep` skips
  unapproved members and stewards see an approve banner. Verify `TestAdminAddedMembersWaitForApproval`,
  `TestInvitedMembersAreApproved`, `keyring.test.ts` and `workspaceWiring.test.ts`.
- SSO account kinds (`ssoKindRefusal`): `kynotes.admin` signs in only to an administrator account and an
  administrator account only with it (`403 admin_account_not_provisioned`, `admin_role_on_everyday_account`,
  `admin_role_required`, audited `auth.sso_admin_refused`); automatic provisioning creates everyday accounts
  only. Directory sync decides the kind at creation and later moves only the grant (an everyday account's is
  refused, `role_refused=everyday_account`); readback reports `accountKind`; `apply-setup` reports `conflict`
  for an identity bound to an everyday account. Verify `TestSSOKindsFollowTheToken`,
  `TestDirectoryNeverGrantsAdminToEverydayAccounts`, `TestDecideAdmin`, `TestApplyAdminNeverPromotesAnEverydayAccount`.
- Web account kinds: `/setup` takes both accounts (`setup.ts` compares them; the server never sees either
  password); `App` routes a `passwordChangeRequired` session to `ChoosePassword` and an administrator session
  to `components/AdminConsole.tsx` before the workspace. The console imports no key, vault, notebook or content
  crypto module and keeps no vault record (`adminSeparation.test.ts`); the workspace has no admin view.
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
  only on 200, loopback hosts only, no redirects. It reads only the bind (`config.Bind`): no
  secrets, no writes (`TestHealthcheckWritesNothing`). Readiness turns false when shutdown starts;
  `Serve` waits up to `shutdown_grace` for a running GC pass before SQLite closes
  (`TestShutdownWaitsForRunningGC`). The reported version is
  `appversion.String()`: `-ldflags "-X …/internal/appversion.release=..."` overrides
  `internal/appversion/VERSION`; the Dockerfile takes `ARG VERSION` (CI passes the commit SHA).
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
  custodian-share/capsule-open entry point; in one transaction it revokes restored sessions,
  paired devices (identities stay), share links and sealed share links, and deletes pending
  invitations. Legacy local plaintext commands are `copy-data-dir` (`--out` absent or empty and
  outside the data directory) and `restore-data-dir` (`--in` needs `kynotes.sqlite` and both
  `secrets/*.key`; stages beside the data, integrity-checks, swaps entries by rename and keeps the
  old ones in `.restore-previous-*`; `TestRestoreDataDir*`). Every offline command that opens the
  database takes the lock (`openLocked`; `TestOfflineCommandsTakeTheDirectoryLock`) except
  `gc --now`, which the probe runs beside the live server (`ponytail:` in `gcCommand`); it refuses
  an unparsable or negative `--retention`. Capsules exclude all
  blob bytes, including note versions; full recovery needs the separate blob store.
  See `docs/RESTORE.md` and `docs/DEPLOYMENT.md`. The scheduler polls each minute,
  counts from last attempt and drains active work before SQLite closes.
- Passwords and recovery codes are Argon2id PHC strings via `ky-primitives/password`
  (scrypt verifiers are refused); login secrets derive through `ky-primitives/derive`
  with label `kynotes/auth/v1`; recovery codes come from `ky-primitives/recoverycode`
  and are minted by the server (`user add` prints one; `POST /api/v1/auth/recover`
  returns the replacement, spending the code only if its hash is unchanged inside the write:
  `TestRecoveryCodeIsSpentOnceUnderRace`); key files under `<data>/secrets` load through
  `ky-primitives/keyfile` and an undecodable file is a startup error. Password and derive
  admission-control failures surface as `auth.ErrBusy` and answer 503, never a lockout strike.
  The login dummy verifier retries a failed mint; it must never cache or use an empty hash.
- Backup/recovery mutations, `POST /api/v1/admin/users`, `PATCH /api/v1/admin/users/{id}`,
  `POST /api/v1/admin/users/{id}/password` and the SSO settings mutations (`POST /admin/sso`,
  `/admin/sso/pair`, verify `TestAdminSSOAndPairing`) use `auth.RequireStepUp`, so a stolen admin
  cookie cannot mint local credentials. The SSO client and directory HMAC secrets are write-only:
  admin responses carry only `clientSecretSet`/`hmacSecretSet` (`ssoView`); an empty field on save keeps
  the stored secret only for the same issuer (and client, for the client secret), otherwise a new one or
  `clearClientSecret`/`clearHmacSecret` is required (`mergeSSOSecrets`). Database, transport and remote
  errors reach clients only as fixed messages; `writeLogged` logs the detail (OIDC login/callback,
  KySignOn pairing: status code only). Verify `TestDatabaseErrorsNeverReachTheClient`,
  `TestProviderErrorsNeverReachTheClient`, `TestMergeSSOSecretsKeepsOnlyForTheSameTarget`. Local sessions re-prove their
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
  the immutable `ky-primitives/offsite` version in `go.mod`, including its strong SFTP
  key/algorithm policy and documented explicit SMB/NTLM interoperability choice.
  Migration `0015_blob_replicas.sql` tracks the single
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
  and spoofed/malformed/multiple-header cases in the HTTP API tests. The rate limiter
  records that address with `auth.WithClientIP`; every lockout keys on `auth.ClientIP`
  (`TestLoginLockoutKeysOnTrustedForwardedClient`). A full lockout table drops all but
  live locks before shedding a new key (`TestLockoutFloodOfCountsAdmitsFreshKey`).

- Migration `0018_sso_app_roles.sql` removes unproven linked-account admin roles,
  except active local grants when no unlinked active admin exists; retention is audited.
  It revokes old SSO sessions once and audits each affected identity. Keep an unlinked
  local administrator through upgrade; resync explicit `kynotes.admin` assignments.
  OIDC ignores singular/global role claims and stores a verified app-admin ceiling
  on each session. `auth.SessionRole` is shared by admin guards and session responses;
  SSO admin needs both that ceiling and an administrator account with the grant. Directory roles
  map only exact `kynotes.admin` from strings or SCIM value objects to admin;
  unrelated/missing/malformed role data grants nothing and never blocks deactivation; it blocks an
  administrator account's login (`admin_role_required`).
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
  `--capabilities` reads no configuration. `--check` uses socket `/v1/check-setup`
  (`checkSetup`, `backup.Service.CheckSetup`): read-only, admin presence means
  `account_kind='admin'`. `--stage` and `--import-client` run without the server through
  `config.LoadExisting` (never creates keys or data) and write only under
  `<data_dir>/installer/` with no-clobber private files. Setup files go through
  `openSetupParent` (descriptor walk, no symlinks, owner/mode checks). Verify
  `TestApplySetupCapabilities*`, `TestSetupInspection*`, `go test ./internal/applysetup`.
  `GET /api/v1/installer/network` is public in `account_kinds_test.go` and shares
  `resolvedClientIP` with the rate limiter. Compose leaves `TRUSTED_PROXY_CIDRS` empty, which
  keeps the loopback-only default (`TestEmptyTrustedProxyCIDRsTrustsNoProxy`,
  `TestDefaultTrustIgnoresForwardedForFromPrivatePeer`). Both handovers report
  `blobTargetConfigured` from `backup.blob_target.url` (`TestSetupHandoverReportsBlobTarget`).
  `X-Forwarded-Proto`/`X-Forwarded-Host` count only from a trusted peer (`forwardedFromProxy`,
  `requestScheme`, `requestHost`), shared by SSO login, KySignOn pairing and the installer
  network check. Verify `TestSSOForwardedHeadersNeedTrustedProxy`.
- Team keys P1: `internal/httpapi/identity_routes.go` serves `GET`/`PUT /api/v1/me/identity`
  (create-only, `auth.RequireUserActionStepUp`: a local password step-up creates `aes-256-gcm`, an SSO KySignOn confirmation creates device-only `wrap_alg='none'`). `GET`
  is public-only; the wrapped key rides only in local login/step-up bodies. The identity is a
  `devices` row with `platform='identity'` and an unusable `secret_hash` (migration 0021,
  `user_identities`); device auth, device list/revoke/selection, directory deactivation and role
  changes, register and the save gate exclude it. Password change must carry `identityDeviceId`
  and `wrappedIdentityKey` when a password-wrapped one exists (`409 identity_rewrap_required`), clears every session's
  step-up and shares the step-up lockout; recovery and admin reset remove only its password copy (audit `identity.password_wrap.delete`), and admin reset revokes paired device credentials in the same transaction.
  `PUT` and password change recheck inside their write transaction (`auth.RecheckUserStepUpTx`,
  `auth.RecheckSessionTx`, `TestRecheckTxSeesCommitsAfterMiddleware`): a session revoked (401)
  or a password/step-up changed (403 for `PUT`) after the middleware writes nothing.
  Login (`auth.MintPasswordSession`) and step-up mint the session or set `stepup_at` and load the
  wrapped identity in one transaction bound to the hash they verified; a change in between gets
  401, no cookie, no step-up and no wrapped key (`Test*RejectsConcurrentPasswordChange`).
  `users.password_admin_known` (admin create/reset, bootstrap, `user add`; cleared by own change or
  recovery) fences the session (account kinds bullet) and, inside identity actions, makes `PUT` and every local identity-action step-up (`auth.RecheckUserStepUpTx`: envelope `PUT`, rotation,
  invitation keys) answer `409 password_change_required`; the browser then creates the identity
  after the user's own password change. Any new path that sets a password for someone else must
  set the flag. `/setup` accepts only `authSecret`. A password change needs no content warning
  (`web/src/passwordChange.ts`).
  `web/src/teamKeys.ts` holds the envelope/identity primitives on `@noble/curves`/`@noble/ciphers`
  (exact pins); `web/src/identity.ts` creates the identity silently after a local password login
  or `/setup`, never replaces one it cannot open, and caches it in the IndexedDB vault
  ("Forget this device" clears it). SSO sessions create device-only identities (P3c).
  `internal/teamkeys` regenerates `testdata/protocol/envelope_vectors.json` (`-update`);
  `web/src/teamKeys.test.ts` replays it. Verify `TestIdentity*`, `TestUserActionStepUpRefusesUngrantedSSOSession`,
  `TestRegisterCannotClaimIdentity`, `TestPasswordChangeRewrapsIdentityAtomically`,
  `TestRecoveryAndAdminResetKeepIdentity`, `TestAdminKnownPasswordGatesIdentityUntilOwnChange`,
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
  member identity. `checkWriteGate` serves object saves, comment create and attachment
  finalize, before streaming and inside the transaction (object saves also recheck role there):
  live membership, `shared-v2`, a key (`shared_generation > 0`), the current generation, then the
  writer's own identity envelope; `checkContainerKeyed` (member, `shared-v2`, a key) gates upload start,
  chunks and preview finalize, and container creation takes no name. `removeMemberTx` serves owner/admin and server-admin
  removal (children revoked, generations bumped, envelopes, selections and the removed user's
  pending invitations deleted, audited in the same transaction). Invitations may carry identity
  envelopes (`invitation_envelopes`, moved on accept only at their generation and only while the
  inviter is still a steward); creating one with envelopes needs `auth.HasUserStepUp` plus
  `RecheckUserStepUpTx`, while accept only moves envelopes authorized at insertion. `GET /users/{id}/identity`
  answers self, live co-members and an inviting steward, else a uniform 404;
  `object_versions.author_user_id` is written, not yet read. Shared 409 `already_exists` covers
  moved generations, duplicates and incomplete rotations. Known limits are listed in
  `IMPLEMENTATION_PLAN.md` §9. The probe seals and opens a real envelope with `internal/teamkeys`
  (never linked into the server). Verify `TestEnvelope*`, `TestKeyRotation*`,
  `TestOwnIdentityWriteIsRewrapOnly`, `TestConcurrentRotationsCannotSplitAGeneration`,
  `TestUnkeyedContainerRefusesEveryWrite`, `TestUnkeyedContainerTakesNoInvitationEnvelope`,
  `TestEveryWriteNeedsTheCurrentKeyScheme`, `TestContainerCreationTakesNoName`,
  `TestNewContentRefusedUntilRotationEnvelopesExist`,
  `TestSaveRacing*`, `TestAdminMemberRemovalRotatesLikeOwnerRemoval`,
  `TestRemovedMemberCannotWriteAnywhereInTheTeam`, `TestCollaboratorRemovalRulesAndAcceptOutcomes`,
  `TestInvitation*`, `TestUserIdentityVisibility`,
  `TestOpenEnvelopeAgreesWithVectors` and the probe.
- Team keys P3a (web): `web/src/keyring.ts` (pure: envelopes → generation keys, write key, exact-generation
  read key, steward sweep plan), `web/src/keyService.ts` (one sweep against an injected API: mint via
  rotation, backfill wraps, one retry on 409) and `web/src/pins.ts` (add-only TOFU pins in the vault
  record, local fingerprints; trust rules in the next bullet). Trust prompts and key notices name people
  only through `displayName(username, userId)`: one sanitized line, `<userId> · <name>`, ID first so a name
  cannot pose as it, name capped at 64 characters. Reads: `readKeys` opens a row only with
  the container key of its own generation at or above the first keyed generation (`sharedGeneration`); below it,
  in an unkeyed container or with a malformed generation it gives no key. `ownCopyKeys` adds the identity's
  waiting key for this browser's own generation-0 copies only. `KeyRef` is branded and minted only in
  `keyring.ts` (`asContentKey`); `contentKeys.test.ts` fails if any other file mints or casts one, or if
  `authSecret` meets content crypto. `writeKey(container, ring, floor)` has no write key for an unkeyed
  container, so the `outbound.ts` gate refuses it; local copies wait under `waitingKey(identity)` (HKDF
  `kynotes/waiting/v1`) or are not kept; `planSweep` mints a first key for every keyed member only when
  the caller's identity is `recoverable` (plan `unrecoverable` otherwise; re-mints never wait).
  Notebooks are created only through `createNamed` (`observe.ts` `createKeyed`: a still-empty notebook
  whose mint or naming failed is deleted). Waiting copy follows the member list, never `kind`
  (`web/src/keyNotices.ts`).   `web/src/components/RecoveryCode.tsx` is the only UI that shows, uploads, restores or resets a recovery
  code: shown once (print or download on a click, never the clipboard, URL or storage), type-back of a
  random group, autofill opt-outs on every code field, restore beside "Link this browser", and a reset
  that lists its losses, offers the unsent-edit export, needs RESET typed and, for password sessions,
  the password (step-up and new password copy). Verify `RecoveryCode.test.tsx` and `workspaceWiring.test.ts`.
  `main.tsx` writes containers only with the current key; with
  keys missing every mutation handler returns on `readOnlyForKeys()` and its control is disabled (no empty
  objects), and in-progress edits queue at generation 0, resealed on arrival, never uploaded at 0. The
  drain uploads an entry only through `readyToSend` (`web/src/drain.ts`): as is only when sealed for the
  current `writeKeyFor` generation, otherwise re-sealed from its own
  generation's key first, or kept queued while no write key exists. Every container-key
  ciphertext upload (object saves, attachment start/chunks/finalize, comments, container names) goes
  through the `web/src/outbound.ts` gate, which re-checks the sealing generation against `floorOf` and
  the workspace's `writeKeyFor` right before the request; pending attachments pass `attachmentStep`
  (wait or reseal payload and metadata) before the first chunk, and `outbound.test.ts` fails if any other
  module calls those API functions; queue
  replacements go through `replaceQueuedSave` (compare-and-set). `api.ts`
  `serverGeneration` turns malformed server generations into `undefined`. The first mint re-seals the shown name and says so.
  Rollback rule: `KeyState` also keeps the highest `shared`/`generation` the server reported (add-only,
  persisted by `syncContainerKeys` before use); `writeKey`/`readKeys` require that floor and
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
  `rollback`: writes paused. `kind`/`teamId` are server claims for layout only and
  decide no key; every notebook gets a key pass. `keyring.test.ts` fails if a key module reads them.
  `storePins` is atomic and returns `{ ok: false, conflicts }` for a member pinned to another key; the
  pass then stops before upload (plan `untrusted`). A pass that stops on a pin it could not keep
  (declined, unsaved or conflicting) re-opens against the stored pins (`persistedOnly`) and returns, and
  saves key memory from, only that; if a first-contact pin is still unstored it returns only held keys
  matching the stored digests and re-saves the prior key memory with the raised floor, so a refused
  sender's key is never adopted or remembered and `keyStateSaved` reports that save.
  Server: containers report `sharedGeneration`; every content write and name change needs
  `X-Kynotes-Key-Scheme: shared-v2` (409 otherwise); meta `PATCH` must carry the current `keyGeneration` and checks role
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
  with the container key, a newcomer gets history, removal re-mints at once
  (generation N+2 holds envelopes for the remaining members only, before anyone writes), and a
  write without the key-scheme header gets 409. P3b steps: an invitation sealed for the invitee opens
  the team before any owner opens it again, refuses another account and a pre-removal invitation, a link
  pasted into an open tab joins, a re-invited member waits and asks, a declined changed key is never
  sealed, re-trust in Settings, unsent edits export and discard, and a click during the automatic load
  (held at its last request) leaves the list loaded when it stops being busy. P3c steps: newcomer Cancel,
  either side leaving Settings, and approver "Codes differ" each delete the request (collect answers 404);
  a reload mid-attempt sends a keepalive cancel, so the request is gone (collect answers 404); a relay
  swapping the approver key (rewritten collect) keeps Approve disabled with the newcomer's code typed and
  sends nothing; the honest link needs the typed code, keeps the collected bundle unopened until the
  newcomer's "Codes match", stores the same identity sealed and non-extractable, refuses a second collect,
  opens the team with one fingerprint; a cache that refuses writes still sends with the no-local-copy text;
  Forget asks with its exact text and empties the vault. P5 steps: an administrator reset keeps the key and
  the user's own reset (typed RESET, password step-up, its response lost after commit) replaces it, after
  which the old key opens no re-shared envelope; a new personal notebook is keyed at creation and no request
  body opens with the login key; a login-key page a server slips in never shows; a recovery code's type-back
  group changes when it is shown again; a waiting-key edit survives a password change and is sent; a fresh
  browser restores with the code (typo refused before any request, wrong code and a copy for another key
  refused, no link request, code in no storage or URL); a v5 local database is dropped at v6. No browser
  ever requests a `/legacy` path. Every browser dialog must
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
  `[owner, id]` (IndexedDB v6 cleared older rows once), so no save, replace, clear or
  read touches another account's entry; every entry carries its owner, and Unsent edits lists this
  account's edits for notebooks it lost and those sealed under a previous key (export, discard). Export is plaintext and marked unencrypted, the drain uploads only this account's edits. `loadGate.ts` lets only the
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

- Team keys P5: personal keys and the recovery code. Every notebook is keyed at creation (`main.tsx`
  `createNamed`; an administrator-created team is keyed and named by its everyday owner); one whose first key was never minted is read-only
  until its owner's next open mints it; `planSweep` has no `blocked` plan and refuses a first key while the caller's
  identity is not `recoverable` (password or recovery-code copy); no key module reads `kind` or `teamId`
  (structure test). Waiting edits seal with `waitingKey` (HKDF `kynotes/waiting/v1` over the identity).
  Server: migration `0025_identity_recovery.sql`; `PUT /api/v1/me/identity/recovery` (compare-and-swap on
  `recoveryId`, idempotent for an identical copy, user-action step-up) and `POST …/recovery/fetch`
  (step-up, `no-store`, audited, one 404 for no identity and no copy). Both and `PUT /me/identity` share the
  `recovery` bucket at `pairing_per_hour` (`ponytail:` in `ratelimit.go`). `PUT /me/identity` with
  `replace` and `expectedDeviceId` is the self-service reset: one transaction swaps the identity, its
  recovery copy and (password users) its password copy, revokes other sessions and paired devices with
  their envelopes, advances `key_generation` in every keyed container where the user is an approved member (`retireKeysTx`,
  as a removal; stewards mint the next key), refuses the old key and audits `identity.reset`
  (`containers_retired=N`), at most `identityResetsPerDay` (3) a rolling day (`429`); members lists give stewards
  `keyResetAt`; a minting sweep also wraps history in that pass. Verify `TestIdentityReset*`,
  `TestStewardsSeeWhoResetTheirKey`, keyService and keyNotices tests. Recovery and administrator resets keep
  the identity and remove only its password copy; the user's own password change re-adds it when
  `GET /me/identity` says `passwordCopy:"addable"` (never for KySignOn-linked accounts). Web:
  `recovery.ts` (128-bit Crockford code, 10-bit checksum, PBKDF2-SHA256 600000 over a labelled salt with
  client-side constants, AAD user and public key; `testdata/protocol/recovery_vectors.json` from
  `internal/teamkeys`), upload only after `confirmRecoverySaved` (a random type-back group, fresh each time
  the code is shown; `components/RecoveryCode.tsx` only), restore checks the checksum first and never
  overwrites another key, reset needs the typed phrase and retries with the same key after a lost response.
  A KySignOn-linked account's reset is device-only from any session (`409 device_only_required`; the
  browser re-sends it). The browser notes a reset's new key before sending (`resetSent`) and explains a
  committed reset whose answer never arrived; edits waiting under the replaced key are marked `previousKey`,
  never sent, and listed under Unsent edits. A notebook's creator (still its owner or admin) deletes it
  without the recent-sign-in window only while it was never keyed or named and holds nothing (spec P5 item 24).
  Add person, Remove and New team notebook show only to stewards (member role from the server).
  A replaced code stays valid in database backups; only a reset cuts it off. Awaiting Yoshi: D-P5-1
  (resets keep the identity), D-P5-2 (the stricter never-password-wrap-after-reset option, not built),
  and P3c (1) raw identity on plain HTTP (P5 adds restored identities), (3) the device-key layer and
  (4) IdP-operator powers (P5 adds replacing the recovery code and resetting an SSO account's identity).
  Known limits are in spec §7 "P5 as built". Verify `TestIdentityRecovery*`, `TestIdentityReset*`,
  `TestRecoveryAndAdminResetKeepIdentity`, `TestPasswordChangeReadds*`, `TestSSOAccountSetsAndFetches*`,
  `TestSSOResetStaysDeviceOnly`, `TestLinkedAccountResetIsDeviceOnlyFromALocalSession`,
  `TestNonStewardsCannotManageMembersOrCreateTeamNotebooks`, `TestCreatorDeletesABlankNotebookWithoutARecentSignIn`,
  `TestAdminPasswordResetRevokesPairedDevices`, `go test ./internal/teamkeys`, `npm test` (recovery, identity,
  keyring, keyService, drain, contentKeys, workspaceWiring, keyNotices, RecoveryCode, storage, stuckEdits) and
  `npm run e2e --prefix web`.
- Team keys, legacy key removed (2026-10-08, spec §9): no content key derives from `authSecret`. Server: a
  container takes content, names, envelopes, invitation envelopes and uploads only once it has a key
  (`checkWriteGate`, `checkContainerKeyed`, meta `PATCH`, `putGenerationTx`), creation takes no name, and
  every write carries `X-Kynotes-Key-Scheme: shared-v2`; `GET /containers/{id}/legacy` and
  `PUT /comments/{id}` are gone (`TestRemovedLegacyRoutesStayGone`); no migration. Web: IndexedDB v6 drops
  the earlier cache, queue and uploads once; `readKeys`/`ownCopyKeys` are the only key choices;
  `contentKeys.test.ts` guards the brand. Probe:
  password-wrapped identity (`teamkeys.UserKEK`/`SealIdentity`/`OpenIdentity`), notebook keyed at creation.
  Verify `TestUnkeyedContainerRefusesEveryWrite`, `TestEveryWriteNeedsTheCurrentKeyScheme`,
  `TestContainerCreationTakesNoName`, `TestIdentityWrapAgreesWithVectors`, `npm test` (contentKeys,
  keyring, drain, storage, stuckEdits, workspaceWiring) and `npm run e2e --prefix web`.
- `internal/notecrypto` is the Go port of `web/src/crypto.ts` content sealing (objects, container
  names, attachment metadata and bytes) for the MCP bridge. Writes are content v2 (`IMPLEMENTATION_PLAN.md`
  §1.3 "Content sealing"): `0x02 ‖ nonce(12) ‖ AES-256-GCM`, subkey `HKDF-SHA256(containerKey, salt =
  containerID, info = "kynotes/content/v2")`, AAD binding container, bound ID (the object; the page for
  comments and attachments; the container for its name) and kind. Seal* take the bound ID; Open* take it
  and whether v1 (unbound, per-label subkeys, no AAD) may be read; `OpenContainerName` also reports the
  migration marker (`objects: 2`, v2 only). `Payload.Legacy` (a page's v1-child pins) round-trips:
  `{}` is written, absent is not. `OpenObject` narrows like `parseObjectPayload`. Change it only
  together with `crypto.ts`. `go test ./internal/notecrypto -run TestPayloadVectors -update` regenerates
  `testdata/protocol/payload_vectors.json` (v1 vectors for the read path, v2 for every kind with its
  AAD); `web/src/payloadVectors.test.ts` opens it and reseals the v2 vectors byte-identically (nonce
  stubbed, no `*ForVector` export). `TestNotLinkedIntoServer` keeps it, `internal/teamkeys`,
  `cmd/kynotes-mcp` and the MCP go-sdk out of `cmd/kynotes-server`. Verify `go test ./internal/notecrypto`
  (`TestSwappedObjectIsRejected`, `TestCrossKindSwapIsRejected`, `TestV1OnlyBeforeTheMarker`,
  `TestLegacyPins`, `TestV2VectorsOpen`) and `npm test` (payloadVectors).
- Content v2 migration (web): every save seals v2 bound to its object; a writer's notebook load queues
  one background pass (`web/src/migrate.ts` `migrateNotebook`, run by `main.tsx` `migrateOpen` after the
  load renders) that re-saves v1 objects through `writeObject`/`updateStructure`/`pinPage` (the
  `chained` queue) and pins each page's v1 children (`childPins`: SHA-256 of the stored ciphertext,
  attachment bytes downloaded) in its `legacy`; only then the name is rewritten v2 with `objects: 2`.
  The marker is pinned per user and notebook in the vault (`KeyState.objects`, add-only); after it,
  server copies open v2 only (`readContainerObjects`), children need a pin (`legacyChildOpens`) and a
  name without the marker is refused (`OLDER_META`). Local copies (cache, queue, pending uploads) may
  be v1 and are re-sealed v2 before upload (`readyToSend`, `attachmentStep`). New notebooks are named
  with the marker. Verify `npm test` (crypto, migrate, drain, pages, notes, storage, payloadVectors,
  workspaceWiring "content v2 refusal point") and `npm run e2e --prefix web` (`web/e2e/migration.e2e.ts`:
  an older notebook migrates in a second browser, then an unpinned v1 comment, an injected v1 page
  and an older name are refused).
- `cmd/kynotes-mcp` is the local stdio MCP bridge (`docs/MCP.md`, go-sdk `v1.8.0`, allowlisted for it
  only): one notebook (`--notebook`), signed in as the agent's own everyday account with its
  password-wrapped identity; no device pairing, no stored session, re-login once on 401. Key trust
  ports `openKeyring` (own identity, or a current owner/admin matching its TOFU pin; pinned history
  below the mark; first key per generation wins); a changed pin stops the bridge, a lower reported
  generation (`keyState.raise`) refuses every tool. State dir `0700`: `trust.json` (pins, floor,
  digests) and `audit.jsonl` (tool, page IDs, outcome, code; never titles or text), both `0600`.
  Tools: `list_pages`, `read_page`, `search`; `create_page`, `append_to_page` only for owner/admin/editor
  without `--read-only`. Writes seal with the current generation, add paragraph and checklist blocks
  only, and resolve their own `version_conflict` (one re-read). 60 calls a minute. Verify
  `go test ./cmd/kynotes-mcp` (`TestBridgeEndToEnd` drives a real router through the SDK) and
  `TestNotLinkedIntoServer`. Pages are sealed v2 (new pages with `legacy: {}`, edits keep `legacy`);
  v1 objects are read only until the notebook's name (from the containers listing) carries the
  migration marker, which `trust.json` then pins per notebook (`objects: 2`); a name without it
  afterwards is `errOlderMeta` for every tool (`TestBridgeFollowsTheMigrationMarker`).

## Operator documentation

`docs/ASSURANCE-CASE.md` and `docs/VERIFYING-RELEASES.md` make claims about the code and the release workflow; a change that moves a trust boundary, a security requirement, the image build or its attestation identity updates them in the same change.

`INSTALL.md` is the root-owned standalone entry point. When installation prerequisites, bootstrap, persistence or verification change, update it together with `README.md` and the linked operator guides.
