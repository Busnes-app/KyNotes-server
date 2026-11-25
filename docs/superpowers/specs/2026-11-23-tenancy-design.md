# Tenancy: single-tenant and multi-tenant (SaaS), KyNotes design

Date: 2026-11-23, revised the same day for owner decisions 9 and 10. Status: merged in #176
and being built; see "PR 1 as built". The line references below describe `master` before any
tenancy code (`961a302`), when no `org_id` appeared under `internal/` or `cmd/`.

Owner decisions (fixed, not reopened here):

1. One binary, both modes. Single-tenant is today's self-hosted behaviour, and it is unchanged,
   byte for byte, on upgrade. Multi-tenant is a mode.
2. Organisations under one sign-in: one KyIdentity issuer for every customer. Each account
   belongs to exactly one org, and tokens carry an opaque `org_id`. There is no org switcher.
3. Only our staff are administrators. Customers are members.
4. Stripe lives only in a separate billing service. KyNotes has no billing code.
5. **Every paid account is an org** (2026-11-23). Personal is an org of 1, Couple 2, Family up
   to 6, and Business N seats (small teams). All four plans run on the **shared, multi-tenant,
   multi-server** install. Only **Enterprise** gets a dedicated install (cloud or on-prem), and
   single-tenant SQLite is fine there. This supersedes every line in T, in KyCalendar's spec and
   in KyDrive's spec that says businesses get their own single-tenant install or that the shared
   service holds only individuals and households.
6. KyNotes and KyMessages are in the hosted launch. All seven apps are sold in every plan.
7. **Multi-tenant needs multi-server** (2026-11-22): multi mode runs as several replicas
   across hosts.
8. 2026-11-20 and 2026-11-21 answers that apply here: the **Delete everything** button that
   cannot be undone and survives a restore, and the `export_only` claim (K open question 4 (a)):
   KyIdentity issues it during `deletion_scheduled`, and apps admit only their export routes
   under it.
9. **Object storage** (2026-11-23). On the hosted install, primary content (for KyNotes: blobs)
   goes in S3-compatible object storage, about $0.014/GB/month with a backup copy, against about
   $0.07 for volumes. Launch runs on disk volumes if object storage is not ready, so the volume
   backend keeps working behind one interface. Single-tenant installs keep the volume path
   unchanged. Bucket keys come from the environment or a file, never from a log or this spec.
10. **One storage pool per org, across all apps, required for launch** (2026-11-23). One number
    per account, shared by every member and set per org: Personal 20 GB, Couple 40 GB, Family
    100 GB, Business 30 GB per seat (pooled across the team), Enterprise custom. **KyIdentity
    holds the pool.** Each app checks it before a write that adds bytes and reports its usage.
    Today's per-upload and per-user caps may stay as safety limits, but the number a customer
    buys is the pool.
11. **Object storage only in multi-tenant mode** (2026-11-23, afternoon; KyNotes #176). There is
    no disk-volume fallback: a hosted install refuses to start without object storage. Single-tenant
    installs keep their volumes. This replaces decision 9's "launch may run on volumes".
12. **Delete everything and shared data** (2026-11-23, afternoon). Shared content passes to the
    longest-standing admin, then an editor, then any member. A person's messages in shared rooms
    become tombstones; for KyNotes, their comments in notebooks others keep. Nothing other
    members wrote is deleted. This answers open question 4 with (a).
13. **No automatic version pruning at launch** (2026-11-23, afternoon). This answers open question 12.
14. The pool is KyIdentity's merged contract (#290, `docs/SUITE-DIRECTORY.md` "Storage pool"):
    report-and-grant. It replaces this spec's assumed allowance in the org poll ("The org storage
    pool" below). The 2026-11-23 decisions on incoming mail and seats do not touch KyNotes.

Tracking: `Busnes-app/ky-launch#4` (a checklist per app).

References:

- KyNotes lines are `origin/master` at `961a302`. Migrations are cited by file name, for
  example `0002_devices.sql:3`, under `internal/storage/migrations/`.
- **T** is KyIdentity `docs/superpowers/specs/2026-11-19-tenancy-design.md` at `origin/master`
  `5604cd9`. It defines `org_id` in tokens, logout tokens and webhooks, `/api/suite/orgs`,
  `/api/suite/erased`, Delete everything, `export_only` and home regions.
- **C** is KyCalendar `docs/superpowers/specs/2026-11-20-tenancy-design.md` at `origin/main`
  `c2e5bf0`. This spec follows its structure.
- **K** is KyPost `docs/superpowers/specs/2026-11-20-tenancy-design.md` at `origin/main`
  `e46f01c2`.
- **D** is KyDrive `docs/superpowers/specs/2026-11-20-tenancy-design.md` at `2a39c11`.
- "The replica pattern" is ky-server-base `docs/REPLICAS.md` at `2340ac8`.
- `suitedir` is ky-primitives `suitedir/client.go` at `90b0e58`.

"Unverified" marks a claim this spec did not check in code or by running it.

## What makes KyNotes different

Three facts drive most of the design. They are why KyNotes cannot simply copy C.

1. **The server never sees plaintext.** Pages, section names, notebook names, comments,
   attachment bytes and attachment metadata are sealed in the browser (`DESIGN.md` §4
   "Encryption", `AGENTS.md:213-218`). Content keys live in per-container envelopes, sealed to
   member identities (`AGENTS.md:657-687`). Search, task parsing and export all run in the
   browser (`IMPLEMENTATION_PLAN.md:2027-2028`, `AGENTS.md:273-289`). So:
   - staff cannot read content even with the database;
   - there is no server search index to isolate;
   - a server-side "export org" command could only hand out ciphertext.
2. **Every write invariant assumes SQLite's single writer.** The store opens SQLite with
   `_txlock=immediate` (`internal/storage/store.go:72`), so every write transaction holds the one
   database write lock. Code relies on that by name. `dropUnclaimed` runs "inside tx (which
   holds the write lock)" (`internal/httpapi/object_routes.go:418-427`). GC deletes a blob file
   inside its transaction (`internal/storage/gc.go:99-125`). Quota checks count and then insert.
   PostgreSQL in read-committed mode gives none of that.
3. **Blobs are content-addressed across the whole install.** `blobs` is keyed by the ciphertext's
   SHA-256 (`0001_init.sql:5`), the file is `<data>/blobs/aa/bb/<digest>`
   (`internal/blobstore/blobstore.go:35`), and `blob_containers` maps one blob to many containers
   (`0001_init.sql:6`). Today, two containers anywhere on the install that hold identical
   ciphertext share one file.

## Summary

| | Single-tenant (self-hosted, Enterprise) | Multi-tenant (hosted: Personal, Couple, Family, Business) |
|---|---|---|
| Mode | `KYNOTES_TENANCY=single` (default) | `KYNOTES_TENANCY=multi` |
| Database | SQLite at `<data>/kynotes.sqlite`, as today | PostgreSQL only (N2) |
| Servers | one process per data directory (`.kynotes.lock`) | several replicas across hosts (N2, N12) |
| Blobs | `<data>/blobs/`, as today | S3-compatible object storage keyed by org, or a shared volume until it is ready (N8, N15) |
| Storage limit | per-user and per-team caps, as today | the org's pool from KyIdentity, with today's caps kept as safety limits (N10) |
| Sign-in | local passwords, plus any OIDC provider an admin pairs | KyIdentity only, fixed by environment (N5) |
| Org of a row | the default org | the account's `org_id`, from KyIdentity |
| Administrators | local administrator accounts | staff only: administrator accounts in the staff org (N6) |
| Teams | admin-created and member-created | member-created, inside one org only (N7) |
| Sharing outside the org | n/a | share links only (by token, ciphertext only) |
| Background jobs | per process, as today | one elected worker, plus claims for reminders (N12) |
| Code paths | one: every query is bound to the default org | the same code, bound to the caller's org |

## Decisions this spec makes

| # | Decision | Why |
|---|---|---|
| N1 | `KYNOTES_TENANCY=single` (default) or `multi`, recorded in `server_settings` at first start. A later start with the other value refuses to start. In multi mode `KYNOTES_STAFF_ORG_ID` and `KYNOTES_REGION` (N13) get the same treatment, and setting either in single mode is a startup error. All three join the shared-configuration fingerprint (N12). | Install-time, as T D1 and C D1. A replica started in the wrong mode, or with another staff org, would make different access decisions on one database. |
| N2 | **Multi mode requires PostgreSQL and runs as several replicas.** SQLite stays single-tenant only, unchanged. Startup in multi mode refuses unless every replica requirement in "Replica work" holds, and the refusal names each missing piece (as D D13). Single-tenant installs keep SQLite. This spec adds no SQLite→PostgreSQL migration for them (open question 7). | Owner decisions 5 and 7. Today the store opens only SQLite (`internal/storage/store.go:16`, `:72`), and the path is hard-coded (`internal/app/serve.go:38`). |
| N3 | **On PostgreSQL every write transaction takes one advisory transaction lock** (`pg_advisory_xact_lock` on a fixed key) as its first statement. Reads take none. **No network or blob I/O runs while it is held.** Where a blob operation must not interleave with another on the same key, both take a PostgreSQL **session** advisory lock on that key (an upload ID, or an org and digest) on a dedicated `*sql.Conn`, do the I/O, and then open the short write transaction **on that same `*sql.Conn`**, so a request never needs two pool connections at once. The two-replica test runs a burst of saves and uploads with the pool saturated. | Fact 2: it keeps every SQLite immediate-transaction invariant without auditing each one again, and across replicas too. KyIdentity serialises its Postgres writes the same way (T "Entitlements"), and C keeps one `calendar-total` lock. The cost is one writer for every org (open question 5). Today the blob is already written before the transaction opens (page save, `object_routes.go:312` then `:319`; finalize, `upload_routes.go:370` then `:378`), In multi mode four paths change: chunks; GC; page save and upload finalize, which now hold the org-and-digest session lock from the existence check through the claim's commit; and `dropUnclaimed` (`object_routes.go:418-427`), which today deletes an unclaimed blob inside the refused transaction. In multi mode the refused transaction rolls back first, and the unclaimed object is deleted after it, still under the session lock. The age-gated orphan sweep is the backstop if that delete fails. |
| N4 | Isolation is enforced in the application: every org-owned row carries `org_id`, an org-bound store handle binds it, and triggers check existence, immutability and agreement with the parent row. | T D3 and C D3. The store has one SQL text for both backends, and single-tenant SQLite runs the same handlers. |
| N5 | In multi mode the sign-in provider is fixed by environment: `KYNOTES_SSO_ISSUER`, `KYNOTES_SSO_CLIENT_ID`, `KYNOTES_SSO_CLIENT_SECRET`, `KYNOTES_SSO_HMAC_SECRET`. The admin SSO save and pairing routes answer `404`. Auto-provisioning is always on. Customer password sign-in, `/setup`, `user add` for everyday accounts and `apply-setup` are refused. | Today SSO settings live in `server_settings` and are cached per process (`internal/sso/sso.go:27-98`), so a save on one replica leaves the others stale. One issuer (owner decision 2) means the binding never changes. Customers then always get device-only identities with a recovery code, which already works (`AGENTS.md:830-873`). |
| N6 | In multi mode an account is an administrator only when it is an administrator account (`account_kind='admin'`) **and** its `org_id` is the staff org. Staff accounts are created only by `kynotes-server user add --admin` and the bootstrap variables, into the staff org. | Owner decision 3. Administrator accounts already open no notes (`AGENTS.md:179-196`), so staff never hold content keys. This is defence in depth against a staff mistake that sends `kynotes.admin` for a customer. |
| N7 | **A container, its members and its invitations are in one org.** Triggers refuse a membership, an invitation acceptance, or a key or invitation envelope (`key_envelopes`, `invitation_envelopes`) whose user is in another org than the container. **No trigger runs on invitation insert:** an invitation to another org's user ID is created like one to an unknown ID, so creation answers the same for both, and it can never be accepted. Handlers check the org explicitly before each insert and answer as for a missing row: accept answers not-found, and `insertInvitationEnvelopeTx` adds the org to its identity-device check (`teamkeys_routes.go:473-477`), so another org's device gets `errEnvelopeInvalid`, as an unknown device does today. The triggers are a backstop whose error no handler maps to its own answer. | Teams are how Couple, Family and Business share notebooks, so they stay on in multi mode. Today `invitee_id` is any well-formed user ID with no existence check (`internal/httpapi/collab_routes.go:165-197`), so creation reveals nothing. Accept checks the invitee inside its transaction (`collab_routes.go:235`). |
| N8 | **Blobs become org-owned.** `blobs` gains `org_id`, and on PostgreSQL its key is `(org_id, digest)`. The key in multi mode is `orgs/<org_id>/blobs/aa/bb/<digest>` on both backends (today's fan-out under an org prefix). Single-tenant keeps `<data>/blobs/aa/bb/<digest>` and the digest key. | Fact 3. A shared digest across orgs would let one org's upload, purge or quota interact with another's file. Per-org keys make a purge a prefix delete and quota exact. KyDrive refused content addressing for the same reason (D "Blob storage"). |
| N9 | KyNotes keeps a local mirror of `/api/suite/orgs` (`orgs` table), polled about every 60 s by the elected worker (`suitedir.Client.Orgs`, `suitedir/client.go:241`). Every authenticated read joins the account's org row in the same query as the account. | T D6 and downstream contract 5. C D6. A suspension then takes effect at the next request on every replica. |
| N10 | **The storage limit is the org's pool, held by KyIdentity.** KyNotes counts the org's charged bytes, reports them, and refuses a write that adds bytes past the grant KyIdentity's answer to the report gives (owner decision 14: `ceiling_bytes`, valid `ttl_seconds`). The grant is stored per org, so the write path makes no network call. Today's per-user and per-team caps stay as safety limits. There is no per-app `max_bytes` key. | Owner decision 10. A per-app storage key in T's `quotas_json` would be a second number the customer never bought. It matches KyCalendar's D14 (PR #190), so every app reads the pool the same way ("The org storage pool"). |
| N11 | **Export runs in the browser, under `export_only`.** A session whose ID token carries `"export_only": true` is marked so. It admits only the routes the browser export needs, listed once in Lifecycle, Export: the reads, plus the few writes that hold no content (logout, recovery-code fetch, browser linking), so a fresh browser can still export (open question 6). Every other route answers `403 export_only`. There is no operator export command. | Fact 1: only the browser can decrypt. The browser export already exists (`exportNotebook.ts`, `AGENTS.md:273-277`). Owner decision 8. |
| N12 | **Multi mode adopts the replica pattern**: `/livez` and `/readyz` with the drain order, a shared-configuration fingerprint, one elected worker through a PostgreSQL session advisory lock, and every security limit in PostgreSQL. | Owner decision 7. The pattern's "Product rollout contract" (a) to (f) is the checklist (Replica work). |
| N13 | Each multi install serves one region, `KYNOTES_REGION`, **required in multi mode with no default** (N1), so a replica cannot silently join as the wrong region. An org whose `home_region` differs is treated as not serving. | T "Home region" H1 to H4: an org's data lives in one region. A misrouted token then reaches no data. |
| N14 | A `deleted` org is purged by the elected worker in short, resumable batches behind a fail-closed audit row. Its `orgs` row stays as a tombstone. Erased subjects come from `/api/suite/erased`. | C D12 and T "Delete everything". A purge in one transaction would hold N3's lock and stop every other org's writes. |
| N15 | **One blob interface, two backends.** `internal/blobstore` gets an interface with the methods its callers use today (`NewTemp`, `Reopen`, `Open`, `Stat`, `Delete`, `ListDigests`), plus a prefix delete for the purge. `volume` is today's code. `object` is S3-compatible. Single-tenant always uses `volume` at `<data>/blobs`, unchanged. **Multi mode uses `object` only, and refuses to start without it** (owner decision 11). The bucket's endpoint, bucket and region join the shared-configuration fingerprint. | Owner decisions 9 and 11: hosted content is in object storage, and single-tenant installs keep volumes. A replica in another bucket would lose blobs written by the others, so a store-ID check proves the storage is shared ("Blobs in S3-compatible storage"). |

## Inventory

Classes, as in T's appendix and C:

- **O** (org-owned): gets `org_id TEXT NOT NULL`, the existence trigger and the immutability
  trigger.
- **D** (derived): scoped through the parent named, with no column of its own.
- **P** (platform): global.
- **Off**: a feature that is off in multi mode. The table stays and holds no customer rows.

KyNotes has 31 migrations (`0001_init.sql` to `0031_cleanup_slots.sql`), each one SQL text for
SQLite. There is no PostgreSQL schema yet. Multi mode needs one (PR 1).

### Tables

| Table | Created | Class | Reasoning |
|---|---|---|---|
| `schema_migrations` | `0001_init.sql:1` | P | Schema version |
| `users` | `0001_init.sql:2` | O | The root of every org's data. `username UNIQUE` stays global: in multi mode it is KyIdentity's username, which is the email and globally unique (T D5). `users_sso_identity` (`0016_sso_logout.sql:3`) stays global: subjects are opaque and global. |
| `sessions` | `0001_init.sql:3` | D | `user_id` FK, cascade. Gains `export_only` (N11). |
| `containers` | `0001_init.sql:4` | O | Notebooks, teams and projects. `owner_user_id` FK. A trigger ties `org_id` to the owner's. `team_id` has no FK, so a trigger also requires a child's org to equal its team's. |
| `blobs` | `0001_init.sql:5` | O | N8. Today `digest` is the primary key and other tables reference it. |
| `blob_containers` | `0001_init.sql:6` | O | It references `blobs(digest)`, so on PostgreSQL that FK becomes `(org_id, digest)`, which needs the column. A trigger requires it to equal the container's org. |
| `objects` | `0001_init.sql:7` | D | `container_id` FK, cascade |
| `object_versions` | `0001_init.sql:8` | O | It is reachable through `objects`, but it references `blobs(digest)`. On PostgreSQL that FK becomes `(org_id, blob_digest)`, which needs the column. A trigger requires it to equal the object's container's org. `author_device_id` and `author_user_id` (`0022_team_keys.sql:2`) have no FK. |
| `devices` | `0002_devices.sql:1` | D | `user_id` FK, cascade. Includes the identity row (`platform='identity'`, `0021_identity_keys.sql`). |
| `memberships` | `0002_devices.sql:3` | D | Both FKs. N7: a trigger requires the user's org to equal the container's, on insert and re-point. |
| `pairing_nonces` | `0002_devices.sql:5` | P | `user_id` has no FK, rows expire, keyed by a nonce hash. The purge deletes the org's users' rows. |
| `key_envelopes` | `0002_devices.sql:6` | D | `container_id` and `device_id` FKs. A trigger requires the device's user to be in the container's org. |
| `device_containers` | `0002_devices.sql:8` | D | Both FKs, same trigger as `key_envelopes` |
| `conflicts` | `0002_devices.sql:9` | O | It references `blobs(digest)`, as `object_versions` does. |
| `attachments` | `0002_devices.sql:10` | O | It references `blobs(digest)`. `idx_attachments_container_digest` (`0002_devices.sql:11`) stays. |
| `upload_sessions` | `0002_devices.sql:12` | O | `user_id` and `container_id` FKs. It gets `org_id` (agreeing with its container, by trigger) so the pool check can sum the org's pending uploads and previews from an `(org_id, status, kind)` index with no join. |
| `idempotency` | `0002_devices.sql:13` | P | `user_id` has no FK. The key is a hash that includes the user ID. Rows expire. |
| `audit_events` | `0002_devices.sql:14` | O, with one exception | **Nullable** `org_id` with **no default**: NULL is a platform row (staff actions, backups, purges, `staff.read`), as T does for `audit_events`. Every writer names the org explicitly: a customer's action names the actor's org, and a platform writer passes NULL. The existence trigger checks only a non-NULL value, and a second trigger refuses a NULL `org_id` when `user_id` names an account outside the staff org, so a writer that forgets the org fails instead of writing a platform row the purge would miss. `TestAuditWritersNameTheOrg` drives every audit writer in multi mode. Migration 0032 backfills existing rows with the default org, and in single mode every new row names the default org, so single-tenant rows look as they do today. `user_id` has no FK. |
| `invitations` | `0003_collaboration.sql:1` | D | `container_id` and `inviter_id` FKs. `invitee_id` has no FK (N7). |
| `comments` | `0003_collaboration.sql:2` | D | `container_id`, `object_id`, `author_user_id` FKs |
| `mentions` | `0003_collaboration.sql:3` | D | Both FKs. Mentions already require current membership (`AGENTS.md:337-339`), so N7 keeps them in one org. |
| `activity` | `0003_collaboration.sql:4` | D | `container_id` FK |
| `push_registrations` | `0004_push.sql:1` | D | `device_id` FK |
| `attachment_refs` | `0006_refs.sql:1` | D | Both FKs |
| `idempotency_keys` | `0008_frozen_contract_columns.sql:9` | P | The key is a hash over the user ID, route and client key (`object_routes.go:257`). Rows expire. |
| `server_settings` | `0009_server_settings.sql:1` | P | Install-wide keys only. Per-org settings would go in a new table, never in prefixed keys. |
| `share_links` | `0010_share_links.sql:1` | D | `object_id` FK. `token_hash UNIQUE` stays global: 32 random bytes (`share_link_routes.go:229-232`). |
| `sealed_share_links` | `0011_sealed_share_links.sql:2` | O | `owner_user_id` (`0029_share_link_owner.sql:3`) has no FK, and the row names no container. The org column lets a suspension and the purge find it. |
| `sso_sync_events` | `0014_sso_sync_events.sql:1` | P | Replay ledger keyed by event ID. Rows expire. |
| `blob_replicas` | `0015_blob_replicas.sql:1` | Off | The offsite mirror. Off in multi mode (open question 2). Its key is a FK to `blobs(digest)`, which PostgreSQL cannot declare once the key is `(org_id, digest)`, and multi mode is PostgreSQL only, so the PostgreSQL schema does not create it. |
| `sso_logout_events` | `0016_sso_logout.sql:19` | P | Replay ledger keyed by issuer, client and JWT ID |
| `sso_directory_state` | `0017_sso_directory.sql:2` | P | Revision fence keyed by `(issuer, subject)`. The purge deletes the org's subjects' rows. |
| `sso_stepup` | `0019_sso_stepup.sql:1` | D | `session_id` FK |
| `sso_login_cutoffs` | `0020_sso_login_cutoffs.sql:3` | P | Fence keyed by `(issuer, subject)`. The purge deletes the org's subjects' rows. |
| `user_identities` | `0021_identity_keys.sql:3` | D | `user_id` and `device_id` FKs |
| `invitation_envelopes` | `0022_team_keys.sql:7` | D | All three FKs, same trigger as `key_envelopes` |
| `link_requests` | `0024_device_linking.sql:8` | D | `user_id` and session FKs |
| `reminders` | `0028_reminder_push.sql:3` | D | `user_id` FK. Gains a claim column (Replica work). |
| `web_push_subscriptions` | `0028_reminder_push.sql:6` | D | `user_id` FK. `endpoint UNIQUE` stays global: an endpoint is one browser's push channel. |
| `cleanup_audit_slots` | `0031_cleanup_slots.sql:10` | D | `container_id` has no FK, but every slot is written with its source row's container. The table is not created on PostgreSQL (Replica work, "SQLite-only mechanisms"), so it never holds a multi-mode row. |

Tables this spec adds:

| Table | Class | Reasoning |
|---|---|---|
| `orgs` (`id`, `status`, `revision`, `enabled`, `home_region`, `pool_allowance_bytes`, `pool_checked_at`, `pool_low`, `seen_at`, `purged_at`) | P | The mirror of `/api/suite/orgs` (N9) and of the org's pool allowance (N10), and the target of every `org_id`. It holds the default org in single mode and the staff org in multi mode. A deleted org stays as a tombstone (N14). |
| `org_usage` (`org_id`, `bytes`) | O | PostgreSQL only, created in PR 4e. The durable part of the org's charged bytes, kept by triggers, and the last figure reported to KyIdentity ("The org storage pool") |
| `org_pool` (`org_id`, `seq`, `reported_bytes`, `ceiling_bytes`, `expires_at`, `attempted_at`, `pool_bytes`, `org_used_bytes`, `over_since`) | P | Grant and report state from KyIdentity, written only in multi mode. |
| `erased_subjects` (`subject`, `org_id`, `revision`) | P | The local copy of `/api/suite/erased`, so a restore can re-erase (Lifecycle) |
| `worker_claims` | P | Only if the elected-worker port needs one. The replica pattern uses a session advisory lock and no table. |

### Files under the data directory

| Path | Written by | Class | Multi mode |
|---|---|---|---|
| `kynotes.sqlite` (+ WAL) | `serve.go:38` | P | Not used. PostgreSQL. |
| `.kynotes.lock` | `internal/storage/lock.go:12-24` (exclusive `flock`, `LOCK_EX\|LOCK_NB`) | P | Kept per replica. Each replica has its own data directory, never shared, so the lock only stops two processes on one directory. |
| `blobs/aa/bb/<digest>` | `blobstore.go:35`, `:58-96` | O (through `blobs`) | The `object` backend, or the shared `volume` (N8, N15) |
| `tmp/<upload>.part` | `blobstore.go:40` (chunked uploads, `upload_routes.go:157`, `:220`) | D (through `upload_sessions`) | **Must be shared.** Chunk 2 can land on another replica than chunk 1, and `Reopen` would not find the part. Each chunk becomes its own object, `orgs/<org_id>/uploads/<upload>/<n>`. Finalize copies them into a private temp file on the replica, hashing as it copies, then writes the blob once under its digest ("Blobs in S3-compatible storage"). |
| `secrets/pairing.key` | `internal/config/config.go:179-200` | P | It is also the CSRF key (`serve.go:29`). Required from `KYNOTES_SECRETS_PAIRING_SECRET`, never minted. Replicas must agree, or a token from one fails CSRF on another. |
| `secrets/serversalt.key` | `config.go:179-200` | P | It derives synthetic login salts (`sso_routes.go:350`). Required from `KYNOTES_SECRETS_SERVER_SALT_KEY`, never minted. |
| `secrets/vapid.key` | `internal/webpush/webpush.go:65-76` (`LoadOrCreateEncoded`) | P | A new `KYNOTES_VAPID_KEY`, required in multi mode. Browsers subscribe against the public key, so every replica needs the same one. |
| `secrets/setup.token` | `internal/httpapi/setup_token.go:14-20` | P | Not written. `/setup` is refused (N5). |
| `admin.sock` | `internal/app/adminsock.go` | P | Kept per replica for `deposit` and `backup-drill`. `apply-setup` is refused (N5). |
| `installer/` | `AGENTS.md:603-609` | P | Not used |
| `snapshot-*`, `.restore-*` | `internal/backup` | P | Per replica, as the replica pattern's backups do |

### In-memory state

Every row below is per process today. On replicas each must move to PostgreSQL, or a request
that lands on another replica sees none of it.

| State | Where | Multi mode |
|---|---|---|
| Pending SSO logins (PKCE verifier, nonce), at most 1024 | `internal/httpapi/sso_routes.go:424-457`. Its own `ponytail:` names the upgrade: "a shared expiring transaction store for multiple replicas". | A table keyed by the state hash, one-use (`DELETE … RETURNING`), with an expiry. The callback can land on any replica. |
| Token buckets for every rate limit | `internal/httpapi/ratelimit.go:22-27`, `:68` | One atomic upsert per key, with database time setting the window (the replica pattern, "How shared security behaves") |
| Login, recovery and device lockouts (50,000 keys each) | `auth_routes.go:26-27`, `internal/auth/middleware.go:22`, `internal/auth/lockout.go:13-20` | The same, with `Reserve` and `Release` kept atomic (`AGENTS.md:543-545`) |
| Back-channel logout failure budget | `internal/httpapi/sso_logout.go:16` | The same |
| Office networks: the live list and `officeBudget` | `internal/httpapi/exempt_networks.go:30` | A `PUT` on one replica swaps only its own list. Each replica re-reads the stored list at most once a minute, and the budget moves to the database. |
| Presence (TTL only) | `internal/httpapi/push_routes.go:13-21` | A table with an expiry, read through membership as today. On one replica, a member on another replica would look absent. |
| Suite apps cache, 60 s per account | `internal/httpapi/suite_routes.go:19`, `:48` | Stays per process. Keys are user IDs, which are random and global. |
| SSO settings and discovery cache | `internal/sso/sso.go:38-98` | Settings come from the environment (N5). The discovery cache stays per process. |
| Per-upload chunk lock (`lockUpload`) | `internal/httpapi/upload_routes.go:33-34`, taken by the chunk handler at `:198` | Retries of one chunk can reach two replicas at once. The chunk handler takes a session advisory lock on the upload ID (N3), writes the chunk object outside any transaction, then runs a short write transaction for `received_bytes`, then releases the lock. Retries keep today's byte check (`upload_routes.go:211-233`). A chunk for an index below `nextChunk` is never written: the handler reads the stored part and compares, then answers success if it matches and the upload conflict if it differs, as today. Only the index equal to `nextChunk` is written, which may replace a part whose counter update was lost (as today's truncate to `received_bytes` does). `TestChunkRetryAfterALostCounterIsWrittenOnce` runs on both backends. The two-replica test sends one chunk to both replicas at once. |
| Migration mutex | `internal/storage/store.go:30`, `:91` | A PostgreSQL advisory lock around migrations, as the replica pattern serialises them |

## Replica work

Each item below was found by a survey and checked in code for this spec.

1. **SQLite only, with a hard-coded path.** `storage.Open(filepath.Join(c.DataDir,
   "kynotes.sqlite"))` (`internal/app/serve.go:38`). The driver is `modernc.org/sqlite` alone
   (`go.mod:15`, `store.go:16`). Multi mode adds a PostgreSQL driver behind the same `*sql.DB` and
   a `KYNOTES_DB_DSN`. A PostgreSQL schema mirrors the 31 migrations with column types swapped.
   N3 adds the write lock. Adding a driver is a new dependency: PR 1 must justify it.
2. **The exclusive `.kynotes.lock`.** `LockDirectory` takes `LOCK_EX|LOCK_NB` on
   `<data>/.kynotes.lock` (`internal/storage/lock.go:16-24`). On replicas each process has its
   own data directory, so it never blocks another replica. Its other job, keeping offline
   commands off a live database, has no PostgreSQL equivalent: in multi mode the offline
   commands that open the database (`copy-data-dir`, `restore-data-dir`, `gc --now`) are refused.
3. **The blob store and `secrets/` keys in the data directory.** Blobs and upload parts are under
   `<data>/blobs` and `<data>/tmp` (`blobstore.go:28`, `:35`, `:40`). Keys are minted there on
   first start (`config.go:191-195`, `webpush.go:70`). In multi mode the keys come only from the
   environment and the blobs from object storage. A replica that would mint a key refuses to
   start and names the missing variable.
4. **Backup, cleanup and reminder-push loops with no lease.** `Serve` starts three goroutines on
   every process: `runBackupLoop` every minute (`serve.go:63`, `:185-210`), `runGC` every
   `gc.interval` (`serve.go:96`, `:154-165`) and `runReminderPush` every minute (`serve.go:116`,
   `:168-181`). None takes a lease. On two replicas:
   - **Reminders send twice.** `Fire` selects due reminders, pushes, and only then deletes
     (`internal/webpush/webpush.go:172-213`). Two replicas both select the same rows, and both
     push.
   - GC runs twice. Each sweep re-checks its row (`gc.go:99-125`), so it is safe but wasted
     (unverified under N3's lock).
   - Backups: `service.Due` decides per process (`serve.go:192`). Two replicas could both run one.

   Multi mode runs all three, plus the org poll and the purge, on one elected worker
   (`internal/worker.Run` in the replica pattern: a PostgreSQL session advisory lock, a probe
   every second). The replica pattern says single-owner scheduling is not exactly-once. So
   reminders also claim before sending: one transaction sets `reminders.claimed_until` to now +
   2 minutes for the rows it will push, then pushes, then deletes. A worker that dies between
   push and delete can cause one duplicate after its claim expires. That is a bounded, at-least-
   once duplicate, and it is accepted (Residual risks).
5. **The SSO login store, rate limiter and lockout counters in memory.** In-memory state, above.
6. **SQLite-only mechanisms.** These use SQLite's physical layout and have no PostgreSQL meaning:
   - the database admission budget (owner Q12): writes stop past 90% of
     `capsule.MaxExpandedBytes` in allocated SQLite pages (`internal/storage/cleanup_slots.go:20`,
     `DESIGN.md` §5). `MaxExpandedBytes` is 256 MiB (ky-primitives `capsule/extract.go:35`);
   - the cleanup slots and padding of migration 0031, which reserve physical leaf space
     (`docs/CLEANUP-CAPACITY.md`);
   - the integrity check at open (`store.go:83`).

   In multi mode the Q12 budget is replaced by the per-org quotas, which already charge comments
   and sealed links (`AGENTS.md:103-107`, `:373`), plus a platform alarm on database size. The
   cleanup slots are not created on PostgreSQL: a delete there does not need preallocated space.
7. **Backups.** A capsule holds the whole SQLite database and is capped at 256 MiB
   (`internal/backup/payload.go:59-80`). The replica pattern snapshots PostgreSQL into the same
   capsule member ("Backups on replicas"), so a shared install with many orgs would outgrow it.
   Open question 3.

The replica pattern's checklist, with KyNotes' state:

| | Contract | KyNotes today | Multi mode |
|---|---|---|---|
| (a) | `/livez`, `/readyz`, drain order | `/livez` and `/readyz` exist (`internal/httpapi/router.go:116-127`). Readiness is startup only. | `/readyz` also pings PostgreSQL. The drain follows the pattern. |
| (b) | Shared settings fingerprint | none | Every variable above, the mode, staff org and region |
| (c) | One ordered table list | none for PostgreSQL | New |
| (d) | Restore drops sessions | `restore` revokes sessions, devices, share links and invitations (`AGENTS.md:453-456`) | Kept, plus the org reset (Lifecycle, Restore) |
| (e) | Scheduled work through one worker | three unleased loops (item 4) | The elected worker |
| (f) | State outside the database has a shared-storage contract | blobs, parts and keys in the data directory (item 3) | Object storage and environment keys |

## Isolation

### `org_id` on every row

One migration (0032, the next free number) on SQLite, and the same tables on PostgreSQL's first
schema. It follows C "`org_id` on every row":

1. Create `orgs` and `erased_subjects`. The migration inserts the default org
   (`00000000-0000-0000-0000-000000000001`, T's default-org ID, `active`, `local`) only when
   `users` already holds rows. That is an existing install, which is always single-tenant. A
   fresh database gets no `orgs` row from the migration.
2. `storage.Open` then runs `ensureOrgs`, right after the migrations and before
   `EnsureBootstrapAdmin` (`serve.go:43`). **It checks before it writes.** First it validates the
   variables (N1: the multi-only ones are refused in single mode and required in multi mode). It
   then works out the stored mode: the `tenancy_mode` row, or `single` when the default org
   exists, or none for a fresh database. If that differs from the configured mode, it refuses, and
   a refused start writes nothing. Only then does it insert, with `ON CONFLICT DO NOTHING` so
   replicas starting together need no lock. First it inserts the N1 rows in `server_settings`:
   `tenancy_mode`, and in multi mode `staff_org_id` and `region`. Then it **reads them
   back**, and refuses if any differs from its own configuration. So a replica that loses the
   race refuses before it writes an org. Only then does it insert the default org (single mode),
   or the staff org named by the stored `staff_org_id` (multi mode, `active`, `enabled`, region
   `KYNOTES_REGION`), if missing. A second, stray staff org row cannot be created. Tests: an
   existing single-tenant database started with `KYNOTES_TENANCY=multi` is refused, and its
   `orgs` table and `server_settings` are byte-identical afterwards.
   `TestEnsureOrgsRaceRefusesTheLoser` starts two replicas together on a fresh PostgreSQL
   database, with different `KYNOTES_STAFF_ORG_ID` values (and, in a second case, different
   modes). Exactly one starts, the other refuses, and `orgs` holds one staff org.
3. Add `org_id`, defaulting to the default org, to every O table except `audit_events` (nullable,
   no default; see its row).
4. Add triggers, with the same names on both backends:
   - one requires the org to exist in `orgs`;
   - one refuses any change to `org_id`;
   - one per O table requires agreement with its parent: a container with its owner, a child
     container with its team, `object_versions`, `conflicts` and `attachments` with their
     container, `blob_containers` and `upload_sessions` with their container, `sealed_share_links`
     with its owner;
   - N7's membership, invitation-accept and envelope triggers compare a user's org with a
     container's.
5. On PostgreSQL, add the composite keys: `blobs(org_id, digest)` as the primary key, and
   `(org_id, blob_digest)` FKs from `object_versions`, `conflicts` and `attachments`, and
   `(org_id, digest)` from `blob_containers`. Those four and `blob_replicas` are every
   `REFERENCES blobs` in the migrations (`0001_init.sql:6`, `:8`, `0002_devices.sql:9`, `:10`,
   `0015_blob_replicas.sql:2`). `attachments.preview_digest` and `upload_sessions.finalized_digest`
   name blobs with no FK, and their lookups add `org_id` on PostgreSQL. SQLite
   keeps `digest` as the key. A unique digest there implies a unique pair, and SQLite cannot
   alter a key without rebuilding the table, which migrations avoid (T D2).

The `org_id` default stays on both backends, as C does. A multi install has no default-org row,
so an insert that forgets `org_id` names a missing org and fails the existence trigger instead of
landing in an org. `audit_events` is the one exception (no default), and its own trigger covers
it (its Inventory row).

**Single-tenant does not change.** With one org every query returns what it returns today. The
browser, the API bodies, the probe and the MCP bridge see no new field. PR 1 proves it with an
upgrade golden test (Tests).

`orgs.status` takes KyIdentity's values (`active`, `suspended`, `deletion_scheduled`, `deleted`)
plus `stale`, which means KyNotes has no current answer for the org (C). In multi mode only
`active`, `enabled`, in this region (`KYNOTES_REGION`), serves. A failed poll changes nothing.
**Single mode runs no org check.** Its one org always serves. Its `local` region is never
compared, and `ResolveSession` and `resolveDevice` keep today's queries, with no join on
`orgs`. The single-tenant golden pins that.

### The org-bound store

KyNotes has no store layer for most reads: handlers run SQL on `*sql.DB` directly, and
authorization is a join on `memberships` with the caller's user ID (for example
`upload_routes.go:98`, `:466`). So the org binding goes where the caller is resolved:

- **`ResolveSession`** (`internal/auth/session.go:109-122`) and **`resolveDevice`**
  (`internal/auth/middleware.go:239-248`), in multi mode, join `orgs` on the user's `org_id` and refuse a
  non-serving org: a session is deleted, as for an inactive account; a device answers `401`.
  **One exception:** a session marked `export_only` is admitted while its org is
  `deletion_scheduled` (and in no other non-serving state), and then only on the N11 allowlist.
  Devices get no exception. `TestExportOnlySessionSurvives` makes ten allowed requests with such a
  session and checks it still exists; the same session in a `suspended` org is deleted.
  The `Session` and `Device` carry `OrgID`. Every route already passes through one of them
  (`AGENTS.md:185-196`: every served route is classified, `TestEveryServedRouteIsClassified`).
- **Request-chosen IDs** are the cross-org surface. A handler that takes a user, container,
  object, attachment, upload, comment, invitation, conflict or link ID from the path or body
  resolves it through a membership join today. Membership is per org (N7), so another org's ID
  finds no row and answers as a missing one. The matrix test proves this route by route rather
  than trusting the argument.
- **Pre-org lookups** stay unscoped, because they find the principal: session by token hash,
  device by ID, user by SSO subject (`sso_routes.go:306`), share link by token hash
  (`share_link_routes.go:229-240`), invitation by ID and token hash at accept.
- **Platform workers** (GC, reminders, purge, org poll, backups) read across orgs. Each due-row
  query carries the same `orgs` join as the account reads, so a stopped org's reminders are not
  sent and its blobs are not swept until a resume or a purge.

### Cross-org matrix

Each row: what a member of org A tries against org B, and the answer. "Missing" means
byte-identical to an ID that exists nowhere: same status, same body code, same headers apart
from `Date` and the request ID.

| Area | Routes (`internal/httpapi/…`) | A uses B's ID | Why |
|---|---|---|---|
| Notebooks | `GET/PATCH/DELETE /containers/{id}`, `/containers/{id}/objects`, `/changes`, `/members` (`container_routes.go:19-245`, `sync_routes.go:13`, `collab_routes.go:27`) | missing | Membership join on the caller; N7 |
| Notes (pages, sections) | `GET/PUT/DELETE /objects/{id}`, conflicts (`object_routes.go:56-220`) | missing | The object's container's membership |
| Shares inside the org | invitations, accept, approve, remove (`collab_routes.go:63-235`), admin team member add (`admin_routes.go:106`) | creation: as for an unknown ID. Accept: `404`. | N7 triggers |
| Share links | `POST /objects/{id}/share-links`, `POST /share-links`, `GET/DELETE /share-links…` (`share_link_routes.go:30-161`) | missing | Owner and membership checks |
| Public share link | `GET /share-links/{token}` (`share_link_routes.go:229`) | n/a: a token is the credential | It serves ciphertext only, and the key is in the URL fragment (`AGENTS.md:321-325`). In multi mode it also answers `404` while the owner's org does not serve. |
| Attachments | uploads, chunks, finalize, by-digest `HEAD`, content, preview (`upload_routes.go:55-539`) | missing | Membership; N8 makes a digest exist only inside its org |
| Comments, mentions | `collab_routes.go:270-420` | missing; a mention of B's member is `400` as for any non-member | `AGENTS.md:337-339` |
| Search | none on the server | n/a | Search runs in the browser over decrypted payloads (`IMPLEMENTATION_PLAN.md:2027`). The MCP bridge's `search` runs locally (`AGENTS.md:956-965`). |
| Reminders and push | `reminder_routes.go:76-214`, `push_routes.go:119` | missing | Keyed by the caller's user ID. A reminder ID is an HMAC under the user's own key (`AGENTS.md:290-296`). |
| Devices, pairing, linking | `device_routes.go:21-255`, `link_routes.go:176-183` | missing | Keyed by the caller's user ID; envelopes need the device's user in the container's org (N7) |
| Identities | `GET /users/{id}/identity` (`teamkeys_routes.go:285`) | missing | It answers self, live co-members and an inviting steward only. Co-members are in one org (N7). |
| Presence, notifications | `push_routes.go:29-95` | missing | Membership-gated |
| Admin | `admin_routes.go:37-491` | staff only | Admin surface |

Tests:

- `TestEveryTableIsClassified`: every table in exactly one of `orgOwned`, `derived` (with its
  parent), `platform` or `off`. A new table fails until it is classified.
- `TestOrgOwnedTablesHaveOrgID`: the column, the triggers and, on PostgreSQL, the FKs.
- **`TestCrossOrgMatrix`**, built on the existing route classification
  (`internal/httpapi/account_kinds_test.go`, which already drives every registered route). It
  builds orgs A and B, each with an owner, an editor, a viewer, an unapproved member, a team
  notebook with pages, comments, an attachment and a preview, a share link, a sealed link, a
  device, a reminder and a push subscription. It calls every route as each A persona with B's
  IDs and compares the answer with one for random IDs. B's rows must be unchanged.
- `TestEveryRouteIsInTheCrossOrgMatrix`: a new route fails until it has a matrix row or a stated
  reason (public, pre-auth, platform, staff, or off).
- N7: an A owner invites B's member, B's member accepts: `404`, and no membership row. The
  accept handler (`collab_routes.go:235`) compares the invitee's org with the container's
  explicitly, before the membership insert, and answers the same not-found it gives for a missing
  invitation. The key-envelope and invitation-envelope writes do the same. The triggers stay as a
  backstop only: no handler maps a trigger error to its own answer, and the matrix test fails if
  a cross-org call ever reaches one (it would answer `500`). A direct insert of that membership is
  refused by the trigger.
- N8: the same ciphertext uploaded in A and B makes two `blobs` rows and two objects. Purging B
  leaves A's object.
- All of these run on PostgreSQL in multi mode. They also run on SQLite: the triggers and the
  handler checks are the same code on both backends, so the SQLite leg builds org B with a test
  helper that inserts a second `orgs` row straight into the store. Startup's mode rules (N1, N2)
  do not apply to a test store. A real single-mode install never has a second org, and the
  single-tenant golden (PR 1) proves its answers are unchanged. **Exception:** the N8 tests (the
  same ciphertext in two orgs) run on PostgreSQL only. SQLite keeps `digest` as the `blobs` key
  (Isolation, step 5), which is sound only with one org, so on SQLite the second org's upload of a
  shared digest is out of scope by design.

## Identity binding

### Sign-in (ID token)

Today a login looks up the account by `(sso_subject, sso_issuer)`
(`internal/httpapi/sso_routes.go:306`), refuses an occupied username (`:319-327`), and
auto-provisions an everyday account when allowed (`:328-359`). `sso.Claims` reads no org
(`internal/sso/sso.go:298-311`).

In multi mode:

1. `VerifyClaims` also reads `org_id` and `export_only`. A token without `org_id` is refused
   `403`, audited `auth.sso_refused reason=no_org`, and nothing is written.
2. The org must be mirrored, `active`, `enabled` and in this region. An unmirrored org triggers
   one single-flight poll, and the callback waits up to 5 s for it (C "Sign-in", step 2). Each
   unknown org ID can trigger a poll at most once every 10 s. Otherwise the login is refused
   `403 org_not_active`.
   - An `export_only` token is the one exception: it is accepted while the org is
     `deletion_scheduled`, and the session is marked `export_only` (N11).
3. A new account is created with the token's `org_id`, in the same transaction as the user row.
4. A known `sub` with another `org_id` is refused `403`, audited `auth.sso_refused
   reason=org_mismatch`, and nothing changes.
5. `kynotes.admin` maps to an administrator account only under N6. A customer's account is always
   everyday.
6. A subject listed in `erased_subjects` is refused, so an erased account is never recreated.

### Directory webhook

`/api/v1/sync/events` (`internal/httpapi/sso_directory.go:80-81`) verifies `syncauth` over the
body, so a field T adds is authenticated. It accepts `user.created`, `user.updated` and
`user.deleted`, refuses everything else (`sso_directory.go:48-55`), and never deletes an account:
inactive delivery keeps accounts and keys (`AGENTS.md:393-394`). KyNotes has no account deletion
today.

In multi mode, as C "Directory webhook" (PR 3c as built):

- The body must carry `org_id` equal to the account's. For a missing or mismatched one,
  **removals are applied and additions never are**: deactivation and its revocations
  (`AGENTS.md:401-402`) happen, while profile and role changes are ignored. Each is audited
  `sso.webhook_org_mismatch`.
- `user.created` for an unknown subject creates nothing. Sign-in auto-provisions.
- New **`user.erased`**, accepted only when its `org_id` equals the account's: it erases the
  account (Lifecycle, A member erases).

### Back-channel logout

`POST /api/v1/auth/oidc/backchannel-logout` (`sso_logout.go:27`) only takes access away. A
logout token with a missing or mismatched `org_id` still ends the matching sessions and is
audited `auth.sso_org_mismatch`, as C does.

### Local accounts

In multi mode only staff break-glass administrator accounts sign in with a password (N5, N6).
`POST /auth/login` refuses any other account with the same answer as a wrong password, so it
reveals nothing.

## Notes specifics

### Blobs in S3-compatible storage (owner decision 9)

Today:

- A blob is written once: `Finalize` hashes, then renames the part file into place
  (`blobstore.go:58-96`).
- A claim records it in the write transaction (`claimBlob`, `object_routes.go:430-441`). A
  refused save drops an unclaimed file (`dropUnclaimed`, `:421-427`).
- A read re-hashes the whole file before it serves it (`blobstore.go:104-133`).
- GC, inside one transaction, deletes the rows, then the file, then commits (`sweepBlob`,
  `gc.go:110-124`). The file goes before the rows are committed.
- Callers hold a concrete `*blobstore.Store` (16 uses under `internal/`). Its methods are
  `NewTemp`, `Reopen`, `Open`, `Stat`, `Delete` and `ListDigests` (`blobstore.go:36-200`).

**One interface (N15).** PR 5a turns those six methods into an interface, plus `DeletePrefix` for
the purge, and keeps today's code as the `volume` backend. That PR changes no behaviour.
Single-tenant installs always get `volume` at `<data>/blobs`, so their files, paths and upgrade
are unchanged.

**Owner decision 11 (2026-11-23, afternoon) supersedes this paragraph's `volume` option:** multi
mode runs `object` only and refuses to start without it; `volume` is single-tenant only. The text
below is kept for the record of the design; read every multi-mode `volume` case as removed.

**Two backends in multi mode**, chosen by `KYNOTES_BLOB_BACKEND`:

- `object`, the target. S3-compatible, configured by `KYNOTES_BLOB_S3_ENDPOINT`, `_REGION`,
  `_BUCKET`, and the keys `KYNOTES_BLOB_S3_ACCESS_KEY` and `KYNOTES_BLOB_S3_SECRET`, or
  `KYNOTES_BLOB_S3_ACCESS_KEY_FILE` and `KYNOTES_BLOB_S3_SECRET_FILE` naming a file that holds
  each. Setting both forms of one key is a startup error. The endpoint must be HTTPS. Keys never
  reach a log, an error body, `/admin/settings` or the fingerprint; the fingerprint holds the
  endpoint, bucket and region only.
- `volume`, the launch fallback. `KYNOTES_BLOB_DIR` is a directory every replica mounts (a
  shared filesystem). Layout is `orgs/<org_id>/blobs/aa/bb/<digest>` and
  `orgs/<org_id>/uploads/<id>/<n>`, the same keys as `object` (N8), so `ListDigests` and the
  orphan sweep walk one layout on both backends. Unverified: that `rename` is
  atomic on the filesystem chosen; PR 5a's two-replica test runs on it.

**The store-ID check** stops a replica that is on a private disk, or in another bucket, from
serving. It runs at startup, in two steps.

1. **Same store.** The replica mints a random 32-byte ID and inserts it into `server_settings`
   with `ON CONFLICT DO NOTHING`, then reads the row back. It then creates `store-id` at the root
   of the store holding the row's ID. The write is create-exclusive (`O_EXCL` on `volume`,
   `If-None-Match: *` on `object`). If the file exists, the replica reads it instead. It refuses
   to start if the file differs from the row. Any replica may create the file, so a replica that
   crashed between the insert and the file leaves nothing stuck: the next start writes it.
2. **Shared store.** `server_settings.blob_probe` names the probe object of the last replica that
   started. The replica must read `probes/<that name>` from its store, or it refuses. Then it
   writes its own `probes/<random>` and moves the row to it by compare-and-swap from the value it
   read (`UPDATE ... WHERE blob_probe = <read value>`, with the empty value for a fresh install).
   If the swap fails, another replica moved the row first: the replica reads that newer probe from
   its own store, and refuses if it cannot. So two replicas starting together on a fresh install
   check each other, and only the first one's empty read goes unchecked. A replica on a private
   disk cannot read the probe, even on a fresh install with no blobs yet. A replica that refuses
   never moves the row. If the probe cannot be read, the replica re-reads the row, and if it now
   names another probe it tries that one, up to three times, so a restart racing another replica's
   start is not refused. The elected worker deletes only probes the row stopped naming more than
   an hour ago (`server_settings.blob_probe_prev` holds the last one with its time).

The one case left: the replica that wins the very first swap is the misconfigured one. Nothing
existed to compare it with, so it starts. Every correct replica then refuses, loudly. Staff
see the install fail to scale and fix it before a second replica serves. That fails closed.

A refusal names `KYNOTES_BLOB_BACKEND`. Staff fix the mount and clear `blob_probe`.

Tests:

- Two replicas starting together on a fresh store both start.
- A replica killed between the insert and the file write: the next start succeeds.
- A replica on an empty second store refuses, on a fresh install and on one with blobs.
- A replica in another install's bucket (another `store-id`) refuses.

Operations in multi mode, on either backend:

| Operation | Today | Multi mode |
|---|---|---|
| Write | rename into `blobs/aa/bb/<digest>` | `volume`: as today, under the org prefix. `object`: one `PUT` to `orgs/<org_id>/blobs/aa/bb/<digest>` conditional on the key not existing (`If-None-Match: *`). An existing object is checked for size and digest, as a present file is today (`blobstore.go:71-82`). |
| Chunked upload | `tmp/<id>.part`, appended | one part per chunk, `orgs/<org_id>/uploads/<id>/<n>`, because chunk 2 can reach another replica. Finalize copies the parts in order into a private temp file on the replica, hashing as it copies, then writes the blob once. The part objects are deleted after the finalize commits, and on
cancel and expiry, under the upload's session lock. The orphan sweep also removes `uploads/` keys
with no live `upload_sessions` row. S3 multipart is not used: its parts must be at least 5 MiB, and a chunk is 4 MiB (`config.go:93`). |
| Read | open, hash, rewind, serve | `object`: download to a private temp file on the replica, hash, then serve. Objects are at most 25 MiB (attachments) or 10 MiB (pages) (`config.go:93`). Unverified: the added latency. |
| Delete | in GC's transaction | `volume` in single mode: as today. Multi mode: GC takes the session lock on the org and digest (N3), re-checks and deletes the rows in a short write transaction, commits, then deletes the object, then releases the lock. A save of the same digest takes the same lock around its existence check, `PUT` and claim, so it cannot interleave. A delete that fails after the commit leaves an object with no row. That costs storage only, and an age-gated orphan sweep (an hour old, no row, under the same lock, using `ListDigests`) removes it. GC sweeps in batches of at most 100 blobs a pass. |
| Purge | n/a | delete rows in batches, then `DeletePrefix("orgs/<org_id>/")` |

**What the `object` backend needs from ky-primitives.** The S3 client KyNotes already ships is
`offsite`'s (`ky-primitives/offsite` v0.3.0, used by the mirror, `internal/backup/mirror.go:74`).
Its `Target` has only `Put`, `Get` and `Test` (`offsite.go:40-44`), and its `PUT` is unconditional
(`s3.go:56-107`). It has no delete and no list, on purpose: the mirror never deletes remote
history (`internal/mirror/AGENTS.md`). The `object` backend needs a conditional put, `HEAD`,
`DELETE` and a prefix list. Recommend a new type in ky-primitives that reuses `offsite`'s request
signing, so KyNotes adds no dependency and the mirror's `Target` stays append-only (open question
1).

The provider sees only ciphertext and digests (fact 1). The strong-crypto profile's HTTPS rule
for `s3_endpoint` applies (`AGENTS.md:66-70`) to the new endpoint too.

### Sharing

- **Inside an org**: team notebooks, invitations and stewards exactly as today, with every member
  in the container's org (N7). Family, Couple and Business share this way.
- **Across orgs**: share links only. A link serves ciphertext, and its key travels in the URL
  fragment, which the server never receives (`AGENTS.md:321-325`). Nobody joins another org's
  notebook.
- Admin-created teams (`POST /api/v1/admin/teams`, `admin_routes.go:37`) answer `404` in multi
  mode. Staff do not create customer content, and members create their own team notebooks.

### Peer integrations

KyNotes calls KyIdentity's suite directory for the app rail (`suite_routes.go:20-38`) and nothing
else. No KyPost, KyCalendar or KyMessages body is sent or received today (unverified for future
integrations). So there is no peer `org_id` contract to add.

## Admin surface (multi mode)

Administrators are staff (N6). Administrator accounts already open no notes, hold no vault
record, and import no content crypto in the browser (`AGENTS.md:364-367`). So staff never read
notes, which matches T.

| Route (`internal/httpapi/…`) | Multi mode |
|---|---|
| `GET /admin/users` (`admin_routes.go:226`) | Needs `?org=<id>`, else `400 org_required`. It lists that org's accounts with status and usage, and writes a platform `staff.read` audit row naming the org. |
| `POST /admin/users`, `PATCH /admin/users/{id}`, `POST /admin/users/{id}/password` (`:171`, `:247`, `:323`) | `404` for customer accounts. Customer lifecycle is KyIdentity's. Staff accounts are managed on the host (`user add --admin`). |
| `/admin/teams…` (`:37-149`) | `404` |
| `/admin/sso`, `/admin/sso/pair` (`:396-492`) | `GET` is read-only. The writes answer `404` (N5). |
| `/admin/settings` (`:200-208`), backups (`backup_routes.go:15-96`), office networks (`exempt_networks.go:93-101`) | Platform settings, unchanged, staff only |
| `GET /admin/audit` (`:366`) | Platform rows by default. `?org=<id>` reads one org's rows and writes `staff.read`. |
| New `GET /admin/orgs` | Read-only: the mirror (status, revision, enabled, region, quotas, usage, last poll) |

`staff.read` rows are platform rows (`org_id` NULL), so they outlive the org's purge, as in C.

## Lifecycle

The org poll (N9) drives every transition, on the elected worker.

### Suspended or `deletion_scheduled`

- In one transaction with its audit row: delete the org's sessions. When the new status is
  `deletion_scheduled`, sessions marked `export_only` are kept, so a member who signed in for
  export just before the poll is not cut off mid-export. `TestExportOnlySessionSurvives` also runs
  the transition while such a session is open.
- Devices, identities and envelopes are kept. Device credentials answer `401` while the org does
  not serve (`resolveDevice`). **Correction (PR 4b, found in review):** a resume needs no
  re-linking only for a device paired from a password session. A device paired from an SSO
  session requires that live session on every request (`AGENTS.md`, "SSO-derived device
  credentials require a live parent session"), so it ends with the sessions and must be linked
  again; in multi mode that is every customer's device. Open question 14.
- Share links of the org's owners answer `404`. Reminders are not sent. GC does not sweep the
  org's blobs.
- Nothing is deleted.
- **`deletion_scheduled` with `export_only`**: the only way in (N11, Export).

**Resumed**: everything above comes back except sessions, as in T.

### Export (`export_only`)

T issues `export_only` to the account holder (deletion by billing) or to every other activated
member (deletion by the holder), with no refresh token. KyNotes marks the session and admits only
these routes:

- `GET /auth/session`, `POST /auth/logout`;
- `GET /me/identity`, `POST /me/identity/recovery/fetch` (a fresh browser restores its key with
  the recovery code), and the link-request routes (to approve from another browser);
- `GET /containers`, `GET /containers/{id}/envelopes`, `GET /containers/{id}/changes`,
  `GET /containers/{id}/objects`, `GET /objects/{id}`, `GET /objects/{id}/attachments`,
  `GET /attachments/{id}`.

The browser export reads a notebook through `readContainerObjects` (`web/src/main.tsx:1475`),
which pages `GET /containers/{id}/changes` (`web/src/api.ts:221-223`) and reads each page with
`GET /objects/{id}` (`api.ts:235-236`). `exportNotebook.ts` calls no route. `GET
/containers/{id}/objects` (`api.ts:229`) is admitted too, as a read, so a later change to the
loader does not break the only way out. Unverified: whether a fresh browser restoring its key with
the recovery code also needs `PUT /me/identity` (`api.ts:178`). `GET /attachments/{id}` serves the
attachment's ciphertext bytes (`upload_routes.go:439`; the browser's `downloadAttachment`,
`api.ts:267`). The preview route (`:459`) is not needed for export and stays refused. PR 4c
freezes the list with an end-to-end export, from a fresh browser under `export_only`, of a
notebook with a page that has an attachment. The zip must hold the attachment, and the export must
report no unreadable item.

The routes are an allowlist in code. Every other route answers `403 export_only`, and
`TestExportOnlyAdmitsOnlyTheExportRoutes` drives every registered route with such a session. The
browser runs the existing export (`exportNotebook.ts`), so the server produces no plaintext. The
link and recovery routes write rows, so the allowlist includes writes. Open question 6 asks
whether that is acceptable.

### Deleted (purge)

On the elected worker, in batches, as C "Deleted":

1. Write `platform.org_purge_started` (org ID only). If it cannot be written, nothing is deleted.
2. Delete each container **bottom-up**, so no one statement cascades a whole history. Each
   batch is one short write transaction under N3's lock that deletes at most 500 child rows. The
   order covers every table with a cascading FK to `containers` or `objects` in the migrations:
   `activity`, `object_versions`, `conflicts`, `mentions` then `comments`, `attachment_refs`,
   `share_links`, `attachments`, `upload_sessions`, `objects`, `invitation_envelopes` then
   `invitations`, `key_envelopes`, `device_containers`, `blob_containers` and `memberships`. The
   container row goes last, once it has no children, so its own cascade is empty. The purge
   runs only in multi mode, which is PostgreSQL only, and the PostgreSQL schema has no
   `cleanup_audit_slots` (Replica work, item 6), so the order does not name it.
   `TestPurgeOrderCoversEveryCascade` reads the FKs of the PostgreSQL schema the purge runs on,
   and fails when a new cascading child is missing from the order.
   Unreferenced blobs then lose their rows in the same way. This "batched container delete" is
   shared with erasure step 4.
3. Delete the org's users and their rows, in the same batches as step 2 (at most 500 rows a
   transaction under N3's lock). First the rows in the tables with no FK, by `org_id` or by
   the org's subjects: `audit_events` (the org's own), `sealed_share_links`, `pairing_nonces`,
   `sso_directory_state` and `sso_login_cutoffs`. Then each user **bottom-up**: its sessions,
   devices, identities, reminders, subscriptions, uploads and link requests. The `users` row
   goes last, once its own cascade is empty. `TestPurgeOrderCoversEveryCascade` also covers the
   cascading FKs to `users`, and the "killed between batches" test kills the worker in step 3
   too.
4. Delete the `orgs/<org_id>/` prefix in object storage. A listing that is not empty is retried
   on the next run.
5. Set `orgs.purged_at` and write `platform.org_deleted` with row counts per table.

The purge is idempotent and resumable. The batch size is a starting value, measured in PR 4 as
C measured its own (500 rows, about 0.1 s a batch on PostgreSQL 17).

### A member erases (Delete everything, `user.erased`)

T sends `user.erased` with `org_id` for a member who clicks Delete everything, and for every
member of an org deleted by `holder_erased`. KyNotes today never deletes an account, so this is
all new. Steps 1 to 3 run in one short transaction, so access ends at once and nobody else's
notebook is touched. Steps 4 to 6 run on the elected worker in resumable batches, as the purge
does (N14), because one transaction for a member's whole history would hold N3's lock and stop
every other org's writes. Step 3's transaction also deletes every pending invitation the member
sent or received (`inviter_id` or `invitee_id`, `status='pending'`, as
`teamkeys_routes.go:373-375` does for one notebook). Nobody can then join a notebook the member
still owns before step 4 deletes it. It also sets the user's status to `erased` and adds the
subject to `erased_subjects`, so the account cannot sign in or be recreated while the batches run.
The worker finds unfinished erasures as `users` rows with status `erased`, so a worker killed
between batches finishes on the next run.

1. End access: sessions, devices and identity, with the same revocations as deactivation.
2. **Transfer ownership first.** For each container they own that still has another approved
   member, set `owner_user_id` and the owner membership to the successor of open question 4 (a):
   the longest-standing approved admin, else the longest-standing editor, else the
   longest-standing approved member of any role (commenter or viewer). This must come before
   step 6, because `containers.owner_user_id` is `ON DELETE CASCADE` (`0001_init.sql:4`): without
   it, deleting the user row would delete the shared notebook for every member.
3. Remove the member from every team notebook through `removeMemberTx`
   (`AGENTS.md:667-670`). That revokes their envelopes and bumps the generation, so the remaining
   stewards re-key and the erased key opens nothing new.
4. Delete the containers they still own with the purge's batched container delete (bottom-up,
   at most 500 child rows a transaction, the container row last). After step 2 these are exactly
   the ones with no other approved member: their personal notebooks and any team they alone
   are in.
5. In batches: **tombstone** their comments in notebooks others keep (owner decision 12: the
   ciphertext cleared and `deleted_at` set, as a comment deletion does), and delete their
   mentions, reminders, push subscriptions, share links and sealed links. Sealed links have no FK
   (`0029_share_link_owner.sql:3`), so this step is needed.
6. **Scrub the user row and keep it** (owner decision 12): its comments reference it and
   `comments.author_user_id` cascades, so deleting it would delete the tombstones. The row keeps
   only its random ID: username set to the ID, every secret, salt, recovery and SSO field
   cleared, status `erased`. Its devices, identity, sessions, memberships and link requests are
   deleted. A pending invitation from an erased member cannot be accepted any more, which is
   intended: the new owner re-invites.

Pages they wrote in a shared notebook are the team's, and they stay.
`object_versions.author_user_id` has no FK (`0022_team_keys.sql:2`), so it keeps the erased
member's random ID and names nobody.

Tests:

- `TestEraseKeepsSharedNotebook`: an erased owner's team notebook with an admin and an editor
  passes to the admin, and both still read every page.
- `TestEraseDeletesSoleNotebooks`, including a worker killed between batches.
- An invitation the member sent before the erase answers `404` on accept after step 3.
- If the only other approved member is a viewer, the notebook passes to that viewer.
- If the only other members are unapproved or pending, the notebook is deleted.

### Restore

A capsule is the whole install, so a restore can bring back an org deleted since. In multi mode,
in the same transaction as today's restore revocations, every customer org row goes to `stale`
with revision 0. The next poll re-reads `/api/suite/orgs` and `/api/suite/erased` from 0. Every
`deleted` org is purged again and every listed subject erased again. So Delete everything
survives a restore, as the owner decided. An org absent from a full listing stays `stale` and
unserved, and is never purged on that ground: KyIdentity is the only source of an org.
**This rests on one KyIdentity contract:** a deleted org stays listed, forever, as `deleted`.
Today it holds. T keeps a deleted org's `orgs` row as a tombstone so an ID is never reused (T
"Data model", "New tables", and its appendix row for `orgs`). `suiteOrgVisibleSQL` lists every
`deleted` org to every app (KyIdentity `internal/store/suite_orgs.go:20`, `origin/master`). No KyIdentity code
deletes an `orgs` row (a search of `internal/` for `DELETE FROM orgs` finds none). No trigger
enforces that yet, so KyNotes asks KyIdentity for one (Downstream contract). If the tombstone
were ever pruned, a restored deleted org would stay `stale`, unserved and unpurged. Its data
would then stay in the database and storage until staff act. There is
no confirm action in KyNotes. If the org is real, staff fix it in KyIdentity, and the next poll
that lists it serves it again. `GET /admin/orgs` shows such an org as `stale` with its last
`seen_at`, so staff can find it. Test: after a restore, an org missing from the listing is
refused, and it serves again at the first poll that lists it.

## The org storage pool (owner decision 10)

KyIdentity holds one storage pool per org across every app (Personal 20 GB, Couple 40 GB,
Family 100 GB, Business 30 GB per seat, Enterprise custom). KyNotes **counts** its bytes for the
org, **reports** them, and **checks headroom** before every write that adds bytes. The API is
KyIdentity's to define (worker `kyint-ki-plans`, board `kyidentity-business-orgs`): T on
`origin/master` `5604cd9` has no pool yet: it keeps opaque per-app quotas (`quotas_json`, T
line 115) and says apps enforce their own (T line 922). This section is KyNotes'
half, and it follows KyCalendar's D14 (`Busnes-app/KyCalendar#190`) so the apps agree. Field names
below are placeholders until T names them.

Single-tenant and Enterprise installs have no pool. Nothing in this section runs there.

### Today

`quotaExceeded` charges a write to the container owner's `quota_bytes` and, in a team, to the
team's cap (`internal/httpapi/upload_routes.go:604-618`). The defaults are 1 GiB per user and
5 GiB per team (`config.go:93`). `usedBytes` (`upload_routes.go:641-651`) sums, for the containers
in scope, every page version, every conflict, live comments, live attachments, live pending
uploads at their declared size, and kept preview blobs. `userQuotaExceeded` adds the owner's live
sealed share links (`:622-636`).

### What KyNotes counts

The org's charged bytes are `usedBytes` with the scope "every container whose `org_id` is the
org", plus every live sealed share link whose owner is in the org. That is ciphertext, so it is
what the customer stored plus encryption overhead, and it is the figure staff and the customer see.

- **Counted:** page versions (history included: every save adds a version), conflicts, comments,
  attachments, previews, pending uploads while they hold a reservation, sealed share links.
- **Not counted:** rows with no customer content (accounts, devices, envelopes, memberships,
  reminders, push subscriptions, audit). They are small and bounded by install limits.
- **Logical, not physical.** Two versions with identical ciphertext count twice, though N8 stores
  one blob in the org. Today's caps count that way too, so a member sees one number everywhere.
- **Kept cheap.** Summing every version of a 100-seat org on each save, under N3's one write lock,
  would stall every org. So `org_usage.bytes` holds the durable per-row terms (versions, conflicts,
  live comments, live attachments), kept by insert, update and delete triggers on those tables.
  Three terms are summed at check time instead, with the same SQL `usedBytes` uses, scoped by
  `org_id` and indexed: pending uploads and sealed links, which lapse with time, and previews.
  Previews count once per distinct digest, and only while their notebook is live
  (`upload_routes.go:641-651`, `TestDuplicatePreviewsAreChargedOnce`), which a per-row trigger
  cannot follow.
  `org_usage` and these triggers exist **only in the PostgreSQL schema**, added by PR 4e. They
  are not in migration 0032, so no single-tenant SQLite write touches them, and comment deletion
  keeps its SQLite capacity bound (`docs/CLEANUP-CAPACITY.md`). The isolation triggers of
  Isolation step 4 are the ones that share names across backends.
  `TestOrgUsageMatchesUsedBytes` builds an org with every term and compares the trigger figure
  with the full `usedBytes` query after each write, delete, GC sweep and purge batch.

**Owner decision 14 supersedes "Report" and "Check" below** with KyIdentity's merged contract
(`POST /api/suite/storage`, KyIdentity `docs/SUITE-DIRECTORY.md` "Storage pool"):

- **Report:** the elected worker sends `{org_id, used_bytes, seq, want_bytes}` for every serving
  org whose charged bytes changed, about every 60 s, at once when half its grant is used, and at
  least once per `ttl_seconds` for every grant held (`want_bytes: 0` releases one). `seq` comes from
  a PostgreSQL sequence, so replicas never collide; a `stale` answer resynchronises it (after a
  restore). `want_bytes` is a fixed step, the larger of 256 MiB and a tenth of the org's pool.
- **Grant:** an `ok` answer stores `ceiling_bytes` and its expiry, `ttl_seconds` after the
  request was **sent**, per org. `unknown_org` and every refusal store a ceiling of 0.
- **Check:** a write that adds `n` bytes passes only while the org's committed charged bytes plus
  `n` are at most the stored ceiling and the grant has not expired, checked inside the write's
  transaction under N3's lock. No grant, or an expired one, refuses growth, as below. Writes that
  add nothing always pass. The answer stays `413 quota_exceeded`.
- `pool_bytes`, `org_used_bytes` and `over_since` are read for `GET /admin/orgs` only.

The paragraphs below are the design before the contract existed; where they differ, the bullets
above win.

### Report

The elected worker reports each serving org's charged bytes to KyIdentity after the org poll
(about every 60 s) when the figure changed since `org_usage.reported_bytes`, and at once after a
purge batch or a restore. A report is the whole figure, never a delta, so a repeat or a lost
report does no harm. It carries `org_id`, the app (`notes`) and the figure, and nothing else: no
names, sizes per member or digests. It goes over the suite client's existing authentication to
KyIdentity (`suitedir`).

### Check

- KyIdentity gives the org's **allowance**: the pool less what every other app reports. The worker
  fetches it for **every** serving org on every org poll (about 60 s), whether or not KyNotes'
  figure changed, and stores it in `orgs.pool_allowance_bytes` with `pool_checked_at`. So an idle
  org's allowance is never older than one poll while KyIdentity answers. KyNotes needs the
  allowance in the bulk poll (`/api/suite/orgs`, or a bulk call beside it), as KyCalendar and
  KyDrive ask too. An answer to a report alone would not be enough.
- Every write that adds bytes runs today's checks, then one more inside its own transaction
  under N3's lock: refuse if the org's charged bytes after the write exceed the allowance.
  No write calls KyIdentity, so a save never waits on the network, and two replicas check the
  same row.
- A write that leaves less than a tenth of the allowance sets `orgs.pool_low`, and the worker
  refreshes that org at once instead of at its next poll.
- **Stale allowance.** If `pool_checked_at` is older than 15 minutes, writes that add bytes are
  refused. Reads, deletes and every write that adds no bytes still pass (open question 10).
- **No allowance yet** (a new org before its first report): writes that add bytes are refused
  until the worker fetches one. The sign-in wait for an unmirrored org (Identity binding,
  step 2) fetches it too, so a new member is not refused on their first save.
- The answer is `413 quota_exceeded`, the code today's caps return, so the browser needs no change.
  The browser cannot tell the pool from a safety cap, which is intended.

### What over-quota refuses

Every route that calls `quotaExceeded` or `userQuotaExceeded` today, and nothing else:

| Write | Where it is checked today |
|---|---|
| Page save (new version, or a conflict) | `object_routes.go:303` before the blob, `:350` in the transaction |
| Attachment and preview upload: create (`POST /containers/{id}/uploads`), then finalize (`POST /uploads/{id}/finalize`); chunks (`PATCH /uploads/{id}`) are not checked, since create reserved the declared size | `upload_routes.go:132`, `:320` (inside the finalize handler, `:280`) |
| Comment | `collab_routes.go:331` |
| Sealed share link | `share_link_routes.go:68` |

Not refused, at any usage: reads, export, deletes of pages, notebooks, attachments, comments and
links, membership and invitation changes, device linking, reminders, plain share links, and
sign-in. A lower pool, a removed Business seat or a stale allowance never deletes data. Since
every save adds a version, an org over its pool cannot edit pages until it deletes something. A
delete frees bytes at once, as it does today:

- a page delete removes that page's versions, conflicts and comments in the same transaction
  (`object_routes.go:170-176`);
- a notebook delete removes the versions and conflicts of every page in it and in its child
  notebooks (`container_routes.go:214-222`);
- a deleted attachment or comment stops counting at once, because `usedBytes` filters on
  `deleted_at`.

The blob files go later, when GC sweeps them (`gc.go:93`), but they are no longer counted.
`TestOrgUsageMatchesUsedBytes` covers a page delete and a notebook delete, and a test fills an org
past its pool with page history alone, deletes one page, and saves again.

### Safety limits

`limits.user_quota_bytes` and `limits.team_quota_bytes`, the attachment and page size limits and
the rate limits stay install settings, checked first, as today. The hosted install sets the two
quota caps at or above the largest pool a single member or team could use, so they only stop
runaway use; the pool is the limit a customer meets. Unverified: which value staff choose, since
a Business pool grows with seats.

### Seat removal

Removing a Business seat lowers the pool, and an org can then be over it. KyIdentity's spec owns
the rule (ky-launch#4 proposes: block new writes until under, never delete, warn the admin first).
KyNotes needs nothing more: an allowance below zero refuses every write that adds bytes and nothing
else.

## Downstream contract (T "Tokens and suite contracts"), KyNotes' half

| # | T requires | KyNotes today | KyNotes in multi mode |
|---|---|---|---|
| 1 | Refuse a token without `org_id` | reads no org (`sso.go:298-311`) | ID token: `403`, nothing written. Webhook: removals only. Logout: still ends sessions. |
| 2 | Key every row by `org_id` | no org anywhere | Inventory and Isolation |
| 3 | Bind `(sub, org_id)`, refuse a known `sub` in another org | bound by `(sso_issuer, sso_subject)` (`0016_sso_logout.sql:3`) | `users.org_id` immutable, a mismatch refused and audited |
| 4 | Take the org only from a verified token, a signed webhook or a suite answer | n/a | The only request-chosen org is a staff `?org=` on a staff read route |
| 5 | Stop serving a non-`active` org; keep data unless `deleted` | n/a | N9, Lifecycle |
| 6 | Enforce its own quotas | install and per-user caps | The org pool: count, report, check (N10); today's caps stay as safety limits |
| — | Admit only export routes under `export_only` | n/a | N11 |
| — | Erase on `user.erased` and `/api/suite/erased` | `user.erased` is refused as unsupported (`sso_directory.go:54`) | Lifecycle |
| — | Asked of KyIdentity: a deleted org stays listed as `deleted` forever | true in code, with no trigger (Lifecycle, Restore) | A trigger refusing `DELETE` on `orgs` (T already refuses any status change out of `deleted`), so a restored deleted org is always purged again |

## Threat model

| Attacker | Goal | Defence |
|---|---|---|
| Member of org A | Read or change B's notebooks, pages, comments or attachments with B's IDs | Every request-chosen ID resolves through a membership join on the caller, and memberships are per org (N7). Answers equal a missing ID's (`TestCrossOrgMatrix`). Content is ciphertext anyway, sealed to B's member keys. |
| Member of org A | Pull a B member into an A notebook, or join a B notebook | N7: the triggers refuse the membership, and accept answers `404`. Creation reveals nothing, as today. |
| Member of org A | Learn whether B holds some ciphertext, by digest | N8: a digest exists only inside its org, and the by-digest `HEAD` is membership-gated (`upload_routes.go:91-103`). |
| Member of org A | Get a B member's public key, presence or mention | Co-members only (`teamkeys_routes.go:285`), membership-gated presence, members-only mentions |
| Customer given `kynotes.admin` | Become an administrator | N6: staff org only, and administrator accounts open no notes |
| Forged or replayed directory webhook | Create, move or erase an account | `syncauth` over the body with replay admission (`AGENTS.md:387-389`). Mismatched org: removals only. `user.erased` only for the account's own org. |
| User of a suspended org | Keep working through a session, a device or a share link | Org status is read with the account on every request. Sessions are deleted, devices refused, links `404`. Window: one poll, about 60 s. |
| User during `deletion_scheduled` | Write under `export_only` | The route allowlist; every write outside it is `403` |
| Former customer | Get data back by a restore | Tombstones and `erased_subjects` re-purge and re-erase at the first poll |
| Two replicas | Send a reminder twice, run two purges, double a rate limit | One elected worker; reminder claims; limits in PostgreSQL (N12) |
| Holder of one replica's disk | Read customer data | In multi mode the data directory holds no key, blob or database |
| Object storage provider | Read notes | It holds only ciphertext and digests (fact 1) |
| Anyone who reads a log, an error or the admin settings | Get the bucket keys | Keys come only from the environment or a key file, and are never logged, returned or fingerprinted (N15). A test greps every log line and answer for them. |
| A replica on the wrong disk or bucket | Serve or lose blobs the others cannot see | The store-ID and probe checks refuse to start it (N15) |
| Member of org A | Use B's pool, or make B look full | The allowance is per `org_id`, from KyIdentity over the suite client's authentication. KyNotes reports only its own count, which it computes; no request can set it. |
| Any member, or a KyIdentity outage | Write past the pool | The check runs in the write's transaction under N3's lock. An allowance older than 15 minutes, or none, refuses growth. |
| Staff, or a stolen staff account | Read notes | Staff hold no content keys. Staff reads of an org's directory write a platform audit row. |
| One org | Exhaust storage or write capacity | The pool allowance (N10), per-user caps, rate limits. Write capacity is shared (N3, open question 5). |

## Phased build plan

Each PR ships with single-tenant behaviour unchanged. `KYNOTES_TENANCY=multi` is refused at
startup until PR 6. Each PR updates `DESIGN.md` and `IMPLEMENTATION_PLAN.md` where it changes a
frozen contract (`AGENTS.md:50-53`; the plan lists multi-tenancy as deferred,
`IMPLEMENTATION_PLAN.md:2034`).

0. **Prerequisites, elsewhere.** KyIdentity has built the org claim, suite APIs and webhooks
   (T PRs 1 to 3). `suitedir` has `Orgs` (`suitedir/client.go:241`) but no `/api/suite/erased`
   method: one is needed for PR 4. T and the other specs must be amended for owner decision 5
   (open question 8). KyIdentity must publish the pool's usage report and allowance (T amendment,
   board `kyidentity-business-orgs`) before PR 4e. ky-primitives needs the S3 type of open
   question 1 before PR 5b.
1. **Org model and the single-tenant golden.** Migration 0032: `orgs`,
   `erased_subjects`, the `org_id` columns, the triggers and `ensureOrgs`.
   - Tests: an upgrade test from a 0031 database: every row in the default org, and every API
     answer byte-identical before and after for a fixed set of requests (a single-tenant golden
     under `testdata/tenancy-golden`, as KyIdentity's). `TestEveryTableIsClassified`,
     `TestOrgOwnedTablesHaveOrgID`, `make test`.
2. **PostgreSQL store.** The driver, `KYNOTES_DB_DSN`, the schema, N3's write lock, the migration
   lock, and the SQLite-only mechanisms switched off on PostgreSQL. The whole suite runs again on
   PostgreSQL in a new CI leg. Single-tenant stays on SQLite.
3. **Isolation and identity.** N7's triggers, the org on `Session` and `Device`, the matrix and
   route-coverage tests, `org_id` from the ID token, webhook and logout token, N5 and N6, and
   `user.erased` accepted but applied only from PR 4.
4. **Org lifecycle and quotas.** Split: (a) the org poll and the sign-in wait; (b) status checks
   on every credential, suspension and its holds; (c) `export_only`; (d) the purge, erasure and
   restore reset; (e) the org pool (N10): `org_usage` and its
   triggers (PostgreSQL only), the report, the cached allowance and the check. 4e waits for
   KyIdentity's contract, and multi mode cannot be enabled (PR 6) without it: the pool is
   required for launch.
   - Tests: a suspended org is refused on session, device and share link. A resume restores
     devices. The purge leaves no row and no object, checked against the classification. A purge
     killed between batches finishes on the next run. A restore of a capsule taken before a
     deletion and an erasure re-applies both.
   - Tests for 4e: two parallel writers on PostgreSQL with one allowance slot left: exactly one
     succeeds. A write that adds no bytes, and every delete, passes at any allowance, including
     below zero. An allowance older than 15 minutes, or none, refuses growth. Each row of "What
     over-quota refuses" answers `413 quota_exceeded` over the pool. `TestOrgUsageMatchesUsedBytes`.
     A report carries only `org_id`, the app and the figure, and a purge reports the lower
     figure at once. A forged or unauthenticated allowance answer changes nothing (the suite
     client's existing verification). The single-tenant golden is unchanged.
5. **Replica work and blob storage.** Owner decision 11: object storage now blocks launch.
   - (a) The elected worker, reminder claims, the in-memory state moved to PostgreSQL,
     environment-only keys, the fingerprint, `/readyz`, the blob interface (N15) with org
     prefixes and upload parts, and the store-ID check. No shared `volume` backend.
   - (b) The `object` backend, with keys from the environment or a file. Multi mode cannot start
     without it.
   - Tests: a two-replica test on one PostgreSQL database and one shared directory, then the same
     test on one bucket (MinIO or another local S3 server in CI, unverified which). A sign-in
     started on one replica completes on the other. A chunked upload alternates replicas. A
     reminder due once is pushed once while both run. A lockout filled on one holds on the other.
     A replica with another shared setting, or another store ID, refuses to start. A blob written
     twice under one key is stored once. A purge leaves nothing under `orgs/<org_id>/`. No log
     line, error body or `/admin/settings` answer holds a bucket key. A single-tenant install
     still writes `<data>/blobs/aa/bb/<digest>` (the golden).
6. **Admin surface and enabling multi mode.** The route changes, `GET /admin/orgs`, `staff.read`,
   and startup accepting `multi` with every requirement. An end-to-end run against KyIdentity in
   multi mode: two orgs, a Family team notebook inside one, a share link across them, then a
   suspension, an `export_only` export and a deletion.

### PR 1 as built

Branch `feat/tenancy-build-1`. Files are cited at that branch's head.

- Migration `internal/storage/migrations/0032_orgs.sql` creates `orgs` (`id`, `status`,
  `revision`, `enabled`, `home_region`, `seen_at`, `purged_at`) and `erased_subjects`. The pool
  columns (`pool_allowance_bytes`, `pool_checked_at`, `pool_low`) are left to PR 4e, which first
  uses them. The default org is inserted only when `users` has rows.
- `org_id` is on the nine O tables named in Isolation step 3, with the default org as default,
  and nullable with no default on `audit_events`. Existing audit rows are backfilled when the
  default org exists.
- **Found while building:** cleanup sizes a row from `SELECT *` (`internal/storage/cleanup_rows.go`,
  `cleanupRowPaddingTx`), and SQLite reports an `ALTER TABLE` default for a row whose stored record
  lacks the column. Left virtual, `org_id` would make cleanup overestimate a legacy `containers` or
  `sealed_share_links` row by 37 bytes, so a cleanup rewrite could grow its cell. The migration
  therefore writes `org_id` into every existing row of those two tables (as 0031 did for its
  padding). `TestUpgradePutsEveryRowInTheDefaultOrg` compares the stored record with `dbstat`;
  without the two `UPDATE`s it fails (149 bytes stored against 186 computed for a container).
  `docs/CLEANUP-CAPACITY.md` says so. The 31→32 upgrade adds no capacity refusal: the growth is one
  `org_id` per container, sealed link and audit row.
- A unique index `blobs_org_digest` on `blobs(org_id, digest)` makes the pair a key on SQLite
  too (it is implied by the digest key there), so the blob claim reads
  `ON CONFLICT(org_id,digest)` (`internal/httpapi/object_routes.go`, `claimBlob`), one SQL text
  for both backends. Isolation step 5's "SQLite keeps `digest` as the key" still holds.
- Triggers, per table: `<table>_org_exists`, `<table>_org_fixed`, and for a table with a parent
  `<table>_org_parent` (insert) and `<table>_org_parent_move` (update of the parent column), plus
  `audit_events_org_named`. A missing parent row compares as NULL and passes: FKs own existence, and
  a historical orphan child keeps working as today. N7's cross-org triggers are left to PR 3, as the
  plan says, in a later migration.
- `storage.ensureOrgs` (`internal/storage/orgs.go`) runs inside `Open` after the migrations, in one
  transaction: it works out the stored mode, refuses another one before writing, inserts
  `tenancy_mode` with `ON CONFLICT DO NOTHING`, reads it back, then inserts the default org. It
  knows only `single`: `KYNOTES_TENANCY=multi` fails every config load (`internal/config/config.go`,
  `tenancyEnv`) until PR 6, so asking for multi mode never serves single-tenant by mistake.
  `KYNOTES_STAFF_ORG_ID` and `KYNOTES_REGION` are refused in single mode.
- The three audit writers (`storage.recordAuditOutcome`, the device revoke in `device_routes.go`
  and account recovery in `auth_routes.go`) name `storage.DefaultOrgID`. PR 3 makes them name the
  actor's org in multi mode.
- **The golden** (`internal/httpapi/tenancy_golden_test.go`, `TestSingleTenantUpgradeGolden`):
  `testdata/tenancy-golden/legacy.sql`, `legacy.json` and `blobs/` are a database and blob store the
  release before tenancy wrote through its own API. The test replays migrations 0001 to 0031, loads
  those rows, upgrades with `storage.Open`, then makes 52 requests (reads by two members and an
  administrator, saves, a conflict, comments, an upload, links, a delete, and the reads again).
  `upgrade.txt` is every answer (status, headers bar `Date` and `X-Request-Id`, body), recorded by
  the commit before any tenancy code. Minted IDs, tokens and clock values become numbered
  placeholders, and the audit list compares as a set, since it orders rows of one second by a random
  ID. The run is stable under `-race` and `GODEBUG=fips140=on`.

### PR 2 as built

Branch `feat/tenancy-build-2`, stacked on PR 1.

- **Driver.** `internal/storage/pgdialect` is KyIdentity's (`internal/store/pgdialect` at
  `886c9d7`) with KyNotes' lock key, plus rules KyNotes' SQL needs: `?NNN` placeholders; the
  placeholders a statement uses renumbered `$1..$k` with only those arguments bound (SQLite lets
  code pass one argument list to several statements that each use part of it; PostgreSQL refuses
  an unused argument and an untyped placeholder); `X'..'`; `zeroblob(n)`;
  `lower(hex(randomblob(N)))` for N up to 16; Go bools bound as 0/1. N3 is its writer lock:
  `pg_advisory_xact_lock` after `BEGIN` in every read-write transaction, and every write outside a
  transaction runs in its own. `TestPostgresWritersAreSerialised` runs 16 read-modify-write
  transactions at once; with the lock disabled it ends at 1, not 16.
- **New dependency, justified:** `github.com/jackc/pgx/v5` v5.13.0, the version KyIdentity,
  KyCalendar and KyDrive ship (their `go.mod`), with `puddle` at their v2.2.4. database/sql has
  no PostgreSQL driver of its own.
- **Schema.** `internal/storage/postgres/0032_schema.sql` is SQLite's after 0032 with BIGINT and
  BYTEA, `blobs` keyed `(org_id, digest)` with the four composite FKs of Isolation step 5, the
  triggers as plpgsql functions (PostgreSQL allows no subquery in a trigger's WHEN), and no
  `cleanup_audit_slots`, `cleanup_padding` or `blob_replicas`. `audit_history` reads
  `audit_events` only. It records version 32 in `schema_migrations`; a later SQLite migration
  needs a file of the same number, or the PostgreSQL open fails and
  `TestPostgresSchemaMatchesSQLite` (every table and column, bar the omissions) fails.
- **Migration lock.** `migratePostgres` holds `pg_advisory_lock` on one pinned connection, so
  replicas starting together migrate once (`TestConcurrentOpenDoesNotRaceMigrations` runs on
  PostgreSQL too).
- **SQLite-only mechanisms off on PostgreSQL** (Replica work, item 6): `storage.CleanupFor(db)`
  makes a comment delete or sealed-link revoke a plain update and writes an ordinary
  `comment.delete` or `share_link.revoke` audit row, the row `audit_history` shows for a filled
  slot on SQLite; `checkDatabaseBudget` admits every write; `IntegrityCheck` pings.
  `WithTx` uses the driver's READ COMMITTED under the writer lock, not SERIALIZABLE.
- **Portable SQL at call sites**, each keeping SQLite's answers: two-argument `max`/`min` as
  `CASE` (`sso_directory.go`, `sso_stepup.go`); the attachment insert as
  `ON CONFLICT(container_id,blob_digest) DO NOTHING` with `RowsAffected` (it caught a unique
  error inside the transaction, which aborts a PostgreSQL transaction); the page read's
  `?version=` decided in Go exactly as SQLite's INTEGER-affinity comparison read it
  (`versionSelector`: numeric text equal to an integer selects that version, anything else none)
  and bound as an integer, or NULL for the current version (`TestObjectReadSelectsTheVersion`
  runs 16 forms on both backends and on PR 1's query; a first `CAST` version selected version 1
  for `1abc` and `1.9`, caught in review).
- **No PostgreSQL install is enabled.** `KYNOTES_DB_DSN` fails config like the other multi-only
  variables until PR 6, which wires `storage.OpenPostgres` into `serve`.
- **The CI leg.** With `KYNOTES_TEST_DATABASE_URL` set, every `storage.Open(path)` in a test opens
  a schema named after the path (dropped by a later run once its directory is gone). ci.yml
  `postgres` runs `internal/storage`, `internal/httpapi`, `internal/auth`, `internal/app`,
  `internal/sso` and `cmd/kynotes-mcp` that way, on PostgreSQL 17 with the C locale, and `test`
  needs it. Left out: `internal/backup` and `cmd/kynotes-server`, whose capsules and offline
  data-directory commands work on the SQLite file (items 2 and 7, open question 3), and
  `internal/mirror`, off in multi mode with no `blob_replicas` table there (open question 2).
  Tests about SQLite itself skip there with their reason (cleanup capacity, journal mode, SQLite
  upgrades, capsules, an INTEGER column holding text, the Q12 page budget). Every other fixture
  goes through `storage.Open`, so it runs on PostgreSQL; tests that inject a failure write their
  trigger in the backend's syntax (`refuseTrigger`, `afterInsertRun` in
  `internal/httpapi/backend_test.go`). Only the golden and the cleanup-cliff seed open SQLite
  directly, and both skip there.
- **Found while building:** the reminder push query selected `u.status` without grouping by it
  (`internal/webpush/webpush.go`, `Fire`), which PostgreSQL refuses: multi mode would never have
  sent a reminder. It now groups by `r.user_id, u.status` (one status per user, so SQLite's rows
  are the same).

### PR 3a as built

Branch `feat/tenancy-build-3`, stacked on PR 2. The plan's PR 3 is split: 3a is isolation
between orgs, 3b the identity binding (ID token, webhook, logout token, N5, N6, `user.erased`).

- **N7.** Migration `0033_org_members.sql` and `postgres/0033_org_members.sql`: `*_org_match` and
  `*_org_match_move` triggers on `memberships`, `key_envelopes`, `device_containers` and
  `invitation_envelopes`, and `invitations_org_match` on an invitation set to `accepted`. The
  accept handler joins the invitee's org to the container's in the query that reads the invitation
  (`collab_routes.go`), so a cross-org accept answers the not-found of a missing invitation;
  `insertInvitationEnvelopeTx` adds the same join to its identity-device check
  (`teamkeys_routes.go`). Key envelopes need no handler change: their recipients must be members,
  and membership is per org.
- **Audit org.** `storage.AuditOrgSQL`, bound to the actor, is every writer's `org_id`:
  `recordAuditOutcome`, the device revoke, account recovery and PostgreSQL's cleanup audit. It reads
  `tenancy_mode` and `staff_org_id` from `server_settings`, which `ensureOrgs` recorded, so every
  replica decides alike (`TestAuditWritersNameTheOrg`).
- **The matrix.** `TestCrossOrgMatrix` covers the 50 served routes (of 52) with a row ID in their path;
  `GET /share-links/{token}` (public) and `PUT /reminders/{id}` (Residual risks, "Reminder ID
  oracle", found by this test) are exempt with their reasons. Bodies are `{}`, or a valid body
  where `{}` would be refused before authorization (link-request steps, page share links,
  attachment links, key rotations). The routes that name rows only in a body act on the caller's
  own rows or are staff routes; the matrix does not drive them.
- **The org on `Session` and `Device`** is left to PR 3b, whose N6 check is its first reader.

### PR 3b as built

Branch `feat/tenancy-build-3b`, stacked on PR 3a. Multi mode is still refused at startup, so
the tests record the multi-mode rows (`tenancy_mode`, `staff_org_id`, `region`) themselves.

- **Mode at run time.** Rules read the mode `ensureOrgs` recorded, in SQL or through
  `storage.TenancyOf`, so every replica decides alike without configuration in each handler.
- **Sign-in** (`internal/httpapi/sso_routes.go`, `tenancyRefusal`): steps 1, 2 (no poll yet; an
  unmirrored org is refused at once, and PR 4a adds the 5 s wait), 3, 4, 5 and 6 of "Sign-in".
  The `export_only` exception waits for PR 4c. `org_id` and `export_only` are read from the
  verified token only (`internal/sso/sso.go`); `export_only` counts only as JSON `true`.
- **N6** in `auth.SessionRole`, which every admin guard and the session answer use: in multi mode
  an administrator account counts only in the staff org.
- **Directory webhook** (`internal/httpapi/sso_directory.go`): `org_id` is a field of the signed
  user body, as KyIdentity sends it (`internal/sync/sync.go`, `OrgID`). A body naming another org
  or none applies a removal (with its revocations) and ignores anything else, audited
  `sso.webhook_org_mismatch`; an unknown subject is never created (answer `ignored`).
  `user.erased`, the bare inactive user, is accepted for the account's own org: access ends as on
  deactivation and the subject goes into `erased_subjects`, so sign-in refuses it. Deleting its
  data is PR 4d. Single mode still refuses `user.erased` as unsupported.
- **Back-channel logout:** KyNotes' `ky-primitives` returns no raw logout claims, so
  `auditLogoutOrg` reads `org_id` from the already verified token's payload.
- **Not built here, moved to PR 3c:** N5 (SSO fixed by `KYNOTES_SSO_*`, the admin SSO writes,
  customer password sign-in, `/setup`, `user add` and `apply-setup` refused). It is the
  configuration surface multi mode needs to start, so it lands with the startup work. The org on
  `Session` and `Device` is not added: every rule that needs the org reads it in its own query.

### PR 3c as built

Branch `feat/tenancy-build-3c`, stacked on PR 3b.

- **Password paths** (N5, "Local accounts"): the login-parameter, login and recovery lookups carry
  `passwordAccount`, a predicate on the recorded mode. In multi mode it finds only administrator
  accounts in the staff org, so any other account takes the unknown name's path: the synthetic
  salt, the dummy verification, the lockout reservation and `401 invalid credentials`
  (`TestMultiModePasswordSignInIsStaffOnly`: the right secret on a customer account answers as an
  unknown name, and its stored salt is never returned).
- **404 in multi mode** (`singleModeOnly`): `GET`/`POST /setup` on both paths, `POST /admin/sso`,
  `POST /admin/sso/pair`, and `POST /v1/apply-setup` on the admin socket.
- **Variables:** the four `KYNOTES_SSO_*` variables join the multi-only ones refused by
  `tenancyEnv`.
- **Left to PR 6**, which lets a start be multi-tenant: reading the identity provider from
  `KYNOTES_SSO_*` into `sso.Store`, and `user add` refusing everyday accounts and creating
  administrators in the staff org. Both run only in a multi-tenant start, which `ensureOrgs`
  refuses in this release, so neither could be exercised here.

### PR 4a as built

Branch `feat/tenancy-build-4a`, stacked on PR 3c.

- **Dependency:** `ky-primitives` moves from `9f4bc58` to `90b0e58`, the revision this spec cites
  for `suitedir.Client.Orgs`. Of the packages KyNotes imports, only `suitedir` changed between
  them (`git diff --stat` per package); `offsite` is its own module and stays at v0.3.0.
- **`internal/orgsync.Poller`:** `Poll` reads the cursor from `server_settings`
  (`org_poll_revision`), calls `Orgs`, and in one transaction upserts each org `WHERE
  excluded.revision>=orgs.revision`, then stores the next cursor. A failed call or transaction
  changes nothing. `suitedir` already refuses a malformed entry, so a partial listing is never
  applied. No row is ever deleted.
- **Sign-in wait** (step 2): `tenancyRefusal` calls `Poller.Await` only when the token's org is
  not mirrored, bounded by 5 s; `Await` shares the running poll and lets each unknown org ID
  trigger one poll per 10 s. A failed or late poll refuses as unmirrored (`org_not_active`).
- **Not built here:** the 60 s schedule. N9 runs it on the elected worker, which PR 5a adds; the
  poller is ready for it. `/api/suite/erased` has no `suitedir` method yet (the plan's
  prerequisite for PR 4d).

### PR 4b as built

Branch `feat/tenancy-build-4b`, stacked on PR 4a.

- **`storage.OrgServes(col)`** (`internal/storage/orgs.go`): SQL true in single mode, and in multi
  mode only for an org that is `active`, enabled and homed in `server_settings.region` (N9, N13).
  It is a predicate on the recorded mode, not a join, so single mode's answers are unchanged (the
  golden).
- **Credentials:** `ResolveSession` and `resolveDevice` (`internal/auth`) carry it: a stopped org's
  session and device answer 401, as for an inactive account. **Links:** the public share-link
  read carries it for sealed links (`org_id`) and page links (the page's notebook's org): 404.
  **Workers:** `webpush.Fire` and GC's sweep (candidates and the in-transaction recheck) carry
  it, so reminders wait and blobs are not swept until a resume or a purge.
- **Transition:** `orgsync.Poller.poll` compares each org's serving state before and after its
  upsert; when it stops serving, the same transaction deletes the org's sessions and writes
  `org.sessions_ended` (platform row, `status=...,sessions=N`). Devices, identities and envelopes
  stay. The `export_only` exception waits for PR 4c.
- **SSO-derived devices** end with the sessions (Lifecycle, "Suspended", correction):
  `TestSuspendAndResumeThroughThePoll` suspends and resumes through the poller; the
  password-paired device works again, the SSO-derived one stays refused. Open question 14.
- Tests: `TestStoppedOrgIsRefusedOnEveryCredential` (suspended, disabled and another region, then
  the resume), `TestStoppedOrgsRemindersWait`, `TestGCWaitsWhileTheBlobsOrgIsStopped`,
  `TestPollEndsTheSessionsOfAnOrgThatStops` (one audit row over two polls).

### PR 4c as built

Branch `feat/tenancy-build-4c`, stacked on PR 4b.

- **Migration 0034** (`sessions.export_only`, 0 or 1) on SQLite and PostgreSQL.
- **Sign-in:** `tenancyRefusal` admits a token whose `export_only` is JSON `true` while its org is
  `deletion_scheduled`, enabled and in this region; `MintSSOSession` marks the session. A token
  with `export_only` in an active org is marked too, and so restricted.
- **Admission:** `ResolveSession` admits a marked session while its org serves or is
  `deletion_scheduled` (and in no other non-serving state). Devices get no exception.
- **The allowlist** (`auth.ExportRoutes`): `GET /auth/session` and `POST /auth/logout` (both
  paths), `GET /me/identity`, `POST /me/identity/recovery/fetch`, the seven link-request routes,
  `GET /containers`, `GET /containers/{id}/changes`, `GET /containers/{id}/envelopes`,
  `GET /objects/{id}`, `GET /objects/{id}/attachments`, `GET /attachments/{id}`. **Correction to
  Export above:** the server has no `GET /containers/{id}/objects` route (the list of served
  routes, `servedRoutes`), so there is nothing to admit for it. `PUT /me/identity` stays refused
  (the spec leaves its need unverified; refusing is the safe default, and a fresh browser
  restores its key through the recovery-code fetch and linking).
- **Transition:** the org poll keeps `export_only` sessions when an org moves to
  `deletion_scheduled` and deletes the rest (PR 4b's step).
- **Not built here:** PR 4c's end-to-end browser export under `export_only` (Export, last
  paragraph). It needs a multi-mode server to sign in to, which PR 6 enables.

### PR 4d as built

Branch `feat/tenancy-build-4d`, stacked on PR 4c. This is the purge of Lifecycle, Deleted; member
erasure follows in its own PR.

- **`storage.PurgeOrg`** (`internal/storage/purge.go`): step 1 (the `platform.org_purge_started`
  row, written before anything is deleted, so a failed write deletes nothing), steps 2 and 3 as
  ordered batches (`purgeSteps`: the containers' children bottom-up, the containers, the org's
  blob rows, then the rows with no foreign key, each user's rows bottom-up, the users), and step 5
  (`purged_at` and `platform.org_deleted` with per-table counts, in one transaction). Each batch
  deletes at most 500 rows by the table's own key, in its own transaction. `PurgeDeletedOrgs`
  purges every `deleted` org not yet purged, in multi mode only; the default org never.
- **Step 4 waits for PR 5a.** Until the per-org blob layout (N8), identical ciphertext in two orgs
  shares one file, so deleting the purged org's files could delete another org's. The purge
  deletes the blob rows; the orphan sweep removes files nothing references.
- **Not built here:** running it on the elected worker (PR 5a), and the restore reset. A capsule
  holds the SQLite file, while multi mode runs on PostgreSQL, whose backups are open question 3;
  the reset belongs with that restore path.
- Tests (both backends): `TestPurgeLeavesNoRowOfTheOrg` seeds two orgs with a row in every table
  the purge reaches and checks that no value of the purged org remains anywhere, while the other
  org's are all kept; `TestPurgeKilledBetweenBatchesFinishesNextRun` (batches of one, killed at
  the 12th); `TestPurgeOrderCoversEveryCascade` (without the `reminders` step it fails).

### PR 4d-2 as built

Branch `feat/tenancy-build-4d-erase`, stacked on PR 4d. "A member erases", built to open question
4's default (a).

- **Steps 1 to 3** (`eraseMemberTx`, `internal/httpapi/erase.go`), in the `user.erased` event's
  transaction after deactivation: status `erased`; pending invitations sent or received deleted;
  each owned notebook with another approved member passes to the successor (approved admin, else
  editor, else any approved member, longest-standing first), the erased owner becoming a viewer
  so it can leave; then `removeMemberTx` for every notebook it does not own (top-level ones; it
  covers their child notebooks), which revokes its envelopes and bumps the key generation.
- **Steps 4 to 6** (`storage.EraseMembers`, `eraseSteps`, `eraseMember`), to owner decision 12
  (KyNotes #176, 2026-11-23 afternoon): the notebooks it still owns alone (bottom-up, as the
  purge's container steps); its mentions, reminders, push subscriptions, sealed links, pending
  uploads, pairing nonces (no foreign key: found by the test's every-table scan), directory
  fences, link requests, sessions, devices, identity and memberships; its **comments in kept
  notebooks become tombstones** (ciphertext cleared, `deleted_at` set, each at its own fresh
  notebook change sequence through the cleanup backend so paginated sync delivers it); and its **user row is
  scrubbed and kept**, holding only its random ID, because `comments.author_user_id` cascades
  and deleting it would delete the tombstones. `erased_subjects` still refuses the subject. A
  scrubbed account (username equal to its ID) is done; anything else resumes after a crash.
  Audit rows keep its random ID, which names nobody. Multi mode only; it runs on the elected
  worker (PR 5a).
- Tests: `TestEraseKeepsSharedNotebookAndDeletesSoleOnes` (the team passes to the admin; the admin
  and editor still read the page; the erased member's invitation answers 404; its sole notebook
  is gone, its account is scrubbed and kept, and incremental sync paged one row at a time delivers
  both comment tombstones), `TestEraseSuccessorIsAnyApprovedMember` (a viewer inherits; a notebook
  with only an unapproved member is deleted), `TestEraseMembersKilledBetweenBatchesFinishesNextRun`.

### PR 4e as built

Branch `feat/tenancy-build-4e`, based on PR 4d-2. Built to KyIdentity's merged report-and-grant
contract (#290, `docs/SUITE-DIRECTORY.md`, Storage pool; owner decision 14).

- Org-owned inserts name their parent's org in the statement: notebooks, versions, conflicts,
  attachments, uploads, blobs, blob links and sealed links. Previously non-default-org writes
  hit the isolation trigger and failed closed; the matrix seeded its rows directly and missed
  that path. `TestOrgMemberWritesLandInItsOrg` exercises the API as org B.
- PostgreSQL `org_usage.bytes` holds versions, conflicts, live comments and live attachments,
  maintained by insert/update/delete triggers, initialized for every org and backfilled on
  migration. Pending reservations, live sealed links and distinct previews are summed at check
  time. Report state (`reported_bytes`) belongs to `org_pool` beside its grant, rather than
  duplicating it in `org_usage`. SQLite has no usage table or triggers, preserving its bounded
  cleanup writes. `TestOrgUsageMatchesUsedBytes` compares the counter with an independent full
  sum after lifecycle mutations and purge; cascade deletion has its own regression.
- `org_pool` holds the current sequence, ceiling, expiry, report baseline, attempt time and
  display figures. PostgreSQL uses `org_storage_report_seq`; stale responses advance its next
  allocation above KyIdentity's stored value. SQLite's synthetic multi-mode tests use a row
  counter; production multi mode remains PostgreSQL-only.
- `storage.PoolRefuses` checks net growth against an unexpired grant inside the writer
  transaction, returning the existing `413 quota_exceeded`. No grant refuses growth. Finalizing
  an already reserved upload adds no bytes and needs no fresh headroom. Upload reservation and
  both finalization paths recheck inside the transaction. Single mode bypasses pool admission.
- `orgsync.Reporter` reports ordinary changes once per minute, sooner for lower usage or a
  half-spent grant, and renews unchanged grants before expiry. Stopped orgs release grants with
  `want_bytes: 0`. Requests contain at most 250 reports and stay within 64 KiB. A short
  transaction snapshots usage and disables the old grant before sending, so no replica spends
  headroom KyIdentity may reassign while the request is in flight. Failed requests leave growth
  paused until a later valid grant; reads, deletes and reservation conversions remain available.
- The response is bounded and validated as a whole; redirects are refused, credentials never
  enter an error, and expiry counts from the send. A stale answer only resynchronizes the
  sequence and requires a fresh report; it never renews the returned old grant. A late response
  cannot overwrite a newer attempt. `unknown_org` records no headroom.
- Scheduling the reporter on the elected worker remains PR 5a; exposing the pool figures in
  `GET /admin/orgs` remains PR 6. Multi mode is still refused at startup.


### Erased-feed reconciliation as built

`httpapi.PollErased` uses the shared `suitedir.Client.Erased` contract; the elected minute
adapter runs it after the org mirror and before cleanup. Fetch outside N3, then one notice
per transaction: durable fence, access revocation, shared-notebook transfer/removal, audit and
cursor. A competing worker checks the cursor inside N3 and re-fetches if another committed.
An org mismatch refuses the notice without skipping it; unknown subjects get a fence without
an account. Webhook and feed share the same subject/org erasure helper. Earlier valid notices
stay committed when a later notice fails. Single mode does nothing.

Tests cover both backends, malformed/refused/authenticated responses, wrong-org bindings,
audit rollback, unknown subjects, shared ownership, independent-pool concurrency and PG
restore reset/replay from zero, including unlisted org fencing. Actual PostgreSQL backup and
restore transport and multi startup remain unbuilt/refused.

### Native PostgreSQL restored-target preparation as built

`prepare-postgres-restore --confirm-restored` opens the existing exact-release PG schema
without migration, with its DSN in the environment only. Every replica must be stopped and
the target separately restored. One transaction revokes sessions/devices/links/pending invites,
turns deposits off through recoveryclient, resets tenancy coordination and audits the reset.
Encryption identities, recovery pairing/pin, erasure fences and permanent store identity remain.
Schedule/audit/reset/cancellation failure rolls back. Single mode refuses this command; its
existing SQLite restore uses the unchanged revocation operations through a common helper.

Tests cover both schema-version refusals, explicit target/secret boundaries, atomic PG success
and rollback, and single-mode no-change. The command does not recover PG backup bytes, choose
open question 3's large-database transport or enable multi startup. Those remain prerequisites.

### PostgreSQL backup transport as built (startup still refused)

Open question 3 is answered for KyNotes with a logical archive, not base backup plus WAL:
it needs no PostgreSQL tooling or superuser on the host, round-trips in CI, and has no capsule
limit. A host that also runs PostgreSQL's own PITR still restores through
`prepare-postgres-restore`, which now writes the same replay gate.

- `pg-backup --out` (`storage.BackupPostgres`): one REPEATABLE READ READ ONLY transaction, a
  JSON header (format, schema version, database time, tables and columns in foreign-key
  order), each table's COPY text rows ended by `\.`, and a trailer of row counts and sequence
  values. The `blobs`, `blob_containers` and version rows are the object references, from the
  same snapshot as the notes. Objects themselves are not copied: GC retention (168 h by
  default) bounds how old a restorable archive may be.
- Sealing (`backup.BackupPostgres`): `KYNOTES_PG_BACKUP_KEY_FILE` (32 bytes, hex), HKDF-SHA256
  per archive salt, 1 MiB AES-256-GCM frames with random nonces (FIPS), associated data binding
  magic, salt, frame index and final flag.
- `pg-restore --in --confirm-stopped`: a just-created database of the archive's schema version
  only. One transaction deletes the migration and `ensureOrgs` seed rows, turns user triggers
  off (usage and org-seeding triggers must not run twice), loads every table with foreign keys
  checked, checks the trailer's counts, sets sequences, turns triggers back on and commits the
  restore fence (`fenceRestoredTx`, shared with `prepare-postgres-restore`).
- **Replay before serving.** `ResetTenancyAfterRestore` writes `restore_replay`. While it
  exists `OrgServes` refuses every customer org (the staff org still serves), so sessions,
  devices, share links, reminders, GC and the orphan sweep all wait. The elected worker's
  `httpapi.FinishRestoreReplay` runs after the org and erased polls and deletes it only when
  both feeds, read from the stored cursors, list nothing more and the cursors did not move.
  So every erasure since the backup is fenced, and every deleted org is marked deleted, before
  any customer org serves. The purge then deletes the restored deleted org again.
- Tests (PostgreSQL): every table round-trips byte for byte, including COPY escapes, NULLs and
  sequences, with triggers back on; damaged, truncated, extended, wrong-schema or wrong-count
  archives, a failing fence and a target holding data load nothing; the snapshot excludes a
  write committed during the backup; every change to a sealed archive fails to open;
  `TestRestoreAfterPurgeReplaysBeforeServing` restores a backup taken before an org purge and
  an erasure and shows the org unserved after the org poll until the erasure is replayed.
- Not built: object storage as the archive's destination and its schedule binding (startup
  binding), a blob-coverage check, and the KyIdentity "deleted orgs stay listed" trigger the
  replay relies on (Downstream contract). Cells (C5) give the archive a cell-scoped object
  prefix when the destination lands.

### Staff surface as built (startup still refused)

The prepared multi-mode admin surface requires one org for the users read, filters the audit
read to platform rows by default or one selected org, and lists org mirror/pool/usage metadata.
A writer transaction rechecks staff authority and commits the platform `staff.read` audit
before response publication. User/team web writes and team listing refuse multi mode.

Only multi-mode user/session metadata adds `user.tenancy="multi"`, selecting a read-only staff
console within the existing shell. Native org/audit selectors, wire validation and scope-bound
async state prevent stale replies appearing under a different org. Single-mode JSON and the
original administration UI remain unchanged. Backend role/isolation checks stay authoritative.
Tests cover both backends, logical usage, failed audit, revoked actors, missing/duplicate orgs,
customer mutation/content refusal, parsing and real-browser late replies. This does not enable
multi startup or complete the native backup/object/runtime prerequisites.

## Residual risks

- **One writer for every org.** N3 serialises all writes on PostgreSQL. A busy org delays the
  others. Capacity is unmeasured (open question 5).
- **Reminder duplicates.** A worker that dies between a push and its delete can cause one
  duplicate after the claim expires.
- **Backups hold deleted orgs** until capsules age out. A restore re-purges at the first poll.
  Object storage versioning or retention, if turned on, keeps deleted ciphertext for its window.
- **Mirror lag.** A suspension reaches device credentials within one poll, about 60 s.
- **Share links cross orgs by design.** Anyone with a link and its fragment can read that page
  until it expires (at most 30 days, `AGENTS.md:372-374`) or the owner's org stops serving.
- **Pool overshoot.** The allowance is up to one poll old, and up to 15 minutes when KyIdentity
  is unreachable. Other apps' growth in that window can take an org past its pool. KyIdentity's
  design bounds it; KyNotes refuses growth past 15 minutes.
- **One member can fill the pool.** The pool is shared by every member, so one member's uploads
  can leave the others no room. The per-user safety cap bounds it. That is the plan as sold.
- **The shared volume is a single point of failure** while launch runs on `volume`, until PR 5b.
- **Reminder ID oracle** (found by the cross-org matrix, PR 3). `PUT /reminders/{id}` with an ID
  another account holds answers 404 where an unused ID creates a reminder, so it reveals that
  the ID exists, across orgs as across users of a single-tenant install today. Using it needs the
  other account's reminder ID, an HMAC under a key only that account's browser holds
  (`reminderPush.ts`), which the server never returns to anyone else. Closing it means keying
  `reminders` by `(user_id, id)`, a SQLite table rebuild that also changes a single-tenant
  answer; owner question 13.
- **Operator access.** The operator holds the database and the bucket, which are ciphertext and
  metadata (who is in which notebook, sizes, times). That metadata is not encrypted.

## Open questions, with recommendations

1. **The S3 client.** `offsite` has no delete, list or conditional put, by design (Blobs in
   S3-compatible storage).
   - (a) A new type in ky-primitives that reuses `offsite`'s signing.
   - (b) Add `Delete` and `List` to `offsite.Target`.
   - (c) The AWS SDK's S3 client, a new direct dependency.
   - **Recommend (a).** (b) would let the mirror delete remote history, which its contract
     forbids. (c) adds a dependency for four requests. Unverified: the chosen provider's support
     for `If-None-Match: *` on `PUT`, its latency for a 10 MiB read, and its egress cost at our
     read rate. PR 5b measures them. Without the conditional put, a write `HEAD`s first, which is
     safe because a blob key names its content.
2. **The offsite mirror in multi mode.** `internal/mirror` copies every blob to one destination
   and never deletes remote history (`internal/mirror/AGENTS.md`), which would defeat the purge
   and Delete everything. Recommend turning it off in multi mode, with the bucket's own
   replication and a lifecycle rule that expires deleted objects within the backup retention.
3. **Database backups past 256 MiB.** A capsule holds at most 256 MiB, and the replica pattern
   snapshots PostgreSQL into a capsule. A shared install will pass that. Recommend PostgreSQL's
   own backups (base backup plus WAL, encrypted, to object storage) for multi mode, with capsules
   kept for single-tenant installs and Enterprise. The restore reset (Lifecycle) then runs after a
   PostgreSQL restore too. **Built** as a logical COPY archive instead ("PostgreSQL backup
   transport as built"). KyIdentity, KyCalendar and KyDrive face the same limit (unverified for
   their sizes).
4. **Answered (owner decision 12): (a), with tombstoned comments.** An erased owner's team notebooks with other members. Delete everything deletes the
   clicker's data, and a team notebook is shared.
   - (a) Ownership passes to the longest-standing approved admin, else the longest-standing
     editor, else the longest-standing approved member of any role. The notebook and the pages
     the erased member wrote stay. A commenter or viewer who becomes owner gains owner rights.
   - (b) The notebook is deleted for everyone.
   - **Recommend (a)**, the default this spec builds to: it deletes nobody else's work.
     Owner question.
5. **One writer (N3).** Recommend accepting it for launch and measuring writes a second before
   launch, as C open question 4 did. N3 is never held over network I/O, so object-store latency
   does not add to it, but its write transactions (GC row deletes and purge batches included)
   count. If it fails, move to a per-org advisory lock and re-check the install-wide invariants
   (blob claims are per org after N8).
6. **Writes under `export_only`.** Restoring a key with the recovery code and linking a browser
   write rows, but no content. Recommend admitting them, since an SSO member with a new browser
   cannot export without them.
7. **Moving a single-tenant install to PostgreSQL.** Enterprise is fine on SQLite (owner decision
   5). Recommend no `migrate-postgres` for KyNotes until an Enterprise customer asks.
8. **T and the sibling specs predate owner decision 5.** T decision 7, T "Business platforms",
   C decision 5 and D decision 5 still say businesses get their own install. T's
   `org_erasures_holder` trigger admits only `person` and `household` orgs. Recommend that
   KyIdentity amends T for Business orgs, including the org kind and Delete everything for them.
   KyNotes needs nothing from the kind: teams already work the same for any org size.
9. **Per-org region in one install.** N13 runs one region per install. Recommend keeping that
   until a region move is designed (T H2).
10. **How long a stale pool allowance is trusted** when KyIdentity cannot be reached.
    Recommend 15 minutes, as KyCalendar's open question 11: long enough to ride out a KyIdentity
    restart without refusing saves, short enough that other apps cannot overshoot the pool by
    much. If KyIdentity's contract fixes a figure, that figure wins.
11. **Moot (owner decision 11: no volume fallback).** The volume fallback's filesystem. Owner decision 9 let launch run on volumes, and
    replicas on several hosts need one filesystem they all mount (NFS or CephFS). Recommend one
    shared filesystem per region for every app that falls back, chosen with KyDrive and
    KyMessages, and moving to `object` before the first plan with large pools fills it.
12. **Answered (owner decision 13): no automatic pruning at launch.** Version history and the pool. Every save adds a version that counts. Recommend no
    automatic pruning for launch, since it would delete customer data; an over-quota member
    frees room by deleting pages, notebooks or attachments, which frees their bytes at once
    ("What over-quota refuses"). A history limit per plan is a later owner choice.
13. **The reminder ID oracle** (Residual risks). Recommend leaving it for launch: it needs a
    secret the server never discloses. If the owner wants it closed, key `reminders` by
    `(user_id, id)` in one migration, accepting that another account's ID then creates a
    reminder instead of answering 404 on single-tenant installs too.
14. **Devices across a suspension** (PR 4b). Ending a stopped org's sessions, as T does, also ends
    every device paired from an SSO session, so members re-link their phones after a resume.
    - (a) Keep that: a suspension ends all access, and a resume revives no credential, which
      matters when an org is suspended because a member's credentials were stolen.
    - (b) Keep the sessions, refused while the org is stopped, so they and their devices work
      again on resume until they expire.
    - **Recommend (a)**, as built: it is the safer default, and re-linking is one approval from a
      signed-in browser. Owner question.



### PR 5a-1 as built: shared replica coordination

- Migration 0036 is a SQLite no-op and creates PG-only `replica_logins`, `replica_rates`,
  `replica_lockouts` and `replica_presence`; reminder claim columns are PG-only too.
- Shared mode is selected from the database record. SQLite keeps its existing memory paths.
  PKCE state is hashed, consumed atomically, expired and capped at 1024 by oldest expiry;
  pending settings are bound by hash without persisting environment client/directory secrets.
- All limiter labels and office budgets use database-clock GCRA; login/recovery/device attempts
  reserve before verification, with per-request generation-bound refunds. Store errors fail closed.
  Office-network lists refresh within a minute. Presence writes recheck membership and have a
  cross-org trigger; reads filter current memberships. Purge/erase cover presence explicitly.
- `SessionLock` keeps SQL and short write transactions on the pinned connection. `worker.Run`
  adds exclusive ownership, one-second liveness probes on its idle lock connection, cancellation
  and standby takeover. Schedule wiring is still the next 5a boundary.
- Reminder claims last two minutes and completion deletes only that token. Rescheduling clears
  the token, preserving the new reminder against a slow old completion.
- PG readiness adds a one-second cached ping; liveness remains database-independent.
  Keyed configuration verification and atomic PG restore fencing are preparation only: the
  full field map, startup adapter and PG restore transport are not enabled here.
- `TestReplica*` uses independent database pools, actual signed OIDC login, concurrent token/
  lockout admission, wrong-org refusal, a fake TLS push, worker-session loss, single-connection
  saturation and restore rollback/fencing. Existing golden and upgrade fixtures are unchanged.
- Still unbuilt: elected schedule adapters, shared key loading, complete fingerprint map/drain,
  blob seam/org prefixes/parts/store identity and primary object storage, erased-feed reconciliation
  and operational PG backup/restore. Startup continues refusing multi; no volume fallback/pruning.


### PR 5a-2 as built: replica adapter and blob seam

- `blobstore.Backend` has the six existing operations and `DeletePrefix`; `Temporary` keeps
  backend stream details private. Volume paths and behavior are unchanged and prefix purge
  returns unsupported. No shared-volume deployment path is added. Org/blob/part key builders
  reject path components; same ciphertext in two orgs has distinct object keys.
- `VerifySharedIdentity` implements the specified random store ID and create-exclusive marker,
  prior-probe read, CAS advance and winner-probe check. Control-file callbacks are internal
  protocol operations, not a new S3 client/interface. All I/O is outside N3; only a changed
  pointer permits up to three re-reads. Database time stamps probe retirement. Tests use
  atomic create semantics and cover fresh concurrent replicas, empty private stores, another
  install, a crash before marker creation and a racing pointer. Runtime object binding waits5b.
- `readReplicaInputs` requires environment pairing/server-salt/SSO/VAPID keys and HTTPS object
  metadata, never local-key fallback/mint. VAPID is the existing file format: standard base64
  of32 P-256 private-key bytes. `replicaFields` enumerates shared security/config/key identities;
  object credentials and per-host bind/proxy/backup path/keep/log settings stay excluded.
- `runReplicaSchedules` prepares one elected app pass: minute org/lifecycle/state/reminder/
  backup attempts, configured GC and per-tick pool reporting. GC/PG-backup callbacks are bound
  only when their real adapters exist. Failed attempts wait their cadence; cancelled jobs stop.
- `drainReplica` follows the pattern's readiness/cancel, five-second proxy delay, five-second
  HTTP drain and ten-second job drain. Single-mode loops and shutdown are unchanged.
- Restore fencing retains permanent store identity and drops obsolete probe pointers as well
  as grants/cursors/ephemeral security state. The PG backup/restore transport is still unbuilt.
- Tests include deterministic schedule cadence, actual elected takeover, environment/fingerprint
  boundaries, HTTP drain and chunks alternating independent routers/pools with concurrent
  duplicate retries on a shared test directory. Actual bucket/part/purge evidence remains5b.
- Multi startup is still refused. Shared S3 absence constrains5b, not this preparation. No
  automatic version pruning or hosted-volume fallback. Phase6 runtime assembly remains gated.


### PR 5b-1 as built: object/part I/O preparation (startup still refused)

The published shared ky-primitives S3 client supplies permanent ciphertext and numbered-part
operations through `blobstore.Objects`, scoped to one resolved org. Bounded private files verify
size/hash before PUT/download publication and are removed on Close/error. Existing immutable
keys/parts are checked and reused. Explicit key/org cleanup covers physical versions/markers;
no kept logical version is pruned. Parts survive final assembly until explicit post-commit
cleanup; a rolled-back counter explicitly trims its uncommitted tail. Assembly verifies ordered
sizes and the final digest. Independent single-connection PG pools hold a key lock across I/O
and a short claim, while a separate writer can still acquire N3.

Tests use the real shared client over a verified local TLS S3 fixture, plus PG; they do not
qualify a provider. The complete Backend/Temporary, route/GC/purge binding and startup adapter
remain unbuilt. Shared-client #77 also lacks N15 create-exclusive marker PUT and provider age
metadata at the initial consumed head; requirements are with its existing owner. No private
client, volume fallback, automatic pruning or hosted/native-backup readiness is claimed.

The object preparation consumes the shared client's encoded-byte GET correction: identity
encoding preserves opaque gzip-labelled bytes and GET/HEAD size agreement. A regression fails
against the earlier published client and passes after the upstream correction. This does not
make the separately merged conditional-PUT/timestamp follow-up part of the consumed dependency.


### PR 5b-2 as built: credential/client preparation (startup still refused)

`app.newReplicaObjectClient` consumes the selected environment/_FILE credential forms through
one bounded, setting-name-only reader and the actual shared client's constructor. One form
per key, one nonempty line, at most64KiB; regular files may have one trailing LF/CRLF.
Credentials never enter shared fingerprints/settings or local keys. Construction performs no
network or database I/O and is not called by ordinary startup or maintenance loading.
Tests cover direct/file/mixed sources, ambiguity/empty/size/multiline/path/type refusal,
secret-safe errors/formatting, shared-field separation and unchanged startup refusals.

Base #77 was pinned at 79823f9; the late-PUT fence moved the pin to the #78 merge b55ca6d. Before
complete GC/purge/runtime binding, Notes must select and qualify delayed remote-PUT fate
after PG-lock loss; cancellation alone is no completion proof. Shared conditional operations
do not select a Notes ledger/protocol. Keep this and native-PG recovery open question3 as
explicit remaining gates, alongside store controls/age/provider proof and lifecycle E2E.


### PR 5b-3 as built: object GC and org purge (startup still refused)

`storage.RunObjectGC` is the multi-mode blob sweep. Candidates and the in-lock re-check are per
`(org_id, digest)` with org-qualified references, at most 100 a pass, serving orgs only. Each
blob takes `BlobLockName(org, digest)`, deletes its rows in a short transaction on that
connection, commits, then deletes every version of the object. A failed delete leaves an
object with no row. `PurgeOrg` takes a `PurgeObjects` step and refuses without one; it deletes
the `orgs/<org_id>/` prefix after the rows and marks the tombstone purged only on success.
Tests use the real shared client over the local TLS fixture on PostgreSQL. Each property fails
under mutation: org-blind candidates, no re-check, object delete before commit, purge without
the prefix step. The schedule adapter carries the purge step; startup binding, the late-PUT
fence and the orphan sweep are separate.


### Late-PUT erasure fence as built (startup still refused)

The problem: a writer admitted before an org's deletion (or holding a blob lock it then
loses) can have a PUT the provider stores after the purge deleted the prefix, or after GC
deleted the blob. Lock loss and cancellation prove nothing about that remote write.

The selected resolution is a time fence, with no new ledger:

- `Objects.Put`/`PutPart` bound the whole call by a 5-minute deadline from entry. Callers
  admit the org under the session lock just before the call, with bytes already received.
- `LatePutWindow` is 20 minutes: the deadline plus SigV4's 15-minute request-age limit, which
  a provider applies when it receives the request.
- The purge's first run inserts `purge_fence:<org>` in database time with the
  `platform.org_purge_started` audit, in one transaction (the audit is now written once). Every
  run deletes the rows and the prefix. Only a run that read the fence at least the window old
  before its prefix delete marks the tombstone purged and removes the fence. The status is
  re-read before the prefix delete, and the mark requires `status='deleted'` in its own
  transaction.
- `SweepOrphanObjects` runs at the end of `RunObjectGC`. For each serving org it lists the
  prefix with provider times and deletes any blob with no row and any upload with no pending
  session, once over an hour old. Each deletion is admitted under the blob or upload session
  lock, in a short transaction that re-reads both the claim and whether the org still serves.
  An org stopped during the listing keeps its objects. Zero (unknown) age
  never deletes; at most 100 a pass.
- The shared client pin moved to the #78 merge (`b55ca6d`) for `LastModified`.

Tests: a PUT blocked at the provider times out at the client; the purge runs; the provider
then stores the PUT. The purge must not be marked inside the window, and the run after it must
leave no key. Removing the window check fails it; removing the deadline fails its 10-second guard.
The orphan sweep keeps young, unknown-age, claimed, pending-upload and stopped-org objects.
Mutations of the age check, the claim re-check and the pending-upload check each fail it.
`TestOrphanSweepKeepsObjectsOfAnOrgStoppedDuringTheListing` suspends the org from inside the
provider listing; it fails without the in-lock serving re-check.
`TestPurgeRereadsTheStatusBeforeThePrefixAndTheMark` fails without either status re-read.

Unproven: that a selected provider honors request age and commits no PUT past the window
(provider qualification), and clock skew between provider and database beyond a few minutes.


### Provider qualification as built (startup still refused)

`blobstore.QualifyProvider`, run by `kynotes-server qualify-object-store` with the replica's
own object environment and bounded `_FILE`/direct credential reader (PR 5b-2), checks the
provider behaviors the object runtime relies on, under a fresh `qualify/<random>/` prefix it
deletes again on success and failure:

- **Signatures:** a request signed with a wrong secret is refused, not answered `404`.
- **Conditional writes:** a second `If-None-Match: *` PUT is refused (`412`) and the object
  keeps its first bytes (blob writes and the store ID rely on this).
- **Age metadata:** `LastModified` is present and within 5 minutes of this host's clock, since
  the orphan sweep ages objects by provider time.
- **Versions and erasure:** an overwrite and a delete, then a prefix delete, leave no version or
  delete marker. Versioning on or off is reported; both qualify, because Delete and Purge remove
  every version.

It needs only read, write, list and delete in the bucket. `TestProviderQualificationOnVersionedS3`
runs it against the suite's signature-checking, versioned SeaweedFS fixture behind a verified TLS
proxy (CI job `object-store`, normal and FIPS), and makes the proxy lie in one way at a time;
each lie fails at its own step. **Not qualified here:** SigV4 request-age refusal (a request
signed more than 15 minutes earlier) and so the late-PUT window's provider bound, because the
shared client exposes no signer clock; that needs a ky-primitives option. Credential scope
(that the key reaches only this bucket) is the operator's IAM policy and is not probed. The
chosen hosted provider must pass this command before multi startup is enabled.

### Phase 6 host maintenance as built (startup still refused)

Multi-mode `user add --admin` uses bounded stdin derived credentials and an exact existing PG
schema, refusing customer/everyday creation and password/DSN argv. Recorded staff-org/region
checks and an in-transaction binding recheck precede atomic account/platform-audit creation;
the recovery code is emitted only after commit. Staff bootstrap preparation is staff-only,
audited and serialized across independent pools, with password work outside N3. Everyday
bootstrap variables refuse; single-mode paths remain unchanged.

`accept-replica-config --confirm-stopped` reads deployment configuration without local-key
fallback/minting and uses the full existing app field map. The retained salt/encryption key
and fixed mode/staff/region cannot change. Fingerprint and changed-name audit commit together;
a failed audit leaves the old fingerprint. Ordinary startup/config loaders still refuse multi.
Tests cover both backends where applicable, actual PG target/schema/audit/input boundaries,
real password checks, concurrent bootstrap and unchanged single-account workflows. Maintenance
preparation does not choose PG backup transport or enable object/runtime/hosted startup.


### Phase 6 fixed environment SSO as built (startup still refused)

`NewFixedStore` accepts the existing app-validated environment snapshot without a database
handle. Reload preserves it and Save refuses; single mode retains its original mutable store.
PG PKCE state remains route-owned. Actual signed TLS issuer/two-pool tests exercise callback,
one-use, wrong-org and differing-environment refusal without persisting client/directory
secrets. Unit/environment-input tests prove immutable copies and concurrent mutation refusal.
This prepares N5's store adapter; final runtime construction still waits for primary object
storage, native PG recovery and full lifecycle acceptance before startup can be enabled.

Final login/step-up, logout and signed-directory admission recognize the immutable snapshot
only when both the store's server-owned fixed marker and recorded multi mode agree. All
account/org/erasure/revocation/replay fences remain under the writer lock. Single mode and
mutable stores retain the database configuration recheck. Signed tests cover fixed directory
signatures, logout replay/in-flight-login fencing, and refusal to bypass single-mode settings.
