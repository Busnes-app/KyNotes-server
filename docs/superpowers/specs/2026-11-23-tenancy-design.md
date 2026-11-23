# Tenancy: single-tenant and multi-tenant (SaaS), KyNotes design

Date: 2026-11-23, revised the same day for owner decisions 9 and 10. Status: proposed design,
waiting for owner review. Nothing is built, and this change is docs only. KyNotes has no tenancy
code today: no `org_id` appears anywhere under `internal/` or `cmd/`.

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
| N3 | **On PostgreSQL every write transaction takes one advisory transaction lock** (`pg_advisory_xact_lock` on a fixed key) as its first statement. Reads take none. | Fact 2: it keeps every SQLite immediate-transaction invariant without auditing each one again, and across replicas too. KyIdentity serialises its Postgres writes the same way (T "Entitlements"), and C keeps one `calendar-total` lock. The cost is one writer for every org (open question 5). |
| N4 | Isolation is enforced in the application: every org-owned row carries `org_id`, an org-bound store handle binds it, and triggers check existence, immutability and agreement with the parent row. | T D3 and C D3. The store has one SQL text for both backends, and single-tenant SQLite runs the same handlers. |
| N5 | In multi mode the sign-in provider is fixed by environment: `KYNOTES_SSO_ISSUER`, `KYNOTES_SSO_CLIENT_ID`, `KYNOTES_SSO_CLIENT_SECRET`, `KYNOTES_SSO_HMAC_SECRET`. The admin SSO save and pairing routes answer `404`. Auto-provisioning is always on. Customer password sign-in, `/setup`, `user add` for everyday accounts and `apply-setup` are refused. | Today SSO settings live in `server_settings` and are cached per process (`internal/sso/sso.go:27-98`), so a save on one replica leaves the others stale. One issuer (owner decision 2) means the binding never changes. Customers then always get device-only identities with a recovery code, which already works (`AGENTS.md:830-873`). |
| N6 | In multi mode an account is an administrator only when it is an administrator account (`account_kind='admin'`) **and** its `org_id` is the staff org. Staff accounts are created only by `kynotes-server user add --admin` and the bootstrap variables, into the staff org. | Owner decision 3. Administrator accounts already open no notes (`AGENTS.md:179-196`), so staff never hold content keys. This is defence in depth against a staff mistake that sends `kynotes.admin` for a customer. |
| N7 | **A container, its members and its invitations are in one org.** Triggers refuse a membership, an invitation acceptance, or a key or invitation envelope (`key_envelopes`, `invitation_envelopes`) whose user is in another org than the container. **No trigger runs on invitation insert:** an invitation to another org's user ID is created like one to an unknown ID, so creation answers the same for both, and it can never be accepted. Handlers check the org explicitly before each insert and answer as for a missing row: accept answers not-found, and `insertInvitationEnvelopeTx` adds the org to its identity-device check (`teamkeys_routes.go:473-477`), so another org's device gets `errEnvelopeInvalid`, as an unknown device does today. The triggers are a backstop whose error no handler maps to its own answer. | Teams are how Couple, Family and Business share notebooks, so they stay on in multi mode. Today `invitee_id` is any well-formed user ID with no existence check (`internal/httpapi/collab_routes.go:165-197`), so creation reveals nothing. Accept checks the invitee inside its transaction (`collab_routes.go:235`). |
| N8 | **Blobs become org-owned.** `blobs` gains `org_id`, and on PostgreSQL its key is `(org_id, digest)`. The object key in multi mode is `orgs/<org_id>/blobs/<digest>`. Single-tenant keeps `<data>/blobs/aa/bb/<digest>` and the digest key. | Fact 3. A shared digest across orgs would let one org's upload, purge or quota interact with another's file. Per-org keys make a purge a prefix delete and quota exact. KyDrive refused content addressing for the same reason (D "Blob storage"). |
| N9 | KyNotes keeps a local mirror of `/api/suite/orgs` (`orgs` table), polled about every 60 s by the elected worker (`suitedir.Client.Orgs`, `suitedir/client.go:241`). Every authenticated read joins the account's org row in the same query as the account. | T D6 and downstream contract 5. C D6. A suspension then takes effect at the next request on every replica. |
| N10 | **The storage limit is the org's pool, held by KyIdentity.** KyNotes counts the org's charged bytes, reports them, and refuses a write that adds bytes past the org's allowance (the pool less what every other app reports). The allowance is cached in the `orgs` mirror, so the write path makes no network call. Today's per-user and per-team caps stay as safety limits. There is no per-app `max_bytes` key. | Owner decision 10. A per-app storage key in T's `quotas_json` would be a second number the customer never bought. It matches KyCalendar's D14 (PR #190), so every app reads the pool the same way ("The org storage pool"). |
| N11 | **Export runs in the browser, under `export_only`.** A session whose ID token carries `"export_only": true` is marked so. It admits only the read routes the notebook export needs (Lifecycle, Export). Every other route answers `403 export_only`. There is no operator export command. | Fact 1: only the browser can decrypt. The browser export already exists (`exportNotebook.ts`, `AGENTS.md:273-277`). Owner decision 8. |
| N12 | **Multi mode adopts the replica pattern**: `/livez` and `/readyz` with the drain order, a shared-configuration fingerprint, one elected worker through a PostgreSQL session advisory lock, and every security limit in PostgreSQL. | Owner decision 7. The pattern's "Product rollout contract" (a) to (f) is the checklist (Replica work). |
| N13 | Each multi install serves one region, `KYNOTES_REGION` (default `local`). An org whose `home_region` differs is treated as not serving. | T "Home region" H1 to H4: an org's data lives in one region. A misrouted token then reaches no data. |
| N14 | A `deleted` org is purged by the elected worker in short, resumable batches behind a fail-closed audit row. Its `orgs` row stays as a tombstone. Erased subjects come from `/api/suite/erased`. | C D12 and T "Delete everything". A purge in one transaction would hold N3's lock and stop every other org's writes. |
| N15 | **One blob interface, two backends.** `internal/blobstore` gets an interface with the methods its callers use today (`NewTemp`, `Reopen`, `Open`, `Stat`, `Delete`, `ListDigests`), plus a prefix delete for the purge. `volume` is today's code. `object` is S3-compatible. Single-tenant always uses `volume` at `<data>/blobs`, unchanged. Multi mode takes `KYNOTES_BLOB_BACKEND=object` or `volume`, and `volume` there must be a directory every replica mounts (`KYNOTES_BLOB_DIR`). The backend joins the shared-configuration fingerprint. | Owner decision 9: launch may run on volumes, so both backends must work. A replica on a private disk would lose blobs written by the others, so a store-ID check proves the storage is shared ("Blobs in S3-compatible storage"). |

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
| `blob_containers` | `0001_init.sql:6` | D | Both FKs. The pair must be one org: a trigger compares `blobs.org_id` with the container's. |
| `objects` | `0001_init.sql:7` | D | `container_id` FK, cascade |
| `object_versions` | `0001_init.sql:8` | O | It is reachable through `objects`, but it references `blobs(digest)`. On PostgreSQL that FK becomes `(org_id, blob_digest)`, which needs the column. A trigger requires it to equal the object's container's org. `author_device_id` and `author_user_id` (`0022_team_keys.sql:2`) have no FK. |
| `devices` | `0002_devices.sql:1` | D | `user_id` FK, cascade. Includes the identity row (`platform='identity'`, `0021_identity_keys.sql`). |
| `memberships` | `0002_devices.sql:3` | D | Both FKs. N7: a trigger requires the user's org to equal the container's, on insert and re-point. |
| `pairing_nonces` | `0002_devices.sql:5` | P | `user_id` has no FK, rows expire, keyed by a nonce hash. The purge deletes the org's users' rows. |
| `key_envelopes` | `0002_devices.sql:6` | D | `container_id` and `device_id` FKs. A trigger requires the device's user to be in the container's org. |
| `device_containers` | `0002_devices.sql:8` | D | Both FKs, same trigger as `key_envelopes` |
| `conflicts` | `0002_devices.sql:9` | O | It references `blobs(digest)`, as `object_versions` does. |
| `attachments` | `0002_devices.sql:10` | O | It references `blobs(digest)`. `idx_attachments_container_digest` (`0002_devices.sql:11`) stays. |
| `upload_sessions` | `0002_devices.sql:12` | D | `user_id` and `container_id` FKs |
| `idempotency` | `0002_devices.sql:13` | P | `user_id` has no FK. The key is a hash that includes the user ID. Rows expire. |
| `audit_events` | `0002_devices.sql:14` | O, with one exception | **Nullable** `org_id` with **no default**: NULL is a platform row (staff actions, backups, purges, `staff.read`), as T does for `audit_events`. Every writer names the org explicitly: a customer's action names the actor's org, and a platform writer passes NULL. The existence trigger checks only a non-NULL value. Migration 0032 backfills existing rows with the default org, and in single mode every new row names the default org, so single-tenant rows look as they do today. `user_id` has no FK. |
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
| `blob_replicas` | `0015_blob_replicas.sql:1` | Off | The offsite mirror. Off in multi mode (open question 2). |
| `sso_logout_events` | `0016_sso_logout.sql:19` | P | Replay ledger keyed by issuer, client and JWT ID |
| `sso_directory_state` | `0017_sso_directory.sql:2` | P | Revision fence keyed by `(issuer, subject)`. The purge deletes the org's subjects' rows. |
| `sso_stepup` | `0019_sso_stepup.sql:1` | D | `session_id` FK |
| `sso_login_cutoffs` | `0020_sso_login_cutoffs.sql:3` | P | Fence keyed by `(issuer, subject)`. The purge deletes the org's subjects' rows. |
| `user_identities` | `0021_identity_keys.sql:3` | D | `user_id` and `device_id` FKs |
| `invitation_envelopes` | `0022_team_keys.sql:7` | D | All three FKs, same trigger as `key_envelopes` |
| `link_requests` | `0024_device_linking.sql:8` | D | `user_id` and session FKs |
| `reminders` | `0028_reminder_push.sql:3` | D | `user_id` FK. Gains a claim column (Replica work). |
| `web_push_subscriptions` | `0028_reminder_push.sql:6` | D | `user_id` FK. `endpoint UNIQUE` stays global: an endpoint is one browser's push channel. |
| `cleanup_audit_slots` | `0031_cleanup_slots.sql:10` | D | `container_id` has no FK, but every slot is written with its source row's container. On PostgreSQL the slot mechanism is replaced (Replica work, "SQLite-only mechanisms"). |

Tables this spec adds:

| Table | Class | Reasoning |
|---|---|---|
| `orgs` (`id`, `status`, `revision`, `enabled`, `home_region`, `pool_allowance_bytes`, `pool_checked_at`, `pool_low`, `seen_at`, `purged_at`) | P | The mirror of `/api/suite/orgs` (N9) and of the org's pool allowance (N10), and the target of every `org_id`. It holds the default org in single mode and the staff org in multi mode. A deleted org stays as a tombstone (N14). |
| `org_usage` (`org_id`, `bytes`, `reported_bytes`) | O | The durable part of the org's charged bytes, kept by triggers, and the last figure reported to KyIdentity ("The org storage pool") |
| `erased_subjects` (`subject`, `org_id`, `revision`) | P | The local copy of `/api/suite/erased`, so a restore can re-erase (Lifecycle) |
| `worker_claims` | P | Only if the elected-worker port needs one. The replica pattern uses a session advisory lock and no table. |

### Files under the data directory

| Path | Written by | Class | Multi mode |
|---|---|---|---|
| `kynotes.sqlite` (+ WAL) | `serve.go:38` | P | Not used. PostgreSQL. |
| `.kynotes.lock` | `internal/storage/lock.go:12-24` (exclusive `flock`, `LOCK_EX\|LOCK_NB`) | P | Kept per replica. Each replica has its own data directory, never shared, so the lock only stops two processes on one directory. |
| `blobs/aa/bb/<digest>` | `blobstore.go:35`, `:58-96` | O (through `blobs`) | The `object` backend, or the shared `volume` (N8, N15) |
| `tmp/<upload>.part` | `blobstore.go:40` (chunked uploads, `upload_routes.go:157`, `:220`) | D (through `upload_sessions`) | **Must be shared.** Chunk 2 can land on another replica than chunk 1, and `Reopen` would not find the part. Each chunk becomes its own object, `orgs/<org_id>/uploads/<upload>/<n>`. Finalize streams them into one put and hashes while it streams. |
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
| Per-upload chunk lock (`lockUpload`) | `internal/httpapi/upload_routes.go:33-34`, taken by the chunk handler at `:198` | Retries of one chunk can reach two replicas at once. The chunk handler takes a PostgreSQL transaction advisory lock on the upload ID instead, held until the chunk's `received_bytes` update commits. The chunk object for a given index is written whole, so a retry replaces it with the same bytes. The two-replica test sends one chunk to both replicas at once. |
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

1. Create `orgs`, `org_usage` and `erased_subjects`. The migration inserts the default org
   (`00000000-0000-0000-0000-000000000001`, T's default-org ID, `active`, `local`) only when
   `users` already holds rows. That is an existing install, which is always single-tenant. A
   fresh database gets no `orgs` row from the migration.
2. `storage.Open` then runs `ensureOrgs`, right after the migrations and before
   `EnsureBootstrapAdmin` (`serve.go:43`). Its inserts are `ON CONFLICT DO NOTHING`, so replicas
   starting together need no lock. It inserts the default org (single mode) or the staff org
   from `KYNOTES_STAFF_ORG_ID` (multi mode, `active`, `enabled`, region `KYNOTES_REGION`) if it
   is missing. It records `tenancy_mode` when no row exists: `single` if the default org exists,
   otherwise the configured mode. N1's mismatch check runs right after.
3. Add `org_id`, defaulting to the default org, to every O table except `audit_events` (nullable,
   no default; see its row). Backfill `org_usage`.
4. Add triggers, with the same names on both backends:
   - one requires the org to exist in `orgs`;
   - one refuses any change to `org_id`;
   - one per O table requires agreement with its parent: a container with its owner, a child
     container with its team, `object_versions`, `conflicts` and `attachments` with their
     container, `blobs` with each `blob_containers` container;
   - N7's membership, invitation-accept and envelope triggers compare a user's org with a
     container's.
5. On PostgreSQL, add the composite keys: `blobs(org_id, digest)` as the primary key, and
   `(org_id, blob_digest)` FKs from `object_versions`, `conflicts` and `attachments`. SQLite
   keeps `digest` as the key. A unique digest there implies a unique pair, and SQLite cannot
   alter a key without rebuilding the table, which migrations avoid (T D2).

The `org_id` default stays on both backends, as C does. A multi install has no default-org row,
so an insert that forgets `org_id` names a missing org and fails the existence trigger instead of
landing in an org.

**Single-tenant does not change.** With one org every query returns what it returns today. The
browser, the API bodies, the probe and the MCP bridge see no new field. PR 1 proves it with an
upgrade golden test (Tests).

`orgs.status` takes KyIdentity's values (`active`, `suspended`, `deletion_scheduled`, `deleted`)
plus `stale`, which means KyNotes has no current answer for the org (C). Only `active`, `enabled`,
in this region, serves. A failed poll changes nothing.

### The org-bound store

KyNotes has no store layer for most reads: handlers run SQL on `*sql.DB` directly, and
authorization is a join on `memberships` with the caller's user ID (for example
`upload_routes.go:98`, `:466`). So the org binding goes where the caller is resolved:

- **`ResolveSession`** (`internal/auth/session.go:109-122`) and **`resolveDevice`**
  (`internal/auth/middleware.go:239-248`) join `orgs` on the user's `org_id` and refuse a
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
- All of these run on SQLite (single, one org) and on PostgreSQL (multi).

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

**Two backends in multi mode**, chosen by `KYNOTES_BLOB_BACKEND`:

- `object`, the target. S3-compatible, configured by `KYNOTES_BLOB_S3_ENDPOINT`, `_REGION`,
  `_BUCKET`, and the keys `KYNOTES_BLOB_S3_ACCESS_KEY` and `KYNOTES_BLOB_S3_SECRET`, or
  `KYNOTES_BLOB_S3_ACCESS_KEY_FILE` and `KYNOTES_BLOB_S3_SECRET_FILE` naming a file that holds
  each. Setting both forms of one key is a startup error. The endpoint must be HTTPS. Keys never
  reach a log, an error body, `/admin/settings` or the fingerprint; the fingerprint holds the
  endpoint, bucket and region only.
- `volume`, the launch fallback. `KYNOTES_BLOB_DIR` is a directory every replica mounts (a
  shared filesystem). Layout is `orgs/<org_id>/blobs/aa/bb/<digest>` and
  `orgs/<org_id>/uploads/<id>/<n>`, the same keys as `object`. Unverified: that `rename` is
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
| Write | rename into `blobs/aa/bb/<digest>` | `volume`: as today, under the org prefix. `object`: one `PUT` to `orgs/<org_id>/blobs/<digest>` conditional on the key not existing (`If-None-Match: *`). An existing object is checked for size and digest, as a present file is today (`blobstore.go:71-82`). |
| Chunked upload | `tmp/<id>.part`, appended | one part per chunk, `orgs/<org_id>/uploads/<id>/<n>`, because chunk 2 can reach another replica. Finalize copies the parts in order into a private temp file on the replica, hashing as it copies, then writes the blob once. S3 multipart is not used: its parts must be at least 5 MiB, and a chunk is 4 MiB (`config.go:93`). |
| Read | open, hash, rewind, serve | `object`: download to a private temp file on the replica, hash, then serve. Objects are at most 25 MiB (attachments) or 10 MiB (pages) (`config.go:93`). Unverified: the added latency. |
| Delete | in GC's transaction | the backend's delete inside GC's transaction, after the row deletes and before the commit, as today (`gc.go:110-124`). A commit that fails after the delete leaves an unreferenced row with no object, which the next GC pass removes. |
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
- Devices, identities and envelopes are kept, so a resume needs no re-linking. Device credentials
  answer `401` while the org does not serve (`resolveDevice`).
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
2. Delete containers in batches of at most 500 objects and versions each, under N3's lock. The
   cascades take objects, versions, comments, attachments, memberships, envelopes and changes.
   Unreferenced blobs then lose their rows in the same batch.
3. Delete the org's users. That cascades to sessions, devices, identities, reminders,
   subscriptions, uploads and link requests. Also delete its rows in the tables with no FK:
   `sealed_share_links`, `audit_events` (the org's own), `pairing_nonces`, `sso_directory_state`
   and `sso_login_cutoffs` for its subjects.
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
4. In batches of at most 500 objects and versions, under N3's lock: delete the containers they
   still own. After step 2 these are exactly the ones with no other approved member: their
   personal notebooks and any team they alone are in.
5. In batches: delete their comments and mentions in shared notebooks, reminders, push
   subscriptions, share links and sealed links. Sealed links have no FK
   (`0029_share_link_owner.sql:3`), so this step is needed.
6. Delete the user row. The cascades from `users` then take what is left: memberships, the
   invitations they sent (`inviter_id`, `0003_collaboration.sql:1`), and any comment
   (`0003_collaboration.sql:2`) or mention (`:3`) a batch missed. A pending invitation from an
   erased member cannot be accepted any more, which is intended: the new owner re-invites.

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
unserved, and is never purged on that ground: KyIdentity is the only source of an org. There is
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
  would stall every org. So `org_usage.bytes` holds the durable terms (versions, conflicts, live
  comments, live attachments, kept previews), kept by insert, update and delete triggers on those
  tables. The terms that lapse with time (pending uploads and sealed links past their expiry) are
  summed at check time from their own indexed rows, which are few.
  `TestOrgUsageMatchesUsedBytes` builds an org with every term and compares the trigger figure
  with the full `usedBytes` query after each write, delete, GC sweep and purge batch.

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
1. **Org model and the single-tenant golden.** Migration 0032: `orgs`, `org_usage`,
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
   restore reset; (e) the org pool (N10): `org_usage` triggers, the report, the cached
   allowance and the check. 4e waits for KyIdentity's contract, and multi mode cannot be enabled
   (PR 6) without it: the pool is required for launch.
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
5. **Replica work and blob storage.** Split so launch never waits on object storage:
   - (a) The elected worker, reminder claims, the in-memory state moved to PostgreSQL,
     environment-only keys, the fingerprint, `/readyz`, the blob interface (N15), the shared
     `volume` backend with org prefixes and upload parts, and the store-ID check. This is enough
     to launch.
   - (b) The `object` backend on ky-primitives' S3 type, with keys from the environment or a file.
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
   PostgreSQL restore too. KyIdentity, KyCalendar and KyDrive face the same limit (unverified for
   their sizes).
4. **An erased owner's team notebooks with other members.** Delete everything deletes the
   clicker's data, and a team notebook is shared.
   - (a) Ownership passes to the longest-standing approved admin, else the longest-standing
     editor, else the longest-standing approved member of any role. The notebook and the pages
     the erased member wrote stay. A commenter or viewer who becomes owner gains owner rights.
   - (b) The notebook is deleted for everyone.
   - **Recommend (a)**, the default this spec builds to: it deletes nobody else's work.
     Owner question.
5. **One writer (N3).** Recommend accepting it for launch and measuring writes a second before
   launch, as C open question 4 did. If it fails, move to a per-org advisory lock and re-check the
   install-wide invariants (blob claims are per org after N8).
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
11. **The volume fallback's filesystem.** Owner decision 9 lets launch run on volumes, and
    replicas on several hosts need one filesystem they all mount (NFS or CephFS). Recommend one
    shared filesystem per region for every app that falls back, chosen with KyDrive and
    KyMessages, and moving to `object` before the first plan with large pools fills it.
12. **Version history and the pool.** Every save adds a version that counts. Recommend no
    automatic pruning for launch, since it would delete customer data; an over-quota member
    frees room by deleting pages, notebooks or attachments, which frees their bytes at once
    ("What over-quota refuses"). A history limit per plan is a later owner choice.
