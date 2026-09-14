# KyNotes Server Design

## 1. Purpose

KyNotes is a self-hosted, zero-knowledge note service. It stores encrypted
structured note documents and encrypted attachments, synchronizes them between trusted
clients, and supports small teams of fewer than 20 people.

The server is a Go application distributed in a Docker container. It stores
metadata and ciphertext, but it must never need plaintext note content,
attachment content, or private encryption keys.

## 2. Initial scope

The first release includes:

- Account login using KyPassword's authentication and key-management
  contracts.
- Web, Android, and iOS clients. Desktop is deferred.
- QR/deep-link device pairing with device-wrapped keys.
- Encrypted workbooks, folders, structured notes, and attachments.
- Explicit sync selection for workbooks, projects, and teams.
- Near-real-time HTTPS synchronization with offline support.
- Personal inboxes and personal workbooks.
- Projects as top-level containers.
- Teams, roles, encrypted collaboration, activity history, and notifications.
- Tasks represented in Markdown with YAML front matter and checkboxes.
- Push notifications through the existing KyPost model, with pull fallback.
- A single-directory self-hosted storage and backup model.

Templates, web clipping, freehand drawing, rich media editing, and desktop
clients are designed as later phases unless required by the client teams.

## 3. Product model

### Containers

- A **Workbook** is a personal top-level encrypted container for folders,
  notes, tasks, and attachments.
- A **Project** is a separate top-level container. It may contain notes, task
  data, folders, and attachments.
- A **Team** is a membership and key-management container. Teams contain
  shared projects and shared notes.
Each container has its own encryption key and explicit device sync selection.

### Notes and tasks

Notes are versioned structured documents edited in the client. Markdown and
HTML are import/export formats only; the encrypted note payload is a versioned
editor document so formatting, images, and comment anchors do not depend on
re-parsing text.

The task screen provides:

- A global personal view organized by date.
- Views scoped to a personal workbook.
- Views scoped to a project or team.
- Due dates, recurrence, priority, status, assignee, subtasks, and reminders.

The personal inbox is a normal encrypted inbox folder. Captured Markdown can
later be moved into another folder, workbook, or project, or converted into a
task by the client.

## 4. Security model

### Authentication

KyNotes reuses KyPassword's client-derived authentication, KDF, login,
lockout, session, and recovery contracts. The server receives and stores only
the authentication verifier required by that protocol.

All application communication uses HTTPS. Push delivery may use FCM or APNs;
push payloads contain notification metadata only and never note content or
keys.

### Single sign-on and directory trust

OIDC login verifies signed ID tokens using `ky-primitives/oidcverify`, binding the
configured issuer, client audience and a one-use login nonce. Existing local usernames
are adopted only by trusted directory provisioning; the login callback never silently
links them. Directory events use `ky-primitives/syncauth` signatures and a durable event
ID admitted in the same SQLite transaction as account changes. Failed applications can
retry; applied events are refused during the signature-validity window.

### Encryption

Encryption and decryption happen in clients. The server stores:

- Encrypted container key envelopes.
- Encrypted structured note-document blobs.
- Encrypted attachment blobs.
- Encrypted collaboration and audit details.
- Non-sensitive routing metadata required for synchronization.

Each container has a randomly generated content-encryption key. That key is
wrapped for each authorized device and member using public-key envelopes. A
device can decrypt only the containers explicitly enrolled on that device.

Attachments use authenticated encryption. Deterministic/convergent
encryption is permitted for attachment deduplication. This intentionally leaks
equality of identical encrypted attachments; the tradeoff is documented in
the security model.

Attachments accept arbitrary binary bytes. Clients encrypt the content and all
attachment metadata, including filenames, MIME types, dimensions, and
plaintext sizes, before upload. The server sees only routing data and
ciphertext properties required for transport and storage.

Attachments are immutable and content-addressed by their encrypted digest.
Deduplication is scoped to a container. Uploads use resumable sessions and
expire after 15 minutes when incomplete. Abandoned uploads remain visible to
the user until they expire. Attachments synchronize separately from notes and
are optional additions: a note saves even if its attachment upload fails or
never completes. Clients download attachments lazily. Image attachments must
include a client-generated preview, stored as a separately encrypted blob.

Attachment access inherits the permissions of the containing project. When a
note is deleted, all current and historical versions are deleted and their
attachment references are released. A blob is deleted when no note references
it and the garbage-collection retention period has elapsed. Garbage collection
is controlled globally and uses a configurable retention period. It may be
disabled, with unreferenced storage growth as the explicit trade-off.

### Device enrollment and revocation

Enrollment is initiated on the authenticated website. The web client creates
a QR code or deep link containing a short-lived, single-use pairing token. The
mobile client scans it, creates or exposes its device public key, and receives
only encrypted device-wrapped key envelopes.

The server derives device identity and fingerprints from the registered public
key rather than trusting client-provided identity fields.

Revoking a device deletes its server-side key envelopes and marks the device
revoked. The client must delete local key material and wipe local encrypted
storage on the next successful connection. Local memory and browser storage
wiping are best effort.

Recovery uses an exported recovery code. Using recovery revokes all device
keys and all active web sessions. The recovery code is single-use and must be
replaced after successful recovery. Existing devices must be enrolled again.

### Teams and revocation limits

Team content uses team-specific keys. Membership changes rotate keys for future
content and re-wrap them for the remaining members. Removed members cannot
decrypt new content after revocation.

Previously downloaded plaintext cannot be recalled. This is an inherent limit
of end-to-end encryption and is treated as best-effort revocation.

Team roles are owner, admin, editor, commenter, and viewer. The server
enforces membership and operation authorization without decrypting content.

## 5. Storage architecture

Use SQLite for metadata and an encrypted filesystem blob store for content.
The instance owns one configurable data directory containing the database,
encrypted blobs, key envelopes, sessions, audit records, and configuration.

The directory can be copied locally with the server stopped. Sealed disaster-recovery
capsules snapshot the live SQLite handle and include effective deployment secrets,
recovery public key, configuration and blob inventory. `ky-primitives/recoveryclient`
owns sealing, pairing, destinations, retention and scheduling. The product validates
restored table counts, keys and inventory and revokes restored sessions. Blob payloads
(note-version and attachment ciphertext) require separate mirroring and restoration.
A database-only restore does not establish that content is recoverable.

The blob store should be content-addressed by the encrypted blob digest. This
supports deduplication, immutable versions, and garbage collection after
metadata deletion.

The server must not log plaintext, keys, recovery codes, pairing codes, or
full encrypted payloads. Logs may contain opaque IDs, operation types, and
timings.

## 6. Synchronization

All sync traffic uses HTTPS. The initial transport is ordinary request/response
API calls. Clients may use push notifications or short polling to learn that
changes are available, then pull ciphertext over HTTPS.

Each mutable object has a monotonically increasing server version. A client
save includes the version from which it was edited:

1. The server compares the supplied base version with the current version.
2. If they match, the encrypted update is stored as the next version.
3. If they differ, the update is rejected with a conflict response.
4. The rejected encrypted upload is preserved for manual client-side review.

There is no automatic merge. Clients can decrypt both versions and let the
user copy or replace content. This same rule applies to notes, folders,
Markdown task changes, and container metadata where practical.

Clients maintain local encrypted stores and indexes. Full-text search is
performed locally after decryption; the server does not search note content.

## 7. Collaboration and activity history

Collaboration supports invitations, membership management, roles, comments,
mentions, presence, notifications, and activity history after core sync.

Activity records contain server-visible routing fields such as container ID,
actor ID, event type, and timestamp. Event details are encrypted so only
authorized members can read them.

Presence is ephemeral and contains no note content. Notifications identify
the affected container or object without including plaintext.

## 8. Publishing

Public Sites are deferred. The initial release does not publish content or
expose plaintext through the server. A future publishing feature may let the
client decrypt selected content and explicitly upload a separate public export.

## 9. API boundaries

The API should be organized around these resource groups:

- Authentication and sessions.
- Device pairing, enrollment, listing, and revocation.
- Container and membership metadata.
- Key-envelope installation and retrieval.
- Encrypted object upload, download, version listing, and conflict retrieval.
- Attachment upload sessions, chunk upload, download, digest lookup, and
  garbage collection.
- Change notification and pull cursors.
- Team invitations, roles, comments, mentions, and activity records.
- Push registration and pull fallback.

Authenticated endpoints must distinguish web sessions from device credentials.
Operations that mint or destroy key envelopes require a web session and any
required step-up authentication. A paired device may retrieve only the
envelope sealed for that device.

## 10. Deployment and operations

The server runs in Docker behind a reverse proxy that terminates HTTPS.
Configuration is provided through environment variables or a mounted config
file. Secrets must not be stored in the content database.

Self-hosting requirements:

- One data directory for all durable state.
- Stop-before-copy backup procedure.
- Restore and integrity-check command.
- Configurable per-user and per-team quotas.
- Default 25 MB maximum attachment size.
- Audit records for authentication, device enrollment/revocation, sharing,
  recovery, and administrative changes.
- Rate limits for login, pairing, uploads, and notifications.

Administrators may manage users, quotas, backups, and audit access, but cannot
decrypt user content.

## 11. Verification strategy

The Go server requires unit and integration tests for:

- Authentication and session revocation.
- Pairing-token expiry, single use, and rate limiting.
- Device enrollment and device revocation.
- Recovery-code use and global device/session revocation.
- Key-envelope authorization and container membership changes.
- Version checks and conflict preservation.
- Attachment size limits, digest deduplication, and encrypted blob storage.
- Sync cursors, retry behavior, and offline catch-up.
- Team role enforcement and key rotation metadata.
- Backup/restore integrity.

Clients require interoperability tests against the Go API, including QR
enrollment, encrypted object round trips, offline edits, rejected versions,
task front matter, resumable attachment uploads, lazy downloads, and cleanup.

Security tests must verify that server logs, API responses, SQLite records,
blobs, backups, and notifications contain no private plaintext or private
keys.

Capsule export is an admin/step-up/CSRF-protected POST, because snapshotting and sealing
are expensive audited operations. Read-only backup status remains GET. Failed runs count
toward the schedule interval; the pinned recovery client records attempts before preconditions.

## 12. Delivery phases

### Phase 1: secure core

Authentication, web sessions, device enrollment, encrypted workbooks,
folders, Markdown notes, attachments, versioned sync, offline pull/push, and
backup/restore.

### Phase 2: organization

Personal inboxes, personal workbooks, projects, task views, task metadata,
and push notifications.

### Phase 3: teams

Team membership, roles, encrypted sharing, key rotation, comments, mentions,
presence, activity history, and collaboration notifications.

### Later work

Templates, web clipping, freehand drawing, richer media workflows, public
publishing, and desktop clients.

## Ciphertext mirror extension (Myslop #290)

`internal/mirror` uses the nested `github.com/Busness-app/ky-primitives/offsite@v0.1.0`
module for file, S3, pinned SFTP and SMB transports. It streams all note-version and
attachment blobs, stores success acknowledgements in migration 0015, and fetches against
the restored database inventory. Credentials live in protected config and encrypted
capsules, never status/audits. Manual and scheduled capsule runs preserve independent
capsule/mirror results and pass snapshot inventory through possible concurrent GC.
`POST /api/v1/admin/backup/mirror` requires admin, step-up and CSRF; status includes
redacted mirror coverage. Offline mirror/fetch share the server directory lock.
No frozen crypto format, capsule v1 recipe, or product upload limit changes. Remote
history is retained; full restore is capsule, fetch-blobs, consistency-check, browser proof.

OIDC login admission is limited per client IP across route aliases. Pending transactions
are bounded with oldest-expiry eviction; capacity does not globally refuse new logins,
and eviction invalidates only that pending callback. CLI server mode rejects positional
commands after explicit subcommand dispatch, including the removed plaintext `backup` name.

IP-keyed rate limits resolve forwarded client identity only behind configured trusted
proxies, using the right-most untrusted X-Forwarded-For address. Untrusted senders and
malformed suffixes fall back to socket identity. Session-keyed limits remain user-keyed.

## SSO lifecycle extension (issue 13, first stage)

Migration 0016 binds users to issuer/subject and SSO browser sessions to
issuer/client/subject/sid and verified ID-token issuance time. The shared
`oidcverify@v0.7.0` verifier handles signed logout tokens at
`POST /api/v1/auth/oidc/backchannel-logout`. Durable replay admission, callback
fencing, scoped revocation and audit share one SQLite writer transaction.
Callbacks recheck their original five-minute deadline, active account and current
SSO configuration under that lock before committing a session and its audit.
Subject-wide logout preserves sessions issued after logout; exact sid logout
never widens to unrelated sessions. A token carrying both sid and subject also
covers older sid-less sessions for that subject, with the same issuance cutoff
and a mirrored callback fence. Session-aware issuers must supply a sid.
Verified tokens bypass the IP abuse bucket; malformed/unverifiable traffic alone
consumes it. Logout audits retain the JWT ID and actual session/device counts.
Key failures retry a changed discovery JWKS URI, with discovery attempts bounded
to once per minute per configured issuer/client.

Device pairing tokens carry their authorizing session. Devices paired through
SSO require that parent session on every authenticated request, so logout,
expiry and configuration revocation cannot leave a derived credential active.
Existing linked-account credentials have no reliable origin and are revoked
once on upgrade; ciphertext and wrapped-key envelopes survive, and users re-pair
without replacing encryption keys. Independent local authentication remains
available. Issuer/client changes or disabling SSO revoke bound sessions and
commit their audit atomically. Identity lookup and trusted legacy directory
linking are issuer-scoped.

This extends the frozen schema and pairing token with origin metadata; it does
not change client cryptography. See `docs/SSO.md` for the operator contract,
upgrade effects, replay response semantics and the remaining directory/role/
reauthentication stages. Live deployment acceptance is still required.
