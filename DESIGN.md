# KyNotes Server Design

## 1. Purpose

KyNotes is a self-hosted, zero-knowledge note service. It stores encrypted
structured note documents and encrypted attachments, synchronizes them between trusted
clients, and supports small teams of fewer than 20 people.

The server is a Go application distributed in a Docker container. It stores
metadata and ciphertext, but it must never need plaintext note content,
attachment content, or private encryption keys.

The public `GET /healthz` returns cached `ky.health/1` dependency health for
startup readiness and SQLite connectivity: 200 when both pass, 503 otherwise.
Responses contain fixed check names and statuses, without error details or
user data. `GET /livez` retains the alive-only response; `GET /readyz` retains
its existing startup-readiness response.

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

Templates, web clipping, rich media editing, and desktop
clients are designed as later phases unless required by the client teams.

## 3. Product model

### Containers

- A **Workbook** is a personal top-level encrypted container for folders,
  notes, tasks, and attachments.
- A **Project** is a separate top-level container. It may contain notes, task
  data, folders, and attachments.
- A **Section** is an encrypted `folder` object inside a workbook. Its payload
  `{type:"section", title, color, order, group?}` is ciphertext; the server sees only the kind.
- A **Section group** is also an encrypted `folder` object, payload
  `{type:"group", title, color, order, group?}`; a section's or group's optional `group` names
  its parent group. Groups nest at most 4 deep. A missing parent, a cycle or a chain past the
  cap shows the item at the notebook root, without writing anything; deleting a group first
  moves its sections and groups up one level.
- A **Page** is an encrypted `note` object. Its payload carries `section` (a section
  object ID), a fractional `order` key and an optional subpage `level` (0-2; missing is 0). The
  client displays each page at most one level below the page before it, never below a page
  from a different stored section (Quick Notes orphans of a deleted section), and writes `level` only
  when a page is indented, outdented or moved, so each page owns its placement and no shared
  manifest is written. Pages without a live section appear in the client's virtual
  Quick Notes section; deleting a section never deletes pages. The first reorder of a
  section that holds legacy unordered pages renumbers every page in it: a one-time burst of
  writes, which other open devices may see as one conflict and from which the server can
  infer that those objects share a list.
- A **Team** is a membership and key-management container. Teams contain
  shared projects and shared notes.
Each container has its own encryption key and explicit device sync selection.

### Notes and tasks

Notes are versioned structured documents edited in the client. Markdown and
HTML are import/export formats only; the encrypted note payload is a versioned
editor document so formatting, images, and comment anchors do not depend on
re-parsing text.

Every new or edited page body is `kynotes.canvas.v1`: positioned rich-text boxes
(BlockNote block arrays) plus ink strokes as flat `[x, y, pressure]` arrays, all inside
the object ciphertext. Older BlockNote, Tiptap and Markdown bodies open as one box at the
origin and are rewritten only when edited. Clients clamp and cap decoded canvas input and
refuse new ink past 9 MiB of serialized body. Decrypted images display from `blob:`
URLs, so the server CSP allows `img-src 'self' data: blob:`.

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
ID and resource revision admitted in the same SQLite transaction as account changes,
credential revocation and audit. Failed applications can retry; identical deliveries
acknowledge the committed revision without repeating account changes.

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

Each user also holds an X25519 identity keypair, represented on the server as a
`devices` row with `platform = 'identity'` and an unusable `secret_hash`. Its
private key is wrapped (AES-256-GCM, AAD `kynotes/identity/v1` || user ID) under
a `userKEK` that the browser derives from the same PBKDF2 output as the login
verifier, with HKDF label `kynotes/user-kek/v1`. The server stores only the
wrapped key and never sees `userKEK`. The wrapped key is returned only in the
bodies of local password login and step-up, never by `GET /me/identity`, so a
session cookie alone yields no offline-guessing target. The browser caches it
in the IndexedDB vault with the other device secrets; "Forget this device"
clears it, and logout keeps it. In secure contexts the vault stores the private key
encrypted under a non-extractable WebCrypto key kept in the same record; that is not
at-rest protection (browsers write the key's bytes into the same profile and page script
can call `decrypt`), it only keeps the raw key out of the record's plain values. On
plain-HTTP origins the key is stored unwrapped and Settings says so (an interim that awaits
Yoshi's decision: refusing to keep it there is the more secure default); without IndexedDB
the browser holds no identity. "Forget this device" keeps the encrypted save queue. Identity rows never authenticate as a device,
are not listed, revoked or selected through device routes or directory
deactivation and role changes, and are excluded from the device-envelope save
gate. No password-wrapped identity is created while someone other than the
user knows the password (`users.password_admin_known`: admin create and reset,
bootstrap, `user add`), and no local password step-up admits an identity action
(identity creation, envelope writes, rotations, invitation keys; `409
password_change_required`), so that password never acts for an SSO user's
device-only identity. The user's own password change or recovery clears the
flag, and the browser then creates the identity under the new password. On an
account that signs in through KySignOn, changing a password an administrator set
also needs a KySignOn confirmation of that request, so the administrator cannot
clear the flag by changing the password. A local-only account has no second proof:
until its user changes the password, whoever set it can act as the user. That is
an accepted residual of administrator-set passwords. The change revokes every
other session and device credential of the account in the same transaction. Envelopes are
`0x02 | senderDeviceID | ephPub | nonce | ChaCha20-Poly1305(CK)` (123 bytes),
keyed by both an ephemeral and the sender identity's X25519 agreement and bound
by AAD to container, key generation, recipient and sender (IDs in the AAD are
fixed-length); `testdata/protocol/envelope_vectors.json` pins the bytes. A
browser accepts an envelope from its own identity, from a current owner or
admin whose identity key matches its local trust-on-first-use pin, or, for
history below the device's high-water mark, from an identity already pinned
(see below), and reads rows at or above `shared_generation` only with that
generation's key. A password change
re-wraps the identity in the same transaction. Recovery and administrator
password resets remove only its password copy and write an audit row (an administrator
reset also revokes paired device credentials): another
browser or the recovery code still restores it, and nothing re-wraps it under the
new password until the user's own password change re-adds the copy from a browser
that holds the identity (not on an account linked to KySignOn). Only the user deletes an identity: the self-service reset, behind a
user-action step-up and a compare-and-swap on the identity the browser saw, swaps
it in one transaction for a new one with a new recovery copy (and, for a password
account, a new password copy, as on a first identity; an account linked to KySignOn
never gets one, from any session), deletes the old envelopes,
copies and link requests, and revokes the account's other sessions and paired
device credentials with their envelopes. It refuses the old identity's own key. Personal
notebooks are then lost, and stewards re-share team keys. An SSO session creates a
device-only identity (`wrap_alg = none`) after a KySignOn confirmation of the
request; no password copy exists on the server, and other
browsers receive it by device linking. A password never unlocks or re-wraps it.
Every account may also keep a recovery-code copy: the identity private key sealed
in the browser under a key derived (PBKDF2-SHA256, 600 000 iterations) from a
one-time 128-bit code the browser shows once. The server stores the copy, never
the code. It hands the copy only to a session of the same account behind a
user-action step-up (for an SSO browser holding nothing, a KySignOn confirmation
of that request), audits each fetch and rate-limits it, and answers the same 404
whether the account has no identity or no copy. A new code replaces the copy by
compare-and-swap, so the old code opens nothing on the live database. The code
is 128 random bits written as 28 Crockford base32 symbols with a 10-bit
checksum; `testdata/protocol/recovery_vectors.json` pins the format.

An owner or admin mints a container's content key for each key generation
through `POST /containers/{id}/key-rotations`. In one transaction it advances
the generation and installs envelopes for the caller and every active member
identity. Envelopes are insert-only per container, generation and recipient.
The one exception is a member's own identity envelope, which that member may
re-wrap but never write first: a steward or an accepted invitation supplies
it. Recipients must be live devices or identities of active members. Any member
may write envelopes for its own paired devices; owners and admins may write for
any member. Envelope writes and rotations need a fresh step-up: a password re-proof for
local sessions, a KySignOn confirmation of the exact request for SSO sessions. A container has no key until its first rotation (`containers.shared_generation`, the first keyed generation); until then it takes no content, name or envelope, and it is created without a name. Afterwards a write needs the writer's own identity to hold an envelope at the current generation. Both gates also need a live membership, and
the write transaction checks them again. Object saves also recheck the writer's
role there; comment and attachment writes recheck only the gate.

The web client seals and opens every container's content only with its container keys; no content key
derives from the login secret. A notebook gets its first key when it is created (team keys P5; a
notebook whose first key was never minted is read-only until its owner's next open mints it, and only
once the owner's identity is recoverable: a password copy or a recovery-code copy exists). A row opens
only with the key of its own generation, at or above the container's first keyed generation
(`sharedGeneration`); a missing, malformed or older generation gets no key, so it
fails closed. A member without the current key
cannot change anything there: pages, sections, groups, moves, deletes,
comments, attachments and conflict copies are disabled and their handlers refuse, so no
empty object is created. Edits already in progress when the key went missing
wait in the encrypted local queue at generation 0, sealed with a key derived from the identity (HKDF label `kynotes/waiting/v1`), are never
uploaded at that generation, and are resealed under the current key when keys arrive. Every content write and name change carries `X-Kynotes-Key-Scheme: shared-v2`; a tab from an older build is refused and told to reload. A container meta `PATCH` must carry
`keyGeneration` equal to the current generation; a missing, zero, old or future
value is refused inside the transaction with `409 already_exists`, so a stale
tab cannot seal a name under a retired key. The same transaction checks the
caller's live writer role and updates only at the request's `baseVersion`; a
stale base is `409 version_conflict`, so concurrent renames never overwrite
each other. Conflict listings report each
copy's `keyGeneration`. Owners and admins mint keys only through rotation;
envelope `PUT` may add a member to any shared generation that already has
envelopes (history for newcomers) and never mints one. Envelopes are v2 and sender-authenticated:
a browser accepts a key only from its own identity, from a current owner or
admin whose identity matches its pin, or from a pinned identity for a
generation below the device's high-water mark. The first key per generation
wins, its SHA-256 is stored add-only on the device, and a different key for
that generation is a refused conflict. Pins are trust-on-first-use and
add-only: replacing one needs an explicit confirmation showing both
fingerprints, and a decline is remembered for the session, per member and key.
A pin write that conflicts with a pin another pass stored meanwhile writes
nothing and stops that pass before any envelope is uploaded. Each device also
keeps, add-only per container, the highest `sharedGeneration` and
`keyGeneration` the server ever reported; key choices use the higher shared
generation, and a lower report pauses writes ("The server reported an older key
state for this notebook than this device has seen"), so a server cannot roll a
shared notebook back to an older generation. This applies to
every container. Relabelling a notebook as personal or team changes nothing, because `kind` and `teamId` never decide keys. A team's first key is minted for every member with an identity; members without one are wrapped by a later sweep.

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

### Device linking

A browser that does not hold the account's identity asks a trusted browser of the same account
for it. The server relays only public keys and one sealed bundle (`/api/v1/me/link-requests`,
migration `0024_device_linking.sql`). The newcomer first posts a commitment to its one-time
X25519 key; the trusted browser claims the request with its own one-time key; the newcomer then
reveals its key, which must match the commitment. Both screens show a six-digit check code over the
account, the request and both keys. The newcomer confirms its code; the approver types the
code shown on the newcomer's screen, so a click cannot replace the comparison. The newcomer pins
the approver's key before it reveals its own, and a failed reveal ends the attempt. The commitment means a relay
cannot pick a key to fit the code after seeing the other one. Only then is the identity private key
sealed to the newcomer (`kynotes/link/v1`, `testdata/protocol/link_vectors.json`), after a fresh
step-up, and collected once (a CSRF-protected `POST …/collect` the newcomer polls). Requests are per user, single use, expire after ten minutes (checked in the step's transaction), need a
live session of that user on both sides, are rate-limited (creation with device pairing, collect polls
by `ratelimit.link_poll_per_minute`) and are audited, except collect misses. Relay success
without the user's help is about 10^-6 per visible attempt.
Recovery, an administrator reset and the self-service reset delete the account's open link requests
in the same transaction.

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
keys and all active web sessions, and removes the password copy of the user's identity key; the
identity, its envelopes and its recovery-code copy stay. The recovery code is single-use and must be
replaced after successful recovery. Existing devices must be enrolled again.

### Teams and revocation limits

Team content uses team-specific keys. Membership changes rotate keys for future
content and re-wrap them for the remaining members. Removed members cannot
decrypt new content after revocation. Removing a member, whether by a team
owner or admin or by a server administrator, revokes the team and child-workspace
memberships, advances their key generations, deletes the member's envelopes and
device selections there, and deletes the pending invitations that member issued.
A steward then rotates to a new key for the remaining members. An invitation may
carry envelopes for the invitee's identity; creating it then needs a local
password step-up; invitations from SSO sessions carry no envelopes. They are installed when the
invitation is accepted, only while the generation is unchanged and the inviter
is still an owner or admin of the live container. Accepting checks the invitation's invitee and expiry inside that transaction. Removing a member deletes pending invitations addressed to them, and accepting is audited. A member who was removed is admitted again by reactivating their revoked membership, with the new role and no keys. A team admin may remove another admin only when its own invitation admitted that admin's current membership; owners and server administrators may remove any non-owner. Invitation creation is rate-limited per account. Envelopes of expired invitations are deleted by the periodic garbage collection.

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

Templates, web clipping, richer media workflows, public
publishing, and desktop clients.

## Ciphertext mirror extension (Myslop #290)

`internal/mirror` uses the nested `github.com/Busnes-app/ky-primitives/offsite@v0.1.0`
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
to once per minute per configured issuer/client. Already-cancelled calls do not
start shared work. Admitted login/logout metadata verification detaches caller
cancellation under a 30-second budget, preserving cache fills on disconnect;
session issuance and logout revocation retain the original request context.

Device pairing tokens carry their authorizing session. Devices paired through
SSO require that parent session on every authenticated request, so logout,
expiry and configuration revocation cannot leave a derived credential active.
Existing linked-account credentials have no reliable origin and are revoked
once on upgrade; ciphertext and wrapped-key envelopes survive, and users re-pair
without replacing encryption keys. Independent local authentication remains
available. Issuer/client changes or disabling SSO revoke bound sessions and
commit their audit atomically. Identity lookup and trusted directory
linking are issuer-scoped.

This extends the frozen schema and pairing token with origin metadata; it does
not change client cryptography. See `docs/SSO.md` for the operator contract,
upgrade effects, replay response semantics and the implemented role/
reauthentication stages. Live deployment acceptance is still required.

## Versioned directory extension (issue 13, second stage)

Migration 0017 retains the highest applied revision and signed-body digest per
issuer/subject independently of the local user row. The signed bare SCIM User
receiver accepts `user.created`, `user.updated` and inactive `user.deleted`, with
`meta.version` formatted as `W/"N"` for a positive signed 64-bit integer. The
legacy unversioned envelope and batch resync are refused. Resync uses versioned
per-user events. Exact same-version/type/body retries return 200 without another
mutation; stale or conflicting revisions and reused event IDs return 422.

Inactive delivery disables a matching account and permanently revokes all its
current sessions/device credentials, including locally authenticated ones, in the
same transaction as revision, replay and audit. It preserves the user, ciphertext,
memberships and wrapped keys. Existing share links remain valid until expiry or
separate revocation; deactivation does not revoke them. An unknown inactive subject
needs only a tombstone.
SQL triggers prevent local activation or OIDC auto-provisioning through a retained
inactive tombstone. A higher active revision permits a fresh login; it never
clears credential revocation. Directory role sets explicitly replace the local account role; only the app role
`kynotes.admin` maps to admin, and every other set maps to user. Trusted directory
provisioning retains its explicit authority to link an unbound local username.

`POST /api/v1/sync/readback` authenticates a signed `user.readback` request whose
body names the subject. Signing the purpose and subject prevents cross-route or
cross-subject reuse because syncauth does not sign the URL. The audited response
reports actual local presence/activity and the last applied version from one
transaction; its audit identifies the probed subject and signed event ID. The
KySignOn suite sender currently reports readback unsupported;
this receiver endpoint requires a future sender adapter or signed operator probe.
See `docs/SSO.md` for wire fields, upgrade and acknowledgment limits. Client
cryptography and the implemented role/reauthentication stages and remaining live acceptance gates
are unchanged.

Directory deactivation also retains a per-identity login-proof cutoff. Session
admission rejects ID tokens issued at or before that cutoff even after a higher
active revision, preventing a pending callback from reviving access. Issuance
and disablement in the same second are conservatively ordered as disabled;
restart login in a later second. The cutoff and session admission serialize with
account/revision changes under SQLite's writer lock.

## Application-role extension (issue 13)

Migration 0018 adds `sessions.sso_app_admin`, removes legacy linked-account admin
roles without guessing provenance, and ends old SSO sessions once, with per-subject
upgrade audit. Unlinked local admins and ciphertext survive. OIDC validates the
plural roles array, ignores singular/global role, and never elevates an account
at auto-provision. `auth.SessionRole` intersects local account permission with the
verified OIDC ceiling for every SSO admin guard and session response. Local password
sessions use the local role. An explicit local grant can supply account permission
for OIDC-only deployments; otherwise versioned directory provisioning supplies it.

The fixed `kynotes.admin` role cannot collide with the sender's legacy SCIM global
admin/user fallback. Every role transition clears existing session/device credentials
and advances the persisted login-proof cutoff, in the same writer transaction as
role replacement, revision and attributed audit. Re-grants do not revive old proofs.
Readback includes the actual local role. Client encryption and workspace membership
roles are unaffected. See `docs/SSO.md` for setup, upgrade and the remaining fresh
OIDC authorization stage.

### SSO last-administrator recovery grant

Active directory-role demotion preserves the last active administrator's local
account grant, and migration 0018 preserves active linked grants when no unlinked
active administrator exists. These exceptions are audited as `admin_retained=true`.
Runtime retention revokes sessions/devices; the upgrade revokes old SSO sessions.
Neither bypasses the verified `kynotes.admin` OIDC session ceiling. Deactivation remains authoritative, including for the last admin.
Keep an unlinked local administrator available for recovery; see [SSO roles](docs/SSO.md#application-roles).

## Action-bound OIDC step-up

Backup/recovery step-up routes, local user creation and password reset require a one-use OIDC proof for SSO
sessions. A `user`-scope challenge (`sso_stepup.scope`, migration 0024) proves only the session's own
account, bound to the action and body (64 KiB at most), with a fresh `auth_time`; it covers identity creation,
envelope writes, rotations and changing an administrator-set password on an SSO-linked account. A grant opens
only its own scope, and challenge creation is rate-limited per account. Migration 0019 binds the exact request digest to the original session;
fresh signed auth_time and ordinary assurance, identity and app-admin permission
are required. Issuance time is never substituted for authentication time. Creation,
verification, cancellation and consumption are audited atomically. Admission
rechecks parent-session and fresh-proof revocation and consumes before the operation;
a subsequent logout cannot undo an admitted operation. Local-password sessions keep
the existing password proof window. Other admin routes retain existing guards.
The browser retains the request only in memory while a separate sign-in window
completes the proof. See [SSO authorization](docs/SSO.md#fresh-authorization-for-backup-and-recovery-actions)
for freshness, expiry, cancellation, restart and live-acceptance limits.
