# SSO sessions, logout and directory provisioning

KyNotes verifies ID tokens and logout tokens with `ky-primitives/oidcverify@v0.7.0`.
Accounts bind to the exact issuer and subject. A matching username alone never
allows an OIDC callback to take over an existing account.

## Configuration

Configure the issuer, client ID, client secret and callback URL in the existing
administrator SSO settings, or use KySignOn pairing. Register these HTTPS URLs
for the KyNotes client at the issuer (replace `notes.example.com`):

- Login callback: `https://notes.example.com/api/v1/auth/oidc/callback`
- Back-channel logout: `https://notes.example.com/api/v1/auth/oidc/backchannel-logout`

Register the back-channel URI in KySignOn's client settings. KySignOn advertises
session support in discovery; KyNotes then requires a
nonempty `sid` in every verified ID token. Other OIDC providers that do not
advertise session support may use subject-wide logout.

The receiver accepts only a POST with `application/x-www-form-urlencoded` and one
body field named `logout_token`. The request body is limited to 64 KiB. Browser
cookies, CSRF tokens and query-string tokens do not authorize this endpoint.
Only malformed or unverifiable requests consume a per-IP abuse bucket using
`LoginPerMinute`; excess failures return 429. Verified logout tokens bypass that
bucket, including bursts from an issuer sharing a proxy address with bad traffic.
Trusted-proxy settings still select the failure bucket.
Responses are `no-store`.

## Revocation behavior

The shared verifier requires `logout+jwt`, RS256, the configured issuer and
client audience, valid bounded timestamps, an event object, a JWT ID, and a
subject or session ID. A logout token cannot authenticate a login. Tokens with
`nonce` or `token_use`, including null values, are rejected.

KyNotes commits replay admission, callback fencing, session/device revocation
and `auth.sso_logout` audit together. An audit failure rolls everything back.
A session ID selects only that issuer/client/session; a supplied subject must
also match. When both are supplied, older sessions without a stored `sid` are
also revoked if their subject matches and they predate the logout. The mirrored
callback fence covers those sessions too; a sid-only token cannot widen scope.
A subject without a session ID ends that subject's SSO sessions
issued at or before the logout's `iat`. A later login remains usable; timestamps
in the same second are conservatively treated as preceding logout.

A valid unmatched logout succeeds with HTTP 200, including when logout arrives
before the callback creates a session. The durable fence then blocks that
pending callback. Replays return 400. Invalid requests return 400 (oversized
bodies return 413); persistence failures return 500 and can be retried. A sender
that lost the first success response may receive 400 for its already-applied
retry. The `auth.sso_logout` audit records the verified JWT ID in `object_id`
and `sessions=N,devices=N` in `reason_code`, including zero matches. Match that
JWT ID to resolve delivery ambiguity; the raw token is never stored in audit.

Replay records survive restart and are retained through both token validity and
the five-minute callback lifetime. Callback expiry is checked under the same
SQLite writer lock as logout, with cookies emitted only after session and login
audit commit. New logout requests prune expired replay records.

Key-resolution or signature failures trigger a discovery recheck and retry when
`jwks_uri` changed. Discovery refresh, including failed fetches, is limited to
once per minute per configured issuer/client, so junk tokens cannot cause a
fetch on every request. During that bounded interval a changed endpoint may need
a later delivery retry; existing verified keys remain usable. Already-cancelled
verification calls do not start shared metadata work. Admitted login/logout
verification uses a caller-independent 30-second budget (with the existing
10-second HTTP timeouts), so disconnects cannot consume discovery/JWKS cooldowns
without completing the fetch. Session issuance and logout revocation still use
the original request context.

Devices paired through SSO carry their authorizing local session ID. Their
credentials require that session to remain live, owned by the same user, and
unexpired. Logout and pending device enrollment serialize; a completed enrollment
cannot bypass a logout that commits afterward. Re-pairing the same public key
rotates its authentication secret and preserves existing wrapped-key envelopes.
Normal local logout, SSO configuration revocation and parent-session expiry also
end derived-device authorization. A device must re-pair after its parent login
ends. Local password sessions and devices independently paired through them
are unaffected by upstream SSO logout.

Changing the configured issuer/client or disabling SSO revokes existing bound
SSO sessions with an atomic `auth.sso_configuration` audit. The receiver still
accepts valid outstanding logout tokens while new SSO logins are disabled.
An issuer change never rebinds an existing linked user to the new issuer by name.

## Upgrade

Migration 0016 backfills each linked account's issuer from the existing SSO
configuration. Because older sessions and devices did not record their login
origin, it revokes **all existing sessions and device credentials belonging to
linked accounts**, including credentials originally obtained locally. Linked
users must sign in and pair devices again. A pre-upgrade pairing token without
an authorizing session cannot enroll a device for a linked account.

The migration preserves users, encrypted notes, ciphertext metadata and wrapped
keys, records `auth.sso_upgrade`, and does not repeat revocation on later starts.
Unlinked local accounts retain their credentials. Duplicate preexisting
issuer/subject identities fail the unique-index migration; resolve the duplicate
identity deliberately before retrying, without deleting encrypted user data.
If the old issuer setting is missing, linked users remain unbound to any new
issuer and cannot sign in through OIDC until their identity is reconciled.

## Versioned directory provisioning

Configure the paired-system callback as
`https://notes.example.com/api/v1/sync/events`. The `/api/sync/events` and
`/sync/events` aliases use the same verification and transaction. The paired
HMAC secret and a nonempty exact issuer must be configured. Directory delivery
continues when interactive SSO is disabled, so pending revocations can finish.

Send POST with a bare SCIM User and the four `syncauth` headers:
`X-KySignOn-Signature`, `X-KySignOn-Timestamp`, `X-KySignOn-Event-Type`, and
`X-KySignOn-Event-ID`. The secret is never an Authorization credential.
The library authenticates body, timestamp, event type and ID within its five-minute
window. KySignOn emits this resource shape:

```json
{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"subject-id","externalId":"subject-id","userName":"alice","active":true,"roles":[],"meta":{"resourceType":"User","version":"W/\"12\""}}
```

The schema must be exactly the User schema, externalId must equal id, and active
must be an explicit boolean. IDs and usernames are bounded to 256 bytes with no
control/format characters or surrounding whitespace. Active users require a
username; inactive resources may omit it. Version is a canonical positive signed
64-bit integer weak ETag. Supported event types are `user.created`,
`user.updated`, and `user.deleted`; deletion must carry `active:false`.
Other events, including `user.mfa_reset`, and unversioned legacy envelopes/batch
resyncs return 400. KySignOn resync sends individual versioned user events.
Extra profile fields are accepted. `roles` accepts string entries or SCIM objects
with a string `value`; only exact `kynotes.admin` requests local administration for
active accounts. Other names, absent roles and unfamiliar shapes request user
permission. Global `admin` and `user` never grant administration. Inactive events
ignore roles entirely. The last-active-admin retention exception is described under
Application roles below.

A 200 `status:applied` acknowledges that the revision, signed-body digest, replay
record, account changes, credential revocation and `directory.apply` audit have
committed. Each apply audit retains the affected subject in `object_id`, with
revision, active state, mapped role and signed event ID in `reason_code`; later resource
updates and replay pruning do not erase that attribution. It does not acknowledge
client data erasure or live suite acceptance. A same-version, identical event type and body returns 200
`status:already_applied`, including a re-signed delivery with a new event ID;
it never repeats the mutation. This acknowledges historical application, not
current account state after a local administrator's later edit. The version
fence survives replay expiry, process restart and local account deletion.

Stale revisions, differing content at the same revision, reused event IDs with
changed contents, and a configuration change during admission return 422.
The sender treats create/409 as successful, so 409 cannot express these failures.
A database/audit failure returns 500 and leaves the event retryable. The sender
may retain an uncertainty fence after losing a response or seeing 500; follow its
operator recovery process instead of assuming this endpoint automatically clears
that fence. Exact replay means identical body bytes, including ignored profile
fields and formatting; a changed resource needs a higher version.

Disablement and deletion preserve the user row, ciphertext, memberships and
wrapped keys. They revoke all current sessions and device credentials, including
those originally obtained with a local password. Re-enabling requires a higher
active revision and fresh login/device pairing; it never revives those credentials.
Unknown inactive subjects retain a tombstone without creating a user. Local
status edits and OIDC auto-provisioning cannot override an inactive tombstone.
Previously issued share links remain valid until expiry or separate revocation;
directory deactivation does not revoke them. These links continue to provide
server-mediated access to their ciphertext. Downloaded plaintext and client-held
keys cannot be recalled by the server.

Directory deactivation also retains a per-identity login-proof cutoff. Session
admission rejects ID tokens issued at or before that cutoff even after a higher
active revision, preventing a pending callback from reviving access. Issuance
and disablement in the same second are conservatively ordered as disabled;
restart login in a later second. The cutoff and session admission serialize with
account/revision changes under SQLite's writer lock.

### Directory readback

POST `/api/v1/sync/readback` with body `{"subject":"subject-id"}`, a fresh event
ID, and event type `user.readback`, signed using the same paired secret. Body and
purpose must be signed because syncauth does not bind method or URL. Mutation
signatures cannot authorize a readback and readback signatures cannot mutate users.

The no-store response reports `subject`, `present`, `active`, local account `role` and `version` from
one audited transaction. The `directory.readback` audit records the probed subject
in `object_id` and the signed event ID in `reason_code`. Version is empty when no versioned event has applied;
a deleted local account may report absent with a retained version. Missing and
inactive accounts never imply ciphertext deletion. Invalid signatures return 401,
malformed probes 400, and unavailable audit/storage 500 without an observation.
Read-only probes may be repeated within their signature window. The current
KySignOn suite sender does **not** call this endpoint: its readback remains
unsupported until an adapter is added. A signed operator probe can inspect state;
no test fixture or probe automatically satisfies a live reconciliation gate.

### Directory upgrade

Migration 0017 preserves existing accounts and adds revision fences without
inventing old delivery revisions. Stop old/unversioned senders before upgrading;
then use the released versioned sender and reconcile current assignments. Old
signed envelopes are refused rather than permitted to bypass ordering. Never
reset the sender revision sequence or delete receiver fences to repair a retry.
Restoring an older receiver database also restores older fences: keep delivery
quiescent and use the suite's restore/reconciliation procedure before resuming.

## Application roles

KyNotes recognizes the fixed application role `kynotes.admin`. Configure this role
on the KySignOn app that owns the KyNotes OIDC client and provisioning connection,
and assign it explicitly to the intended users or groups. Link those connections
before configuring roles/assignments, as required by KySignOn's app registry.
Then resync users and sign in again. Turn off the app's legacy global `role` claim
after verifying the migration. A KySignOn global administrator receives no automatic
KyNotes administration. The distinct role name also prevents SCIM's legacy global
`admin` fallback from granting product access when upstream app roles are removed.

OIDC login reads the signed, issuer/client-bound `roles` array. Both string entries
and SCIM objects with a string `value` are recognized; only exact `kynotes.admin`
grants the session ceiling. Unrelated names, unfamiliar entries, missing roles and
wrong-shaped role data grant nothing and do not prevent ordinary login. The old
singular `role` claim is ignored. Automatic account creation starts as a local user.
Directory events use the same role interpretation; deactivation ignores roles entirely.

SSO administration requires **both** local account permission and `kynotes.admin`
in that session's verified ID token. Directory provisioning normally sets the local
permission; a local administrator can also deliberately edit it using the existing
user-management route. An OIDC claim alone does not grant a local role. OIDC-only
installations therefore need an explicit local grant as well as the app-role claim.
Every admin request and the session response use the same intersection. Existing
ordinary SSO sessions cannot acquire admin rights from a later local role edit or
another login. Local password sessions use the local account role.

Versioned directory role changes normally replace the local role, revoke all existing
sessions/device credentials, and advance the login-proof cutoff in the same
transaction as the attributed audit. Both promotion and demotion require fresh
login/device pairing, and a later re-grant cannot revive a revoked credential or
pre-change callback. A stale token cannot overwrite newer directory permissions.
Readback reports the current local role, not a particular session's token ceiling.
An active-role demotion retains the last active administrator's local grant, with
`admin_retained=true` in the application audit. It still revokes credentials and
advances the proof cutoff. This recovery grant does not bypass the verified OIDC
role ceiling. Deactivation/deletion always disables the account, even the last admin;
disabled accounts never receive the retention exception.
Workspace/team membership roles and client encryption remain independent.

Migration 0018 removes existing linked-account administrator roles because their
origin may be the old global claim. If no unlinked active administrator exists, it
retains active linked local admin grants and records `admin_retained=true` in their
upgrade audits. It always revokes old SSO sessions once and audits each linked subject
with its previous role. Retention does not restore SSO administration without a new
verified `kynotes.admin` claim. Unlinked administrators and encrypted data stay intact. **Before upgrade, keep an unlinked local administrator
available** (the server CLI supports `user add --username <name> --admin`). After
upgrade, configure/assign `kynotes.admin`, request a new versioned resync and sign
in again. Replaying an old acknowledged revision does not reapply its roles. Do not
reuse an old receiver binary after migration; it does not enforce these controls.

## Fresh authorization for backup and recovery actions

The existing `RequireStepUp` routes (backup key pinning, pairing/unpairing,
schedule changes, deposit, export, mirror and restore drill) and the local
credential routes (user creation and password reset) require a fresh,
one-use OIDC proof for SSO sessions. Local-password sessions retain the existing
ten-minute password step-up. Other administrator routes retain their current
admin/CSRF requirements; this extension does not add step-up to every mutation.

A blocked action returns `403 sso_step_up_required` and a challenge ID. The server
binds that challenge to the original local session and a SHA-256 digest of the
method, exact request URI, Content-Type and body (at most 64 KiB), storing no body.
Only one challenge may exist per session; starting another action cancels the old
one. Pending challenges expire in five minutes. The browser keeps the attempted
request only in memory and opens a native confirmation dialog. Continue opens
KySignOn in a separate window with its opener detached; cancellation burns the challenge, including a
callback that races cancellation. Reloading abandons the in-memory request.

`POST /api/v1/auth/oidc/step-up` takes `{ "challenge": "rea_..." }`, requires
current admin and CSRF, and returns an authorization URL using PKCE, state, nonce,
`prompt=login`, `max_age=0`, and `acr_values=urn:kysignon:acr:password`. It uses the
same registered callback as ordinary login. The callback must arrive with the
original live local session, authenticate the same issuer/client/subject, and
include verified `kynotes.admin`. It never creates or replaces a local session.

The signed integer `auth_time` must be at or after challenge creation (epoch-second
precision), no later than now or `iat`. Issuance time alone proves nothing.
Accepted assurance is `urn:kysignon:acr:password` with `pwd`, or
`urn:kysignon:acr:mfa` with `pwd`, `mfa`, and a recognized ordinary second factor
(`otp`, KySignOn push or WebAuthn). Recovery, missing/unknown assurance, malformed
methods, stale authentication and a changed account fail closed. Configure stronger
MFA requirements in the KySignOn app policy; the receiver requests password as the
minimum and accepts ordinary MFA when the issuer requires it.

The browser polls `GET /api/v1/auth/oidc/step-up/{id}` and retries the identical
request once with `X-Kynotes-Step-Up: <id>`. A verified grant expires after at most
one minute. Consumption checks current admin permission, session lifetimes,
configuration and directory/logout fences, including logout of the fresh proof's
`sid`, then deletes the grant with an audit in the same writer transaction. One
concurrent request wins. The protected operation follows that committed admission;
a later logout cannot undo an already admitted operation. A failed operation needs
a new proof. `DELETE` requires admin access, the owning session and CSRF, and validates
the `rea_` ID format before database access. A well-formed absent, foreign-session or
repeated ID returns 204 without an audit write; only actual deletion is audited.

Migration 0019 adds the challenge table. Challenge creation, verification,
cancellation and consumption have atomic audits. Verification records the actual
`auth_time`, accepted `acr` and original session ID. Audit correlation uses the
middleware-established request ID, never an untrusted caller header. Restart loses pending PKCE state;
restart the action. Verified grants remain bounded by their persisted expiry and
parent-session revocation. Restoring a database revokes the parent sessions through
the existing restore procedure. Older receiver binaries do not enforce this policy.

## Adoption boundary and verification

This completes the session/logout and versioned-directory implementation stages of
[issue 13](https://github.com/Busnes-app/kynotes-server/issues/13).
It does not complete KyNotes adoption of the KySignOn access lifecycle plan.
Application roles and action-bound OIDC reauthentication for the existing backup/recovery
step-up routes are implemented. Live acceptance remains outstanding.

`go test -race ./...` covers real signed TLS/JWKS login/logout, wrong scope and
invalid tokens, concurrent replay, restart, audit rollback, callback and device
enrollment races, configuration revocation, valid bursts after invalid traffic,
sid-less compatibility, audit counts, JWKS endpoint rotation, migration and
versioned directory ordering/data-preservation tests. `TestSSOStepUp*` adds proof freshness,
action binding, concurrent consumption, cancellation, revocation and audit failure
checks. Browser tests cover the identical one-use retry and cancellation. These are local fixtures.
Live KySignOn/KyNotes deployment, other suite products, external relying parties,
upstream-directory integration, role-aware consumers and the combined custodian
recovery run remain separate acceptance gates.
