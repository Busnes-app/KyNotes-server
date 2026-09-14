# SSO sessions and back-channel logout

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

## Adoption boundary and verification

This is the first stage of [issue 13](https://github.com/Busness-app/kynotes-server/issues/13).
It does not complete KyNotes adoption of the KySignOn access lifecycle plan.
Versioned bare SCIM directory delivery, deactivation that preserves encrypted
accounts, application roles and action-bound reauthentication remain follow-up
work. The legacy directory webhook still accepts its existing envelope and its
existing delete event can delete an account: do not treat this release as the
new provisioning receiver.

`go test -race ./...` covers real signed TLS/JWKS login/logout, wrong scope and
invalid tokens, concurrent replay, restart, audit rollback, callback and device
enrollment races, configuration revocation, valid bursts after invalid traffic, sid-less compatibility,
audit counts, JWKS endpoint rotation, and migration from all pre-feature
schema versions. These are local fixtures. Live KySignOn/KyNotes deployment,
other suite products, external relying parties, upstream-directory integration,
role-aware consumers and the combined custodian recovery run remain separate
acceptance gates.
