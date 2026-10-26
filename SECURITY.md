# Security Policy

KyNotes is a self-hosted, zero-knowledge note service. The server stores
metadata and ciphertext; clients encrypt and decrypt notes, attachments, and
container keys.

## Reporting vulnerabilities

Report security vulnerabilities privately to the maintainer through GitHub
Security Advisories: <https://github.com/Busnes-app/kynotes-server/security/advisories>.
Do not open a public issue. Include the affected area, reproduction steps,
impact, and affected versions. We will acknowledge reports within two business
days and coordinate a fix and disclosure.

## Trust boundaries and limitations

- The server can see routing metadata, object versions, sizes, timestamps, and
  membership metadata. It must not receive plaintext note or attachment data,
  private encryption keys, or recovery codes.
- Device keys and container keys are wrapped for authorized devices. Explicit
  device revocation removes server-side envelopes. SSO logout, directory deactivation and the SSO upgrade
  instead revoke authentication while preserving envelopes for re-pairing; none of these
  paths recalls plaintext already downloaded or guarantees client-storage wiping.
- SSO logout ends scoped browser sessions and credentials derived from them.
  Independent local password authentication remains available. Devices paired
  through SSO must re-pair after their parent session ends, including expiry.
  Logout requires verified issuer/client signatures and durable atomic replay,
  revocation and audit. Admitted metadata verification may finish for up to 30
  seconds after a caller disconnects, preventing cancellation from poisoning shared
  discovery/JWKS caches; session mutations still honor request cancellation.
  See [SSO setup and upgrade](docs/SSO.md) for migration
  effects and the staged directory/role/reauthentication acceptance boundary.
- Trusted signed directory delivery may link an unbound local username. It maps only the explicit application
  role `kynotes.admin` to product administration; directory role sets replace local
  permission. SSO admin requests also require that role in the session’s verified
  OIDC claims; global role claims and auto-provisioning never elevate an account. Directory deactivation or a role change revokes the account’s
  sessions and device credentials and preserves encrypted data; a higher active revision or role re-grant requires
  fresh credentials. Previously issued share links remain valid until expiry or
  separate revocation; directory deactivation does not revoke them. A persistent
  login-proof cutoff rejects callbacks carrying
  pre-disable ID tokens after re-enablement. Durable issuer/subject revision fences survive replay expiry
  and user deletion. Local administrators cannot override an inactive directory
  fence by editing status. Unversioned senders must upgrade before this receiver.
  Readback requires a signed purpose/subject and an atomic successful audit
  identifying the probed subject and signed event ID.
- Team membership changes rotate keys for future content. Removed members may
  retain content they already downloaded.
- Deterministic attachment encryption may reveal that two ciphertexts are
  equal. This is an intentional deduplication trade-off.
- Each ciphertext is bound to its notebook, its object (comments and attachments: their page) and
  its kind, so the server cannot substitute one for another. It can still serve an older revision of
  the same object, swap one page's own comments or attachments among themselves, and show a browser
  that never opened a migrated notebook its older, unmarked name; the browser that migrates a
  notebook pins the older comments and attachments the server serves at that time.
- Public publishing is deferred. The initial release does not expose plaintext
  through the server. A future publisher must use an explicit client-mediated
  export and a separate public storage model.
- Push payloads contain notification metadata only. Clients pull ciphertext
  over HTTPS.
- Reminder push is off by default. With it on, for each open task marked `push:yes` the server stores
  an opaque id and the reminder's UTC minute, so it learns when the account has reminders, how many,
  and which account owns them; never the page, task, notebook or text. The browser's push service
  (Google for Chrome, Mozilla for Firefox, Apple for Safari, Microsoft for Edge on Windows) sees an empty
  push to that browser at that minute. Subscription changes are audited with the push service host only;
  reminder writes are not audited. Subscription endpoints are limited to those push services (https,
  default port, no redirects, 5 s timeout), so the server cannot be pointed at another host.

## Deployment requirements

- Run the service behind HTTPS. Do not introduce a default that silently
  downgrades to cleartext.
- Keep the single data directory and its backups private. It contains the
  database, ciphertext blobs, key envelopes, sessions, and audit records.
- Stop the server before copying the data directory. Restore it while stopped,
  then run a database integrity check.
- Configure quotas and rate limits for login, pairing, uploads, and
  notifications.
- Logs must contain only opaque IDs, operation types, coarse timings, and
  privacy-safe outcomes. Never log plaintext, keys, recovery codes, tokens, or
  full encrypted payloads.

## Blob mirror transport policy

The optional mirror is off until a destination is configured. Its shared SFTP client
requires pinned host keys, RSA keys of at least 2048 bits (host and private authentication),
supported Ed25519/ECDSA keys and maintained negotiation algorithms. RSA signatures use
SHA-2. Keep existing keys, configuration and replica history; upgrade an unsupported
destination through separately verified administrator access before changing its pin.

An `smb://` destination is an explicit legacy compatibility choice. NTLM password
authentication uses MD4, HMAC-MD5 and negotiated RC4, and the client can accept an unsigned
guest session. Use it only when necessary for interoperability, on a trusted network with
independent replica verification. Prefer pinned SFTP, HTTPS S3 or an independently secured
OS-managed mount. See [deployment policy and migration](docs/DEPLOYMENT.md#ciphertext-blob-mirror).
This transport policy does not establish whole-product key-size or protocol-review compliance.

## Security-sensitive changes

Changes to authentication, sessions, device enrollment or revocation,
recovery, key envelopes, authorization, sync conflict handling, attachment
storage, or logging require tests for both the expected path and
the relevant failure or attack path. Review the verification strategy in
[DESIGN.md](DESIGN.md#11-verification-strategy).

## Related documents

- [DESIGN.md](DESIGN.md) — architecture, encryption, storage, and deployment
- [LOGGING.md](LOGGING.md) — privacy-safe logging rules
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution and review requirements
- [docs/VERIFYING-RELEASES.md](docs/VERIFYING-RELEASES.md) — verify a release image and rebuild its binary
- [docs/ASSURANCE-CASE.md](docs/ASSURANCE-CASE.md) — threat model and the argument that the protections above hold

### SSO last-administrator recovery grant

Active directory-role demotion preserves the last active administrator's local
account grant, and migration 0018 preserves active linked grants when no unlinked
active administrator exists. These exceptions are audited as `admin_retained=true`.
Runtime retention revokes sessions/devices; the upgrade revokes old SSO sessions.
Neither bypasses the verified `kynotes.admin` OIDC session ceiling. Deactivation remains authoritative, including for the last admin.
Keep an unlinked local administrator available for recovery; see [SSO roles](docs/SSO.md#application-roles).

## Action-bound OIDC step-up

Backup/recovery step-up routes, local user creation and password reset require a one-use OIDC proof for SSO
sessions. Migration 0019 binds the exact request digest to the original session;
fresh signed auth_time and ordinary assurance, identity and app-admin permission
are required. Issuance time is never substituted for authentication time. Creation,
verification, cancellation and consumption are audited atomically. Admission
rechecks parent-session and fresh-proof revocation and consumes before the operation;
a subsequent logout cannot undo an admitted operation. Local-password sessions keep
the existing password proof window. Other admin routes retain existing guards.
The browser retains the request only in memory while a separate sign-in window
completes the proof. See [SSO authorization](docs/SSO.md#fresh-authorization-for-backup-and-recovery-actions)
for freshness, expiry, cancellation, restart and live-acceptance limits.
