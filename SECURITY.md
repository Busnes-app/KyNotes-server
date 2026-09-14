# Security Policy

KyNotes is a self-hosted, zero-knowledge note service. The server stores
metadata and ciphertext; clients encrypt and decrypt notes, attachments, and
container keys.

## Reporting vulnerabilities

Report security vulnerabilities privately to the maintainer through GitHub
Security Advisories: <https://github.com/Busness-app/kynotes-server/security/advisories>.
Do not open a public issue. Include the affected area, reproduction steps,
impact, and affected versions. We will acknowledge reports within two business
days and coordinate a fix and disclosure.

## Trust boundaries and limitations

- The server can see routing metadata, object versions, sizes, timestamps, and
  membership metadata. It must not receive plaintext note or attachment data,
  private encryption keys, or recovery codes.
- Device keys and container keys are wrapped for authorized devices. Explicit
  device revocation removes server-side envelopes. SSO logout and the SSO upgrade
  instead revoke authentication while preserving envelopes for re-pairing; neither
  path recalls plaintext already downloaded or guarantees client-storage wiping.
- SSO logout ends scoped browser sessions and credentials derived from them.
  Independent local password authentication remains available. Devices paired
  through SSO must re-pair after their parent session ends, including expiry.
  Logout requires verified issuer/client signatures and durable atomic replay,
  revocation and audit. Admitted metadata verification may finish for up to 30
  seconds after a caller disconnects, preventing cancellation from poisoning shared
  discovery/JWKS caches; session mutations still honor request cancellation.
  See [SSO setup and upgrade](docs/SSO.md) for migration
  effects and the staged directory/role/reauthentication acceptance boundary.
- Team membership changes rotate keys for future content. Removed members may
  retain content they already downloaded.
- Deterministic attachment encryption may reveal that two ciphertexts are
  equal. This is an intentional deduplication trade-off.
- Public publishing is deferred. The initial release does not expose plaintext
  through the server. A future publisher must use an explicit client-mediated
  export and a separate public storage model.
- Push payloads contain notification metadata only. Clients pull ciphertext
  over HTTPS.

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
