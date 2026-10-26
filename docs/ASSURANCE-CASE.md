# Assurance case

[README](../README.md) · [Security](../SECURITY.md) · [Design](../DESIGN.md#4-security-model)

This is the argument that KyNotes meets its security requirements: what it protects, from whom,
where the trust boundaries are, and why the design and the code hold at each one. The detailed
behaviour lives in [SECURITY.md](../SECURITY.md) and [DESIGN.md](../DESIGN.md); this page ties it
together and points at the evidence. Where a claim names code, the path is relative to the
repository root.

## What KyNotes must protect

KyNotes is a self-hosted, zero-knowledge notebook. Its security requirements:

1. **The server never needs plaintext.** Notes, attachments, container keys and private keys are
   encrypted and decrypted in the browser; the server stores ciphertext and routing metadata.
2. **Only the right person signs in as an account.** Passwords, recovery codes, sessions and
   device secrets cannot be guessed, replayed or recovered from the database.
3. **A user reaches only the containers they belong to**, with only their role's rights, and an
   administrator manages accounts without reading notes.
4. **Access ends when it should.** Device revocation, SSO logout, directory deactivation and role
   changes revoke credentials at once.
5. **The server cannot be pointed at arbitrary hosts** by a user.
6. **No secret or note content reaches a log.**

## Threat model

| Attacker | Can | Wants |
|---|---|---|
| Anonymous internet client | Send any request through the proxy | Take over an account, guess passwords, enumerate usernames |
| Signed-in user | Use their own session, devices and APIs | Read or change containers they are not a member of, reach admin functions |
| Removed team member | Hold content and keys downloaded earlier | Read content written after removal |
| Administrator account | Manage users and the service | Read notes (must not be able to) |
| Someone with a copy of the data directory or a capsule | Read the SQLite database and blobs | Recover passwords, sessions or note plaintext |
| Network attacker | Read and alter traffic | Steal sessions or keys |

Out of scope: a server operator who changes the code the browser runs (they control the client;
see [SECURITY.md](../SECURITY.md#trust-boundaries-and-limitations)), and content already
downloaded by a member before revocation.

## Trust boundaries

1. **Browser → KyNotes.** The browser holds the content keys. The server stores ciphertext,
   key envelopes and metadata ([DESIGN.md, Encryption](../DESIGN.md#encryption)). The server
   binary does not link the client-side sealing code (`internal/notecrypto` is used only by the MCP
   bridge in `cmd/kynotes-mcp`; `TestNotLinkedIntoServer` in `internal/notecrypto` checks it).
2. **Proxy → KyNotes.** `X-Forwarded-For` counts only when `behind_proxy` is set and the peer is in
   the trusted proxies, read right to left (`resolvedClientIP` in `internal/httpapi/ratelimit.go`).
3. **KyNotes → push services.** Subscription endpoints must be `https` to one of five browser push
   hosts on the default port, with no redirects and a 5-second timeout
   (`internal/webpush/webpush.go`).
4. **KyNotes → blob mirror and KyRecovery.** Operator-configured; SFTP targets are pinned by host
   key and enforce RSA-2048 endpoint keys and maintained negotiation algorithms
   (`ky-primitives/offsite`, pinned in `go.mod`). S3 signing uses the shared module's AWS SDK
   SigV4 signer. SMB/NTLM is a separately selected legacy compatibility mode with the
   [documented credential and peer-authentication risks](DEPLOYMENT.md#smb-compatibility-choice).
   Capsules are sealed to the suite public key.
5. **KyNotes → its data directory.** Passwords, sessions and device secrets are stored only as
   hashes; content is ciphertext.

## Secure design principles applied

- **Least privilege.** Administrator and everyday accounts are separate, and an administrator
  account is refused at the note APIs (`refuseSession` in `internal/auth/middleware.go`). The
  image runs as distroless `nonroot`.
- **Fail-safe defaults.** Forwarded headers are ignored unless the proxy is trusted. Push
  endpoints outside the known services are refused. Conflicts fail closed and keep the rejected
  ciphertext ([CONTRIBUTING.md](../CONTRIBUTING.md#security-requirements)).
- **Complete mediation.** Every request resolves its session from the database
  (`ResolveSession`), so a revoked session or deactivated account stops at the next request.
- **Economy of mechanism.** Seven direct Go modules (`go.mod`); WebCrypto in the browser.
- **Separation of privilege.** Backup and recovery actions need step-up, except a manual
  deposit, which only seals to the already-pinned key (admin plus CSRF); SSO admin needs both the
  account role and the verified `kynotes.admin` claim ([SECURITY.md](../SECURITY.md)).
- **Open design.** Only published algorithms: Argon2id, PBKDF2-SHA256, HKDF-SHA256, AES-256-GCM,
  X25519 for note/authentication mechanisms. Optional SMB uses the documented legacy NTLM
  mechanisms for interoperability; it is disabled unless explicitly selected. The code and
  this argument are public. Listing primitives does not establish expert review of every
  application protocol.
- **Psychological acceptability.** Each trade-off (equal-ciphertext attachment deduplication,
  reminder timing visible to the server) is written in [SECURITY.md](../SECURITY.md).

## Common weaknesses and how they are countered

| Weakness | Counter | Where |
|---|---|---|
| Password theft from the server | The browser derives the login secret with PBKDF2-SHA256 (600,000 iterations; every password write refuses fewer, and the browser signs in to an older account at no fewer than 100,000 only until it has upgraded that account and pinned it) and HKDF; the server stores that as Argon2id | `web/src/crypto.ts`, `internal/auth/hash.go`, `internal/httpapi/auth_routes.go` |
| Username enumeration | A synthetic login salt for unknown usernames | `SyntheticLoginSalt` in `internal/auth/derive.go` |
| Credential guessing | 3 failed logins lock for 15 minutes, 3 failed recoveries for 60; per-minute rate limits on login, pairing and uploads | `internal/httpapi/auth_routes.go`, `internal/httpapi/ratelimit.go` |
| Session theft or fixation | A fresh 32-byte `crypto/rand` token per sign-in, only its SHA-256 stored; `HttpOnly`, `SameSite=Lax`, `Secure` unless configured insecure; 24-hour sliding and 7-day hard expiry | `internal/auth/session.go` |
| CSRF | `SameSite=Lax` session cookie, plus a session-bound token: state-changing requests with a session cookie must send `X-CSRF-Token` equal to an HMAC-SHA256 of that session cookie under a server key derived from `secrets/pairing.key` (constant-time compare). The `csrf_token` cookie only tells the web app the value and is never trusted, so a token or cookie pair from another session, or one tossed in from a sibling origin, is refused. Requests without a session cookie (sign-in) carry no session to forge and are not CSRF-checked. The check runs in each handler, not in middleware | `CheckCSRF` in `internal/auth/csrf.go` |
| Device secret theft | Device secrets stored as SHA-256, compared in constant time, with a lockout per device and address | `internal/auth/middleware.go` |
| Cross-site scripting | No `dangerouslySetInnerHTML` or `innerHTML` assignment in `web/src`; the web app's CSP has `script-src 'self'` and `frame-ancestors 'none'`; every other response gets `default-src 'none'` and `X-Frame-Options: DENY` | `internal/web/embed.go`, `SecurityHeaders` in `internal/httpapi/middleware.go` |
| SQL injection | `database/sql` with `?` parameters; the one concatenated statement joins a constant | `internal/storage/gc.go` |
| Command injection | The server starts no subprocess; `exec.Command` appears only in the test probe | `cmd/kynotes-probe` |
| Server-side request forgery | Push endpoints restricted to five hosts; other outbound targets are operator configuration | `internal/webpush/webpush.go` |
| Content disclosure or substitution by the server | Content sealed with AES-256-GCM under per-container keys, subkeys from HKDF-SHA256 bound to the container ID, and associated data binding each ciphertext to its object (or page) and kind; older unbound content refused once its notebook migrates; keys wrapped to X25519 device and identity keys | `web/src/crypto.ts`, `internal/notecrypto/notecrypto.go`, [DESIGN.md](../DESIGN.md#encryption) |
| Secrets in logs | A logging contract that allows only opaque IDs and outcomes | [LOGGING.md](../LOGGING.md) |
| Vulnerable dependencies | Dependabot for Go, npm, Actions and the base image; `govulncheck` in CI | `.github/dependabot.yml`, `.github/workflows/ci.yml` |
| Supply-chain tampering | Actions pinned by commit; base images pinned by digest; release images attested and built only from a commit that passed CI; the binary rebuilds to the same bytes | [VERIFYING-RELEASES.md](VERIFYING-RELEASES.md) |

## Residual risk

Known limitations are listed, not hidden: the server sees routing metadata, sizes and timing;
removed members keep what they downloaded; deterministic attachment encryption reveals equal
ciphertexts; the server can roll an object back to its own older revision or swap one page's
comments and attachments among themselves; reminder push leaks reminder times to the server; and share links survive directory
deactivation until they expire. Each is in
[SECURITY.md](../SECURITY.md#trust-boundaries-and-limitations).

## Evidence

- **Tests:** `make test` runs every Go package under the race detector with
  `-count=1` and a 20-minute per-package hang budget for the real-password API suite.
  Package tests cover every security-sensitive route, including
  `TestMutatingRequestWithoutCSRFHeaderIsRejected`, `TestCSRFTokenIsBoundToSession`,
  `TestCSRFTokenFromAnotherSessionIsRefused` and the route-level CSRF and step-up tests in
  `internal/httpapi`; SECURITY.md requires attack-path tests for security changes. CI runs the
  Go suite under the race detector, the web unit tests, and Playwright browser regressions on
  every push and pull request.
  `TestSFTPTransportPolicy` uses real protocol peers: pinned RSA-1024/2047 and SHA-1-only
  key exchange are refused before password authentication, failed uploads stay pending,
  and RSA-2048/Ed25519 peers still mirror and recover the original ciphertext.
- **Static analysis:** CodeQL default setup (Go, JavaScript/TypeScript, Actions), `go vet`,
  `tsc` in strict mode, and `govulncheck`.
- **Dynamic analysis:** the race detector, four Go fuzz targets in CI (pairing token, auth
  secret, IDs, config), and a container probe against the built image.
- **Releases:** attested images and a repeatable binary ([VERIFYING-RELEASES.md](VERIFYING-RELEASES.md)).

This case is updated when a trust boundary or a security requirement changes. A pull request that
moves one must update this page in the same change.
