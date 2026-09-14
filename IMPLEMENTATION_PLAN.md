# KyNotes Server — Implementation Plan (Handoff)

Status: authoritative. Supersedes any earlier phase sketch.
Audience: the engineer or agent implementing the server from an empty Go module.
Extension for Myslop #290: the implemented OIDC and directory-sync paths now use
`ky-primitives@v0.5.1` (`oidcverify` and `syncauth`), per DESIGN.md. Migration
0014 records signed event replay atomically with account changes. This supersedes
the original deferral of SSO for that existing subsystem; client crypto is unchanged.

Lifecycle extension for issue 13, first stage: the root shared dependency is now
`ky-primitives@v0.7.0`. Migration 0016 adds issuer-bound users, SSO session origin,
device parent-session binding and durable logout replay/fences. The canonical
POST `/api/v1/auth/oidc/backchannel-logout` verifies signed form tokens and commits
revocation with audit. Login cookies require atomic session/audit admission;
logout can fence an unfinished callback, including older sid-less logins matched
by the token's subject and issuance time. Verified logout bypasses IP abuse limits;
audit retains the JWT ID and revocation counts. Failed key verification can refresh
a changed discovery JWKS URI at most once per minute per issuer/client. Shared
login/logout metadata verification rejects already-cancelled calls, then uses a
detached 30-second budget so disconnects cannot poison shared fetch cooldowns;
session mutations retain the original request context.
Pairing tokens add optional signed
`session` metadata; unbound legacy tokens are refused for linked accounts.
The migration revokes old linked-account sessions/devices once, preserving
ciphertext and envelopes. See DESIGN.md and `docs/SSO.md` for the complete
contract. Verification includes TLS/JWKS integration, writer races, audit
rollback, restart and migration 1–15 upgrade coverage. Follow-up stages retain
versioned directory/deactivation, app roles and action-bound reauthentication;
this stage does not satisfy live deployment acceptance.

Recovery extension for Myslop #290: sealed capsule collection and restore live in
`internal/backup`, using `ky-primitives/recoveryclient@v0.5.1`; see DESIGN.md and
`docs/RESTORE.md`. The existing local plaintext commands are now `copy-data-dir`
and `restore-data-dir`; sealed `restore --in --to` consumes custodian shares on stdin.
The backup API is `/api/v1/admin/backup/{status,pin-key,pair-remote,unpair,schedule,
deposit,drill,export-capsule}`; status is GET; all other operations, including export, are POST. Mutations
use admin+CSRF+step-up. Backup errors retain the existing envelope.

Source documents: [DESIGN.md](DESIGN.md), [SECURITY.md](SECURITY.md),
[LOGGING.md](LOGGING.md), [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md).

---

## 0. Rules for the implementer

Read this section before anything else. It is binding.

1. **Do not invent contracts.** Every format, constant, name, table, column,
   endpoint, header, and error code you need is written down in this document.
   If something you need is genuinely absent, stop and ask. Do not guess and do
   not "pick something reasonable".
2. **Do not reorder phases.** Phase N+1 starts only when Phase N's exit gate
   passes. The exit gate is a command with an expected result, not an opinion.
3. **Do not skip tests.** Each phase lists exact test function names. They are
   the deliverable, not decoration. A phase with missing tests is not done.
4. **Do not widen scope.** Section 14 lists what must not be built. Building a
   deferred feature is a defect.
5. **Every non-trivial function gets a runnable check** (AGENTS.md, Ponytail
   rule). Every security-sensitive change gets both a success-path test and a
   failure/attack-path test (SECURITY.md).
6. **Smallest correct change.** Prefer the Go standard library. The dependency
   allowlist in §1.2 is complete; adding to it requires an explicit decision
   recorded in DESIGN.md.
7. **If a shortcut has a limit**, mark it `// ponytail: <limit>. Upgrade path:
   <what to do>` and nothing else.
8. **Never log** note content, task text, attachment bytes, container names,
   keys, envelopes, session tokens, device secrets, pairing tokens, recovery
   codes, or raw request bodies. Opaque IDs, event names, outcomes, byte counts,
   and coarse timings only (LOGGING.md).
9. **The server must never be able to read user content.** If a design choice
   would require the server to parse plaintext, the choice is wrong.
10. **Run a DOX pass after every meaningful change**: update the nearest
    `AGENTS.md` when behaviour, responsibilities, or verification change.

### 0.1 Definition of done, per phase

```
go build ./...              # exits 0
go vet ./...                # exits 0, no findings
go test ./...               # exits 0, no skipped security tests
go test -race ./...         # exits 0
gofmt -l .                  # prints nothing
```

Record the commands and their output in the PR (CONTRIBUTING.md).

---

## 1. Phase 0 — Frozen contracts

Phase 0 is **complete**. Everything below is decided. Do not re-open any of it.

Provenance note: `~/git/kypassword-server` contains documentation only and no
code, and its own PROMPT.md defers to KyPost's protocol. The only implemented
client-derived authentication in the KySecurity suite is
`~/git/kypost-server/backend/internal/{users,api}`. KyNotes therefore **ports
KyPost's proven scheme with a KyNotes domain-separation label**, rather than
depending on an unbuilt service. KySignOn/OIDC integration is out of scope for
this plan; see §14.

### 1.1 Module, language, layout

| Item | Frozen value |
|---|---|
| Module path | `github.com/Busness-app/kynotes-server` |
| Go version | `1.26.6` (`go.mod`: `go 1.26.6`) |
| `go.mod` location | repository root (this repo is server-only) |
| Binary | `kynotes-server` |
| Entry point | `cmd/kynotes-server/main.go` |
| CGO | `CGO_ENABLED=0`, always |
| Build flags | `-trimpath` |
| Clients | separate repositories: `kynotes-web`, `kynotes-android`, `kynotes-ios`. Do not add client code to this repo. Protocol fixtures live here under `testdata/protocol/`. |

Directory layout, exactly:

```
cmd/kynotes-server/main.go
internal/app/          # wiring, serve, graceful shutdown, background sweepers
internal/config/       # load, defaults, validation
internal/httpapi/      # router, middleware, handlers, error envelope
internal/storage/      # SQLite store + migrations runner
internal/storage/migrations/*.sql
internal/blobstore/    # content-addressed encrypted-blob filesystem store
internal/auth/         # derived auth, sessions, device credentials, lockout
internal/ids/          # ID minting and validation
internal/logging/      # structured privacy-safe logger
internal/health/       # health + readiness checkers
testdata/protocol/     # golden protocol fixtures for client interop
Dockerfile
Makefile
```

`internal/http` is **not** used as a package name (it shadows `net/http` at call
sites). The package is `httpapi`.

### 1.2 Dependency allowlist (complete)

```
github.com/Busness-app/ky-primitives # shared auth, OIDC and sync contracts
modernc.org/sqlite          # pure-Go SQLite driver; required for CGO_ENABLED=0
golang.org/x/crypto         # pbkdf2, hkdf, scrypt
gopkg.in/yaml.v3            # config file
```

Everything else uses the standard library: `net/http` (incl. `http.ServeMux`
method+pattern routing, Go 1.22+), `log/slog`, `database/sql`, `crypto/*`,
`encoding/*`, `testing`. **No** web framework, **no** ORM, **no** migration
library, **no** UUID library, **no** logging library.

### 1.3 Authentication contract (ported from KyPost)

The client derives an authentication secret from the password. The server never
receives the password.

```
authSecret = hex( HKDF-SHA256(
                    ikm  = PBKDF2-SHA256(password, base64decode(loginSalt), iterations, 32),
                    salt = <empty>,
                    info = "kynotes/auth/v1",
                    L    = 32 ) )
```

| Constant | Frozen value |
|---|---|
| HKDF info label | `kynotes/auth/v1` (differs from KyPost's `kypost/auth/v1` on purpose: a KyPost verifier must never authenticate to KyNotes) |
| PBKDF2 stretch output | 32 bytes |
| Auth secret output | 32 bytes, lowercase hex (64 chars) |
| Iterations served to new clients | `600_000` |
| `MinLoginIterations` | `100_000` |
| `MaxLoginIterations` | `12_000_000` |
| `MinLoginSaltBytes` | `16` |
| `MaxLoginSaltBytes` | `64` |
| Login salt wire format | standard base64 (`base64.StdEncoding`), decoding to 16..64 bytes |

**Server-side storage of the verifier**: the auth secret is hashed with scrypt
before storage, in KyPost's self-describing format:

```
scrypt$<N>$<r>$<p>$<base64 salt>$<base64 hash>
```

| Constant | Frozen value |
|---|---|
| `scryptN` | `1 << 17` (131072) |
| `scryptR` | `8` |
| `scryptP` | `1` |
| `scryptKeyLen` | `32` |
| scrypt salt | 16 random bytes from `crypto/rand` |
| Concurrent scrypt slots | `4` (semaphore; each holds 128 MiB) |

Verification parses N/r/p out of the stored string, so raising `scryptN` later
does not invalidate stored hashes. Comparison is
`crypto/subtle.ConstantTimeCompare`.

**Unknown usernames**: `POST /api/v1/auth/login-params` for an unknown username
returns a *synthetic but stable* salt, computed as
`base64( HMAC-SHA256(serverSaltKey, "login-salt/v1\x00"+lowercase(username))[:16] )`
and `iterations = 600000`. It must be indistinguishable from a real response.
`serverSaltKey` comes from §1.9. Login for an unknown username performs a full
scrypt against a fixed dummy hash before answering, so timing does not enumerate
accounts.

**Lockout** (in-memory, per process):

| Surface | Max failures | Cooldown | Key |
|---|---|---|---|
| Login | `3` | `15 * time.Minute` | `username + "\x00" + ipKey(clientIP)` |
| Device credential | `10` | `15 * time.Minute` | `deviceID + "\x00" + ipKey(clientIP)` |
| Recovery code | `3` | `60 * time.Minute` | `username + "\x00" + ipKey(clientIP)` |

`ipKey` folds IPv6 to its /64 and IPv4 to the full address. The lockout table
sweeps non-locked entries at `10_000` entries and **sheds new keys** past
`50_000` — live lockouts are never evicted to make room (evicting them is a
bypass, not a memory trade). Shedding answers `429`.

### 1.4 Session contract

| Item | Frozen value |
|---|---|
| Session cookie | `kynotes_session`, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/` |
| CSRF cookie | `csrf_token`, **not** `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/` |
| Token material | 32 bytes `crypto/rand`, `base64.RawURLEncoding` |
| Stored form | lowercase hex SHA-256 of the token; the raw token is never stored |
| Idle timeout (sliding) | `24 * time.Hour` |
| Hard lifetime (absolute) | `7 * 24 * time.Hour` |
| Slide granularity | `5 * time.Minute` (only rewrite the row when the deadline moved by at least this) |
| Sweep interval | `1 * time.Hour` |
| CSRF rule | every non-`GET`/`HEAD`/`OPTIONS` request with a session cookie must carry header `X-CSRF-Token` equal to the `csrf_token` cookie, compared with `subtle.ConstantTimeCompare` |

`Secure` is unconditionally `true` unless `server.dev_insecure_cookies: true` is
set in config, which is refused when `server.bind` is not a loopback address
(§1.9). There is no silent downgrade (SECURITY.md).

### 1.5 Device contract

| Item | Frozen value |
|---|---|
| Device auth headers | `X-Kynotes-Device-Id`, `X-Kynotes-Device-Secret` |
| Max device-id length | `128` bytes (reject longer before any map insertion) |
| Max device-secret header length | `512` bytes |
| Device secret | 24 bytes `crypto/rand`, lowercase hex (48 chars), returned exactly once at registration |
| Device secret storage | `"sha256:" + hex(sha256(secret))`. **Not** scrypt: the secret is 192 bits of `crypto/rand`, so a password KDF buys nothing and costs ~50 ms on every device request |
| Device public key | X25519, raw 32 bytes, standard base64 on the wire |
| Device fingerprint | lowercase hex SHA-256 of the raw 32 public-key bytes; server-computed only |
| Identity rule | the server derives device identity from the registered public key. Client-supplied identity fields are display-only and are stored encrypted (`label_ciphertext`) |

Device credentials and session cookies are **different credentials**. A device
credential must never be accepted on an envelope-minting or device-management
route (§1.8).

### 1.6 Pairing token contract

Ported from KyPost's HMAC pairing tokens.

```
payload = json{"sub":"<userID>","exp":<unix>,"nonce":"<hex 8 bytes>","purpose":"device-pair"}
token   = base64url_raw(payload) + "." + base64url_raw(HMAC-SHA256(pairingSecret, payload))
```

| Item | Frozen value |
|---|---|
| Purpose string | `device-pair` (the only purpose in this release) |
| TTL | `120 * time.Second` |
| Single use | enforced by inserting `nonce` into `pairing_nonces`; a duplicate insert is `409 pairing_token_used` |
| `pairingSecret` minimum length | `32` characters when operator-supplied |
| Signature check | `hmac.Equal`; subject check `subtle.ConstantTimeCompare`; purpose check plain `!=` (purpose is not secret) |
| Failure mode | an unset or too-short pairing secret **disables pairing and answers `503`**. Never fall back to a generated per-replica secret when the operator supplied a bad one |

The QR/deep link carries `kynotes://pair?host=<https url>&token=<token>`. The
token is never logged, never placed in a URL query the server logs, and never
returned in an error message.

### 1.7 API contract

* Base path: `/api/v1`. Unversioned paths do not exist except `/healthz` and
  `/readyz`.
* Request and response bodies are `application/json; charset=utf-8`, except
  ciphertext transfer routes which are `application/octet-stream`.
* Ciphertext larger than 4 KiB is **never** base64-in-JSON. Key envelopes and
  small metadata ciphertext are base64 (`base64.StdEncoding`) inside JSON.
* All timestamps on the wire are RFC3339 UTC with second precision.
* Every response carries `X-Request-Id`. Every log line for that request carries
  the same value.

**Error envelope** — exactly this shape, always:

```json
{"error":{"code":"version_conflict","message":"base version is stale","requestId":"req_01H..."}}
```

`message` is a fixed English string chosen from the handler. It must never
contain user content, a filename, a container name, a token, or a digest of
user data.

**Error code table** (complete; do not add codes without updating this table):

| `code` | HTTP | Meaning |
|---|---|---|
| `invalid_request` | 400 | malformed body, bad parameter, failed validation |
| `unauthenticated` | 401 | no or invalid session/device credential |
| `csrf_failed` | 403 | missing or mismatched CSRF token |
| `forbidden` | 403 | authenticated but not authorized for this container/object |
| `not_found` | 404 | unknown ID, or an ID the caller may not know exists |
| `method_not_allowed` | 405 | |
| `version_conflict` | 409 | `baseVersion` != current version; a conflict record was preserved |
| `already_exists` | 409 | idempotency or uniqueness violation |
| `pairing_token_used` | 409 | pairing nonce already redeemed |
| `gone` | 410 | upload session expired or object hard-deleted |
| `payload_too_large` | 413 | body or declared size exceeds the configured limit |
| `quota_exceeded` | 413 | per-user or per-team quota would be exceeded |
| `unsupported_media_type` | 415 | |
| `digest_mismatch` | 422 | finalized bytes do not hash to the declared digest |
| `rate_limited` | 429 | rate limit or lockout; includes `Retry-After` |
| `internal` | 500 | unexpected; details go to the log, never to the client |
| `unavailable` | 503 | a required secret or subsystem is not configured |

**Authorization leak rule**: when a caller is authenticated but has no
membership in the container that owns the requested resource, answer
`404 not_found`, not `403 forbidden`. `403 forbidden` is used only when the
caller *is* a member but lacks the role for the operation. This prevents
probing for object existence across accounts.

### 1.8 Credential requirements per route class

| Route class | Session | Device credential | Step-up |
|---|---|---|---|
| Login, login-params, recovery | none | none | — |
| Device list, revoke, pairing-token mint | required | rejected | fresh session (< 5 min since login) for mint and revoke |
| Device registration (redeem pairing token) | none | none (mints one) | pairing token |
| Envelope write (`PUT .../envelopes`) | required | rejected | fresh session |
| Envelope read (`GET .../envelopes`) | either | either | a device may read only envelopes sealed for **itself** |
| Container/object/attachment sync | either | either | — |
| Admin (quota, GC, backup) | required, role `admin` | rejected | fresh session |

"Fresh session" = `now - session.created_at < 5 * time.Minute`, else `403
forbidden` with message `re-authentication required`.

### 1.9 Configuration contract

One YAML file, path from `--config` (default `/data/kynotes.yaml`), with
environment overrides prefixed `KYNOTES_`. Env wins over file. Nested keys map
by uppercasing and replacing `.` with `_`: `server.bind` → `KYNOTES_SERVER_BIND`.

```yaml
server:
  bind: "0.0.0.0:8080"
  behind_proxy: true              # trust X-Forwarded-For from trusted_proxies only
  trusted_proxies: ["127.0.0.1/32"]
  read_header_timeout: "10s"
  read_timeout: "60s"
  write_timeout: "120s"
  idle_timeout: "120s"
  shutdown_grace: "20s"
  max_request_bytes: 1048576      # JSON bodies; ciphertext routes use their own limits
  dev_insecure_cookies: false

data_dir: "/data"                 # single directory; db + blobs + secrets live here

secrets:
  pairing_secret: ""              # empty => load-or-create <data_dir>/secrets/pairing.key
  server_salt_key: ""             # empty => load-or-create <data_dir>/secrets/serversalt.key

limits:
  attachment_max_bytes: 26214400  # 25 MiB
  chunk_bytes: 4194304            # 4 MiB
  object_max_bytes: 10485760      # 10 MiB of ciphertext per note version
  upload_session_ttl: "15m"
  user_quota_bytes: 1073741824    # 1 GiB, 0 = unlimited
  team_quota_bytes: 5368709120    # 5 GiB, 0 = unlimited

gc:
  enabled: true
  retention: "168h"               # 7 days
  interval: "1h"

ratelimit:
  login_per_minute: 10
  pairing_per_hour: 20
  upload_per_minute: 60

log:
  level: "info"                   # debug|info|warn|error
  format: "json"                  # json|text
```

**Startup validation — the server refuses to start (exit code 2, one clear log
line) when:**

1. `data_dir` is empty, does not exist, or is not writable.
2. `data_dir` resolves inside `/tmp` while `dev_insecure_cookies` is false.
3. `server.bind` is missing or unparseable.
4. `dev_insecure_cookies` is true and `server.bind` host is not `127.0.0.1`,
   `::1`, or `localhost`.
5. `limits.chunk_bytes` < 65536 or > `limits.attachment_max_bytes`.
6. `limits.attachment_max_bytes` < `limits.chunk_bytes`.
7. `gc.retention` < `1h` while `gc.enabled` is true.
8. `secrets.pairing_secret` is non-empty and shorter than 32 characters.
9. `server.behind_proxy` is true and `trusted_proxies` is empty.
10. Any duration or byte-size field fails to parse.

A *disabled* pairing secret (unset, generated file unreadable) does **not**
prevent startup: it disables pairing and every pairing route answers `503
unavailable`. That distinction is deliberate — a broken optional capability that
says so is better than a server that will not boot.

Secrets are 32 random bytes generated on first start with mode `0600` under
`<data_dir>/secrets/`, stored base64. Never written to the SQLite database.

### 1.10 Identifier contract

```go
// internal/ids
// Mint returns prefix + "_" + base32(crockford, lowercase, no padding) of 16 random bytes.
// Example: "obj_7k9m2ptqv3xe4wnr8ha6cdz5fy"
```

| Entity | Prefix |
|---|---|
| user | `usr` |
| session | `ses` |
| device | `dev` |
| container | `cnt` |
| membership | `mem` |
| key envelope | `env` |
| object | `obj` |
| conflict record | `cfl` |
| attachment | `att` |
| upload session | `ups` |
| audit event | `aud` |
| request | `req` |
| invitation | `inv` |
| comment | `cmt` |

IDs are opaque, log-safe, and never encode user data. `ids.Validate(prefix, s)`
checks prefix, separator, length (26 chars of base32), and alphabet. Every
handler validates path IDs before touching the database.

### 1.11 Versioning and cursor contract

* Each mutable object has `current_version int64`, starting at `1` for the first
  accepted write and incrementing by exactly `1`.
* A save carries `baseVersion`. `baseVersion == current_version` → accept as
  `current_version + 1`. Otherwise → reject with `409 version_conflict` **and
  persist the rejected ciphertext as a conflict record** (never discard it).
* `baseVersion == 0` means "create"; it is valid only when the object does not
  yet exist.
* Each container has `change_seq int64`, incremented once per accepted mutation
  inside the same transaction as the mutation. Every mutated row records the
  `change_seq` value it was written at.
* A sync cursor is the decimal string of a `change_seq`. `GET
  /api/v1/containers/{id}/changes?since=<cursor>&limit=<n>` returns rows with
  `change_seq > since` in ascending `change_seq` order. Default `limit` 200, max
  1000. The response carries `nextCursor` (highest `change_seq` returned, or the
  request's `since` when empty) and `hasMore`.
* Deletions are soft: the row stays with `deleted_at` set and a fresh
  `change_seq`, so a client that was offline learns about the deletion. Hard
  removal happens only in GC after retention.

### 1.12 Blob and chunk contract

| Item | Frozen value |
|---|---|
| Digest | lowercase hex SHA-256 **of the ciphertext** |
| On-disk path | `<data_dir>/blobs/<d[0:2]>/<d[2:4]>/<d>` |
| Temp path | `<data_dir>/tmp/<uploadSessionID>.part` |
| File mode | `0600`; directories `0700` |
| Finalize | `fsync(tempfile)` → `rename(temp, final)` → `fsync(parent dir)` |
| Chunk size | `limits.chunk_bytes`, default 4 MiB; every chunk except the last must be exactly this size |
| Max attachment | `limits.attachment_max_bytes`, default 25 MiB |
| Dedup scope | container (`blob_containers` table); a digest existing in another container is invisible |

**Ordering invariant (this is the whole point of Phase 2):**

> Write the blob to its final content-addressed path **before** committing the
> metadata transaction that references it.

Consequences, both required:

* Metadata can never reference a blob that is not on disk.
* A crash between blob finalize and metadata commit leaves an *unreferenced*
  blob, which is safe and is exactly what garbage collection reclaims.

Never do it in the other order. Never delete a blob inside a request handler;
only the GC sweeper deletes blobs.

### 1.13 Migration contract

Numbered SQL files, embedded, applied in order, each in its own transaction:

```
internal/storage/migrations/0001_init.sql
internal/storage/migrations/0002_....sql
```

```go
//go:embed migrations/*.sql
var migrationFS embed.FS
```

Rules:

* Filenames are `NNNN_snake_case.sql`, zero-padded to 4 digits, strictly
  increasing, no gaps.
* Applied versions are recorded in `schema_migrations(version INTEGER PRIMARY
  KEY, applied_at TEXT NOT NULL)`.
* A migration file that has already been applied is **never** re-read or
  re-checked; a file that changes after being applied is not detected and must
  not happen. Add a new file instead.
* Migrations run inside `BEGIN IMMEDIATE` so two processes starting at once
  cannot race (`_txlock=immediate` in the DSN makes this the default).
* No `CREATE TABLE IF NOT EXISTS` as a migration strategy. KyPost's own comments
  record why that path required a separate additive-column mechanism; do not
  repeat it.

**SQLite DSN** — frozen:

```go
fmt.Sprintf("file:%s?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)", path)
```

`db.SetMaxOpenConns(1)` for the writer handle is **not** used; instead all
writes go through `BEGIN IMMEDIATE` transactions and rely on `busy_timeout`.
Reads use the same pool.

### 1.14 Quota contract

* A user's usage = sum of `ciphertext_bytes` over: accepted object versions,
  conflict records, and attachments, for every container the user *owns*
  (`containers.owner_user_id`).
* A team's usage = the same sum over containers whose `team_id` matches.
* A blob shared by two containers counts once per container that references it.
  Deduplication saves disk, not quota. This is deliberate: making quota depend
  on other containers' contents leaks their contents.
* Enforcement happens **twice**: at upload-session creation against the declared
  size, and at finalize against the actual size. Finalize is the authoritative
  check.
* Over quota → `413 quota_exceeded`. The upload session is marked `failed` and
  its temp file is removed.
* `0` means unlimited.

### 1.15 Garbage-collection contract

* GC runs on a ticker every `gc.interval`, and never inside a request handler.
* Pass 1 — **expire uploads**: upload sessions older than
  `limits.upload_session_ttl` with status `pending` become `expired`; their temp
  files are removed. Expired sessions stay visible to the owner for 24 hours so
  the client can show a failed upload, then the row is deleted.
* Pass 2 — **mark**: for every blob with no live reference (no accepted object
  version, no unresolved conflict, no live attachment), set `unreferenced_since`
  if unset. If a reference reappears, clear it.
* Pass 3 — **sweep**: delete blobs whose `unreferenced_since` is older than
  `gc.retention`; delete the file first, then the row, and tolerate a missing
  file.
* Pass 4 — **purge tombstones**: rows soft-deleted longer ago than
  `gc.retention` are removed.
* `gc.enabled: false` disables passes 2–4 only. Upload expiry always runs —
  otherwise temp files grow without bound and the 15-minute expiry contract
  breaks.
* Every sweep logs one summary line: counts only, no digests.

---

## 2. Phase 1 — Server foundation

**Goal**: a binary that starts, validates its configuration, serves health and
readiness, logs safely, shuts down cleanly, and **cannot serve any user data**.

### 2.1 Files to create

```
go.mod, go.sum
Makefile
Dockerfile
.dockerignore
cmd/kynotes-server/main.go
internal/config/config.go
internal/config/config_test.go
internal/logging/logger.go
internal/logging/logger_test.go
internal/health/checker.go
internal/health/checker_test.go
internal/httpapi/router.go
internal/httpapi/errors.go
internal/httpapi/errors_test.go
internal/httpapi/middleware.go
internal/httpapi/middleware_test.go
internal/app/serve.go
internal/app/serve_test.go
internal/ids/ids.go
internal/ids/ids_test.go
kynotes.example.yaml
```

### 2.2 Behaviour

* `main.go` parses flags (`--config`, `--version`, `--check-config`), loads
  config, builds the logger, calls `app.Serve(ctx, cfg)`, and returns exit code
  `0` on clean shutdown, `2` on configuration failure, `1` on runtime failure.
* `--check-config` validates and exits without binding a port. This is what the
  Docker `HEALTHCHECK` and the operator's pre-flight use.
* Shutdown: `signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)`, then
  `srv.Shutdown(ctxWithTimeout(server.shutdown_grace))`. In-flight requests
  finish; new ones get connection refusal from the closed listener.
* `GET /healthz` → `200 {"status":"ok"}` whenever the process is alive. Never
  touches the database. No authentication.
* `GET /readyz` → `200 {"status":"ready"}` only when: config validated, data
  directory writable, database open and `PRAGMA quick_check` clean at startup,
  migrations applied, blob root writable. Otherwise `503` with
  `{"error":{"code":"unavailable",...}}` and a `checks` object of boolean
  results. No authentication, no detail beyond check names.
* Every request passes through, in order:
  1. `requestID` — reads `X-Request-Id` **only** from a trusted proxy, else
     mints `req_...`; always sets the response header.
  2. `recoverPanic` — logs `panic` with the request ID and stack to the logger
     only, answers `500 internal`.
  3. `limitBody` — `http.MaxBytesReader` at `server.max_request_bytes` for JSON
     routes.
  4. `accessLog` — method, route pattern (not the raw path, which contains IDs),
     status, byte count, duration bucketed to milliseconds, request ID.
  5. `securityHeaders` — `X-Content-Type-Options: nosniff`,
     `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on every API
     response, `Content-Security-Policy: default-src 'none'`.
* The router registers **only** `/healthz` and `/readyz` in this phase. Any
  other path answers `404 not_found` through the standard error envelope.

### 2.3 Logging

`internal/logging` wraps `log/slog` with a JSON handler on stdout. Exposed
methods take a message and typed attributes. It ships a **field allowlist**: an
attribute whose key is not in the allowlist is dropped and replaced with
`"dropped_fields": n`. Allowlist:

```
request_id, route, method, status, duration_ms, bytes, event, outcome,
user_id, device_id, container_id, object_id, attachment_id, upload_id,
session_id, audit_id, count, reason_code, retry_after_s, version, error_kind
```

`error_kind` is a fixed enum string, never `err.Error()` — an error string can
contain a filename or a SQL fragment with user bytes. Wrapped errors are logged
by classification only.

### 2.4 Docker

* Multi-stage. Builder `golang:1.26.6` pinned **by digest as well as tag**
  (resolve with `docker buildx imagetools inspect golang:1.26.6 --format
  '{{.Manifest.Digest}}'` and write both).
* Runtime stage `gcr.io/distroless/static-debian12:nonroot`, also digest-pinned.
  There is no shell and no package manager in the runtime image.
* `USER nonroot`, `EXPOSE 8080`, `VOLUME /data`.
* `HEALTHCHECK CMD ["/kynotes-server","--check-config"]` — works without a shell
  or curl.
* Build: `RUN CGO_ENABLED=0 go build -trimpath -o /kynotes-server ./cmd/kynotes-server`.

### 2.5 Tests (exact names)

`internal/config`:
- `TestLoadDefaultsMatchExampleFile`
- `TestEnvOverridesFile`
- `TestMissingDataDirIsRefused`
- `TestUnwritableDataDirIsRefused`
- `TestInsecureCookiesRefusedOnNonLoopbackBind`
- `TestShortPairingSecretIsRefused`
- `TestChunkSizeLargerThanAttachmentLimitIsRefused`
- `TestGCRetentionBelowOneHourIsRefused`
- `TestBehindProxyWithoutTrustedProxiesIsRefused`
- `TestUnparseableDurationIsRefused`
- `TestValidationErrorNamesTheOffendingKey`

`internal/logging`:
- `TestDisallowedFieldIsDropped`
- `TestErrorStringIsNeverLogged`
- `TestOutputIsValidJSONLines`

`internal/httpapi`:
- `TestUnknownRouteReturnsErrorEnvelope`
- `TestErrorEnvelopeShapeIsStable`
- `TestRequestIDIsEchoedAndGeneratedWhenUntrusted`
- `TestPanicBecomesInternalWithoutLeakingStack`
- `TestSecurityHeadersOnEveryResponse`
- `TestOversizedJSONBodyIsRejected`

`internal/app`:
- `TestHealthzIgnoresDatabaseState`
- `TestReadyzFailsBeforeMigrations`
- `TestGracefulShutdownDrainsInFlightRequest`
- `TestServeRefusesToStartOnInvalidConfig`
- `TestNoUserDataRouteIsRegistered` — enumerates the router's registered
  patterns and asserts the set is exactly `{"GET /healthz", "GET /readyz"}`.

`internal/ids`:
- `TestMintHasPrefixAndFixedLength`
- `TestValidateRejectsWrongPrefix`
- `TestValidateRejectsBadAlphabet`
- `TestMintIsUnpredictable` (10k mints, no duplicates, byte-histogram sanity)

Docker: `scripts/test-docker-health.sh` builds the image, runs
`--check-config` against a good and a bad config, and asserts exit codes 0 and 2.

### 2.6 Exit gate

```
go build ./... && go vet ./... && gofmt -l . && go test -race ./...
docker build -t kynotes-server:dev .
docker run --rm -v "$PWD/testdata/config-good:/data" kynotes-server:dev --check-config   # exit 0
docker run --rm -v "$PWD/testdata/config-bad:/data"  kynotes-server:dev --check-config   # exit 2
```

All must pass, and `TestNoUserDataRouteIsRegistered` must be green.

---

## 3. Phase 2 — Storage primitives

**Goal**: SQLite metadata store and content-addressed blob store, with the
transaction ordering of §1.12 proven under crash-like failures.

### 3.1 Files

```
internal/storage/store.go            # Open, Close, migrate, WithTx, quick_check
internal/storage/migrations/0001_init.sql
internal/storage/store_test.go
internal/storage/migrate_test.go
internal/blobstore/blobstore.go      # Put, Open, Stat, Delete, Digest, temp lifecycle
internal/blobstore/blobstore_test.go
internal/blobstore/paths.go
```

### 3.2 `0001_init.sql` — complete schema

Write it exactly as follows. Timestamps are RFC3339 UTC strings. Empty string
means "not set" (never `NULL`, so every scan target is a plain Go value).

```sql
CREATE TABLE schema_migrations (
  version    INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE users (
  id               TEXT PRIMARY KEY,
  username         TEXT NOT NULL UNIQUE,
  auth_secret_hash TEXT NOT NULL,
  login_salt       TEXT NOT NULL,
  login_iterations INTEGER NOT NULL,
  recovery_hash    TEXT NOT NULL DEFAULT '',
  recovery_used_at TEXT NOT NULL DEFAULT '',
  role             TEXT NOT NULL DEFAULT 'user',      -- user|admin
  status           TEXT NOT NULL DEFAULT 'active',    -- active|disabled
  quota_bytes      INTEGER NOT NULL DEFAULT 0,        -- 0 = server default
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE TABLE sessions (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash      TEXT NOT NULL UNIQUE,
  csrf_hash       TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  expires_at      TEXT NOT NULL,
  hard_expires_at TEXT NOT NULL,
  revoked_at      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE devices (
  id               TEXT PRIMARY KEY,
  user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key       TEXT NOT NULL,
  fingerprint      TEXT NOT NULL,
  secret_hash      TEXT NOT NULL,
  label_ciphertext BLOB NOT NULL DEFAULT x'',
  platform         TEXT NOT NULL DEFAULT 'unknown',   -- web|android|ios|unknown
  created_at       TEXT NOT NULL,
  last_seen_at     TEXT NOT NULL DEFAULT '',
  revoked_at       TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_devices_user_fingerprint ON devices(user_id, fingerprint);
CREATE INDEX idx_devices_user ON devices(user_id);

CREATE TABLE pairing_nonces (
  nonce      TEXT PRIMARY KEY,
  purpose    TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  used_at    TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE containers (
  id              TEXT PRIMARY KEY,
  kind            TEXT NOT NULL,                       -- workbook|project|team
  owner_user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  team_id         TEXT NOT NULL DEFAULT '',
  key_generation  INTEGER NOT NULL DEFAULT 1,
  change_seq      INTEGER NOT NULL DEFAULT 0,
  meta_ciphertext BLOB NOT NULL DEFAULT x'',           -- encrypted name/settings
  meta_version    INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  deleted_at      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_containers_owner ON containers(owner_user_id);
CREATE INDEX idx_containers_team ON containers(team_id);

CREATE TABLE memberships (
  id           TEXT PRIMARY KEY,
  container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role         TEXT NOT NULL,                          -- owner|admin|editor|commenter|viewer
  created_at   TEXT NOT NULL,
  revoked_at   TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_memberships_container_user ON memberships(container_id, user_id);
CREATE INDEX idx_memberships_user ON memberships(user_id);

CREATE TABLE key_envelopes (
  id             TEXT PRIMARY KEY,
  container_id   TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  device_id      TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  key_generation INTEGER NOT NULL,
  alg            TEXT NOT NULL,
  envelope       BLOB NOT NULL,
  created_at     TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_envelopes_container_device_gen
  ON key_envelopes(container_id, device_id, key_generation);
CREATE INDEX idx_envelopes_device ON key_envelopes(device_id);

CREATE TABLE device_containers (
  device_id    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  selected_at  TEXT NOT NULL,
  PRIMARY KEY (device_id, container_id)
);

CREATE TABLE blobs (
  digest             TEXT PRIMARY KEY,                 -- hex sha256 of ciphertext
  size_bytes         INTEGER NOT NULL,
  created_at         TEXT NOT NULL,
  unreferenced_since TEXT NOT NULL DEFAULT ''
);

CREATE TABLE blob_containers (
  digest        TEXT NOT NULL REFERENCES blobs(digest) ON DELETE CASCADE,
  container_id  TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  first_seen_at TEXT NOT NULL,
  PRIMARY KEY (digest, container_id)
);

CREATE TABLE objects (
  id              TEXT PRIMARY KEY,
  container_id    TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  kind            TEXT NOT NULL,                       -- note|folder
  current_version INTEGER NOT NULL DEFAULT 0,
  change_seq      INTEGER NOT NULL,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  deleted_at      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_objects_container_seq ON objects(container_id, change_seq);

CREATE TABLE object_versions (
  object_id        TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  version          INTEGER NOT NULL,
  blob_digest      TEXT NOT NULL REFERENCES blobs(digest),
  ciphertext_bytes INTEGER NOT NULL,
  key_generation   INTEGER NOT NULL,
  author_device_id TEXT NOT NULL DEFAULT '',
  base_version     INTEGER NOT NULL DEFAULT 0,
  change_seq       INTEGER NOT NULL,
  created_at       TEXT NOT NULL,
  PRIMARY KEY (object_id, version)
);
CREATE INDEX idx_object_versions_digest ON object_versions(blob_digest);

CREATE TABLE conflicts (
  id               TEXT PRIMARY KEY,
  object_id        TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  container_id     TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  base_version     INTEGER NOT NULL,
  current_version  INTEGER NOT NULL,
  blob_digest      TEXT NOT NULL REFERENCES blobs(digest),
  ciphertext_bytes INTEGER NOT NULL,
  key_generation   INTEGER NOT NULL,
  device_id        TEXT NOT NULL DEFAULT '',
  change_seq       INTEGER NOT NULL,
  created_at       TEXT NOT NULL,
  resolved_at      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_conflicts_object ON conflicts(object_id);
CREATE INDEX idx_conflicts_digest ON conflicts(blob_digest);

CREATE TABLE attachments (
  id                  TEXT PRIMARY KEY,
  container_id        TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  blob_digest         TEXT NOT NULL REFERENCES blobs(digest),
  preview_digest      TEXT NOT NULL DEFAULT '',
  ciphertext_bytes    INTEGER NOT NULL,
  metadata_ciphertext BLOB NOT NULL,
  key_generation      INTEGER NOT NULL,
  change_seq          INTEGER NOT NULL,
  created_at          TEXT NOT NULL,
  deleted_at          TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_attachments_container_digest ON attachments(container_id, blob_digest);
CREATE INDEX idx_attachments_container_seq ON attachments(container_id, change_seq);
CREATE INDEX idx_attachments_preview ON attachments(preview_digest);

CREATE TABLE attachment_refs (
  attachment_id  TEXT NOT NULL REFERENCES attachments(id) ON DELETE CASCADE,
  object_id      TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  object_version INTEGER NOT NULL,
  created_at     TEXT NOT NULL,
  PRIMARY KEY (attachment_id, object_id, object_version)
);
CREATE INDEX idx_attachment_refs_object ON attachment_refs(object_id);

CREATE TABLE upload_sessions (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  container_id    TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  kind            TEXT NOT NULL DEFAULT 'attachment',  -- attachment|preview
  declared_bytes  INTEGER NOT NULL,
  chunk_bytes     INTEGER NOT NULL,
  expected_digest TEXT NOT NULL DEFAULT '',
  received_bytes  INTEGER NOT NULL DEFAULT 0,
  next_chunk      INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'pending',     -- pending|finalized|failed|expired
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  expires_at      TEXT NOT NULL,
  finalized_at    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_upload_sessions_expiry ON upload_sessions(status, expires_at);
CREATE INDEX idx_upload_sessions_user ON upload_sessions(user_id, status);

CREATE TABLE audit_events (
  id              TEXT PRIMARY KEY,
  at              TEXT NOT NULL,
  event           TEXT NOT NULL,
  outcome         TEXT NOT NULL,                       -- success|failure|denied
  actor_user_id   TEXT NOT NULL DEFAULT '',
  actor_device_id TEXT NOT NULL DEFAULT '',
  container_id    TEXT NOT NULL DEFAULT '',
  object_id       TEXT NOT NULL DEFAULT '',
  request_id      TEXT NOT NULL DEFAULT '',
  reason_code     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_audit_at ON audit_events(at);
CREATE INDEX idx_audit_actor ON audit_events(actor_user_id, at);

CREATE TABLE idempotency_keys (
  key          TEXT PRIMARY KEY,                       -- sha256(userID + "\x00" + route + "\x00" + clientKey)
  response_id  TEXT NOT NULL,
  status_code  INTEGER NOT NULL,
  created_at   TEXT NOT NULL
);
CREATE INDEX idx_idempotency_created ON idempotency_keys(created_at);
```

`audit_events` has **no free-text detail column**. Anything worth recording is
an enum in `event` or `reason_code`. This is how "audit records must remain
content-blind" (LOGGING.md) is enforced structurally rather than by discipline.

### 3.3 `internal/storage` API

```go
func Open(path string) (*Store, error)      // opens with the frozen DSN, runs migrations, quick_check
func (s *Store) Close() error
func (s *Store) WithTx(ctx context.Context, fn func(*sql.Tx) error) error  // BEGIN IMMEDIATE, rollback on error
func (s *Store) IntegrityCheck(ctx context.Context) error                  // PRAGMA integrity_check
func (s *Store) NextChangeSeq(tx *sql.Tx, containerID string) (int64, error)
```

`NextChangeSeq` does `UPDATE containers SET change_seq = change_seq + 1 WHERE id
= ? RETURNING change_seq` inside the caller's transaction. It is the only way a
`change_seq` is produced. Never compute one in Go.

### 3.4 `internal/blobstore` API

```go
func New(root string) (*Store, error)              // creates root/blobs and root/tmp with 0700
func (s *Store) NewTemp(id string) (*Temp, error)  // creates root/tmp/<id>.part, 0600
func (t *Temp) Write(p []byte) (int, error)        // streams, updating a running sha256 and byte count
func (t *Temp) Digest() string                     // hex of the running hash
func (t *Temp) Size() int64
func (t *Temp) Finalize(expectedDigest string) (digest string, size int64, err error)
func (t *Temp) Abort() error                       // close + remove; safe to call twice
func (s *Store) Open(digest string) (io.ReadSeekCloser, int64, error)
func (s *Store) Stat(digest string) (int64, bool, error)
func (s *Store) Delete(digest string) error        // GC only; missing file is not an error
func (s *Store) Reopen(id string) (*Temp, error)   // resume: reopens the part file and REHASHES it
```

`Finalize` rules:
* Reject with `ErrDigestMismatch` when `expectedDigest != ""` and the running
  digest differs. The temp file is aborted.
* If the destination path already exists with the same size, treat as success
  and remove the temp — duplicate content is not an error.
* If the destination exists with a *different* size, return `ErrCorruptBlob` and
  do not overwrite. This can only happen after disk corruption; log it and let
  the operator run the consistency check (Phase 9).
* Order is `Sync(file)` → `rename` → `Sync(parentDir)`. All three must succeed.

`Reopen` re-hashes the existing bytes rather than trusting a stored digest,
because a crash mid-`Write` can leave a partial trailing chunk. Resume is
therefore always correct, at the cost of one read pass.

### 3.5 Tests

`internal/storage`:
- `TestOpenAppliesMigrationsOnce`
- `TestOpenIsIdempotentAcrossRestarts`
- `TestMigrationVersionsAreContiguous` — reads the embedded FS, asserts 1..N
- `TestConcurrentOpenDoesNotRaceMigrations` — two `Open` calls in goroutines
- `TestWithTxRollsBackOnError`
- `TestNextChangeSeqIsStrictlyIncreasingUnderConcurrency` — 100 goroutines,
  assert 100 distinct ascending values
- `TestForeignKeysAreEnforced`
- `TestWALModeIsActive`
- `TestIntegrityCheckPassesOnFreshDatabase`

`internal/blobstore`:
- `TestPutThenOpenRoundTrips`
- `TestFinalizeRejectsDigestMismatch`
- `TestFinalizeIsIdempotentForDuplicateContent`
- `TestFinalizeRefusesToOverwriteDifferentSize`
- `TestAbortRemovesTempFile`
- `TestAbortIsSafeTwice`
- `TestReopenRehashesPartialFile`
- `TestOpenMissingBlobReportsNotFound`
- `TestDeleteMissingBlobIsNotAnError`
- `TestFileModesAre0600AndDirs0700`
- `TestPathShardingSplitsOnFirstFourHexChars`

Cross-cutting crash tests (`internal/storage/crash_test.go`) — these are the
Phase 2 deliverable that matters most:
- `TestBlobSurvivesMetadataTransactionFailure` — finalize blob, then force the
  metadata tx to fail; assert the blob file exists, no metadata row references
  it, and a restart plus GC mark pass flags it unreferenced.
- `TestMetadataNeverReferencesUnfinalizedBlob` — attempt the wrong ordering in a
  test helper and assert the store API makes it impossible (the commit path
  requires a finalized digest argument).
- `TestRestartRecoversPendingUploadSession`
- `TestDuplicateBlobFromTwoContainersSharesOneFile` — one file on disk, two
  `blob_containers` rows.
- `TestMissingBlobIsDetectedByConsistencyCheck`

### 3.6 Exit gate

`go test -race ./internal/storage/... ./internal/blobstore/...` green, and a
manual check: create a blob, kill the process before commit (`kill -9` in a
subprocess test), restart, confirm the database is consistent and
`PRAGMA integrity_check` returns `ok`.

**Milestone 1 is complete when Phase 1 and Phase 2 both pass their gates.**

---

## 4. Phase 3 — Authentication and sessions

### 4.1 Files

```
internal/auth/derive.go        # DeriveAuthSecret, validateLoginSalt, validateLoginIterations
internal/auth/hash.go          # HashAuthSecret, VerifyAuthSecret, kdf slot semaphore
internal/auth/session.go       # mint, resolve, slide, revoke, sweep
internal/auth/lockout.go       # failureLockout: tryAttempt, cancelAttempt, recordSuccess, sweep, shed
internal/auth/recovery.go
internal/auth/middleware.go    # RequireSession, RequireDevice, RequireEither, RequireFresh, RequireAdmin
internal/httpapi/auth_routes.go
internal/storage/migrations/0002_auth.sql   # only if Phase 3 needs a column 0001 lacks
```

Plus a `TestMain`-level hook so tests can lower `scryptN` (mirroring KyPost's
`hashCostN` override) — **and** a `TestProductionScryptCostIsUnchanged` guard so
the test hook can never silently become production.

### 4.2 Endpoints

| Method | Path | Credential | Body → Response |
|---|---|---|---|
| POST | `/api/v1/auth/login-params` | none | `{"username":"..."}` → `{"loginSalt":"<b64>","iterations":600000}` |
| POST | `/api/v1/auth/login` | none | `{"username":"...","authSecret":"<hex64>"}` → sets cookies, `{"user":{"id":"usr_...","role":"user"}}` |
| GET | `/api/v1/auth/session` | session | → `{"user":{...},"expiresAt":"...","hardExpiresAt":"..."}` |
| POST | `/api/v1/auth/logout` | session + CSRF | → `204`, clears both cookies, revokes the row |
| POST | `/api/v1/auth/logout-all` | session + CSRF + fresh | → `204`, revokes every session for the user |
| POST | `/api/v1/auth/recover` | none | `{"username","recoveryCode","newAuthSecret","newLoginSalt","iterations","newRecoveryCode"}` → `204` |

Login-params must answer identically in shape and timing for known and unknown
usernames (§1.3). Login must perform its scrypt work even when the username is
unknown.

Recovery, when it succeeds, does all of this in one transaction:
1. Replaces `auth_secret_hash`, `login_salt`, `login_iterations`.
2. Replaces `recovery_hash` with the hash of the *new* recovery code (scrypt,
   same format as the auth secret). A recovery that does not supply a
   replacement code is `400 invalid_request` — the code is single-use and must
   be replaced.
3. Marks **every** device `revoked_at`.
4. Deletes **every** `key_envelopes` row for those devices.
5. Marks **every** session `revoked_at`.
6. Writes an `audit_events` row `event=account.recovery`.

### 4.3 Middleware semantics

* `RequireSession` — resolves the cookie, hashes it, looks up by `token_hash`,
  rejects when `revoked_at != ""`, `now > expires_at`, or `now >
  hard_expires_at`. Slides `expires_at` only when it has moved by at least
  `sessionSlideGranularity`. Loads the user and rejects when `status !=
  "active"`.
* `RequireDevice` — §1.5 headers; resolves the device, checks lockout **after**
  resolving the device ID to a real row (resolving first is what stops an
  anonymous caller from minting lockout entries for invented IDs), verifies the
  secret hash in constant time, rejects revoked devices and disabled users. A
  *correct* secret on a revoked device or disabled account calls
  `cancelAttempt`, not a bare return — the strike goes back, so a legitimate
  client is not backed off forever for a condition it cannot fix by retrying.
* `RequireEither` — tries device headers first, then session; never both.
* `RequireFresh` — §1.8.
* `RequireAdmin` — session with `users.role = "admin"`.

### 4.4 Tests

- `TestDeriveAuthSecretMatchesFixture` — pinned against
  `testdata/protocol/auth_vectors.json`, which is generated once and then frozen.
  Any change to the derivation must break this test.
- `TestDeriveAuthSecretRejectsShortSalt` / `TestDeriveAuthSecretRejectsBadBase64`
- `TestIterationsBelowMinimumRejected` / `TestIterationsAboveMaximumRejected`
- `TestProductionScryptCostIsUnchanged`
- `TestHashVerifyRoundTrip` / `TestVerifyRejectsWrongSecret`
- `TestVerifyParsesStoredCostParameters`
- `TestLoginParamsAreIndistinguishableForUnknownUser`
- `TestLoginPerformsKDFWorkForUnknownUser`
- `TestLoginSucceedsAndSetsBothCookies`
- `TestSessionCookieIsHttpOnlySecureLax`
- `TestCSRFCookieIsReadableByJS`
- `TestMutatingRequestWithoutCSRFHeaderIsRejected`
- `TestSessionSlidesOnlyPastGranularity`
- `TestSessionExpiresAfterIdleTimeout`
- `TestSessionExpiresAtHardLifetimeDespiteActivity`
- `TestRevokedSessionIsRejectedImmediately`
- `TestLogoutAllRevokesEverySession`
- `TestLockoutAfterThreeFailedLogins`
- `TestLockoutIsScopedToUsernameAndIP`
- `TestLockoutAppliesToUnknownUsernamesToo`
- `TestLockoutTableShedsNewKeysWithoutEvictingLiveLockouts`
- `TestCorrectSecretOnRevokedDeviceDoesNotBurnStrike`
- `TestDeviceLockoutRequiresResolvableDeviceID`
- `TestRecoveryRevokesAllDevicesSessionsAndEnvelopes`
- `TestRecoveryWithoutReplacementCodeIsRejected`
- `TestRecoveryCodeIsSingleUse`
- `TestDisabledUserCannotUseValidSessionOrDevice`
- `TestAuthFailureLogsNoSecretMaterial` — captures log output, asserts no
  substring of the secret, token, or salt appears.

### 4.5 Exit gate

All Phase 3 tests green under `-race`, plus `TestNoUserDataRouteIsRegistered`
updated to the new expected route set (it is a whitelist and must be edited
deliberately every phase).

---

## 5. Phase 4 — Containers and device enrollment

### 5.1 Endpoints

| Method | Path | Credential | Notes |
|---|---|---|---|
| GET | `/api/v1/containers` | either | containers the caller is a member of; device credential sees only its selected containers |
| POST | `/api/v1/containers` | session + CSRF | `{"kind":"workbook\|project\|team","metaCiphertext":"<b64>"}` → creates container + `owner` membership + `change_seq` 1 |
| PATCH | `/api/v1/containers/{id}` | either | `{"metaCiphertext":"<b64>","baseVersion":n}` → §1.11 rules on `meta_version` |
| DELETE | `/api/v1/containers/{id}` | session + CSRF + fresh | soft delete, role `owner` only |
| GET | `/api/v1/devices` | session | id, fingerprint, platform, created/last-seen, revoked; never the secret |
| POST | `/api/v1/devices/pairing-token` | session + CSRF + fresh | → `{"token":"...","expiresAt":"...","deepLink":"kynotes://pair?..."}` |
| POST | `/api/v1/devices/register` | pairing token | `{"pairingToken","publicKey","platform","labelCiphertext"}` → `{"deviceId","deviceSecret","fingerprint"}` |
| DELETE | `/api/v1/devices/{id}` | session + CSRF + fresh | revoke: set `revoked_at`, delete envelopes, delete `device_containers` |
| GET | `/api/v1/devices/{id}/containers` | session, or that device | selected container IDs |
| PUT | `/api/v1/devices/{id}/containers` | session + CSRF, or that device | `{"containerIds":[...]}`, replaces the selection |
| GET | `/api/v1/containers/{id}/envelopes` | either | session: all envelopes for the container. device: **only** the row where `device_id` is the calling device |
| PUT | `/api/v1/containers/{id}/envelopes` | session + CSRF + fresh | `{"envelopes":[{"deviceId","keyGeneration","alg","envelope":"<b64>"}]}` |

### 5.2 Rules

* `publicKey` must decode (standard base64) to exactly 32 bytes. Anything else
  is `400 invalid_request`. The fingerprint is computed server-side; a
  client-supplied fingerprint field is ignored, not trusted.
* Registering a public key that already exists for that user returns the
  existing device ID **and a freshly minted secret**, replacing the old hash.
  Re-pairing a phone must not create a second device row.
* `alg` is validated against the allowlist `{"x25519-hkdf-sha256-chacha20poly1305"}`.
  Unknown algorithms are `400`. The server never parses the envelope bytes.
* Envelope bytes are capped at 4096 bytes.
* Revoking a device is a single transaction: `revoked_at`, envelope delete,
  selection delete, audit row.
* A device credential may never write envelopes, mint pairing tokens, list other
  devices, or read another device's envelope. Each of those is a named test.

### 5.3 Tests

- `TestPairingTokenExpiresAfter120Seconds`
- `TestPairingTokenIsSingleUse`
- `TestReplayedPairingTokenIsRejectedAfterNonceConsumed`
- `TestPairingTokenForgedSignatureIsRejected`
- `TestPairingTokenWrongPurposeIsRejected`
- `TestPairingDisabledWhenSecretMissingReturns503`
- `TestRegisterRejectsNon32BytePublicKey`
- `TestFingerprintIsServerComputedNotClientSupplied`
- `TestRePairingSamePublicKeyReusesDeviceRow`
- `TestDeviceSecretIsReturnedOnceAndNeverAgain`
- `TestDeviceCannotReadAnotherDevicesEnvelope`
- `TestDeviceCannotWriteEnvelopes`
- `TestDeviceCannotMintPairingToken`
- `TestRevokedDeviceLosesEnvelopesAndAccess`
- `TestRevokedDeviceCredentialIsRejectedImmediately`
- `TestNonMemberContainerAccessReturns404NotForbidden`
- `TestMemberWithViewerRoleCannotDeleteContainer`
- `TestUnknownAlgIsRejected`
- `TestOversizedEnvelopeIsRejected`
- `TestSyncSelectionLimitsDeviceContainerListing`
- `TestContainerMetaUsesBaseVersionConflictRule`

---

## 6. Phase 5 — Encrypted object synchronization

### 6.1 Endpoints

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/api/v1/containers/{id}/objects` | JSON `{"kind":"note\|folder"}` | mints an object ID at version 0; no content |
| PUT | `/api/v1/objects/{id}` | `application/octet-stream` ciphertext | headers `X-Kynotes-Base-Version`, `X-Kynotes-Key-Generation`, optional `Idempotency-Key` |
| GET | `/api/v1/objects/{id}` | — | `?version=` optional, defaults to current; returns `application/octet-stream` + metadata headers |
| DELETE | `/api/v1/objects/{id}` | — | soft delete, releases attachment refs |
| GET | `/api/v1/objects/{id}/conflicts` | — | list of conflict records (metadata only) |
| GET | `/api/v1/conflicts/{id}` | — | the rejected ciphertext |
| POST | `/api/v1/conflicts/{id}/resolve` | — | sets `resolved_at`; the blob becomes GC-eligible |
| GET | `/api/v1/containers/{id}/changes` | — | `?since=&limit=`, §1.11 |

Response headers on object GET: `X-Kynotes-Version`, `X-Kynotes-Key-Generation`,
`X-Kynotes-Digest`, `X-Kynotes-Change-Seq`, `Content-Length`.

### 6.2 The save path, in order (do not reorder)

1. Authorize: caller is a member of the object's container with role `editor` or
   higher.
2. Reject bodies over `limits.object_max_bytes` with `413 payload_too_large`
   (`http.MaxBytesReader`).
3. Stream the body into a `blobstore.Temp`, computing the digest as it goes.
4. `Finalize("")` — the blob is now on disk and content-addressed.
5. Open a write transaction:
   * Re-read `objects.current_version`.
   * If `baseVersion == current_version`: insert `object_versions` at
     `current_version + 1`, bump `objects.current_version`, take a new
     `change_seq`, insert `blob_containers` if absent, insert `blobs` if absent.
     Commit. Answer `200` with the new version.
   * Else: insert a `conflicts` row referencing the same finalized digest, take a
     new `change_seq`, commit, and answer `409 version_conflict` with
     `{"error":{...},"currentVersion":n,"conflictId":"cfl_..."}`.

   The conflict body is the one place an error response carries extra fields;
   they sit **beside** `error`, not inside it.
6. Never delete the blob in this handler, in either branch.

### 6.3 Idempotency

`Idempotency-Key` is optional on POST and PUT. When present:
* Key = `hex(sha256(userID + "\x00" + routePattern + "\x00" + clientKey))`.
* On first use, the row is inserted in the same transaction as the mutation.
* A replay returns the recorded status and the current state of the named
  resource, not a second mutation.
* Keys older than 24 hours are purged by the GC sweeper.
* A duplicate save **without** an idempotency key and with the same
  `baseVersion` as a save that already landed is a normal `409
  version_conflict`. That is correct behaviour, not a bug.

### 6.4 Tests

- `TestFirstSaveCreatesVersionOne`
- `TestSequentialSavesIncrementByOne`
- `TestStaleBaseVersionIsRejectedWith409`
- `TestRejectedCiphertextIsPreservedAsConflict`
- `TestConflictBlobIsDownloadableByOwner`
- `TestConcurrentSavesProduceExactlyOneWinner` — N goroutines, same
  `baseVersion`; assert 1 success, N-1 conflicts, N-1 conflict rows, and
  `current_version == base + 1`.
- `TestDuplicateRetryWithIdempotencyKeyDoesNotDoubleWrite`
- `TestIdempotencyKeyIsScopedPerUserAndRoute`
- `TestCursorAdvancesMonotonically`
- `TestChangesIncludeDeletions`
- `TestOfflineClientCatchesUpFromOldCursor` — write 500 changes, page through
  with `limit=50`, assert every change is seen exactly once in order.
- `TestChangesLimitIsClamped`
- `TestChangesFromForeignContainerReturns404`
- `TestObjectBodyOverLimitIsRejectedBeforeDiskWrite`
- `TestNoFullTextSearchEndpointExists` — router whitelist assertion.
- `TestSaveDoesNotDeleteBlobOnConflict`
- `TestViewerRoleCannotSave`

---

## 7. Phase 6 — Attachment subsystem

### 7.1 Endpoints

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/containers/{id}/uploads` | `{"declaredBytes":n,"expectedDigest":"<hex>","kind":"attachment\|preview"}` → `{"uploadId","chunkBytes","expiresAt","nextChunk":0}` |
| PATCH | `/api/v1/uploads/{id}` | `application/octet-stream` chunk; header `X-Kynotes-Chunk-Index` |
| GET | `/api/v1/uploads/{id}` | → status, `receivedBytes`, `nextChunk`, `expiresAt` |
| POST | `/api/v1/uploads/{id}/finalize` | `{"metadataCiphertext":"<b64>","keyGeneration":n,"previewUploadId":"ups_..."}` → `{"attachmentId","digest","bytes"}` |
| DELETE | `/api/v1/uploads/{id}` | abort; removes the temp file |
| HEAD | `/api/v1/containers/{id}/attachments/by-digest/{digest}` | `200` if that digest is already in **this** container, else `404` |
| GET | `/api/v1/attachments/{id}` | ciphertext stream, supports `Range` |
| GET | `/api/v1/attachments/{id}/preview` | preview ciphertext stream |
| POST | `/api/v1/objects/{id}/attachments` | `{"attachmentId":"att_...","objectVersion":n}` → creates a ref |
| DELETE | `/api/v1/objects/{id}/attachments/{attachmentId}` | removes refs for that object |

### 7.2 Rules

1. `declaredBytes` over `limits.attachment_max_bytes` → `413
   payload_too_large`, before any file is created.
2. `declaredBytes` that would exceed the owner's quota → `413 quota_exceeded`.
3. Chunks must arrive with `X-Kynotes-Chunk-Index == next_chunk`. Out of order →
   `409 already_exists` carrying the expected `nextChunk`. A repeat of the
   *current* `next_chunk - 1` after a network retry, with identical bytes, is
   accepted as a no-op — clients retry, and forcing a restart of a 25 MB upload
   over one dropped ACK is a worse failure than a byte comparison.
4. Every chunk except the last must be exactly `chunk_bytes`.
5. `received_bytes` exceeding `declared_bytes` at any point → `413`, session
   `failed`, temp removed.
6. Expiry is `15m` from the **last** chunk activity, not from creation
   (`limits.upload_session_ttl`, refreshed on each accepted chunk). A `PATCH`
   after `expires_at` → `410 gone`.
7. Finalize verifies the digest against `expected_digest`. Mismatch → `422
   digest_mismatch`, session `failed`, temp removed. This is the ciphertext
   integrity check; the server cannot verify the AEAD tag because it has no key,
   so the digest **is** the server-side integrity contract, and the client must
   verify the AEAD tag after download.
8. Finalize re-checks quota against the actual size.
9. Finalize is where dedup happens: if `blobs` already has the digest, no new
   file is written (the temp is discarded); a `blob_containers` row is inserted
   for this container if absent. If the container already has an `attachments`
   row for that digest, return the existing attachment ID — the unique index
   `idx_attachments_container_digest` makes this deterministic.
10. Image attachments must supply `previewUploadId`. The server does not know
    what an image is, so this is a client obligation; the server simply stores
    `preview_digest` when supplied. Do **not** attempt MIME sniffing — the bytes
    are ciphertext and the MIME type is encrypted.
11. Attachments are immutable. There is no update route.
12. Attachment permissions derive entirely from the containing container's
    membership. There is no per-attachment ACL.

### 7.3 Deletion order (exactly this)

`DELETE /api/v1/objects/{id}`, in one transaction:
1. Soft-delete the object (`deleted_at`, new `change_seq`).
2. Delete every `object_versions` row for the object. (Historical versions go
   too — DESIGN.md §Encryption is explicit about this.)
3. Delete every `attachment_refs` row for the object.
4. Soft-delete `attachments` rows in this container that now have zero refs.
5. Commit. **No blob is touched.**

GC (§1.15) later marks the orphaned blobs and deletes them after
`gc.retention`.

### 7.4 Tests

- `TestUploadSessionRejectsOversizeDeclaration`
- `TestUploadSessionRejectsOverQuotaDeclaration`
- `TestChunkOutOfOrderIsRejectedWithExpectedNext`
- `TestIdenticalChunkRetryIsAcceptedAsNoOp`
- `TestDifferentBytesForSameChunkIndexIsRejected`
- `TestWrongSizedMiddleChunkIsRejected`
- `TestExceedingDeclaredBytesFailsSession`
- `TestInterruptedUploadResumesFromNextChunk`
- `TestResumeAfterProcessRestartRehashesCorrectly`
- `TestSessionExpiresAfter15MinutesOfInactivity`
- `TestActivityRefreshesExpiry`
- `TestExpiredSessionRemainsVisibleForTwentyFourHours`
- `TestExpiredSessionTempFileIsRemoved`
- `TestFinalizeRejectsDigestMismatch`
- `TestCorruptedChunkChangesDigestAndFailsFinalize`
- `TestFinalizeRechecksQuota`
- `TestDuplicateUploadInSameContainerReturnsExistingAttachment`
- `TestSameDigestInTwoContainersCreatesTwoAttachmentsOneFile`
- `TestByDigestLookupIsInvisibleAcrossContainers` — the definitive dedup
  isolation test: container A has the digest, container B's HEAD returns 404.
- `TestQuotaCountsDedupedBlobPerContainer`
- `TestLazyDownloadRequiresContainerMembership`
- `TestRangeRequestOnAttachmentWorks`
- `TestPreviewIsSeparateBlob`
- `TestAttachmentHasNoUpdateRoute`
- `TestNoteSavesWhenAttachmentUploadNeverCompletes` — the independence contract.
- `TestDeleteNoteReleasesAllVersionsAndRefs`
- `TestGCDeletesUnreferencedBlobAfterRetention`
- `TestGCDoesNotDeleteBeforeRetention`
- `TestGCDisabledLeavesBlobsButStillExpiresUploads`
- `TestGCToleratesAlreadyMissingFile`
- `TestCorruptedFinalizedBlobIsReportedNotServed` — truncate a file on disk,
  assert `GET` fails with `500 internal` and logs `error_kind=blob_corrupt`,
  rather than serving short content.

---

## 8. Phase 7 — Organization and task metadata

**Server work in this phase is deliberately small.**

* `containers.kind = "workbook"` with a well-known client-side flag is how a
  personal workbook is represented. The server adds no new kind.
* The personal inbox is an ordinary folder object created by the client at
  account setup. The server adds no inbox concept.
* Projects already exist as `containers.kind = "project"`.
* **The server does not parse Markdown, YAML front matter, tasks, due dates,
  recurrence, or checkboxes.** Parsing plaintext would require the key. Task
  views are built client-side from decrypted content (DESIGN.md §3).
* The only server addition is an optional per-object encrypted routing hint:
  add column `objects.routing_ciphertext BLOB NOT NULL DEFAULT x''` via
  `0003_routing.sql`, written on save, returned in change listings. It exists so
  a client can decide what to fetch without downloading every note body. Cap it
  at 1024 bytes. The server never interprets it.

Tests:
- `TestServerHasNoMarkdownParser` — `grep`-style source assertion: no import of
  a Markdown or YAML library outside `internal/config`.
- `TestRoutingCiphertextIsOpaqueAndSizeCapped`
- `TestRoutingCiphertextIsReturnedInChangeListing`

---

## 9. Phase 8 — Teams and collaboration

Start only after Phase 5 is stable in real client use.

New tables (`0004_collaboration.sql`):

```sql
CREATE TABLE invitations (
  id            TEXT PRIMARY KEY,
  container_id  TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  inviter_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invitee_id    TEXT NOT NULL DEFAULT '',
  token_hash    TEXT NOT NULL UNIQUE,
  role          TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'pending',   -- pending|accepted|revoked|expired
  created_at    TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  responded_at  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE comments (
  id               TEXT PRIMARY KEY,
  container_id     TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  object_id        TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  author_user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body_ciphertext  BLOB NOT NULL,
  key_generation   INTEGER NOT NULL,
  change_seq       INTEGER NOT NULL,
  created_at       TEXT NOT NULL,
  deleted_at       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE mentions (
  comment_id       TEXT NOT NULL REFERENCES comments(id) ON DELETE CASCADE,
  mentioned_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (comment_id, mentioned_user_id)
);

CREATE TABLE activity (
  id              TEXT PRIMARY KEY,
  container_id    TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
  actor_user_id   TEXT NOT NULL,
  event           TEXT NOT NULL,
  object_id       TEXT NOT NULL DEFAULT '',
  detail_ciphertext BLOB NOT NULL DEFAULT x'',
  change_seq      INTEGER NOT NULL,
  created_at      TEXT NOT NULL
);
```

Rules:

* **Mentions carry a user ID, not a name.** The comment text stays encrypted;
  the mention list is routing metadata the server needs to deliver a
  notification.
* Role capability matrix, enforced server-side and tested independently of any
  encryption behaviour:

  | Operation | owner | admin | editor | commenter | viewer |
  |---|---|---|---|---|---|
  | read objects | ✓ | ✓ | ✓ | ✓ | ✓ |
  | save objects | ✓ | ✓ | ✓ | — | — |
  | upload attachments | ✓ | ✓ | ✓ | — | — |
  | comment | ✓ | ✓ | ✓ | ✓ | — |
  | invite / change roles | ✓ | ✓ | — | — | — |
  | remove members | ✓ | ✓ | — | — | — |
  | rotate keys | ✓ | ✓ | — | — | — |
  | delete container | ✓ | — | — | — | — |

* **Key rotation on membership change**: removing a member increments
  `containers.key_generation`, deletes that member's devices' envelopes for the
  container, and requires the rotating client to `PUT` a full envelope set for
  the new generation for every remaining device. Until that set exists,
  `POST`/`PUT` of new content at the new generation is refused with `409
  already_exists` and message `key rotation incomplete`. The server never sees
  the key; it only enforces that the generation moved and that envelopes exist.
* Presence is in-memory only, never persisted, TTL 60 seconds, and contains only
  `{userId, containerId, since}`. On restart it is empty. That is correct.

Tests:
- `TestRoleMatrixIsEnforcedForEveryOperation` — table-driven over the matrix
  above, with encryption entirely absent from the test.
- `TestRemovingMemberIncrementsKeyGeneration`
- `TestRemovedMemberEnvelopesAreDeleted`
- `TestNewContentRefusedUntilRotationEnvelopesExist`
- `TestRemovedMemberCannotReadNewGenerationContent`
- `TestRemovedMemberRetainsNoServerSideAccessAtAll`
- `TestInvitationTokenIsSingleUseAndExpires`
- `TestInvitationCannotEscalateAboveInviterRole`
- `TestCommentBodyIsNeverReadableByServer` — asserts the handler never decodes
  or inspects `body_ciphertext`.
- `TestMentionStoresUserIDNotName`
- `TestPresenceIsNotPersisted`
- `TestActivityDetailIsEncrypted`

---

## 10. Phase 9 — Push and operational behaviour

* `POST /api/v1/push/registrations` — `{"deviceId","transport":"fcm|apns","token"}`.
  Device credential required. One registration per device; re-registering
  replaces.
* Push payload is **exactly**:
  `{"type":"kynotes.changes","containerId":"cnt_...","changeSeq":n}`.
  No titles, no names, no counts of anything nameable, no preview.
* Pull fallback: `GET /api/v1/sync/pending` returns
  `[{"containerId","changeSeq"}]` for the calling device's selected containers.
  A client with no push works by polling this at its own cadence.
* Rate limits (token bucket, per key, in-memory):
  login `ratelimit.login_per_minute` per IP, pairing `ratelimit.pairing_per_hour`
  per user, uploads `ratelimit.upload_per_minute` per user. Exceeding returns
  `429 rate_limited` with `Retry-After` in seconds.
* Admin CLI subcommands on the same binary — no second image:
  * `kynotes-server backup --out <dir>` — refuses to run while a server holds
    the data directory lock; the documented procedure is stop, copy, start.
  * `kynotes-server restore --in <dir>` — refuses to overwrite a non-empty data
    directory without `--force`, and runs `integrity-check` afterwards.
  * `kynotes-server integrity-check` — `PRAGMA integrity_check` plus the storage
    consistency check below.
  * `kynotes-server consistency-check` — every referenced digest exists on disk;
    every on-disk blob has a `blobs` row; every `blobs` row has a file. Reports
    counts and exits non-zero on any mismatch.
  * `kynotes-server quota set --user <id> --bytes <n>`.
  * `kynotes-server user add --username <name> [--admin]` — reads a
    client-derived auth secret and login salt from stdin as JSON, so the server
    never sees a password. This is the only account-creation path; there is no
    self-service registration. Needed as soon as Phase 3 is testable, so build
    it there and leave it in the Phase 9 CLI surface.
  * `kynotes-server gc --now` — runs one sweep and exits.

**The privacy verification suite** (`internal/httpapi/privacy_test.go`) — this is
the phase's headline deliverable. It drives a full lifecycle (register, pair,
create container, save note with a known plaintext marker, upload attachment,
comment, delete) with a fixed marker string, then asserts the marker appears
**nowhere** in:

- `TestMarkerAbsentFromLogs`
- `TestMarkerAbsentFromEveryHTTPResponse`
- `TestMarkerAbsentFromEverySQLiteColumn` — iterates `sqlite_master`, dumps
  every row of every table, scans for the marker.
- `TestMarkerAbsentFromBlobDirectory` — blobs are ciphertext, so a plaintext
  marker must not appear.
- `TestMarkerAbsentFromBackupArchive`
- `TestMarkerAbsentFromPushPayloads`
- `TestNoPrivateKeyOrTokenMaterialInAnyTable` — the same sweep for a known
  session token, device secret, pairing token, and recovery code.

These tests must be written so that adding a new table or a new log call without
thinking will break them.

---

## 11. Phase 10 — Client interoperability

Deliverable: `cmd/kynotes-probe`, a test client in this repository, plus frozen
fixtures in `testdata/protocol/`.

`kynotes-probe` performs, in one run against a live server:

1. login-params → derive auth secret → login
2. mint a pairing token, register a device, receive the device secret
3. install a key envelope from the web session, read it back from the device
4. select containers for sync
5. create a note, save v1, save v2, read back both
6. save with a stale base version, receive `409`, download the preserved conflict
7. upload a 9 MiB attachment in 4 MiB chunks, interrupt after chunk 1, resume,
   finalize
8. re-upload the identical bytes in the same container, assert dedup returns the
   same attachment
9. download the attachment lazily and by `Range`
10. upload and fetch an image preview
11. go "offline" (stop calling), make server-side changes from a second client,
    then catch up from an old cursor
12. delete the note, run `gc --now` with retention `0s`, assert the blob is gone

Exit code 0 only if every step matched its expected status and body. Each step
prints one line. This binary is the acceptance test for the whole server and is
run in CI against the Docker image.

Frozen fixtures (`testdata/protocol/`):
- `auth_vectors.json` — password/salt/iterations → expected auth secret
- `pairing_token.json` — secret/claims → expected token string
- `id_samples.json` — valid and invalid IDs per prefix
- `error_envelopes.json` — one example per error code

Client repositories consume these fixtures. Changing a fixture is a protocol
break and must be called out in the PR.

---

## 12. Phase 11 — Deployment and release hardening

* `docker-compose.yml` with one service, one named volume at `/data`, no
  published port except through the documented reverse proxy, `read_only: true`
  root filesystem with `/data` and `/tmp` as writable mounts, `no-new-privileges`,
  dropped capabilities, and `mem_limit`/`pids_limit` set.
* `docs/DEPLOYMENT.md`: HTTPS termination, `X-Forwarded-For` and
  `trusted_proxies`, backup (stop → copy `/data` → start), restore (stop →
  replace → `integrity-check` → start), upgrade (backup first, migrations run
  automatically at startup, roll back by restoring the copy).
* Timeouts from §1.9 applied to the `http.Server` and to every outbound call.
* Storage exhaustion: `POST /uploads` checks free space via `syscall.Statfs` and
  refuses with `507`-equivalent `503 unavailable` when free space is below
  `2 × attachment_max_bytes`. A full disk must fail an upload, never corrupt the
  database.
* `go test -race ./...` in CI on every push.
* `go test -fuzz` targets, each with a seed corpus, run for 60s in CI:
  `FuzzParsePairingToken`, `FuzzParseAuthSecret`, `FuzzParseID`,
  `FuzzParseChunkHeaders`, `FuzzParseCursor`, `FuzzConfigLoad`.
* `govulncheck ./...` in CI.
* Release: tag, build the digest-pinned image, publish, and record the image
  digest in `CHANGELOG.md`.

---

## 13. Cross-cutting invariants (verify every phase)

1. No endpoint accepts, returns, or stores plaintext note or attachment content.
2. No log line contains anything outside the §2.3 allowlist.
3. Every mutating route requires CSRF when authenticated by cookie.
4. Every ID in a path is validated before a database call.
5. Every blob write is finalized before the referencing metadata commits.
6. Every failure path that consumes a lockout strike is deliberate, and every
   correct-credential-but-refused path returns the strike.
7. `404` for non-membership, `403` only for insufficient role.
8. No route exists that the router whitelist test does not know about.
9. Every new table added in a later phase is added to the privacy sweep test.
10. Every security-relevant change ships a success test and a failure test.

---

## 14. Explicitly out of scope

Do not implement, do not stub, do not leave TODOs for:

* Public Sites, publishing, public asset URLs, MDBook generation, automatic
  publishing, private/unlisted publishing.
* Desktop client support.
* Templates, web clipping, freehand drawing, rich media editing.
* Server-side full-text search or any server-side note indexing.
* Server-side Markdown, YAML, or task parsing.
* KySignOn/OIDC integration. KyNotes owns its own login for this release. If
  KySignOn ships later, integration is a separate plan, and it must not remove
  the password-derived key material that envelope wrapping depends on.
* Self-service registration. Accounts are created by an administrator via
  `kynotes-server user add`.
* Multi-tenancy, SCIM, SAML, refresh tokens.
* Telemetry of any kind.
* An embedded log database or log viewer (LOGGING.md is explicit).

---

## 15. Open items requiring a human decision

None block Phases 1 and 2. Raise these before the phase that needs them.

| Needed by | Question |
|---|---|
| Phase 4 | Confirm X25519 as the device key type, or supply the exact algorithm string the KyNotes web client will implement. The plan freezes `x25519-hkdf-sha256-chacha20poly1305`; the client teams must agree before the first pairing ships. |
| Phase 6 | Confirm deterministic/convergent attachment encryption is actually wanted. The server design works either way; DESIGN.md permits it and SECURITY.md documents the equality leak. If clients use random nonces instead, dedup simply stops matching and nothing breaks. |
| Phase 9 | KyPost push integration: the exact registration and delivery endpoints of the KyPost push relay. Until supplied, implement pull fallback only and leave `push.transport` unconfigured (routes answer `503 unavailable`). |
| Phase 3 | Administrator account bootstrap: whether `kynotes-server user add` prompts interactively or takes a pre-derived auth secret. Default in this plan: it takes `--username` and reads a client-derived auth secret from stdin, so the server never sees a password. Proceed on that default unless told otherwise. |

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
