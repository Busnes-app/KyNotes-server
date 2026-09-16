# ky-primitives/offsite: lift KyRecovery's replication clients into the lib

Hand-off, 2026-09-05. Board folder `ky-primitives-offsite`. Written before any code. Durable copy lives here in kynotes-server until the ky-primitives PR carries its own.

**Repo:** ky-primitives (nested module), then kyrecovery-server, kynotes-server, kypost-server as consumers
**PR:** none yet
**Worktree:** none

## Why

`kyrecovery-server/internal/replication` ships sealed capsules to S3, SFTP, SMB and a local directory. kynotes needs the same clients to mirror its attachment store (decision 2026-09-05: attachments never go in the capsule), and kypost will need them for mail bodies, which exceed the capsule caps (suite spec, kypost row). That is three consumers of code where divergence loses data silently: an SFTP client that accepts an unpinned host, or sends a PEM key as a password, or an SMB client that lets a guest session swallow uploads while the log says success. That is the lib's admission bar.

## Shape: a nested module

ky-primitives is stdlib-only, enforced by `TestModuleDependenciesAreAllowlisted`, bent once for Argon2. SFTP needs `github.com/pkg/sftp` and `golang.org/x/crypto/ssh`; SMB needs `github.com/hirochachacha/go-smb2`. So `offsite` gets its own `go.mod` at `ky-primitives/offsite/go.mod`, module path `github.com/Busness-app/ky-primitives/offsite`. The root module's dependency test keeps passing; the nested module carries the three pins kyrecovery already uses (`pkg/sftp v1.13.11`, `go-smb2 v1.1.0`, `x/crypto` current). Tags are `offsite/v0.1.0`. Root `nodeps_test.go` must skip the nested module's directory (check how it walks; a nested `go.mod` is normally invisible to `./...` from the root, so this may already hold).

If Yoshi prefers no non-stdlib code anywhere in the repo: ship S3 and local only, in the root module, and leave SFTP and SMB per product. S3 plus a host-mounted directory still covers every cloud bucket and a NAS.

## Package contents (lift from kyrecovery `internal/replication`, keep the tests)

```go
package offsite

type Target interface {
	Put(ctx context.Context, name string, r io.Reader, size int64) error
	Get(ctx context.Context, name string) (io.ReadCloser, error) // os.ErrNotExist when absent
	Test(ctx context.Context) error                             // proves the destination is writable
}

type Config struct {
	URL        string // s3://bucket/prefix | sftp://user@host:22/dir | smb://host/share/dir | file:///path
	AccessKey  string // S3 key id; SFTP/SMB user when absent from the URL
	Secret     string // S3 secret, SFTP password or PEM private key, SMB password
	HostKey    string // SFTP: SHA256:... fingerprint, required
	S3Endpoint string // R2, MinIO
	S3Region   string // default us-east-1
	Timeout    time.Duration
}
func Parse(c Config) (Target, error)  // scheme dispatch; refuses userinfo passwords, unpinned sftp, s3 without both creds
func Key(c Config) string             // URL without credentials: stable identity for a product's replica table

type UnknownHostKeyError struct{ Fingerprint string } // sftp: what to pin
func ParseSMBEndpoint(endpoint, share, dir string) (addr, share, dir string, err error)
```

- `s3.go`: today's `PutObject` (SigV4, stdlib) plus `GetObject`: signed GET, `x-amz-content-sha256: UNSIGNED-PAYLOAD`, same canonical request shape; 404 → `os.ErrNotExist`. Add a SigV4 GET vector test.
- `sftp.go`: unchanged `dial` (pinned host key, PEM-or-password by structure), `Put` temp+rename, new `Get` via `client.Open` returning a closer that also tears down the session; "no such file" → `os.ErrNotExist`.
- `smb.go`: unchanged mount (SMB 2/3, signing required), `Put`, new `Get` via `share.Open`. Keep the guest-session limitation paragraph in the package doc and README; it is a property of the library, not of kyrecovery.
- `local.go`: temp+rename `Put` at 0600, `os.Open` `Get`.
- Tests: `sftp_test.go` and `smb_test.go` in-process servers, stalled-server budget, host-key mismatch refusal, unpinned fingerprint report, PEM-never-as-password, UNC/URL endpoint forms, userinfo refusal; plus `Get` round trips and the `ErrNotExist` mapping per target.
- Ping file name: `.ky-offsite-ping`, not `.kyrecovery-ping`.

Not in the lib: target tables, sync logs, audit rows, schedulers, what to send. Each product keeps those.

## Consumers, in order

1. **kyrecovery-server**: `internal/replication/manager.go` keeps the target table, sync log and ledger rows; the four client files go, `SyncCapsule` builds a `Target` via `offsite.Parse` from the stored record and calls `Put`. Its live replication targets must keep working: the settings columns are unchanged, only the client bodies move. Prove with the existing manager test and one live sync from the dashboard.
2. **kynotes-server**: Plan C (`kynotes-server/docs/superpowers/plans/2026-09-05-kynotes-blob-mirror.md`) Task 2 becomes `go get github.com/Busness-app/ky-primitives/offsite@offsite/v0.1.0`; the rest of Plan C stands.
3. **kypost-server**: mail-body mirror, its own folder later.

## Proving it

- `go test ./...` in the nested module, and root `go test ./...` still green with the dependency test passing.
- `go vet`, `gofmt`, `govulncheck` on the nested module; CI matrix job for `offsite` (its own `cd offsite && go test` step).
- kyrecovery consumer PR: manager test green; one live sync to a real target in the homelab.

## Careful

- Do not soften the SFTP pin rule while moving it: no pin, no connection, and the error names the fingerprint.
- `Get` must map "absent" to `os.ErrNotExist` on every target, or a consumer's restore cannot tell "not uploaded yet" from "target down".
- Nested-module tagging: `git tag offsite/v0.1.0`, and the root module's tags do not cover it. Document in the README next to the recoveryclient section.
- The reviewer bot will ask about SMB signing and the guest session; the answer is already in kyrecovery's README, carry it over verbatim.
