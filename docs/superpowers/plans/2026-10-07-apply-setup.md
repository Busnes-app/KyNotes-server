# KyNotes `apply-setup` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** KyQuickStart runs `kynotes-server apply-setup --file <bundle>` inside the running container. The command configures SSO, SSO-bound administrators and backups, creating only what is missing. It never overwrites, writes one audit row per change, and prints a JSON report whose exit code the installer acts on.

**Architecture:**
- New pure package `internal/applysetup` holds the bundle and wire types, strict decoding and validation, the per-section decisions (created/present/conflict) and the report with its exit code.
- The CLI reads the bundle and its secret files and validates them. It sends the resolved request to the running server over a Unix socket, `<data_dir>/admin.sock` (mode 0600, peer uid checked).
- The server applies the request with its own machinery:
  - `httpapi.SetupHandler`: SSO through the shared `sso.Store` and an issuer probe; admins in one SQLite transaction each, with audit.
  - `backup.Service.ApplySetup`: the existing `Pair` and `SetSchedule`.
- The socket's `http.Server` is owned by `app.Serve`. The server creates it after the data-directory lock and removes it on shutdown.

**Tech Stack:** Go 1.26 stdlib (`net`, `net/http` over `unix`, `encoding/json`, `syscall` SO_PEERCRED), `ky-primitives/recoveryclient`, SQLite (modernc).

**Spec:** `docs/superpowers/specs/2026-10-07-apply-setup-design.md`

## Global Constraints

- **Socket:** `<data_dir>/admin.sock` (`app.AdminSocketPath`).
  - Mode 0600, created in `app.Serve` after `storage.LockDirectory` and removed when `Serve` returns.
  - Only `net.Listen("unix", …)`; never bound to a network address.
  - Peers other than the server's uid and root are closed at accept.
  - A stale *socket* at the path is replaced. Any other file type there is refused.
- **Exit codes** (`applysetup.ExitOK/ExitError/ExitInvalid/ExitConflict`):
  - 0: everything created or present.
  - 3: something conflicts and was left unchanged.
  - 2: invalid input (local validation, server 400, or a section reported `invalid`).
  - 1: any other error (server not running, busy, transport, or a section reported `failed`).
  - Precedence when statuses mix: invalid (2) > failed (1) > conflict (3) > 0.
- **Secrets** (`clientSecretFile`, `directoryHmacSecretFile`, `pairingCodeFile`):
  - Arrive only as absolute paths to regular files of at most 4 KiB (`MaxSecretBytes`). Trailing `\r\n` is trimmed. They must be non-empty and contain no control characters.
  - Inline `clientSecret`, `hmacSecret` or `pairingCode` in the bundle are unknown fields and rejected.
  - Secret values never appear in the report, stdout, stderr, logs or audit rows.
- **Create-only.**
  - SSO: stored only when no SSO settings exist. Identical settings are `present`; anything else is `conflict` and left unchanged.
  - Backup interval: set only when the admin setting is unset.
  - Recovery key: never re-pinned. A different URL or key is `conflict`.
  - Accounts: never adopted by username.
- **One audit row per change.** Actor `system`, request ID `apply-setup`. Reuse the existing event names:
  - `admin.sso_update` for SSO.
  - `admin.user.create` and `admin.user.update` for admins.
  - `admin.backup_schedule` and `admin.backup_pair`, written by the existing `backup.Service` methods.
  - `sso.Store.Save` also writes its pre-existing unattributed `auth.sso_configuration` revocation row. It is not an apply-setup row.
  - `present` and `conflict` write nothing.
- **URLs:** `recoveryclient.ValidateURL(raw, cfg.Backup.AllowPrivateRecovery)` for issuer, redirect, admin issuer and recovery URL. This means HTTPS only, no credentials, query or fragment, and no loopback. Literal private IPs are allowed only with `KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY`. The redirect path must be `/api/v1/auth/oidc/callback`.
- **Unknown fields rejected** (`DisallowUnknownFields`) in both the bundle and the socket request, along with trailing data. Bundle at most 64 KiB (`MaxBundleBytes`), socket body at most 1 MiB.
- **Reuse, no parallel paths:**
  - SSO writes go through the router's own `sso.Store` instance (Task 5), so login sees the change without a restart.
  - Recovery pairing is `backup.Service.Pair`; the interval is `backup.Service.SetSchedule`.
  - The username rule is shared with directory provisioning (`applysetup.Identifier`).
  - Promotion revokes credentials through the helper extracted from `syncSingleUser`.
- **Checks** (from the repo root): `go build ./...`, `go vet ./...`, `gofmt -l .` (empty), `go test -race ./...`.
- **Commits:** a subject line, a blank line, then `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>` on its own line.

## Review Focus

1. **Overwriting what an operator configured.** Re-running the installer must not replace hand-entered SSO settings (for example a KySignOn pairing), re-pin a different recovery key, or change an admin-set interval. Pinned by:
   - Task 3 `TestDecideSSO`, `TestDecideRecovery` and `TestDecideInterval`.
   - Task 6 `TestApplySSOCreatesThenPresentThenConflict`.
   - Task 8 `TestApplySetupRecoveryKeyMismatchIsConflict` and `TestApplySetupLocalSettings`.
2. **Secret leakage.** The client secret, HMAC secret or pairing code must not reach the report, stdout/stderr, logs or audit rows. Pinned by:
   - Task 2 `TestLoadErrorsNeverEchoSecrets`.
   - Task 9 `TestSetupHandlerAppliesAndNeverEchoesSecrets`.
   - Task 11 `TestApplySetupLocalFailures`.
   - Task 12 `TestApplySetupTwiceEndToEnd` (stdout).
3. **Admin takeover by username.** A bundle username that matches an existing local or other-bound account must not bind or elevate it. Pinned by Task 3 `TestDecideAdmin` and Task 7 `TestApplyAdminNeverAdoptsByUsername`.
4. **Socket exposure and lifecycle.**
   - The socket must not be world-connectable, reachable over the network, left after shutdown, or used to delete a non-socket file.
   - Peers of another uid must be refused.
   - Pinned by Task 10 `TestAdminSocketIsPrivateAndReplacesOnlyStaleSockets`, `TestPeerAllowedRefusesOtherUIDs` and `TestServeOwnsAdminSocketLifecycle`, and by the Task 14 container check (`stat` 600, gone after `docker stop`).
5. **Second run not idempotent, or applied state not live.** A rerun must not re-claim the pairing code, add audit rows or rewrite settings. SSO must take effect without a restart. Pinned by:
   - Task 8 `TestApplySetupRecoveryPairsOnceAndNeverRepins` (claim count stays 1).
   - Task 5 `TestRouterUsesSuppliedSSOStore`.
   - Task 12 `TestApplySetupTwiceEndToEnd`: run 2 all `present`, exactly 3 `apply-setup` audit rows, and `/api/v1/auth/sso-config` live.

## Resolved Ambiguities and Constraints from the Code

- **Backup dir and keep are fixed when the process starts.** `backup.dir` and `backup.keep` come from `KYNOTES_BACKUP_DIR` and `KYNOTES_BACKUP_KEEP` (`internal/config/config.go:243-252`). The running server cannot change them.
  - apply-setup **checks** them: an equal value is `present`; a different one is `conflict`, with the env var named in the detail.
  - `docs/INSTALLER.md` makes the manifest set both env vars.
  - Only `depositInterval` is a stored admin setting that can be created.
- **No validation in the admin route.** `POST /api/v1/admin/sso` (`internal/httpapi/admin_routes.go:297-316`) decodes and saves without validating or probing. apply-setup therefore validates with the shared URL rule and probes with `sso.DiscoverEndpoints`, the same check login uses (`internal/sso/sso.go:172`). The admin route stays unchanged; hardening it is separate work.
- **A key mismatch shows up only after claiming.** It surfaces as `fs.ErrExist` from `Pair`, by which point the pairing code is spent. To avoid that, apply-setup does not claim when this instance is already paired to the same URL (`present`) or to a different one (`conflict`).
- **New status `failed`.** It covers a storage or audit error, an unreachable KyRecovery, or a backup operation already in progress. It maps to exit 1. The spec's four statuses cannot express these.
- **Admin issuer.** It must equal the SSO issuer, either the one in the bundle or the one already stored. Otherwise the account could never sign in, so the section reports `invalid`.
- **Disabled binding.** A disabled account bound to the identity is a `conflict`: the directory owns account status.
- **Who reads secrets.** The CLI reads secret files, so the server never opens a path a socket client names. The server re-validates the resolved request.
- **Handover fields.** `url` is the origin of the stored SSO redirect URI. `recoveryKeyFingerprint` is the pinned recovery key ID (`kyrecovery_key_id`, the value `admin.backup_pair` audits). `adminUsernames` lists the actual usernames of the bound admin accounts.
- **AutoProvision.** apply-setup stores `AutoProvision: true`, the same as KySignOn pairing (`admin_routes.go:348-356`).
- **First-run setup closes.** Creating an SSO admin makes `users` non-empty, which closes first-run `POST /api/v1/setup` (`auth_routes.go:68-69`). `docs/INSTALLER.md` states this.

---

### Task 1: Wire request types, strict decoding, validation

**Files:**
- Create: `internal/applysetup/request.go`
- Test: `internal/applysetup/request_test.go`
- Modify: `internal/httpapi/sso_directory.go:41-43` (`directoryIdentifier` delegates to the shared rule)

**Interfaces:**
- Consumes: `recoveryclient.ValidateURL(raw string, allowPrivate bool) error`, `recoveryclient.MinInterval`, `recoveryclient.MaxInterval`.
- Produces:
  - `const Version = 1`, `MaxBundleBytes = 64 << 10`, `MaxSecretBytes = 4 << 10`, `MaxAdmins = 16`, `CallbackPath = "/api/v1/auth/oidc/callback"`, `Actor = "system"`, `RequestID = "apply-setup"`
  - `type Request struct { Version int; SSO *SSO; Admins []Admin; Backup *Backup }` (JSON `version`, `sso`, `admins`, `backup`)
  - `type SSO struct { IssuerURL, ClientID, ClientSecret, RedirectURI, HMACSecret string }` (JSON `issuerUrl`, `clientId`, `clientSecret`, `redirectUri`, `hmacSecret`)
  - `type Admin struct { Issuer, Subject, Username string }` (JSON `issuer`, `subject`, `username`)
  - `type Backup struct { Dir string; Keep int; DepositInterval string; Recovery *Recovery }` (JSON `dir`, `keep`, `depositInterval`, `recovery`)
  - `type Recovery struct { URL, PairingCode string }` (JSON `url`, `pairingCode`)
  - `func (r Request) Validate(allowPrivate bool) error`
  - `func DecodeRequest(r io.Reader, allowPrivate bool) (Request, error)`
  - `func Identifier(s string) bool`
  - `func IntervalSeconds(raw string) (int64, error)`

- [ ] **Step 1: Write the failing test.** Create `internal/applysetup/request_test.go`:

```go
package applysetup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func validRequest() Request {
	return Request{
		Version: 1,
		SSO:     &SSO{IssuerURL: "https://id.example", ClientID: "kynotes", ClientSecret: "client-secret-value", RedirectURI: "https://notes.example/api/v1/auth/oidc/callback", HMACSecret: "hmac-secret-value"},
		Admins:  []Admin{{Issuer: "https://id.example", Subject: "sub-owner", Username: "owner-admin"}},
		Backup:  &Backup{Dir: "/backups", Keep: 7, DepositInterval: "24h", Recovery: &Recovery{URL: "https://kyrecovery.example", PairingCode: "123456"}},
	}
}

func TestValidateAcceptsSpecExample(t *testing.T) {
	if err := validRequest().Validate(false); err != nil {
		t.Fatal(err)
	}
	if err := (Request{Version: 1}).Validate(false); err != nil {
		t.Fatal("every section is optional:", err)
	}
}

func TestValidateRefusesHostileInput(t *testing.T) {
	cases := map[string]func(*Request){
		"version":             func(r *Request) { r.Version = 2 },
		"http issuer":         func(r *Request) { r.SSO.IssuerURL = "http://id.example" },
		"loopback issuer":     func(r *Request) { r.SSO.IssuerURL = "https://127.0.0.1" },
		"credential in url":   func(r *Request) { r.SSO.IssuerURL = "https://u:p@id.example" },
		"padded url":          func(r *Request) { r.SSO.IssuerURL = " https://id.example" },
		"private recovery":    func(r *Request) { r.Backup.Recovery.URL = "https://10.0.0.5" },
		"redirect path":       func(r *Request) { r.SSO.RedirectURI = "https://notes.example/callback" },
		"empty client id":     func(r *Request) { r.SSO.ClientID = "" },
		"empty secret":        func(r *Request) { r.SSO.ClientSecret = "" },
		"control in secret":   func(r *Request) { r.SSO.ClientSecret = "a\x00b" },
		"oversize secret":     func(r *Request) { r.SSO.HMACSecret = strings.Repeat("h", MaxSecretBytes+1) },
		"admin issuer":        func(r *Request) { r.Admins[0].Issuer = "https://other.example" },
		"blank username":      func(r *Request) { r.Admins[0].Username = " " },
		"control username":    func(r *Request) { r.Admins[0].Username = "a\nb" },
		"duplicate subject":   func(r *Request) { r.Admins = append(r.Admins, Admin{Issuer: "https://id.example", Subject: "sub-owner", Username: "other"}) },
		"duplicate username":  func(r *Request) { r.Admins = append(r.Admins, Admin{Issuer: "https://id.example", Subject: "sub-2", Username: "OWNER-ADMIN"}) },
		"relative dir":        func(r *Request) { r.Backup.Dir = "backups" },
		"negative keep":       func(r *Request) { r.Backup.Keep = -1 },
		"short interval":      func(r *Request) { r.Backup.DepositInterval = "5m" },
		"fractional interval": func(r *Request) { r.Backup.DepositInterval = "15m0.5s" },
		"pairing code":        func(r *Request) { r.Backup.Recovery.PairingCode = "12345a" },
		"too many admins": func(r *Request) {
			for i := 0; i < MaxAdmins; i++ {
				r.Admins = append(r.Admins, Admin{Issuer: "https://id.example", Subject: fmt.Sprint("s", i), Username: fmt.Sprint("u", i)})
			}
		},
	}
	for name, mutate := range cases {
		r := validRequest()
		mutate(&r)
		if err := r.Validate(false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidatePrivateRecoveryNeedsOptIn(t *testing.T) {
	r := validRequest()
	r.Backup.Recovery.URL = "https://10.0.0.5"
	if err := r.Validate(true); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeRequestIsStrict(t *testing.T) {
	good, err := json.Marshal(validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRequest(bytes.NewReader(good), false); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"unknown field": `{"version":1,"extra":true}`,
		"trailing data": `{"version":1}{"version":1}`,
		"not an object": `[1]`,
		"bad version":   `{"version":2}`,
	} {
		if _, err := DecodeRequest(strings.NewReader(body), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
```

- [ ] **Step 2: Run it and see it fail.** `go test ./internal/applysetup` → FAIL (package has no non-test files / undefined: Request).

- [ ] **Step 3: Implement.** Create `internal/applysetup/request.go`:

```go
// Package applysetup is the apply-setup contract: the installer's bundle, the request the
// CLI sends over the admin socket, the per-section decisions and the report.
package applysetup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
)

const (
	Version        = 1
	MaxBundleBytes = 64 << 10
	MaxSecretBytes = 4 << 10
	MaxAdmins      = 16
	CallbackPath   = "/api/v1/auth/oidc/callback"
	Actor          = "system"
	RequestID      = "apply-setup"
)

// Request is the bundle with every secret file already read. It travels only over the
// admin socket and is never logged or echoed.
type Request struct {
	Version int     `json:"version"`
	SSO     *SSO    `json:"sso,omitempty"`
	Admins  []Admin `json:"admins,omitempty"`
	Backup  *Backup `json:"backup,omitempty"`
}

type SSO struct {
	IssuerURL    string `json:"issuerUrl"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectUri"`
	HMACSecret   string `json:"hmacSecret,omitempty"`
}

type Admin struct {
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
	Username string `json:"username"`
}

type Backup struct {
	Dir             string    `json:"dir,omitempty"`
	Keep            int       `json:"keep,omitempty"`
	DepositInterval string    `json:"depositInterval,omitempty"`
	Recovery        *Recovery `json:"recovery,omitempty"`
}

type Recovery struct {
	URL         string `json:"url"`
	PairingCode string `json:"pairingCode"`
}

// DecodeRequest is the server-side boundary: strict JSON, then the same validation the CLI ran.
func DecodeRequest(r io.Reader, allowPrivate bool) (Request, error) {
	var req Request
	if err := decodeStrict(r, &req); err != nil {
		return Request{}, err
	}
	return req, req.Validate(allowPrivate)
}

func decodeStrict(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("bundle: trailing data after the JSON object")
	}
	return nil
}

func (r Request) Validate(allowPrivate bool) error {
	if r.Version != Version {
		return fmt.Errorf("version: want %d", Version)
	}
	if r.SSO != nil {
		if err := r.SSO.validate(allowPrivate); err != nil {
			return err
		}
	}
	if len(r.Admins) > MaxAdmins {
		return fmt.Errorf("admins: at most %d", MaxAdmins)
	}
	subjects, names := map[[2]string]bool{}, map[string]bool{}
	for i, a := range r.Admins {
		if err := checkURL(fmt.Sprintf("admins[%d].issuer", i), a.Issuer, allowPrivate); err != nil {
			return err
		}
		if r.SSO != nil && a.Issuer != r.SSO.IssuerURL {
			return fmt.Errorf("admins[%d].issuer: must equal sso.issuerUrl", i)
		}
		if !Identifier(a.Subject) || !Identifier(a.Username) {
			return fmt.Errorf("admins[%d]: subject and username must be 1-256 bytes without surrounding space or control characters", i)
		}
		key, name := [2]string{a.Issuer, a.Subject}, strings.ToLower(a.Username)
		if subjects[key] || names[name] {
			return fmt.Errorf("admins[%d]: duplicate identity or username", i)
		}
		subjects[key], names[name] = true, true
	}
	if r.Backup != nil {
		return r.Backup.validate(allowPrivate)
	}
	return nil
}

func (s SSO) validate(allowPrivate bool) error {
	if err := checkURL("sso.issuerUrl", s.IssuerURL, allowPrivate); err != nil {
		return err
	}
	if err := checkURL("sso.redirectUri", s.RedirectURI, allowPrivate); err != nil {
		return err
	}
	if u, _ := url.Parse(s.RedirectURI); u.Path != CallbackPath {
		return fmt.Errorf("sso.redirectUri: path must be %s", CallbackPath)
	}
	if !Identifier(s.ClientID) {
		return errors.New("sso.clientId: must be 1-256 bytes without surrounding space or control characters")
	}
	if !secretOK(s.ClientSecret) {
		return errors.New("sso client secret: empty, over 4 KiB, or contains control characters")
	}
	if s.HMACSecret != "" && !secretOK(s.HMACSecret) {
		return errors.New("sso directory HMAC secret: over 4 KiB or contains control characters")
	}
	return nil
}

func (b Backup) validate(allowPrivate bool) error {
	if b.Dir != "" && !filepath.IsAbs(b.Dir) {
		return errors.New("backup.dir: want an absolute path")
	}
	if b.Keep < 0 {
		return errors.New("backup.keep: want a positive integer")
	}
	if b.DepositInterval != "" {
		if _, err := IntervalSeconds(b.DepositInterval); err != nil {
			return err
		}
	}
	if rc := b.Recovery; rc != nil {
		if err := checkURL("backup.recovery.url", rc.URL, allowPrivate); err != nil {
			return err
		}
		if len(rc.PairingCode) != 6 || strings.Trim(rc.PairingCode, "0123456789") != "" {
			return errors.New("backup.recovery pairing code: want six digits")
		}
	}
	return nil
}

// IntervalSeconds applies the recovery client's schedule bound: 0 (off) or
// MinInterval..MaxInterval in whole seconds.
func IntervalSeconds(raw string) (int64, error) {
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 || d%time.Second != 0 || (d != 0 && (d < recoveryclient.MinInterval || d > recoveryclient.MaxInterval)) {
		return 0, fmt.Errorf("backup.depositInterval: 0 (off) or %s through %s in whole seconds", recoveryclient.MinInterval, recoveryclient.MaxInterval)
	}
	return int64(d / time.Second), nil
}

// Identifier is the account-name rule shared with directory provisioning.
func Identifier(s string) bool {
	return s != "" && len(s) <= 256 && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

func secretOK(s string) bool {
	return s != "" && len(s) <= MaxSecretBytes && !strings.ContainsFunc(s, unicode.IsControl)
}

func checkURL(field, raw string, allowPrivate bool) error {
	if strings.TrimSpace(raw) != raw {
		return fmt.Errorf("%s: surrounding whitespace", field)
	}
	if err := recoveryclient.ValidateURL(raw, allowPrivate); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}
```

Then, in `internal/httpapi/sso_directory.go`, replace lines 41-43 with the line below and add the import `"github.com/Busnes-app/kynotes-server/internal/applysetup"`:

```go
func directoryIdentifier(s string) bool { return applysetup.Identifier(s) }
```

Remove the `"unicode"` import from that file; `directoryIdentifier` was its only user.

- [ ] **Step 4: Run tests.** `go test ./internal/applysetup && go test ./internal/httpapi -run 'TestDirectory'` → PASS.

- [ ] **Step 5: Commit.** `git add internal/applysetup internal/httpapi/sso_directory.go && git commit -m "applysetup: request types and validation"` (with the Co-Authored-By trailer).

---

### Task 2: Bundle loading with secrets by file path

**Files:**
- Create: `internal/applysetup/bundle.go`
- Test: `internal/applysetup/bundle_test.go`

**Interfaces:**
- Consumes: `Request`, `SSO`, `Admin`, `Backup`, `Recovery`, `decodeStrict`, `Request.Validate` (Task 1).
- Produces: `func Load(path string, allowPrivate bool) (Request, error)`.

- [ ] **Step 1: Write the failing test.** Create `internal/applysetup/bundle_test.go`:

```go
package applysetup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func specBundle(t *testing.T, dir string) string {
	t.Helper()
	secret := writeFile(t, dir, "oidc", "client-secret-value\n")
	hmac := writeFile(t, dir, "hmac", "hmac-secret-value")
	code := writeFile(t, dir, "pair", "123456\r\n")
	return fmt.Sprintf(`{"version":1,
 "sso":{"issuerUrl":"https://id.example","clientId":"kynotes","clientSecretFile":%q,"redirectUri":"https://notes.example/api/v1/auth/oidc/callback","directoryHmacSecretFile":%q},
 "admins":[{"issuer":"https://id.example","subject":"sub-owner","username":"owner-admin"}],
 "backup":{"dir":"/backups","keep":7,"depositInterval":"24h","recovery":{"url":"https://kyrecovery.example","pairingCodeFile":%q}}}`, secret, hmac, code)
}

func TestLoadReadsSecretsFromFiles(t *testing.T) {
	dir := t.TempDir()
	req, err := Load(writeFile(t, dir, "bundle.json", specBundle(t, dir)), false)
	if err != nil {
		t.Fatal(err)
	}
	if req.SSO.ClientSecret != "client-secret-value" || req.SSO.HMACSecret != "hmac-secret-value" || req.Backup.Recovery.PairingCode != "123456" || req.Admins[0].Username != "owner-admin" {
		t.Fatalf("%+v", req)
	}
}

func TestLoadRefusesHostileBundles(t *testing.T) {
	dir := t.TempDir()
	secret := writeFile(t, dir, "oidc", "client-secret-value")
	code := writeFile(t, dir, "code", "123456")
	sso := func(extra string) string {
		return `{"version":1,"sso":{"issuerUrl":"https://id.example","clientId":"kynotes","redirectUri":"https://notes.example/api/v1/auth/oidc/callback",` + extra + `}}`
	}
	cases := map[string]string{
		"inline client secret":  sso(`"clientSecret":"inline","clientSecretFile":"` + secret + `"`),
		"inline hmac secret":    sso(`"hmacSecret":"inline","clientSecretFile":"` + secret + `"`),
		"inline pairing code":   `{"version":1,"backup":{"recovery":{"url":"https://kyrecovery.example","pairingCode":"123456"}}}`,
		"relative secret path":  sso(`"clientSecretFile":"oidc"`),
		"missing secret file":   sso(`"clientSecretFile":"` + filepath.Join(dir, "absent") + `"`),
		"empty secret file":     sso(`"clientSecretFile":"` + writeFile(t, dir, "empty", "\n") + `"`),
		"oversize secret file":  sso(`"clientSecretFile":"` + writeFile(t, dir, "big", strings.Repeat("s", MaxSecretBytes+1)) + `"`),
		"secret is a directory": sso(`"clientSecretFile":"` + dir + `"`),
		"http recovery url":     `{"version":1,"backup":{"recovery":{"url":"http://kyrecovery.example","pairingCodeFile":"` + code + `"}}}`,
		"unknown field":         `{"version":1,"theme":"dark"}`,
		"missing version":       `{}`,
	}
	for name, body := range cases {
		if _, err := Load(writeFile(t, dir, "bundle.json", body), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	big := writeFile(t, dir, "big.json", `{"version":1,"admins":[`+strings.Repeat(" ", MaxBundleBytes)+`]}`)
	if _, err := Load(big, false); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversize bundle: %v", err)
	}
}

func TestLoadErrorsNeverEchoSecrets(t *testing.T) {
	dir := t.TempDir()
	secret := writeFile(t, dir, "oidc", "client-secret-value\x01")
	path := writeFile(t, dir, "bundle.json", `{"version":1,"sso":{"issuerUrl":"https://id.example","clientId":"kynotes","clientSecretFile":"`+secret+`","redirectUri":"https://notes.example/api/v1/auth/oidc/callback"}}`)
	if _, err := Load(path, false); err == nil || strings.Contains(err.Error(), "client-secret-value") {
		t.Fatalf("got %v", err)
	}
}
```

- [ ] **Step 2: Run it and see it fail.** `go test ./internal/applysetup -run TestLoad` → FAIL (undefined: Load).

- [ ] **Step 3: Implement.** Create `internal/applysetup/bundle.go`:

```go
package applysetup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// bundle is the file the installer writes. Secrets appear only as paths; an inline secret
// field is unknown and rejected.
type bundle struct {
	Version int `json:"version"`
	SSO     *struct {
		IssuerURL               string `json:"issuerUrl"`
		ClientID                string `json:"clientId"`
		ClientSecretFile        string `json:"clientSecretFile"`
		RedirectURI             string `json:"redirectUri"`
		DirectoryHMACSecretFile string `json:"directoryHmacSecretFile"`
	} `json:"sso"`
	Admins []Admin `json:"admins"`
	Backup *struct {
		Dir             string `json:"dir"`
		Keep            int    `json:"keep"`
		DepositInterval string `json:"depositInterval"`
		Recovery        *struct {
			URL             string `json:"url"`
			PairingCodeFile string `json:"pairingCodeFile"`
		} `json:"recovery"`
	} `json:"backup"`
}

// Load reads and validates a bundle and the secret files it names.
func Load(path string, allowPrivate bool) (Request, error) {
	raw, err := readCapped(path, MaxBundleBytes)
	if err != nil {
		return Request{}, fmt.Errorf("bundle: %w", err)
	}
	var b bundle
	if err := decodeStrict(bytes.NewReader(raw), &b); err != nil {
		return Request{}, err
	}
	req := Request{Version: b.Version, Admins: b.Admins}
	if s := b.SSO; s != nil {
		secret, err := readSecret("sso.clientSecretFile", s.ClientSecretFile)
		if err != nil {
			return Request{}, err
		}
		var hmac string
		if s.DirectoryHMACSecretFile != "" {
			if hmac, err = readSecret("sso.directoryHmacSecretFile", s.DirectoryHMACSecretFile); err != nil {
				return Request{}, err
			}
		}
		req.SSO = &SSO{IssuerURL: s.IssuerURL, ClientID: s.ClientID, ClientSecret: secret, RedirectURI: s.RedirectURI, HMACSecret: hmac}
	}
	if bb := b.Backup; bb != nil {
		req.Backup = &Backup{Dir: bb.Dir, Keep: bb.Keep, DepositInterval: bb.DepositInterval}
		if rc := bb.Recovery; rc != nil {
			code, err := readSecret("backup.recovery.pairingCodeFile", rc.PairingCodeFile)
			if err != nil {
				return Request{}, err
			}
			req.Backup.Recovery = &Recovery{URL: rc.URL, PairingCode: code}
		}
	}
	return req, req.Validate(allowPrivate)
}

// readCapped refuses anything but a regular file (a FIFO would block the open) and
// anything larger than max.
func readCapped(path string, max int64) ([]byte, error) {
	if st, err := os.Stat(path); err != nil {
		return nil, err
	} else if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return raw, nil
}

// readSecret names the field, never the content, in every error.
func readSecret(field, path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s: want an absolute path inside the container", field)
	}
	raw, err := readCapped(path, MaxSecretBytes)
	if err != nil {
		return "", fmt.Errorf("%s: %w", field, err)
	}
	v := strings.TrimRight(string(raw), "\r\n")
	if !secretOK(v) {
		return "", fmt.Errorf("%s: empty or contains control characters", field)
	}
	return v, nil
}
```

- [ ] **Step 4: Run tests.** `go test ./internal/applysetup` → PASS.

- [ ] **Step 5: Commit.** `git add internal/applysetup && git commit -m "applysetup: load bundles with secrets by file path"` (with trailer).

---

### Task 3: Per-section decisions

**Files:**
- Create: `internal/applysetup/decide.go`
- Test: `internal/applysetup/decide_test.go`

**Interfaces:**
- Consumes: `sso.SSOSettings` (`internal/sso/sso.go:26-34`; every field is comparable, so `==` works).
- Produces:
  - `type Status string`; `const Created Status = "created"`, `Present = "present"`, `Conflict = "conflict"`, `Invalid = "invalid"`, `Failed = "failed"`
  - `func WantSSO(s SSO) sso.SSOSettings`
  - `func DecideSSO(have, want sso.SSOSettings) Status`
  - `func SSODiff(have, want sso.SSOSettings) string`
  - `type Account struct { ID, Username, Role, Status string }`
  - `type AdminAction int`; `const NoAction AdminAction = iota; CreateAdmin; GrantAdmin`
  - `func DecideAdmin(bound, named *Account) (Status, AdminAction, string)`
  - `func DecideFixed(running, want, env string) (Status, string)`
  - `func DecideInterval(stored, want int64) Status` (`stored < 0` means unset)
  - `func DecideRecovery(keyID, pairedURL, wantURL string) (status Status, claim bool)`

- [ ] **Step 1: Write the failing test.** Create `internal/applysetup/decide_test.go`:

```go
package applysetup

import (
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/sso"
)

func TestDecideSSO(t *testing.T) {
	want := WantSSO(SSO{IssuerURL: "https://id.example", ClientID: "kynotes", ClientSecret: "client-secret-value", RedirectURI: "https://notes.example/api/v1/auth/oidc/callback"})
	if !want.Enabled || !want.AutoProvision {
		t.Fatalf("%+v", want)
	}
	// sso.Store.Reload reports AutoProvision=true when nothing is stored.
	if DecideSSO(sso.SSOSettings{AutoProvision: true}, want) != Created {
		t.Fatal("empty settings must be created")
	}
	if DecideSSO(want, want) != Present {
		t.Fatal("identical settings must be present")
	}
	paired := sso.SSOSettings{Enabled: true, IssuerURL: "https://id.example", ClientID: "kynotes", AutoProvision: true, HMACSecret: "paired-hmac-value"}
	if DecideSSO(paired, want) != Conflict {
		t.Fatal("a KySignOn pairing must not be overwritten")
	}
	if DecideSSO(sso.SSOSettings{IssuerURL: "https://id.example", AutoProvision: true}, want) != Conflict {
		t.Fatal("disabled but configured settings must not be overwritten")
	}
	d := SSODiff(paired, want)
	for _, field := range []string{"clientSecret", "redirectUri", "hmacSecret"} {
		if !strings.Contains(d, field) {
			t.Errorf("diff %q lacks %s", d, field)
		}
	}
	if strings.Contains(d, "client-secret-value") || strings.Contains(d, "paired-hmac-value") || strings.Contains(d, "issuerUrl") {
		t.Fatalf("diff %q leaks values or names equal fields", d)
	}
}

func TestDecideAdmin(t *testing.T) {
	admin := &Account{ID: "usr_1", Username: "owner", Role: "admin", Status: "active"}
	user := &Account{ID: "usr_1", Username: "owner", Role: "user", Status: "active"}
	disabled := &Account{ID: "usr_1", Username: "owner", Role: "user", Status: "disabled"}
	other := &Account{ID: "usr_2", Username: "owner-admin", Role: "admin", Status: "active"}
	for _, c := range []struct {
		name         string
		bound, named *Account
		status       Status
		action       AdminAction
	}{
		{"new identity", nil, nil, Created, CreateAdmin},
		{"bound admin", admin, nil, Present, NoAction},
		{"bound user", user, nil, Created, GrantAdmin},
		{"bound disabled", disabled, nil, Conflict, NoAction},
		{"username taken", nil, other, Conflict, NoAction},
	} {
		st, act, _ := DecideAdmin(c.bound, c.named)
		if st != c.status || act != c.action {
			t.Errorf("%s: got %s/%d", c.name, st, act)
		}
	}
}

func TestDecideFixed(t *testing.T) {
	if st, _ := DecideFixed("/backups", "/backups", "KYNOTES_BACKUP_DIR"); st != Present {
		t.Fatal(st)
	}
	st, d := DecideFixed("", "/backups", "KYNOTES_BACKUP_DIR")
	if st != Conflict || !strings.Contains(d, "KYNOTES_BACKUP_DIR") {
		t.Fatal(st, d)
	}
}

func TestDecideInterval(t *testing.T) {
	for _, c := range []struct {
		stored, want int64
		status       Status
	}{{-1, 86400, Created}, {86400, 86400, Present}, {3600, 86400, Conflict}, {0, 86400, Conflict}} {
		if got := DecideInterval(c.stored, c.want); got != c.status {
			t.Errorf("%d→%d: %s", c.stored, c.want, got)
		}
	}
}

func TestDecideRecovery(t *testing.T) {
	const url = "https://kyrecovery.example"
	for _, c := range []struct {
		name                string
		keyID, paired, want string
		status              Status
		claim               bool
	}{
		{"fresh", "", "", url, Created, true},
		{"key pinned by hand", "key1", "", url, Created, true},
		{"already paired", "key1", url, url, Present, false},
		{"paired elsewhere", "key1", "https://other.example", url, Conflict, false},
		{"pairing without key", "", url, url, Conflict, false},
	} {
		st, claim := DecideRecovery(c.keyID, c.paired, c.want)
		if st != c.status || claim != c.claim {
			t.Errorf("%s: got %s claim=%t", c.name, st, claim)
		}
	}
}
```

- [ ] **Step 2: Run it and see it fail.** `go test ./internal/applysetup -run TestDecide` → FAIL (undefined: WantSSO, …).

- [ ] **Step 3: Implement.** Create `internal/applysetup/decide.go`:

```go
package applysetup

import (
	"fmt"
	"strings"

	"github.com/Busnes-app/kynotes-server/internal/sso"
)

type Status string

const (
	Created  Status = "created"
	Present  Status = "present"
	Conflict Status = "conflict"
	Invalid  Status = "invalid"
	Failed   Status = "failed"
)

// WantSSO is the stored form of the bundle's SSO section, with the same AutoProvision as
// KySignOn pairing.
func WantSSO(s SSO) sso.SSOSettings {
	return sso.SSOSettings{Enabled: true, IssuerURL: s.IssuerURL, ClientID: s.ClientID, ClientSecret: s.ClientSecret, RedirectURI: s.RedirectURI, AutoProvision: true, HMACSecret: s.HMACSecret}
}

// DecideSSO creates only when nothing is configured. AutoProvision is ignored for
// emptiness because an empty store reports it as true.
func DecideSSO(have, want sso.SSOSettings) Status {
	switch {
	case have == want:
		return Present
	case !have.Enabled && have.IssuerURL == "" && have.ClientID == "" && have.ClientSecret == "" && have.RedirectURI == "" && have.HMACSecret == "":
		return Created
	}
	return Conflict
}

// SSODiff names the differing fields, never their values.
func SSODiff(have, want sso.SSOSettings) string {
	var d []string
	for _, f := range []struct {
		name string
		same bool
	}{
		{"enabled", have.Enabled == want.Enabled},
		{"issuerUrl", have.IssuerURL == want.IssuerURL},
		{"clientId", have.ClientID == want.ClientID},
		{"clientSecret", have.ClientSecret == want.ClientSecret},
		{"redirectUri", have.RedirectURI == want.RedirectURI},
		{"autoProvision", have.AutoProvision == want.AutoProvision},
		{"hmacSecret", have.HMACSecret == want.HMACSecret},
	} {
		if !f.same {
			d = append(d, f.name)
		}
	}
	return "existing SSO settings differ in " + strings.Join(d, ", ") + "; left unchanged"
}

type Account struct{ ID, Username, Role, Status string }

type AdminAction int

const (
	NoAction AdminAction = iota
	CreateAdmin
	GrantAdmin
)

// DecideAdmin: bound is the account bound to the identity's issuer+subject; named is the
// account holding the bundle's username, looked up only when nothing is bound.
func DecideAdmin(bound, named *Account) (Status, AdminAction, string) {
	switch {
	case bound != nil && bound.Status != "active":
		return Conflict, NoAction, "the account bound to this identity is disabled; the directory owns its status"
	case bound != nil && bound.Role == "admin":
		return Present, NoAction, ""
	case bound != nil:
		return Created, GrantAdmin, "granted admin to the account bound to this identity"
	case named != nil:
		return Conflict, NoAction, "username belongs to another account; bindings are never adopted by username"
	}
	return Created, CreateAdmin, ""
}

// DecideFixed checks a value the process reads from its environment at start.
func DecideFixed(running, want, env string) (Status, string) {
	if running == want {
		return Present, ""
	}
	return Conflict, fmt.Sprintf("running value is %q; set %s and restart the container", running, env)
}

func DecideInterval(stored, want int64) Status {
	switch {
	case stored < 0:
		return Created
	case stored == want:
		return Present
	}
	return Conflict
}

// DecideRecovery claims only when this instance is not paired, so a rerun never spends a
// code. A pairing without a pinned key is left for the admin UI.
func DecideRecovery(keyID, pairedURL, wantURL string) (Status, bool) {
	switch {
	case pairedURL == "":
		return Created, true
	case pairedURL != wantURL || keyID == "":
		return Conflict, false
	}
	return Present, false
}
```

- [ ] **Step 4: Run tests.** `go test ./internal/applysetup` → PASS.

- [ ] **Step 5: Commit.** `git add internal/applysetup && git commit -m "applysetup: per-section created/present/conflict decisions"` (with trailer).

---

### Task 4: Report and exit code

**Files:**
- Create: `internal/applysetup/report.go`
- Test: `internal/applysetup/report_test.go`

**Interfaces:**
- Consumes: `Status` constants (Task 3), `Version` (Task 1).
- Produces:
  - `const ExitOK = 0`, `ExitError = 1`, `ExitInvalid = 2`, `ExitConflict = 3`
  - `type Result struct { Section string; Status Status; Detail string }` (JSON `section`, `status`, `detail,omitempty`)
  - `type Handover struct { URL string; AdminUsernames []string; RecoveryKeyFingerprint, BackupDir, Version string }` (JSON `url`, `adminUsernames`, `recoveryKeyFingerprint`, `backupDir`, `version`)
  - `type Report struct { Version int; Results []Result; Handover Handover }` (JSON `version`, `results`, `handover`)
  - `func NewReport(results []Result, h Handover) Report`
  - `func (r Report) ExitCode() int`
  - `func Origin(raw string) string`

- [ ] **Step 1: Write the failing test.** Create `internal/applysetup/report_test.go`:

```go
package applysetup

import (
	"encoding/json"
	"testing"
)

func TestExitCodePrecedence(t *testing.T) {
	report := func(statuses ...Status) Report {
		var rs []Result
		for _, s := range statuses {
			rs = append(rs, Result{Section: "x", Status: s})
		}
		return NewReport(rs, Handover{})
	}
	for _, c := range []struct {
		r    Report
		want int
	}{
		{report(), ExitOK},
		{report(Created, Present), ExitOK},
		{report(Present, Conflict), ExitConflict},
		{report(Conflict, Failed), ExitError},
		{report(Failed, Invalid, Conflict), ExitInvalid},
	} {
		if got := c.r.ExitCode(); got != c.want {
			t.Errorf("%+v: got %d want %d", c.r.Results, got, c.want)
		}
	}
}

func TestReportJSONShape(t *testing.T) {
	b, err := json.Marshal(NewReport(nil, Handover{URL: "https://notes.example", Version: "v1"}))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"results":[],"handover":{"url":"https://notes.example","adminUsernames":[],"recoveryKeyFingerprint":"","backupDir":"","version":"v1"}}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
	b, _ = json.Marshal(Result{Section: "sso", Status: Present})
	if string(b) != `{"section":"sso","status":"present"}` {
		t.Fatalf("got %s", b)
	}
}

func TestOrigin(t *testing.T) {
	if got := Origin("https://notes.example/api/v1/auth/oidc/callback"); got != "https://notes.example" {
		t.Fatal(got)
	}
	if got := Origin(""); got != "" {
		t.Fatal(got)
	}
}
```

- [ ] **Step 2: Run it and see it fail.** `go test ./internal/applysetup -run 'TestExitCode|TestReport|TestOrigin'` → FAIL.

- [ ] **Step 3: Implement.** Create `internal/applysetup/report.go`:

```go
package applysetup

import "net/url"

const (
	ExitOK       = 0
	ExitError    = 1
	ExitInvalid  = 2
	ExitConflict = 3
)

type Result struct {
	Section string `json:"section"`
	Status  Status `json:"status"`
	Detail  string `json:"detail,omitempty"`
}

// Handover carries only non-secret facts for the installer's handover record.
type Handover struct {
	URL                    string   `json:"url"`
	AdminUsernames         []string `json:"adminUsernames"`
	RecoveryKeyFingerprint string   `json:"recoveryKeyFingerprint"`
	BackupDir              string   `json:"backupDir"`
	Version                string   `json:"version"`
}

type Report struct {
	Version  int      `json:"version"`
	Results  []Result `json:"results"`
	Handover Handover `json:"handover"`
}

func NewReport(results []Result, h Handover) Report {
	if results == nil {
		results = []Result{}
	}
	if h.AdminUsernames == nil {
		h.AdminUsernames = []string{}
	}
	return Report{Version: Version, Results: results, Handover: h}
}

// ExitCode: invalid input first, then errors, then conflicts.
func (r Report) ExitCode() int {
	code := ExitOK
	for _, x := range r.Results {
		switch x.Status {
		case Invalid:
			return ExitInvalid
		case Failed:
			code = ExitError
		case Conflict:
			if code == ExitOK {
				code = ExitConflict
			}
		}
	}
	return code
}

func Origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
```

- [ ] **Step 4: Run tests.** `go test ./internal/applysetup` → PASS.

- [ ] **Step 5: Commit.** `git add internal/applysetup && git commit -m "applysetup: report and exit codes"` (with trailer).

---

### Task 5: One shared `sso.Store` between the router and apply-setup

**Files:**
- Modify: `internal/httpapi/router.go:17-36`
- Test: `internal/httpapi/apply_setup_test.go` (create)

**Interfaces:**
- Consumes: `sso.NewStore(db *sql.DB) *sso.Store`.
- Produces: `NewRouter(…, extras ...any)` accepts a `*sso.Store` extra and uses it instead of creating its own.

- [ ] **Step 1: Write the failing test.** Create `internal/httpapi/apply_setup_test.go`:

```go
package httpapi

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/sso"
)

func TestRouterUsesSuppliedSSOStore(t *testing.T) {
	db, cfg := setupTestDB(t)
	store := sso.NewStore(db)
	h := NewRouter(logging.New(io.Discard, "info", "json"), 1<<20, func() bool { return true }, db, cfg, store)
	if err := store.Save(sso.SSOSettings{Enabled: true, IssuerURL: "https://id.example", ClientID: "kynotes"}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/auth/sso-config", nil))
	if !strings.Contains(rec.Body.String(), `"issuerUrl":"https://id.example"`) {
		t.Fatalf("router served stale SSO settings: %s", rec.Body.String())
	}
}
```

- [ ] **Step 2: Run it and see it fail.** `go test ./internal/httpapi -run TestRouterUsesSuppliedSSOStore` → FAIL (router's own store still has the empty cache).

- [ ] **Step 3: Implement.** In `internal/httpapi/router.go`:
  - After `var backups *backup.Service` (line 22), add `var ssoStore *sso.Store`.
  - In the `switch v := extra.(type)` add:

```go
		case *sso.Store:
			ssoStore = v
```

  - Replace line 36 `ssoStore := sso.NewStore(db)` with:

```go
		if ssoStore == nil {
			ssoStore = sso.NewStore(db)
		}
```

- [ ] **Step 4: Run tests.** `go test ./internal/httpapi` → PASS.

- [ ] **Step 5: Commit.** `git add internal/httpapi && git commit -m "httpapi: router accepts the shared SSO store"` (with trailer).

---

### Task 6: Apply the SSO section

**Files:**
- Create: `internal/httpapi/apply_setup.go`
- Test: `internal/httpapi/apply_setup_test.go` (append)

**Interfaces:**
- Consumes:
  - `applysetup.WantSSO`, `DecideSSO`, `SSODiff`, `Result`, the status constants, `Actor` and `RequestID`.
  - `sso.DiscoverEndpoints(ctx, issuerURL) (*sso.DiscoveryDoc, error)` (`internal/sso/sso.go:172`).
  - `(*sso.Store).Load()` and `Save(sso.SSOSettings) error`.
  - `storage.RecordAuditOutcome(db, actor, event, container, object, outcome, reason, requestID string) error`.
- Produces: `func applySSO(ctx context.Context, db *sql.DB, store *sso.Store, want applysetup.SSO) applysetup.Result`.

- [ ] **Step 1: Write the failing test.** Append to `internal/httpapi/apply_setup_test.go`. Add the imports `"context"`, `"crypto/tls"`, `"database/sql"`, `"encoding/json"`, `"net"`, `"net/http"`, `"github.com/Busnes-app/kynotes-server/internal/applysetup"`.

```go
// setupIssuer serves OIDC discovery as https://example.com:<port> (a name the httptest
// certificate covers) and routes the default transport to it for this test.
func setupIssuer(t *testing.T, mismatch bool) string {
	t.Helper()
	var issuer string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := issuer
		if mismatch {
			doc = "https://other.example"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": doc, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"})
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	issuer = "https://example.com:" + port
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: "example.com"}
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	old := http.DefaultTransport
	http.DefaultTransport = tr
	t.Cleanup(func() { http.DefaultTransport = old })
	return issuer
}

func setupAuditCount(t *testing.T, db *sql.DB, event string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE event=? AND actor_user_id=? AND request_id=?`, event, applysetup.Actor, applysetup.RequestID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func setupSSO(issuer string) applysetup.SSO {
	return applysetup.SSO{IssuerURL: issuer, ClientID: "kynotes", ClientSecret: "client-secret-value", RedirectURI: "https://notes.example/api/v1/auth/oidc/callback", HMACSecret: "hmac-secret-value"}
}

func TestApplySSOCreatesThenPresentThenConflict(t *testing.T) {
	db, _ := setupTestDB(t)
	store := sso.NewStore(db)
	want := setupSSO(setupIssuer(t, false))
	ctx := context.Background()
	if r := applySSO(ctx, db, store, want); r.Status != applysetup.Created {
		t.Fatalf("%+v", r)
	}
	if store.Load() != applysetup.WantSSO(want) {
		t.Fatalf("stored %+v", store.Load())
	}
	if r := applySSO(ctx, db, store, want); r.Status != applysetup.Present {
		t.Fatalf("%+v", r)
	}
	other := want
	other.ClientSecret = "different-secret-value"
	r := applySSO(ctx, db, store, other)
	if r.Status != applysetup.Conflict || !strings.Contains(r.Detail, "clientSecret") || strings.Contains(r.Detail, "secret-value") {
		t.Fatalf("%+v", r)
	}
	if store.Load() != applysetup.WantSSO(want) {
		t.Fatal("conflict overwrote settings")
	}
	if n := setupAuditCount(t, db, "admin.sso_update"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

func TestApplySSOProbeFailureStoresNothing(t *testing.T) {
	db, _ := setupTestDB(t)
	store := sso.NewStore(db)
	r := applySSO(context.Background(), db, store, setupSSO(setupIssuer(t, true)))
	if r.Status != applysetup.Invalid || !strings.Contains(r.Detail, "issuer metadata probe failed") {
		t.Fatalf("%+v", r)
	}
	if store.Load().IssuerURL != "" || setupAuditCount(t, db, "admin.sso_update") != 0 {
		t.Fatal("probe failure stored or audited settings")
	}
}
```

> `srv.Client().Transport` trusts the httptest certificate through `TLSClientConfig.RootCAs`; that certificate's SANs include `example.com`.

- [ ] **Step 2: Run it and see it fail.** `go test ./internal/httpapi -run TestApplySSO` → FAIL (undefined: applySSO).

- [ ] **Step 3: Implement.** Create `internal/httpapi/apply_setup.go`:

```go
package httpapi

import (
	"context"
	"database/sql"

	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// applySSO stores the bundle's SSO settings only when none exist, after the same
// discovery check login uses. It writes through the router's store so login sees it now.
func applySSO(ctx context.Context, db *sql.DB, store *sso.Store, want applysetup.SSO) applysetup.Result {
	have, next := store.Load(), applysetup.WantSSO(want)
	res := applysetup.Result{Section: "sso", Status: applysetup.DecideSSO(have, next)}
	switch res.Status {
	case applysetup.Present:
		return res
	case applysetup.Conflict:
		res.Detail = applysetup.SSODiff(have, next)
		return res
	}
	if _, err := sso.DiscoverEndpoints(ctx, next.IssuerURL); err != nil {
		res.Status, res.Detail = applysetup.Invalid, "issuer metadata probe failed: "+err.Error()
		return res
	}
	if err := store.Save(next); err != nil {
		res.Status, res.Detail = applysetup.Failed, "storing SSO settings failed"
		return res
	}
	if err := storage.RecordAuditOutcome(db, applysetup.Actor, "admin.sso_update", "", "", "success", applysetup.RequestID, applysetup.RequestID); err != nil {
		res.Status, res.Detail = applysetup.Failed, "SSO settings stored but the audit row failed"
	}
	return res
}
```

- [ ] **Step 4: Run tests.** `go test ./internal/httpapi -run 'TestApplySSO|TestRouterUses'` → PASS.

- [ ] **Step 5: Commit.** `git add internal/httpapi && git commit -m "httpapi: apply-setup SSO section"` (with trailer).

---

### Task 7: Apply the admins section

**Files:**
- Modify: `internal/httpapi/sso_directory.go:298-308`. Extract `revokeForRoleChange`; behavior is unchanged.
- Modify: `internal/httpapi/apply_setup.go` (append)
- Test: `internal/httpapi/apply_setup_test.go` (append)

**Interfaces:**
- Consumes:
  - `applysetup.DecideAdmin`, `Account`, `Admin`, `CreateAdmin`, `GrantAdmin`, `NoAction`.
  - `auth.HashAuthSecret(string) (string, error)`, `auth.SyntheticLoginSalt(key, username string) string`, `ids.Mint("usr")`.
  - `storage.RecordAuditOutcomeTx`.
- Produces:
  - `func revokeForRoleChange(tx *sql.Tx, issuer, subject, userID, now string) error`
  - `func applyAdmin(db *sql.DB, cfg config.Config, issuer string, want applysetup.Admin) (applysetup.Result, string)`. The second value is the bound account's username, or empty on conflict, invalid or failed.

- [ ] **Step 1: Write the failing test.** Append to `internal/httpapi/apply_setup_test.go` (add import `"time"`):

```go
const setupTestIssuer = "https://id.example"

func TestApplyAdminCreatesBindingWithoutPassword(t *testing.T) {
	db, cfg := setupTestDB(t)
	want := applysetup.Admin{Issuer: setupTestIssuer, Subject: "sub-owner", Username: "Owner-Admin"}
	res, name := applyAdmin(db, cfg, setupTestIssuer, want)
	if res.Status != applysetup.Created || name != "owner-admin" {
		t.Fatalf("%+v %q", res, name)
	}
	var role, status, issuer, subject, hash string
	if err := db.QueryRow(`SELECT role,status,sso_issuer,sso_subject,auth_secret_hash FROM users WHERE username='owner-admin'`).Scan(&role, &status, &issuer, &subject, &hash); err != nil {
		t.Fatal(err)
	}
	if role != "admin" || status != "active" || issuer != setupTestIssuer || subject != "sub-owner" || hash == "" {
		t.Fatal(role, status, issuer, subject)
	}
	if res, _ = applyAdmin(db, cfg, setupTestIssuer, want); res.Status != applysetup.Present {
		t.Fatalf("%+v", res)
	}
	if n := setupAuditCount(t, db, "admin.user.create"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

func TestApplyAdminGrantRevokesCredentials(t *testing.T) {
	db, cfg := setupTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,status,sso_issuer,sso_subject,created_at,updated_at) VALUES('usr_b','owner','x','salt',600000,'user','active',?,'sub-owner',?,?)`, setupTestIssuer, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('ses_b','usr_b','tok','csrf',?,?,?)`, now, now, now); err != nil {
		t.Fatal(err)
	}
	res, name := applyAdmin(db, cfg, setupTestIssuer, applysetup.Admin{Issuer: setupTestIssuer, Subject: "sub-owner", Username: "owner-admin"})
	if res.Status != applysetup.Created || name != "owner" {
		t.Fatalf("%+v %q", res, name)
	}
	var role, revoked string
	_ = db.QueryRow(`SELECT role FROM users WHERE id='usr_b'`).Scan(&role)
	_ = db.QueryRow(`SELECT revoked_at FROM sessions WHERE id='ses_b'`).Scan(&revoked)
	if role != "admin" || revoked == "" {
		t.Fatalf("role=%q revoked_at=%q", role, revoked)
	}
	if n := setupAuditCount(t, db, "admin.user.update"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

func TestApplyAdminNeverAdoptsByUsername(t *testing.T) {
	db, cfg := setupTestDB(t)
	createAdminUser(t, db) // local, unbound account named "admin"
	res, name := applyAdmin(db, cfg, setupTestIssuer, applysetup.Admin{Issuer: setupTestIssuer, Subject: "sub-x", Username: "ADMIN"})
	if res.Status != applysetup.Conflict || name != "" {
		t.Fatalf("%+v %q", res, name)
	}
	var subject string
	_ = db.QueryRow(`SELECT coalesce(sso_subject,'') FROM users WHERE username='admin'`).Scan(&subject)
	if subject != "" || setupAuditCount(t, db, "admin.user.create")+setupAuditCount(t, db, "admin.user.update") != 0 {
		t.Fatal("local account was bound or audited")
	}
}

func TestApplyAdminRefusesDisabledBindingAndForeignIssuer(t *testing.T) {
	db, cfg := setupTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,status,sso_issuer,sso_subject,created_at,updated_at) VALUES('usr_d','gone','x','salt',600000,'user','disabled',?,'sub-gone',?,?)`, setupTestIssuer, now, now); err != nil {
		t.Fatal(err)
	}
	if res, _ := applyAdmin(db, cfg, setupTestIssuer, applysetup.Admin{Issuer: setupTestIssuer, Subject: "sub-gone", Username: "gone"}); res.Status != applysetup.Conflict {
		t.Fatalf("%+v", res)
	}
	want := applysetup.Admin{Issuer: setupTestIssuer, Subject: "sub-new", Username: "new"}
	for _, configured := range []string{"", "https://other.example"} {
		if res, _ := applyAdmin(db, cfg, configured, want); res.Status != applysetup.Invalid {
			t.Fatalf("issuer %q: %+v", configured, res)
		}
	}
}
```

- [ ] **Step 2: Run it and see it fail.** `go test ./internal/httpapi -run TestApplyAdmin` → FAIL (undefined: applyAdmin).

- [ ] **Step 3: Implement.**

  First, in `internal/httpapi/sso_directory.go`, replace the block at lines 298-308. The current text:

```go
	if u.localRole() != existingRole {
		if _, err := db.Exec(`UPDATE sso_directory_state SET revoked_before=max(revoked_before,?) WHERE issuer=? AND subject=?`, time.Now().Unix(), issuer, u.ID); err != nil {
			return false, err
		}
		// Both promotion and demotion require fresh sessions and device pairing.
		for _, table := range []string{"sessions", "devices"} {
			if _, err := db.Exec(`UPDATE `+table+` SET revoked_at=? WHERE user_id=? AND revoked_at=''`, now, existingID); err != nil {
				return false, err
			}
		}
	}
```

  becomes:

```go
	if u.localRole() != existingRole {
		if err := revokeForRoleChange(db, issuer, u.ID, existingID, now); err != nil {
			return false, err
		}
	}
```

  and append to the same file:

```go
// revokeForRoleChange: promotion and demotion both require fresh sessions, device pairing
// and login proofs.
func revokeForRoleChange(tx *sql.Tx, issuer, subject, userID, now string) error {
	if _, err := tx.Exec(`UPDATE sso_directory_state SET revoked_before=max(revoked_before,?) WHERE issuer=? AND subject=?`, time.Now().Unix(), issuer, subject); err != nil {
		return err
	}
	for _, table := range []string{"sessions", "devices"} {
		if _, err := tx.Exec(`UPDATE `+table+` SET revoked_at=? WHERE user_id=? AND revoked_at=''`, now, userID); err != nil {
			return err
		}
	}
	return nil
}
```

  Then append to `internal/httpapi/apply_setup.go`, adding the imports `"crypto/rand"`, `"encoding/hex"`, `"errors"`, `"strings"`, `"time"`, `".../internal/auth"`, `".../internal/config"` and `".../internal/ids"`:

```go
// applyAdmin ensures an active admin bound to issuer+subject. Accounts are never adopted by
// username; a grant revokes the account's credentials like a directory promotion.
func applyAdmin(db *sql.DB, cfg config.Config, issuer string, want applysetup.Admin) (applysetup.Result, string) {
	res := applysetup.Result{Section: "admin:" + strings.ToLower(want.Username)}
	failed := func() (applysetup.Result, string) {
		res.Status, res.Detail = applysetup.Failed, "account update failed"
		return res, ""
	}
	if issuer == "" || want.Issuer != issuer {
		res.Status, res.Detail = applysetup.Invalid, "admin issuer must equal the configured SSO issuer"
		return res, ""
	}
	tx, err := db.Begin()
	if err != nil {
		return failed()
	}
	defer tx.Rollback()
	bound, err := lookupAccount(tx, `SELECT id,username,role,status FROM users WHERE sso_issuer=? AND sso_subject=?`, want.Issuer, want.Subject)
	if err != nil {
		return failed()
	}
	var named *applysetup.Account
	if bound == nil {
		if named, err = lookupAccount(tx, `SELECT id,username,role,status FROM users WHERE username=?`, strings.ToLower(want.Username)); err != nil {
			return failed()
		}
	}
	status, action, detail := applysetup.DecideAdmin(bound, named)
	res.Status, res.Detail = status, detail
	now := time.Now().UTC().Format(time.RFC3339)
	switch action {
	case applysetup.CreateAdmin:
		err = createSSOAdmin(tx, cfg, want, now)
	case applysetup.GrantAdmin:
		err = grantAdmin(tx, bound.ID, want, now)
	}
	if err == nil && action != applysetup.NoAction {
		err = tx.Commit()
	}
	switch {
	case err != nil:
		return failed()
	case status == applysetup.Conflict:
		return res, ""
	case bound != nil:
		return res, bound.Username
	}
	return res, strings.ToLower(want.Username)
}

func lookupAccount(tx *sql.Tx, query string, args ...any) (*applysetup.Account, error) {
	var a applysetup.Account
	err := tx.QueryRow(query, args...).Scan(&a.ID, &a.Username, &a.Role, &a.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func createSSOAdmin(tx *sql.Tx, cfg config.Config, want applysetup.Admin, now string) error {
	id, err := ids.Mint("usr")
	if err != nil {
		return err
	}
	// No usable password: the verifier is for a random secret nobody keeps.
	unusable := make([]byte, 32)
	if _, err := rand.Read(unusable); err != nil {
		return err
	}
	hash, err := auth.HashAuthSecret(hex.EncodeToString(unusable))
	if err != nil {
		return err
	}
	username := strings.ToLower(want.Username)
	if _, err = tx.Exec(`INSERT INTO users(id, username, auth_secret_hash, login_salt, login_iterations, role, status, sso_subject, sso_issuer, created_at, updated_at) VALUES(?, ?, ?, ?, 600000, 'admin', 'active', ?, ?, ?, ?)`,
		id, username, hash, auth.SyntheticLoginSalt(cfg.Secrets.ServerSaltKey, username), want.Subject, want.Issuer, now, now); err != nil {
		return err
	}
	return storage.RecordAuditOutcomeTx(tx, applysetup.Actor, "admin.user.create", "", id, "success", "role=admin", applysetup.RequestID)
}

func grantAdmin(tx *sql.Tx, userID string, want applysetup.Admin, now string) error {
	if err := revokeForRoleChange(tx, want.Issuer, want.Subject, userID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE users SET role='admin', updated_at=? WHERE id=?`, now, userID); err != nil {
		return err
	}
	return storage.RecordAuditOutcomeTx(tx, applysetup.Actor, "admin.user.update", "", userID, "success", "role=admin", applysetup.RequestID)
}
```

- [ ] **Step 4: Run tests.** `go test -race ./internal/httpapi` → PASS. This includes the directory tests that cover the extracted helper (`TestDirectory*`, `TestSSOAppRoles*`).

- [ ] **Step 5: Commit.** `git add internal/httpapi && git commit -m "httpapi: apply-setup admins bound by issuer and subject"` (with trailer).

---

### Task 8: Apply the backup section through the backup service

**Files:**
- Create: `internal/backup/setup.go`
- Test: `internal/backup/setup_test.go`

**Interfaces:**
- Consumes:
  - `(*Service).Pair(ctx, actor, requestID, url, code string) error` (`internal/backup/service.go:134`).
  - `(*Service).SetSchedule(actor, requestID string, seconds int64) error` (`:167`).
  - `ErrorCode(error) string`, `ErrInvalid`.
  - `recoveryclient.Interval(time.Duration, Settings)`, `recoveryclient.HasPairing`.
  - `applysetup.DecideFixed`, `DecideInterval`, `DecideRecovery`, `IntervalSeconds`, `Backup`, `Recovery`, `Result`.
- Produces:
  - `func (s *Service) ApplySetup(ctx context.Context, want applysetup.Backup) []applysetup.Result`. Sections: `backup.dir`, `backup.keep`, `backup.interval`, `backup.recovery`, each emitted only when the bundle sets it.
  - `func (s *Service) KeyID() (string, error)`

- [ ] **Step 1: Write the failing test.** Create `internal/backup/setup_test.go`:

```go
package backup

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kynotes-server/internal/applysetup"
)

type setupClaims struct {
	key    recoverykey.PrivateKey
	claims int
}

func (c *setupClaims) ClaimPairing(context.Context, string, string, string, string) (recoveryclient.PairingResult, error) {
	c.claims++
	return recoveryclient.PairingResult{APIToken: "setup-private-token", Key: recoveryclient.RecoveryKey{Public: c.key.Public(), Threshold: 2, TotalShares: 3}}, nil
}
func (c *setupClaims) Deposit(context.Context, string, string, []byte) (recoveryclient.Receipt, error) {
	return recoveryclient.Receipt{}, errors.New("apply-setup never deposits")
}

func setupStatuses(rs []applysetup.Result) map[string]applysetup.Result {
	out := map[string]applysetup.Result{}
	for _, r := range rs {
		out[r.Section] = r
	}
	return out
}

func setupAudits(t *testing.T, svc *Service, event string) int {
	t.Helper()
	var n int
	if err := svc.store.DB().QueryRow(`SELECT count(*) FROM audit_events WHERE event=? AND outcome='success' AND request_id=?`, event, applysetup.RequestID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestApplySetupLocalSettings(t *testing.T) {
	svc, _ := fixture(t)
	ctx := context.Background()
	want := applysetup.Backup{Dir: svc.cfg.Backup.Dir, Keep: svc.cfg.Backup.Keep, DepositInterval: "24h"}
	got := setupStatuses(svc.ApplySetup(ctx, want))
	if got["backup.dir"].Status != applysetup.Present || got["backup.keep"].Status != applysetup.Present || got["backup.interval"].Status != applysetup.Created {
		t.Fatalf("%+v", got)
	}
	if got = setupStatuses(svc.ApplySetup(ctx, want)); got["backup.interval"].Status != applysetup.Present {
		t.Fatalf("%+v", got)
	}
	got = setupStatuses(svc.ApplySetup(ctx, applysetup.Backup{Dir: "/elsewhere", Keep: 3, DepositInterval: "12h"}))
	for _, section := range []string{"backup.dir", "backup.keep", "backup.interval"} {
		if got[section].Status != applysetup.Conflict {
			t.Errorf("%s: %+v", section, got[section])
		}
	}
	if !strings.Contains(got["backup.dir"].Detail, "KYNOTES_BACKUP_DIR") {
		t.Fatal(got["backup.dir"].Detail)
	}
	if d, err := recoveryclient.Interval(0, settings{svc.store}); err != nil || d != 24*time.Hour {
		t.Fatalf("interval changed to %s (%v)", d, err)
	}
	if n := setupAudits(t, svc, "admin.backup_schedule"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

func TestApplySetupRecoveryPairsOnceAndNeverRepins(t *testing.T) {
	svc, key := fixture(t) // fixture pins key by hand
	claims := &setupClaims{key: key}
	svc.client = claims
	ctx := context.Background()
	want := applysetup.Backup{Recovery: &applysetup.Recovery{URL: "https://kyrecovery.example", PairingCode: "123456"}}
	if got := setupStatuses(svc.ApplySetup(ctx, want)); got["backup.recovery"].Status != applysetup.Created {
		t.Fatalf("%+v", got)
	}
	if got := setupStatuses(svc.ApplySetup(ctx, want)); got["backup.recovery"].Status != applysetup.Present || claims.claims != 1 {
		t.Fatalf("%+v claims=%d", got, claims.claims)
	}
	elsewhere := applysetup.Backup{Recovery: &applysetup.Recovery{URL: "https://kyrecovery-2.example", PairingCode: "654321"}}
	if got := setupStatuses(svc.ApplySetup(ctx, elsewhere)); got["backup.recovery"].Status != applysetup.Conflict || claims.claims != 1 {
		t.Fatalf("%+v claims=%d", got, claims.claims)
	}
	if n := setupAudits(t, svc, "admin.backup_pair"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

func TestApplySetupRecoveryKeyMismatchIsConflict(t *testing.T) {
	svc, _ := fixture(t)
	other, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	svc.client = &setupClaims{key: other}
	pinned, _ := svc.KeyID()
	got := svc.ApplySetup(context.Background(), applysetup.Backup{Recovery: &applysetup.Recovery{URL: "https://kyrecovery.example", PairingCode: "123456"}})
	if len(got) != 1 || got[0].Status != applysetup.Conflict {
		t.Fatalf("%+v", got)
	}
	if after, _ := svc.KeyID(); after != pinned || pinned == "" {
		t.Fatalf("pin moved from %q to %q", pinned, after)
	}
	if recoveryclient.HasPairing(settings{svc.store}) {
		t.Fatal("token stored for a refused key")
	}
}
```

- [ ] **Step 2: Run it and see it fail.** `go test ./internal/backup -run TestApplySetup` → FAIL (undefined: ApplySetup).

- [ ] **Step 3: Implement.** Create `internal/backup/setup.go`:

```go
package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"time"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// ApplySetup reconciles the installer's backup section. Directory and keep come from the
// process environment, so they are checked, not set.
func (s *Service) ApplySetup(ctx context.Context, want applysetup.Backup) []applysetup.Result {
	var out []applysetup.Result
	if want.Dir != "" {
		st, d := applysetup.DecideFixed(s.cfg.Backup.Dir, want.Dir, "KYNOTES_BACKUP_DIR")
		out = append(out, applysetup.Result{Section: "backup.dir", Status: st, Detail: d})
	}
	if want.Keep != 0 {
		st, d := applysetup.DecideFixed(strconv.Itoa(s.cfg.Backup.Keep), strconv.Itoa(want.Keep), "KYNOTES_BACKUP_KEEP")
		out = append(out, applysetup.Result{Section: "backup.keep", Status: st, Detail: d})
	}
	if want.DepositInterval != "" {
		out = append(out, s.applyInterval(want.DepositInterval))
	}
	if want.Recovery != nil {
		out = append(out, s.applyRecovery(ctx, *want.Recovery))
	}
	return out
}

func (s *Service) applyInterval(raw string) applysetup.Result {
	res := applysetup.Result{Section: "backup.interval"}
	sec, err := applysetup.IntervalSeconds(raw)
	if err != nil {
		res.Status, res.Detail = applysetup.Invalid, err.Error()
		return res
	}
	// Interval returns its default argument only when no admin setting exists.
	stored, err := recoveryclient.Interval(-time.Second, settings{s.store})
	if err != nil {
		res.Status, res.Detail = applysetup.Failed, ErrorCode(err)
		return res
	}
	res.Status = applysetup.DecideInterval(int64(stored/time.Second), sec)
	switch res.Status {
	case applysetup.Conflict:
		res.Detail = fmt.Sprintf("interval is already %s; left unchanged", stored)
	case applysetup.Created:
		if err := s.SetSchedule(applysetup.Actor, applysetup.RequestID, sec); err != nil {
			res.Status, res.Detail = applysetup.Failed, ErrorCode(err)
		}
	}
	return res
}

func (s *Service) applyRecovery(ctx context.Context, want applysetup.Recovery) applysetup.Result {
	res := applysetup.Result{Section: "backup.recovery"}
	keyID, err := s.KeyID()
	var pairedURL string
	if err == nil && recoveryclient.HasPairing(settings{s.store}) {
		pairedURL, err = s.setting("kyrecovery_url")
	}
	if err != nil {
		res.Status, res.Detail = applysetup.Failed, ErrorCode(err)
		return res
	}
	status, claim := applysetup.DecideRecovery(keyID, pairedURL, want.URL)
	res.Status = status
	if !claim {
		if status == applysetup.Conflict {
			res.Detail = "already paired to another KyRecovery, or the pairing has no pinned key; left unchanged"
		}
		return res
	}
	err = s.Pair(ctx, applysetup.Actor, applysetup.RequestID, want.URL, want.PairingCode)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrExist):
		res.Status, res.Detail = applysetup.Conflict, "KyRecovery returned a key other than the pinned one; the pin is unchanged and the code is spent"
	case errors.Is(err, ErrInvalid):
		res.Status, res.Detail = applysetup.Invalid, ErrorCode(err)
	default:
		res.Status, res.Detail = applysetup.Failed, ErrorCode(err)
	}
	return res
}

// KeyID is the pinned recovery key's ID, empty when none is pinned.
func (s *Service) KeyID() (string, error) { return s.setting("kyrecovery_key_id") }

func (s *Service) setting(k string) (string, error) {
	v, err := s.store.GetSetting(k)
	if errors.Is(err, storage.ErrNotFound) {
		return "", nil
	}
	return v, err
}
```

- [ ] **Step 4: Run tests.** `go test -race ./internal/backup` → PASS.

- [ ] **Step 5: Commit.** `git add internal/backup && git commit -m "backup: apply-setup reconciles schedule and KyRecovery pairing"` (with trailer).

---

### Task 9: Setup handler (apply, report, handover)

**Files:**
- Modify: `internal/httpapi/apply_setup.go` (append)
- Test: `internal/httpapi/apply_setup_test.go` (append)

**Interfaces:**
- Consumes:
  - `applySSO` (Task 6), `applyAdmin` (Task 7), `(*backup.Service).ApplySetup` and `KeyID` (Task 8).
  - `applysetup.DecodeRequest`, `NewReport`, `Handover`, `Origin`.
  - `WriteError` (`internal/httpapi/errors.go:19`), `writeJSON` (`auth_routes.go:449`), `backup.OperationTimeout`.
- Produces:
  - `type SetupDeps struct { DB *sql.DB; Config config.Config; SSO *sso.Store; Backups *backup.Service; Version string; Log *logging.Logger }`
  - `func SetupHandler(d SetupDeps) http.Handler`, serving `POST /v1/apply-setup`. It answers 200 with an `applysetup.Report`, 400 `invalid_bundle`, or 409 `apply_in_progress`.

- [ ] **Step 1: Write the failing test.** Append to `internal/httpapi/apply_setup_test.go` (add import `"bytes"`):

```go
func TestSetupHandlerAppliesAndNeverEchoesSecrets(t *testing.T) {
	db, cfg := setupTestDB(t)
	issuer := setupIssuer(t, false)
	var logs bytes.Buffer
	h := SetupHandler(SetupDeps{DB: db, Config: cfg, SSO: sso.NewStore(db), Version: "test", Log: logging.New(&logs, "debug", "json")})
	s := setupSSO(issuer)
	body, _ := json.Marshal(applysetup.Request{Version: 1, SSO: &s, Admins: []applysetup.Admin{{Issuer: issuer, Subject: "sub-owner", Username: "owner-admin"}}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/apply-setup", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var report applysetup.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	h2 := report.Handover
	if report.ExitCode() != applysetup.ExitOK || len(report.Results) != 2 || h2.URL != "https://notes.example" || len(h2.AdminUsernames) != 1 || h2.AdminUsernames[0] != "owner-admin" || h2.Version != "test" {
		t.Fatalf("%+v", report)
	}
	for _, secret := range []string{"client-secret-value", "hmac-secret-value"} {
		var inAudit int
		_ = db.QueryRow(`SELECT count(*) FROM audit_events WHERE instr(reason_code,?)>0 OR instr(object_id,?)>0`, secret, secret).Scan(&inAudit)
		if strings.Contains(rec.Body.String(), secret) || strings.Contains(logs.String(), secret) || inAudit != 0 {
			t.Fatalf("%s leaked", secret)
		}
	}
	if !strings.Contains(logs.String(), "apply_setup") {
		t.Fatal("no apply_setup log line")
	}
}

func TestSetupHandlerRejectsInvalidRequests(t *testing.T) {
	db, cfg := setupTestDB(t)
	h := SetupHandler(SetupDeps{DB: db, Config: cfg, SSO: sso.NewStore(db), Log: logging.New(io.Discard, "info", "json")})
	for _, body := range []string{
		`{"version":2}`,
		`{"version":1,"extra":1}`,
		`{"version":1,"sso":{"issuerUrl":"http://id.example","clientId":"kynotes","clientSecret":"client-secret-value","redirectUri":"https://notes.example/api/v1/auth/oidc/callback"}}`,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/apply-setup", strings.NewReader(body)))
		if rec.Code != 400 || strings.Contains(rec.Body.String(), "client-secret-value") {
			t.Fatalf("%s → %d %s", body, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/apply-setup", strings.NewReader(`{"version":1,"backup":{"keep":7}}`)))
	var report applysetup.Report
	_ = json.Unmarshal(rec.Body.Bytes(), &report)
	if rec.Code != 200 || len(report.Results) != 1 || report.Results[0].Status != applysetup.Failed {
		t.Fatalf("backup section without a backup service: %d %s", rec.Code, rec.Body.String())
	}
}
```

- [ ] **Step 2: Run it and see it fail.** `go test ./internal/httpapi -run TestSetupHandler` → FAIL (undefined: SetupHandler).

- [ ] **Step 3: Implement.** Append to `internal/httpapi/apply_setup.go`, adding the imports `"net/http"`, `"sync"`, `".../internal/backup"` and `".../internal/logging"`:

```go
type SetupDeps struct {
	DB      *sql.DB
	Config  config.Config
	SSO     *sso.Store
	Backups *backup.Service
	Version string
	Log     *logging.Logger
}

// SetupHandler serves apply-setup. It is mounted only on the admin Unix socket, never on
// the network router.
func SetupHandler(d SetupDeps) http.Handler {
	var running sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/apply-setup", func(w http.ResponseWriter, r *http.Request) {
		if !running.TryLock() {
			WriteError(w, r, http.StatusConflict, "apply_in_progress", "apply-setup is already running")
			return
		}
		defer running.Unlock()
		req, err := applysetup.DecodeRequest(http.MaxBytesReader(w, r.Body, 1<<20), d.Config.Backup.AllowPrivateRecovery)
		if err != nil {
			WriteError(w, r, http.StatusBadRequest, "invalid_bundle", err.Error())
			return
		}
		// A client hang-up must not abandon a pairing halfway.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), backup.OperationTimeout)
		defer cancel()
		report := applySetup(ctx, d, req)
		d.Log.Info("apply_setup", "outcome", report.ExitCode(), "count", len(report.Results))
		writeJSON(w, report)
	})
	return mux
}

func applySetup(ctx context.Context, d SetupDeps, req applysetup.Request) applysetup.Report {
	var results []applysetup.Result
	if req.SSO != nil {
		results = append(results, applySSO(ctx, d.DB, d.SSO, *req.SSO))
	}
	var admins []string
	for _, a := range req.Admins {
		res, username := applyAdmin(d.DB, d.Config, d.SSO.Load().IssuerURL, a)
		results = append(results, res)
		if username != "" {
			admins = append(admins, username)
		}
	}
	h := applysetup.Handover{URL: applysetup.Origin(d.SSO.Load().RedirectURI), AdminUsernames: admins, BackupDir: d.Config.Backup.Dir, Version: d.Version}
	switch {
	case d.Backups != nil:
		if req.Backup != nil {
			results = append(results, d.Backups.ApplySetup(ctx, *req.Backup)...)
		}
		h.RecoveryKeyFingerprint, _ = d.Backups.KeyID()
	case req.Backup != nil:
		results = append(results, applysetup.Result{Section: "backup", Status: applysetup.Failed, Detail: "backup service unavailable"})
	}
	return applysetup.NewReport(results, h)
}
```

- [ ] **Step 4: Run tests.** `go test -race ./internal/httpapi` → PASS.

- [ ] **Step 5: Commit.** `git add internal/httpapi && git commit -m "httpapi: apply-setup handler and report"` (with trailer).

---

### Task 10: Admin Unix socket owned by `app.Serve`

**Files:**
- Create: `internal/app/adminsock.go`, `internal/app/adminsock_linux.go`, `internal/app/adminsock_other.go`
- Test: `internal/app/adminsock_test.go`, `internal/app/adminsock_linux_test.go`
- Modify: `internal/app/serve.go:21` (signature), `:48` (socket after the worker defer), `:54` (router extras)
- Modify: `internal/app/serve_contract_test.go:17,30` (pass a version), `cmd/kynotes-server/main.go:138` (pass `version`)

**Interfaces:**
- Consumes: `httpapi.SetupHandler`, `httpapi.SetupDeps` (Task 9), `sso.NewStore`.
- Produces:
  - `func AdminSocketPath(dataDir string) string` (`<dataDir>/admin.sock`)
  - `func listenAdminSocket(dataDir string) (net.Listener, error)`
  - `type peerListener struct { net.Listener; uid int }`
  - `func peerAllowed(c *net.UnixConn, uid int) bool`
  - `func Serve(ctx context.Context, c config.Config, log *logging.Logger, version string) error`

- [ ] **Step 1: Write the failing tests.**

  Create `internal/app/adminsock_test.go`:

```go
package app

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
)

func TestAdminSocketIsPrivateAndReplacesOnlyStaleSockets(t *testing.T) {
	dir := t.TempDir()
	l, err := listenAdminSocket(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(AdminSocketPath(dir))
	if err != nil || st.Mode().Type() != fs.ModeSocket || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v", st.Mode(), err)
	}
	if l.Addr().Network() != "unix" {
		t.Fatal(l.Addr().Network())
	}
	// A crash leaves the socket file behind.
	l.(peerListener).Listener.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	l2, err := listenAdminSocket(dir)
	if err != nil {
		t.Fatal("stale socket not replaced:", err)
	}
	l2.Close()
	if _, err := os.Lstat(AdminSocketPath(dir)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("socket left after close")
	}
	if err := os.WriteFile(AdminSocketPath(dir), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenAdminSocket(dir); err == nil {
		t.Fatal("replaced a regular file")
	}
	if b, _ := os.ReadFile(AdminSocketPath(dir)); string(b) != "keep" {
		t.Fatal("regular file changed")
	}
}

func TestServeOwnsAdminSocketLifecycle(t *testing.T) {
	c := config.Defaults()
	c.DataDir = t.TempDir()
	c.Server.Bind = "127.0.0.1:0"
	c.Server.DevInsecureCookies = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, c, logging.New(io.Discard, "info", "json"), "test") }()
	sock := AdminSocketPath(c.DataDir)
	for deadline := time.Now().Add(5 * time.Second); ; {
		if conn, err := net.Dial("unix", sock); err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admin socket never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sock); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("socket left after shutdown")
	}
}
```

  Create `internal/app/adminsock_linux_test.go`:

```go
//go:build linux

package app

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPeerAllowedRefusesOtherUIDs(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always admitted")
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "p.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.Dial("unix", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if !peerAllowed(server, os.Getuid()) {
		t.Fatal("own uid refused")
	}
	if peerAllowed(server, os.Getuid()+1) {
		t.Fatal("other uid admitted")
	}
}
```

  Update `internal/app/serve_contract_test.go` lines 17 and 30 to `Serve(…, logging.New(io.Discard, "info", "json"), "test")`.

- [ ] **Step 2: Run them and see them fail.** `go test ./internal/app` → FAIL (undefined: listenAdminSocket, AdminSocketPath, peerAllowed; Serve arity).

- [ ] **Step 3: Implement.**

  Create `internal/app/adminsock.go`:

```go
package app

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
)

// AdminSocketPath is where apply-setup reaches the running server.
func AdminSocketPath(dataDir string) string { return filepath.Join(dataDir, "admin.sock") }

// listenAdminSocket binds the local admin socket at mode 0600. The caller holds the
// data-directory lock, so a socket already at the path is a crash leftover; any other
// file type is refused.
func listenAdminSocket(dataDir string) (net.Listener, error) {
	path := AdminSocketPath(dataDir)
	if st, err := os.Lstat(path); err == nil {
		if st.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("admin socket: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("admin socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return peerListener{Listener: l, uid: os.Getuid()}, nil
}

// peerListener closes connections from any uid but the server's own and root.
type peerListener struct {
	net.Listener
	uid int
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if uc, ok := c.(*net.UnixConn); ok && peerAllowed(uc, l.uid) {
			return c, nil
		}
		c.Close()
	}
}
```

  Create `internal/app/adminsock_linux.go`:

```go
//go:build linux

package app

import (
	"net"
	"syscall"
)

// peerAllowed admits the server's uid and root; both already own the container.
func peerAllowed(c *net.UnixConn, uid int) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || cerr != nil {
		return false
	}
	return int(cred.Uid) == uid || cred.Uid == 0
}
```

  Create `internal/app/adminsock_other.go`:

```go
//go:build !linux

package app

import "net"

// ponytail: peer credentials are read only on Linux, the shipped platform; elsewhere the
// socket refuses every peer. Upgrade path: getpeereid via golang.org/x/sys/unix.
func peerAllowed(*net.UnixConn, int) bool { return false }
```

  Edit `internal/app/serve.go`:
  - Line 21 becomes `func Serve(ctx context.Context, c config.Config, log *logging.Logger, version string) error {`.
  - Add imports `"os"` and `"github.com/Busnes-app/kynotes-server/internal/sso"`.
  - After line 48 (`defer func() { stopWorker(); <-workerDone }()`), insert the block below. Its defer runs before the worker, backup and store defers, so nothing applies while SQLite closes.

```go
	ssoStore := sso.NewStore(store.DB())
	adminLn, err := listenAdminSocket(c.DataDir)
	if err != nil {
		return err
	}
	admin := &http.Server{Handler: httpapi.SetupHandler(httpapi.SetupDeps{DB: store.DB(), Config: c, SSO: ssoStore, Backups: backups, Version: version, Log: log}), ReadHeaderTimeout: parse(c.Server.ReadHeaderTimeout)}
	go func() { _ = admin.Serve(adminLn) }()
	defer func() {
		sh, cancel := context.WithTimeout(context.Background(), parse(c.Server.ShutdownGrace))
		defer cancel()
		_ = admin.Shutdown(sh)
		_ = os.Remove(AdminSocketPath(c.DataDir))
	}()
```

  - On line 54, append `ssoStore` to the `httpapi.NewRouter(…)` extras: `…, store.DB(), blobs, c, backups, ssoStore)`.
  - In `cmd/kynotes-server/main.go:138`, change `app.Serve(ctx, c, log)` to `app.Serve(ctx, c, log, version)`.

- [ ] **Step 4: Run tests.** `go test -race ./internal/app ./cmd/kynotes-server && GOOS=darwin go vet ./internal/app` → PASS. The darwin vet proves the stub builds.

- [ ] **Step 5: Commit.** `git add internal/app cmd/kynotes-server/main.go && git commit -m "app: admin Unix socket for apply-setup"` (with trailer).

---

### Task 11: `apply-setup` CLI client

**Files:**
- Create: `cmd/kynotes-server/applysetup.go`
- Test: `cmd/kynotes-server/applysetup_test.go`
- Modify: `cmd/kynotes-server/main.go:27-28` (dispatch before `healthcheck`)

**Interfaces:**
- Consumes: `applysetup.Load`, `Report`, the `Exit*` constants, `app.AdminSocketPath`, `config.Load`.
- Produces:
  - `func applySetupCommand(args []string, stdout, stderr io.Writer) int`
  - `func postSetup(socket string, req applysetup.Request) ([]byte, int, error)`

- [ ] **Step 1: Write the failing test.** Create `cmd/kynotes-server/applysetup_test.go`:

```go
package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupCLIFixture(t *testing.T) (cfgPath, bundle, dataDir string) {
	t.Helper()
	dataDir = t.TempDir()
	cfgPath = filepath.Join(dataDir, "kynotes.yaml")
	bundle = filepath.Join(dataDir, "bundle.json")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dataDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, []byte(`{"version":1,"backup":{"keep":7}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, bundle, dataDir
}

func fakeSetupServer(t *testing.T, dataDir string, status int, body string) {
	t.Helper()
	l, err := net.Listen("unix", filepath.Join(dataDir, "admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func TestApplySetupExitCodes(t *testing.T) {
	report := func(status string) string {
		return `{"version":1,"results":[{"section":"backup.keep","status":"` + status + `"}],"handover":{}}` + "\n"
	}
	for _, c := range []struct {
		name   string
		status int
		body   string
		want   int
	}{
		{"applied", 200, report("present"), 0},
		{"conflict", 200, report("conflict"), 3},
		{"invalid on server", 200, report("invalid"), 2},
		{"failed", 200, report("failed"), 1},
		{"rejected", 400, `{"error":{"code":"invalid_bundle","message":"version: want 1"}}`, 2},
		{"busy", 409, `{"error":{"code":"apply_in_progress","message":"apply-setup is already running"}}`, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfgPath, bundle, dataDir := setupCLIFixture(t)
			fakeSetupServer(t, dataDir, c.status, c.body)
			var out, errb bytes.Buffer
			if got := applySetupCommand([]string{"--file", bundle, "--config", cfgPath}, &out, &errb); got != c.want {
				t.Fatalf("exit %d, stderr %s", got, errb.String())
			}
			if c.status == 200 && out.String() != c.body {
				t.Fatalf("stdout %q", out.String())
			}
			if c.status != 200 && !strings.Contains(errb.String(), "already running") && !strings.Contains(errb.String(), "version: want 1") {
				t.Fatalf("stderr %q", errb.String())
			}
		})
	}
}

func TestApplySetupLocalFailures(t *testing.T) {
	cfgPath, bundle, _ := setupCLIFixture(t)
	var out, errb bytes.Buffer
	if got := applySetupCommand([]string{"--file", bundle, "--config", cfgPath}, &out, &errb); got != 1 || !strings.Contains(errb.String(), "not running") {
		t.Fatalf("no server: %d %q", got, errb.String())
	}
	if err := os.WriteFile(bundle, []byte(`{"version":1,"sso":{"clientSecret":"inline-secret-value"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if got := applySetupCommand([]string{"--file", bundle, "--config", cfgPath}, &out, &errb); got != 2 || strings.Contains(errb.String(), "inline-secret-value") {
		t.Fatalf("inline secret: %d %q", got, errb.String())
	}
	if got := applySetupCommand([]string{"--config", cfgPath}, &out, &errb); got != 2 {
		t.Fatalf("missing --file: %d", got)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout written on failure: %q", out.String())
	}
}
```

- [ ] **Step 2: Run it and see it fail.** `go test ./cmd/kynotes-server -run TestApplySetup` → FAIL (undefined: applySetupCommand).

- [ ] **Step 3: Implement.** Create `cmd/kynotes-server/applysetup.go`:

```go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/app"
	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/config"
)

// setupTimeout outlasts backup.OperationTimeout, the server's own bound.
const setupTimeout = 20 * time.Minute

// applySetupCommand validates the bundle locally, sends it to the running server over the
// admin socket and prints the server's report. It returns the process exit code.
func applySetupCommand(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("apply-setup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "setup bundle (JSON)")
	cfgPath := flags.String("config", "/data/kynotes.yaml", "config path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *file == "" {
		fmt.Fprintln(stderr, "usage: apply-setup --file BUNDLE [--config PATH]")
		return applysetup.ExitInvalid
	}
	c, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "apply-setup:", err)
		return applysetup.ExitInvalid
	}
	req, err := applysetup.Load(*file, c.Backup.AllowPrivateRecovery)
	if err != nil {
		fmt.Fprintln(stderr, "apply-setup:", err)
		return applysetup.ExitInvalid
	}
	body, code, err := postSetup(app.AdminSocketPath(c.DataDir), req)
	if err != nil {
		fmt.Fprintln(stderr, "apply-setup:", err)
		return code
	}
	_, _ = stdout.Write(body)
	return code
}

func postSetup(socket string, req applysetup.Request) ([]byte, int, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, applysetup.ExitError, err
	}
	client := &http.Client{Timeout: setupTimeout, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	resp, err := client.Post("http://kynotes/v1/apply-setup", "application/json", bytes.NewReader(payload))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, applysetup.ExitError, fmt.Errorf("kynotes-server is not running (no admin socket at %s); start it and wait for the health check", socket)
		}
		return nil, applysetup.ExitError, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, applysetup.ExitError, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		var report applysetup.Report
		if err := json.Unmarshal(body, &report); err != nil {
			return nil, applysetup.ExitError, fmt.Errorf("unreadable report: %w", err)
		}
		return body, report.ExitCode(), nil
	case http.StatusBadRequest:
		return nil, applysetup.ExitInvalid, fmt.Errorf("server rejected the bundle: %s", errorMessage(body))
	}
	return nil, applysetup.ExitError, fmt.Errorf("server answered %d: %s", resp.StatusCode, errorMessage(body))
}

func errorMessage(body []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		return e.Error.Message
	}
	return strings.TrimSpace(string(body))
}
```

  In `cmd/kynotes-server/main.go`, insert as the first statement of `main()` (before the `healthcheck` check at line 28):

```go
	if len(os.Args) > 1 && os.Args[1] == "apply-setup" {
		os.Exit(applySetupCommand(os.Args[2:], os.Stdout, os.Stderr))
	}
```

- [ ] **Step 4: Run tests.** `go test -race ./cmd/kynotes-server` → PASS (`TestUnknownSubcommandIsRejected` included).

- [ ] **Step 5: Commit.** `git add cmd/kynotes-server && git commit -m "cmd: apply-setup client over the admin socket"` (with trailer).

---

### Task 12: End-to-end: real server, `apply-setup` twice

**Files:**
- Test: `cmd/kynotes-server/applysetup_e2e_test.go`

**Interfaces:**
- Consumes: `app.Serve(ctx, c, log, version)` and `app.AdminSocketPath` (Task 10), `applySetupCommand` (Task 11), `config.Load`, `logging.New`.
- Produces: `TestApplySetupTwiceEndToEnd`.

- [ ] **Step 1: Write the test.** Create `cmd/kynotes-server/applysetup_e2e_test.go`:

```go
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/app"
	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
)

// e2eIssuer serves discovery as https://example.com:<port> and routes the default
// transport (used by sso.DiscoverEndpoints) to it.
func e2eIssuer(t *testing.T) string {
	t.Helper()
	var issuer string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"})
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	issuer = "https://example.com:" + port
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: "example.com"}
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	old := http.DefaultTransport
	http.DefaultTransport = tr
	t.Cleanup(func() { http.DefaultTransport = old })
	return issuer
}

func TestApplySetupTwiceEndToEnd(t *testing.T) {
	issuer := e2eIssuer(t)
	dir := t.TempDir()
	backups := filepath.Join(dir, "backups")
	if err := os.Mkdir(backups, 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	cfgPath := filepath.Join(dir, "kynotes.yaml")
	yaml := fmt.Sprintf("data_dir: %s\nserver:\n  bind: %q\n  dev_insecure_cookies: true\nbackup:\n  dir: %s\n", dir, addr, backups)
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("kynotes.yaml", yaml)
	secret := write("oidc", "client-secret-value\n")
	hmac := write("hmac", "hmac-secret-value\n")
	bundle := write("bundle.json", fmt.Sprintf(`{"version":1,
 "sso":{"issuerUrl":%q,"clientId":"kynotes","clientSecretFile":%q,"redirectUri":"https://notes.example/api/v1/auth/oidc/callback","directoryHmacSecretFile":%q},
 "admins":[{"issuer":%q,"subject":"sub-owner","username":"owner-admin"}],
 "backup":{"dir":%q,"keep":7,"depositInterval":"24h"}}`, issuer, secret, hmac, issuer, backups))

	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx, c, logging.New(io.Discard, "info", "json"), "e2e") }()
	sock := app.AdminSocketPath(dir)
	for deadline := time.Now().Add(5 * time.Second); ; {
		if conn, err := net.Dial("unix", sock); err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("admin socket never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	run := func() applysetup.Report {
		t.Helper()
		var out, errb bytes.Buffer
		if code := applySetupCommand([]string{"--file", bundle, "--config", cfgPath}, &out, &errb); code != 0 {
			t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
		}
		for _, s := range []string{"client-secret-value", "hmac-secret-value"} {
			if strings.Contains(out.String(), s) || strings.Contains(errb.String(), s) {
				t.Fatalf("%s printed", s)
			}
		}
		var r applysetup.Report
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	statuses := func(r applysetup.Report) map[string]applysetup.Status {
		m := map[string]applysetup.Status{}
		for _, x := range r.Results {
			m[x.Section] = x.Status
		}
		return m
	}

	first := statuses(run())
	want := map[string]applysetup.Status{"sso": "created", "admin:owner-admin": "created", "backup.dir": "present", "backup.keep": "present", "backup.interval": "created"}
	for k, v := range want {
		if first[k] != v {
			t.Fatalf("first run %s: %s (%v)", k, first[k], first)
		}
	}
	second := run()
	if len(second.Results) != len(want) {
		t.Fatalf("second run: %+v", second.Results)
	}
	for _, x := range second.Results {
		if x.Status != applysetup.Present {
			t.Fatalf("second run %s: %s", x.Section, x.Status)
		}
	}
	if h := second.Handover; h.URL != "https://notes.example" || len(h.AdminUsernames) != 1 || h.BackupDir != backups || h.Version != "e2e" {
		t.Fatalf("handover %+v", h)
	}

	// The live router sees the new settings without a restart.
	resp, err := (&http.Client{Transport: &http.Transport{}}).Get("http://" + addr + "/api/v1/auth/sso-config")
	if err != nil {
		t.Fatal(err)
	}
	var live map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&live)
	resp.Body.Close()
	if live["enabled"] != true || live["issuerUrl"] != issuer {
		t.Fatalf("sso-config %v", live)
	}

	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "kynotes.sqlite")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var rows int
	err = db.QueryRow(`SELECT count(*) FROM audit_events WHERE actor_user_id=? AND request_id=?`, applysetup.Actor, applysetup.RequestID).Scan(&rows)
	db.Close()
	if err != nil || rows != 3 {
		t.Fatalf("apply-setup audit rows: %d (%v); want sso, admin, schedule", rows, err)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sock); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("socket left after shutdown")
	}
}
```

- [ ] **Step 2: Run it.** `go test -race ./cmd/kynotes-server -run TestApplySetupTwiceEndToEnd -v` → PASS. If it fails, fix the implementation, not the test; the test is the spec's acceptance check. Then run the full suite: `go test -race ./...`.

- [ ] **Step 3: Commit.** `git add cmd/kynotes-server && git commit -m "test: apply-setup twice against a real server"` (with trailer).

---

### Task 13: Installer documentation and DOX pass

**Files:**
- Create: `docs/INSTALLER.md`
- Modify: `docs/SSO.md:9-10` (one sentence), `CHANGELOG.md` (Unreleased bullet), `AGENTS.md` (Child DOX Index), `internal/backup/AGENTS.md` (Local Contracts bullet)

- [ ] **Step 1: Write `docs/INSTALLER.md`.** CI lints every non-`docs/superpowers` Markdown file. The only image coordinate allowed is `ghcr.io/busnes-app/kynotes-server`. Do not write `--repo` or `--cert-identity` here; point to the pin block instead.

```markdown
# KyNotes for the suite installer

KyQuickStart's KyNotes manifest lives in KyQuickStart. This page lists what it must declare
and how it configures KyNotes with `apply-setup`.

## Manifest

- **Image:** `ghcr.io/busnes-app/kynotes-server@<digest>`. Verify the digest against its
  attestation with the command in the pin block of `docker-compose.yml` before deploying.
- **Port:** the container listens on 8080 (`KYNOTES_PORT`); publish it only to the reverse proxy.
- **Volumes:** `/data` (database, secrets, blobs, the admin socket) and `/backups` for local
  sealed capsules.
- **Environment:**
  - `TRUSTED_PROXY_CIDRS`: the reverse proxy's address.
  - `KYNOTES_BACKUP_DIR=/backups` and `KYNOTES_BACKUP_KEEP=<n>`. These are read at start;
    `apply-setup` checks them and reports `conflict` if they differ from the bundle.
  - `KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY=true` only for a KyRecovery on a private address.
- **Health:** `GET /healthz`, or `/kynotes-server healthcheck` inside the container.
- **OIDC client (confidential) in KyIdentity:**
  - Redirect URI `https://<host>/api/v1/auth/oidc/callback`.
  - Back-channel logout URI `https://<host>/api/v1/auth/oidc/backchannel-logout`.
  - Application role `kynotes.admin`, assigned only to the administrator identity.
- **SCIM:** the connector posts to `https://<host>/api/v1/sync/events`, signed with the HMAC
  secret passed as `directoryHmacSecretFile`.
- **restic:** back up `/data/blobs` only. The sealed capsule holds the database
  (`/data/kynotes.sqlite*`) and secrets.
- **Upgrades:** take a capsule (`deposit`, or a scheduled run) before upgrading. Never roll the
  image back after a migration has run.

## apply-setup

Run it after the health check passes:

    docker exec <container> /kynotes-server apply-setup --file /run/secrets/kynotes_setup.json

(`kubectl exec` works the same way.) The command talks to the running server over
`/data/admin.sock` (mode 0600). It fails with exit 1 if the server is not running.

Bundle, version 1. Every section is optional; unknown fields are rejected:

    {"version":1,
     "sso":{"issuerUrl":"https://id.example","clientId":"kynotes",
            "clientSecretFile":"/run/secrets/kynotes_oidc",
            "redirectUri":"https://notes.example/api/v1/auth/oidc/callback",
            "directoryHmacSecretFile":"/run/secrets/kynotes_scim_hmac"},
     "admins":[{"issuer":"https://id.example","subject":"<sub>","username":"owner-admin"}],
     "backup":{"dir":"/backups","keep":7,"depositInterval":"24h",
               "recovery":{"url":"https://kyrecovery.example",
                           "pairingCodeFile":"/run/secrets/kynotes_pair"}}}

- Secrets are absolute paths to files of at most 4 KiB inside the container. Inline secrets
  are rejected, and no secret is ever printed.
- URLs must be HTTPS. Admin issuers must equal the SSO issuer.
- `sso` is stored only when no SSO settings exist, after an issuer discovery probe.
- `admins` creates or promotes the account bound to issuer+subject, with no password. A
  username held by another account is a conflict; accounts are never adopted by username.
  Sign-in as admin also needs the `kynotes.admin` claim. Creating an admin closes the
  first-run web setup.
- `backup.depositInterval` is set only when no interval is stored. `recovery` claims the
  one-time code unless this instance is already paired. If KyRecovery returns a key other
  than the pinned one, the result is a conflict and the code is spent.

Output on stdout:

    {"version":1,"results":[{"section":"sso","status":"created"}, ...],
     "handover":{"url":"https://notes.example","adminUsernames":["owner-admin"],
                 "recoveryKeyFingerprint":"<key id>","backupDir":"/backups","version":"<sha>"}}

Statuses are `created`, `present`, `conflict`, `invalid` and `failed`. Exit codes:

- 0: all created or present.
- 3: a conflict, left unchanged.
- 2: invalid input.
- 1: any other error.

Rerunning the same bundle reports `present` for every section and writes no audit rows.
Each change writes one audit row with actor `system` and request ID `apply-setup`.
```

- [ ] **Step 2: Update `docs/SSO.md`.** After the first sentence of `## Configuration` (line 9-10, "...or use KySignOn pairing."), add:

```markdown
The suite installer sets them with `apply-setup` (see `docs/INSTALLER.md`), which never
overwrites existing settings.
```

- [ ] **Step 3: Update `CHANGELOG.md`.** Under `## Unreleased`, add as the first bullet:

```markdown
- `apply-setup --file BUNDLE` configures SSO, SSO-bound admins and backups on a running server
  through the local admin socket `<data_dir>/admin.sock` (mode 0600). It is create-only and
  prints a JSON report. See `docs/INSTALLER.md`.
```

- [ ] **Step 4: DOX pass on `AGENTS.md`.**
  - Replace the bullet at lines 278-280 ("CLI server mode accepts flags only…") with:

```markdown
- CLI server mode accepts flags only. Removed `backup` names `copy-data-dir`/`deposit`
  in its error; unknown commands and trailing positional arguments exit before loading
  configuration or starting the server. `TestUnknownSubcommandIsRejected` covers dispatch.
  `apply-setup` is the one subcommand that needs the server running: it talks to it over
  `<data_dir>/admin.sock`.
```

  - Append to the Child DOX Index:

```markdown
- `internal/applysetup` owns the apply-setup contract: bundle (secrets only by file path,
  unknown fields rejected), socket request, create/present/conflict decisions, report and
  exit codes 0/3/2/1 (precedence invalid > failed > conflict). `internal/httpapi/apply_setup.go`
  applies SSO through the router's shared `sso.Store` after a discovery probe, and admins
  bound by issuer+subject (never by username; a grant revokes credentials through
  `revokeForRoleChange`). `backup.Service.ApplySetup` checks env-fixed dir/keep and creates
  the interval and pairing only when unset or unpaired. `internal/app` owns `admin.sock`:
  0600, peer uid or root, created after the data-dir lock and removed on shutdown, never a
  network listener. One audit row per change (actor `system`, request `apply-setup`).
  `docs/INSTALLER.md` is the installer contract. Verify `go test ./internal/applysetup`,
  `TestApply*`, `TestSetupHandler*`, `TestAdminSocket*`, `TestServeOwnsAdminSocketLifecycle`,
  `TestApplySetupTwiceEndToEnd` and `scripts/apply-setup-container-check.sh`.
```

  - In `internal/backup/AGENTS.md` under `# Local Contracts`, add:

```markdown
- `ApplySetup` never claims a pairing code when the instance is already paired, never
  re-pins a key, and sets the interval only when no admin setting exists. Dir and keep are
  env-fixed and only compared.
```

  - The repository-root `busnes.app/AGENTS.md` is left unchanged: the KyQuickStart manifest is a follow-up in that repo.

- [ ] **Step 5: Verify and commit.** `gofmt -l .` (empty), then `git add docs/INSTALLER.md docs/SSO.md CHANGELOG.md AGENTS.md internal/backup/AGENTS.md && git commit -m "docs: installer contract for apply-setup"` (with trailer).

---

### Task 14: Container check (`docker exec` against a local container) and CI

**Files:**
- Create: `scripts/apply-setup-container-check.sh`
- Modify: `.github/workflows/ci.yml:79` (run the script after the probe, same step, same image)

- [ ] **Step 1: Write the script.** Create `scripts/apply-setup-container-check.sh` and mark it executable (`chmod +x`):

```bash
#!/usr/bin/env bash
# apply-setup inside a real container: socket mode, two runs (second all present), an
# inline secret refused without echo, and the socket removed on stop.
# Usage: scripts/apply-setup-container-check.sh IMAGE   (run from the repository root)
set -euo pipefail
image=${1:?usage: apply-setup-container-check.sh IMAGE}
name=kynotes-applysetup-check
data=$(mktemp -d)
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$data"; }
trap cleanup EXIT
docker rm -f "$name" >/dev/null 2>&1 || true

cp testdata/config-good/kynotes.yaml "$data/"
mkdir "$data/backups"
printf '%s\n' '{"version":1,"backup":{"dir":"/data/backups","keep":7,"depositInterval":"24h"}}' >"$data/bundle.json"
printf '%s\n' '{"version":1,"sso":{"issuerUrl":"https://id.example","clientId":"kynotes","clientSecret":"inline-secret-value","redirectUri":"https://notes.example/api/v1/auth/oidc/callback"}}' >"$data/inline.json"

docker run -d --name "$name" --user "$(id -u):$(id -g)" -e KYNOTES_BACKUP_DIR=/data/backups -e KYNOTES_BACKUP_KEEP=7 \
  -v "$data:/data" "$image" --config /data/kynotes.yaml >/dev/null
ready=0
for _ in $(seq 1 30); do
  if docker exec "$name" /kynotes-server healthcheck --config /data/kynotes.yaml 2>/dev/null; then ready=1; break; fi
  sleep 1
done
test "$ready" -eq 1 || { docker logs "$name"; echo "server never became healthy"; exit 1; }

test "$(stat -c %a "$data/admin.sock")" = 600 || { echo "admin.sock is not 0600"; exit 1; }

docker exec "$name" /kynotes-server apply-setup --file /data/bundle.json --config /data/kynotes.yaml >"$data/run1.json"
grep -qF '"section":"backup.interval","status":"created"' "$data/run1.json" || { cat "$data/run1.json"; exit 1; }

docker exec "$name" /kynotes-server apply-setup --file /data/bundle.json --config /data/kynotes.yaml >"$data/run2.json"
if grep -oE '"status":"[a-z]+"' "$data/run2.json" | grep -vqxF '"status":"present"'; then
  cat "$data/run2.json"; echo "second run not all present"; exit 1
fi
test "$(grep -oF '"status":"present"' "$data/run2.json" | wc -l)" -eq 3 || { cat "$data/run2.json"; exit 1; }

set +e
docker exec "$name" /kynotes-server apply-setup --file /data/inline.json --config /data/kynotes.yaml >"$data/inline.out" 2>"$data/inline.err"
rc=$?
set -e
test "$rc" -eq 2 || { echo "inline secret: exit $rc, want 2"; exit 1; }
if grep -qF inline-secret-value "$data/inline.out" "$data/inline.err"; then echo "inline secret echoed"; exit 1; fi

docker stop "$name" >/dev/null
test ! -e "$data/admin.sock" || { echo "admin.sock left after stop"; exit 1; }
echo "apply-setup container check passed"
```

- [ ] **Step 2: Run it against a local build.** From the repository root, in bash:

```bash
docker build --build-arg VERSION=applysetup-check -t kynotes-server:applysetup-check .
bash scripts/apply-setup-container-check.sh kynotes-server:applysetup-check
```

  Expected last line: `apply-setup container check passed`. If `stat` reports a mode other than 600, or the socket survives `docker stop`, fix Task 10. Do not relax the script.

- [ ] **Step 3: Wire it into CI.** In `.github/workflows/ci.yml`, after line 79 (`go run ./cmd/kynotes-probe …`) in the same `run: |` block, add:

```yaml
          bash scripts/apply-setup-container-check.sh "$image"
```

  The step already has `set -eu`, `image=kynotes-server:ci`, and the repository root as its working directory.

- [ ] **Step 4: Full verification.** `go build ./... && go vet ./... && test -z "$(gofmt -l .)" && go test -race ./...`, then rerun Step 2. Both must pass.

- [ ] **Step 5: Commit.** `git add scripts/apply-setup-container-check.sh .github/workflows/ci.yml && git commit -m "ci: apply-setup container check"` (with trailer).

---

## Self-Review

- **Spec coverage:**

  | Spec item | Task |
  |---|---|
  | Socket: path, 0600, lifecycle, local only | 10 |
  | CLI: `--file`, `--config`, JSON on stdout | 11 |
  | Exit codes 0/3/2/1 | 4, 11 |
  | Server not running | 11 |
  | Bundle v1 and optional sections | 1, 2 |
  | Secrets by file, never echoed | 2, 9, 11, 12, 14 |
  | HTTPS and private-address rule | 1 |
  | Usernames | 1 |
  | Unknown fields | 1, 2 |
  | SSO created/present/conflict with probe and audit | 3, 6 |
  | Admins: binding, grant with audit, username conflict, both gates | 3, 7, docs |
  | Backup dir/keep/interval | 3, 8; resolved as a check |
  | Pairing claim, pin, token; pinned/different key | 3, 8 |
  | Report and handover | 4, 9 |
  | `docs/INSTALLER.md` (all nine manifest items) | 13 |
  | Go tests listed in the spec's Verification | 1-12 |
  | E2E twice | 12 |
  | Container check | 14 |

- **Type consistency:**
  - `applysetup.Result{Section, Status, Detail}` is used in Tasks 4, 6, 7, 8 and 9.
  - `DecideAdmin(bound, named *Account) (Status, AdminAction, string)` matches Tasks 3 and 7.
  - `DecideRecovery(keyID, pairedURL, wantURL) (Status, bool)` matches Tasks 3 and 8.
  - `Serve(ctx, c, log, version)` matches Tasks 10 and 12, `main.go` and `serve_contract_test.go`.
  - `SetupDeps` fields match Tasks 9 and 10.
  - `AdminSocketPath` is used in Tasks 10, 11 and 12.
- **Placeholders:** none. `<digest>`, `<host>`, `<sub>` and `<container>` appear only in operator documentation, as values the operator supplies.
