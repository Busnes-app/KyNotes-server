# KyNotes adopts ky-primitives (Plan A: independent of the recoveryclient package)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put kynotes-server on `github.com/Busness-app/ky-primitives` for passwords, login-secret derivation, key files and recovery codes, and lay every adapter the KyRecovery backup port (Plan B) needs. It does not depend on `ky-primitives/recoveryclient` (v0.5.0, tagged 2026-09-05), so it can run while that tag and the kysignon first-consumer swap land.

**Architecture:** kynotes is not a scaffold fork. Nothing here copies a backup package; every task replaces one hand-rolled primitive with the library call, or adds one small adapter (settings, snapshot, audit outcome, step-up, config) that Plan B's thin wiring will call. Each task leaves the repo green and shippable on its own.

**Tech Stack:** Go 1.26.6, modernc.org/sqlite (WAL), `golang.org/x/crypto/argon2` (already transitively present via ky-primitives/password), React + Vite frontend embedded from `internal/web/dist`.

**Spec:** Board folder `kynotes-kyrecovery-deposit` (myslop), durable copies `ky_server_base/docs/superpowers/plans/2026-09-04-kynotes-kyrecovery-deposit.md` and `.../2026-09-04-bring-suite-to-kysignon-spec.md`. Plan B is `docs/superpowers/plans/2026-09-04-kynotes-kyrecovery-backup.md` in this repo.

## Global Constraints

- `go 1.26.6`; `github.com/Busness-app/ky-primitives v0.5.0` (tagged 2026-09-05). Nothing in Plan A imports `recoveryclient`.
- Audit stays a flat `audit_events` table (suite decision 6). Do not add `auditchain`.
- Passwords: scrypt is dropped outright, no dual-verify. Nothing is in the wild (HANDOFF.md: "This product has never gone live"). Existing dev databases must be recreated.
- Every env var is `KYNOTES_*`. Config file keys stay snake_case under the existing sections.
- Gate before every commit: `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`. CI also runs the fuzz targets and the Docker probe.
- Never print a secret or a recovery code to a log line. Recovery codes go to the operator once, on stdout, at creation.
- Branch: `feat/adopt-ky-primitives` in worktree `.claude/worktrees/adopt` (created with `superpowers:using-git-worktrees`).

---

## File map

| File | Responsibility after this plan |
|---|---|
| `go.mod`, `go.sum` | adds ky-primitives; drops direct `golang.org/x/crypto` if nothing else imports it (check: `internal/auth/hash.go` and `derive.go` are the only importers today) |
| `internal/auth/hash.go` | `HashAuthSecret`/`VerifyAuthSecret` over `ky-primitives/password` (Argon2id, PHC) |
| `internal/auth/derive.go` | `DeriveAuthSecret`/`SyntheticLoginSalt` over `ky-primitives/derive`, label `kynotes/auth/v1` |
| `internal/config/config.go` | `loadSecrets` over `ky-primitives/keyfile` (refuses an undecodable key file); new `Backup` section |
| `internal/auth/recovery.go` (new) | `NewRecoveryCode()`; recovery-code hashing over `password` + `recoverycode.Normalize` |
| `cmd/kynotes-server/main.go` | `user add` prints a server-generated recovery code once; `--recovery-hash` stdin field removed |
| `internal/httpapi/auth_routes.go` | recover route normalises the code and returns a fresh one; `POST /api/v1/auth/step-up` |
| `internal/storage/migrations/0013_stepup.sql` (new) | `sessions.stepup_at` |
| `internal/auth/middleware.go` | `RequireStepUp` |
| `internal/storage/store.go` | `GetSetting`/`SetSetting`/`DeleteSetting` over `server_settings` with `ErrNotFound` (the database snapshot comes from `recoveryclient.SQLiteSnapshot` in Plan B) |
| `internal/httpapi/admin_routes.go` | `recordAuditOutcome` (outcome + reason_code) beside `recordAudit` |
| `docker-compose.yml`, `docker-compose.lan-dns.yml` (new) | backup env passthrough; LAN DNS override file |
| `AGENTS.md`, `zero_code_pairing_handoff_spec.md` (deleted) | truth about what exists |

---

### Task 1: Dependency and Argon2id passwords

**Files:**
- Modify: `go.mod`
- Modify: `internal/auth/hash.go` (whole file)
- Test: `internal/auth/hash_test.go` (new)

**Interfaces:**
- Produces: `auth.HashAuthSecret(secret string) (string, error)` and `auth.VerifyAuthSecret(secret, stored string) error` keep their signatures; every caller (16 sites) is untouched. Stored form is now a PHC `$argon2id$...` string.

- [ ] **Step 1: Add the dependency**

```bash
go get github.com/Busness-app/ky-primitives@v0.5.0
go mod tidy
```
Expected: `go.mod` lists `github.com/Busness-app/ky-primitives v0.5.0`. `golang.org/x/crypto` stays (argon2 and, until Task 2, pbkdf2/hkdf).

- [ ] **Step 2: Write the failing test**

`internal/auth/hash_test.go`:
```go
package auth

import (
	"strings"
	"testing"
)

func TestHashAuthSecretIsArgon2idPHC(t *testing.T) {
	h, err := HashAuthSecret(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("want PHC argon2id, got %q", h)
	}
	if err := VerifyAuthSecret(strings.Repeat("a", 64), h); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyAuthSecret(strings.Repeat("b", 64), h); err == nil {
		t.Fatal("wrong secret verified")
	}
}

func TestVerifyAuthSecretRefusesScrypt(t *testing.T) {
	if err := VerifyAuthSecret("x", "scrypt$131072$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAA"); err == nil {
		t.Fatal("legacy scrypt verifier must be refused, not verified")
	}
}
```

- [ ] **Step 3: Run it to see it fail**

Run: `go test ./internal/auth -run 'TestHashAuthSecretIsArgon2idPHC|TestVerifyAuthSecretRefusesScrypt' -v`
Expected: FAIL, `want PHC argon2id, got "scrypt$..."`.

- [ ] **Step 4: Replace hash.go**

```go
package auth

import (
	"errors"

	"github.com/Busness-app/ky-primitives/password"
)

var errInvalidSecret = errors.New("invalid secret")

// HashAuthSecret stores a login secret or recovery code as an Argon2id PHC string.
func HashAuthSecret(secret string) (string, error) { return password.Hash(secret) }

// VerifyAuthSecret is nil only when secret matches stored. A malformed or
// legacy (scrypt) verifier is an error, never a match.
func VerifyAuthSecret(secret, stored string) error {
	ok, err := password.Verify(secret, stored)
	if err != nil {
		return err
	}
	if !ok {
		return errInvalidSecret
	}
	return nil
}
```

- [ ] **Step 5: Run the whole suite**

Run: `go test -race ./...`
Expected: PASS. If a test fixture stores a literal `scrypt$` verifier, replace it with `HashAuthSecret` at test time. `dummyVerifier()` in `auth_routes.go:22` already hashes at runtime and needs no change.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/auth/hash.go internal/auth/hash_test.go
git commit -m "auth: hash login secrets with ky-primitives/password (Argon2id)"
```

---

### Task 2: Login-secret derivation from the library

**Files:**
- Modify: `internal/auth/derive.go` (whole file)
- Test: `internal/auth/derive_test.go` (existing golden vectors must stay green unchanged)

**Interfaces:**
- Produces: `auth.DeriveAuthSecret(password, salt string, iterations int) (string, error)` and `auth.SyntheticLoginSalt(key, username string) string`, unchanged signatures.

- [ ] **Step 1: Read the existing golden test**

Run: `grep -n "func Test" internal/auth/derive_test.go`. These vectors were the source of the library's own vectors (`ky-primitives/derive` doc: "The golden vectors in the test come from kynotes-server's implementation"). They are the proof the swap is byte-identical; do not edit them.

- [ ] **Step 2: Replace derive.go**

```go
package auth

import (
	"errors"

	"github.com/Busness-app/ky-primitives/derive"
)

const MinLoginIterations = derive.MinIterations
const MaxLoginIterations = 12000000

const authLabel = "kynotes/auth/v1"
const saltLabel = "login-salt/v1"

func DeriveAuthSecret(password, salt string, iterations int) (string, error) {
	if iterations < MinLoginIterations || iterations > MaxLoginIterations {
		return "", errors.New("invalid iterations")
	}
	return derive.AuthSecret(password, salt, iterations, authLabel)
}

// SyntheticLoginSalt keeps its old signature; the library returns an error only
// for an empty key, which config validation already refuses.
func SyntheticLoginSalt(key, username string) string {
	s, _ := derive.SyntheticSalt([]byte(key), saltLabel, username)
	return s
}
```

- [ ] **Step 3: Run the golden tests**

Run: `go test ./internal/auth -run 'Derive|Salt|Synthetic' -v`
Expected: PASS with no vector changed. If `SyntheticLoginSalt` vectors fail, the library's salt construction differs from `HMAC(key, "login-salt/v1\x00"+lower(username))[:16]`; in that case keep the old `SyntheticLoginSalt` body (it is 4 lines of stdlib) and only swap `DeriveAuthSecret`. Record which in the commit message.

- [ ] **Step 4: Drop the now-unused x/crypto imports**

Run: `go mod tidy && go build ./... && grep -rn "golang.org/x/crypto" --include='*.go' .`
Expected: no direct importer left; `go.mod` keeps `golang.org/x/crypto` only as an indirect of ky-primitives.

- [ ] **Step 5: Full gate and commit**

```bash
gofmt -l . ; go vet ./... && go test -race ./...
git add internal/auth/derive.go go.mod go.sum
git commit -m "auth: derive login secrets with ky-primitives/derive"
```

---

### Task 3: Key files through keyfile

**Files:**
- Modify: `internal/config/config.go:91-125` (`loadSecrets`)
- Test: `internal/config/secrets_test.go` (new)

**Interfaces:**
- Consumes: `keyfile.LoadOrCreateEncoded(path string, size int, enc keyfile.Encoding) ([]byte, error)`, `keyfile.Base64`, `keyfile.ErrUnreadable`.
- Produces: `config.Load` returns an error when `secrets/pairing.key` or `secrets/serversalt.key` exists but does not decode to 32 bytes (today it silently continues with an empty secret; ky-primitives/keyfile's doc names kynotes for exactly this).

- [ ] **Step 1: Write the failing test**

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSecretsRefusesUndecodableKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets", "pairing.key"), []byte("not base64!"), 0600); err != nil {
		t.Fatal(err)
	}
	c := Defaults()
	c.DataDir = dir
	if err := loadSecrets(&c); err == nil {
		t.Fatal("undecodable key file must be an error, not an empty secret")
	}
}

func TestLoadSecretsCreatesAndRereads(t *testing.T) {
	dir := t.TempDir()
	c := Defaults()
	c.DataDir = dir
	if err := loadSecrets(&c); err != nil {
		t.Fatal(err)
	}
	first := c.Secrets.PairingSecret
	if len(first) != 32 {
		t.Fatalf("want 32 raw bytes, got %d", len(first))
	}
	again := Defaults()
	again.DataDir = dir
	if err := loadSecrets(&again); err != nil || again.Secrets.PairingSecret != first {
		t.Fatalf("second load differs: err=%v", err)
	}
}
```
`Defaults()` is at `config.go:66`, `applyEnv` at `:129`, `Validate` at `:238`.

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/config -run TestLoadSecrets -v`
Expected: `TestLoadSecretsRefusesUndecodableKeyFile` FAILS (returns nil today).

- [ ] **Step 3: Replace the loop body in loadSecrets**

```go
	for name, dst := range map[string]*string{"pairing.key": &c.Secrets.PairingSecret, "serversalt.key": &c.Secrets.ServerSaltKey} {
		if *dst != "" {
			continue
		}
		raw, err := keyfile.LoadOrCreateEncoded(filepath.Join(dir, name), 32, keyfile.Base64)
		if err != nil {
			return fmt.Errorf("secrets/%s: %w", name, err)
		}
		*dst = string(raw)
	}
	return nil
```
Add `"github.com/Busness-app/ky-primitives/keyfile"` to imports; remove `crypto/rand`, `encoding/base64` and `strings` from `config.go` if nothing else uses them. Existing files written by the old code are base64 of 32 bytes with a trailing newline; confirm `keyfile.Base64` trims whitespace (run `go doc github.com/Busness-app/ky-primitives/keyfile Base64`); if not, keep a one-line `strings.TrimSpace` shim is impossible with this API, so instead test against a fixture written by the old code (`testdata/config-good` has none; write one in the test with `base64 + "\n"`).

- [ ] **Step 4: Run tests, then the Docker probe locally**

Run: `go test -race ./internal/config/... ./internal/app/...`
Then the CI probe block from `.github/workflows/ci.yml` (`docker build`, `user add`, run, `go run ./cmd/kynotes-probe ...`). Expected: probe passes; the probe's data dir keys are created fresh by keyfile.

- [ ] **Step 5: Commit**

```bash
git add internal/config
git commit -m "config: load secret key files through ky-primitives/keyfile"
```

---

### Task 4: Server-generated recovery codes

**Files:**
- Create: `internal/auth/recovery.go`
- Modify: `cmd/kynotes-server/main.go:280-372` (`user add`)
- Modify: `internal/httpapi/auth_routes.go:264-331` (recover route)
- Test: `internal/auth/recovery_test.go`, `internal/httpapi/recover_test.go` (new)

**Interfaces:**
- Consumes: `recoverycode.Generate(n int) ([]string, error)`, `recoverycode.Normalize(code string) string`.
- Produces: `auth.NewRecoveryCode() (code, hash string, err error)`; `auth.VerifyRecoveryCode(code, stored string) error`.
- Wire change: `user add` no longer reads `recoveryHash` from stdin; it prints `recovery code: xxxx-xxxx-xxxx` to stdout. `POST /api/v1/auth/recover` no longer takes `newRecoveryCode`; it returns `{"recoveryCode": "..."}`. Nothing in `web/src` or `cmd/kynotes-probe` uses either (grep proves it), so no client changes.

- [ ] **Step 1: Write the failing test**

```go
package auth

import "testing"

func TestRecoveryCodeRoundTrip(t *testing.T) {
	code, hash, err := NewRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 14 { // xxxx-xxxx-xxxx
		t.Fatalf("unexpected format %q", code)
	}
	if err := VerifyRecoveryCode(code, hash); err != nil {
		t.Fatal(err)
	}
	// Operators type codes with spaces and capitals.
	if err := VerifyRecoveryCode(" "+strings.ToUpper(code)+" ", hash); err != nil {
		t.Fatalf("normalised code must verify: %v", err)
	}
	if err := VerifyRecoveryCode("0000-0000-0000", hash); err == nil {
		t.Fatal("wrong code verified")
	}
}
```
(add `"strings"` to imports.)

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/auth -run TestRecoveryCodeRoundTrip`
Expected: compile error, `NewRecoveryCode` undefined.

- [ ] **Step 3: Write recovery.go**

```go
package auth

import "github.com/Busness-app/ky-primitives/recoverycode"

// NewRecoveryCode mints one single-use code and the verifier to store for it.
// The code is shown to the operator once; only the hash is kept.
func NewRecoveryCode() (code, hash string, err error) {
	codes, err := recoverycode.Generate(1)
	if err != nil {
		return "", "", err
	}
	hash, err = HashAuthSecret(recoverycode.Normalize(codes[0]))
	return codes[0], hash, err
}

func VerifyRecoveryCode(code, stored string) error {
	return VerifyAuthSecret(recoverycode.Normalize(code), stored)
}
```

- [ ] **Step 4: Run the test**

Run: `go test ./internal/auth -run TestRecoveryCodeRoundTrip -v`
Expected: PASS.

- [ ] **Step 5: user add mints and prints the code**

In `cmd/kynotes-server/main.go` `userCommand`: delete the `RecoveryHash` stdin field and the `recoveryHash` variable; after `hash, e := auth.HashAuthSecret(authSecret)` add:
```go
	code, recoveryHash, e := auth.NewRecoveryCode()
	if e != nil {
		return e
	}
```
and after the successful `INSERT` add:
```go
	fmt.Fprintf(os.Stdout, "recovery code: %s\nStore it offline; it is shown once and unlocks the account without the password.\n", code)
```
Update the usage string: `user add --username <name> [--password <pass>] [--admin]  (stdin JSON {authSecret, loginSalt, iterations} when --password is absent)`.

- [ ] **Step 6: Recover route uses the library**

In `auth_routes.go` recover handler: remove `NewRecoveryCode` from the input struct and its `in.NewRecoveryCode == ""` check; replace `auth.VerifyAuthSecret(in.RecoveryCode, stored) != nil` with `auth.VerifyRecoveryCode(in.RecoveryCode, stored) != nil`; delete the "replacement recovery code must be new" block; replace `recoveryHash, e := auth.HashAuthSecret(in.NewRecoveryCode)` with `nextCode, recoveryHash, e := auth.NewRecoveryCode()`; replace the final `w.WriteHeader(http.StatusNoContent)` with `writeJSON(w, map[string]string{"recoveryCode": nextCode})`.

- [ ] **Step 7: Route test**

`internal/httpapi/recover_test.go`, following the harness in `integration_test.go` (`newTestServer` or equivalent; read it first):
```go
func TestRecoverRotatesCodeAndRevokesSessions(t *testing.T) {
	srv, db := newTestServer(t) // whatever integration_test.go calls it
	code, hash, _ := auth.NewRecoveryCode()
	seedUser(t, db, "alice", hash) // INSERT with recovery_hash=hash; write this helper if absent
	body := `{"username":"alice","recoveryCode":"` + code + `","newAuthSecret":"` + strings.Repeat("1", 64) + `","newLoginSalt":"` + validSalt + `","iterations":100000}`
	rr := do(t, srv, "POST", "/api/v1/auth/recover", body)
	if rr.Code != 200 {
		t.Fatalf("status %d: %s", rr.Code, rr.Body)
	}
	var out struct{ RecoveryCode string }
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.RecoveryCode) != 14 {
		t.Fatalf("no replacement code in %s", rr.Body)
	}
	// The old code is dead.
	if rr := do(t, srv, "POST", "/api/v1/auth/recover", body); rr.Code != 401 {
		t.Fatalf("reused code: %d", rr.Code)
	}
}
```
Adapt helper names to what `integration_test.go` and `setup_test.go` already provide; do not add a second harness.

- [ ] **Step 8: Gate and commit**

```bash
gofmt -l . ; go vet ./... && go test -race ./...
git add internal/auth/recovery.go internal/auth/recovery_test.go cmd/kynotes-server/main.go internal/httpapi/auth_routes.go internal/httpapi/recover_test.go
git commit -m "auth: server-minted recovery codes from ky-primitives/recoverycode"
```

---

### Task 5: Store adapter: settings with ErrNotFound

**Files:**
- Modify: `internal/storage/store.go`
- Test: `internal/storage/settings_test.go` (new)

**Interfaces:**
- Produces:
  - `storage.ErrNotFound` (`var ErrNotFound = errors.New("storage: not found")`)
  - `func (s *Store) GetSetting(key string) (string, error)` returns `ErrNotFound` when the key was never written; a key set to `""` returns `""` and no error (the library distinguishes the two)
  - `func (s *Store) SetSetting(key, value string) error` (upsert into `server_settings(key,value,updated_at)`)
  - `func (s *Store) DeleteSetting(key string) error` (no error when absent)
  Plan B's `recoveryclient.Settings` adapter is these three methods. The database snapshot is not a store method: Plan B calls `recoveryclient.SQLiteSnapshot(ctx, s.DB(), dest)` through the existing `DB()` accessor, and proves the WAL-row case there.

- [ ] **Step 1: Failing test**

`settings_test.go`:
```go
package storage

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestSettingsRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "k.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.GetSetting("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.SetSetting("a", "1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("a", "2"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.GetSetting("a"); v != "2" {
		t.Fatalf("got %q", v)
	}
	if err := s.SetSetting("empty", ""); err != nil {
		t.Fatal(err)
	}
	if v, err := s.GetSetting("empty"); err != nil || v != "" {
		t.Fatalf("a key set to empty is present, not missing: %v %q", err, v)
	}
	if err := s.DeleteSetting("a"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSetting("a"); err != nil {
		t.Fatalf("deleting an absent key must be a no-op: %v", err)
	}
	if _, err := s.GetSetting("a"); !errors.Is(err, ErrNotFound) {
		t.Fatal("still present after delete")
	}
}
```

- [ ] **Step 2: Run to see it fail**

Run: `go test ./internal/storage -run TestSettingsRoundTrip`
Expected: compile errors for the missing methods.

- [ ] **Step 3: Implement in store.go**

```go
var ErrNotFound = errors.New("storage: not found")

func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM server_settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (s *Store) SetSetting(key, value string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`INSERT INTO server_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`, key, value, now)
	return err
}

func (s *Store) DeleteSetting(key string) error {
	_, err := s.db.Exec(`DELETE FROM server_settings WHERE key=?`, key)
	return err
}
```
`server_settings` is `(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)` per `0009_server_settings.sql`.

- [ ] **Step 4: Run, gate, commit**

```bash
go test -race ./internal/storage/... && gofmt -l . ; go vet ./...
git add internal/storage
git commit -m "storage: settings accessors with ErrNotFound"
```

---

### Task 6: Audit rows with an outcome

**Files:**
- Modify: `internal/httpapi/admin_routes.go:20-27`
- Test: `internal/httpapi/audit_outcome_test.go` (new)

**Interfaces:**
- Produces: `recordAuditOutcome(db *sql.DB, actor, event, target, outcome, reason, requestID string)`; `recordAudit` becomes a one-line call to it with `outcome="success", reason=""`. Plan B records every backup result through this. `outcome` is `success` or `failure`; `reason` is bounded printable text (Plan B passes it through the library's `AuditSafe`).

- [ ] **Step 1: Failing test**

```go
func TestRecordAuditOutcomeStoresFailure(t *testing.T) {
	db := openTestDB(t) // reuse the helper integration_test.go uses
	recordAuditOutcome(db, "usr_x", "admin.backup_run", "cap_1", "failure", "KyRecovery refused", "req-1")
	var outcome, reason, object string
	if err := db.QueryRow(`SELECT outcome,reason_code,object_id FROM audit_events WHERE event='admin.backup_run'`).Scan(&outcome, &reason, &object); err != nil {
		t.Fatal(err)
	}
	if outcome != "failure" || reason != "KyRecovery refused" || object != "cap_1" {
		t.Fatalf("got %q %q %q", outcome, reason, object)
	}
}
```

- [ ] **Step 2: Run to see it fail** — `go test ./internal/httpapi -run TestRecordAuditOutcomeStoresFailure` → undefined.

- [ ] **Step 3: Implement**

```go
func recordAudit(db *sql.DB, actor, event, container, object, requestID string) {
	recordAuditOutcome(db, actor, event, object, "success", "", requestID, container)
}

// recordAuditOutcome writes one flat audit row. reason is the operator-facing
// failure text, already bounded by the caller; it is never a secret.
func recordAuditOutcome(db *sql.DB, actor, event, object, outcome, reason, requestID string, container ...string) {
	id, err := ids.Mint("aud")
	if err != nil {
		return
	}
	c := ""
	if len(container) > 0 {
		c = container[0]
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = db.Exec(`INSERT INTO audit_events(id,user_id,event,container_id,object_id,created_at,at,outcome,actor_user_id,request_id,reason_code) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, actor, event, c, object, now, now, outcome, actor, requestID, reason)
}
```
Check the `reason_code` column width/constraints in `0002_devices.sql` line 14; if it is constrained to a code vocabulary, store the text in `object_id`'s sibling column instead and say so in the commit.

- [ ] **Step 4: Gate and commit**

```bash
go test -race ./internal/httpapi/... && gofmt -l . ; go vet ./...
git add internal/httpapi/admin_routes.go internal/httpapi/audit_outcome_test.go
git commit -m "httpapi: audit rows carry an outcome and reason"
```

---

### Task 7: Step-up for destructive admin routes

kynotes has no second factor and no re-auth; the suite spec (row 10) requires every destructive backup route behind step-up or the product's equivalent. The equivalent here is re-proving the login secret: the browser already derives it (`web/src/crypto.ts:70`).

**Files:**
- Create: `internal/storage/migrations/0013_stepup.sql`
- Modify: `internal/auth/session.go` (Session gets `StepUpAt`), `internal/auth/middleware.go` (`RequireStepUp`), `internal/httpapi/auth_routes.go` (route)
- Modify: `web/src/api.ts` (`stepUp`), `web/src/main.tsx` (a `useStepUp` helper the Admin backup screen in Plan B calls)
- Test: `internal/httpapi/stepup_test.go`

**Interfaces:**
- Produces: `POST /api/v1/auth/step-up {"authSecret": hex64}` → 204 and `sessions.stepup_at = now`; 401 on a wrong secret, rate-limited by `loginLockout`. `auth.RequireStepUp(db, next)` wraps `RequireAdmin` and returns 403 `step_up_required` unless `stepup_at` is within `auth.StepUpWindow = 10 * time.Minute`. `api.stepUp(authSecret)` in the web client.

- [ ] **Step 1: Migration**

`0013_stepup.sql`:
```sql
ALTER TABLE sessions ADD COLUMN stepup_at TEXT NOT NULL DEFAULT '';
```
Confirm `store.go:41 migrate()` picks up files by glob; if it has a hard-coded list, add the file there.

- [ ] **Step 2: Failing test**

```go
func TestStepUpGatesDestructiveRoute(t *testing.T) {
	srv, cookie := loggedInAdmin(t) // reuse the harness in admin_team_test.go
	mux := srv.mux
	mux.Handle("POST /api/v1/admin/_destructive", auth.RequireStepUp(srv.db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	if rr := doWithCookie(t, srv, "POST", "/api/v1/admin/_destructive", "", cookie); rr.Code != 403 {
		t.Fatalf("without step-up: %d", rr.Code)
	}
	if rr := doWithCookie(t, srv, "POST", "/api/v1/auth/step-up", `{"authSecret":"`+adminSecret+`"}`, cookie); rr.Code != 204 {
		t.Fatalf("step-up: %d %s", rr.Code, rr.Body)
	}
	if rr := doWithCookie(t, srv, "POST", "/api/v1/admin/_destructive", "", cookie); rr.Code != 204 {
		t.Fatalf("after step-up: %d", rr.Code)
	}
}
```

- [ ] **Step 3: Implement**

`session.go`: add `StepUpAt time.Time` to `Session`; in `ResolveSession` scan `stepup_at` alongside the other columns and parse it (empty string → zero time).

`middleware.go`:
```go
const StepUpWindow = 10 * time.Minute

// RequireStepUp is RequireAdmin plus a recent re-proof of the login secret.
// One-way doors (pairing, key pinning, exporting recovery material) sit behind it.
func RequireStepUp(db *sql.DB, next http.Handler) http.Handler {
	return RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := SessionFromContext(r)
		if s.StepUpAt.IsZero() || time.Since(s.StepUpAt) > StepUpWindow {
			WriteAuthError(w, "step_up_required", "re-enter your password to continue")
			return
		}
		next.ServeHTTP(w, r)
	}))
}
```
`auth_routes.go`, inside `AuthRoutes`:
```go
	mux.Handle("POST /api/v1/auth/step-up", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		var in struct{ AuthSecret string `json:"authSecret"` }
		if json.NewDecoder(r.Body).Decode(&in) != nil || len(in.AuthSecret) != 64 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		s, _ := auth.SessionFromContext(r)
		key := s.UserID + "\x00" + clientIP(r)
		if !loginLockout.Try(key, time.Now().UTC()) {
			WriteError(w, r, 429, "rate_limited", "try again later")
			return
		}
		var stored string
		if db.QueryRow(`SELECT auth_secret_hash FROM users WHERE id=?`, s.UserID).Scan(&stored) != nil || auth.VerifyAuthSecret(in.AuthSecret, stored) != nil {
			loginLockout.Fail(key, time.Now().UTC())
			WriteError(w, r, 401, "unauthenticated", "invalid credentials")
			return
		}
		loginLockout.Success(key)
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := db.Exec(`UPDATE sessions SET stepup_at=? WHERE id=?`, now, s.ID); err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		recordAudit(db, s.UserID, "auth.step_up", "", "", r.Header.Get("X-Request-Id"))
		w.WriteHeader(http.StatusNoContent)
	})))
```
`web/src/api.ts`:
```ts
export function stepUp(authSecret: string) { return request<void>("/api/v1/auth/step-up", { method: "POST", body: JSON.stringify({ authSecret }) }); }
```
`web/src/main.tsx`: a helper next to the change-password form (line ~1771 already derives the current secret from a typed password and the user's login params):
```ts
async function stepUpWithPassword(username: string, password: string) {
  const { loginSalt, iterations } = await loginParams(username);
  const authSecret = await deriveAuthSecret(password, loginSalt, iterations);
  await stepUp(authSecret);
}
```
Export it; Plan B's backup screen prompts for the password and calls it when a route answers `step_up_required`.

- [ ] **Step 4: Gate, rebuild the embed, commit**

```bash
go test -race ./... && gofmt -l . ; go vet ./...
cd web && npm ci --ignore-scripts && npm run build && npm test && cd ..
rm -rf internal/web/dist && cp -r web/dist internal/web/dist
git add internal/storage/migrations/0013_stepup.sql internal/auth internal/httpapi web/src internal/web/dist
git commit -m "auth: step-up re-proof for destructive admin routes"
```

---

### Task 8: Backup configuration and compose passthrough

**Files:**
- Modify: `internal/config/config.go` (new `Backup` section + env), `kynotes.example.yaml`, `docker-compose.yml`
- Create: `docker-compose.lan-dns.yml`
- Test: `internal/config/backup_config_test.go`

**Interfaces:**
- Produces on `config.Config`:
```go
type Backup struct {
	Dir                  string `yaml:"dir"`                    // KYNOTES_BACKUP_DIR
	Keep                 int    `yaml:"keep"`                   // KYNOTES_BACKUP_KEEP, default 7
	DepositInterval      string `yaml:"deposit_interval"`       // KYNOTES_BACKUP_DEPOSIT_INTERVAL, default "24h", "0" disables, floor 15m
	AllowPrivateRecovery bool   `yaml:"allow_private_recovery"` // KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY, default false
}
```
  plus `const MinBackupDepositInterval = 15 * time.Minute` and `const AppName = "KyNotes"` in `config`.

- [ ] **Step 1: Failing test**

```go
func TestBackupConfigDefaultsAndFloor(t *testing.T) {
	c := Defaults()
	if c.Backup.Keep != 7 || c.Backup.DepositInterval != "24h" || c.Backup.AllowPrivateRecovery {
		t.Fatalf("defaults: %+v", c.Backup)
	}
	c.Backup.DepositInterval = "5m"
	if err := Validate(c); err == nil {
		t.Fatal("interval under 15m must be refused")
	}
	c.Backup.DepositInterval = "0"
	if err := Validate(c); err != nil {
		t.Fatalf("0 disables: %v", err)
	}
	t.Setenv("KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY", "true")
	t.Setenv("KYNOTES_BACKUP_KEEP", "3")
	c = Defaults()
	if err := applyEnv(&c); err != nil { t.Fatal(err) }
	if !c.Backup.AllowPrivateRecovery || c.Backup.Keep != 3 {
		t.Fatalf("env not applied: %+v", c.Backup)
	}
}
```

- [ ] **Step 2: Run to see it fail** — compile error on `c.Backup`.

- [ ] **Step 3: Implement**

Add the struct and `Backup: Backup{Keep: 7, DepositInterval: "24h"}` to the defaults literal at `config.go:67`. In the env overlay, after the GC block:
```go
	if v := os.Getenv("KYNOTES_BACKUP_DIR"); v != "" {
		c.Backup.Dir = v
	}
	if v := os.Getenv("KYNOTES_BACKUP_KEEP"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return fmt.Errorf("KYNOTES_BACKUP_KEEP: want a positive integer")
		}
		c.Backup.Keep = n
	}
	if v := os.Getenv("KYNOTES_BACKUP_DEPOSIT_INTERVAL"); v != "" {
		c.Backup.DepositInterval = v
	}
	if v := os.Getenv("KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY"); v != "" {
		c.Backup.AllowPrivateRecovery = v == "true" || v == "1"
	}
```
In validation:
```go
	if d, err := time.ParseDuration(c.Backup.DepositInterval); err != nil || (d != 0 && d < MinBackupDepositInterval) {
		return fmt.Errorf("backup.deposit_interval: 0 or at least %s", MinBackupDepositInterval)
	}
```
Make the env overlay return an error if it does not already (the `parseEnvInt64` calls at `config.go:166` suggest it does).

`docker-compose.yml`, under `environment:` add:
```yaml
      KYNOTES_BACKUP_DEPOSIT_INTERVAL: ${KYNOTES_BACKUP_DEPOSIT_INTERVAL:-24h}
      KYNOTES_BACKUP_DIR: ${KYNOTES_BACKUP_DIR:-}
      KYNOTES_BACKUP_KEEP: ${KYNOTES_BACKUP_KEEP:-7}
      KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY: ${KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY:-false}
```
and a comment above `volumes:` that a local backup directory needs a bind mount (the container is `read_only`), e.g. `- ${KYNOTES_BACKUP_HOST_DIR:-./backups}:/backups` with `KYNOTES_BACKUP_DIR=/backups`. Do not add a `dns:` key here.

`docker-compose.lan-dns.yml`:
```yaml
# Optional override: send the container's DNS lookups to your LAN resolver so a
# KyRecovery that exists only there resolves inside the container. A dns: entry
# replaces the host's resolvers for every lookup, which is why it is its own file.
#
#   KYNOTES_DNS=192.168.1.1 docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml up -d
services:
  kynotes-server:
    dns:
      - ${KYNOTES_DNS:?set KYNOTES_DNS to your LAN DNS server}
```
`kynotes.example.yaml`: add the `backup:` section with the four keys and one-line comments.

- [ ] **Step 4: Gate and commit**

```bash
go test -race ./internal/config/... && gofmt -l . ; go vet ./... && docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml config >/dev/null
git add internal/config kynotes.example.yaml docker-compose.yml docker-compose.lan-dns.yml
git commit -m "config: backup settings and compose passthrough"
```
(`docker compose config` needs `KYNOTES_DNS` set; run it with `KYNOTES_DNS=1.1.1.1` to prove the override parses.)

---

### Task 9: Docs tell the truth

**Files:**
- Delete: `zero_code_pairing_handoff_spec.md` (stale v1; md5 `24899bae…` matches the copy retired from every other repo)
- Modify: `AGENTS.md:126-128` (the "KyBackup owns backup/restore" and the "This repo owns the client half" lines)
- Modify: `docs/DEPLOYMENT.md` (env vars from Task 8; `user add` now prints a recovery code; scrypt → Argon2id means dev databases are recreated)

- [ ] **Step 1: Delete and edit**

```bash
git rm zero_code_pairing_handoff_spec.md
```
Replace the two AGENTS.md bullets with:
```
- Backups: Plan B (`docs/superpowers/plans/2026-09-04-kynotes-kyrecovery-backup.md`)
  wires `ky-primitives/kyrecovery`. Until it lands, `kynotes-server backup --out` /
  `restore --in` are plaintext directory copies taken with the server stopped; there is
  no KyRecovery client in this repo yet. The wire contract lives in
  `kyrecovery-server/zero_code_pairing_handoff_spec.md` (v2), not here.
- Passwords and recovery codes are Argon2id PHC strings via `ky-primitives/password`;
  login secrets derive through `ky-primitives/derive` with label `kynotes/auth/v1`;
  key files under `<data>/secrets` load through `ky-primitives/keyfile` and an
  undecodable file is a startup error.
```
In `docs/DEPLOYMENT.md` add a "Backup settings" table (`KYNOTES_BACKUP_DIR`, `_KEEP`, `_DEPOSIT_INTERVAL`, `_ALLOW_PRIVATE_RECOVERY`, `KYNOTES_DNS` override) and a line under user creation: "`user add` prints the account's recovery code once; store it offline."

- [ ] **Step 2: Commit**

```bash
git add -A AGENTS.md docs/DEPLOYMENT.md
git commit -m "docs: drop the stale pairing spec, describe the primitives in use"
```

---

### Task 10: Gate, PR, review rounds

- [ ] **Step 1: Full gate**

```bash
gofmt -l . ; go vet ./... && go test -race ./... && go build ./...
go test -fuzz=FuzzParseAuthSecret -fuzztime=30s ./internal/auth
cd web && npm run build && npm test && cd .. && git diff --quiet internal/web/dist || echo "dist changed: commit it"
```
Then the CI Docker probe block from `.github/workflows/ci.yml`, verbatim.

- [ ] **Step 2: Open the PR** with the `pull-request` skill. Title: `Adopt ky-primitives: Argon2id, derive, keyfile, recovery codes; backup adapters`. Body lists the wire changes (recover route response, `user add` output, undecodable key file now fatal) and states that Plan B follows.

- [ ] **Step 3: Post to myslop** in folder `kynotes-kyrecovery-deposit` (skill `myslop-handoff`): PR link, what landed, that Plan B waits on `ky-primitives-kyrecovery-package`.

---

## Self-review

- Spec coverage: hand-off items "scrypt→Argon2id" (T1), "library recovery codes" (T4), keyfile (T3), derive (T2), settings/audit adapters (T5, T6; the snapshot moved to the library), step-up equivalent for row 10 (T7), rows 7 and 8 config/compose (T8), row 14 delete spec + AGENTS.md:128 (T9). Rows 1–6, 9, 11–13 are Plan B by design.
- Names used across tasks: `HashAuthSecret`/`VerifyAuthSecret` (T1, T4, T7), `NewRecoveryCode`/`VerifyRecoveryCode` (T4), `GetSetting`/`SetSetting`/`DeleteSetting`/`ErrNotFound` (T5, consumed in Plan B), `recordAuditOutcome` (T6, consumed in Plan B), `RequireStepUp`/`stepUpWithPassword` (T7, consumed in Plan B), `config.Backup`, `MinBackupDepositInterval`, `AppName` (T8, consumed in Plan B).
- Test-harness helper names in T4, T6, T7 (`newTestServer`, `openTestDB`, `loggedInAdmin`, `doWithCookie`) do not exist yet: every current test in `internal/httpapi` builds its own mux and sqlite file inline (see `setup_test.go:13`, `integration_test.go:24`). T4 introduces `internal/httpapi/harness_test.go` with those four helpers, extracted from the inline setup in `integration_test.go`, and T6 and T7 reuse it.
