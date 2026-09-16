# KyNotes wires ky-primitives/recoveryclient (Plan B)

> Implementation is governed by [the #290 execution plan](2026-09-05-kynotes-myslop-290-execution.md). The historical sketches below are task references; current code and tagged APIs control signatures.

**Goal:** Bring kynotes-server to the KySignOn backup spec (all fourteen rows) as a thin adapter over `github.com/Busness-app/ky-primitives/recoveryclient`, with Plan A's adapters underneath.

**Architecture:** One small product package, `internal/backup`, holds only what the library cannot know: what to seal (`Collect`: database, secrets, recovery key, config manifest; never attachments), the token sealer, the drill checks, and a `Service` struct that binds config, store and library into the operations the routes, CLI and scheduler call. Each caller records the result through `recordAuditOutcome`. The frontend gets one `AdminBackup.tsx` lifted from kysignon.

**Tech Stack:** Go 1.26.6, `ky-primitives` **v0.5.1** (tagged 2026-09-05), React + Vite. kysignon's adapter over the lib is PR kysignon-server #21 (`internal/backup/{adapter,payload,drill}.go`, `nodecrypt_test.go`): copy that shape, not the pre-lib handlers.

**Spec:** Board folders `kynotes-kyrecovery-deposit` and `ky-primitives-kyrecovery-package` (myslop); durable copies `ky_server_base/docs/superpowers/plans/2026-09-04-bring-suite-to-kysignon-spec.md` (the fourteen rows, hazards, proof steps) and `.../2026-09-04-kynotes-kyrecovery-deposit.md`. Library reference: `ky-primitives/README.md` section "recoveryclient" and `go doc github.com/Busness-app/ky-primitives/recoveryclient`. Product reference: `kysignon-server` master handlers, `web/src/components/AdminBackup.tsx`, `docs/RESTORE.md`, and, once it lands, the kysignon first-consumer swap (the pattern for handlers over the library).

## Global Constraints

- KySignOn adapter and v0.5.1 are available; use the shared package, preserving product token labels.
- Plan A merged first: `storage.GetSetting/SetSetting/DeleteSetting/ErrNotFound`, `recordAuditOutcome`, `auth.RequireStepUp`, `config.Backup`, `config.MinBackupDepositInterval`, `config.AppName`.
- `service_name` sent at pairing = `config.AppName` = `"KyNotes"` = `Payload.ServiceName` = `RunConfig.AppName`. `Run` refuses a payload whose ServiceName differs from AppName; KyRecovery refuses a deposit whose manifest names anything else.
- **Decided (Yoshi, 2026-09-05):** the KyRecovery token is sealed at rest by `recoveryclient.NewAESGCMSealer([]byte(Secrets.ServerSaltKey), "kynotes:setting:kyrecovery_token")`; never a plaintext settings row and no new key file. kynotes has no deployment encryption key; the salt key is the one 32-byte secret every deployment already holds and already must protect.
- Audit stays flat. Every backup outcome is one `recordAuditOutcome` row with the action from `recoveryclient.Outcome`.
- **Decided (Yoshi, 2026-09-05): attachment data is never in the capsule.** The capsule carries the database (which holds every blob digest and size), the secrets, the recovery key and a config manifest. The blob directory is backed up by the mirror in Plan C (`docs/superpowers/plans/2026-09-05-kynotes-blob-mirror.md`). Status, screen, manifest and runbook all say so; a restore without the mirror has notes and no attachments.
- Drill scratch root is the data directory (`ErrNoScratchRoot` otherwise; never the system temp dir).
- Local copies are named `<escaped-app>.<capsule-id>.kycap` by the library. Do not assert a `KyNotes-` prefix anywhere.
- Shares never on argv. No server code path calls `capsule.Open`, `recoverykey.Combine`, `recoverykey.FromSeed` or `recoveryclient.Restore` except the named functions (guard test).
- Branch `feat/kyrecovery-deposit` in worktree `.claude/worktrees/deposit`.

### Library API (transcribed from `go doc` at ky-primitives 633925b; Task 0 re-checks against the tag)

```go
package recoveryclient
const MaxCapsuleFileBytes, MaxCapsuleTotalBytes; const MinInterval = 15m, MaxInterval = 366d
var ErrNotPaired, ErrKeyMismatch, ErrKeyPinMissing, ErrNoDestination, ErrInProgress, ErrRemote, ErrReceiptUnrecorded, ErrBadInterval, ErrBadKeep, ErrNoScratchRoot, ErrNotFound
var TooLargeMessage string

type Settings interface { Get(key string) (string, error); Set(key, value string) error; Delete(key string) error }
// keys written: kyrecovery_key_id, kyrecovery_threshold, kyrecovery_total_shares, kyrecovery_url, kyrecovery_token_enc, kyrecovery_last_deposit, backup_interval_sec, backup_last_attempt
type Sealer interface { Seal(plain []byte) (string, error); Open(sealed string) ([]byte, error) }
func NewAESGCMSealer(key []byte, label string) (Sealer, error)          // key >= 32 bytes

type RecoveryKey struct { Public recoverykey.PublicKey; Threshold, TotalShares int }
func RecoveryKeyPath(dataDir string) string
func StoreRecoveryKey(dataDir string, settings Settings, k RecoveryKey) error   // fs.ErrExist on a different key
func LoadRecoveryKey(dataDir string, settings Settings) (RecoveryKey, error)
func ParsePinRequest(publicKeyB64 string, threshold, total int) (RecoveryKey, error)

type Options struct{ AllowPrivate bool }
type Client struct{}; func NewClient(o Options) *Client
func (c *Client) ClaimPairing(ctx, serverURL, pairingCode, serviceName, appName string) (PairingResult, error)
func (c *Client) Deposit(ctx, serverURL, apiToken string, container []byte) (Receipt, error)
type Depositor interface{ Deposit(...) }
type PairingResult struct { APIToken string; Key RecoveryKey }
type Receipt struct { CapsuleID, Digest string; SizeBytes int64; DepositedAt time.Time }
func ValidateURL(raw string, allowPrivate bool) error
func StorePairing(settings Settings, sealer Sealer, serverURL, token string) error
type Pairing struct { URL, Token string; Key RecoveryKey }
func LoadPairing(dataDir string, settings Settings, sealer Sealer) (Pairing, error)
func HasPairing(settings Settings) bool
func ClearPairing(settings Settings) error
func LastDeposit(settings Settings) (Receipt, bool, error)

type LocalCopy struct { Name string; SizeBytes int64; CreatedAt time.Time }
func WriteLocalCopy(dir, appName, capsuleID string, raw []byte, keep int) (string, error)
func ListLocalCopies(dir, appName string) ([]LocalCopy, error)

func Interval(defaultInterval time.Duration, settings Settings) (time.Duration, error)
func SetInterval(settings Settings, sec int64) error
func NextRun(defaultInterval time.Duration, settings Settings) (time.Time, bool, error)

type File struct { Path string; Data []byte; Mode int64 }
type Payload struct { ServiceName, AppVersion string; Files []File; Dependencies, VerificationRecipe map[string]any }
func Seal(p Payload, key RecoveryKey) ([]byte, capsule.Manifest, error)
func SQLiteSnapshot(ctx context.Context, db *sql.DB, destPath string) error  // VACUUM INTO; destPath must not exist; 0600

type RunConfig struct { DataDir, AppName, AppVersion, BackupDir string; Keep int; Sealer Sealer }
type Result struct { Manifest capsule.Manifest; SizeBytes int; LocalPath, LocalError string; Receipt *Receipt }
func Run(ctx, cfg RunConfig, settings Settings, collect func() (Payload, error), client Depositor) (Result, error)
func Outcome(res Result, err error) (action, outcome string, details map[string]any)

type Check struct { Name string; Passed bool; Message string }
type DrillResult struct { Passed bool; Checks []Check; ErrorMessage string; DurationMs int64; SizeBytes int }
func Drill(ctx, scratchRoot string, payload Payload, checks func(dir string, opened capsule.Manifest) []Check) (*DrillResult, error)

func ReadShares(r io.Reader) ([]string, error)
func Restore(capsulePath, targetDir, expectService string, shareStrings []string, stdout io.Writer) error
func AuditSafe(s string) string
func FilenameSafe(s string) string

package guardtest // recoveryclient/guardtest
const MinFiles = 10
func NoDecryptOutside(t testing.TB, repoRoot string, allowed map[string][]string) // repo-relative file path -> function names
```

---

## File map

| File | Responsibility |
|---|---|
| `internal/backup/settings.go` | `Settings(*storage.Store)` mapping `storage.ErrNotFound` → `recoveryclient.ErrNotFound`; `TokenSealer(config.Config)` |
| `internal/backup/collect.go` | `Collect(ctx, cfg, store, version) (Payload, error)`; `BlobSummary(store) (count int, bytes int64, err error)` for the status line |
| `internal/backup/service.go` | `Service`; `Run`, `Drill`, `Export`, `Pair`, `Pin`, `Unpair`, `SetSchedule`, `NextRun`, `Status` |
| `internal/backup/drill_checks.go` | the checks a kynotes restore must pass |
| `internal/backup/nodecrypt_test.go` | `guardtest.NoDecryptOutside` |
| `internal/backup/AGENTS.md` | the local contracts |
| `internal/httpapi/backup_routes.go` | eight routes |
| `cmd/kynotes-server/main.go` | `backup-drill`, `export-capsule`, `deposit`, `restore` (kycap); the old `backup --out`/`restore --in` renamed `copy-data-dir` / `restore-data-dir` |
| `internal/app/serve.go` | `runBackupLoop` beside `runGC` |
| `web/src/components/AdminBackup.tsx`, `web/src/api.ts`, `web/src/styles.css` | the screen |
| `docs/RESTORE.md`, `README.md`, `docs/DEPLOYMENT.md`, `AGENTS.md` | operator docs |

---

### Task 0: Pin the tag and reconcile

- [ ] **Step 1:** `go get github.com/Busness-app/ky-primitives@v0.5.1 && go mod tidy`. If the tag does not exist yet, stop: post to `ky-primitives-kyrecovery-package` asking for it rather than pinning a pseudo-version in a product.
- [ ] **Step 2:** `go doc -all github.com/Busness-app/ky-primitives/recoveryclient` and `.../recoveryclient/guardtest`; diff against the block above. Edit this plan where they differ; commit `docs(plan): reconcile against ky-primitives v0.5.0`.
- [ ] **Step 3:** Read `ky-primitives/README.md` "recoveryclient" (the invariant list) and, if merged by then, kysignon's first-consumer PR: its handlers over the library are the pattern for Task 4.

---

### Task 1: Settings adapter and sealer

**Files:** `internal/backup/settings.go`, `internal/backup/settings_test.go`

**Interfaces:**
- Produces: `backup.Settings(s *storage.Store) recoveryclient.Settings`; `backup.TokenSealer(cfg config.Config) (recoveryclient.Sealer, error)`.

- [ ] **Step 1: Failing tests**
```go
package backup

func TestSettingsAdapterMapsNotFound(t *testing.T) {
	st, err := storage.Open(filepath.Join(t.TempDir(), "k.sqlite"))
	if err != nil { t.Fatal(err) }
	defer st.Close()
	s := Settings(st)
	if _, err := s.Get("x"); !errors.Is(err, recoveryclient.ErrNotFound) {
		t.Fatalf("want recoveryclient.ErrNotFound, got %v", err)
	}
	if err := s.Set("x", "1"); err != nil { t.Fatal(err) }
	if v, _ := s.Get("x"); v != "1" { t.Fatal(v) }
	if err := s.Set("empty", ""); err != nil { t.Fatal(err) }
	if _, err := s.Get("empty"); err != nil { t.Fatalf("empty value is present, not missing: %v", err) }
	if err := s.Delete("x"); err != nil { t.Fatal(err) }
	if _, err := s.Get("x"); !errors.Is(err, recoveryclient.ErrNotFound) { t.Fatal("not deleted") }
}

func TestTokenSealerRoundTripAndDomain(t *testing.T) {
	c := config.Defaults()
	c.Secrets.ServerSaltKey = strings.Repeat("k", 32)
	sealer, err := TokenSealer(c)
	if err != nil { t.Fatal(err) }
	sealed, err := sealer.Seal([]byte("tok"))
	if err != nil { t.Fatal(err) }
	if strings.Contains(sealed, "tok") { t.Fatal("token in the clear") }
	got, err := sealer.Open(sealed)
	if err != nil || string(got) != "tok" { t.Fatal(err) }
	other := c
	other.Secrets.ServerSaltKey = strings.Repeat("j", 32)
	os, _ := TokenSealer(other)
	if _, err := os.Open(sealed); err == nil { t.Fatal("opened under another key") }
	short := c
	short.Secrets.ServerSaltKey = "short"
	if _, err := TokenSealer(short); err == nil { t.Fatal("a key under 32 bytes must be refused") }
}
```
- [ ] **Step 2: Run → undefined.**
- [ ] **Step 3: Implement**
```go
package backup

import (
	"errors"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/kynotes-server/internal/config"
	"github.com/Busness-app/kynotes-server/internal/storage"
)

type settingsAdapter struct{ s *storage.Store }

// Settings is the slice of server_settings the library reads and writes.
func Settings(s *storage.Store) recoveryclient.Settings { return settingsAdapter{s} }

func (a settingsAdapter) Get(k string) (string, error) {
	v, err := a.s.GetSetting(k)
	if errors.Is(err, storage.ErrNotFound) {
		return "", recoveryclient.ErrNotFound
	}
	return v, err
}
func (a settingsAdapter) Set(k, v string) error { return a.s.SetSetting(k, v) }
func (a settingsAdapter) Delete(k string) error { return a.s.DeleteSetting(k) }

const tokenLabel = "kynotes:setting:kyrecovery_token"

// TokenSealer keeps the KyRecovery credential out of the database in the clear.
// kynotes has no deployment encryption key; the server salt key is the one
// 32-byte secret every deployment holds.
func TokenSealer(c config.Config) (recoveryclient.Sealer, error) {
	return recoveryclient.NewAESGCMSealer([]byte(c.Secrets.ServerSaltKey), tokenLabel)
}
```
- [ ] **Step 4: Pass, commit** `backup: settings adapter and token sealer over recoveryclient`.

---

### Task 2: Collect: what a KyNotes capsule carries

**Files:** `internal/backup/collect.go`, `internal/backup/collect_test.go`

**Interfaces:**
- Produces:
```go
func Collect(ctx context.Context, c config.Config, st *storage.Store, appVersion string) (recoveryclient.Payload, error)
func BlobSummary(st *storage.Store) (count int, bytes int64, err error) // for Status and the screen
```
- Files sealed: `kynotes.sqlite` (via `recoveryclient.SQLiteSnapshot`), `secrets/pairing.key`, `secrets/serversalt.key` (base64 as on disk), `recovery.pub` when present, `config-manifest.json` (non-secret config, the blob count and total bytes, and `"attachments": "not included; restore blobs/ from the mirror"`).
- Never a blob. The database's `blobs` table is the inventory a restore checks the mirror against.
- Refuses (error) without the database or either secret: a restore without `serversalt.key` locks out every synthetic-salt user.

- [ ] **Step 1: Failing tests**
```go
func TestCollectRefusesWithoutSaltKey(t *testing.T)               // data dir with db but no secrets/ → err mentions serversalt.key
func TestCollectSnapshotCarriesUncheckpointedWALRow(t *testing.T) // st.SetSetting("wal","row") then Collect; write Files[0].Data to a temp file, open read-only, SELECT it back
func TestCollectNeverIncludesBlobs(t *testing.T)                  // seed two rows in blobs and two files under <data>/blobs → no Files path starts with "blobs/"; manifest says count 2 and the bytes
func TestBlobSummaryCounts(t *testing.T)
```

- [ ] **Step 2: Run → undefined.**
- [ ] **Step 3: Implement**
```go
func Collect(ctx context.Context, c config.Config, st *storage.Store, appVersion string) (recoveryclient.Payload, error) {
	p := recoveryclient.Payload{ServiceName: config.AppName, AppVersion: appVersion}
	scratch, err := os.MkdirTemp(c.DataDir, ".snapshot-*")
	if err != nil {
		return p, err
	}
	defer os.RemoveAll(scratch)
	snap := filepath.Join(scratch, "kynotes.sqlite")
	if err := recoveryclient.SQLiteSnapshot(ctx, st.DB(), snap); err != nil {
		return p, fmt.Errorf("snapshot: %w", err)
	}
	db, err := os.ReadFile(snap)
	if err != nil {
		return p, err
	}
	p.Files = append(p.Files, recoveryclient.File{Path: "kynotes.sqlite", Data: db, Mode: 0600})
	for _, name := range []string{"pairing.key", "serversalt.key"} {
		b, err := os.ReadFile(filepath.Join(c.DataDir, "secrets", name))
		if err != nil {
			return p, fmt.Errorf("secrets/%s is required for a restorable capsule: %w", name, err)
		}
		p.Files = append(p.Files, recoveryclient.File{Path: "secrets/" + name, Data: b, Mode: 0600})
	}
	if pub, err := os.ReadFile(recoveryclient.RecoveryKeyPath(c.DataDir)); err == nil {
		p.Files = append(p.Files, recoveryclient.File{Path: "recovery.pub", Data: pub, Mode: 0600})
	}
	count, bytes, err := BlobSummary(st)
	if err != nil {
		return p, err
	}
	manifest, _ := json.Marshal(map[string]any{
		"app": config.AppName, "limits": c.Limits,
		"blobs": map[string]any{"count": count, "bytes": bytes, "attachments": "not included; restore blobs/ from the mirror (docs/RESTORE.md)"},
	})
	p.Files = append(p.Files, recoveryclient.File{Path: "config-manifest.json", Data: manifest, Mode: 0600})
	p.Dependencies = map[string]any{"sqlite": "modernc.org/sqlite", "go": runtime.Version()}
	p.VerificationRecipe = map[string]any{
		"required_tables": []string{"users", "containers", "objects", "blobs", "server_settings"},
		"required_files":  []string{"secrets/pairing.key", "secrets/serversalt.key"},
	}
	return p, nil
}

func BlobSummary(st *storage.Store) (int, int64, error) {
	var n int
	var b int64
	err := st.DB().QueryRow(`SELECT COUNT(*), COALESCE(SUM(size_bytes),0) FROM blobs`).Scan(&n, &b)
	return n, b, err
}
```
- [ ] **Step 4: Pass, commit** `backup: collect the database, secrets and recovery key; attachments stay out by design`.

---

### Task 3: Service

**Files:** `internal/backup/service.go`, `internal/backup/drill_checks.go`, `internal/backup/service_test.go`

**Interfaces:**
- Produces:
```go
type Service struct {
	cfg      config.Config
	store    *storage.Store
	client   *recoveryclient.Client
	settings recoveryclient.Settings
	sealer   recoveryclient.Sealer
	version  string
}
func New(cfg config.Config, st *storage.Store, version string) (*Service, error)
func (s *Service) Run(ctx context.Context) (recoveryclient.Result, error)
func (s *Service) Drill(ctx context.Context) (*recoveryclient.DrillResult, error)
func (s *Service) Export(ctx context.Context) (raw []byte, m capsule.Manifest, err error)
func (s *Service) Pair(ctx context.Context, url, code string) (recoveryclient.RecoveryKey, error)
func (s *Service) Pin(publicKeyB64 string, k, n int) (recoveryclient.RecoveryKey, error)
func (s *Service) Unpair() (url string, err error)
func (s *Service) SetSchedule(sec int64) (stored int64, err error)
func (s *Service) NextRun() (time.Time, bool, error)
func (s *Service) Status() map[string]any
```
- `New` builds `client = recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: cfg.Backup.AllowPrivateRecovery})`, `settings = Settings(st)`, `sealer` from `TokenSealer` (error propagates).
- `Run` is `recoveryclient.Run(ctx, recoveryclient.RunConfig{DataDir: cfg.DataDir, AppName: config.AppName, AppVersion: s.version, BackupDir: cfg.Backup.Dir, Keep: cfg.Backup.Keep, Sealer: s.sealer}, s.settings, collect, s.client)` where `collect` closes over `Collect`.
- `Drill` is `recoveryclient.Drill(ctx, s.cfg.DataDir, payload, Checks)`.
- `Export`: `LoadRecoveryKey`, `Collect`, `recoveryclient.Seal(payload, key)`.
- `defaultInterval()` parses `cfg.Backup.DepositInterval` (validated in Plan A Task 8).
- Drill checks (`drill_checks.go`, `func Checks(dir string) []recoveryclient.Check`): open `<dir>/kynotes.sqlite` read-only; `PRAGMA integrity_check` = ok; each of `users, containers, objects, blobs, server_settings` present; `SELECT 1 FROM users WHERE role='admin' AND status='active'` returns a row; both secret files present and base64-decode to 32 bytes; `recovery.pub` parses via `recoverykey.ParsePublicKey` when present; `config-manifest.json` parses. No attachment check: blobs are not in the capsule.

- [ ] **Step 1: Failing tests** (each with a private key held only by the test: `k, _ := recoverykey.Generate()`; pin with `Pin(base64.StdEncoding.EncodeToString(k.Public().Bytes()), 2, 3)`)
```go
func TestRunWithLocalDirWritesCapsuleAt0600(t *testing.T)       // cfg.Backup.Dir set, not paired → res.LocalPath exists, mode 0600, name ends ".kycap", listed by ListLocalCopies(dir, "KyNotes"); capsule.Open(raw, k, tmp) yields kynotes.sqlite
func TestRunWithNoDestinationIsErrNoDestination(t *testing.T)   // pinned, no dir, not paired
func TestRunUnpinnedIsErrNotPaired(t *testing.T)
func TestPairStoresSealedTokenAndPinsKey(t *testing.T)           // TLS httptest KyRecovery stub returning key+token; server_settings holds no row containing "tok"; kyrecovery_token_enc opens through the sealer to "tok"
func TestPairToDifferentKeyIsRefused(t *testing.T)               // second Pair with another key → fs.ErrExist; pin unchanged
func TestDepositResultAudits(t *testing.T)                       // stub accepts; res.Receipt non-nil; recoveryclient.Outcome gives action "admin.backup_run", outcome "success"
func TestDrillPassesOnOwnPayload(t *testing.T)                   // Drill → Passed; no leftover dirs under DataDir afterwards
func TestUnpairKeepsKeyPinAndLocalCopies(t *testing.T)
func TestSetScheduleReadsBack(t *testing.T)                      // 3600 → 3600; 60 → ErrBadInterval; 1<<55 → ErrBadInterval; 0 → 0 and NextRun ok=false
```
The httptest stub implements `POST /api/pairing/claim` and `POST /api/backup/push` per `kyrecovery-server/zero_code_pairing_handoff_spec.md` v2 (read it for the exact JSON). Use `httptest.NewTLSServer` and `Options{AllowPrivate: true}` so `127.0.0.1` is admitted; the client must trust the stub's certificate: look for the hook the library's own `client_test.go` uses (`export_test.go` in `recoveryclient` names it) and, if there is none exported, exercise pairing at the `Service` level through a `Depositor`/claim fake and leave the wire path to the library's tests.

- [ ] **Step 2: Run → undefined.**
- [ ] **Step 3: Implement service.go**; `Status()` is the one method with logic of its own:
```go
func (s *Service) Status() map[string]any {
	out := map[string]any{"paired": false, "key_pinned": false, "app_name": config.AppName, "app_version": s.version}
	if u, err := s.settings.Get("kyrecovery_url"); err == nil {
		out["recovery_url"] = u
	}
	key, err := recoveryclient.LoadRecoveryKey(s.cfg.DataDir, s.settings)
	switch {
	case err == nil:
		out["key_pinned"], out["paired"] = true, recoveryclient.HasPairing(s.settings)
		out["recovery_key_id"], out["threshold"], out["total_shares"] = key.Public.ID(), key.Threshold, key.TotalShares
	case errors.Is(err, recoveryclient.ErrKeyMismatch):
		out["recovery_key_error"] = "recovery.pub does not match the pinned key ID"
	case recoveryclient.HasPairing(s.settings):
		out["recovery_key_error"] = "paired, but recovery.pub is missing; restore it or re-pair"
	}
	if last, ok, err := recoveryclient.LastDeposit(s.settings); err == nil && ok {
		out["last_deposit"] = last
	}
	if s.cfg.Backup.Dir != "" {
		out["local_dir"], out["local_keep"] = s.cfg.Backup.Dir, s.cfg.Backup.Keep
		if copies, err := recoveryclient.ListLocalCopies(s.cfg.Backup.Dir, config.AppName); err == nil {
			out["local_copies"] = copies
		} else {
			out["local_error"] = recoveryclient.AuditSafe(err.Error())
		}
	}
	if iv, err := recoveryclient.Interval(s.defaultInterval(), s.settings); err == nil {
		out["interval_sec"] = int64(iv / time.Second)
		out["min_interval_sec"] = int64(recoveryclient.MinInterval / time.Second)
		if next, on, err := s.NextRun(); err == nil && on {
			out["next_run_at"] = next.Format(time.RFC3339)
		}
	}
	if n, b, err := BlobSummary(s.store); err == nil {
		out["attachments"] = map[string]any{"in_capsule": false, "count": n, "bytes": b}
	}
	return out
}
```
- [ ] **Step 4: Pass, commit** `backup: service over recoveryclient`.

---

### Task 4: Routes

**Files:** `internal/httpapi/backup_routes.go`, `internal/httpapi/backup_routes_test.go`, `internal/httpapi/router.go` (wire), `internal/httpapi/hardening_test.go` (new)

**Interfaces:** `BackupRoutes(mux *http.ServeMux, db *sql.DB, svc *backup.Service)`. All under `auth.RequireAdmin`; those marked † under `auth.RequireStepUp`; all non-GET check `auth.CheckCSRF`. Audit through `recordAuditOutcome(db, actor, action, object, outcome, recoveryclient.AuditSafe(reason), requestID)`.

| Route | Behaviour |
|---|---|
| `GET  /api/v1/admin/backup/status` | `writeJSON(w, svc.Status())` |
| `POST /api/v1/admin/backup/drill` | `svc.Drill`; audit `admin.backup_drill_run` with outcome from `Passed`; body is the `DrillResult` |
| `GET  /api/v1/admin/backup/export-capsule` † | audit `admin.backup_export` **first**; if the audit insert fails, 500 and no bytes; `svc.Export`; `Content-Type: application/octet-stream`, `Content-Disposition: attachment; filename="KyNotes."+recoveryclient.FilenameSafe(m.CapsuleID)+".kycap"` |
| `POST /api/v1/admin/backup/pair-remote` † | `{recovery_url, pairing_code}`; `recoveryclient.ValidateURL(url, cfg.Backup.AllowPrivateRecovery)` before anything; `svc.Pair`; 409 on `fs.ErrExist`; audit `admin.backup_remote_pair` with `recovery_key_id`, `threshold`, `total_shares`, `private_recovery_allowed` in the reason text |
| `POST /api/v1/admin/backup/pin-key` † | `{public_key, threshold, total_shares}` via `svc.Pin` (`ParsePinRequest` inside); 400 on parse, 409 on `fs.ErrExist`; audit `admin.backup_key_pin` |
| `POST /api/v1/admin/backup/deposit` † | `http.NewResponseController(w).SetWriteDeadline(now+16m)`; actor resolved before the run; `svc.Run(context.WithoutCancel(r.Context()))`; then, when Plan C has landed, `mirror.Sync` for the blobs (its result is a second audit row, never a reason to fail the capsule); audit via `Outcome` always; then: `ErrReceiptUnrecorded` → 500 saying the capsule was deposited; `ErrKeyPinMissing`/`ErrNotPaired`/`ErrNoDestination` → 412 (message names `KYNOTES_BACKUP_DIR` for no destination); `ErrKeyMismatch` → 409; `ErrInProgress` → 409; `capsule.ErrCapsuleTooLarge` → 413 with `recoveryclient.TooLargeMessage`; `ErrRemote` → 502 mentioning the local copy if `res.LocalPath != ""`; else 500. Success body: the `Result` |
| `DELETE /api/v1/admin/backup/pairing` † | `svc.Unpair`; 412 when `ErrNotPaired`; audit `admin.backup_unpair`; reply text: rows removed; the credential is dead only when the KyRecovery admin revokes it |
| `PUT  /api/v1/admin/backup/schedule` † | `{interval_sec}`; 400 on `ErrBadInterval`; reply and audit carry the read-back value from `svc.SetSchedule` |

- [ ] **Step 1: Failing tests** — one per row, plus `TestUnpairedExportAndDepositAre412`, `TestDestructiveBackupRoutesNeedStepUp` (table of the six † routes; admin cookie without step-up → 403 `step_up_required`), `TestExportRefusedWhenAuditFails` (run the export against a store whose `audit_events` table was dropped in the test: the audit insert fails, the body must be empty and status 500). Use the `harness_test.go` helpers Plan A Task 4 introduced.
- [ ] **Step 2: Run → undefined.**
- [ ] **Step 3: Implement**, then wire `BackupRoutes` in `router.go` next to `AdminRoutes`.
- [ ] **Step 4: Pass, commit** `httpapi: backup routes behind step-up`.

---

### Task 5: CLI and scheduler

**Files:** `cmd/kynotes-server/main.go`, `internal/app/serve.go`, `cmd/kynotes-server/restore_test.go`

- [ ] **Step 1:** Rename the plaintext commands: `backup --out` → `copy-data-dir --out`, `restore --in` → `restore-data-dir --in` (same bodies; still require the server stopped). Update `docs/DEPLOYMENT.md`. The probe does not call them (grep).
- [ ] **Step 2:** Move `recordAuditOutcome` from `httpapi` to `storage` as `storage.RecordAuditOutcome(db, actor, event, object, outcome, reason, requestID string)` so `cmd` and `app` can call it; `httpapi.recordAuditOutcome` becomes a one-line wrapper. Commit that separately: `storage: RecordAuditOutcome shared by routes, CLI and scheduler`.
- [ ] **Step 3:** Subcommands, each through `loadStoreForCommand` and `backup.New(c, s, "dev")`:
  - `backup-drill` → `svc.Drill(ctx)`; print each check as `PASS name` / `FAIL name: message`; exit 1 unless `Passed`.
  - `export-capsule --out <file.kycap>` → `svc.Export`; write 0600 via temp+rename; refuse an existing path.
  - `deposit` → `svc.Run(context.Background())`; `storage.RecordAuditOutcome(db, "system", action, capsuleID, outcome, reason, "cli")`; print `capsule <id> <bytes> local=<path|none> remote=<receipt|none>`; exit 1 on error.
  - `restore --capsule <file> --to <dir> [--service KyNotes]` → shares via `recoveryclient.ReadShares(os.Stdin)`; refuse when fewer than two lines arrive; refuse a non-empty `--to` (`os.ReadDir` len > 0); `recoveryclient.Restore(capsule, to, service, shares, os.Stdout)`. Usage text: shares are read from stdin one per line and never from the command line.
- [ ] **Step 4:** Failing test `TestRestoreRoundTripWithSplitKey` in `cmd/kynotes-server/restore_test.go`: `k, _ := recoverykey.Generate()`; `shares, _ := recoverykey.Split(k, 2, 3)`; seal a payload with `recoveryclient.Seal(payload, RecoveryKey{Public: k.Public(), Threshold: 2, TotalShares: 3})`; write it; run `restoreCommand` with two share strings on a pipe → `kynotes.sqlite` exists in the target; then one share → error; `--service Other` → error before any combine (assert the error text names the service); non-empty target → error. `shamir.Share` to string: use the encoding the library's `ReadShares`/`ParseShare` expect (`go doc shamir.Share`).
- [ ] **Step 5:** Scheduler in `serve.go`, started beside `runGC` on the same context, and the loop's `Run` on `context.WithoutCancel`:
```go
func runBackupLoop(ctx context.Context, svc *backup.Service, db *sql.DB, log *logging.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		next, on, err := svc.NextRun()
		if err != nil || !on || time.Now().Before(next) {
			continue
		}
		res, err := svc.Run(context.WithoutCancel(ctx))
		if errors.Is(err, recoveryclient.ErrNotPaired) || errors.Is(err, recoveryclient.ErrNoDestination) {
			continue // never paired and nowhere to write: the only silent skip
		}
		action, outcome, details := recoveryclient.Outcome(res, err)
		reason, _ := details["error"].(string)
		storage.RecordAuditOutcome(db, "system", action, res.Manifest.CapsuleID, outcome, reason, "scheduler")
		if err != nil {
			log.Warn("backup: scheduled run failed", "error", recoveryclient.AuditSafe(err.Error()))
		}
	}
}
```
  `ErrKeyPinMissing` is deliberately not skipped: it is audited as a failure. At startup, when `c.Backup.AllowPrivateRecovery`, log `backup: private KyRecovery addresses admitted (KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY)`. Check `logging.Logger`'s method names in `internal/logging/logger.go` before writing the calls.
- [ ] **Step 6:** Pass, commit `cli: backup-drill, export-capsule, deposit, restore; scheduler`.

---

### Task 6: Screen

**Files:** `web/src/components/AdminBackup.tsx` (new, lifted from kysignon), `web/src/api.ts`, `web/src/main.tsx` (mount under the Admin view), `web/src/styles.css` (`.dr-*`), `web/src/components/AdminBackup.test.tsx`

- [ ] **Step 1:** `api.ts`: `backupStatus`, `backupRun`, `backupDrill`, `backupPair`, `backupPin`, `backupUnpair`, `backupSchedule`, `downloadCapsule()` (fetch → blob → anchor click, filename from `Content-Disposition`). A `withStepUp(fn)` wrapper catches a `step_up_required` error, prompts for the password via a small modal, calls `stepUpWithPassword` (Plan A Task 7), retries once.
- [ ] **Step 2:** Copy `kysignon-server/web/src/components/AdminBackup.tsx`; rename `KYSIGNON_*` strings to `KYNOTES_*`; the "what a capsule carries" panel lists database, secret keys, recovery key file, config manifest, and a fifth line driven by `status.attachments`: "Attachments: not in the capsule (N files, X MiB). They are backed up by the blob mirror" with a link to the mirror panel once Plan C lands, or "no mirror configured: set KYNOTES_BLOB_TARGET" as a warning until then. Four fact cards, one action row, schedule form (min from `min_interval_sec`), pairing panel with Unpair, key-by-hand panel; warnings for no key, no destination, schedule off.
- [ ] **Step 3:** No `dangerouslySetInnerHTML` anywhere in the component; add a vitest that reads the component source and asserts that.
- [ ] **Step 4:** vitest: renders the four cards from a mocked status; the no-destination warning shows when `key_pinned && !paired && !local_dir`; the schedule form refuses values under `min_interval_sec`; the attachments line shows the count and the mirror warning.
- [ ] **Step 5:** `npm run build && npm test`, `rm -rf internal/web/dist && cp -r web/dist internal/web/dist`, commit `web: disaster recovery screen`.

---

### Task 7: Decrypt guard

**Files:** `internal/backup/nodecrypt_test.go`

- [ ] **Step 1:**
```go
package backup

import (
	"path/filepath"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient/guardtest"
)

func TestNothingInTheServerDecrypts(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	guardtest.NoDecryptOutside(t, root, map[string][]string{
		"cmd/kynotes-server/main.go": {"restoreCommand"}, // recoveryclient.Restore
	})
}
```
The drill needs no exemption: `recoveryclient.Drill` opens the throwaway-key capsule inside the library, not in this repo. `restoreCommand` is the only function in the repo that may call `recoveryclient.Restore`; nothing calls `capsule.Open`, `recoverykey.Combine` or `recoverykey.FromSeed` directly. Test files are skipped by the guard, so `restore_test.go`'s `capsule.Open` is fine.
- [ ] **Step 2:** Prove it bites: add `_, _, _ = capsule.Open(nil, recoverykey.PrivateKey{}, "")` to `main()`, run the test, see it fail naming `main.go`, remove the line. Say so in the commit message.
- [ ] **Step 3:** Commit `backup: decrypt guard`.

---

### Task 8: Docs

**Files:** `docs/RESTORE.md` (new), `README.md` (new), `docs/DEPLOYMENT.md`, `AGENTS.md`, `internal/backup/AGENTS.md` (new)

- [ ] **Step 1:** `docs/RESTORE.md` from kysignon's template, adapted: paths (`/data/kynotes.sqlite`, `/data/secrets/*.key`, `/data/blobs`); the empty-volume gate (a leftover `-wal` replays into the restored database); copy the old volume out first as root, mode 700, verified by file count, before any `down -v`; no key on stdout; Docker restore target writable by `$(id -u):$(id -g)`; session revocation is per user (`POST /api/v1/auth/logout-all` per account, or `UPDATE sessions SET revoked_at=... WHERE user_id=?`); rotation: `pairing.key` can be rotated (every device re-pairs), `serversalt.key` is never rotated (it decides every synthetic login salt, rotating it locks out every user without a stored salt); post-restore trust step: pin the key again or re-pair; attachments: the capsule never carries them; restore `blobs/` with `kynotes-server fetch-blobs` from the mirror (Plan C) or from a `copy-data-dir` copy, then run `kynotes-server consistency-check`, which lists every digest the database expects and the blob store lacks.
- [ ] **Step 2:** `README.md`: what KyNotes is (two lines), link to `docs/DEPLOYMENT.md`, and the backup paragraphs: why TLS matters when the capsule is sealed (the recovery key at pairing, the token, the receipts otherwise travel in the clear), pin by hand or compare fingerprints, every `KYNOTES_BACKUP_*` variable and `KYNOTES_DNS`.
- [ ] **Step 3:** `internal/backup/AGENTS.md`: the local contracts (service name = `config.AppName`; sealer label; attachments never in the capsule and why; drill scratch root is the data dir; drill checks; nothing decrypts outside `restoreCommand`). Root `AGENTS.md`: replace Plan A's interim bullet with the DOX chain entry.
- [ ] **Step 4:** Commit `docs: restore runbook, README, backup contracts`.

---

### Task 9: Prove it, PR, board

- [ ] **Step 1: Gate** — `gofmt -l .`, `go vet ./...`, `go test -race ./...`, web build + tests, `internal/web/dist` diff committed, the CI Docker probe block from `.github/workflows/ci.yml`.
- [ ] **Step 2: Screen live** — throwaway data dir, `KYNOTES_BACKUP_DIR=/tmp/kyn-bk`, run, log in, pin a freshly generated key by hand (a ten-line `go run` program calling `recoverykey.Generate` and printing base64 of the public key bytes; the private key is dropped), Back up now, confirm a `.kycap` at 0600 in the directory and audit rows `admin.backup_key_pin` and `admin.backup_run`.
- [ ] **Step 3: Restore runbook Step 1** — seal to a freshly split 2-of-3 key, `kynotes-server restore` with two shares on stdin into an empty dir, start the server on it, log in. Then each failure mode: one share, wrong `--service`, non-empty target.
- [ ] **Step 4: Live pairing in the homelab** — `KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY=true KYNOTES_DNS=192.168.1.1 docker compose -f docker-compose.yml -f docker-compose.lan-dns.yml up -d`; recreate the container; `docker inspect KyNotes-Server --format '{{.HostConfig.Dns}}'` shows the resolver; pair from the screen; Back up now; the KyRecovery dashboard shows the capsule.
- [ ] **Step 5: PR** via the `pull-request` skill; expect two to three reviewer rounds. Post each round's state to `kynotes-kyrecovery-deposit`; the final post sets `status=done`.

---

## Self-review

- Spec rows: 1 (T3 Pair, sealer T1), 2 (T3 Pin, T4), 3 (library `Run` via T3), 4 (library `WriteLocalCopy` via `RunConfig.BackupDir`), 5 (T3 SetSchedule, T5 loop, T6 form), 6 (T3 Unpair, T4 text), 7 (Plan A config + `Options{AllowPrivate}` in T3 + startup log in T5 + audit text in T4), 8 (Plan A compose), 9 (T6), 10 (Plan A step-up + T4 hardening test), 11 (T7), 12 (T8 RESTORE.md, T9 proof), 13 (T8 README/AGENTS), 14 (Plan A). Attachments: excluded in T2 by decision, surfaced in T3 Status, T6 screen, T8 runbook; their backup is Plan C.
- Names: `Settings`, `TokenSealer` (T1 → T3); `Collect`, `BlobSummary` (T2 → T3); `Service` methods (T3 → T4, T5); `storage.RecordAuditOutcome` (T5, replacing Plan A's httpapi-local function; Plan A's callers keep working through the wrapper); `Checks` (T3); `restoreCommand` (T5 → T7).
- Library names all come from `go doc` at 633925b, including `recoverykey.PrivateKey.Public()`; the only thing Task 0 must re-check is that the tag carries the same API.
- Decisions taken 2026-09-05: sealer keyed from `ServerSaltKey`; attachments never in the capsule; plaintext copy commands renamed (T5) and the off-box path for blobs is Plan C.
