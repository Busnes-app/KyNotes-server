package backup

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"
)

func fixture(t *testing.T) (*Service, recoverykey.PrivateKey) {
	t.Helper()
	cfg := config.Defaults()
	cfg.DataDir = t.TempDir()
	cfg.Backup.Dir = t.TempDir()
	cfg.Secrets.PairingSecret = strings.Repeat("p", 32)
	cfg.Secrets.ServerSaltKey = strings.Repeat("s", 32)
	st, err := storage.Open(filepath.Join(cfg.DataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err = st.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,status,created_at,updated_at) VALUES('usr_fixture','admin','fixture','salt',600000,'admin','active','','')`); err != nil {
		t.Fatal(err)
	}
	svc := New(cfg, st, "test")
	key, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.Pin("system", "test", base64.StdEncoding.EncodeToString(key.Public().Bytes()), 2, 3); err != nil {
		t.Fatal(err)
	}
	return svc, key
}

type recoveryFixture struct {
	t         *testing.T
	key       recoverykey.PrivateKey
	fail      bool
	raw       []byte
	onDeposit func()
}

func (f *recoveryFixture) ClaimPairing(_ context.Context, _ string, _ string, service, app string) (recoveryclient.PairingResult, error) {
	if service != config.AppName || app != config.AppName {
		f.t.Fatal("wrong claim identity")
	}
	return recoveryclient.PairingResult{APIToken: "fixture-private-token", Key: recoveryclient.RecoveryKey{Public: f.key.Public(), Threshold: 2, TotalShares: 3}}, nil
}
func (f *recoveryFixture) Deposit(_ context.Context, _, token string, raw []byte) (recoveryclient.Receipt, error) {
	if token != "fixture-private-token" {
		f.t.Fatal("pairing token changed")
	}
	f.raw = raw
	if f.onDeposit != nil {
		f.onDeposit()
	}
	if f.fail {
		return recoveryclient.Receipt{}, errors.New("fixture unavailable")
	}
	m, _, err := capsule.Open(raw, f.key, filepath.Join(f.t.TempDir(), "opened"))
	if err != nil {
		return recoveryclient.Receipt{}, err
	}
	sum := sha256.Sum256(raw)
	return recoveryclient.Receipt{CapsuleID: m.CapsuleID, Digest: hex.EncodeToString(sum[:]), SizeBytes: int64(len(raw)), DepositedAt: time.Now().UTC()}, nil
}
func TestCapsuleSnapshotDrillDestinationsAndTokenCompatibility(t *testing.T) {
	svc, key := fixture(t)
	remote := &recoveryFixture{t: t, key: key}
	svc.client = remote
	if err := svc.Pair(context.Background(), "system", "test", "https://recovery.example", "123456"); err != nil {
		t.Fatal(err)
	}
	stored, err := svc.store.GetSetting("kyrecovery_token_enc")
	if err != nil || strings.Contains(stored, "fixture-private-token") {
		t.Fatal("token not sealed")
	}
	restarted := New(svc.cfg, svc.store, "test")
	seal, err := restarted.sealer()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := seal.Open(stored)
	if err != nil || string(plain) != "fixture-private-token" {
		t.Fatal("restart lost token")
	}
	wrong, _ := recoveryclient.NewAESGCMSealer([]byte(svc.cfg.Secrets.ServerSaltKey), TokenLabel+"wrong")
	if _, err = wrong.Open(stored); err == nil {
		t.Fatal("label not separated")
	}
	if _, err = svc.store.DB().Exec(`PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal(err)
	}
	if err = svc.store.SetSetting("uncheckpointed", "present"); err != nil {
		t.Fatal(err)
	}
	result, err := svc.Run(context.Background(), "system", "test")
	if err != nil || result.Receipt == nil || result.LocalPath == "" {
		t.Fatalf("run: %+v %v", result, err)
	}
	local, err := os.ReadFile(result.LocalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(local) != string(remote.raw) {
		t.Fatal("destinations received different capsules")
	}
	info, err := os.Stat(result.LocalPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe local permissions")
	}
	opened := filepath.Join(t.TempDir(), "restored")
	m, _, err := capsule.Open(local, key, opened)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range Checks(opened, m) {
		if !check.Passed {
			t.Fatal(check)
		}
	}
	snap, err := storage.Open(filepath.Join(opened, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	value, err := snap.GetSetting("uncheckpointed")
	if err != nil || value != "present" {
		t.Fatal("WAL row lost")
	}
	if _, err = os.Stat(filepath.Join(opened, "blobs")); !os.IsNotExist(err) {
		t.Fatal("blob bytes included in capsule")
	}
	drill, err := svc.Drill(context.Background(), "system", "test")
	if err != nil || !drill.Passed {
		t.Fatalf("drill %+v %v", drill, err)
	}
	// Raw JSON values, missing fields and malicious paths cannot silently skip checks.
	for _, bad := range []string{`{}`, `{"version":1,"required_files":["../outside"]}`, `{"version":1,"counts":[]}`, `null`} {
		copy := m
		_ = json.Unmarshal([]byte(bad), &copy.VerificationRecipe)
		if Checks(opened, copy)[0].Passed {
			t.Fatal("malformed recipe passed")
		}
	}
	remote.fail = true
	result, err = svc.Run(context.Background(), "system", "test")
	if err == nil || result.LocalPath == "" {
		t.Fatal("remote failure hid local result")
	}
	remote.fail = false
	svc.cfg.Backup.Dir = filepath.Join(svc.cfg.DataDir, "not-directory")
	if err = os.WriteFile(svc.cfg.Backup.Dir, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err = svc.Run(context.Background(), "system", "test")
	if err != nil || result.Receipt == nil || result.LocalError == "" {
		t.Fatal("local failure prevented remote copy")
	}
	if err = svc.Unpair("system", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.store.GetSetting("kyrecovery_token_enc"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("unpair retained token")
	}
	if _, err = recoveryclient.LoadRecoveryKey(svc.cfg.DataDir, settings{svc.store}); err != nil {
		t.Fatal("unpair lost pin")
	}
	if _, ok, err := recoveryclient.LastDeposit(settings{svc.store}); err != nil || !ok {
		t.Fatal("unpair lost receipt")
	}
}
func TestPreconditionsScheduleAndExportAudit(t *testing.T) {
	svc, _ := fixture(t)
	if err := svc.Pin("system", "test", "not-a-public-key", 2, 3); ErrorCode(err) != "invalid_backup_request" {
		t.Fatalf("invalid pin: %v", err)
	}
	other, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.Pin("system", "test", base64.StdEncoding.EncodeToString(other.Public().Bytes()), 2, 3); ErrorCode(err) != "recovery_key_conflict" {
		t.Fatalf("second key: %v", err)
	}
	for _, seconds := range []int64{-1, 1, 899, 1 << 55} {
		if err = svc.SetSchedule("system", "test", seconds); err == nil {
			t.Fatalf("invalid interval %d", seconds)
		}
	}
	if err = svc.SetSchedule("system", "test", 900); err != nil {
		t.Fatal(err)
	}
	if due, err := svc.Due(time.Now().Add(time.Second)); err != nil || !due {
		t.Fatal("first backup not due")
	}
	if _, err = svc.Run(context.Background(), "system", "test"); err != nil {
		t.Fatal(err)
	}
	if due, err := svc.Due(time.Now()); err != nil || due {
		t.Fatal("schedule ignored last attempt")
	}
	if err = svc.SetSchedule("system", "test", 0); err != nil {
		t.Fatal(err)
	}
	if due, err := svc.Due(time.Now().Add(48 * time.Hour)); err != nil || due {
		t.Fatal("disabled schedule ran")
	}
	svc.cfg.Backup.Dir = ""
	if _, err = svc.Run(context.Background(), "system", "test"); !errors.Is(err, recoveryclient.ErrNoDestination) {
		t.Fatal("no destination accepted")
	}
	if _, err = svc.store.DB().Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	raw, _, err := svc.Export(context.Background(), "system", "test")
	if !errors.Is(err, ErrAudit) || raw != nil {
		t.Fatal("unaudited export escaped")
	}
	if _, err = svc.store.DB().Exec(`DROP TRIGGER fail_audit`); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(svc.cfg.DataDir, "recovery.pub")); err != nil {
		t.Fatal(err)
	}
	raw, _, err = svc.Export(context.Background(), "system", "test")
	if err == nil || raw != nil {
		t.Fatal("missing key exported")
	}
	svc.Close()
	if _, err = svc.Run(context.Background(), "system", "test"); !errors.Is(err, ErrClosed) {
		t.Fatal("closed service ran")
	}
}

func TestMirrorUsesCapsuleInventoryDespiteConcurrentGC(t *testing.T) {
	svc, key := fixture(t)
	svc.cfg.Backup.BlobTarget.URL = "file://" + t.TempDir()
	blobs, err := blobstore.New(svc.cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	temp, err := blobs.NewTemp("gc-race")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(temp, "synthetic ciphertext"); err != nil {
		t.Fatal(err)
	}
	digest, size, err := temp.Finalize("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.store.DB().Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES(?,?,'')`, digest, size); err != nil {
		t.Fatal(err)
	}
	remote := &recoveryFixture{t: t, key: key, onDeposit: func() {
		if _, err := svc.store.DB().Exec(`DELETE FROM blobs WHERE digest=?`, digest); err != nil {
			t.Fatal(err)
		}
		if err := blobs.Delete(digest); err != nil {
			t.Fatal(err)
		}
	}}
	svc.client = remote
	if err = svc.Pair(context.Background(), "system", "gc", "https://recovery.example", "123456"); err != nil {
		t.Fatal(err)
	}
	result, err := svc.Run(context.Background(), "system", "gc")
	if err == nil || result.Receipt == nil || result.LocalPath == "" || result.Mirror == nil || result.Mirror.Missing != 1 {
		t.Fatal("GC race hid missing capsule content", result, err)
	}
	status, err := svc.Status()
	if err != nil || status.Mirror.Last == nil || status.Mirror.Last.Missing != 1 {
		t.Fatal("missing content not visible", err)
	}
}

func TestFailedRunsAdvanceSchedule(t *testing.T) {
	for _, failure := range []string{"remote", "no_destination", "missing_key", "local"} {
		t.Run(failure, func(t *testing.T) {
			svc, key := fixture(t)
			if err := svc.SetSchedule("system", "test", 900); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "remote":
				svc.client = &recoveryFixture{t: t, key: key, fail: true}
				if err := svc.Pair(context.Background(), "system", "test", "https://recovery.example", "123456"); err != nil {
					t.Fatal(err)
				}
				svc.cfg.Backup.Dir = ""
			case "no_destination":
				svc.cfg.Backup.Dir = ""
			case "missing_key":
				if err := os.Remove(filepath.Join(svc.cfg.DataDir, "recovery.pub")); err != nil {
					t.Fatal(err)
				}
			case "local":
				path := filepath.Join(t.TempDir(), "occupied")
				if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
				svc.cfg.Backup.Dir = path
			}
			if due, err := svc.Due(time.Now()); err != nil || !due {
				t.Fatal("fresh run not due", err)
			}
			if _, err := svc.Run(context.Background(), "system", "test"); err == nil {
				t.Fatal("fixture did not fail")
			}
			for _, offset := range []time.Duration{0, time.Minute, 14 * time.Minute} {
				if due, err := svc.Due(time.Now().Add(offset)); err != nil || due {
					t.Fatal("failed run retried before interval", offset, err)
				}
			}
			restarted := New(svc.cfg, svc.store, "test")
			if due, err := restarted.Due(time.Now()); err != nil || due {
				t.Fatal("restart lost failure backoff", err)
			}
			if due, err := restarted.Due(time.Now().Add(16 * time.Minute)); err != nil || !due {
				t.Fatal("failed run never retried", err)
			}
		})
	}
}
