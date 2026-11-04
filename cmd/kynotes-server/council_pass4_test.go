package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Secrets given by the environment have no file in the data directory: copy-data-dir carries them,
// so restore-data-dir accepts the copy (hostile-review pass 4).
func TestCopyDataDirCarriesEnvironmentSecrets(t *testing.T) {
	pairing, salt := "pairing-secret-from-the-env-0001", "server-salt-key-from-the-env-001"
	t.Setenv("KYNOTES_SECRETS_PAIRING_SECRET", pairing)
	t.Setenv("KYNOTES_SECRETS_SERVER_SALT_KEY", salt)
	dataDir := t.TempDir()
	cfgPath := filepath.Join(dataDir, "kynotes.yaml")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dataDir+"\nserver:\n  bind: 127.0.0.1:0\n  dev_insecure_cookies: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := userCommand([]string{"add", "--username", "restored", "--password", "pw-1", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "secrets", "pairing.key")); err == nil {
		t.Fatal("fixture: the environment's secret was written to the data directory")
	}
	copyDir := filepath.Join(t.TempDir(), "copy")
	if err := backupCommand([]string{"--out", copyDir, "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"pairing.key": pairing, "serversalt.key": salt} {
		path := filepath.Join(copyDir, "secrets", name)
		got, err := os.ReadFile(path)
		if err != nil || string(got) != base64.StdEncoding.EncodeToString([]byte(want)) {
			t.Fatalf("%s not carried: %q %v", name, got, err)
		}
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", name, info.Mode())
		}
	}
	target := t.TempDir()
	targetCfg := filepath.Join(t.TempDir(), "kynotes.yaml")
	if err := os.WriteFile(targetCfg, []byte("data_dir: "+target+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreCommand([]string{"--in", copyDir, "--force", "--config", targetCfg}); err != nil {
		t.Fatal("restore refused the copy:", err)
	}
}

// A capsule a newer release wrote cannot be migrated here; the target it leaves is still revoked
// and has deposits off, since the operator will start the newer release on it (hostile-review pass 4).
func TestRestoreOfANewerCapsuleStillRevokesAndStopsDeposits(t *testing.T) {
	cfg := config.Defaults()
	cfg.DataDir = t.TempDir()
	cfg.Secrets.PairingSecret = strings.Repeat("p", 32)
	cfg.Secrets.ServerSaltKey = strings.Repeat("s", 32)
	cfg.Backup.BlobTarget.URL = "file://" + t.TempDir()
	st, err := storage.Open(filepath.Join(cfg.DataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	later := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	for _, q := range []string{
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,status,created_at,updated_at) VALUES('usr_fixture','admin','x','salt',600000,'admin','admin','active','','')`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('sess_fixture','usr_fixture','token','csrf','',?1,?1)`,
		`INSERT INTO schema_migrations(version,applied_at) VALUES(999,'')`,
	} {
		if _, err = st.DB().Exec(q, later); err != nil {
			t.Fatal(q, err)
		}
	}
	svc := backup.New(cfg, st, "test")
	defer svc.Close()
	key, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.Pin("system", "fixture", base64.StdEncoding.EncodeToString(key.Public().Bytes()), 2, 3); err != nil {
		t.Fatal(err)
	}
	raw, _, err := svc.Export(context.Background(), "system", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "newer.kycap")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	shares, err := recoverykey.Split(key, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	var output bytes.Buffer
	err = restoreCapsule(path, target, strings.NewReader(shares[0].String()+"\n"+shares[1].String()+"\n"), &output)
	if !errors.Is(err, storage.ErrSchemaNewer) || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("restore of a newer capsule: %v", err)
	}
	restored, err := storage.OpenUnmigrated(filepath.Join(target, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var live int
	if err = restored.DB().QueryRow(`SELECT COUNT(*) FROM sessions WHERE revoked_at=''`).Scan(&live); err != nil || live != 0 {
		t.Fatalf("%d sessions still live (%v)", live, err)
	}
	if interval, err := restored.GetSetting("backup_interval_sec"); err != nil || interval != "0" {
		t.Fatalf("deposits not turned off: %q %v", interval, err)
	}
}
