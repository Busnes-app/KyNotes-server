package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Q5: restore-data-dir keeps credentials by default (the upgrade rollback), and
// --revoke-credentials ends the copy's sessions and paired devices as a capsule restore does.
func TestRestoreDataDirRevokeCredentials(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		cfgPath, dataDir, copyDir := restoreFixture(t)
		seed, err := storage.Open(filepath.Join(copyDir, "kynotes.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = seed.DB().Exec(`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) SELECT 'ses_x',id,'t','c','','9999','9999' FROM users WHERE username='restored'`); err != nil {
			t.Fatal(err)
		}
		if _, err = seed.DB().Exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,created_at) SELECT 'dev_x',id,'k','f','h','' FROM users WHERE username='restored'`); err != nil {
			t.Fatal(err)
		}
		seed.Close()
		args := []string{"--in", copyDir, "--force", "--config", cfgPath}
		if revoke {
			args = append(args, "--revoke-credentials")
		}
		if err = restoreCommand(args); err != nil {
			t.Fatal(err)
		}
		s, err := storage.Open(filepath.Join(dataDir, "kynotes.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		var live int
		if err = s.DB().QueryRow(`SELECT (SELECT count(*) FROM sessions WHERE id='ses_x' AND revoked_at='')+(SELECT count(*) FROM devices WHERE id='dev_x' AND revoked_at='')`).Scan(&live); err != nil {
			t.Fatal(err)
		}
		s.Close()
		if want := map[bool]int{false: 2, true: 0}[revoke]; live != want {
			t.Fatalf("revoke=%v: %d live credentials, want %d", revoke, live, want)
		}
	}
}

// An offline backup made with a newer binary must not upgrade the live database it copies: the
// older release could no longer open it, and no copy with the old schema would exist.
func TestOfflineBackupCommandsNeverMigrateTheLiveDatabase(t *testing.T) {
	cfgPath, _, dataDir := setupCLIFixture(t)
	db := filepath.Join(dataDir, "kynotes.sqlite")
	s, err := storage.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	var latest int
	if err = s.DB().QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	// As if an older release wrote it: its last migration is not recorded yet.
	if _, err = s.DB().Exec(`DELETE FROM schema_migrations WHERE version=?`, latest); err != nil {
		t.Fatal(err)
	}
	s.Close()
	for _, command := range []string{"export-capsule", "backup-drill", "deposit"} {
		err := capsuleCommand(command, []string{"--config", cfgPath, "--out", filepath.Join(t.TempDir(), "x.kycap")})
		if !errors.Is(err, storage.ErrSchemaOlder) {
			t.Fatalf("%s on an older schema: %v, want ErrSchemaOlder", command, err)
		}
	}
	s, err = storage.OpenUnmigrated(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var now int
	if err = s.DB().QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&now); err != nil || now != latest-1 {
		t.Fatalf("schema now %d %v, want %d (unmigrated)", now, err, latest-1)
	}
}

// copy-data-dir never leaves the copy readable by other local users, even into a 0755 --out.
func TestCopyDataDirIsOwnerOnly(t *testing.T) {
	cfgPath, _, dataDir := setupCLIFixture(t)
	if err := userCommand([]string{"add", "--username", "copied", "--password", "pw-1", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dataDir, "kynotes.sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "copy")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := backupCommand([]string{"--out", out, "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	_ = filepath.Walk(out, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is %v", path, info.Mode().Perm())
		}
		return nil
	})
}
