package main

import (
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
