package main

import (
	"path/filepath"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// The operator chose this password, so the account gets no identity until the user changes it.
func TestUserAddFlagsOperatorKnownPassword(t *testing.T) {
	cfgPath, _, dataDir := setupCLIFixture(t)
	if err := userCommand([]string{"add", "--username", "Op", "--password", "operator-chosen-1", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if err := userCommand([]string{"add", "--username", "Boss", "--password", "operator-chosen-2", "--admin", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	s, err := storage.Open(filepath.Join(dataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var known int
	if err := s.DB().QueryRow(`SELECT password_admin_known FROM users WHERE username='op'`).Scan(&known); err != nil || known != 1 {
		t.Fatalf("password_admin_known=%d %v", known, err)
	}
	for name, want := range map[string]string{"op": "user", "boss": "admin"} {
		var kind, role string
		if err := s.DB().QueryRow(`SELECT account_kind,role FROM users WHERE username=?`, name).Scan(&kind, &role); err != nil || kind != want || role != want {
			t.Fatalf("%s account_kind=%q role=%q %v", name, kind, role, err)
		}
	}
}
