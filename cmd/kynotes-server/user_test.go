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
	if err := userCommand([]string{"add", "--username", "Writer", "--password", "operator-chosen-3", "--everyday", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if err := userCommand([]string{"add", "--username", "Both", "--password", "operator-chosen-4", "--admin", "--everyday", "--config", cfgPath}); err == nil {
		t.Fatal("an account was both kinds")
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
	var both int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM users WHERE username='both'`).Scan(&both); err != nil || both != 0 {
		t.Fatal("a refused user add created an account", both, err)
	}
	for name, want := range map[string]string{"op": "user", "boss": "admin", "writer": "user"} {
		var kind, role string
		var flagged int
		if err := s.DB().QueryRow(`SELECT account_kind,role,password_admin_known FROM users WHERE username=?`, name).Scan(&kind, &role, &flagged); err != nil || kind != want || role != want || flagged != 1 {
			t.Fatalf("%s account_kind=%q role=%q flagged=%d %v", name, kind, role, flagged, err)
		}
	}
}
