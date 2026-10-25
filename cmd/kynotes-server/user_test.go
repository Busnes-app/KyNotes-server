package main

import (
	"os"
	"path/filepath"
	"strings"
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

// A derived secret on stdin must name at least auth.LoginIterations; fewer is refused before any write.
func TestUserAddRefusesFewIterations(t *testing.T) {
	cfgPath, _, dataDir := setupCLIFixture(t)
	for _, iterations := range []string{"1", "100000", "599999"} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.WriteString(`{"authSecret":"` + strings.Repeat("a", 64) + `","loginSalt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":` + iterations + `}`)
		w.Close()
		stdin := os.Stdin
		os.Stdin = r
		err = userCommand([]string{"add", "--username", "low", "--config", cfgPath})
		os.Stdin = stdin
		r.Close()
		if err == nil {
			t.Fatalf("user add accepted %s iterations", iterations)
		}
	}
	s, err := storage.Open(filepath.Join(dataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM users WHERE username='low'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("refused user add created %d accounts %v", n, err)
	}
}
