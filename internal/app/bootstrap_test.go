package app

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func TestEnsureBootstrapAdminNoPass(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "kynotes.sqlite"))
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}
	defer store.Close()

	cfg := config.Defaults()
	cfg.DataDir = dir

	// Without BOOTSTRAP_ADMIN_PASS, EnsureBootstrapAdmin does nothing (interactive setup required)
	t.Setenv("BOOTSTRAP_ADMIN_PASS", "")
	if err := EnsureBootstrapAdmin(store.DB(), cfg); err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}

	var count int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("failed to count users: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 users without BOOTSTRAP_ADMIN_PASS, got %d", count)
	}
}

func TestEnsureBootstrapAdminCustomPass(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "kynotes.sqlite"))
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}
	defer store.Close()

	cfg := config.Defaults()
	cfg.DataDir = dir
	cfg.Secrets.ServerSaltKey = "test-salt-key-32-bytes-long-1234"

	t.Setenv("BOOTSTRAP_ADMIN_USER", "customadmin")
	t.Setenv("BOOTSTRAP_ADMIN_PASS", "SuperSecretPassword123!")

	if err := EnsureBootstrapAdmin(store.DB(), cfg); err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}

	var username, storedHash, salt string
	var iterations int
	var role, status string
	err = store.DB().QueryRow(`SELECT username, auth_secret_hash, login_salt, login_iterations, role, status FROM users WHERE username='customadmin'`).Scan(
		&username, &storedHash, &salt, &iterations, &role, &status,
	)
	if err != nil {
		t.Fatalf("custom admin user not found: %v", err)
	}

	if role != "admin" || status != "active" {
		t.Fatalf("unexpected role/status: %s/%s", role, status)
	}
	var known int
	if err := store.DB().QueryRow(`SELECT password_admin_known FROM users WHERE username='customadmin'`).Scan(&known); err != nil || known != 1 {
		t.Fatalf("bootstrap password is operator-known but not flagged: %d %v", known, err)
	}

	authSecret, err := auth.DeriveAuthSecret("SuperSecretPassword123!", salt, iterations)
	if err != nil {
		t.Fatalf("derive failed: %v", err)
	}
	if err := auth.VerifyAuthSecret(authSecret, storedHash); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestBootstrapCreatesSeparateAccounts(t *testing.T) {
	cfg := config.Defaults()
	cfg.Secrets.ServerSaltKey = "test-salt-key-32-bytes-long-1234"
	open := func() *storage.Store {
		store, err := storage.Open(filepath.Join(t.TempDir(), "kynotes.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		return store
	}
	t.Setenv("BOOTSTRAP_ADMIN_USER", "Ops")
	t.Setenv("BOOTSTRAP_ADMIN_PASS", "operator-chosen-1")
	for name, env := range map[string][2]string{"same username": {"ops", "operator-chosen-2"}, "user without pass": {"owner", ""}, "pass without user": {"", "operator-chosen-2"}} {
		t.Setenv("BOOTSTRAP_EVERYDAY_USER", env[0])
		t.Setenv("BOOTSTRAP_EVERYDAY_PASS", env[1])
		store := open()
		var users int
		err := EnsureBootstrapAdmin(store.DB(), cfg)
		if err == nil || store.DB().QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users) != nil || users != 0 {
			t.Fatalf("%s: err=%v users=%d", name, err, users)
		}
		if name == "same username" && !strings.Contains(err.Error(), "must differ") {
			t.Fatalf("same username: %v", err)
		}
	}
	t.Setenv("BOOTSTRAP_EVERYDAY_USER", "Owner")
	t.Setenv("BOOTSTRAP_EVERYDAY_PASS", "operator-chosen-2")
	store := open()
	if err := EnsureBootstrapAdmin(store.DB(), cfg); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"ops": "admin|admin|1", "owner": "user|user|1"} {
		var kind, role string
		var flagged int
		if err := store.DB().QueryRow(`SELECT account_kind,role,password_admin_known FROM users WHERE username=?`, name).Scan(&kind, &role, &flagged); err != nil || fmt.Sprintf("%s|%s|%d", kind, role, flagged) != want {
			t.Fatalf("%s: %s|%s|%d %v", name, kind, role, flagged, err)
		}
	}
}

func TestWarnWithoutAdmin(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var buf bytes.Buffer
	log := logging.New(&buf, "info", "json")
	if WarnWithoutAdmin(store.DB(), log) {
		t.Fatal("an empty database warned")
	}
	insert := `INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,created_at,updated_at) VALUES(?,?,'h','s',1,?,?,'now','now')`
	if _, err := store.DB().Exec(insert, "usr_plain", "plain", "user", "user"); err != nil {
		t.Fatal(err)
	}
	if !WarnWithoutAdmin(store.DB(), log) || !strings.Contains(buf.String(), "user add --admin") || !strings.Contains(buf.String(), "no_active_admin") {
		t.Fatalf("no warning: %s", buf.String())
	}
	if _, err := store.DB().Exec(insert, "usr_inert", "inert", "user", "admin"); err != nil {
		t.Fatal(err)
	}
	if !WarnWithoutAdmin(store.DB(), log) {
		t.Fatal("an admin account without the grant counted as an administrator")
	}
	if _, err := store.DB().Exec(insert, "usr_admin", "admin", "admin", "admin"); err != nil {
		t.Fatal(err)
	}
	if WarnWithoutAdmin(store.DB(), log) {
		t.Fatal("warned with an active administrator account")
	}
}
