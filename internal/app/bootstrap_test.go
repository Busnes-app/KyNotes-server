package app

import (
	"path/filepath"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
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

	authSecret, err := auth.DeriveAuthSecret("SuperSecretPassword123!", salt, iterations)
	if err != nil {
		t.Fatalf("derive failed: %v", err)
	}
	if err := auth.VerifyAuthSecret(authSecret, storedHash); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}
