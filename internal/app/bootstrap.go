package app

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
)

// EnsureBootstrapAdmin seeds initial admin credentials if BOOTSTRAP_ADMIN_PASS is set and no users exist.
// If BOOTSTRAP_ADMIN_PASS is not provided, the database remains unseeded and the web UI prompts
// the user to create the primary administrator account on first visit via /api/setup.
func EnsureBootstrapAdmin(db *sql.DB, c config.Config) error {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	password := os.Getenv("BOOTSTRAP_ADMIN_PASS")
	if password == "" {
		// First-run setup will be performed interactively by the user in the web UI.
		return nil
	}

	username := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_USER"))
	if username == "" {
		username = "admin"
	}

	salt := auth.SyntheticLoginSalt(c.Secrets.ServerSaltKey, username)
	iterations := 600000
	authSecret, err := auth.DeriveAuthSecret(password, salt, iterations)
	if err != nil {
		return fmt.Errorf("failed to derive bootstrap auth secret: %w", err)
	}

	hash, err := auth.HashAuthSecret(authSecret)
	if err != nil {
		return fmt.Errorf("failed to hash bootstrap auth secret: %w", err)
	}

	id, err := ids.Mint("usr")
	if err != nil {
		return fmt.Errorf("failed to mint admin user id: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.Exec(`INSERT INTO users(id, username, auth_secret_hash, login_salt, login_iterations, role, status, created_at, updated_at) VALUES(?, ?, ?, ?, ?, 'admin', 'active', ?, ?)`,
		id, strings.ToLower(username), hash, salt, iterations, now, now)
	if err != nil {
		return fmt.Errorf("failed to insert bootstrap admin user: %w", err)
	}

	fmt.Printf("Initial admin account created for '%s' from BOOTSTRAP_ADMIN_PASS.\n", username)
	return nil
}
