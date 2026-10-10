package app

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/logging"
)

// EnsureBootstrapAdmin seeds an empty database from the environment: BOOTSTRAP_ADMIN_PASS (and
// BOOTSTRAP_ADMIN_USER, default "admin") create the administrator account, and BOOTSTRAP_EVERYDAY_USER
// with BOOTSTRAP_EVERYDAY_PASS optionally create the everyday account that writes notes. They are
// separate accounts with different usernames, never one account doing both. The operator chose both
// passwords, so both accounts are flagged (password_admin_known) and change them at first sign-in.
// Without BOOTSTRAP_ADMIN_PASS the database stays empty and the web setup creates both accounts.
func EnsureBootstrapAdmin(db *sql.DB, c config.Config) error {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	password := os.Getenv("BOOTSTRAP_ADMIN_PASS")
	if count > 0 || password == "" {
		return nil
	}
	admin := strings.ToLower(strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_USER")))
	if admin == "" {
		admin = "admin"
	}
	everyday := strings.ToLower(strings.TrimSpace(os.Getenv("BOOTSTRAP_EVERYDAY_USER")))
	everydayPassword := os.Getenv("BOOTSTRAP_EVERYDAY_PASS")
	if (everyday == "") != (everydayPassword == "") {
		return errors.New("BOOTSTRAP_EVERYDAY_USER and BOOTSTRAP_EVERYDAY_PASS go together")
	}
	if everyday == admin {
		return errors.New("BOOTSTRAP_EVERYDAY_USER must differ from BOOTSTRAP_ADMIN_USER: the administrator account cannot open notes")
	}
	type account struct{ username, password, kind string }
	accounts := []account{{admin, password, auth.KindAdmin}}
	if everyday != "" {
		accounts = append(accounts, account{everyday, everydayPassword, auth.KindEveryday})
	}
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, a := range accounts {
		salt := auth.SyntheticLoginSalt(c.Secrets.ServerSaltKey, a.username)
		authSecret, err := auth.DeriveAuthSecret(a.password, salt, 600000)
		if err != nil {
			return fmt.Errorf("failed to derive bootstrap auth secret: %w", err)
		}
		hash, err := auth.HashAuthSecret(authSecret)
		if err != nil {
			return fmt.Errorf("failed to hash bootstrap auth secret: %w", err)
		}
		id, err := ids.Mint("usr")
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO users(id, username, auth_secret_hash, login_salt, login_iterations, role, account_kind, status, password_admin_known, created_at, updated_at) VALUES(?, ?, ?, ?, 600000, ?, ?, 'active', 1, ?, ?)`,
			id, a.username, hash, salt, a.kind, a.kind, now, now); err != nil {
			return fmt.Errorf("failed to insert bootstrap %s account: %w", a.kind, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	fmt.Printf("Initial administrator account created for '%s' from BOOTSTRAP_ADMIN_PASS.\n", admin)
	if everyday != "" {
		fmt.Printf("Initial everyday account created for '%s' from BOOTSTRAP_EVERYDAY_PASS.\n", everyday)
	}
	return nil
}

// WarnWithoutAdmin logs no_active_admin when the database has accounts but no active administrator
// account, which the 0026 upgrade causes when every administrator also held notes. /setup stays
// closed; the CLI creates one. role='admin' implies an admin account (0026 triggers).
func WarnWithoutAdmin(db *sql.DB, log *logging.Logger) bool {
	var users, admins int
	if db.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE role='admin' AND status='active') FROM users`).Scan(&users, &admins) != nil || users == 0 || admins > 0 {
		return false
	}
	// The remedy is in the message: the logger drops every attribute key outside its allowlist.
	log.Warn("no_active_admin: no active administrator account; create one with kynotes-server user add --admin --username <name>", "event", "no_active_admin")
	return true
}
