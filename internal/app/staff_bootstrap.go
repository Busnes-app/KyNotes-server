package app

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func ensureStaffBootstrap(db *sql.DB, c config.Config, tenancy storage.Tenancy) error {
	if !storage.IsPostgres(db) || tenancy.StaffOrg == "" || tenancy.Region == "" {
		return errors.New("staff bootstrap requires recorded multi PostgreSQL bindings")
	}
	if os.Getenv("BOOTSTRAP_EVERYDAY_USER") != "" || os.Getenv("BOOTSTRAP_EVERYDAY_PASS") != "" {
		return errors.New("multi mode refuses BOOTSTRAP_EVERYDAY_USER and BOOTSTRAP_EVERYDAY_PASS; customer accounts come from KyIdentity")
	}
	password := os.Getenv("BOOTSTRAP_ADMIN_PASS")
	if password == "" {
		return nil
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM users WHERE org_id=?`, tenancy.StaffOrg).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	username := strings.ToLower(strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_USER")))
	if username == "" {
		username = "admin"
	}
	if len(username) > 128 || strings.IndexFunc(username, unicode.IsControl) >= 0 {
		return errors.New("BOOTSTRAP_ADMIN_USER is invalid")
	}
	salt := auth.SyntheticLoginSalt(c.Secrets.ServerSaltKey, username)
	proof, err := auth.DeriveAuthSecret(password, salt, auth.LoginIterations)
	if err != nil {
		return err
	}
	hash, err := auth.HashAuthSecret(proof)
	if err != nil {
		return err
	}
	id, err := ids.Mint("usr")
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := storage.TenancyOf(tx)
	if err != nil {
		return err
	}
	if current != tenancy {
		return errors.New("staff bootstrap target changed")
	}
	// N3 serializes this recheck across replicas; password work occurs before taking it.
	if err := tx.QueryRow(`SELECT count(*) FROM users WHERE org_id=?`, tenancy.StaffOrg).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	if _, err := tx.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,status,password_admin_known,created_at,updated_at,org_id) VALUES(?,?,?,?,?,'admin','admin','active',1,?,?,?)`, id, username, hash, salt, auth.LoginIterations, now, now, tenancy.StaffOrg); err != nil {
		return err
	}
	if err := storage.RecordAuditOutcomeTx(tx, "", "admin.user.create", "", id, "success", "kind=admin,source=bootstrap", "staff-bootstrap"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	fmt.Printf("Initial staff administrator account created for '%s' from BOOTSTRAP_ADMIN_PASS.\n", username)
	return nil
}
