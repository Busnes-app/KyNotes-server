package httpapi

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// applySSO stores the bundle's SSO settings only when none exist, after the same
// discovery check login uses. It writes through the router's store so login sees it now.
func applySSO(ctx context.Context, db *sql.DB, store *sso.Store, want applysetup.SSO) applysetup.Result {
	have, next := store.Load(), applysetup.WantSSO(want)
	res := applysetup.Result{Section: "sso", Status: applysetup.DecideSSO(have, next)}
	switch res.Status {
	case applysetup.Present:
		return res
	case applysetup.Conflict:
		res.Detail = applysetup.SSODiff(have, next)
		return res
	}
	if _, err := sso.DiscoverEndpoints(ctx, next.IssuerURL); err != nil {
		res.Status, res.Detail = applysetup.Invalid, "issuer metadata probe failed: "+err.Error()
		return res
	}
	if err := store.Save(next); err != nil {
		res.Status, res.Detail = applysetup.Failed, "storing SSO settings failed"
		return res
	}
	if err := storage.RecordAuditOutcome(db, applysetup.Actor, "admin.sso_update", "", "", "success", applysetup.RequestID, applysetup.RequestID); err != nil {
		res.Status, res.Detail = applysetup.Failed, "SSO settings stored but the audit row failed"
	}
	return res
}

// applyAdmin ensures an active admin bound to issuer+subject. issuer is the stored SSO
// issuer, so a bundle without an sso section is still checked against the server's
// settings. Accounts are never adopted by username; a grant revokes the account's
// credentials like a directory promotion.
func applyAdmin(db *sql.DB, cfg config.Config, issuer string, want applysetup.Admin) (applysetup.Result, string) {
	res := applysetup.Result{Section: "admin:" + strings.ToLower(want.Username)}
	failed := func() (applysetup.Result, string) {
		res.Status, res.Detail = applysetup.Failed, "account update failed"
		return res, ""
	}
	if issuer == "" || want.Issuer != issuer {
		res.Status, res.Detail = applysetup.Invalid, "admin issuer must equal the configured SSO issuer"
		if issuer == "" {
			res.Detail = "no SSO issuer is configured; admins need the sso section or existing SSO settings"
		}
		return res, ""
	}
	tx, err := db.Begin()
	if err != nil {
		return failed()
	}
	defer tx.Rollback()
	bound, err := lookupAccount(tx, `SELECT id,username,role,status FROM users WHERE sso_issuer=? AND sso_subject=?`, want.Issuer, want.Subject)
	if err != nil {
		return failed()
	}
	var named *applysetup.Account
	if bound == nil {
		if named, err = lookupAccount(tx, `SELECT id,username,role,status FROM users WHERE username=?`, strings.ToLower(want.Username)); err != nil {
			return failed()
		}
	}
	status, action, detail := applysetup.DecideAdmin(bound, named)
	res.Status, res.Detail = status, detail
	now := time.Now().UTC().Format(time.RFC3339)
	switch action {
	case applysetup.CreateAdmin:
		err = createSSOAdmin(tx, cfg, want, now)
	case applysetup.GrantAdmin:
		err = grantAdmin(tx, bound.ID, want, now)
	}
	if err == nil && action != applysetup.NoAction {
		err = tx.Commit()
	}
	switch {
	case err != nil:
		return failed()
	case status == applysetup.Conflict:
		return res, ""
	case bound != nil:
		return res, bound.Username
	}
	return res, strings.ToLower(want.Username)
}

func lookupAccount(tx *sql.Tx, query string, args ...any) (*applysetup.Account, error) {
	var a applysetup.Account
	err := tx.QueryRow(query, args...).Scan(&a.ID, &a.Username, &a.Role, &a.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func createSSOAdmin(tx *sql.Tx, cfg config.Config, want applysetup.Admin, now string) error {
	id, err := ids.Mint("usr")
	if err != nil {
		return err
	}
	// No usable password: the verifier is for a random secret nobody keeps.
	unusable := make([]byte, 32)
	if _, err := rand.Read(unusable); err != nil {
		return err
	}
	hash, err := auth.HashAuthSecret(hex.EncodeToString(unusable))
	if err != nil {
		return err
	}
	username := strings.ToLower(want.Username)
	if _, err = tx.Exec(`INSERT INTO users(id, username, auth_secret_hash, login_salt, login_iterations, role, status, sso_subject, sso_issuer, created_at, updated_at) VALUES(?, ?, ?, ?, 600000, 'admin', 'active', ?, ?, ?, ?)`,
		id, username, hash, auth.SyntheticLoginSalt(cfg.Secrets.ServerSaltKey, username), want.Subject, want.Issuer, now, now); err != nil {
		return err
	}
	return storage.RecordAuditOutcomeTx(tx, applysetup.Actor, "admin.user.create", "", id, "success", "role=admin", applysetup.RequestID)
}

func grantAdmin(tx *sql.Tx, userID string, want applysetup.Admin, now string) error {
	if err := revokeForRoleChange(tx, want.Issuer, want.Subject, userID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE users SET role='admin', updated_at=? WHERE id=?`, now, userID); err != nil {
		return err
	}
	return storage.RecordAuditOutcomeTx(tx, applysetup.Actor, "admin.user.update", "", userID, "success", "role=admin", applysetup.RequestID)
}
