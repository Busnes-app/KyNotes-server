package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Busness-app/ky-primitives/oidcverify"
	"github.com/Busness-app/kynotes-server/internal/storage"
)

var ErrSSOLogoutRejected = errors.New("invalid or repeated SSO logout")

// ApplySSOLogout records replay admission, a fence for callbacks already in flight,
// scoped session/device revocation and audit in one writer transaction.
func ApplySSOLogout(ctx context.Context, db *sql.DB, c oidcverify.LogoutClaims, clientID, requestID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if !now.Before(c.ReplayUntil) {
		return ErrSSOLogoutRejected
	}
	var configured int
	if err = tx.QueryRow(`SELECT count(*) FROM server_settings WHERE key='sso_issuer_url' AND value=? AND EXISTS(SELECT 1 FROM server_settings WHERE key='sso_client_id' AND value=?)`, c.Issuer, clientID).Scan(&configured); err != nil {
		return err
	}
	if configured != 1 {
		return ErrSSOLogoutRejected
	}
	// A nonce-bound callback cannot commit beyond SSOLoginLifetime. Retain fences
	// for that entire window even when the logout token itself expires sooner.
	retain := now.Add(SSOLoginLifetime)
	if c.ReplayUntil.After(retain) {
		retain = c.ReplayUntil
	}
	if _, err = tx.Exec(`DELETE FROM sso_logout_events WHERE retain_until<?`, now.Unix()); err != nil {
		return err
	}
	result, err := tx.Exec(`INSERT INTO sso_logout_events(issuer,client_id,jti,subject,sid,issued_at,retain_until) VALUES(?,?,?,?,?,?,?) ON CONFLICT(issuer,client_id,jti) DO NOTHING`, c.Issuer, clientID, c.JWTID, c.Subject, c.SessionID, c.IssuedAt.Unix(), retain.Unix()+1)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrSSOLogoutRejected
	}
	_, err = tx.Exec(`UPDATE sessions SET revoked_at=? WHERE revoked_at='' AND sso_issuer=? AND sso_client_id=?
 AND ((?<>'' AND sso_sid=? AND (?='' OR sso_subject=?)) OR (?='' AND sso_subject=? AND sso_issued_at<=?))`, now.Format(time.RFC3339), c.Issuer, clientID, c.SessionID, c.SessionID, c.Subject, c.Subject, c.SessionID, c.Subject, c.IssuedAt.Unix())
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE devices SET revoked_at=? WHERE revoked_at='' AND sso_session_id<>'' AND EXISTS(SELECT 1 FROM sessions WHERE sessions.id=devices.sso_session_id AND sessions.user_id=devices.user_id AND sessions.revoked_at<>'')`, now.Format(time.RFC3339)); err != nil {
		return err
	}
	if err = storage.RecordAuditOutcomeTx(tx, "", "auth.sso_logout", "", "", "success", "", requestID); err != nil {
		return err
	}
	return tx.Commit()
}
