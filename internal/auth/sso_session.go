package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/Busness-app/kynotes-server/internal/storage"
)

// SSOLoginLifetime bounds a callback even when token exchange outlives its admission.
const SSOLoginLifetime = 5 * time.Minute

var ErrSSOLoginRejected = errors.New("expired or revoked SSO login")

// SSOIdentity is constructed only from an issuer-verified ID token and login transaction.
type SSOIdentity struct {
	Issuer, ClientID, Subject, SessionID string
	IssuedAt, LoginExpires               time.Time
}

// MintSSOSession serializes login with logout and account disablement. Cookies are
// emitted only after the bound session and its audit have committed.
func MintSSOSession(ctx context.Context, db *sql.DB, w http.ResponseWriter, userID string, identity SSOIdentity, insecure bool, requestID string) (Session, error) {
	c, err := prepareSession(userID, time.Now().UTC())
	if err != nil {
		return Session{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if identity.Issuer == "" || identity.ClientID == "" || identity.Subject == "" || identity.IssuedAt.IsZero() || !now.Before(identity.LoginExpires) {
		return Session{}, ErrSSOLoginRejected
	}
	var allowed int
	err = tx.QueryRow(`SELECT count(*) FROM users WHERE id=? AND status='active' AND sso_issuer=? AND sso_subject=?
 AND EXISTS(SELECT 1 FROM server_settings WHERE key='sso_enabled' AND value IN ('true','1'))
 AND EXISTS(SELECT 1 FROM server_settings WHERE key='sso_issuer_url' AND value=?)
 AND EXISTS(SELECT 1 FROM server_settings WHERE key='sso_client_id' AND value=?)
 AND NOT EXISTS(SELECT 1 FROM sso_logout_events WHERE issuer=? AND client_id=? AND retain_until>=?
 AND ((sid<>'' AND sid=? AND (subject='' OR subject=?)) OR (sid='' AND subject=? AND issued_at>=?)))`,
		userID, identity.Issuer, identity.Subject, identity.Issuer, identity.ClientID, identity.Issuer, identity.ClientID, now.Unix(), identity.SessionID, identity.Subject, identity.Subject, identity.IssuedAt.Unix()).Scan(&allowed)
	if err != nil {
		return Session{}, err
	}
	if allowed != 1 {
		return Session{}, ErrSSOLoginRejected
	}
	s := c.session
	_, err = tx.Exec(`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at,sso_issuer,sso_client_id,sso_subject,sso_sid,sso_issued_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, s.ID, userID, c.tokenHash, c.csrfHash, s.CreatedAt.Format(time.RFC3339), s.ExpiresAt.Format(time.RFC3339), s.HardExpiresAt.Format(time.RFC3339), identity.Issuer, identity.ClientID, identity.Subject, identity.SessionID, identity.IssuedAt.Unix())
	if err != nil {
		return Session{}, err
	}
	if err = storage.RecordAuditOutcomeTx(tx, userID, "auth.sso_login", "", "", "success", "", requestID); err != nil {
		return Session{}, err
	}
	if err = tx.Commit(); err != nil {
		return Session{}, err
	}
	c.setCookies(w, insecure)
	return s, nil
}
