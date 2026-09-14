package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/Busness-app/kynotes-server/internal/ids"
)

const sessionCookie = "kynotes_session"
const csrfCookie = "csrf_token"

type Session struct {
	ID, UserID, CSRF                    string
	CreatedAt, ExpiresAt, HardExpiresAt time.Time
	StepUpAt                            time.Time // zero until the login secret was re-proven
}

type sessionCredentials struct {
	session   Session
	token     string
	tokenHash string
	csrfHash  string
}

func prepareSession(userID string, now time.Time) (sessionCredentials, error) {
	id, err := ids.Mint("ses")
	if err != nil {
		return sessionCredentials{}, err
	}
	token := make([]byte, 32)
	csrf := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		return sessionCredentials{}, err
	}
	if _, err = rand.Read(csrf); err != nil {
		return sessionCredentials{}, err
	}
	hash := sha256.Sum256(token)
	csrfHash := sha256.Sum256(csrf)
	s := Session{ID: id, UserID: userID, CSRF: base64.RawURLEncoding.EncodeToString(csrf), CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour), HardExpiresAt: now.Add(7 * 24 * time.Hour)}
	return sessionCredentials{session: s, token: base64.RawURLEncoding.EncodeToString(token), tokenHash: hex.EncodeToString(hash[:]), csrfHash: hex.EncodeToString(csrfHash[:])}, nil
}

func (c sessionCredentials) setCookies(w http.ResponseWriter, insecure bool) {
	secure := !insecure
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: c.token, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 7 * 24 * 60 * 60})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: c.session.CSRF, Path: "/", HttpOnly: false, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 7 * 24 * 60 * 60})
}

func MintSession(db *sql.DB, w http.ResponseWriter, userID string, insecure bool, now time.Time) (Session, error) {
	c, err := prepareSession(userID, now)
	if err != nil {
		return Session{}, err
	}
	s := c.session
	result, err := db.Exec(`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) SELECT ?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM users WHERE id=? AND status='active')`, s.ID, userID, c.tokenHash, c.csrfHash, s.CreatedAt.UTC().Format(time.RFC3339), s.ExpiresAt.UTC().Format(time.RFC3339), s.HardExpiresAt.UTC().Format(time.RFC3339), userID)
	if err != nil {
		return Session{}, err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return Session{}, errors.New("account is not active")
	}
	c.setCookies(w, insecure)
	return s, nil
}

func ResolveSession(db *sql.DB, r *http.Request, now time.Time) (Session, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return Session{}, errors.New("unauthenticated")
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != 32 {
		return Session{}, errors.New("unauthenticated")
	}
	h := sha256.Sum256(raw)
	var s Session
	var created, expires, hard, revoked, status, stepup string
	err = db.QueryRow(`SELECT s.id,s.user_id,s.created_at,s.expires_at,s.hard_expires_at,s.revoked_at,s.stepup_at,u.status FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, hex.EncodeToString(h[:])).Scan(&s.ID, &s.UserID, &created, &expires, &hard, &revoked, &stepup, &status)
	if err != nil || revoked != "" || status != "active" {
		return Session{}, errors.New("unauthenticated")
	}
	s.CreatedAt, _ = time.Parse(time.RFC3339, created)
	s.ExpiresAt, _ = time.Parse(time.RFC3339, expires)
	s.HardExpiresAt, _ = time.Parse(time.RFC3339, hard)
	if stepup != "" {
		s.StepUpAt, _ = time.Parse(time.RFC3339, stepup)
	}
	if now.After(s.ExpiresAt) || now.After(s.HardExpiresAt) {
		return Session{}, errors.New("unauthenticated")
	}
	newExpiry := now.Add(24 * time.Hour)
	if newExpiry.After(s.HardExpiresAt) {
		newExpiry = s.HardExpiresAt
	}
	if newExpiry.Sub(s.ExpiresAt) >= 5*time.Minute {
		if _, e := db.Exec(`UPDATE sessions SET expires_at=? WHERE id=?`, newExpiry.UTC().Format(time.RFC3339), s.ID); e == nil {
			s.ExpiresAt = newExpiry
		}
	}
	return s, nil
}

func RevokeSession(db *sql.DB, id string) error {
	_, err := db.Exec(`UPDATE sessions SET revoked_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), id)
	return err
}
