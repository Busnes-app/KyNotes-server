package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/reqid"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

const (
	stepUpAdmin = "admin" // RequireStepUp: the session's verified kynotes.admin ceiling and local admin role
	stepUpUser  = "user"  // RequireUserActionStepUp: the session's own account
)

type challengeLimitKey struct{}

// WithChallengeLimit lets the HTTP rate limiter bound how fast one account mints step-up
// challenges (each writes a row and an audit event). allow reports whether userID may mint one.
func WithChallengeLimit(ctx context.Context, allow func(userID string) bool) context.Context {
	return context.WithValue(ctx, challengeLimitKey{}, allow)
}

// The digest binds the exact attempted operation without storing its potentially secret body.
func stepUpAction(w http.ResponseWriter, r *http.Request) (string, error) {
	// ponytail: one confirmation binds ≤64 KiB; upgrade: batch putEnvelopes, one confirmation each.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	h := sha256.New()
	h.Write([]byte(r.Method + "\x00" + r.URL.RequestURI() + "\x00" + r.Header.Get("Content-Type") + "\x00"))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func requireSSOStepUp(db *sql.DB, s Session, scope string, next http.Handler, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if CheckCSRF(r) != nil {
		WriteAuthError(w, "forbidden", "CSRF validation failed")
		return
	}
	action, err := stepUpAction(w, r)
	if err != nil {
		WriteAuthError(w, "payload_too_large", "this change is too large to confirm with KySignOn at once")
		return
	}
	grant := r.Header.Get("X-Kynotes-Step-Up")
	if grant != "" {
		if err = consumeSSOStepUp(r.Context(), db, s, grant, action, scope, reqid.FromContext(r.Context())); err != nil {
			if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrSSOLoginRejected) {
				WriteAuthError(w, "forbidden", "reauthentication grant is expired, revoked or does not match this action")
			} else {
				http.Error(w, "reauthentication unavailable", 500)
			}
			return
		}
		next.ServeHTTP(w, r)
		return
	}
	tx, err := db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "reauthentication unavailable", 500)
		return
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	// A confirmation the user has opened in KySignOn (started or verified) is never replaced: a
	// background write must not cancel it. The refusal names it so another tab can cancel it, and is
	// checked before the rate limit so refused background writes spend none of the account's budget.
	var pending string
	err = tx.QueryRow(`SELECT id FROM sso_stepup WHERE session_id=? AND started=1 AND expires_at>?`, s.ID, now.Unix()).Scan(&pending)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(409)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "step_up_pending", "message": "finish or cancel the open KySignOn confirmation first", "challenge": pending}})
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "reauthentication unavailable", 500)
		return
	}
	if allow, ok := r.Context().Value(challengeLimitKey{}).(func(string) bool); ok && !allow(s.UserID) {
		WriteAuthError(w, "rate_limited", "rate limit exceeded")
		return
	}
	id, err := ids.Mint("rea")
	if err == nil {
		_, err = tx.Exec(`DELETE FROM sso_stepup WHERE session_id=? OR expires_at<=?`, s.ID, now.Unix())
	}
	if err == nil {
		_, err = tx.Exec(`INSERT INTO sso_stepup(id,session_id,action,scope,created_at,expires_at) VALUES(?,?,?,?,?,?)`, id, s.ID, action, scope, now.Unix(), now.Add(SSOLoginLifetime).Unix())
	}
	if err == nil {
		err = storage.RecordAuditOutcomeTx(tx, s.UserID, "auth.sso_step_up.start", "", id, "success", r.Method+" "+r.URL.Path, reqid.FromContext(r.Context()))
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		http.Error(w, "reauthentication unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "sso_step_up_required", "message": "Confirm this action with KySignOn", "challenge": id}})
}

// BeginSSOStepUp claims a challenge once. Cancellation deletes it; callback cannot recreate it.
func BeginSSOStepUp(ctx context.Context, db *sql.DB, s Session, id string) (time.Time, error) {
	var created int64
	err := db.QueryRowContext(ctx, `UPDATE sso_stepup SET started=1 WHERE id=? AND session_id=? AND started=0 AND expires_at>? RETURNING created_at`, id, s.ID, time.Now().Unix()).Scan(&created)
	return time.Unix(created, 0), err
}

func CancelSSOStepUp(ctx context.Context, db *sql.DB, s Session, id, requestID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`DELETE FROM sso_stepup WHERE id=? AND session_id=?`, id, s.ID)
	if err != nil {
		return err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if deleted == 1 {
		err = storage.RecordAuditOutcomeTx(tx, s.UserID, "auth.sso_step_up.cancel", "", id, "success", "", requestID)
	}
	if err == nil {
		err = tx.Commit()
	}
	return err
}

// liveStepUpSession requires the original still-live session, never a replacement login. Admin
// challenges also need the session's verified administrator ceiling and the local admin role.
func liveStepUpSession(tx *sql.Tx, s Session, now time.Time, scope string) error {
	var count int
	err := tx.QueryRow(`SELECT count(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.user_id=? AND s.revoked_at='' AND s.expires_at>? AND s.hard_expires_at>? AND s.sso_issuer=? AND s.sso_client_id=? AND s.sso_subject=? AND u.status='active' AND (?<>'admin' OR (s.sso_app_admin=1 AND u.role='admin'))`, s.ID, s.UserID, now.Format(time.RFC3339), now.Format(time.RFC3339), s.SSOIssuer, s.SSOClientID, s.SSOSubject, scope).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrSSOLoginRejected
	}
	return nil
}

func CompleteSSOStepUp(ctx context.Context, db *sql.DB, s Session, id string, identity SSOIdentity, authTime time.Time, assurance, requestID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if identity.Issuer != s.SSOIssuer || identity.ClientID != s.SSOClientID || identity.Subject != s.SSOSubject || !now.Before(identity.LoginExpires) {
		return ErrSSOLoginRejected
	}
	var scope string
	if err = tx.QueryRow(`SELECT scope FROM sso_stepup WHERE id=? AND session_id=?`, id, s.ID).Scan(&scope); errors.Is(err, sql.ErrNoRows) {
		return ErrSSOLoginRejected
	} else if err != nil {
		return err
	}
	// Admin challenges need the verified kynotes.admin role; user challenges prove only the account.
	if scope == stepUpAdmin && !identity.AppAdmin {
		return ErrSSOLoginRejected
	}
	if err = liveStepUpSession(tx, s, now, scope); err != nil {
		return err
	}
	if err = checkSSOIdentityTx(tx, s.UserID, identity, now); err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE sso_stepup SET verified=1,auth_time=?,proof_sid=?,proof_iat=?,expires_at=min(expires_at,?) WHERE id=? AND session_id=? AND started=1 AND verified=0 AND expires_at>? AND created_at<=?`, authTime.Unix(), identity.SessionID, identity.IssuedAt.Unix(), now.Add(time.Minute).Unix(), id, s.ID, now.Unix(), authTime.Unix())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrSSOLoginRejected
	}
	if err = storage.RecordAuditOutcomeTx(tx, s.UserID, "auth.sso_step_up.verify", "", id, "success", fmt.Sprintf("auth_time=%d,acr=%s,session=%s", authTime.Unix(), assurance, s.ID), requestID); err != nil {
		return err
	}
	return tx.Commit()
}

func consumeSSOStepUp(ctx context.Context, db *sql.DB, s Session, id, action, scope, requestID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	var sid string
	var issued int64
	err = tx.QueryRow(`DELETE FROM sso_stepup WHERE id=? AND session_id=? AND action=? AND scope=? AND verified=1 AND expires_at>? RETURNING proof_sid,proof_iat`, id, s.ID, action, scope, now.Unix()).Scan(&sid, &issued)
	if err != nil {
		return err
	}
	if err = liveStepUpSession(tx, s, now, scope); err != nil {
		return err
	}
	identity := SSOIdentity{Issuer: s.SSOIssuer, ClientID: s.SSOClientID, Subject: s.SSOSubject, SessionID: sid, IssuedAt: time.Unix(issued, 0)}
	if err = checkSSOIdentityTx(tx, s.UserID, identity, now); err != nil {
		return err
	}
	if err = storage.RecordAuditOutcomeTx(tx, s.UserID, "auth.sso_step_up.consume", "", id, "success", "", requestID); err != nil {
		return err
	}
	return tx.Commit()
}
