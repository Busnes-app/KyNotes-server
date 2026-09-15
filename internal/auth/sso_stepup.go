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

	"github.com/Busness-app/kynotes-server/internal/ids"
	"github.com/Busness-app/kynotes-server/internal/storage"
)

// The digest binds the exact attempted operation without storing its potentially secret body.
func stepUpAction(w http.ResponseWriter, r *http.Request) (string, error) {
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

func requireSSOStepUp(db *sql.DB, s Session, next http.Handler, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if CheckCSRF(r) != nil {
		WriteAuthError(w, "forbidden", "CSRF validation failed")
		return
	}
	action, err := stepUpAction(w, r)
	if err != nil {
		http.Error(w, "action body too large", 413)
		return
	}
	grant := r.Header.Get("X-Kynotes-Step-Up")
	if grant != "" {
		if err = consumeSSOStepUp(r.Context(), db, s, grant, action, r.Header.Get("X-Request-Id")); err != nil {
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
	id, err := ids.Mint("rea")
	if err != nil {
		http.Error(w, "reauthentication unavailable", 500)
		return
	}
	tx, err := db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "reauthentication unavailable", 500)
		return
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	_, err = tx.Exec(`DELETE FROM sso_stepup WHERE session_id=? OR expires_at<=?`, s.ID, now.Unix())
	if err == nil {
		_, err = tx.Exec(`INSERT INTO sso_stepup(id,session_id,action,created_at,expires_at) VALUES(?,?,?,?,?)`, id, s.ID, action, now.Unix(), now.Add(SSOLoginLifetime).Unix())
	}
	if err == nil {
		err = storage.RecordAuditOutcomeTx(tx, s.UserID, "auth.sso_step_up.start", "", id, "success", r.Method+" "+r.URL.Path, r.Header.Get("X-Request-Id"))
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
	_, err = tx.Exec(`DELETE FROM sso_stepup WHERE id=? AND session_id=?`, id, s.ID)
	if err == nil {
		err = storage.RecordAuditOutcomeTx(tx, s.UserID, "auth.sso_step_up.cancel", "", id, "success", "", requestID)
	}
	if err == nil {
		err = tx.Commit()
	}
	return err
}

// liveStepUpSession requires the original still-live admin session, never a replacement login.
func liveStepUpSession(tx *sql.Tx, s Session, now time.Time) error {
	var count int
	err := tx.QueryRow(`SELECT count(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.user_id=? AND s.revoked_at='' AND s.expires_at>? AND s.hard_expires_at>? AND s.sso_issuer=? AND s.sso_client_id=? AND s.sso_subject=? AND s.sso_app_admin=1 AND u.status='active' AND u.role='admin'`, s.ID, s.UserID, now.Format(time.RFC3339), now.Format(time.RFC3339), s.SSOIssuer, s.SSOClientID, s.SSOSubject).Scan(&count)
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
	if identity.Issuer != s.SSOIssuer || identity.ClientID != s.SSOClientID || identity.Subject != s.SSOSubject || !identity.AppAdmin || !now.Before(identity.LoginExpires) {
		return ErrSSOLoginRejected
	}
	if err = liveStepUpSession(tx, s, now); err != nil {
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

func consumeSSOStepUp(ctx context.Context, db *sql.DB, s Session, id, action, requestID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	var sid string
	var issued int64
	err = tx.QueryRow(`DELETE FROM sso_stepup WHERE id=? AND session_id=? AND action=? AND verified=1 AND expires_at>? RETURNING proof_sid,proof_iat`, id, s.ID, action, now.Unix()).Scan(&sid, &issued)
	if err != nil {
		return err
	}
	if err = liveStepUpSession(tx, s, now); err != nil {
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
