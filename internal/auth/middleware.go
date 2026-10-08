package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"
)

type sessionKey struct{}
type deviceKey struct{}
type Device struct{ ID, UserID string }

var deviceLockout = NewLockout(10, 15*time.Minute, 50000)

func RequireSession(db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := ResolveSession(db, r, time.Now().UTC())
		if err != nil {
			unauthenticated(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, s)))
	})
}

func RequireFresh(db *sql.DB, next http.Handler) http.Handler {
	return RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := SessionFromContext(r)
		if time.Since(s.CreatedAt) >= 5*time.Minute {
			WriteAuthError(w, "forbidden", "re-authentication required")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func RequireAdmin(db *sql.DB, next http.Handler) http.Handler {
	return RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := SessionFromContext(r)
		role, err := SessionRole(db, s)
		if err != nil || role != "admin" {
			WriteAuthError(w, "forbidden", "administrator access required")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// SessionRole applies the verified OIDC role ceiling to every SSO admin request.
// A local role edit or another login cannot turn a user-scoped SSO token into admin.
func SessionRole(db *sql.DB, s Session) (string, error) {
	var role string
	err := db.QueryRow(`SELECT CASE WHEN u.role='admin' AND (s.sso_issuer='' OR s.sso_app_admin=1) THEN 'admin' ELSE 'user' END
 FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.id=? AND u.id=? AND s.revoked_at='' AND u.status='active'`, s.ID, s.UserID).Scan(&role)
	return role, err
}

// StepUpWindow is how long a re-proof of the login secret grants access to
// destructive admin routes.
const StepUpWindow = 10 * time.Minute

// RequireStepUp is RequireAdmin plus a recent re-proof of the login secret.
// One-way doors (pairing, key pinning, exporting recovery material) sit behind
// it, so a stolen admin cookie alone cannot open them.
func RequireStepUp(db *sql.DB, next http.Handler) http.Handler {
	return RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := SessionFromContext(r)
		if s.SSOIssuer != "" {
			requireSSOStepUp(db, s, stepUpAdmin, next, w, r)
			return
		}
		if !freshLocalProof(s) {
			WriteAuthError(w, "step_up_required", "re-enter your password to continue")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func freshLocalProof(s Session) bool {
	return !s.StepUpAt.IsZero() && time.Since(s.StepUpAt) <= StepUpWindow
}

// RequireUserStepUp gates one-way doors on the caller's own account: any local
// session that re-proved its login secret within StepUpWindow. SSO sessions are
// refused; their step-up proves the IdP, not the password these routes rely on.
func RequireUserStepUp(db *sql.DB, next http.Handler) http.Handler {
	return RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := SessionFromContext(r)
		if !HasUserStepUp(s) {
			WriteAuthError(w, "step_up_required", "re-enter your password to continue")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// HasUserStepUp is the RequireUserStepUp test, for routes that need it only for
// some request bodies.
func HasUserStepUp(s Session) bool {
	return s.SSOIssuer == "" && freshLocalProof(s)
}

// RequireUserActionStepUp gates one-way doors on the caller's own account for every kind of
// session: a local session re-proves its password within StepUpWindow; an SSO session confirms this
// exact request with a fresh KySignOn proof (user scope: no administrator role involved).
func RequireUserActionStepUp(db *sql.DB, next http.Handler) http.Handler {
	return RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := SessionFromContext(r)
		if s.SSOIssuer != "" {
			requireSSOStepUp(db, s, stepUpUser, next, w, r)
			return
		}
		if !freshLocalProof(s) {
			WriteAuthError(w, "step_up_required", "re-enter your password to continue")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// RecheckUserActionTx repeats, inside the write transaction, what RequireUserActionStepUp admitted.
// An SSO grant was consumed in its own transaction just before; the session must still be live.
func RecheckUserActionTx(tx *sql.Tx, s Session, now time.Time) error {
	if s.SSOIssuer == "" {
		return RecheckUserStepUpTx(tx, s, now)
	}
	_, _, err := liveSessionTx(tx, s, now)
	return err
}

func SessionFromContext(r *http.Request) (Session, bool) {
	s, ok := r.Context().Value(sessionKey{}).(Session)
	return s, ok
}
func RequireDevice(db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d, ok := resolveDevice(db, r); !ok {
			unauthenticated(w)
			return
		} else {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), deviceKey{}, d)))
		}
	})
}

func RequireEither(db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Kynotes-Device-Id") != "" || r.Header.Get("X-Kynotes-Device-Secret") != "" {
			if d, ok := resolveDevice(db, r); ok {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), deviceKey{}, d)))
				return
			}
		}
		if s, e := ResolveSession(db, r, time.Now().UTC()); e == nil {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, s)))
			return
		}
		unauthenticated(w)
	})
}
func unauthenticated(w http.ResponseWriter) {
	WriteAuthError(w, "unauthenticated", "authentication required")
}

func WriteAuthError(w http.ResponseWriter, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	status := http.StatusUnauthorized
	switch code {
	case "forbidden", "step_up_required":
		status = http.StatusForbidden
	case "step_up_pending":
		status = http.StatusConflict
	case "rate_limited":
		status = http.StatusTooManyRequests
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message, "requestId": w.Header().Get("X-Request-Id")}})
}
func resolveDevice(db *sql.DB, r *http.Request) (Device, bool) {
	id := r.Header.Get("X-Kynotes-Device-Id")
	secret := r.Header.Get("X-Kynotes-Device-Secret")
	if len(id) == 0 || len(id) > 128 || len(secret) > 512 {
		return Device{}, false
	}
	var d Device
	var stored, status, revoked string
	now := time.Now().UTC()
	if e := db.QueryRow(`SELECT d.id,d.user_id,d.secret_hash,u.status,d.revoked_at FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=? AND d.platform<>'identity' AND (d.sso_session_id='' OR EXISTS(SELECT 1 FROM sessions s WHERE s.id=d.sso_session_id AND s.user_id=d.user_id AND s.revoked_at='' AND s.expires_at>? AND s.hard_expires_at>?))`, id, now.Format(time.RFC3339), now.Format(time.RFC3339)).Scan(&d.ID, &d.UserID, &stored, &status, &revoked); e != nil || status != "active" || revoked != "" {
		return Device{}, false
	}
	key := id + "\x00" + clientIP(r)
	if !deviceLockout.Try(key, now) {
		return Device{}, false
	}
	sum := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare([]byte("sha256:"+hex.EncodeToString(sum[:])), []byte(stored)) != 1 {
		deviceLockout.Fail(key, now)
		return Device{}, false
	}
	deviceLockout.Success(key)
	_, _ = db.Exec(`UPDATE devices SET last_seen_at=? WHERE id=?`, now.Format(time.RFC3339), d.ID)
	return d, true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	ip = ip.To16()
	for i := 8; i < len(ip); i++ {
		ip[i] = 0
	}
	return ip.String()
}
func CredentialUserID(r *http.Request) (string, bool) {
	if d, ok := DeviceFromContext(r); ok {
		return d.UserID, true
	}
	if s, ok := SessionFromContext(r); ok {
		return s.UserID, true
	}
	return "", false
}
func DeviceFromContext(r *http.Request) (Device, bool) {
	d, ok := r.Context().Value(deviceKey{}).(Device)
	return d, ok
}
func CheckCSRF(r *http.Request) error {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return nil
	}
	if _, err := r.Cookie(sessionCookie); err != nil {
		return nil
	}
	csrf, err := r.Cookie(csrfCookie)
	if err != nil {
		return errors.New("csrf")
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrf.Value)) != 1 {
		return errors.New("csrf")
	}
	return nil
}

var (
	ErrSessionInvalid = errors.New("session no longer valid")
	ErrStepUpInvalid  = errors.New("step-up no longer valid")
	// ErrPasswordAdminKnown: an administrator set the password, so proving it proves nothing about the user.
	ErrPasswordAdminKnown = errors.New("password known to an administrator")
)

// RecheckSessionTx repeats the session check inside the writing transaction: a
// revocation or password change can commit between the middleware and the write.
// It returns the user's current password verifier for the caller to compare.
func RecheckSessionTx(tx *sql.Tx, s Session, now time.Time) (passwordHash string, err error) {
	_, passwordHash, err = liveSessionTx(tx, s, now)
	return passwordHash, err
}

// RecheckUserStepUpTx re-proves, inside the writing transaction, what
// RequireUserStepUp authorized: the session is live, its step-up is the one the
// middleware read and still in window, the password it proved is current, and nobody else knows it.
func RecheckUserStepUpTx(tx *sql.Tx, s Session, now time.Time) error {
	stepUp, passwordHash, err := liveSessionTx(tx, s, now)
	if err != nil {
		return err
	}
	if s.passwordHash == "" || passwordHash != s.passwordHash || stepUp != s.stepUpRaw || s.StepUpAt.IsZero() || now.Sub(s.StepUpAt) > StepUpWindow {
		return ErrStepUpInvalid
	}
	var adminKnown int
	if err := tx.QueryRow(`SELECT password_admin_known FROM users WHERE id=?`, s.UserID).Scan(&adminKnown); err != nil {
		return err
	}
	if adminKnown != 0 {
		return ErrPasswordAdminKnown
	}
	return nil
}

func liveSessionTx(tx *sql.Tx, s Session, now time.Time) (stepUp, passwordHash string, err error) {
	var expires, hard string
	err = tx.QueryRow(`SELECT s.stepup_at,s.expires_at,s.hard_expires_at,u.auth_secret_hash FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.user_id=? AND s.revoked_at='' AND u.status='active'`, s.ID, s.UserID).Scan(&stepUp, &expires, &hard, &passwordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrSessionInvalid
	}
	if err != nil {
		return "", "", err
	}
	e, err1 := time.Parse(time.RFC3339, expires)
	h, err2 := time.Parse(time.RFC3339, hard)
	if err1 != nil || err2 != nil || now.After(e) || now.After(h) {
		return "", "", ErrSessionInvalid
	}
	return stepUp, passwordHash, nil
}
