package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
)

var dummyMu sync.Mutex
var dummyHash string
var loginLockout = auth.NewLockout(3, 15*time.Minute, 50000)
var recoveryLockout = auth.NewLockout(3, 60*time.Minute, 50000)
var hashDummySecret = auth.HashAuthSecret

func authBusy(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Retry-After", "60")
	WriteError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable", message)
}

func dummyVerifier() (string, error) {
	dummyMu.Lock()
	defer dummyMu.Unlock()
	if dummyHash != "" {
		return dummyHash, nil
	}
	h, err := hashDummySecret(strings.Repeat("0", 64))
	if err != nil {
		return "", err
	}
	dummyHash = h
	return dummyHash, nil
}

func AuthRoutes(mux *http.ServeMux, db *sql.DB, cfg config.Config) {
	mux.HandleFunc("GET /api/v1/theme", func(w http.ResponseWriter, r *http.Request) {
		var theme string
		if db.QueryRow(`SELECT value FROM server_settings WHERE key='default_theme'`).Scan(&theme) != nil {
			theme = "Patina Ky"
		}
		writeJSON(w, map[string]string{"defaultTheme": theme})
	})
	mux.HandleFunc("GET /api/theme", func(w http.ResponseWriter, r *http.Request) {
		var theme string
		if db.QueryRow(`SELECT value FROM server_settings WHERE key='default_theme'`).Scan(&theme) != nil {
			theme = "Patina Ky"
		}
		writeJSON(w, map[string]string{"defaultTheme": theme})
	})

	handleSetupCheck := func(w http.ResponseWriter, r *http.Request) {
		var count int
		_ = db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
		writeJSON(w, map[string]any{"setupRequired": count == 0})
	}
	mux.HandleFunc("GET /api/v1/setup", handleSetupCheck)
	mux.HandleFunc("GET /api/setup", handleSetupCheck)

	handleSetupInit := func(w http.ResponseWriter, r *http.Request) {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil || count > 0 {
			WriteError(w, r, http.StatusForbidden, "setup_completed", "setup has already been completed")
			return
		}

		var in struct {
			Username   string `json:"username"`
			Password   string `json:"password"`
			AuthSecret string `json:"authSecret"`
			LoginSalt  string `json:"loginSalt"`
			Iterations int    `json:"iterations"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}

		username := strings.TrimSpace(in.Username)
		if username == "" {
			username = "admin"
		}

		salt := in.LoginSalt
		if salt == "" {
			salt = auth.SyntheticLoginSalt(cfg.Secrets.ServerSaltKey, username)
		}
		iterations := in.Iterations
		if iterations < 100000 || iterations > 1000000 {
			iterations = 600000
		}

		authSecret := in.AuthSecret
		if authSecret == "" && in.Password != "" {
			var err error
			authSecret, err = auth.DeriveAuthSecret(in.Password, salt, iterations)
			if err != nil {
				WriteError(w, r, 500, "internal", "failed to derive auth secret")
				return
			}
		}
		if len(authSecret) != 64 {
			WriteError(w, r, 400, "invalid_request", "authSecret or password required")
			return
		}

		hash, err := auth.HashAuthSecret(authSecret)
		if err != nil {
			WriteError(w, r, 500, "internal", "failed to hash auth secret")
			return
		}

		id, err := ids.Mint("usr")
		if err != nil {
			WriteError(w, r, 500, "internal", "failed to mint user id")
			return
		}

		now := time.Now().UTC().Format(time.RFC3339)
		_, err = db.Exec(`INSERT INTO users(id, username, auth_secret_hash, login_salt, login_iterations, role, status, created_at, updated_at) VALUES(?, ?, ?, ?, ?, 'admin', 'active', ?, ?)`,
			id, strings.ToLower(username), hash, salt, iterations, now, now)
		if err != nil {
			WriteError(w, r, 500, "internal", "failed to create initial admin: "+err.Error())
			return
		}

		s, err := auth.MintSession(db, w, id, cfg.Server.DevInsecureCookies, time.Now().UTC())
		if err != nil {
			WriteError(w, r, 500, "internal", "failed to create session")
			return
		}

		recordAudit(db, id, "setup.initialized", "", "", r.Header.Get("X-Request-Id"))
		writeJSON(w, map[string]any{
			"ok":            true,
			"user":          map[string]string{"id": id, "role": "admin", "username": username},
			"expiresAt":     s.ExpiresAt.UTC().Format(time.RFC3339),
			"hardExpiresAt": s.HardExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	mux.HandleFunc("POST /api/v1/setup", handleSetupInit)
	mux.HandleFunc("POST /api/setup", handleSetupInit)

	handleLoginParams := func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Username string `json:"username"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || strings.TrimSpace(in.Username) == "" {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var salt string
		var iterations int
		if err := db.QueryRow(`SELECT login_salt,login_iterations FROM users WHERE username=?`, strings.ToLower(in.Username)).Scan(&salt, &iterations); err != nil {
			salt = auth.SyntheticLoginSalt(cfg.Secrets.ServerSaltKey, in.Username)
			iterations = 600000
		}
		writeJSON(w, map[string]any{"loginSalt": salt, "iterations": iterations})
	}
	mux.HandleFunc("POST /api/v1/auth/login-params", handleLoginParams)
	mux.HandleFunc("POST /api/auth/login-params", handleLoginParams)

	handleLogin := func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Username   string `json:"username"`
			AuthSecret string `json:"authSecret"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Username == "" || len(in.AuthSecret) != 64 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		key := strings.ToLower(in.Username) + "\x00" + clientIP(r)
		if !recoveryLockout.Try(key, time.Now().UTC()) {
			WriteError(w, r, 429, "rate_limited", "login temporarily unavailable")
			return
		}
		var id, stored, status, role string
		err := db.QueryRow(`SELECT id,auth_secret_hash,status,role FROM users WHERE username=?`, strings.ToLower(in.Username)).Scan(&id, &stored, &status, &role)
		if err != nil {
			stored, err = dummyVerifier()
			if err != nil {
				auth.DummyVerify()
				if errors.Is(err, auth.ErrBusy) {
					authBusy(w, r, "login temporarily unavailable")
					return
				}
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
		}
		verifyErr := auth.VerifyAuthSecret(in.AuthSecret, stored)
		if errors.Is(verifyErr, auth.ErrBusy) {
			authBusy(w, r, "login temporarily unavailable")
			return
		}
		if err != nil || verifyErr != nil || status != "active" {
			recoveryLockout.Fail(key, time.Now().UTC())
			WriteError(w, r, 401, "unauthenticated", "invalid credentials")
			return
		}
		recoveryLockout.Success(key)
		s, err := auth.MintSession(db, w, id, cfg.Server.DevInsecureCookies, time.Now().UTC())
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		recordAudit(db, id, "auth.login", "", "", r.Header.Get("X-Request-Id"))
		writeJSON(w, map[string]any{"user": map[string]string{"id": id, "role": role}, "expiresAt": s.ExpiresAt.UTC().Format(time.RFC3339), "hardExpiresAt": s.HardExpiresAt.UTC().Format(time.RFC3339)})
	}
	mux.HandleFunc("POST /api/v1/auth/login", handleLogin)
	mux.HandleFunc("POST /api/auth/login", handleLogin)

	handleSession := auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		var username string
		_ = db.QueryRow(`SELECT username FROM users WHERE id=?`, s.UserID).Scan(&username)
		role, err := auth.SessionRole(db, s)
		if err != nil {
			WriteError(w, r, 401, "unauthenticated", "session no longer active")
			return
		}

		writeJSON(w, map[string]any{"sso": s.SSOIssuer != "", "user": map[string]string{"id": s.UserID, "role": role, "username": username}, "expiresAt": s.ExpiresAt.UTC().Format(time.RFC3339), "hardExpiresAt": s.HardExpiresAt.UTC().Format(time.RFC3339)})
	}))
	mux.Handle("GET /api/v1/auth/session", handleSession)
	mux.Handle("GET /api/auth/session", handleSession)

	handleLogout := auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		if err := auth.RevokeSession(db, s.ID); err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		secure := !cfg.Server.DevInsecureCookies
		clearCookie(w, "kynotes_session", true, secure)
		clearCookie(w, "csrf_token", false, secure)
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.Handle("POST /api/v1/auth/logout", handleLogout)
	mux.Handle("POST /api/auth/logout", handleLogout)
	mux.Handle("POST /api/v1/auth/password", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var in struct {
			CurrentAuthSecret, NewAuthSecret, NewLoginSalt string
			Iterations                                     int `json:"iterations"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || len(in.CurrentAuthSecret) != 64 || len(in.NewAuthSecret) != 64 || in.NewLoginSalt == "" || in.Iterations < 100000 || in.Iterations > 1000000 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var stored string
		err := db.QueryRow(`SELECT auth_secret_hash FROM users WHERE id=? AND status='active'`, s.UserID).Scan(&stored)
		verifyErr := auth.VerifyAuthSecret(in.CurrentAuthSecret, stored)
		if errors.Is(verifyErr, auth.ErrBusy) {
			authBusy(w, r, "password change temporarily unavailable")
			return
		}
		if err != nil || verifyErr != nil {
			WriteError(w, r, 401, "unauthenticated", "current password is incorrect")
			return
		}
		hash, err := auth.HashAuthSecret(in.NewAuthSecret)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		if _, err = db.Exec(`UPDATE users SET auth_secret_hash=?,login_salt=?,login_iterations=?,updated_at=? WHERE id=?`, hash, in.NewLoginSalt, in.Iterations, time.Now().UTC().Format(time.RFC3339), s.UserID); err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		recordAudit(db, s.UserID, "account.password_change", "", "", r.Header.Get("X-Request-Id"))
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("POST /api/v1/auth/logout-all", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		if time.Since(s.CreatedAt) >= 5*time.Minute {
			WriteError(w, r, 403, "forbidden", "re-authentication required")
			return
		}
		if _, e := db.Exec(`UPDATE sessions SET revoked_at=? WHERE user_id=?`, time.Now().UTC().Format(time.RFC3339), s.UserID); e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	// Step-up re-proves the login secret for this session. The browser derives
	// it from the typed password exactly as at login; the server never sees
	// the password.
	mux.Handle("POST /api/v1/auth/step-up", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		var in struct {
			AuthSecret string `json:"authSecret"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || len(in.AuthSecret) != 64 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		s, _ := auth.SessionFromContext(r)
		key := s.UserID + "\x00" + clientIP(r)
		if !loginLockout.Try(key, time.Now().UTC()) {
			recordAuditOutcome(db, s.UserID, "auth.step_up", "", "", "failure", "rate_limited", r.Header.Get("X-Request-Id"))
			WriteError(w, r, 429, "rate_limited", "try again later")
			return
		}
		var stored string
		err := db.QueryRow(`SELECT auth_secret_hash FROM users WHERE id=?`, s.UserID).Scan(&stored)
		verifyErr := auth.VerifyAuthSecret(in.AuthSecret, stored)
		if errors.Is(verifyErr, auth.ErrBusy) {
			authBusy(w, r, "step-up temporarily unavailable")
			return
		}
		if err != nil || verifyErr != nil {
			loginLockout.Fail(key, time.Now().UTC())
			recordAuditOutcome(db, s.UserID, "auth.step_up", "", "", "failure", "invalid_secret", r.Header.Get("X-Request-Id"))
			WriteError(w, r, 401, "unauthenticated", "invalid credentials")
			return
		}
		loginLockout.Success(key)
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := db.Exec(`UPDATE sessions SET stepup_at=? WHERE id=?`, now, s.ID); err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		recordAudit(db, s.UserID, "auth.step_up", "", "", r.Header.Get("X-Request-Id"))
		w.WriteHeader(http.StatusNoContent)
	})))

	mux.HandleFunc("POST /api/v1/auth/recover", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Username, RecoveryCode, NewAuthSecret, NewLoginSalt string
			Iterations                                          int `json:"iterations"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Username == "" || len(in.NewAuthSecret) != 64 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if _, e := auth.DeriveAuthSecret("", in.NewLoginSalt, in.Iterations); errors.Is(e, auth.ErrBusy) {
			authBusy(w, r, "recovery temporarily unavailable")
			return
		} else if e != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		key := strings.ToLower(in.Username) + "\x00" + clientIP(r)
		if !loginLockout.Try(key, time.Now().UTC()) {
			WriteError(w, r, 429, "rate_limited", "recovery temporarily unavailable")
			return
		}
		var uid, stored, usedAt string
		e := db.QueryRow(`SELECT id,recovery_hash,recovery_used_at FROM users WHERE username=?`, strings.ToLower(in.Username)).Scan(&uid, &stored, &usedAt)
		if e != nil || usedAt != "" || stored == "" {
			auth.DummyVerify()
			loginLockout.Fail(key, time.Now().UTC())
			WriteError(w, r, 401, "unauthenticated", "invalid recovery credentials")
			return
		}
		if e := auth.VerifyRecoveryCode(in.RecoveryCode, stored); errors.Is(e, auth.ErrBusy) {
			authBusy(w, r, "recovery temporarily unavailable")
			return
		} else if e != nil {
			loginLockout.Fail(key, time.Now().UTC())
			WriteError(w, r, 401, "unauthenticated", "invalid recovery credentials")
			return
		}
		newHash, e := auth.HashAuthSecret(in.NewAuthSecret)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		// The used code is replaced by a fresh one the server mints; it is
		// returned once in the response and never stored in the clear.
		nextCode, recoveryHash, e := auth.NewRecoveryCode()
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		auditID, _ := ids.Mint("aud")
		e = dbTx(db, func(tx *sql.Tx) error {
			if _, e := tx.Exec(`UPDATE users SET auth_secret_hash=?,login_salt=?,login_iterations=?,recovery_hash=?,recovery_used_at='',updated_at=? WHERE id=?`, newHash, in.NewLoginSalt, in.Iterations, recoveryHash, now, uid); e != nil {
				return e
			}
			if _, e := tx.Exec(`UPDATE sessions SET revoked_at=? WHERE user_id=?`, now, uid); e != nil {
				return e
			}
			if _, e := tx.Exec(`UPDATE devices SET revoked_at=? WHERE user_id=?`, now, uid); e != nil {
				return e
			}
			_, e = tx.Exec(`DELETE FROM key_envelopes WHERE device_id IN (SELECT id FROM devices WHERE user_id=?)`, uid)
			if e != nil {
				return e
			}
			_, e = tx.Exec(`INSERT INTO audit_events(id,user_id,event,container_id,object_id,created_at,at,outcome,actor_user_id,request_id,reason_code) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, auditID, uid, "account.recovery", "", "", now, now, "success", uid, r.Header.Get("X-Request-Id"), "")
			return e
		})
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		loginLockout.Success(key)
		writeJSON(w, map[string]string{"recoveryCode": nextCode})
	})
}

func clientIP(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return normalizeClientIP(ip)
	}
	return host
}

func normalizeClientIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	ip = ip.To16()
	for i := 8; i < len(ip); i++ {
		ip[i] = 0
	}
	return ip.String()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func clearCookie(w http.ResponseWriter, name string, httpOnly, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: httpOnly, Secure: secure, SameSite: http.SameSiteLaxMode})
}
