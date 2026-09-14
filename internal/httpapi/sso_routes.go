package httpapi

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Busness-app/ky-primitives/syncauth"
	"github.com/Busness-app/kynotes-server/internal/auth"
	"github.com/Busness-app/kynotes-server/internal/config"
	"github.com/Busness-app/kynotes-server/internal/ids"
	"github.com/Busness-app/kynotes-server/internal/sso"
)

const ssoCookieName = "kynotes_sso_state"

type syncSettingsKey struct{}

func isRequestSecure(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func requestHost(r *http.Request) string {
	if host := r.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	return r.Host
}

// SSORoutes registers OIDC SSO and directory sync endpoints.
func SSORoutes(mux *http.ServeMux, db *sql.DB, cfg config.Config, ssoStore *sso.Store) {
	transactions := &ssoTransactions{pending: make(map[string]ssoTransaction)}
	registerSSOLogout(mux, db, ssoStore, cfg)
	handleSSOConfig := func(w http.ResponseWriter, r *http.Request) {
		settings := ssoStore.Load()
		writeJSON(w, map[string]any{
			"enabled":   settings.Enabled,
			"issuerUrl": settings.IssuerURL,
			"clientId":  settings.ClientID,
		})
	}
	mux.HandleFunc("GET /api/v1/auth/sso-config", handleSSOConfig)
	mux.HandleFunc("GET /api/auth/sso-config", handleSSOConfig)

	// Initiates OpenID Connect authorization code flow with PKCE
	handleOIDCFlow := func(w http.ResponseWriter, r *http.Request) {
		settings := ssoStore.Load()
		if !settings.Enabled || settings.IssuerURL == "" {
			WriteError(w, r, http.StatusServiceUnavailable, "sso_disabled", "Single Sign-On is not configured or disabled")
			return
		}

		verifier, challenge, err := sso.GeneratePKCE()
		if err != nil {
			WriteError(w, r, http.StatusInternalServerError, "pkce_failed", "failed to generate PKCE challenge")
			return
		}

		disc, err := sso.DiscoverEndpoints(r.Context(), settings.IssuerURL)
		if err != nil {
			WriteError(w, r, http.StatusBadGateway, "discovery_failed", "failed to discover OIDC endpoints: "+err.Error())
			return
		}

		scheme := "http"
		if isRequestSecure(r) {
			scheme = "https"
		}
		redirectURI := settings.RedirectURI
		if redirectURI == "" {
			redirectURI = fmt.Sprintf("%s://%s%s", scheme, requestHost(r), strings.Replace(r.URL.Path, "/login", "/callback", 1))
		}

		state, nonce := sso.GenerateState(), sso.GenerateState()
		transactions.add(state, ssoTransaction{Verifier: verifier, Nonce: nonce, RedirectURI: redirectURI, Settings: settings, Expires: time.Now().Add(auth.SSOLoginLifetime)})
		http.SetCookie(w, &http.Cookie{Name: ssoCookieName, Value: state, Path: "/", HttpOnly: true, Secure: !cfg.Server.DevInsecureCookies && isRequestSecure(r), SameSite: http.SameSiteLaxMode, MaxAge: 300})

		authURL, err := url.Parse(disc.AuthorizationEndpoint)
		if err != nil {
			WriteError(w, r, http.StatusInternalServerError, "invalid_endpoint", "invalid authorization endpoint")
			return
		}
		q := authURL.Query()
		q.Set("response_type", "code")
		q.Set("client_id", settings.ClientID)
		q.Set("redirect_uri", redirectURI)
		q.Set("scope", "openid profile email")
		q.Set("state", state)
		q.Set("nonce", nonce)
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
		authURL.RawQuery = q.Encode()

		http.Redirect(w, r, authURL.String(), http.StatusFound)
	}
	mux.HandleFunc("GET /api/v1/auth/oidc/login", handleOIDCFlow)
	mux.HandleFunc("GET /api/auth/oidc/login", handleOIDCFlow)
	mux.HandleFunc("GET /auth/oidc/login", handleOIDCFlow)

	// Handles OAuth redirect callback, verifies PKCE, exchanges code for token, mints session
	handleOIDCCallback := func(w http.ResponseWriter, r *http.Request) {
		settings := ssoStore.Load()
		if !settings.Enabled || settings.IssuerURL == "" {
			WriteError(w, r, http.StatusServiceUnavailable, "sso_disabled", "Single Sign-On is not configured or disabled")
			return
		}

		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" || state == "" {
			WriteError(w, r, http.StatusBadRequest, "invalid_request", "missing code or state")
			return
		}

		cookie, err := r.Cookie(ssoCookieName)
		if err != nil || cookie.Value == "" {
			WriteError(w, r, http.StatusBadRequest, "invalid_state", "missing or expired SSO cookie")
			return
		}

		if cookie.Value != state {
			WriteError(w, r, http.StatusBadRequest, "invalid_state", "invalid SSO state")
			return
		}
		transaction, ok := transactions.take(state)
		clearCookie(w, ssoCookieName, true, !cfg.Server.DevInsecureCookies && isRequestSecure(r))
		if !ok || transaction.Settings != settings {
			WriteError(w, r, http.StatusBadRequest, "invalid_state", "expired or changed SSO login")
			return
		}
		codeVerifier := transaction.Verifier

		disc, err := sso.DiscoverEndpoints(r.Context(), settings.IssuerURL)
		if err != nil {
			WriteError(w, r, http.StatusBadGateway, "discovery_failed", "failed to discover OIDC endpoints: "+err.Error())
			return
		}

		redirectURI := transaction.RedirectURI

		tok, err := sso.ExchangeCode(r.Context(), disc.TokenEndpoint, settings.ClientID, settings.ClientSecret, code, redirectURI, codeVerifier)
		if err != nil {
			WriteError(w, r, http.StatusBadGateway, "exchange_failed", "failed to exchange token: "+err.Error())
			return
		}

		claims, err := ssoStore.VerifyClaims(r.Context(), settings, disc, tok.IDToken, transaction.Nonce)
		if err != nil {
			WriteError(w, r, http.StatusBadGateway, "invalid_claims", "ID token verification failed")
			return
		}

		var userID, userStatus, userRole string
		// 1. Try finding user by sso_subject
		err = db.QueryRow(`SELECT id, status, role FROM users WHERE sso_subject=? AND sso_issuer=?`, claims.Subject, settings.IssuerURL).Scan(&userID, &userStatus, &userRole)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			WriteError(w, r, 500, "internal", "account lookup failed")
			return
		}

		// 3. Auto-provision if user does not exist
		if userID == "" {
			var occupied int
			if err := db.QueryRow(`SELECT count(*) FROM users WHERE username=?`, strings.ToLower(claims.Username)).Scan(&occupied); err != nil {
				WriteError(w, r, 500, "internal", "account lookup failed")
				return
			}
			if occupied != 0 {
				WriteError(w, r, 403, "account_link_required", "account must be linked by the trusted directory")
				return
			}
			if !settings.AutoProvision {
				WriteError(w, r, http.StatusForbidden, "user_not_found", "Account does not exist and auto-provisioning is disabled")
				return
			}

			userID, err = ids.Mint("usr")
			if err != nil {
				WriteError(w, r, http.StatusInternalServerError, "internal", "failed to mint user id")
				return
			}

			role := "user"
			if claims.Role == "admin" {
				role = "admin"
			}
			userStatus = "active"
			userRole = role

			dummyBytes := make([]byte, 32)
			_, _ = rand.Read(dummyBytes)
			dummySecret := hex.EncodeToString(dummyBytes)
			dummyHash, hashErr := auth.HashAuthSecret(dummySecret)
			if hashErr != nil {
				WriteError(w, r, 503, "auth_busy", "authentication temporarily unavailable")
				return
			}
			loginSalt := auth.SyntheticLoginSalt(cfg.Secrets.ServerSaltKey, claims.Username)
			now := time.Now().UTC().Format(time.RFC3339)

			_, err = db.Exec(`INSERT INTO users(id, username, auth_secret_hash, login_salt, login_iterations, role, status, sso_subject, sso_issuer, created_at, updated_at) VALUES(?, ?, ?, ?, 600000, ?, 'active', ?, ?, ?, ?)`,
				userID, strings.ToLower(claims.Username), dummyHash, loginSalt, role, claims.Subject, settings.IssuerURL, now, now)
			if err != nil {
				WriteError(w, r, http.StatusInternalServerError, "internal", "failed to auto-provision user: "+err.Error())
				return
			}
			recordAudit(db, userID, "user.auto_provision", "", "", RequestID(r))
		}

		if userStatus != "active" {
			WriteError(w, r, http.StatusForbidden, "account_disabled", "Account is disabled")
			return
		}

		// Clear SSO state cookie
		clearCookie(w, ssoCookieName, true, !cfg.Server.DevInsecureCookies && isRequestSecure(r))

		// Mint KyNotes session
		deadline := transaction.Expires
		if claims.ValidUntil.Before(deadline) {
			deadline = claims.ValidUntil
		}
		_, err = auth.MintSSOSession(r.Context(), db, w, userID, auth.SSOIdentity{Issuer: settings.IssuerURL, ClientID: settings.ClientID, Subject: claims.Subject, SessionID: claims.SessionID, IssuedAt: claims.IssuedAt, LoginExpires: deadline}, cfg.Server.DevInsecureCookies, RequestID(r))
		if err != nil {
			if errors.Is(err, auth.ErrSSOLoginRejected) {
				WriteError(w, r, 403, "sso_login_rejected", "restart Single Sign-On login")
				return
			}
			WriteError(w, r, http.StatusInternalServerError, "internal", "failed to create session")
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	}
	mux.HandleFunc("GET /api/v1/auth/oidc/callback", handleOIDCCallback)
	mux.HandleFunc("GET /api/auth/oidc/callback", handleOIDCCallback)
	mux.HandleFunc("GET /auth/oidc/callback", handleOIDCCallback)

	// Directory Sync Webhook from KySignOn
	handleSyncEvents := func(w http.ResponseWriter, r *http.Request) {
		syncSettings := r.Context().Value(syncSettingsKey{}).(sso.SSOSettings)
		verified, ok := syncauth.EventFromContext(r)
		if !ok {
			WriteError(w, r, 401, "invalid_signature", "unverified event")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			WriteError(w, r, 400, "invalid_request", "failed to read event")
			return
		}

		var event struct {
			EventID   string         `json:"eventId"`
			EventType string         `json:"eventType"`
			Timestamp string         `json:"timestamp"`
			User      *sso.SyncUser  `json:"user,omitempty"`
			Users     []sso.SyncUser `json:"users,omitempty"`
		}

		if err := json.Unmarshal(body, &event); err != nil {
			WriteError(w, r, http.StatusBadRequest, "invalid_json", "failed to decode sync payload")
			return
		}

		if event.EventID != verified.ID || event.EventType != verified.Type {
			WriteError(w, r, 400, "invalid_event", "event metadata mismatch")
			return
		}
		tx, err := db.BeginTx(r.Context(), nil)
		if err != nil {
			WriteError(w, r, 500, "sync_failed", "event transaction failed")
			return
		}
		defer tx.Rollback()
		var current int
		if err = tx.QueryRow(`SELECT count(*) FROM server_settings WHERE key='sso_hmac_secret' AND value=? AND EXISTS(SELECT 1 FROM server_settings WHERE key='sso_issuer_url' AND value=?)`, syncSettings.HMACSecret, syncSettings.IssuerURL).Scan(&current); err != nil || current != 1 {
			WriteError(w, r, 409, "sync_configuration_changed", "directory configuration changed")
			return
		}
		// Replay admission and account mutations commit together; failed events remain retryable.
		if _, err = tx.Exec(`DELETE FROM sso_sync_events WHERE expires_at < ?`, time.Now().Unix()); err == nil {
			var result sql.Result
			result, err = tx.Exec(`INSERT INTO sso_sync_events(event_id,expires_at) VALUES(?,?) ON CONFLICT(event_id) DO NOTHING`, verified.ID, verified.At.Add(syncauth.DefaultWindow).Unix())
			if err == nil {
				var n int64
				n, err = result.RowsAffected()
				if err == nil && n == 0 {
					WriteError(w, r, 409, "event_replayed", "event already applied")
					return
				}
			}
		}
		if err != nil {
			WriteError(w, r, 500, "sync_failed", "event admission failed")
			return
		}
		switch verified.Type {
		case "user.created", "user.updated", "user.status_changed", "user.disabled", "user.enabled":
			if event.User == nil {
				err = errors.New("missing user")
			} else {
				err = syncSingleUser(tx, cfg, syncSettings.IssuerURL, event.User)
			}
		case "user.deleted":
			if event.User == nil || event.User.ID == "" {
				err = errors.New("missing subject")
			} else {
				_, err = tx.Exec(`DELETE FROM users WHERE sso_subject=? AND sso_issuer=?`, event.User.ID, syncSettings.IssuerURL)
			}
		case "directory.resync":
			for _, u := range event.Users {
				if err = syncSingleUser(tx, cfg, syncSettings.IssuerURL, &u); err != nil {
					break
				}
			}
		default:
			WriteError(w, r, 400, "invalid_event", "unsupported event type")
			return
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			WriteError(w, r, 500, "sync_failed", "directory event was not applied")
			return
		}

		writeJSON(w, map[string]any{"status": "applied", "eventId": event.EventID})
	}
	verify := syncauth.Middleware(func(r *http.Request) ([]byte, error) {
		return []byte(r.Context().Value(syncSettingsKey{}).(sso.SSOSettings).HMACSecret), nil
	}, syncauth.Options{}, cfg.Server.MaxRequestBytes, nil)
	handler := verify(http.HandlerFunc(handleSyncEvents))
	for _, path := range []string{"/api/v1/sync/events", "/api/sync/events", "/sync/events"} {
		mux.Handle("POST "+path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.WithValue(r.Context(), syncSettingsKey{}, ssoStore.Load()))
			handler.ServeHTTP(&syncAuthWriter{ResponseWriter: w, request: r}, r)
		}))
	}
}

// Keep the product's error envelope at the library middleware boundary.
type syncAuthWriter struct {
	http.ResponseWriter
	request  *http.Request
	rejected bool
}

func (w *syncAuthWriter) WriteHeader(status int) {
	if status == http.StatusUnauthorized {
		w.rejected = true
		WriteError(w.ResponseWriter, w.request, status, "invalid_signature", "invalid directory signature")
		return
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *syncAuthWriter) Write(b []byte) (int, error) {
	if w.rejected {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

type ssoTransaction struct {
	Verifier, Nonce, RedirectURI string
	Settings                     sso.SSOSettings
	Expires                      time.Time
}
type ssoTransactions struct {
	mu      sync.Mutex
	pending map[string]ssoTransaction
}

func (s *ssoTransactions) add(state string, tx ssoTransaction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, item := range s.pending {
		if !time.Now().Before(item.Expires) {
			delete(s.pending, key)
		}
	}
	// ponytail: bounded per-process login state; oldest eviction keeps admission open.
	// Upgrade path: a shared expiring transaction store for multiple replicas.
	if len(s.pending) >= 1024 {
		var oldest string
		var expiry time.Time
		for key, item := range s.pending {
			if expiry.IsZero() || item.Expires.Before(expiry) {
				oldest, expiry = key, item.Expires
			}
		}
		delete(s.pending, oldest)
	}
	s.pending[state] = tx
}
func (s *ssoTransactions) take(state string) (ssoTransaction, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.pending[state]
	delete(s.pending, state)
	return tx, ok && time.Now().Before(tx.Expires)
}

func syncSingleUser(db *sql.Tx, cfg config.Config, issuer string, u *sso.SyncUser) error {
	if u.ID == "" {
		return errors.New("missing directory subject")
	}
	var existingID, existingUsername, existingRole, existingStatus, existingSubject, existingIssuer string
	err := db.QueryRow(`SELECT id, username, role, status, coalesce(sso_subject,''),sso_issuer FROM users WHERE sso_subject=? AND sso_issuer=?`, u.ID, issuer).Scan(&existingID, &existingUsername, &existingRole, &existingStatus, &existingSubject, &existingIssuer)
	if errors.Is(err, sql.ErrNoRows) && u.Username != "" {
		err = db.QueryRow(`SELECT id, username, role, status, coalesce(sso_subject,''),sso_issuer FROM users WHERE username=?`, strings.ToLower(u.Username)).Scan(&existingID, &existingUsername, &existingRole, &existingStatus, &existingSubject, &existingIssuer)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && existingSubject != "" && (existingSubject != u.ID || existingIssuer != issuer) {
		return errors.New("directory subject conflict")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	username := strings.ToLower(u.Username)
	if username == "" {
		username = existingUsername
	}
	role := existingRole
	if role == "" {
		role = "user"
	}
	if u.Role != "" {
		if u.Role == "admin" {
			role = "admin"
		} else {
			role = "user"
		}
	}
	status := existingStatus
	if status == "" {
		status = "active"
	}
	if u.Status != "" {
		if u.Status == "disabled" {
			status = "disabled"
		} else {
			status = "active"
		}
	}

	if err != nil {
		// Insert new user
		if username == "" {
			username = u.ID
		}
		newID, mintErr := ids.Mint("usr")
		if mintErr != nil {
			return mintErr
		}
		dummyBytes := make([]byte, 32)
		_, _ = rand.Read(dummyBytes)
		dummySecret := hex.EncodeToString(dummyBytes)
		dummyHash, hashErr := auth.HashAuthSecret(dummySecret)
		if hashErr != nil {
			return hashErr
		}
		loginSalt := auth.SyntheticLoginSalt(cfg.Secrets.ServerSaltKey, username)

		_, err = db.Exec(`INSERT INTO users(id, username, auth_secret_hash, login_salt, login_iterations, role, status, sso_subject, sso_issuer, created_at, updated_at) VALUES(?, ?, ?, ?, 600000, ?, ?, ?, ?, ?, ?)`,
			newID, username, dummyHash, loginSalt, role, status, u.ID, issuer, now, now)
		return err
	}

	// Update existing user
	_, err = db.Exec(`UPDATE users SET username=?, role=?, status=?, sso_subject=?, sso_issuer=?, updated_at=? WHERE id=?`,
		username, role, status, u.ID, issuer, now, existingID)
	return err
}
