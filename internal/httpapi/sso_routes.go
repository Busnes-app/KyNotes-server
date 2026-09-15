package httpapi

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Busness-app/kynotes-server/internal/auth"
	"github.com/Busness-app/kynotes-server/internal/config"
	"github.com/Busness-app/kynotes-server/internal/ids"
	"github.com/Busness-app/kynotes-server/internal/sso"
)

const ssoCookieName = "kynotes_sso_state"

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
		w.Header().Set("Cache-Control", "no-store")
		var reauthSession auth.Session
		var challengeID string
		var started time.Time
		if r.Method == "POST" {
			if auth.CheckCSRF(r) != nil {
				WriteError(w, r, 403, "csrf_failed", "CSRF validation failed")
				return
			}
			reauthSession, _ = auth.SessionFromContext(r)
			var in struct {
				Challenge string `json:"challenge"`
			}
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in) != nil || len(in.Challenge) > 128 || reauthSession.SSOIssuer == "" {
				WriteError(w, r, 400, "invalid_request", "invalid SSO challenge")
				return
			}
			var err error
			challengeID = in.Challenge
			started, err = auth.BeginSSOStepUp(r.Context(), db, reauthSession, challengeID)
			if err != nil {
				WriteError(w, r, 403, "invalid_challenge", "restart the action")
				return
			}
		}
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
			callbackPath := strings.Replace(r.URL.Path, "/login", "/callback", 1)
			if challengeID != "" {
				callbackPath = "/api/v1/auth/oidc/callback"
			}
			redirectURI = fmt.Sprintf("%s://%s%s", scheme, requestHost(r), callbackPath)
		}

		state, nonce := sso.GenerateState(), sso.GenerateState()
		transactions.add(state, ssoTransaction{Verifier: verifier, Nonce: nonce, RedirectURI: redirectURI, Settings: settings, ReauthSession: reauthSession, Challenge: challengeID, Started: started, Expires: time.Now().Add(auth.SSOLoginLifetime)})
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
		if challengeID != "" {
			q.Set("prompt", "login")
			q.Set("max_age", "0")
			q.Set("acr_values", "urn:kysignon:acr:password")
		}
		authURL.RawQuery = q.Encode()
		if challengeID != "" {
			writeJSON(w, map[string]string{"url": authURL.String()})
			return
		}

		http.Redirect(w, r, authURL.String(), http.StatusFound)
	}
	mux.Handle("POST /api/v1/auth/oidc/step-up", auth.RequireAdmin(db, http.HandlerFunc(handleOIDCFlow)))
	mux.Handle("GET /api/v1/auth/oidc/step-up/{id}", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		session, _ := auth.SessionFromContext(r)
		var verified bool
		err := db.QueryRow(`SELECT verified FROM sso_stepup WHERE id=? AND session_id=? AND expires_at>?`, r.PathValue("id"), session.ID, time.Now().Unix()).Scan(&verified)
		if err != nil {
			WriteError(w, r, 403, "invalid_challenge", "restart the action")
			return
		}
		writeJSON(w, map[string]bool{"verified": verified})
	})))
	mux.Handle("DELETE /api/v1/auth/oidc/step-up/{id}", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "CSRF validation failed")
			return
		}
		id := r.PathValue("id")
		if ids.Validate("rea", id) != nil {
			WriteError(w, r, 400, "invalid_challenge", "invalid challenge ID")
			return
		}
		session, _ := auth.SessionFromContext(r)
		if err := auth.CancelSSOStepUp(r.Context(), db, session, id, RequestID(r)); err != nil {
			WriteError(w, r, 500, "internal", "cancellation failed")
			return
		}
		w.WriteHeader(204)
	})))
	mux.HandleFunc("GET /api/v1/auth/oidc/login", handleOIDCFlow)
	mux.HandleFunc("GET /api/auth/oidc/login", handleOIDCFlow)
	mux.HandleFunc("GET /auth/oidc/login", handleOIDCFlow)

	// Handles OAuth redirect callback, verifies PKCE, exchanges code for token, mints session
	handleOIDCCallback := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		settings := ssoStore.Load()
		if !settings.Enabled || settings.IssuerURL == "" {
			WriteError(w, r, http.StatusServiceUnavailable, "sso_disabled", "Single Sign-On is not configured or disabled")
			return
		}

		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if state == "" {
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
		if code == "" {
			WriteError(w, r, 400, "authorization_cancelled", "authorization was cancelled; return to KyNotes")
			return
		}
		if transaction.Challenge != "" {
			current, err := auth.ResolveSession(db, r, time.Now())
			if err != nil || current.ID != transaction.ReauthSession.ID {
				WriteError(w, r, 403, "session_changed", "original session is no longer available")
				return
			}
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

		if transaction.Challenge != "" {
			now := time.Now().UTC()
			if !claims.FreshProof(transaction.Started, now) {
				WriteError(w, r, 403, "fresh_proof_required", "fresh ordinary authentication evidence required")
				return
			}
			deadline := transaction.Expires
			if claims.ValidUntil.Before(deadline) {
				deadline = claims.ValidUntil
			}
			identity := auth.SSOIdentity{Issuer: settings.IssuerURL, ClientID: settings.ClientID, Subject: claims.Subject, SessionID: claims.SessionID, IssuedAt: claims.IssuedAt, AppAdmin: claims.AppAdmin, LoginExpires: deadline}
			err := auth.CompleteSSOStepUp(r.Context(), db, transaction.ReauthSession, transaction.Challenge, identity, claims.AuthTime, claims.Assurance, RequestID(r))
			if err != nil {
				if errors.Is(err, auth.ErrSSOLoginRejected) {
					WriteError(w, r, 403, "reauthentication_rejected", "session, account or authorization changed; restart the action")
				} else {
					WriteError(w, r, 500, "internal", "reauthentication unavailable")
				}
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<!doctype html><html lang=en><meta charset=utf-8><title>KyNotes confirmation</title><p>Identity confirmed. Return to KyNotes to finish the action.</p></html>"))
			return
		}

		var userID, userStatus string
		// 1. Try finding user by sso_subject
		err = db.QueryRow(`SELECT id, status FROM users WHERE sso_subject=? AND sso_issuer=?`, claims.Subject, settings.IssuerURL).Scan(&userID, &userStatus)
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
			userStatus = "active"

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
		_, err = auth.MintSSOSession(r.Context(), db, w, userID, auth.SSOIdentity{Issuer: settings.IssuerURL, ClientID: settings.ClientID, Subject: claims.Subject, SessionID: claims.SessionID, AppAdmin: claims.AppAdmin, IssuedAt: claims.IssuedAt, LoginExpires: deadline}, cfg.Server.DevInsecureCookies, RequestID(r))
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

	registerDirectorySync(mux, db, cfg, ssoStore)
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
	ReauthSession                auth.Session
	Challenge                    string
	Started                      time.Time
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
