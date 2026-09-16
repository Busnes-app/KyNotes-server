package sso

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
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

	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busness-app/ky-primitives/oidcverify"
)

// SSOSettings holds the OpenID Connect and KySignOn sync configuration.
type SSOSettings struct {
	Enabled       bool   `json:"enabled"`
	IssuerURL     string `json:"issuerUrl"`
	ClientID      string `json:"clientId"`
	ClientSecret  string `json:"clientSecret,omitempty"`
	RedirectURI   string `json:"redirectUri,omitempty"`
	AutoProvision bool   `json:"autoProvision"`
	HMACSecret    string `json:"hmacSecret,omitempty"`
}

// Store manages SSOSettings loaded and persisted to the SQLite server_settings table.
type Store struct {
	mu                 sync.RWMutex
	discoveryMu        sync.Mutex
	logoutDiscoveryAt  time.Time
	logoutDiscoveryKey string
	db                 *sql.DB
	cached             SSOSettings
	inMemory           bool
	verifier           *oidcverify.Verifier
}

// NewStore initializes a new Store backed by the SQLite database.
func NewStore(db *sql.DB) *Store {
	s := &Store{db: db}
	_ = s.Reload()
	return s
}

// Reload re-reads settings from the database.
func (s *Store) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return nil
	}

	var enabledStr, issuerURL, clientID, clientSecret, redirectURI, autoProvStr, hmacSecret string
	_ = s.db.QueryRow(`SELECT value FROM server_settings WHERE key='sso_enabled'`).Scan(&enabledStr)
	_ = s.db.QueryRow(`SELECT value FROM server_settings WHERE key='sso_issuer_url'`).Scan(&issuerURL)
	_ = s.db.QueryRow(`SELECT value FROM server_settings WHERE key='sso_client_id'`).Scan(&clientID)
	_ = s.db.QueryRow(`SELECT value FROM server_settings WHERE key='sso_client_secret'`).Scan(&clientSecret)
	_ = s.db.QueryRow(`SELECT value FROM server_settings WHERE key='sso_redirect_uri'`).Scan(&redirectURI)
	_ = s.db.QueryRow(`SELECT value FROM server_settings WHERE key='sso_auto_provision'`).Scan(&autoProvStr)
	_ = s.db.QueryRow(`SELECT value FROM server_settings WHERE key='sso_hmac_secret'`).Scan(&hmacSecret)

	s.cached = SSOSettings{
		Enabled:       enabledStr == "true" || enabledStr == "1",
		IssuerURL:     issuerURL,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		RedirectURI:   redirectURI,
		AutoProvision: autoProvStr == "" || autoProvStr == "true" || autoProvStr == "1",
		HMACSecret:    hmacSecret,
	}
	return nil
}

// Load returns the current SSOSettings.
func (s *Store) Load() SSOSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cached
}

// Save persists new SSOSettings to the database.
func (s *Store) Save(settings SSOSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		s.cached = settings
		return nil
	}

	enabledVal := "false"
	if settings.Enabled {
		enabledVal = "true"
	}
	autoProvVal := "false"
	if settings.AutoProvision {
		autoProvVal = "true"
	}

	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	upsert := func(key, value string) error {
		_, err := tx.Exec(`INSERT INTO server_settings(key, value, updated_at) VALUES(?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`, key, value, now)
		return err
	}

	if err := upsert("sso_enabled", enabledVal); err != nil {
		return err
	}
	if err := upsert("sso_issuer_url", settings.IssuerURL); err != nil {
		return err
	}
	if err := upsert("sso_client_id", settings.ClientID); err != nil {
		return err
	}
	if err := upsert("sso_client_secret", settings.ClientSecret); err != nil {
		return err
	}
	if err := upsert("sso_redirect_uri", settings.RedirectURI); err != nil {
		return err
	}
	if err := upsert("sso_auto_provision", autoProvVal); err != nil {
		return err
	}
	if err := upsert("sso_hmac_secret", settings.HMACSecret); err != nil {
		return err
	}

	if settings.IssuerURL != s.cached.IssuerURL || settings.ClientID != s.cached.ClientID || !settings.Enabled {
		if _, err := tx.Exec(`UPDATE sessions SET revoked_at=? WHERE sso_issuer<>'' AND revoked_at=''`, now); err != nil {
			return err
		}
		if err := storage.RecordAuditOutcomeTx(tx, "", "auth.sso_configuration", "", "", "success", "configuration_changed", ""); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	s.cached = settings
	return nil
}

// DiscoveryDoc represents the OpenID Provider Configuration document.
type DiscoveryDoc struct {
	Issuer                            string `json:"issuer"`
	AuthorizationEndpoint             string `json:"authorization_endpoint"`
	TokenEndpoint                     string `json:"token_endpoint"`
	UserinfoEndpoint                  string `json:"userinfo_endpoint"`
	JWKSURI                           string `json:"jwks_uri"`
	BackchannelLogoutSessionSupported bool   `json:"backchannel_logout_session_supported"`
}

// DiscoverEndpoints fetches the OpenID configuration from the issuer URL.
func DiscoverEndpoints(ctx context.Context, issuerURL string) (*DiscoveryDoc, error) {
	if err := requireHTTPS(issuerURL); err != nil {
		return nil, err
	}
	wellKnown := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	client := oidcClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned HTTP %d", resp.StatusCode)
	}

	var doc DiscoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	if doc.Issuer != issuerURL {
		return nil, errors.New("OIDC discovery issuer mismatch")
	}
	for _, endpoint := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JWKSURI} {
		if err := requireHTTPS(endpoint); err != nil {
			return nil, err
		}
	}
	return &doc, nil
}

// GeneratePKCE creates a code_verifier and code_challenge (S256).
func GeneratePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

// GenerateState generates a random 16-byte hex state parameter.
func GenerateState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// TokenResponse represents the token response from the authorization server.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// ExchangeCode exchanges an authorization code for tokens.
func ExchangeCode(ctx context.Context, tokenEndpoint, clientID, clientSecret, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	if err := requireHTTPS(tokenEndpoint); err != nil {
		return nil, err
	}
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	}
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := oidcClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed (%d)", resp.StatusCode)
	}

	var tok TokenResponse
	if err := json.Unmarshal(bodyBytes, &tok); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tok, nil
}

// Claims represents standard OpenID Connect claims.
type Claims struct {
	AuthTime      time.Time
	Assurance     string
	Methods       []string
	Subject       string    `json:"sub"`
	SessionID     string    `json:"sid"`
	IssuedAt      time.Time `json:"-"`
	ValidUntil    time.Time `json:"-"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Name          string    `json:"name"`
	Username      string    `json:"preferred_username"`
	AppAdmin      bool      `json:"-"`
}

// VerifyClaims accepts identity only from a signed ID token bound to this login.
func (s *Store) VerifyClaims(ctx context.Context, settings SSOSettings, doc *DiscoveryDoc, idToken, nonce string) (*Claims, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The verifier shares its JWKS cache with logout; callers cannot abort a
	// cache fill and consume its refresh cooldown without reaching the issuer.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	s.mu.Lock()
	v := s.verifier
	if v == nil || v.Issuer != settings.IssuerURL || v.Audience != settings.ClientID || v.JWKSURL != doc.JWKSURI {
		v = &oidcverify.Verifier{Issuer: settings.IssuerURL, Audience: settings.ClientID, JWKSURL: doc.JWKSURI, HTTPClient: oidcClient()}
		s.verifier = v
	}
	s.mu.Unlock()
	if nonce == "" || settings.ClientID == "" {
		return nil, errors.New("missing OIDC login binding")
	}
	verified, err := v.VerifyWithNonce(ctx, idToken, nonce)
	if err != nil {
		return nil, err
	}
	claims := &Claims{Subject: verified.Subject, IssuedAt: verified.IssuedAt, ValidUntil: verified.ExpiresAt.Add(time.Minute), Email: verified.String("email"), Name: verified.String("name"), Username: verified.String("preferred_username")}
	claims.AppAdmin = HasAdminRole(verified.Raw["roles"])
	var authTime int64
	if json.Unmarshal(verified.Raw["auth_time"], &authTime) == nil && authTime > 0 {
		claims.AuthTime = time.Unix(authTime, 0)
	}
	_ = json.Unmarshal(verified.Raw["acr"], &claims.Assurance)
	var methods []string
	if json.Unmarshal(verified.Raw["amr"], &methods) == nil {
		claims.Methods = methods
	}
	if verified.IssuedAt.IsZero() {
		return nil, errors.New("missing ID token issuance time")
	}
	if raw, present := verified.Raw["sid"]; present {
		if err := json.Unmarshal(raw, &claims.SessionID); err != nil || claims.SessionID == "" {
			return nil, errors.New("invalid ID token session")
		}
	}
	if doc.BackchannelLogoutSessionSupported && claims.SessionID == "" {
		return nil, errors.New("missing ID token session")
	}
	if raw := verified.Raw["email_verified"]; raw != nil {
		_ = json.Unmarshal(raw, &claims.EmailVerified)
	}
	if claims.Username == "" {
		claims.Username = claims.Subject
	}
	return claims, nil
}

// VerifyLogout uses the login verifier and retries key failures against current
// discovery. Refreshes are bounded per issuer/client, including failed fetches.
func (s *Store) VerifyLogout(ctx context.Context, settings SSOSettings, token string) (oidcverify.LogoutClaims, error) {
	if err := ctx.Err(); err != nil {
		return oidcverify.LogoutClaims{}, err
	}
	// Bound shared discovery/JWKS work independently of caller disconnects.
	// The HTTP handler still uses the original context for the revocation commit.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	if settings.IssuerURL == "" || settings.ClientID == "" {
		return oidcverify.LogoutClaims{}, errors.New("SSO logout is not configured")
	}
	v, err := s.logoutVerifier(ctx, settings, false)
	if err != nil {
		return oidcverify.LogoutClaims{}, err
	}
	claims, err := v.VerifyLogout(ctx, token)
	if !errors.Is(err, oidcverify.ErrUnknownKey) && !errors.Is(err, oidcverify.ErrJWKS) && !errors.Is(err, oidcverify.ErrSignature) {
		return claims, err
	}
	refreshed, refreshErr := s.logoutVerifier(ctx, settings, true)
	if refreshErr != nil || refreshed == v {
		return claims, err
	}
	return refreshed.VerifyLogout(ctx, token)
}

func (s *Store) logoutVerifier(ctx context.Context, settings SSOSettings, refresh bool) (*oidcverify.Verifier, error) {
	// Never hold the settings mutex across network work.
	s.discoveryMu.Lock()
	defer s.discoveryMu.Unlock()
	// A request that exhausted its own budget waiting did not attempt discovery.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	v := s.verifier
	s.mu.RUnlock()
	matches := v != nil && v.Issuer == settings.IssuerURL && v.Audience == settings.ClientID
	if matches && !refresh {
		return v, nil
	}
	key := settings.IssuerURL + "\x00" + settings.ClientID
	if s.logoutDiscoveryKey == key && time.Since(s.logoutDiscoveryAt) < time.Minute {
		if matches {
			return v, nil
		}
		return nil, errors.New("SSO discovery temporarily unavailable")
	}
	s.logoutDiscoveryKey, s.logoutDiscoveryAt = key, time.Now()
	doc, err := DiscoverEndpoints(ctx, settings.IssuerURL)
	if err != nil {
		if matches {
			return v, nil
		}
		return nil, err
	}
	if !matches || v.JWKSURL != doc.JWKSURI {
		v = &oidcverify.Verifier{Issuer: settings.IssuerURL, Audience: settings.ClientID, JWKSURL: doc.JWKSURI, HTTPClient: oidcClient()}
		s.mu.Lock()
		s.verifier = v
		s.mu.Unlock()
	}
	return v, nil
}

func oidcClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("OIDC redirects refused") }}
}

func requireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("OIDC endpoint must be HTTPS without credentials or fragment")
	}
	return nil
}

// SystemPairingRequest represents the registration payload sent to KySignOn.
type SystemPairingRequest struct {
	PairingToken string `json:"pairingToken"`
	SystemName   string `json:"systemName"`
	SystemType   string `json:"systemType"`
	CallbackURL  string `json:"callbackUrl"`
}

// SystemPairingResponse represents KySignOn's response to pairing registration.
type SystemPairingResponse struct {
	SystemID   string `json:"systemId"`
	HMACSecret string `json:"hmacSecret"`
	Status     string `json:"status"`
}

// PairWithKySignOn redeems a 90s pairing token against KySignOn to automatically obtain credentials.
func PairWithKySignOn(ctx context.Context, issuerURL, pairingToken, callbackURL string) (*SystemPairingResponse, error) {
	issuerURL = strings.TrimRight(issuerURL, "/")
	registerURL := issuerURL + "/api/systems/register"

	payload := SystemPairingRequest{
		PairingToken: pairingToken,
		SystemName:   "KyNotes",
		SystemType:   "kynotes",
		CallbackURL:  callbackURL,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := oidcClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pairing request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pairing failed (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var pairResp SystemPairingResponse
	if err := json.Unmarshal(bodyBytes, &pairResp); err != nil {
		return nil, fmt.Errorf("failed to parse pairing response: %w", err)
	}

	return &pairResp, nil
}

// AdminAppRole cannot be confused with the sender's legacy global admin/user roles.
const AdminAppRole = "kynotes.admin"

// HasAdminRole recognizes only the exact product role, in string or SCIM form.
// Unrelated or unfamiliar role data never prevents login or offboarding.
func HasAdminRole(raw json.RawMessage) bool {
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return false
	}
	for _, entry := range entries {
		var name string
		if json.Unmarshal(entry, &name) != nil {
			var role struct {
				Value string `json:"value"`
			}
			if json.Unmarshal(entry, &role) != nil {
				continue
			}
			name = role.Value
		}
		if name == AdminAppRole {
			return true
		}
	}
	return false
}

// FreshProof validates actual authentication evidence, never token issuance as a substitute.
func (c Claims) FreshProof(start, now time.Time) bool {
	if c.AuthTime.IsZero() || c.AuthTime.Before(start) || c.AuthTime.After(now) || c.AuthTime.After(c.IssuedAt) {
		return false
	}
	pwd, mfa, factor := false, false, false
	for _, method := range c.Methods {
		switch method {
		case "pwd":
			pwd = true
		case "mfa":
			mfa = true
		case "otp", "urn:kysignon:amr:push", "urn:kysignon:amr:webauthn":
			factor = true
		case "urn:kysignon:amr:recovery":
			return false
		}
	}
	return pwd && (c.Assurance == "urn:kysignon:acr:password" || c.Assurance == "urn:kysignon:acr:mfa" && mfa && factor)
}
