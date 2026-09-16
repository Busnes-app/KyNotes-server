package httpapi

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/Busnes-app/ky-primitives/syncauth"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func setupTestDB(t *testing.T) (*sql.DB, config.Config) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "kynotes_test.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	cfg := config.Defaults()
	cfg.DataDir = dir
	cfg.Secrets.ServerSaltKey = "test-salt-key-32-bytes-long-1234"
	cfg.Server.DevInsecureCookies = true

	return store.DB(), cfg
}

func createAdminUser(t *testing.T, db *sql.DB) (string, string) {
	userID, _ := ids.Mint("usr")
	secret, _ := auth.HashAuthSecret(strings.Repeat("a", 64))
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`INSERT INTO users(id, username, auth_secret_hash, login_salt, login_iterations, role, status, created_at, updated_at) VALUES(?, 'admin', ?, 'salt', 600000, 'admin', 'active', ?, ?)`, userID, secret, now, now)
	if err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}
	return userID, "admin"
}

func TestSSOConfigEndpoint(t *testing.T) {
	db, cfg := setupTestDB(t)
	ssoStore := sso.NewStore(db)

	mux := http.NewServeMux()
	SSORoutes(mux, db, cfg, ssoStore)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/auth/sso-config", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var res map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&res)
	if res["enabled"] != false {
		t.Fatalf("expected enabled=false initially")
	}

	// Update settings
	_ = ssoStore.Save(sso.SSOSettings{
		Enabled:   true,
		IssuerURL: "https://auth.example.com",
		ClientID:  "kynotes",
	})

	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req)
	var res2 map[string]any
	_ = json.NewDecoder(rec2.Body).Decode(&res2)
	if res2["enabled"] != true || res2["issuerUrl"] != "https://auth.example.com" || res2["clientId"] != "kynotes" {
		t.Fatalf("expected updated settings in response, got %+v", res2)
	}
}

func TestDirectorySyncWebhook(t *testing.T) {
	db, cfg := setupTestDB(t)
	ssoStore := sso.NewStore(db)
	secret := "shared-hmac-secret-123"

	_ = ssoStore.Save(sso.SSOSettings{
		Enabled:    true,
		HMACSecret: secret,
		IssuerURL:  "https://issuer.example",
	})

	router := NewRouter(logging.New(io.Discard, "error", "json"), 1048576, func() bool { return true }, db, cfg)

	eventPayload := directoryPayload("kysignon-user-999", "charlie", 1, true)
	eventPayload["roles"] = []any{map[string]any{"value": "admin", "primary": true}}
	bodyBytes, _ := json.Marshal(eventPayload)

	req := httptest.NewRequest("POST", "/api/v1/sync/events", bytes.NewReader(bodyBytes))
	signSync(t, req, secret, "ev_1", "user.created", bodyBytes)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from sync event, got %d: %s", rec.Code, rec.Body.String())
	}

	var uRole, uStatus string
	err := db.QueryRow(`SELECT role, status FROM users WHERE sso_subject='kysignon-user-999'`).Scan(&uRole, &uStatus)
	if err != nil || uRole != "user" || uStatus != "active" {
		t.Fatalf("failed to replicate user from sync event: err=%v, role=%s, status=%s", err, uRole, uStatus)
	}

	// 2. Disable user event
	eventPayload2 := directoryPayload("kysignon-user-999", "", 2, false)
	bodyBytes2, _ := json.Marshal(eventPayload2)
	req2 := httptest.NewRequest("POST", "/api/v1/sync/events", bytes.NewReader(bodyBytes2))
	signSync(t, req2, secret, "ev_2", "user.updated", bodyBytes2)

	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 from sync event, got %d", rec2.Code)
	}

	_ = db.QueryRow(`SELECT status FROM users WHERE sso_subject='kysignon-user-999'`).Scan(&uStatus)
	if uStatus != "disabled" {
		t.Fatalf("expected status=disabled, got %s", uStatus)
	}
}

func TestAdminSSOAndPairing(t *testing.T) {
	db, cfg := setupTestDB(t)
	adminID, _ := createAdminUser(t, db)

	// Mint admin session and get cookies
	mintRec := httptest.NewRecorder()
	sess, err := auth.MintSession(db, mintRec, adminID, true, time.Now().UTC())
	if err != nil {
		t.Fatalf("failed to mint session: %v", err)
	}

	var sessionCookie, csrfCookie *http.Cookie
	for _, c := range mintRec.Result().Cookies() {
		if c.Name == "kynotes_session" {
			sessionCookie = c
		}
		if c.Name == "csrf_token" {
			csrfCookie = c
		}
	}

	// Mock KySignOn Server for System Pairing
	var mockKySignOn *httptest.Server
	mockKySignOn = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/systems/register" {
			var in sso.SystemPairingRequest
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.PairingToken != "valid-pairing-token" {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sso.SystemPairingResponse{
				SystemID:   "sys_paired_123",
				HMACSecret: "shared-hmac-secret-xyz",
				Status:     "active",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockKySignOn.Close()

	router := NewRouter(logging.New(io.Discard, "error", "json"), 1048576, func() bool { return true }, db, cfg)

	// Call POST /api/v1/admin/sso/pair
	pairBody := map[string]string{
		"issuerUrl":    mockKySignOn.URL,
		"pairingToken": "valid-pairing-token",
	}
	pairJSON, _ := json.Marshal(pairBody)
	req := httptest.NewRequest("POST", "/api/v1/admin/sso/pair", bytes.NewReader(pairJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sess.CSRF)
	req.AddCookie(sessionCookie)
	req.AddCookie(csrfCookie)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from admin sso pair, got %d: %s", rec.Code, rec.Body.String())
	}

	var pairRes map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&pairRes)
	if pairRes["success"] != true || pairRes["systemId"] != "sys_paired_123" {
		t.Fatalf("unexpected pair result: %+v", pairRes)
	}

	// Verify GET /api/v1/admin/sso returns paired configuration
	getReq := httptest.NewRequest("GET", "/api/v1/admin/sso", nil)
	getReq.AddCookie(sessionCookie)
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from GET /api/v1/admin/sso, got %d", getRec.Code)
	}

	var ssoSettings sso.SSOSettings
	_ = json.NewDecoder(getRec.Body).Decode(&ssoSettings)
	if !ssoSettings.Enabled || ssoSettings.IssuerURL != mockKySignOn.URL || ssoSettings.HMACSecret != "shared-hmac-secret-xyz" {
		t.Fatalf("unexpected sso settings in admin response: %+v", ssoSettings)
	}
}

// postSyncEvent sends a directory sync event to path, signing it when secret is non-empty.
func postSyncEvent(t *testing.T, router http.Handler, path, secret string, payload map[string]any) int {
	t.Helper()
	wire := make(map[string]any, len(payload))
	for key, value := range payload {
		if key != "eventId" && key != "eventType" {
			wire[key] = value
		}
	}
	body, _ := json.Marshal(wire)
	req := httptest.NewRequest("POST", path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		signSync(t, req, secret, fmt.Sprint(payload["eventId"]), fmt.Sprint(payload["eventType"]), body)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec.Code
}

// The webhook has no session authentication, so the signature is the only control on it.
func TestDirectorySyncRejectsUnsignedEvents(t *testing.T) {
	db, cfg := setupTestDB(t)
	ssoStore := sso.NewStore(db)
	const secret = "shared-hmac-secret-123"
	_ = ssoStore.Save(sso.SSOSettings{Enabled: true, HMACSecret: secret, IssuerURL: "https://issuer.example"})
	router := NewRouter(logging.New(io.Discard, "error", "json"), 1048576, func() bool { return true }, db, cfg)

	event := directoryPayload("attacker-sub", "mallory", 1, true)
	event["eventId"], event["eventType"] = "ev_x", "user.created"

	// Every alias must reject: omitting the header is the whole attack.
	for _, path := range []string{"/api/v1/sync/events", "/api/sync/events", "/sync/events"} {
		if code := postSyncEvent(t, router, path, "", event); code != http.StatusUnauthorized {
			t.Errorf("unsigned event on %s: got %d, want 401", path, code)
		}
		if code := postSyncEvent(t, router, path, "wrong-secret", event); code != http.StatusUnauthorized {
			t.Errorf("badly signed event on %s: got %d, want 401", path, code)
		}
	}

	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM users WHERE username='mallory'`).Scan(&n)
	if n != 0 {
		t.Fatal("an unsigned sync event created an admin account")
	}

	if code := postSyncEvent(t, router, "/api/v1/sync/events", secret, event); code != http.StatusOK {
		t.Fatalf("correctly signed event: got %d, want 200", code)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM users WHERE username='mallory'`).Scan(&n)
	if n != 1 {
		t.Fatal("correctly signed event did not replicate the user")
	}
}

// With no secret configured the endpoint must fail closed, not accept everything.
func TestDirectorySyncFailsClosedWithoutSecret(t *testing.T) {
	db, cfg := setupTestDB(t)
	ssoStore := sso.NewStore(db)
	_ = ssoStore.Save(sso.SSOSettings{Enabled: true, HMACSecret: ""})
	router := NewRouter(logging.New(io.Discard, "error", "json"), 1048576, func() bool { return true }, db, cfg)

	code := postSyncEvent(t, router, "/api/v1/sync/events", "", map[string]any{
		"eventId": "ev_y", "eventType": "user.created",
		"user": map[string]any{"id": "s", "username": "nobody", "role": "admin"},
	})
	if code != http.StatusUnauthorized {
		t.Errorf("event with no secret configured: got %d, want 401", code)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM users WHERE username='nobody'`).Scan(&n)
	if n != 0 {
		t.Fatal("sync event was applied with no secret configured")
	}
}

// syncSingleUser writes sso_subject on update, so an unsigned event could rebind an
// existing admin to an attacker-controlled OIDC identity: account takeover, not just
// privilege escalation.
func TestDirectorySyncCannotRebindAdminSSOSubject(t *testing.T) {
	db, cfg := setupTestDB(t)
	createAdminUser(t, db)
	ssoStore := sso.NewStore(db)
	_ = ssoStore.Save(sso.SSOSettings{Enabled: true, HMACSecret: "shared-hmac-secret-123"})
	router := NewRouter(logging.New(io.Discard, "error", "json"), 1048576, func() bool { return true }, db, cfg)

	code := postSyncEvent(t, router, "/api/v1/sync/events", "", map[string]any{
		"eventId": "ev_z", "eventType": "user.updated",
		"user": map[string]any{"id": "attacker-controlled-sub", "username": "admin", "role": "admin"},
	})
	if code != http.StatusUnauthorized {
		t.Errorf("unsigned rebinding event: got %d, want 401", code)
	}

	var subject string
	_ = db.QueryRow(`SELECT COALESCE(sso_subject,'') FROM users WHERE username='admin'`).Scan(&subject)
	if subject == "attacker-controlled-sub" {
		t.Fatal("an unsigned sync event rebound the admin account to an attacker's SSO identity")
	}
}

func signSync(t *testing.T, req *http.Request, secret, id, kind string, body []byte) {
	t.Helper()
	h, err := syncauth.Sign([]byte(secret), time.Now().UTC(), kind, id, body)
	if err != nil {
		req.Header.Set(syncauth.HeaderSignature, "invalid")
		return
	}
	h.Apply(req)
}
