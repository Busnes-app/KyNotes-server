package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
)

func TestSetupFlow(t *testing.T) {
	db, cfg := setupTestDB(t)

	mux := http.NewServeMux()
	AuthRoutes(mux, db, cfg)

	// 1. Initial state: setup should be required
	req := httptest.NewRequest("GET", "/api/v1/setup", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from GET /api/v1/setup, got %d", rec.Code)
	}

	var res struct {
		SetupRequired bool `json:"setupRequired"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode setup response: %v", err)
	}
	if !res.SetupRequired {
		t.Fatal("expected setupRequired=true on empty DB")
	}

	// 2. Perform setup
	salt := auth.SyntheticLoginSalt(cfg.Secrets.ServerSaltKey, "admin")
	authSecret, err := auth.DeriveAuthSecret("AdminMasterPassword123!", salt, 600000)
	if err != nil {
		t.Fatalf("failed to derive auth secret: %v", err)
	}

	setupPayload := map[string]string{
		"username":   "admin",
		"password":   "AdminMasterPassword123!",
		"authSecret": authSecret,
	}
	setupBytes, _ := json.Marshal(setupPayload)
	req2 := httptest.NewRequest("POST", "/api/v1/setup", bytes.NewReader(setupBytes))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 from POST /api/v1/setup, got %d: %s", rec2.Code, rec2.Body.String())
	}

	// Verify session cookie was set
	cookies := rec2.Result().Cookies()
	var hasSession bool
	for _, c := range cookies {
		if c.Name == "kynotes_session" && c.Value != "" {
			hasSession = true
		}
	}
	if !hasSession {
		t.Fatal("expected session cookie on successful setup")
	}

	// 3. Second setup call must be forbidden (403)
	req3 := httptest.NewRequest("POST", "/api/v1/setup", bytes.NewReader(setupBytes))
	req3.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from duplicate POST /api/v1/setup, got %d", rec3.Code)
	}

	// 4. GET /api/v1/setup now returns setupRequired=false
	req4 := httptest.NewRequest("GET", "/api/v1/setup", nil)
	rec4 := httptest.NewRecorder()
	mux.ServeHTTP(rec4, req4)

	var res2 struct {
		SetupRequired bool `json:"setupRequired"`
	}
	_ = json.NewDecoder(rec4.Body).Decode(&res2)
	if res2.SetupRequired {
		t.Fatal("expected setupRequired=false after setup completed")
	}

	// 5. Subsequent login with admin credentials succeeds
	loginParamsPayload, _ := json.Marshal(map[string]string{"username": "admin"})
	req5 := httptest.NewRequest("POST", "/api/v1/auth/login-params", bytes.NewReader(loginParamsPayload))
	req5.Header.Set("Content-Type", "application/json")
	rec5 := httptest.NewRecorder()
	mux.ServeHTTP(rec5, req5)

	if rec5.Code != http.StatusOK {
		t.Fatalf("expected 200 from login-params, got %d: %s", rec5.Code, rec5.Body.String())
	}
	var lp struct {
		LoginSalt  string `json:"loginSalt"`
		Iterations int    `json:"iterations"`
	}
	if err := json.NewDecoder(rec5.Body).Decode(&lp); err != nil {
		t.Fatalf("failed to decode login-params: %v", err)
	}

	loginAuthSecret, err := auth.DeriveAuthSecret("AdminMasterPassword123!", lp.LoginSalt, lp.Iterations)
	if err != nil {
		t.Fatalf("failed to derive login auth secret: %v", err)
	}

	loginPayload, _ := json.Marshal(map[string]string{
		"username":   "admin",
		"authSecret": loginAuthSecret,
	})
	req6 := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(loginPayload))
	req6.Header.Set("Content-Type", "application/json")
	rec6 := httptest.NewRecorder()
	mux.ServeHTTP(rec6, req6)

	if rec6.Code != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d: %s", rec6.Code, rec6.Body.String())
	}
}
