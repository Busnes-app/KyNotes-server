package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
)

// A stolen admin cookie is the whole threat: step-up costs the login secret,
// which the thief does not have.
func TestStepUpGatesDestructiveRoute(t *testing.T) {
	db, cfg := setupTestDB(t)
	mux := http.NewServeMux()
	AuthRoutes(mux, db, cfg)
	mux.Handle("POST /api/v1/admin/_destructive", auth.RequireStepUp(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))

	adminID, _ := createAdminUser(t, db) // secret is 64 x "a"
	rec := httptest.NewRecorder()
	s, err := auth.MintSession(db, rec, adminID, true, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", s.CSRF)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}

	if rr := do("POST", "/api/v1/admin/_destructive", ""); rr.Code != 403 || !strings.Contains(rr.Body.String(), "step_up_required") {
		t.Fatalf("without step-up: %d %s", rr.Code, rr.Body)
	}
	if rr := do("POST", "/api/v1/auth/step-up", `{"authSecret":"`+strings.Repeat("b", 64)+`"}`); rr.Code != 401 {
		t.Fatalf("wrong secret: %d", rr.Code)
	}
	if rr := do("POST", "/api/v1/admin/_destructive", ""); rr.Code != 403 {
		t.Fatalf("a failed step-up must not grant: %d", rr.Code)
	}
	if rr := do("POST", "/api/v1/auth/step-up", `{"authSecret":"`+strings.Repeat("a", 64)+`"}`); rr.Code != 204 {
		t.Fatalf("step-up: %d %s", rr.Code, rr.Body)
	}
	if rr := do("POST", "/api/v1/admin/_destructive", ""); rr.Code != 204 {
		t.Fatalf("after step-up: %d %s", rr.Code, rr.Body)
	}

	// The grant expires.
	old := time.Now().UTC().Add(-auth.StepUpWindow - time.Minute).Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE sessions SET stepup_at=? WHERE id=?`, old, s.ID); err != nil {
		t.Fatal(err)
	}
	if rr := do("POST", "/api/v1/admin/_destructive", ""); rr.Code != 403 {
		t.Fatalf("stale step-up honoured: %d", rr.Code)
	}

	var failures, successes int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='auth.step_up' AND outcome='failure' AND reason_code='invalid_secret'`).Scan(&failures); err != nil || failures != 1 {
		t.Fatalf("failed step-up not audited: %v %d", err, failures)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='auth.step_up' AND outcome='success'`).Scan(&successes); err != nil || successes != 1 {
		t.Fatalf("successful step-up not audited: %v %d", err, successes)
	}
}

func TestStepUpIsRateLimited(t *testing.T) {
	db, cfg := setupTestDB(t)
	cfg.RateLimit.LoginPerMinute = 1
	mux := http.NewServeMux()
	AuthRoutes(mux, db, cfg)
	h := rateLimitMiddleware(cfg, db, mux)

	adminID, _ := createAdminUser(t, db)
	rec := httptest.NewRecorder()
	s, err := auth.MintSession(db, rec, adminID, true, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/auth/step-up", strings.NewReader(`{"authSecret":"`+strings.Repeat("a", 64)+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", s.CSRF)
		req.RemoteAddr = "203.0.113.55:44444"
		for _, c := range rec.Result().Cookies() {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	if rr := call(); rr.Code != http.StatusNoContent {
		t.Fatalf("first step-up: %d %s", rr.Code, rr.Body)
	}
	if rr := call(); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second step-up: %d %s", rr.Code, rr.Body)
	}
}

func TestStepUpIsNotAdminByItself(t *testing.T) {
	db, cfg := setupTestDB(t)
	mux := http.NewServeMux()
	AuthRoutes(mux, db, cfg)
	mux.Handle("POST /api/v1/admin/_destructive", auth.RequireStepUp(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	now := time.Now().UTC().Format(time.RFC3339)
	h, _ := auth.HashAuthSecret(strings.Repeat("a", 64))
	if _, err := db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,status,created_at,updated_at) VALUES('usr_plain','carol',?,'salt',600000,'user','active',?,?)`, h, now, now); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s, _ := auth.MintSession(db, rec, "usr_plain", true, time.Now().UTC())
	_, _ = db.Exec(`UPDATE sessions SET stepup_at=? WHERE id=?`, now, s.ID)
	req := httptest.NewRequest("POST", "/api/v1/admin/_destructive", nil)
	req.Header.Set("X-CSRF-Token", s.CSRF)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("non-admin with step-up must still be refused: %d", rr.Code)
	}
}
