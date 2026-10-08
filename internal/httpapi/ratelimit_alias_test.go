package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
)

// TestRateLimitCoversUnversionedAliases guards the fact that every /api/v1/…
// route is also registered under /api/…. A limiter keyed on the versioned
// spelling alone is opt-out: the caller just drops "v1" from the URL.
func TestRateLimitCoversUnversionedAliases(t *testing.T) {
	cfg := config.Defaults()
	cfg.RateLimit.LoginPerMinute = 1

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := rateLimitMiddleware(cfg, nil, next)

	call := func(path string) int {
		req := httptest.NewRequest("POST", path, nil)
		req.RemoteAddr = "203.0.113.7:44444"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := call("/api/v1/auth/login"); got != http.StatusOK {
		t.Fatalf("first login returned %d, want 200", got)
	}
	if got := call("/api/v1/auth/login"); got != http.StatusTooManyRequests {
		t.Fatalf("second login returned %d, want 429 (bucket size is 1)", got)
	}

	for _, alias := range []string{"/api/auth/login", "/api/auth/login-params"} {
		if got := call(alias); got != http.StatusTooManyRequests {
			t.Fatalf("%s returned %d after the bucket was spent, want 429", alias, got)
		}
	}
}

// TestRateLimitDoesNotOverreach keeps the canonicalisation from folding
// unrelated paths into a limited bucket.
func TestRateLimitDoesNotOverreach(t *testing.T) {
	cfg := config.Defaults()
	cfg.RateLimit.LoginPerMinute = 1

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := rateLimitMiddleware(cfg, nil, next)

	call := func(path string) int {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "203.0.113.8:44444"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < 5; i++ {
		if got := call("/api/v1/containers"); got != http.StatusOK {
			t.Fatalf("unlimited route returned %d on call %d, want 200", got, i)
		}
	}
	if got := call("/healthz"); got != http.StatusOK {
		t.Fatalf("/healthz returned %d, want 200", got)
	}
}

func TestRateLimitStillUsesAuthenticatedUserAcrossIPs(t *testing.T) {
	db, cfg := setupTestDB(t)
	cfg.RateLimit.PairingPerHour = 1
	userID, _ := createAdminUser(t, db)
	cookies := httptest.NewRecorder()
	if _, err := auth.MintSession(db, cookies, userID, true, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	h := rateLimitMiddleware(cfg, db, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i, ip := range []string{"203.0.113.1:1234", "203.0.113.2:1234"} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/devices/pairing-token", nil)
		r.RemoteAddr = ip
		for _, c := range cookies.Result().Cookies() {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := http.StatusOK
		if i == 1 {
			want = http.StatusTooManyRequests
		}
		if w.Code != want {
			t.Fatalf("request from %s returned %d, want %d", ip, w.Code, want)
		}
	}
}

func TestInvitationCreationIsRateLimitedPerCaller(t *testing.T) {
	cfg := config.Defaults()
	if cfg.RateLimit.InvitationPerHour != 30 {
		t.Fatalf("default invitation_per_hour=%d, want 30", cfg.RateLimit.InvitationPerHour)
	}
	cfg.RateLimit.InvitationPerHour = 2
	h := rateLimitMiddleware(cfg, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	call := func(method, path, ip string) int {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = ip
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	const team = "/api/v1/containers/cnt_aaaaaaaaaaaaaaaaaaaaaaaaaa/invitations"
	for i := 0; i < 2; i++ {
		if got := call(http.MethodPost, team, "203.0.113.20:1"); got != http.StatusOK {
			t.Fatalf("invitation %d=%d", i, got)
		}
	}
	for _, path := range []string{"/api/v1/containers/cnt_bbbbbbbbbbbbbbbbbbbbbbbbbb/invitations", "/api/containers/cnt_aaaaaaaaaaaaaaaaaaaaaaaaaa/invitations"} {
		if got := call(http.MethodPost, path, "203.0.113.20:1"); got != http.StatusTooManyRequests {
			t.Fatalf("%s after the bucket was spent=%d, want 429", path, got)
		}
	}
	if got := call(http.MethodPost, team, "203.0.113.21:1"); got != http.StatusOK {
		t.Fatalf("another caller=%d", got)
	}
	if got := call(http.MethodPost, "/api/v1/invitations/inv_aaaaaaaaaaaaaaaaaaaaaaaaaa/accept", "203.0.113.20:1"); got != http.StatusOK {
		t.Fatalf("accept was limited: %d", got)
	}
}

func TestRetryAfterFollowsRefillInterval(t *testing.T) {
	cfg := config.Defaults()
	cfg.RateLimit.InvitationPerHour = 30
	h := rateLimitMiddleware(cfg, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	var rec *httptest.ResponseRecorder
	for i := 0; i < 31; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/cnt_aaaaaaaaaaaaaaaaaaaaaaaaaa/invitations", nil)
		req.RemoteAddr = "203.0.113.30:1"
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "120" {
		t.Fatalf("code=%d Retry-After=%q, want 429 and 120", rec.Code, rec.Header().Get("Retry-After"))
	}
}
