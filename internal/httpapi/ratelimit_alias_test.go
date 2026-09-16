package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
