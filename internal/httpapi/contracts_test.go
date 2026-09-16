package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
)

func testRouter(max int64) http.Handler {
	return NewRouter(logging.New(io.Discard, "info", "json"), max, func() bool { return true })
}

func TestUnknownRouteReturnsErrorEnvelope(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/missing", nil)
	w := httptest.NewRecorder()
	testRouter(1024).ServeHTTP(w, r)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
}

func TestErrorEnvelopeShapeIsStable(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/missing", nil)
	w := httptest.NewRecorder()
	testRouter(1024).ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), `"code":"method_not_allowed"`) || !strings.Contains(w.Body.String(), `"requestId"`) {
		t.Fatalf("unexpected envelope: %s", w.Body.String())
	}
}

func TestRequestIDIsEchoedAndGeneratedWhenUntrusted(t *testing.T) {
	c := config.Defaults()
	c.Server.TrustedProxies = []string{"127.0.0.1/32"}
	h := NewRouter(logging.New(io.Discard, "info", "json"), 1024, func() bool { return true }, c)
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Request-Id", "trusted-request")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("X-Request-Id") != "trusted-request" {
		t.Fatal("trusted request id was not echoed")
	}
	r = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("X-Request-Id", "untrusted-request")
	w = httptest.NewRecorder()
	testRouter(1024).ServeHTTP(w, r)
	if w.Header().Get("X-Request-Id") == "untrusted-request" || w.Header().Get("X-Request-Id") == "" {
		t.Fatal("untrusted request id was accepted or omitted")
	}
}

func TestPanicBecomesInternalWithoutLeakingStack(t *testing.T) {
	h := Middleware(logging.New(io.Discard, "info", "json"), 1024)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("secret-stack-marker") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "secret-stack-marker") || strings.Contains(w.Body.String(), "goroutine") {
		t.Fatalf("panic leaked: status=%d body=%s", w.Code, w.Body)
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	w := httptest.NewRecorder()
	testRouter(1024).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	for _, name := range []string{"X-Content-Type-Options", "Referrer-Policy", "Cache-Control", "Content-Security-Policy", "X-Frame-Options"} {
		if w.Header().Get(name) == "" {
			t.Errorf("missing %s", name)
		}
	}
}

func TestOversizedJSONBodyIsRejected(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader([]byte(strings.Repeat("x", 100))))
	w := httptest.NewRecorder()
	testRouter(16).ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
}

func TestHealthzIgnoresDatabaseState(t *testing.T) {
	w := httptest.NewRecorder()
	NewRouter(logging.New(io.Discard, "info", "json"), 1024, func() bool { return false }).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestReadyzFailsBeforeMigrations(t *testing.T) {
	w := httptest.NewRecorder()
	NewRouter(logging.New(io.Discard, "info", "json"), 1024, func() bool { return false }).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestNoUserDataRouteIsRegistered(t *testing.T) {
	for _, path := range []string{"/api/v1/users", "/api/v1/search", "/api/v1/markdown"} {
		w := httptest.NewRecorder()
		testRouter(1024).ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code == http.StatusOK {
			t.Fatalf("unexpected user-data route %s", path)
		}
	}
}
