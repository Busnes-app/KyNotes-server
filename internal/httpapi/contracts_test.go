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

func TestLivezIgnoresDatabaseState(t *testing.T) {
	w := httptest.NewRecorder()
	NewRouter(logging.New(io.Discard, "info", "json"), 1024, func() bool { return false }).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
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
	// /api/v1/users/{id}/identity is the only per-user route: public key and fingerprint.
	for _, path := range []string{"/api/v1/users", "/api/v1/users/usr_0123456789abcdefghjkmnpqrs", "/api/v1/search", "/api/v1/markdown"} {
		w := httptest.NewRecorder()
		testRouter(1024).ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code == http.StatusOK {
			t.Fatalf("unexpected user-data route %s", path)
		}
	}
}

// The legacy review and the comment re-seal served only the login-derived content key, which is
// gone. A registered route answers 401 to an unauthenticated request through its session
// middleware; an unregistered one never reaches it. The envelope list is the control: it proves
// this server registers the team-key routes at all.
func TestRemovedLegacyRoutesStayGone(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	send := func(method, path string) int {
		req, _ := http.NewRequest(method, p.url+path, strings.NewReader("{}"))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if code := send(http.MethodGet, "/api/v1/containers/cnt_0123456789abcdefghjkmnpqrs/envelopes"); code != http.StatusUnauthorized {
		t.Fatalf("control route=%d, want 401", code)
	}
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/containers/cnt_0123456789abcdefghjkmnpqrs/legacy"},
		{http.MethodPut, "/api/v1/comments/cmt_0123456789abcdefghjkmnpqrs"},
	} {
		if code := send(route.method, route.path); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s=%d, want an unregistered route", route.method, route.path, code)
		}
	}
}
