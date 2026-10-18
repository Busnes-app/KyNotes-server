package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

type healthReply struct {
	Schema  string    `json:"schema"`
	Service string    `json:"service"`
	Status  string    `json:"status"`
	Time    time.Time `json:"time"`
	Checks  []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"checks"`
}

func probeHealth(t *testing.T, h http.Handler) (int, healthReply) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var got healthReply
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return w.Code, got
}

func TestHealthzChecksStartupAndMigratedDatabase(t *testing.T) {
	s, err := storage.Open(filepath.Join(t.TempDir(), "notes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	readyCalls := 0
	h := NewRouter(logging.New(io.Discard, "info", "json"), 1024, func() bool {
		readyCalls++
		return true
	}, s.DB())
	code, got := probeHealth(t, h)
	if code != 200 || got.Schema != "ky.health/1" || got.Service != "kynotes" || got.Status != "ok" || got.Time.IsZero() || len(got.Checks) != 2 || got.Checks[0].Name != "startup" || got.Checks[0].Status != "ok" || got.Checks[1].Name != "database" || got.Checks[1].Status != "ok" {
		t.Fatalf("health=%d %+v", code, got)
	}
	_, cached := probeHealth(t, h)
	if !cached.Time.Equal(got.Time) {
		t.Fatalf("health evaluation was not cached: %s then %s", got.Time, cached.Time)
	}
	if readyCalls != 1 {
		t.Fatalf("startup check ran %d times, want one cached evaluation", readyCalls)
	}
}

func TestHealthzFailsWhenDatabaseClosedBeforeFirstProbe(t *testing.T) {
	s, err := storage.Open(filepath.Join(t.TempDir(), "notes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	h := NewRouter(logging.New(io.Discard, "info", "json"), 1024, func() bool { return true }, s.DB())
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	code, got := probeHealth(t, h)
	if code != 503 || got.Status != "down" || len(got.Checks) != 2 || got.Checks[1].Name != "database" || got.Checks[1].Status != "down" {
		t.Fatalf("health=%d %+v", code, got)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if w.Code != 200 {
		t.Fatalf("livez=%d", w.Code)
	}
}

func TestHealthzFailsWhenStartupNotReady(t *testing.T) {
	h := NewRouter(logging.New(io.Discard, "info", "json"), 1024, func() bool { return false })
	code, got := probeHealth(t, h)
	if code != 503 || got.Status != "down" || len(got.Checks) != 1 || got.Checks[0].Name != "startup" || got.Checks[0].Status != "down" {
		t.Fatalf("health=%d %+v", code, got)
	}
	for _, path := range []string{"/livez", "/readyz"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		want := 200
		if path == "/readyz" {
			want = 503
		}
		if w.Code != want {
			t.Fatalf("%s=%d, want %d", path, w.Code, want)
		}
	}
}

func TestCookieBearingProbesBypassSessionLookup(t *testing.T) {
	s, err := storage.Open(filepath.Join(t.TempDir(), "notes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.DB().SetMaxOpenConns(1)
	h := NewRouter(logging.New(io.Discard, "info", "json"), 1024, func() bool { return true }, s.DB())
	if code, got := probeHealth(t, h); code != 200 || got.Status != "ok" {
		t.Fatalf("prime health cache: %d %+v", code, got)
	}
	cookie := &http.Cookie{Name: "kynotes_session", Value: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	for _, path := range []string{"/livez", "/healthz"} {
		conn, err := s.DB().Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan int, 1)
		go func() {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			done <- w.Code
		}()
		blocked := false
		select {
		case code := <-done:
			if code != 200 {
				t.Errorf("%s returned %d, want 200", path, code)
			}
		case <-time.After(200 * time.Millisecond):
			t.Errorf("%s waited for an unrelated SQLite session lookup", path)
			blocked = true
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if blocked {
			<-done
		}
	}
}

// TestHealthzWireContract pins ky.health/1 as KyPulse reads it, through the full router:
// exact fields, no version or error text, headers, HEAD served, other methods refused.
func TestHealthzWireContract(t *testing.T) {
	s, err := storage.Open(filepath.Join(t.TempDir(), "notes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := NewRouter(logging.New(io.Discard, "info", "json"), 1024, func() bool { return true }, s.DB())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET /healthz = %d %q %q", w.Code, w.Header().Get("Content-Type"), w.Header().Get("Cache-Control"))
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	keys := func(m map[string]json.RawMessage) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	if got := strings.Join(keys(body), ","); got != "checks,schema,service,status,time" {
		t.Fatalf("top-level fields = %s", got)
	}
	var stamp string
	if err := json.Unmarshal(body["time"], &stamp); err != nil {
		t.Fatal(err)
	}
	if ts, err := time.Parse(time.RFC3339, stamp); err != nil || !strings.HasSuffix(stamp, "Z") || ts.Nanosecond() != 0 {
		t.Fatalf("time = %q, want UTC RFC 3339 whole seconds", stamp)
	}
	var checks []map[string]json.RawMessage
	if err := json.Unmarshal(body["checks"], &checks); err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if got := strings.Join(keys(c), ","); got != "name,status" {
			t.Fatalf("healthy check fields = %s", got)
		}
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodHead, "/healthz", nil))
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("HEAD /healthz = %d with %d body bytes", w.Code, w.Body.Len())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if w.Code < 400 {
		t.Fatalf("POST /healthz = %d, want refused", w.Code)
	}
}
