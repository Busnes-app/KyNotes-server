package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
