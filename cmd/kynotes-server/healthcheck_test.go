package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProbeHealth(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ok.Close()
	if err := probeHealth(ok.URL + "/healthz"); err != nil {
		t.Fatal(err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	if probeHealth(bad.URL+"/healthz") == nil {
		t.Fatal("500 passed")
	}
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://example.com/", 302) }))
	defer redir.Close()
	if probeHealth(redir.URL+"/healthz") == nil {
		t.Fatal("redirect followed")
	}
}

func TestProbeHealthTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	defer slow.Close()
	start := time.Now()
	if probeHealth(slow.URL+"/healthz") == nil {
		t.Fatal("timeout passed")
	}
	if time.Since(start) > 6*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestProbeHealthRefusesNonLoopback(t *testing.T) {
	for _, u := range []string{"http://example.com/healthz", "http://10.0.0.5:8080/healthz", "http://0.0.0.0:8080/healthz", "https://127.0.0.1/healthz", "file:///etc/passwd", "http://127.0.0.1@evil.com/healthz", "http://127.0.0.1.evil.com/healthz", "http://localhost.evil.com/healthz", "http://localhost:8080/healthz"} {
		if probeHealth(u) == nil {
			t.Fatal("accepted", u)
		}
	}
}

// Docker runs this every 30 s: it must not mint secrets or probe-write the data directory.
func TestHealthcheckWritesNothing(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ok.Close()
	_, port, err := net.SplitHostPort(ok.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "kynotes.yaml")
	if err = os.WriteFile(cfgPath, []byte("data_dir: "+dir+"\nserver:\n  bind: 127.0.0.1:"+port+"\n  dev_insecure_cookies: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = healthcheckCommand([]string{"--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("healthcheck wrote into the data directory: %v %v", entries, err)
	}
}

func TestDefaultHealthURL(t *testing.T) {
	got, err := defaultHealthURL("0.0.0.0:9090")
	if err != nil || got != "http://127.0.0.1:9090/healthz" {
		t.Fatal(got, err)
	}
}

func TestProbeHealthIPv6Loopback(t *testing.T) {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	defer srv.Close()
	if err := probeHealth(srv.URL + "/healthz"); err != nil {
		t.Fatal(err)
	}
}
