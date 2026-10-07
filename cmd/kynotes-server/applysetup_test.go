package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/app"
	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
)

func setupCLIFixture(t *testing.T) (cfgPath, bundle, dataDir string) {
	t.Helper()
	dataDir = t.TempDir()
	cfgPath = filepath.Join(dataDir, "kynotes.yaml")
	bundle = filepath.Join(dataDir, "bundle.json")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dataDir+"\nserver:\n  bind: 127.0.0.1:0\n  dev_insecure_cookies: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, []byte(`{"version":1,"backup":{"keep":7}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, bundle, dataDir
}

func fakeSetupServer(t *testing.T, dataDir string, status int, body string) {
	t.Helper()
	l, err := net.Listen("unix", filepath.Join(dataDir, "admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func TestApplySetupExitCodes(t *testing.T) {
	report := func(status string) string {
		return `{"version":1,"results":[{"section":"backup.keep","status":"` + status + `"}],"handover":{}}` + "\n"
	}
	for _, c := range []struct {
		name   string
		status int
		body   string
		want   int
	}{
		{"applied", 200, report("present"), 0},
		{"conflict", 200, report("conflict"), 3},
		{"invalid on server", 200, report("invalid"), 2},
		{"failed", 200, report("failed"), 1},
		{"rejected", 400, `{"error":{"code":"invalid_bundle","message":"version: want 1"}}`, 2},
		{"busy", 409, `{"error":{"code":"apply_in_progress","message":"apply-setup is already running"}}`, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfgPath, bundle, dataDir := setupCLIFixture(t)
			fakeSetupServer(t, dataDir, c.status, c.body)
			var out, errb bytes.Buffer
			if got := applySetupCommand([]string{"--file", bundle, "--config", cfgPath}, &out, &errb); got != c.want {
				t.Fatalf("exit %d, stderr %s", got, errb.String())
			}
			if c.status == 200 && out.String() != c.body {
				t.Fatalf("stdout %q", out.String())
			}
			if c.status != 200 && !strings.Contains(errb.String(), "already running") && !strings.Contains(errb.String(), "version: want 1") {
				t.Fatalf("stderr %q", errb.String())
			}
		})
	}
}

func TestApplySetupLocalFailures(t *testing.T) {
	cfgPath, bundle, _ := setupCLIFixture(t)
	var out, errb bytes.Buffer
	if got := applySetupCommand([]string{"--file", bundle, "--config", cfgPath}, &out, &errb); got != 1 || !strings.Contains(errb.String(), "not running") {
		t.Fatalf("no server: %d %q", got, errb.String())
	}
	if err := os.WriteFile(bundle, []byte(`{"version":1,"sso":{"clientSecret":"inline-secret-value"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if got := applySetupCommand([]string{"--file", bundle, "--config", cfgPath}, &out, &errb); got != 2 || strings.Contains(errb.String(), "inline-secret-value") {
		t.Fatalf("inline secret: %d %q", got, errb.String())
	}
	if got := applySetupCommand([]string{"--config", cfgPath}, &out, &errb); got != 2 {
		t.Fatalf("missing --file: %d", got)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout written on failure: %q", out.String())
	}
}

func TestApplySetupAgainstRunningServer(t *testing.T) {
	cfgPath, bundle, _ := setupCLIFixture(t)
	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx, c, logging.New(io.Discard, "info", "json"), "e2e") }()
	t.Cleanup(func() { cancel(); <-done })
	var out, errb bytes.Buffer
	for deadline := time.Now().Add(5 * time.Second); ; {
		out.Reset()
		errb.Reset()
		code := applySetupCommand([]string{"--file", bundle, "--config", cfgPath}, &out, &errb)
		if !strings.Contains(errb.String(), "not running") {
			if code != applysetup.ExitOK {
				t.Fatalf("exit %d stdout %s stderr %s", code, out.String(), errb.String())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server never answered")
		}
		time.Sleep(20 * time.Millisecond)
	}
	var report applysetup.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Handover.Version != "e2e" || errb.Len() != 0 {
		t.Fatalf("report %q stderr %q err %v", out.String(), errb.String(), err)
	}
}
