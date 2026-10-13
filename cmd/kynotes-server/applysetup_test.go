package main

import (
	"bytes"
	"context"
	"encoding/base64"
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
	// A setup command contacts an already initialized running server. Prepare
	// its durable keys in the fixture; the setup CLI itself must not mint them.
	if _, err := config.Load(cfgPath); err != nil {
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

func TestApplySetupCapabilitiesAndReadOnlyDispatch(t *testing.T) {
	var out, errb bytes.Buffer
	if code := applySetupCommand([]string{"--capabilities"}, &out, &errb); code != 0 || !strings.Contains(out.String(), `"check"`) || !strings.Contains(out.String(), `"dedicated-admin"`) || !strings.Contains(out.String(), `"protected-setup-files"`) {
		t.Fatal(code, out.String(), errb.String())
	}
	cfgPath, bundle, dataDir := setupCLIFixture(t)
	l, err := net.Listen("unix", filepath.Join(dataDir, "admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/check-setup" {
			t.Errorf("inspection sent mutation %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"version":1,"results":[{"section":"backup.keep","status":"present"}],"handover":{}}`)
	})}
	go srv.Serve(l)
	defer srv.Close()
	out.Reset()
	if code := applySetupCommand([]string{"--file", bundle, "--config", cfgPath, "--check"}, &out, &errb); code != 0 {
		t.Fatal(code, errb.String())
	}
}

func TestApplySetupStagesMetadataWithoutSocketOrCredentials(t *testing.T) {
	cfg, _, dir := setupCLIFixture(t)
	file := filepath.Join(dir, "installer", "setup.json")
	for i, check := range []bool{false, true, false} {
		args := []string{"--stage", "--file", file, "--config", cfg}
		if check {
			args = append(args, "--check")
		}
		var out, errb bytes.Buffer
		code := applySetupCommandInput(args, strings.NewReader(`{"version":1,"backup":{"keep":7}}`), &out, &errb)
		status := "present"
		if i == 0 {
			status = "created"
		}
		if code != 0 || !strings.Contains(out.String(), `"schema":"kynotes.setup-preparation/1"`) || !strings.Contains(out.String(), `"status":"`+status+`"`) {
			t.Fatal(code, out.String(), errb.String())
		}
	}
	var out, errb bytes.Buffer
	if code := applySetupCommandInput([]string{"--stage", "--file", file, "--config", cfg}, strings.NewReader(`{"version":1,"clientSecret":"never-echo-preparation-secret"}`), &out, &errb); code != applysetup.ExitInvalid || out.Len() != 0 || strings.Contains(errb.String(), "never-echo-preparation-secret") {
		t.Fatal(code, out.String(), errb.String())
	}
}

func TestApplySetupImportsScopedCredentialsWithoutSocket(t *testing.T) {
	cfg, _, dir := setupCLIFixture(t)
	file := filepath.Join(dir, "installer", "setup.json")
	issuer, callback := "https://identity.example.test", "https://notes.example.test/api/v1/auth/oidc/callback"
	metadata, _ := json.Marshal(map[string]any{"version": 1, "sso": map[string]string{"issuerUrl": issuer, "clientId": "notes", "redirectUri": callback, "clientSecretFile": filepath.Join(dir, "installer", "client.secret")}, "admins": []applysetup.Admin{{Issuer: issuer, Subject: "owner-subject", Username: "owner-admin"}}})
	var out, errb bytes.Buffer
	if code := applySetupCommandInput([]string{"--stage", "--file", file, "--config", cfg}, bytes.NewReader(metadata), &out, &errb); code != 0 {
		t.Fatal("metadata stage failed", code)
	}
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'s'}, 32))
	frame, _ := json.Marshal(map[string]any{"schema": "kyidentity.client-credentials/1", "setupId": "271333e2-c221-4601-b249-563b3d828530", "issuerUrl": issuer, "clientId": "notes", "redirectUris": []string{callback}, "clientSecret": secret, "administrator": map[string]string{"subject": "owner-subject", "username": "owner-admin", "role": "kynotes.admin"}})
	args := []string{"--import-client", "--file", file, "--config", cfg}
	for i, check := range []bool{false, true, false} {
		out.Reset()
		errb.Reset()
		flags := append([]string(nil), args...)
		if check {
			flags = append(flags, "--check")
		}
		code := applySetupCommandInput(flags, bytes.NewReader(append([]byte(nil), frame...)), &out, &errb)
		status := "present"
		if i == 0 {
			status = "created"
		}
		if code != 0 || out.String() != `{"schema":"kynotes.client-import/1","status":"`+status+`"}`+"\n" || errb.Len() != 0 {
			t.Fatal("native import dispatch or safe response failed", code)
		}
	}
	req, err := applysetup.Load(file, false)
	if err != nil || req.SSO.ClientSecret != secret {
		t.Fatal("native setup cannot read imported credential")
	}
	for _, extra := range []string{"--stage", "--capabilities"} {
		out.Reset()
		errb.Reset()
		if code := applySetupCommandInput(append(append([]string(nil), args...), extra), bytes.NewReader(frame), &out, &errb); code != applysetup.ExitInvalid || out.Len() != 0 || strings.Contains(errb.String(), secret) {
			t.Fatal("invalid combined import mode accepted or disclosed input")
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "admin.sock")); !os.IsNotExist(err) {
		t.Fatal("credential import created a server socket")
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
