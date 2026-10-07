package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
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

// e2eIssuer serves discovery as https://example.com:<port> and routes the default
// transport (used by sso.DiscoverEndpoints) to it.
func e2eIssuer(t *testing.T) string {
	t.Helper()
	var issuer string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"})
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	issuer = "https://example.com:" + port
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: "example.com"}
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	old := http.DefaultTransport
	http.DefaultTransport = tr
	t.Cleanup(func() { http.DefaultTransport = old })
	return issuer
}

func TestApplySetupTwiceEndToEnd(t *testing.T) {
	issuer := e2eIssuer(t)
	dir := t.TempDir()
	backups := filepath.Join(dir, "backups")
	if err := os.Mkdir(backups, 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	cfgPath := filepath.Join(dir, "kynotes.yaml")
	yaml := fmt.Sprintf("data_dir: %s\nserver:\n  bind: %q\n  dev_insecure_cookies: true\nbackup:\n  dir: %s\n", dir, addr, backups)
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("kynotes.yaml", yaml)
	secret := write("oidc", "client-secret-value\n")
	hmac := write("hmac", "hmac-secret-value\n")
	bundle := write("bundle.json", fmt.Sprintf(`{"version":1,
 "sso":{"issuerUrl":%q,"clientId":"kynotes","clientSecretFile":%q,"redirectUri":"https://notes.example/api/v1/auth/oidc/callback","directoryHmacSecretFile":%q},
 "admins":[{"issuer":%q,"subject":"sub-owner","username":"owner-admin"}],
 "backup":{"dir":%q,"keep":7,"depositInterval":"24h"}}`, issuer, secret, hmac, issuer, backups))

	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx, c, logging.New(io.Discard, "info", "json"), "e2e") }()
	sock := app.AdminSocketPath(dir)
	for deadline := time.Now().Add(5 * time.Second); ; {
		if conn, err := net.Dial("unix", sock); err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("admin socket never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	run := func() applysetup.Report {
		t.Helper()
		var out, errb bytes.Buffer
		if code := applySetupCommand([]string{"--file", bundle, "--config", cfgPath}, &out, &errb); code != 0 {
			t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
		}
		for _, s := range []string{"client-secret-value", "hmac-secret-value"} {
			if strings.Contains(out.String(), s) || strings.Contains(errb.String(), s) {
				t.Fatalf("%s printed", s)
			}
		}
		var r applysetup.Report
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	statuses := func(r applysetup.Report) map[string]applysetup.Status {
		m := map[string]applysetup.Status{}
		for _, x := range r.Results {
			m[x.Section] = x.Status
		}
		return m
	}

	first := statuses(run())
	want := map[string]applysetup.Status{"sso": "created", "admin:owner-admin": "created", "backup.dir": "present", "backup.keep": "present", "backup.interval": "created"}
	for k, v := range want {
		if first[k] != v {
			t.Fatalf("first run %s: %s (%v)", k, first[k], first)
		}
	}
	second := run()
	if len(second.Results) != len(want) {
		t.Fatalf("second run: %+v", second.Results)
	}
	for _, x := range second.Results {
		if x.Status != applysetup.Present {
			t.Fatalf("second run %s: %s", x.Section, x.Status)
		}
	}
	if h := second.Handover; h.URL != "https://notes.example" || len(h.AdminUsernames) != 1 || h.BackupDir != backups || h.Version != "e2e" {
		t.Fatalf("handover %+v", h)
	}

	// The live router sees the new settings without a restart.
	resp, err := (&http.Client{Transport: &http.Transport{}}).Get("http://" + addr + "/api/v1/auth/sso-config")
	if err != nil {
		t.Fatal(err)
	}
	var live map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&live)
	resp.Body.Close()
	if live["enabled"] != true || live["issuerUrl"] != issuer {
		t.Fatalf("sso-config %v", live)
	}

	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "kynotes.sqlite")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var rows int
	err = db.QueryRow(`SELECT count(*) FROM audit_events WHERE actor_user_id=? AND request_id=?`, applysetup.Actor, applysetup.RequestID).Scan(&rows)
	db.Close()
	if err != nil || rows != 3 {
		t.Fatalf("apply-setup audit rows: %d (%v); want sso, admin, schedule", rows, err)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sock); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("socket left after shutdown")
	}
}
