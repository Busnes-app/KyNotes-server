//go:build kye2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/app"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
)

type runtimeFixture struct {
	db            *sql.DB
	c             config.Config
	objects       map[string][]byte
	mu            sync.Mutex
	identityCalls atomic.Int32
	polls         atomic.Int32
	wrong         bool
}
type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func runtimeSetup(t *testing.T) *runtimeFixture {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("KYNOTES_TEST_DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("set TEST_POSTGRES_DSN or KYNOTES_TEST_DATABASE_URL for native Serve runtime")
	}
	root, err := sql.Open("kynotespg", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	schema := fmt.Sprintf("serve_%d", time.Now().UnixNano())
	if _, err = root.Exec(`CREATE SCHEMA "` + schema + `"`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = root.Exec(`DROP SCHEMA "` + schema + `" CASCADE`) })
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	f := &runtimeFixture{objects: map[string][]byte{}}
	f.db, err = sql.Open("kynotespg", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Close() })
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			f.polls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.Path, "erased") {
				io.WriteString(w, `{"subjects":[],"next":""}`)
			} else {
				io.WriteString(w, `{"orgs":[]}`)
			}
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		key := strings.TrimPrefix(r.URL.Path, "/bucket/")
		if strings.HasPrefix(key, "control/") {
			f.identityCalls.Add(1)
		}
		if r.URL.Query().Get("list-type") != "" {
			io.WriteString(w, `<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`)
			return
		}
		switch r.Method {
		case "PUT":
			if _, ok := f.objects[key]; ok && r.Header.Get("If-None-Match") == "*" {
				w.WriteHeader(412)
				return
			}
			raw, _ := io.ReadAll(r.Body)
			f.objects[key] = raw
			w.Header().Set("ETag", `"runtime"`)
		case "GET":
			raw, ok := f.objects[key]
			if !ok {
				w.WriteHeader(404)
				return
			}
			if f.wrong && key == "control/store-id" {
				raw = bytes.Repeat([]byte("x"), 43)
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(raw)))
			w.Write(raw)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	old := http.DefaultTransport
	http.DefaultTransport = transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "id.runtime.test" {
			copy := r.Clone(r.Context())
			target, _ := url.Parse(server.URL)
			copy.URL.Host = target.Host
			return transport.RoundTrip(copy)
		}
		return transport.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = old; transport.CloseIdleConnections() })
	for key, value := range map[string]string{
		"KYNOTES_TENANCY": "multi", "KYNOTES_DB_DSN": u.String(), "KYNOTES_STAFF_ORG_ID": "org_staff", "KYNOTES_REGION": "test-region",
		"KYNOTES_SECRETS_PAIRING_SECRET": strings.Repeat("p", 32), "KYNOTES_SECRETS_SERVER_SALT_KEY": strings.Repeat("s", 32),
		"KYNOTES_SSO_ISSUER": "https://id.runtime.test", "KYNOTES_SSO_CLIENT_ID": "kynotes", "KYNOTES_SSO_CLIENT_SECRET": "runtime-secret", "KYNOTES_SSO_HMAC_SECRET": strings.Repeat("h", 32),
		"KYNOTES_VAPID_KEY":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		"KYNOTES_BLOB_BACKEND": "object", "KYNOTES_BLOB_S3_ENDPOINT": server.URL, "KYNOTES_BLOB_S3_BUCKET": "bucket", "KYNOTES_BLOB_S3_REGION": "test-region",
		"KYNOTES_BLOB_S3_ACCESS_KEY": "runtime-access", "KYNOTES_BLOB_S3_SECRET": "runtime-secret", "BOOTSTRAP_ADMIN_PASS": "", "BOOTSTRAP_EVERYDAY_USER": "", "BOOTSTRAP_EVERYDAY_PASS": "", "PUSH_RELAY_URL": "", "APNS_RELAY_URL": "",
	} {
		t.Setenv(key, value)
	}
	for _, key := range []string{"KYNOTES_BLOB_S3_ACCESS_KEY_FILE", "KYNOTES_BLOB_S3_SECRET_FILE"} {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}
	f.c = config.Defaults()
	f.c.DataDir = t.TempDir()
	f.c.Server.DevInsecureCookies = true
	f.c.Backup.DepositInterval = "0"
	f.c.GC.Interval = "1s"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.c.Server.Bind = listener.Addr().String()
	listener.Close()
	return f
}
func (f *runtimeFixture) start(t *testing.T) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		defer close(done)
		done <- app.Serve(ctx, f.c, logging.New(io.Discard, "info", "json"), "runtime-test")
	}()
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("runtime did not stop during cleanup")
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("Serve stopped before readiness: %v", err)
		default:
		}
		response, err := http.Get("http://" + f.c.Server.Bind + "/readyz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				return stop, done
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Serve never became ready")
	return nil, nil
}
func TestMultiServeRuntime(t *testing.T) {
	f := runtimeSetup(t)
	stop, done := f.start(t)
	for _, path := range []string{"/livez", "/readyz", "/healthz", "/api/v1/auth/sso-config"} {
		res, err := http.Get("http://" + f.c.Server.Bind + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("%s: %d %s", path, res.StatusCode, body)
		}
		if path == "/api/v1/auth/sso-config" && !bytes.Contains(body, []byte(`"enabled":true`)) {
			t.Fatalf("fixed SSO not wired: %s", body)
		}
	}
	for _, name := range []string{"kynotes.sqlite", ".kynotes.lock", "secrets/setup.token", "secrets/vapid.key"} {
		if _, err := os.Stat(filepath.Join(f.c.DataDir, name)); !os.IsNotExist(err) {
			t.Fatalf("single-mode artifact %s: %v", name, err)
		}
	}
	var count int
	if err := f.db.QueryRow(`SELECT count(*) FROM server_settings WHERE key LIKE 'sso_%'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("SSO secrets persisted: %d %v", count, err)
	}
	if f.identityCalls.Load() < 2 {
		t.Fatal("bucket identity protocol was skipped")
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.polls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f.polls.Load() == 0 {
		t.Fatal("elected directory schedules never ran")
	}
	stop()
	// Readiness withdraws while the listener remains available for proxy convergence.
	deadline = time.Now().Add(time.Second)
	withdrawn := false
	for time.Now().Before(deadline) {
		res, err := http.Get("http://" + f.c.Server.Bind + "/readyz")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 503 {
				withdrawn = true
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	if !withdrawn {
		t.Fatal("drain did not withdraw readiness before stopping HTTP")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Serve did not drain")
	}
	calls := f.polls.Load()
	time.Sleep(1100 * time.Millisecond)
	if f.polls.Load() != calls {
		t.Fatal("worker survived Serve")
	}
	// A drifted replica fails before making any bucket request.
	old := f.identityCalls.Load()
	changed := f.c
	changed.RateLimit.LoginPerMinute++
	err := app.Serve(context.Background(), changed, logging.New(io.Discard, "info", "json"), "test")
	if err == nil || !strings.Contains(err.Error(), "ratelimit") {
		t.Fatalf("fingerprint drift accepted: %v", err)
	}
	if f.identityCalls.Load() != old {
		t.Fatal("mismatched configuration contacted object store")
	}
	f.mu.Lock()
	f.wrong = true
	f.mu.Unlock()
	err = app.Serve(context.Background(), f.c, logging.New(io.Discard, "info", "json"), "test")
	if err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("wrong bucket identity accepted: %v", err)
	}
}
