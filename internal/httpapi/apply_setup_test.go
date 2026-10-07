package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/sso"
)

func TestRouterUsesSuppliedSSOStore(t *testing.T) {
	db, cfg := setupTestDB(t)
	store := sso.NewStore(db)
	h := NewRouter(logging.New(io.Discard, "info", "json"), 1<<20, func() bool { return true }, db, cfg, store)
	if err := store.Save(sso.SSOSettings{Enabled: true, IssuerURL: "https://id.example", ClientID: "kynotes"}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/auth/sso-config", nil))
	if !strings.Contains(rec.Body.String(), `"issuerUrl":"https://id.example"`) {
		t.Fatalf("router served stale SSO settings: %s", rec.Body.String())
	}
}

// setupIssuer serves OIDC discovery as https://example.com:<port> (a name the httptest
// certificate covers) and routes the default transport to it for this test.
func setupIssuer(t *testing.T, mismatch bool) string {
	t.Helper()
	var issuer string
	issuer = routeIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		doc := issuer
		if mismatch {
			doc = "https://other.example"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": doc, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"})
	})
	return issuer
}

func routeIssuer(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: "example.com"}
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	old := http.DefaultTransport
	http.DefaultTransport = tr
	t.Cleanup(func() { http.DefaultTransport = old })
	return "https://example.com:" + port
}

func setupAuditCount(t *testing.T, db *sql.DB, event string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE event=? AND actor_user_id=? AND request_id=?`, event, applysetup.Actor, applysetup.RequestID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func setupSSO(issuer string) applysetup.SSO {
	return applysetup.SSO{IssuerURL: issuer, ClientID: "kynotes", ClientSecret: "client-secret-value", RedirectURI: "https://notes.example/api/v1/auth/oidc/callback", HMACSecret: "hmac-secret-value"}
}

func TestApplySSOCreatesThenPresentThenConflict(t *testing.T) {
	db, _ := setupTestDB(t)
	store := sso.NewStore(db)
	want := setupSSO(setupIssuer(t, false))
	ctx := context.Background()
	if r := applySSO(ctx, db, store, want); r.Status != applysetup.Created {
		t.Fatalf("%+v", r)
	}
	if store.Load() != applysetup.WantSSO(want) {
		t.Fatalf("stored %+v", store.Load())
	}
	if r := applySSO(ctx, db, store, want); r.Status != applysetup.Present {
		t.Fatalf("%+v", r)
	}
	other := want
	other.ClientSecret = "different-secret-value"
	r := applySSO(ctx, db, store, other)
	if r.Status != applysetup.Conflict || !strings.Contains(r.Detail, "clientSecret") || strings.Contains(r.Detail, "secret-value") {
		t.Fatalf("%+v", r)
	}
	if store.Load() != applysetup.WantSSO(want) {
		t.Fatal("conflict overwrote settings")
	}
	if n := setupAuditCount(t, db, "admin.sso_update"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

func TestApplySSOProbeFailureStoresNothing(t *testing.T) {
	db, _ := setupTestDB(t)
	store := sso.NewStore(db)
	r := applySSO(context.Background(), db, store, setupSSO(setupIssuer(t, true)))
	if r.Status != applysetup.Invalid || !strings.Contains(r.Detail, "issuer metadata probe failed") {
		t.Fatalf("%+v", r)
	}
	if store.Load().IssuerURL != "" || setupAuditCount(t, db, "admin.sso_update") != 0 {
		t.Fatal("probe failure stored or audited settings")
	}
}

// An issuer that is down or overloaded is retryable (failed, exit 1); only a definite
// bad configuration is invalid (exit 2).
func TestApplySSOProbeOutageIsFailedNotInvalid(t *testing.T) {
	for _, c := range []struct {
		name string
		h    http.HandlerFunc
	}{
		{"503", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }},
		{"transport", func(w http.ResponseWriter, r *http.Request) {
			conn, _, _ := http.NewResponseController(w).Hijack()
			_ = conn.Close()
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			db, _ := setupTestDB(t)
			store := sso.NewStore(db)
			r := applySSO(context.Background(), db, store, setupSSO(routeIssuer(t, c.h)))
			if r.Status != applysetup.Failed || !strings.Contains(r.Detail, "issuer metadata probe failed") {
				t.Fatalf("%+v", r)
			}
			if store.Load().IssuerURL != "" {
				t.Fatal("outage stored settings")
			}
		})
	}
}

const setupTestIssuer = "https://id.example"

func TestApplyAdminCreatesBindingWithoutPassword(t *testing.T) {
	db, cfg := setupTestDB(t)
	want := applysetup.Admin{Issuer: setupTestIssuer, Subject: "sub-owner", Username: "Owner-Admin"}
	res, name := applyAdmin(db, cfg, setupTestIssuer, want)
	if res.Status != applysetup.Created || name != "owner-admin" {
		t.Fatalf("%+v %q", res, name)
	}
	var role, status, issuer, subject, hash string
	if err := db.QueryRow(`SELECT role,status,sso_issuer,sso_subject,auth_secret_hash FROM users WHERE username='owner-admin'`).Scan(&role, &status, &issuer, &subject, &hash); err != nil {
		t.Fatal(err)
	}
	if role != "admin" || status != "active" || issuer != setupTestIssuer || subject != "sub-owner" || hash == "" {
		t.Fatal(role, status, issuer, subject)
	}
	if res, _ = applyAdmin(db, cfg, setupTestIssuer, want); res.Status != applysetup.Present {
		t.Fatalf("%+v", res)
	}
	if n := setupAuditCount(t, db, "admin.user.create"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

func TestApplyAdminGrantRevokesCredentials(t *testing.T) {
	db, cfg := setupTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,status,sso_issuer,sso_subject,created_at,updated_at) VALUES('usr_b','owner','x','salt',600000,'user','active',?,'sub-owner',?,?)`, setupTestIssuer, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('ses_b','usr_b','tok','csrf',?,?,?)`, now, now, now); err != nil {
		t.Fatal(err)
	}
	res, name := applyAdmin(db, cfg, setupTestIssuer, applysetup.Admin{Issuer: setupTestIssuer, Subject: "sub-owner", Username: "owner-admin"})
	if res.Status != applysetup.Created || name != "owner" {
		t.Fatalf("%+v %q", res, name)
	}
	var role, revoked string
	_ = db.QueryRow(`SELECT role FROM users WHERE id='usr_b'`).Scan(&role)
	_ = db.QueryRow(`SELECT revoked_at FROM sessions WHERE id='ses_b'`).Scan(&revoked)
	if role != "admin" || revoked == "" {
		t.Fatalf("role=%q revoked_at=%q", role, revoked)
	}
	if n := setupAuditCount(t, db, "admin.user.update"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

func TestApplyAdminNeverAdoptsByUsername(t *testing.T) {
	db, cfg := setupTestDB(t)
	createAdminUser(t, db) // local, unbound account named "admin"
	res, name := applyAdmin(db, cfg, setupTestIssuer, applysetup.Admin{Issuer: setupTestIssuer, Subject: "sub-x", Username: "ADMIN"})
	if res.Status != applysetup.Conflict || name != "" {
		t.Fatalf("%+v %q", res, name)
	}
	var subject string
	_ = db.QueryRow(`SELECT coalesce(sso_subject,'') FROM users WHERE username='admin'`).Scan(&subject)
	if subject != "" || setupAuditCount(t, db, "admin.user.create")+setupAuditCount(t, db, "admin.user.update") != 0 {
		t.Fatal("local account was bound or audited")
	}
}

func TestApplyAdminRefusesDisabledBindingAndForeignIssuer(t *testing.T) {
	db, cfg := setupTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,status,sso_issuer,sso_subject,created_at,updated_at) VALUES('usr_d','gone','x','salt',600000,'user','disabled',?,'sub-gone',?,?)`, setupTestIssuer, now, now); err != nil {
		t.Fatal(err)
	}
	if res, _ := applyAdmin(db, cfg, setupTestIssuer, applysetup.Admin{Issuer: setupTestIssuer, Subject: "sub-gone", Username: "gone"}); res.Status != applysetup.Conflict {
		t.Fatalf("%+v", res)
	}
	// The configured issuer is the stored SSO setting: none stored, or a different one, is
	// invalid even when the bundle carries no sso section.
	want := applysetup.Admin{Issuer: setupTestIssuer, Subject: "sub-new", Username: "new"}
	for _, configured := range []string{"", "https://other.example"} {
		if res, _ := applyAdmin(db, cfg, configured, want); res.Status != applysetup.Invalid {
			t.Fatalf("issuer %q: %+v", configured, res)
		}
	}
	var n int
	_ = db.QueryRow(`SELECT count(*) FROM users WHERE username='new'`).Scan(&n)
	if n != 0 {
		t.Fatal("invalid admin was created")
	}
}

func TestSetupHandlerAppliesAndNeverEchoesSecrets(t *testing.T) {
	db, cfg := setupTestDB(t)
	issuer := setupIssuer(t, false)
	var logs bytes.Buffer
	h := SetupHandler(SetupDeps{DB: db, Config: cfg, SSO: sso.NewStore(db), Version: "test", Log: logging.New(&logs, "debug", "json")})
	s := setupSSO(issuer)
	body, _ := json.Marshal(applysetup.Request{Version: 1, SSO: &s, Admins: []applysetup.Admin{{Issuer: issuer, Subject: "sub-owner", Username: "owner-admin"}}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/apply-setup", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var report applysetup.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	h2 := report.Handover
	if report.ExitCode() != applysetup.ExitOK || len(report.Results) != 2 || h2.URL != "https://notes.example" || len(h2.AdminUsernames) != 1 || h2.AdminUsernames[0] != "owner-admin" || h2.Version != "test" {
		t.Fatalf("%+v", report)
	}
	for _, secret := range []string{"client-secret-value", "hmac-secret-value"} {
		var inAudit int
		_ = db.QueryRow(`SELECT count(*) FROM audit_events WHERE instr(reason_code,?)>0 OR instr(object_id,?)>0`, secret, secret).Scan(&inAudit)
		if strings.Contains(rec.Body.String(), secret) || strings.Contains(logs.String(), secret) || inAudit != 0 {
			t.Fatalf("%s leaked", secret)
		}
	}
	if !strings.Contains(logs.String(), "apply_setup") {
		t.Fatal("no apply_setup log line")
	}
}

func TestSetupHandlerRejectsInvalidRequests(t *testing.T) {
	db, cfg := setupTestDB(t)
	h := SetupHandler(SetupDeps{DB: db, Config: cfg, SSO: sso.NewStore(db), Log: logging.New(io.Discard, "info", "json")})
	for _, body := range []string{
		`{"version":2}`,
		`{"version":1,"extra":1}`,
		`{"version":1,"sso":{"issuerUrl":"http://id.example","clientId":"kynotes","clientSecret":"client-secret-value","redirectUri":"https://notes.example/api/v1/auth/oidc/callback"}}`,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/apply-setup", strings.NewReader(body)))
		if rec.Code != 400 || strings.Contains(rec.Body.String(), "client-secret-value") {
			t.Fatalf("%s → %d %s", body, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/apply-setup", strings.NewReader(`{"version":1,"backup":{"keep":7}}`)))
	var report applysetup.Report
	_ = json.Unmarshal(rec.Body.Bytes(), &report)
	if rec.Code != 200 || len(report.Results) != 1 || report.Results[0].Status != applysetup.Failed {
		t.Fatalf("backup section without a backup service: %d %s", rec.Code, rec.Body.String())
	}
}

// blockingRT holds every outbound request until release closes.
type blockingRT struct {
	inner            http.RoundTripper
	started, release chan struct{}
	once             *sync.Once
}

func (b blockingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return b.inner.RoundTrip(r)
}

func TestSetupDrainWaitsForInFlightApply(t *testing.T) {
	db, cfg := setupTestDB(t)
	issuer := setupIssuer(t, false)
	rt := blockingRT{inner: http.DefaultTransport, started: make(chan struct{}), release: make(chan struct{}), once: &sync.Once{}}
	http.DefaultTransport = rt
	store := sso.NewStore(db)
	h := SetupHandler(SetupDeps{DB: db, Config: cfg, SSO: store, Version: "test", Log: logging.New(io.Discard, "info", "json")})
	s := setupSSO(issuer)
	body, _ := json.Marshal(applysetup.Request{Version: 1, SSO: &s})
	applied := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/apply-setup", bytes.NewReader(body)))
		applied <- rec.Code
	}()
	<-rt.started
	drained := make(chan bool, 1)
	go func() { drained <- h.Drain(context.Background()) }()
	for deadline := time.Now().Add(5 * time.Second); ; {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/apply-setup", strings.NewReader(`{"version":1}`)))
		if rec.Code == http.StatusServiceUnavailable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("new apply admitted during drain:", rec.Code)
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-drained:
		t.Fatal("drain returned while an apply was running")
	case <-time.After(100 * time.Millisecond):
	}
	cut, cancel := context.WithCancel(context.Background())
	cancel()
	if h.Drain(cut) {
		t.Fatal("drain reported success while an apply was running")
	}
	close(rt.release)
	if !<-drained || <-applied != 200 || store.Load().IssuerURL != issuer {
		t.Fatal("in-flight apply did not finish before drain returned")
	}
	if !h.Drain(context.Background()) {
		t.Fatal("second drain with nothing running must succeed")
	}
}

func TestNetworkRouterNeverServesApplySetup(t *testing.T) {
	db, cfg := setupTestDB(t)
	r := NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, db, cfg, sso.NewStore(db))
	for _, p := range []string{"/v1/apply-setup", "/api/v1/apply-setup", "/api/v1/admin/apply-setup"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest("POST", p, strings.NewReader(`{"version":1}`)))
		// Unknown /api/v1/ paths answer 405 by the router's existing contract.
		if (rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed) || strings.Contains(rec.Body.String(), "handover") {
			t.Fatalf("%s → %d %s", p, rec.Code, rec.Body.String())
		}
	}
}
