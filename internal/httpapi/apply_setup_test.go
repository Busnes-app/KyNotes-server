package httpapi

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := issuer
		if mismatch {
			doc = "https://other.example"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": doc, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"})
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
