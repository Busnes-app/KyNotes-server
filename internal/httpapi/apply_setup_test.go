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
