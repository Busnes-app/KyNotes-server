package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/sso"
)

// X-Forwarded-Proto/Host shape the derived callback and cookie only from a trusted proxy.
func TestSSOForwardedHeadersNeedTrustedProxy(t *testing.T) {
	db, cfg := setupTestDB(t)
	cfg.Server.DevInsecureCookies = false
	cfg.Server.BehindProxy = true
	cfg.Server.TrustedProxies = []string{"10.0.0.9/32"}
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(sso.DiscoveryDoc{Issuer: issuer.URL, AuthorizationEndpoint: issuer.URL + "/authorize", TokenEndpoint: issuer.URL + "/token", JWKSURI: issuer.URL + "/keys"})
	}))
	defer issuer.Close()
	original := http.DefaultTransport
	http.DefaultTransport = issuer.Client().Transport
	defer func() { http.DefaultTransport = original }()
	store := sso.NewStore(db)
	if err := store.Save(sso.SSOSettings{Enabled: true, IssuerURL: issuer.URL, ClientID: "fixture"}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	SSORoutes(mux, db, cfg, store)
	for _, test := range []struct {
		peer, wantRedirect string
		wantSecure         bool
	}{
		{"203.0.113.9:1234", "http://notes.internal/api/v1/auth/oidc/callback", false},
		{"10.0.0.9:1234", "https://notes.example/api/v1/auth/oidc/callback", true},
	} {
		r := httptest.NewRequest("GET", "http://notes.internal/api/v1/auth/oidc/login", nil)
		r.RemoteAddr = test.peer
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", "notes.example")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		loc, err := url.Parse(w.Header().Get("Location"))
		cookies := w.Result().Cookies()
		if w.Code != 302 || err != nil || len(cookies) != 1 {
			t.Fatal(test.peer, w.Code, w.Body.String())
		}
		if got := loc.Query().Get("redirect_uri"); got != test.wantRedirect || cookies[0].Secure != test.wantSecure {
			t.Fatalf("%s: redirect %q secure %v", test.peer, got, cookies[0].Secure)
		}
	}
}
