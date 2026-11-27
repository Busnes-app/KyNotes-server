package sso

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Busnes-app/ky-primitives/pqtls"
)

// Outbound SSO/HTTP clients must negotiate TLS 1.3 with the hybrid PQ key exchange
// (X25519MLKEM768) under both the default profile and GODEBUG=fips140=on.
func TestOutboundTLSPQHandshake(t *testing.T) {
	t.Logf("fips140 profile enabled: %v", fips140.Enabled())

	var (
		mu          sync.Mutex
		issuer      string
		serverState tls.ConnectionState
		sawTLS      bool
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.TLS != nil {
			serverState = *r.TLS
			sawTLS = true
		}
		iss := issuer
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DiscoveryDoc{
			Issuer:                iss,
			AuthorizationEndpoint: iss + "/authorize",
			TokenEndpoint:         iss + "/token",
			JWKSURI:               iss + "/keys",
		})
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()

	mu.Lock()
	issuer = srv.URL
	mu.Unlock()

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })

	tr := original.(*http.Transport).Clone()
	var tlsCfg tls.Config
	if tr.TLSClientConfig != nil {
		tlsCfg = *tr.TLSClientConfig.Clone()
	}
	tlsCfg.RootCAs = roots
	tr.TLSClientConfig = &tlsCfg
	http.DefaultTransport = tr

	if _, err := DiscoverEndpoints(context.Background(), issuer); err != nil {
		t.Fatalf("DiscoverEndpoints: %v", err)
	}

	mu.Lock()
	gotSawTLS := sawTLS
	gotServerState := serverState
	mu.Unlock()
	if !gotSawTLS {
		t.Fatal("loopback server saw no TLS connection state")
	}
	pqtls.RequireHybrid(t, gotServerState)

	resp, err := oidcClient().Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("oidcClient GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil {
		t.Fatal("oidcClient response had nil TLS connection state")
	}
	pqtls.RequireHybrid(t, *resp.TLS)
}
