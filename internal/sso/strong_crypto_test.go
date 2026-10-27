package sso

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Under GODEBUG=fips140=on Go's TLS client refuses a chain with any RSA key below 2048 bits,
// a root the operator trusts explicitly included. Proven here through OIDC discovery.
func TestStrongProfileRefusesWeakIssuerCertificateChain(t *testing.T) {
	t.Logf("fips140 profile enabled: %v", fips140.Enabled())
	for _, bits := range []int{1024, 2047, 2048} {
		rootKey, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		root, _ := x509.ParseCertificate(rootDER)
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}

		var issuer string
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(DiscoveryDoc{Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/keys"})
		}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
		srv.StartTLS()
		issuer = srv.URL
		roots := x509.NewCertPool()
		roots.AddCert(root)
		original := http.DefaultTransport
		http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}

		_, err = DiscoverEndpoints(context.Background(), issuer)
		http.DefaultTransport = original
		srv.Close()
		if refuse := bits < 2048 && fips140.Enabled(); (err != nil) != refuse {
			t.Fatalf("RSA-%d root, profile=%v: %v", bits, fips140.Enabled(), err)
		}
	}
}
