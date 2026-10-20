package httpapi

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
)

func TestInstallerNetworkSharesTrustWithoutIPv6Grouping(t *testing.T) {
	cfg := config.Defaults()
	cfg.Server.TrustedProxies = []string{"10.0.0.9/32"}
	h := NewRouter(logging.New(io.Discard, "info", "json"), 1024, func() bool { return true }, cfg)
	for _, test := range []struct {
		peer, chain, proto, wantIP, wantScheme string
		trusted                                bool
	}{
		{"203.0.113.9:9000", "198.51.100.66", "https", "203.0.113.9", "http", false},
		{"10.0.0.9:9000", "198.51.100.66, 203.0.113.9", "http, https", "203.0.113.9", "https", true},
		{"10.0.0.9:9000", "198.51.100.66, 2001:db8::abcd", "https", "2001:db8::abcd", "https", true},
		{"10.0.0.9:9000", "203.0.113.9, malformed", "https", "10.0.0.9", "https", true},
	} {
		r := httptest.NewRequest("GET", "/api/v1/installer/network", nil)
		r.RemoteAddr = test.peer
		r.Header.Set("X-Forwarded-For", test.chain)
		r.Header.Set("X-Forwarded-Proto", test.proto)
		r.Header.Set("X-Real-IP", "198.51.100.66")
		r.Header.Set("Forwarded", "for=198.51.100.66;proto=http")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var got struct {
			ClientIP string `json:"clientIp"`
			Trusted  bool   `json:"proxyHeadersTrusted"`
			Scheme   string `json:"scheme"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.ClientIP != test.wantIP || got.Trusted != test.trusted || got.Scheme != test.wantScheme {
			t.Fatal(test, w.Code, w.Body.String())
		}
	}
}

// The compose default (no TRUSTED_PROXY_CIDRS) leaves only the built-in loopback trust.
func TestDefaultTrustIgnoresForwardedForFromPrivatePeer(t *testing.T) {
	h := NewRouter(logging.New(io.Discard, "info", "json"), 1024, func() bool { return true }, config.Defaults())
	r := httptest.NewRequest("GET", "/api/v1/installer/network", nil)
	r.RemoteAddr = "192.168.1.20:9000"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var got struct {
		ClientIP string `json:"clientIp"`
		Trusted  bool   `json:"proxyHeadersTrusted"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.ClientIP != "192.168.1.20" || got.Trusted {
		t.Fatal(w.Code, w.Body.String())
	}
}
