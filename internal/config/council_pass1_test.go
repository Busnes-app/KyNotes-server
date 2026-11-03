package config

import (
	"strings"
	"testing"
)

// The install guide says to set the proxy's "exact peer address": a bare IP, spaces after
// commas and CIDRs all work, and a typo stops startup instead of trusting no proxy.
func TestTrustedProxyEntries(t *testing.T) {
	for entry, want := range map[string]string{"172.20.0.5": "172.20.0.5/32", " 10.0.0.0/8 ": "10.0.0.0/8", "fd00::1": "fd00::1/128"} {
		n, err := ParseTrustedProxy(entry)
		if err != nil || n.String() != want {
			t.Errorf("%q: %v %v, want %s", entry, n, err, want)
		}
	}
	t.Setenv("TRUSTED_PROXY_CIDRS", "172.20.0.5, 10.0.0.0/8,")
	c := testConfig(t)
	if err := applyEnv(&c); err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.Server.TrustedProxies, "|") != "172.20.0.5|10.0.0.0/8" {
		t.Fatalf("parsed %q", c.Server.TrustedProxies)
	}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	c.Server.TrustedProxies = []string{"172.20.0.5/33"}
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "trusted_proxies") {
		t.Fatalf("bad entry accepted: %v", err)
	}
}
