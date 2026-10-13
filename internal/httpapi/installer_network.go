package httpapi

import (
	"net"
	"net/http"
	"strings"
)

// networkHandler discloses only this request's resolved network metadata. It
// shares address resolution with the rate limiter without applying IPv6 grouping.
func networkHandler(behindProxy bool, proxies []*net.IPNet) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := resolvedClientIP(r, behindProxy, proxies)
		if ip == nil {
			WriteError(w, r, 400, "invalid_peer", "invalid transport peer")
			return
		}
		accepted := behindProxy && trusted(remoteIP(r), proxies)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if accepted {
			parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-Proto"), ","), ",")
			switch last := strings.TrimSpace(parts[len(parts)-1]); last {
			case "http", "https":
				scheme = last
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, struct {
			ClientIP string `json:"clientIp"`
			Trusted  bool   `json:"proxyHeadersTrusted"`
			Scheme   string `json:"scheme"`
		}{ip.String(), accepted, scheme})
	}
}
