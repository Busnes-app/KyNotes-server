package httpapi

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"database/sql"
	"github.com/Busness-app/kynotes-server/internal/auth"
	"github.com/Busness-app/kynotes-server/internal/config"
)

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu      sync.Mutex
	buckets map[string]bucket
}

func newLimiter() *limiter { return &limiter{buckets: make(map[string]bucket)} }

func (l *limiter) allow(key string, rate float64, burst int, now time.Time) bool {
	if rate <= 0 || burst <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b.last.IsZero() {
		b.tokens = float64(burst)
		b.last = now
	}
	b.tokens += now.Sub(b.last).Seconds() * float64(rate)
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.last = now
	if b.tokens < 1 {
		l.buckets[key] = b
		return false
	}
	b.tokens--
	l.buckets[key] = b
	return true
}

// canonicalAPIPath rewrites the unversioned /api/… alias of a route onto its
// /api/v1/… spelling so both are matched by the same rule.
func canonicalAPIPath(p string) string {
	if strings.HasPrefix(p, "/api/") && !strings.HasPrefix(p, "/api/v1/") {
		return "/api/v1/" + strings.TrimPrefix(p, "/api/")
	}
	return p
}

func rateLimitMiddleware(cfg config.Config, db *sql.DB, next http.Handler) http.Handler {
	l := newLimiter()
	proxies := parseTrustedProxies(cfg.Server.TrustedProxies)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit, rate, label := 0, 0, ""
		// Every /api/v1/… route is also served at /api/…, so match the canonical
		// spelling. Keying on "v1" alone lets a caller opt out of the limit.
		path := canonicalAPIPath(r.URL.Path)
		switch {
		case path == "/api/v1/auth/oidc/backchannel-logout":
			limit, rate, label = cfg.RateLimit.LoginPerMinute, cfg.RateLimit.LoginPerMinute, "oidc_logout"
		case path == "/api/v1/auth/oidc/login" || path == "/auth/oidc/login":
			limit, rate, label = cfg.RateLimit.LoginPerMinute, cfg.RateLimit.LoginPerMinute, "oidc"
		case path == "/api/v1/auth/login" || path == "/api/v1/auth/login-params":
			limit, rate, label = cfg.RateLimit.LoginPerMinute, cfg.RateLimit.LoginPerMinute, "login"
		case path == "/api/v1/auth/step-up" || path == "/api/v1/auth/password" || path == "/api/v1/auth/recover":
			limit, rate, label = cfg.RateLimit.LoginPerMinute, cfg.RateLimit.LoginPerMinute, "auth"
		case path == "/api/v1/devices/pairing-token":
			limit, rate, label = cfg.RateLimit.PairingPerHour, cfg.RateLimit.PairingPerHour, "pairing"
		case (strings.HasPrefix(path, "/api/v1/containers/") && strings.HasSuffix(path, "/uploads")) || strings.HasPrefix(path, "/api/v1/uploads/"):
			limit, rate, label = cfg.RateLimit.UploadPerMinute, cfg.RateLimit.UploadPerMinute, "upload"
		}
		refill := float64(rate) / 60
		if label == "pairing" {
			refill = float64(rate) / 3600
		}
		identity := rateLimitClientIP(r, cfg.Server.BehindProxy, proxies)
		if label != "login" && label != "oidc" && label != "oidc_logout" && db != nil {
			if s, err := auth.ResolveSession(db, r, time.Now().UTC()); err == nil {
				identity = s.UserID
			}
		}
		if label != "" && !l.allow(label+"\x00"+identity, refill, limit, time.Now().UTC()) {
			w.Header().Set("Retry-After", strconv.Itoa(60))
			WriteError(w, r, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func parseTrustedProxies(cidrs []string) []*net.IPNet {
	var networks []*net.IPNet
	for _, cidr := range cidrs {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			networks = append(networks, network)
		}
	}
	return networks
}

// Walk from the trusted immediate peer toward the client. A sender cannot select
// its bucket by prepending forged addresses. Invalid suffixes fall back to the peer.
func rateLimitClientIP(r *http.Request, behindProxy bool, proxies []*net.IPNet) string {
	if !behindProxy || !trusted(remoteIP(r), proxies) {
		return clientIP(r)
	}
	chain := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(chain) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(chain[i]))
		if ip == nil {
			return clientIP(r)
		}
		if !trusted(ip, proxies) {
			return normalizeClientIP(ip)
		}
	}
	return clientIP(r)
}
