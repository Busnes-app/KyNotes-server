package httpapi

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"database/sql"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
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
			// The receiver throttles failed verification; valid issuer bursts must pass.
			next.ServeHTTP(w, r)
			return
		case path == "/api/v1/auth/oidc/login" || path == "/auth/oidc/login":
			limit, rate, label = cfg.RateLimit.LoginPerMinute, cfg.RateLimit.LoginPerMinute, "oidc"
		case path == "/api/v1/auth/login" || path == "/api/v1/auth/login-params":
			limit, rate, label = cfg.RateLimit.LoginPerMinute, cfg.RateLimit.LoginPerMinute, "login"
		case path == "/api/v1/auth/oidc/step-up" || path == "/api/v1/auth/step-up" || path == "/api/v1/auth/password" || path == "/api/v1/auth/recover":
			limit, rate, label = cfg.RateLimit.LoginPerMinute, cfg.RateLimit.LoginPerMinute, "auth"
		case path == "/api/v1/devices/pairing-token":
			limit, rate, label = cfg.RateLimit.PairingPerHour, cfg.RateLimit.PairingPerHour, "pairing"
		case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/containers/") && strings.HasSuffix(path, "/invitations"):
			// Bounds how fast one account can learn whether user IDs are live by inviting them.
			limit, rate, label = cfg.RateLimit.InvitationPerHour, cfg.RateLimit.InvitationPerHour, "invitation"
		case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/invitations/") && strings.HasSuffix(path, "/accept"):
			// Its own bucket at the same rate: bounds guessing and the refusal audit rows a caller can write.
			limit, rate, label = cfg.RateLimit.InvitationPerHour, cfg.RateLimit.InvitationPerHour, "accept"
		case r.Method == http.MethodPost && path == "/api/v1/me/link-requests":
			// Linking a browser is device pairing: the same per-account hourly budget.
			limit, rate, label = cfg.RateLimit.PairingPerHour, cfg.RateLimit.PairingPerHour, "link"
		case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/me/link-requests/") && strings.HasSuffix(path, "/collect"):
			// The newcomer polls every two seconds.
			limit, rate, label = cfg.RateLimit.LinkPollPerMinute, cfg.RateLimit.LinkPollPerMinute, "link-poll"
		case r.Method != http.MethodGet && strings.HasPrefix(path, "/api/v1/me/link-requests/"):
			// Claim, reveal, approve and cancel: a ceremony needs a handful; bounds refusal audit rows.
			limit, rate, label = cfg.RateLimit.LoginPerMinute, cfg.RateLimit.LoginPerMinute, "link-step"
		case (strings.HasPrefix(path, "/api/v1/containers/") && strings.HasSuffix(path, "/uploads")) || strings.HasPrefix(path, "/api/v1/uploads/"):
			limit, rate, label = cfg.RateLimit.UploadPerMinute, cfg.RateLimit.UploadPerMinute, "upload"
		}
		refill := float64(rate) / 60
		if label == "pairing" || label == "invitation" || label == "accept" || label == "link" {
			refill = float64(rate) / 3600
		}
		identity := rateLimitClientIP(r, cfg.Server.BehindProxy, proxies)
		if label != "" && label != "login" && label != "oidc" && db != nil {
			if s, err := auth.ResolveSession(db, r, time.Now().UTC()); err == nil {
				identity = s.UserID
			}
		}
		if label != "" && !l.allow(label+"\x00"+identity, refill, limit, time.Now().UTC()) {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(1/refill))))
			WriteError(w, r, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")
			return
		}
		// SSO step-up challenges are minted by whatever route asked for one: their own bucket at the login rate.
		challenge := float64(cfg.RateLimit.LoginPerMinute) / 60
		next.ServeHTTP(w, r.WithContext(auth.WithChallengeLimit(r.Context(), func(userID string) bool {
			if l.allow("challenge\x00"+userID, challenge, cfg.RateLimit.LoginPerMinute, time.Now().UTC()) {
				return true
			}
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(1/challenge))))
			return false
		})))
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
