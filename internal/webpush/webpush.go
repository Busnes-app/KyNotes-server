// Package webpush sends content-free Web Push (RFC 8030) with VAPID (RFC 8292) for opt-in task
// reminders. A push carries no payload: it only wakes the browser, which shows a fixed text.
package webpush

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/keyfile"
)

const (
	// Timeout bounds one push request, connection included.
	Timeout = 5 * time.Second
	// MaxEndpoint bounds a stored endpoint URL.
	MaxEndpoint = 2048
	tokenLife   = time.Hour
	// retryFor is how long a reminder whose push failed transiently is retried.
	retryFor = time.Hour
	// ponytail: RFC 8292 wants the operator's contact; Apple refuses localhost subjects with
	// BadJwtToken, so this names the project. Upgrade path: a push.vapid_subject config field.
	subject = "https://github.com/Busnes-app/kynotes-server"
)

// pushHosts are the browser push services. An endpoint host must be one of them or a subdomain.
var pushHosts = []string{"fcm.googleapis.com", "updates.push.services.mozilla.com", "push.services.mozilla.com", "web.push.apple.com", "notify.windows.com"}

var ErrEndpoint = errors.New("not a browser push service endpoint")

// ParseEndpoint accepts only https to a known push service on its default port, with no userinfo,
// so a subscription can never point the server's requests anywhere else.
func ParseEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > MaxEndpoint || u.String() != raw || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.Host != u.Hostname() || !strings.HasPrefix(u.Path, "/") {
		return nil, ErrEndpoint
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return nil, ErrEndpoint
	}
	for _, h := range pushHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return u, nil
		}
	}
	return nil, ErrEndpoint
}

// LoadKey loads, or creates on first start, the VAPID P-256 key at <dataDir>/secrets/vapid.key.
func LoadKey(dataDir string) (*ecdsa.PrivateKey, error) {
	dir := filepath.Join(dataDir, "secrets")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	raw, err := keyfile.LoadOrCreateEncoded(filepath.Join(dir, "vapid.key"), 32, keyfile.Base64)
	if err != nil {
		return nil, err
	}
	// A random 32 bytes is a valid scalar except with probability about 2^-32; such a file is refused.
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
}

type Sender struct {
	key    *ecdsa.PrivateKey
	public string
	Client *http.Client
	// Allow overrides ParseEndpoint at send time; only tests set it, to reach an httptest server.
	Allow func(endpoint string) bool
}

func New(key *ecdsa.PrivateKey) (*Sender, error) {
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	return &Sender{key: key, public: base64.RawURLEncoding.EncodeToString(pub), Client: NewClient(http.DefaultTransport)}, nil
}

// NewClient never follows a redirect and gives up after Timeout.
func NewClient(transport http.RoundTripper) *http.Client {
	return &http.Client{Transport: transport, Timeout: Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// PublicKey is the uncompressed P-256 point, base64url without padding (applicationServerKey).
func (s *Sender) PublicKey() string { return s.public }

func b64json(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Token is the ES256 VAPID JWT for one push service origin.
func (s *Sender) Token(audience string, now time.Time) (string, error) {
	signing := b64json(map[string]string{"typ": "JWT", "alg": "ES256"}) + "." + b64json(map[string]any{"aud": audience, "exp": now.Add(tokenLife).Unix(), "sub": subject})
	digest := sha256.Sum256([]byte(signing))
	r, sig, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", err
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	sig.FillBytes(raw[32:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(raw), nil
}

type outcome int

const (
	delivered outcome = iota
	gone              // 404/410: the subscription no longer exists
	transient         // network error, 429 or 5xx: worth another try
	refused           // any other answer
)

// send posts one empty push to endpoint.
func (s *Sender) send(ctx context.Context, endpoint string, now time.Time) outcome {
	allowed := s.Allow
	if allowed == nil {
		allowed = func(e string) bool { _, err := ParseEndpoint(e); return err == nil }
	}
	u, err := url.Parse(endpoint)
	if err != nil || !allowed(endpoint) {
		return refused
	}
	token, err := s.Token(u.Scheme+"://"+u.Host, now)
	if err != nil {
		return transient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return refused
	}
	req.Header.Set("TTL", "3600")
	req.Header.Set("Urgency", "high")
	req.Header.Set("Authorization", "vapid t="+token+", k="+s.public)
	res, err := s.Client.Do(req)
	if err != nil {
		return transient
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	res.Body.Close()
	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		return delivered
	case res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusGone:
		return gone
	case res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500:
		return transient
	}
	return refused
}

// Fire sends one empty push to every subscription of each active account with a reminder due at
// now, however many are due, then deletes those reminders (one-shot). Only when every
// subscription failed transiently are they kept, for retryFor after the oldest came due.
// ponytail: one account at a time, each request up to Timeout. Upgrade path: a bounded worker pool.
func (s *Sender) Fire(ctx context.Context, db *sql.DB, now time.Time) error {
	cutoff := now.UTC().Format(time.RFC3339)
	rows, err := db.QueryContext(ctx, `SELECT r.user_id,MIN(r.at),u.status='active' FROM reminders r JOIN users u ON u.id=r.user_id WHERE r.at<=? GROUP BY r.user_id`, cutoff)
	if err != nil {
		return err
	}
	type due struct {
		user, oldest string
		active       bool
	}
	var users []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.user, &d.oldest, &d.active); err != nil {
			rows.Close()
			return err
		}
		users = append(users, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, d := range users {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		keep := false
		if d.active {
			if keep, err = s.pushUser(ctx, db, d.user, now); err != nil {
				return err
			}
		}
		if oldest, err := time.Parse(time.RFC3339, d.oldest); keep && err == nil && now.Sub(oldest) < retryFor {
			continue
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM reminders WHERE user_id=? AND at<=?`, d.user, cutoff); err != nil {
			return err
		}
	}
	return nil
}

// pushUser reports whether every subscription failed transiently (worth a retry).
func (s *Sender) pushUser(ctx context.Context, db *sql.DB, user string, now time.Time) (bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT id,endpoint FROM web_push_subscriptions WHERE user_id=? ORDER BY id`, user)
	if err != nil {
		return false, err
	}
	var subs [][2]string
	for rows.Next() {
		var id, endpoint string
		if err := rows.Scan(&id, &endpoint); err != nil {
			rows.Close()
			return false, err
		}
		subs = append(subs, [2]string{id, endpoint})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	retry := len(subs) > 0
	for _, sub := range subs {
		switch s.send(ctx, sub[1], now) {
		case delivered:
			retry = false
			_, err = db.ExecContext(ctx, `UPDATE web_push_subscriptions SET last_ok_at=? WHERE id=?`, now.UTC().Format(time.RFC3339), sub[0])
		case gone:
			retry = false
			_, err = db.ExecContext(ctx, `DELETE FROM web_push_subscriptions WHERE id=?`, sub[0])
		case refused:
			retry = false
		}
		if err != nil {
			return false, err
		}
	}
	return retry, nil
}
