package httpapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busness-app/kynotes-server/internal/auth"
	"github.com/Busness-app/kynotes-server/internal/config"
	"github.com/Busness-app/kynotes-server/internal/sso"
	"github.com/Busness-app/kynotes-server/internal/storage"
)

const logoutPath = "/api/v1/auth/oidc/backchannel-logout"

type logoutFixture struct {
	t                       *testing.T
	db                      *sql.DB
	cfg                     config.Config
	settings                *sso.Store
	key                     *rsa.PrivateKey
	issuer                  *httptest.Server
	router                  http.Handler
	mu                      sync.Mutex
	proofs                  map[string]map[string]any
	tokenHook               func()
	sessionSupport          bool
	jwksPath, keyID         string
	discoveryRequests       int
	discoveryHook, jwksHook func()
}

func newLogoutFixture(t *testing.T) *logoutFixture {
	return newLogoutFixtureWithSessionSupport(t, true)
}
func newLogoutFixtureWithSessionSupport(t *testing.T, sessionSupport bool) *logoutFixture {
	t.Helper()
	db, cfg := setupTestDB(t)
	cfg.Secrets.PairingSecret = strings.Repeat("p", 32)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &logoutFixture{t: t, db: db, cfg: cfg, key: key, settings: sso.NewStore(db), proofs: make(map[string]map[string]any), sessionSupport: sessionSupport, jwksPath: "/keys", keyID: "one"}
	f.issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			f.mu.Lock()
			f.discoveryRequests++
			hook, path, support := f.discoveryHook, f.jwksPath, f.sessionSupport
			f.mu.Unlock()
			if hook != nil {
				hook()
			}
			_ = json.NewEncoder(w).Encode(sso.DiscoveryDoc{Issuer: f.issuer.URL, AuthorizationEndpoint: f.issuer.URL + "/authorize", TokenEndpoint: f.issuer.URL + "/token", JWKSURI: f.issuer.URL + path, BackchannelLogoutSessionSupported: support})
		case "/keys", "/rotated-keys":
			f.mu.Lock()
			hook := f.jwksHook
			f.mu.Unlock()
			if hook != nil {
				hook()
			}
			kid, signingKey := "one", key
			if r.URL.Path == "/rotated-keys" {
				f.mu.Lock()
				kid, signingKey = f.keyID, f.key
				f.mu.Unlock()
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(signingKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signingKey.E)).Bytes())}}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				return
			}
			f.mu.Lock()
			claims := f.proofs[r.PostForm.Get("code")]
			f.mu.Unlock()
			token := f.sign("JWT", claims)
			if f.tokenHook != nil {
				f.tokenHook()
			}
			_ = json.NewEncoder(w).Encode(sso.TokenResponse{IDToken: token})
		default:
			http.NotFound(w, r)
		}
	}))
	original := http.DefaultTransport
	http.DefaultTransport = f.issuer.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original; f.issuer.Close() })
	if err := f.settings.Save(sso.SSOSettings{Enabled: true, IssuerURL: f.issuer.URL, ClientID: "kynotes", AutoProvision: true}); err != nil {
		t.Fatal(err)
	}
	f.restartRouter()
	return f
}
func (f *logoutFixture) restartRouter() {
	f.settings = sso.NewStore(f.db)
	mux := http.NewServeMux()
	SSORoutes(mux, f.db, f.cfg, f.settings)
	AuthRoutes(mux, f.db, f.cfg)
	DeviceRoutes(mux, f.db, f.cfg)
	mux.Handle("GET /protected", auth.RequireSession(f.db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	mux.Handle("GET /device-protected", auth.RequireDevice(f.db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	f.router = mux
}
func (f *logoutFixture) sign(typ string, claims map[string]any) string {
	f.t.Helper()
	f.mu.Lock()
	key, kid := f.key, f.keyID
	f.mu.Unlock()
	h, err := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": typ})
	if err != nil {
		f.t.Fatal(err)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		f.t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		f.t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}
func (f *logoutFixture) beginLogin(subject, sid string, issued time.Time) *http.Request {
	f.t.Helper()
	res := f.send(httptest.NewRequest("GET", "/api/v1/auth/oidc/login", nil))
	if res.Code != 302 {
		f.t.Fatalf("login: %d %s", res.Code, res.Body.String())
	}
	dest, err := url.Parse(res.Header().Get("Location"))
	if err != nil {
		f.t.Fatal(err)
	}
	state := dest.Query().Get("state")
	f.mu.Lock()
	f.proofs[state] = map[string]any{"iss": f.issuer.URL, "aud": "kynotes", "sub": subject, "sid": sid, "preferred_username": subject, "role": "user", "iat": issued.Unix(), "exp": issued.Add(time.Hour).Unix(), "nonce": dest.Query().Get("nonce")}
	if sid == "" {
		delete(f.proofs[state], "sid")
	}
	f.mu.Unlock()
	req := httptest.NewRequest("GET", "/api/v1/auth/oidc/callback?code="+state+"&state="+state, nil)
	for _, c := range res.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}
func (f *logoutFixture) login(subject, sid string) []*http.Cookie {
	f.t.Helper()
	res := f.send(f.beginLogin(subject, sid, time.Now()))
	if res.Code != 302 {
		f.t.Fatalf("callback: %d %s", res.Code, res.Body.String())
	}
	return res.Result().Cookies()
}
func (f *logoutFixture) send(req *http.Request) *httptest.ResponseRecorder {
	res := httptest.NewRecorder()
	f.router.ServeHTTP(res, req)
	return res
}
func (f *logoutFixture) logoutClaims(jti, subject, sid string) map[string]any {
	c := map[string]any{"iss": f.issuer.URL, "aud": "kynotes", "iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(), "jti": jti, "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}}
	if subject != "" {
		c["sub"] = subject
	}
	if sid != "" {
		c["sid"] = sid
	}
	return c
}
func (f *logoutFixture) logout(token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", logoutPath, strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return f.send(req)
}
func (f *logoutFixture) protected(cookies []*http.Cookie) int {
	req := httptest.NewRequest("GET", "/protected", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return f.send(req).Code
}
func withCookies(req *http.Request, cookies []*http.Cookie) *http.Request {
	for _, c := range cookies {
		req.AddCookie(c)
		if c.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	return req
}
func (f *logoutFixture) pairing(cookies []*http.Cookie) string {
	f.t.Helper()
	res := f.send(withCookies(httptest.NewRequest("POST", "/api/v1/devices/pairing-token", nil), cookies))
	var body struct{ Token string }
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &body) != nil || body.Token == "" {
		f.t.Fatalf("pairing: %d %s", res.Code, res.Body.String())
	}
	return body.Token
}
func (f *logoutFixture) register(token string) *httptest.ResponseRecorder {
	data, _ := json.Marshal(map[string]string{"pairingToken": token, "publicKey": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "platform": "fixture"})
	return f.send(httptest.NewRequest("POST", "/api/v1/devices/register", bytes.NewReader(data)))
}
func TestSSOLogoutScopesAndPreservesCiphertext(t *testing.T) {
	f := newLogoutFixture(t)
	a := f.login("alice", "sid-a")
	b := f.login("alice", "sid-b")
	other := f.login("bob", "sid-c")
	var uid string
	if err := f.db.QueryRow(`SELECT id FROM users WHERE username='alice'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	local := httptest.NewRecorder()
	if _, err := auth.MintSession(f.db, local, uid, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	pending := f.pairing(a)
	enrolled := f.register(f.pairing(a))
	var device struct{ DeviceID, DeviceSecret string }
	if enrolled.Code != 200 || json.Unmarshal(enrolled.Body.Bytes(), &device) != nil {
		t.Fatalf("registration: %d %s", enrolled.Code, enrolled.Body.String())
	}
	deviceRequest := func() int {
		r := httptest.NewRequest("GET", "/device-protected", nil)
		r.Header.Set("X-Kynotes-Device-Id", device.DeviceID)
		r.Header.Set("X-Kynotes-Device-Secret", device.DeviceSecret)
		return f.send(r).Code
	}
	if deviceRequest() != 204 {
		t.Fatal("device was not authenticated")
	}
	if _, err := f.db.Exec(`INSERT INTO containers(id,kind,owner_user_id,meta_ciphertext,created_at,updated_at) VALUES('cipher-container','workbook',?,x'010203','now','now')`, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES('cipher-key','cipher-container',?,1,'fixture',x'040506','now')`, device.DeviceID); err != nil {
		t.Fatal(err)
	}
	// Neither an unknown sid nor a mismatched subject may broaden the logout scope.
	for i, c := range []map[string]any{f.logoutClaims("unknown", "alice", "unknown"), f.logoutClaims("mismatch", "bob", "sid-a")} {
		if res := f.logout(f.sign("logout+jwt", c)); res.Code != 200 {
			t.Fatalf("scope %d: %d", i, res.Code)
		}
		if f.protected(a) != 204 {
			t.Fatal("unmatched logout revoked alice")
		}
	}
	res := f.logout(f.sign("logout+jwt", f.logoutClaims("end-a", "alice", "sid-a")))
	if res.Code != 200 || res.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("logout: %d %s", res.Code, res.Body.String())
	}
	if f.protected(a) != 401 || f.protected(b) != 204 || f.protected(other) != 204 || f.protected(local.Result().Cookies()) != 204 {
		t.Fatal("session logout scope")
	}
	if deviceRequest() != 401 {
		t.Fatal("session-derived device survived logout")
	}
	if res := f.register(pending); res.Code < 400 {
		t.Fatal("pending pairing escaped logout")
	}
	var cipher, env []byte
	if err := f.db.QueryRow(`SELECT meta_ciphertext FROM containers WHERE id='cipher-container'`).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT envelope FROM key_envelopes WHERE id='cipher-key'`).Scan(&env); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cipher, []byte{1, 2, 3}) || !bytes.Equal(env, []byte{4, 5, 6}) {
		t.Fatal("encrypted data changed")
	}
	if res := f.logout(f.sign("logout+jwt", f.logoutClaims("end-subject", "alice", ""))); res.Code != 200 {
		t.Fatal(res.Code)
	}
	if f.protected(b) != 401 || f.protected(other) != 204 || f.protected(local.Result().Cookies()) != 204 {
		t.Fatal("subject logout scope")
	}
}
func TestSSOLogoutAtomicAuditReplayAndRestart(t *testing.T) {
	f := newLogoutFixture(t)
	cookies := f.login("alice", "sid-a")
	token := f.sign("logout+jwt", f.logoutClaims("replay", "alice", "sid-a"))
	if _, err := f.db.Exec(`CREATE TRIGGER fail_logout BEFORE INSERT ON audit_events WHEN NEW.event='auth.sso_logout' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if res := f.logout(token); res.Code != 500 {
		t.Fatalf("audit failure: %d", res.Code)
	}
	if f.protected(cookies) != 204 {
		t.Fatal("audit failure revoked session")
	}
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM sso_logout_events`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("replay admission not rolled back: %d %v", n, err)
	}
	if _, err := f.db.Exec(`DROP TRIGGER fail_logout`); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	codes := make(chan int, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- f.logout(token).Code }()
	}
	wg.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 200 {
			success++
		} else if code != 400 {
			t.Fatalf("concurrent logout: %d", code)
		}
	}
	if success != 1 || f.protected(cookies) != 401 {
		t.Fatal("logout did not commit exactly once")
	}
	// Open another connection to the same on-disk database, not an in-memory replay cache.
	var path string
	rows, err := f.db.Query(`PRAGMA database_list`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var seq int
		var name string
		if err := rows.Scan(&seq, &name, &path); err != nil {
			t.Fatal(err)
		}
		if name == "main" {
			break
		}
	}
	rows.Close()
	reopened, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	f.db = reopened.DB()
	f.restartRouter()
	if res := f.logout(token); res.Code != 400 {
		t.Fatalf("replay after restart: %d", res.Code)
	}
	if f.protected(cookies) != 401 {
		t.Fatal("restart restored revoked session")
	}
}
func TestSSOLogoutFencesPendingLogin(t *testing.T) {
	for _, scope := range []string{"session", "subject"} {
		t.Run(scope, func(t *testing.T) {
			f := newLogoutFixture(t)
			req := f.beginLogin("alice", "sid-before", time.Now())
			entered, release := make(chan struct{}), make(chan struct{})
			f.tokenHook = func() { close(entered); <-release }
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- f.send(req) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("token exchange not reached")
			}
			sid := "sid-before"
			if scope == "subject" {
				sid = ""
			}
			result := f.logout(f.sign("logout+jwt", f.logoutClaims("fence", "alice", sid)))
			close(release)
			callback := <-done
			f.tokenHook = nil
			if result.Code != 200 || callback.Code != 403 {
				t.Fatalf("logout=%d callback=%d %s", result.Code, callback.Code, callback.Body.String())
			}
			for _, cookie := range callback.Result().Cookies() {
				if cookie.Name == "kynotes_session" {
					t.Fatal("revoked callback emitted credentials")
				}
			}
			// A later login uses a new sid and issuance time; same-second issuance is denied conservatively.
			fresh := f.send(f.beginLogin("alice", "sid-after", time.Now().Add(2*time.Second)))
			if fresh.Code != 302 {
				t.Fatalf("new login blocked: %d %s", fresh.Code, fresh.Body.String())
			}
		})
	}
}
func TestSSOLogoutRejectsInvalidRequests(t *testing.T) {
	f := newLogoutFixture(t)
	cookies := f.login("alice", "sid-a")
	for _, mode := range []string{"authentication", "signature", "issuer", "audience", "expired", "nonce", "query", "duplicate", "oversized", "json"} {
		t.Run(mode, func(t *testing.T) {
			claims := f.logoutClaims(mode, "alice", "sid-a")
			typ := "logout+jwt"
			switch mode {
			case "authentication":
				typ = "JWT"
			case "issuer":
				claims["iss"] = "https://wrong.example"
			case "audience":
				claims["aud"] = "other"
			case "expired":
				claims["exp"] = time.Now().Add(-time.Hour).Unix()
			case "nonce":
				claims["nonce"] = nil
			}
			token := f.sign(typ, claims)
			if mode == "signature" {
				parts := strings.Split(token, ".")
				sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
				sig[0] ^= 1
				token = parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
			}
			body := url.Values{"logout_token": {token}}.Encode()
			path := logoutPath
			contentType := "application/x-www-form-urlencoded"
			switch mode {
			case "query":
				path += "?" + body
				body = ""
			case "duplicate":
				body += "&" + body
			case "oversized":
				body = strings.Repeat("a", 65<<10)
			case "json":
				contentType = "application/json"
			}
			req := withCookies(httptest.NewRequest("POST", path, strings.NewReader(body)), cookies)
			req.Header.Set("Content-Type", contentType)
			res := f.send(req)
			if res.Code < 400 || f.protected(cookies) != 204 {
				t.Fatalf("invalid request %s: %d", mode, res.Code)
			}
		})
	}
}

func TestSSOLogoutRacesDeviceEnrollment(t *testing.T) {
	f := newLogoutFixture(t)
	cookies := f.login("alice", "device-race")
	pairing := f.pairing(cookies)
	token := f.sign("logout+jwt", f.logoutClaims("device-race", "alice", "device-race"))
	start := make(chan struct{})
	enrollment := make(chan *httptest.ResponseRecorder, 1)
	logout := make(chan *httptest.ResponseRecorder, 1)
	go func() { <-start; enrollment <- f.register(pairing) }()
	go func() { <-start; logout <- f.logout(token) }()
	close(start)
	enrolled, loggedOut := <-enrollment, <-logout
	if loggedOut.Code != 200 {
		t.Fatalf("logout: %d %s", loggedOut.Code, loggedOut.Body.String())
	}
	if enrolled.Code == 200 {
		var device struct{ DeviceID, DeviceSecret string }
		if err := json.Unmarshal(enrolled.Body.Bytes(), &device); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/device-protected", nil)
		r.Header.Set("X-Kynotes-Device-Id", device.DeviceID)
		r.Header.Set("X-Kynotes-Device-Secret", device.DeviceSecret)
		if f.send(r).Code != 401 {
			t.Fatal("raced enrollment survived logout")
		}
	} else if enrolled.Code != 409 {
		t.Fatalf("enrollment: %d %s", enrolled.Code, enrolled.Body.String())
	}
	if f.protected(cookies) != 401 {
		t.Fatal("session survived logout")
	}
}

func TestSSOLoginRequiresAtomicAuditAndSessionIdentity(t *testing.T) {
	f := newLogoutFixture(t)
	// A session-aware issuer must supply a usable sid.
	if res := f.send(f.beginLogin("alice", "", time.Now())); res.Code == 302 {
		t.Fatal("missing sid accepted")
	}
	if _, err := f.db.Exec(`CREATE TRIGGER fail_login_audit BEFORE INSERT ON audit_events WHEN NEW.event='auth.sso_login' BEGIN SELECT RAISE(ABORT,'test audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	res := f.send(f.beginLogin("alice", "audited", time.Now()))
	if res.Code != 500 {
		t.Fatalf("callback: %d %s", res.Code, res.Body.String())
	}
	for _, c := range res.Result().Cookies() {
		if c.Name == "kynotes_session" && c.Value != "" {
			t.Fatal("cookie escaped audit rollback")
		}
	}
	var sessions int
	if err := f.db.QueryRow(`SELECT count(*) FROM sessions`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("session escaped audit rollback: %d %v", sessions, err)
	}
}

func TestSSOConfigurationRevocationIsAtomic(t *testing.T) {
	f := newLogoutFixture(t)
	cookies := f.login("alice", "configuration")
	settings := f.settings.Load()
	settings.Enabled = false
	if _, err := f.db.Exec(`CREATE TRIGGER fail_config_audit BEFORE INSERT ON audit_events WHEN NEW.event='auth.sso_configuration' BEGIN SELECT RAISE(ABORT,'test audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := f.settings.Save(settings); err == nil {
		t.Fatal("configuration committed without audit")
	}
	if !f.settings.Load().Enabled || f.protected(cookies) != 204 {
		t.Fatal("failed configuration changed authorization")
	}
	if _, err := f.db.Exec(`DROP TRIGGER fail_config_audit`); err != nil {
		t.Fatal(err)
	}
	if err := f.settings.Save(settings); err != nil {
		t.Fatal(err)
	}
	if f.protected(cookies) != 401 {
		t.Fatal("disabled SSO session survived")
	}
	// Disabling new logins does not prevent authenticating an outstanding logout.
	if res := f.logout(f.sign("logout+jwt", f.logoutClaims("after-disable", "alice", "configuration"))); res.Code != 200 {
		t.Fatalf("disabled logout: %d %s", res.Code, res.Body.String())
	}
}

func TestSSOLogoutValidBurstBypassesAbuseLimit(t *testing.T) {
	f := newLogoutFixture(t)
	sessions := make([][]*http.Cookie, 20)
	for i := range sessions {
		sessions[i] = f.login("alice", "burst-"+strconv.Itoa(i))
	}
	f.router = rateLimitMiddleware(config.Defaults(), f.db, f.router)
	throttled := false
	for i := 0; i < 20; i++ {
		if f.logout("junk").Code == 429 {
			throttled = true
		}
	}
	if !throttled {
		t.Fatal("invalid tokens were not throttled")
	}
	for i, cookies := range sessions {
		sid := "burst-" + strconv.Itoa(i)
		if res := f.logout(f.sign("logout+jwt", f.logoutClaims(sid, "alice", sid))); res.Code != 200 {
			t.Fatalf("valid logout %d: %d", i, res.Code)
		}
		if f.protected(cookies) != 401 {
			t.Fatalf("session %d survived", i)
		}
	}
}

func TestSSOLogoutRevokesLegacySidlessSessions(t *testing.T) {
	f := newLogoutFixtureWithSessionSupport(t, false)
	alice, bob := f.login("alice", ""), f.login("bob", "")
	// A subject is required to identify any legacy sid-less session.
	if res := f.logout(f.sign("logout+jwt", f.logoutClaims("sid-only", "", "new-sid"))); res.Code != 200 {
		t.Fatal(res.Code)
	}
	if f.protected(alice) != 204 {
		t.Fatal("sid-only token widened scope")
	}
	if res := f.logout(f.sign("logout+jwt", f.logoutClaims("legacy", "alice", "new-sid"))); res.Code != 200 {
		t.Fatal(res.Code)
	}
	if f.protected(alice) != 401 || f.protected(bob) != 204 {
		t.Fatal("legacy logout scope")
	}
	old := f.send(f.beginLogin("alice", "", time.Now().Add(-time.Minute)))
	if old.Code != 403 {
		t.Fatalf("legacy callback escaped fence: %d", old.Code)
	}
	fresh := f.send(f.beginLogin("alice", "", time.Now().Add(2*time.Second)))
	if fresh.Code != 302 {
		t.Fatalf("new legacy login blocked: %d", fresh.Code)
	}
}

func TestSSOLogoutAuditIdentifiesDeliveryAndCounts(t *testing.T) {
	f := newLogoutFixture(t)
	alice := f.login("alice", "audit")
	if res := f.register(f.pairing(alice)); res.Code != 200 {
		t.Fatal(res.Code)
	}
	for _, tc := range []struct{ jti, sid, want string }{{"audit-match", "audit", "sessions=1,devices=1"}, {"audit-unmatched", "unknown", "sessions=0,devices=0"}} {
		if res := f.logout(f.sign("logout+jwt", f.logoutClaims(tc.jti, "alice", tc.sid))); res.Code != 200 {
			t.Fatal(res.Code)
		}
		var counts string
		if err := f.db.QueryRow(`SELECT reason_code FROM audit_events WHERE event='auth.sso_logout' AND object_id=?`, tc.jti).Scan(&counts); err != nil || counts != tc.want {
			t.Fatalf("audit %s: %q %v", tc.jti, counts, err)
		}
	}
}

func TestSSOLogoutRefreshesChangedJWKSLocation(t *testing.T) {
	f := newLogoutFixture(t)
	alice := f.login("alice", "rotation")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.key, f.keyID, f.jwksPath = key, "two", "/rotated-keys"
	f.mu.Unlock()
	if res := f.logout(f.sign("logout+jwt", f.logoutClaims("rotation", "alice", "rotation"))); res.Code != 200 {
		t.Fatalf("rotated JWKS logout: %d %s", res.Code, res.Body.String())
	}
	if f.protected(alice) != 401 {
		t.Fatal("session survived key rotation")
	}
	f.mu.Lock()
	before := f.discoveryRequests
	f.mu.Unlock()
	for i := 0; i < 5; i++ {
		parts := strings.Split(f.sign("logout+jwt", f.logoutClaims("unknown-key", "alice", "rotation")), ".")
		// Never publish this key ID, even if a very slow test crosses cache expiry.
		parts[0] = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"logout+jwt","kid":"unknown"}`))
		if res := f.logout(strings.Join(parts, ".")); res.Code == 200 {
			t.Fatal("unknown key accepted")
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.discoveryRequests != before {
		t.Fatal("invalid tokens amplified discovery requests")
	}
}

func TestSSOLogoutCancelledCallerDoesNotConsumeDiscovery(t *testing.T) {
	f := newLogoutFixture(t)
	alice := f.login("alice", "cancelled")
	f.restartRouter() // Keep durable sessions, but start with cold verification caches.
	token := f.sign("logout+jwt", f.logoutClaims("cancelled", "alice", "cancelled"))
	f.mu.Lock()
	before := f.discoveryRequests
	f.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.settings.VerifyLogout(ctx, f.settings.Load(), token); err == nil {
		t.Fatal("cancelled verification succeeded")
	}
	f.mu.Lock()
	afterCancelled := f.discoveryRequests
	f.mu.Unlock()
	if afterCancelled != before {
		t.Fatal("already-cancelled caller started discovery")
	}
	if res := f.logout(token); res.Code != 200 {
		t.Fatalf("cancelled caller poisoned next delivery: %d %s", res.Code, res.Body.String())
	}
	if f.protected(alice) != 401 {
		t.Fatal("session survived valid delivery")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.discoveryRequests != before+1 {
		t.Fatal("fresh caller did not fetch discovery")
	}
}

func TestSSOLogoutFetchSurvivesCallerDisconnect(t *testing.T) {
	for _, stage := range []string{"discovery", "jwks", "login-jwks"} {
		t.Run(stage, func(t *testing.T) {
			f := newLogoutFixture(t)
			alice := f.login("alice", "disconnect")
			f.restartRouter()
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			hook := func() { close(entered); <-release }
			f.mu.Lock()
			if stage == "discovery" {
				f.discoveryHook = hook
			} else {
				f.jwksHook = hook
			}
			f.mu.Unlock()
			token := f.sign("logout+jwt", f.logoutClaims("disconnect", "alice", "disconnect"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				if stage == "login-jwks" {
					idToken := f.sign("JWT", map[string]any{"iss": f.issuer.URL, "aud": "kynotes", "sub": "alice", "sid": "disconnect", "nonce": "test-nonce", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
					_, err = f.settings.VerifyClaims(ctx, f.settings.Load(), &sso.DiscoveryDoc{JWKSURI: f.issuer.URL + "/keys"}, idToken, "test-nonce")
				} else {
					_, err = f.settings.VerifyLogout(ctx, f.settings.Load(), token)
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("metadata fetch not reached")
			}
			cancel()
			unblock()
			if err := <-done; err != nil {
				t.Fatalf("caller aborted shared %s fetch: %v", stage, err)
			}
			f.mu.Lock()
			f.discoveryHook, f.jwksHook = nil, nil
			f.mu.Unlock()
			if res := f.logout(token); res.Code != 200 {
				t.Fatalf("disconnect poisoned next delivery: %d %s", res.Code, res.Body.String())
			}
			if f.protected(alice) != 401 {
				t.Fatal("session survived valid delivery")
			}
		})
	}
}
