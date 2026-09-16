package httpapi

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/sso"
)

// A real TLS issuer signs the ID token; no security path accepts fixture signatures.
func TestOIDCVerifiedLogin(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "forged", "unsigned", "issuer", "audience", "expired", "nonce", "missing_nonce", "kid", "collision", "disabled", "provision_off", "discovery_issuer", "changed_settings"} {
		t.Run(mode, func(t *testing.T) {
			db, cfg := setupTestDB(t)
			settings := sso.NewStore(db)
			var server *httptest.Server
			nonce := ""
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					issuer := server.URL
					if mode == "discovery_issuer" {
						issuer += "/wrong"
					}
					_ = json.NewEncoder(w).Encode(sso.DiscoveryDoc{Issuer: issuer, AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token", JWKSURI: server.URL + "/keys"})
				case "/keys":
					_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "one", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
				case "/token":
					claims := map[string]any{"iss": server.URL, "aud": "kynotes", "sub": "subject-bob", "preferred_username": "bob", "role": "user", "nonce": nonce, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
					header := map[string]any{"alg": "RS256", "kid": "one"}
					switch mode {
					case "issuer":
						claims["iss"] = "https://wrong.example"
					case "audience":
						claims["aud"] = "another-client"
					case "expired":
						claims["exp"] = time.Now().Add(-time.Hour).Unix()
					case "nonce":
						claims["nonce"] = "wrong"
					case "missing_nonce":
						delete(claims, "nonce")
					case "kid":
						header["kid"] = "unknown"
					case "unsigned":
						header["alg"] = "none"
					}
					h, _ := json.Marshal(header)
					b, _ := json.Marshal(claims)
					input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
					digest := sha256.Sum256([]byte(input))
					sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
					if err != nil {
						t.Error(err)
						return
					}
					if mode == "forged" {
						sig[0] ^= 1
					}
					_ = json.NewEncoder(w).Encode(sso.TokenResponse{IDToken: input + "." + base64.RawURLEncoding.EncodeToString(sig)})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			old := http.DefaultTransport
			http.DefaultTransport = server.Client().Transport
			defer func() { http.DefaultTransport = old }()
			config := sso.SSOSettings{Enabled: true, IssuerURL: server.URL, ClientID: "kynotes", AutoProvision: mode != "provision_off"}
			if err := settings.Save(config); err != nil {
				t.Fatal(err)
			}
			if mode == "collision" || mode == "disabled" {
				id, _ := createAdminUser(t, db)
				if _, err := db.Exec(`UPDATE users SET username='bob' WHERE id=?`, id); err != nil {
					t.Fatal(err)
				}
				if mode == "disabled" {
					if _, err := db.Exec(`UPDATE users SET sso_subject='subject-bob',status='disabled' WHERE id=?`, id); err != nil {
						t.Fatal(err)
					}
				}
			}
			mux := http.NewServeMux()
			SSORoutes(mux, db, cfg, settings)
			aliases := []string{"/api/v1/auth/oidc", "/api/auth/oidc", "/auth/oidc"}
			for _, alias := range aliases {
				login := httptest.NewRecorder()
				mux.ServeHTTP(login, httptest.NewRequest("GET", alias+"/login", nil))
				if mode == "discovery_issuer" {
					if login.Code != 502 {
						t.Fatalf("discovery mismatch: %d", login.Code)
					}
					continue
				}
				if login.Code != 302 {
					t.Fatalf("login: %d %s", login.Code, login.Body.String())
				}
				dest, err := url.Parse(login.Header().Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				nonce = dest.Query().Get("nonce")
				state := dest.Query().Get("state")
				if nonce == "" || nonce == state {
					t.Fatal("missing independent nonce")
				}
				if mode == "changed_settings" {
					config.ClientID = "changed"
					if err := settings.Save(config); err != nil {
						t.Fatal(err)
					}
				}
				req := httptest.NewRequest("GET", alias+"/callback?code=code&state="+url.QueryEscape(state), nil)
				for _, cookie := range login.Result().Cookies() {
					req.AddCookie(cookie)
				}
				result := httptest.NewRecorder()
				mux.ServeHTTP(result, req)
				if mode == "valid" {
					if result.Code != 302 {
						t.Fatalf("callback: %d %s", result.Code, result.Body.String())
					}
					found := false
					for _, cookie := range result.Result().Cookies() {
						if cookie.Name == "kynotes_session" {
							found = true
						}
					}
					if !found {
						t.Fatal("no session")
					}
				} else {
					if result.Code < 400 {
						t.Fatalf("invalid login accepted: %d", result.Code)
					}
					for _, cookie := range result.Result().Cookies() {
						if cookie.Name == "kynotes_session" {
							t.Fatal("invalid login minted session")
						}
					}
				}
				again := httptest.NewRecorder()
				mux.ServeHTTP(again, req)
				if again.Code != 400 {
					t.Fatalf("consumed callback accepted: %d", again.Code)
				}
				if mode == "changed_settings" {
					config.ClientID = "kynotes"
					if err := settings.Save(config); err != nil {
						t.Fatal(err)
					}
				}
			}
			var sessions int
			if err := db.QueryRow(`SELECT count(*) FROM sessions`).Scan(&sessions); err != nil {
				t.Fatal(err)
			}
			if mode != "valid" && sessions != 0 {
				t.Fatal("invalid flow left session")
			}
		})
	}
}

func TestSSOTransactionExpiryAndCapacity(t *testing.T) {
	pending := &ssoTransactions{pending: make(map[string]ssoTransaction)}
	pending.add("expired", ssoTransaction{Expires: time.Now().Add(-time.Second)})
	if _, ok := pending.take("expired"); ok {
		t.Fatal("expired transaction")
	}
	oldest := time.Now().Add(time.Minute)
	for i := 0; i < 1024; i++ {
		pending.add(strings.Repeat("x", i+1), ssoTransaction{Expires: oldest.Add(time.Duration(i) * time.Millisecond)})
	}
	pending.add("overflow", ssoTransaction{Expires: time.Now().Add(5 * time.Minute)})
	if len(pending.pending) != 1024 {
		t.Fatal("unbounded pending logins")
	}
	if _, ok := pending.take("x"); ok {
		t.Fatal("oldest pending login retained")
	}
	if _, ok := pending.take("overflow"); !ok {
		t.Fatal("new pending login missing")
	}
	if _, ok := pending.take("overflow"); ok {
		t.Fatal("consumed transaction reused")
	}
}

func TestSSOLoginSurvivesPendingFlood(t *testing.T) {
	db, cfg := setupTestDB(t)
	store := sso.NewStore(db)
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(sso.DiscoveryDoc{Issuer: issuer.URL, AuthorizationEndpoint: issuer.URL + "/authorize", TokenEndpoint: issuer.URL + "/token", JWKSURI: issuer.URL + "/keys"})
	}))
	defer issuer.Close()
	original := http.DefaultTransport
	http.DefaultTransport = issuer.Client().Transport
	defer func() { http.DefaultTransport = original }()
	if err := store.Save(sso.SSOSettings{Enabled: true, IssuerURL: issuer.URL, ClientID: "fixture"}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	SSORoutes(mux, db, cfg, store)
	aliases := []string{"/api/v1/auth/oidc/login", "/api/auth/oidc/login", "/auth/oidc/login"}
	call := func(h http.Handler, path, ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for i := 0; i < 1025; i++ {
		call(mux, aliases[i%len(aliases)], "192.0.2.1")
	}
	fresh := call(mux, aliases[0], "192.0.2.2")
	if fresh.Code != 302 || len(fresh.Result().Cookies()) == 0 {
		t.Fatalf("flood denied new client: %d", fresh.Code)
	}
	cfg.RateLimit.LoginPerMinute = 2
	limited := rateLimitMiddleware(cfg, db, mux)
	for i, path := range aliases {
		got := call(limited, path, "192.0.2.3")
		want := 302
		if i == 2 {
			want = 429
		}
		if got.Code != want {
			t.Fatalf("alias rate limit: %s got %d want %d", path, got.Code, want)
		}
	}
	if got := call(limited, aliases[2], "192.0.2.4"); got.Code != 302 {
		t.Fatal("one client limited another", got.Code)
	}
	cfg.Server.BehindProxy = true
	cfg.Server.TrustedProxies = []string{"127.0.0.1/32"}
	proxied := rateLimitMiddleware(cfg, db, mux)
	for i, ip := range []string{"192.0.2.3", "192.0.2.3", "192.0.2.3", "192.0.2.4"} {
		r := httptest.NewRequest("GET", aliases[i%len(aliases)], nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("X-Forwarded-For", ip)
		w := httptest.NewRecorder()
		proxied.ServeHTTP(w, r)
		want := 302
		if i == 2 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("trusted proxy client %s: got %d want %d", ip, w.Code, want)
		}
	}

}
