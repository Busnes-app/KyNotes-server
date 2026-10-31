package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/sso"
)

const suiteSecret = "suite-client-secret"

// suiteFixture: SSO configured with a client secret, and a fake KyIdentity directory that answers
// each sub with its own one-app list, or 500 while failing is set.
type suiteFixture struct {
	*logoutFixture
	mu      sync.Mutex
	asked   []string
	failing bool
}

func newSuiteFixture(t *testing.T) *suiteFixture {
	f := &suiteFixture{logoutFixture: newLogoutFixture(t)}
	if err := f.settings.Save(sso.SSOSettings{Enabled: true, IssuerURL: f.issuer.URL, ClientID: "kynotes", ClientSecret: suiteSecret, AutoProvision: true}); err != nil {
		t.Fatal(err)
	}
	f.restartRouter()
	f.logoutFixture.suite = func(w http.ResponseWriter, r *http.Request) {
		if id, secret, ok := r.BasicAuth(); !ok || id != "kynotes" || secret != suiteSecret {
			http.Error(w, `{"error":"invalid_client"}`, 401)
			return
		}
		sub := r.URL.Query().Get("sub")
		f.mu.Lock()
		f.asked = append(f.asked, sub)
		failing := f.failing
		f.mu.Unlock()
		if failing {
			http.Error(w, "down", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"apps": []map[string]string{{"id": "kypost", "name": "KyPost for " + sub, "url": "https://mail.example.com/api/auth/oidc/login"}}})
	}
	return f
}

func (f *suiteFixture) ssoCookies(subject string) []*http.Cookie {
	f.t.Helper()
	res := f.send(f.beginLogin(subject, "sid-"+subject, time.Now()))
	if res.Code != 302 {
		f.t.Fatalf("callback: %d %s", res.Code, res.Body.String())
	}
	return liveCookies(res)
}

func (f *suiteFixture) apps(cookies []*http.Cookie) []map[string]string {
	f.t.Helper()
	res := f.send(withCookies(httptest.NewRequest("GET", "/api/v1/suite/apps", nil), cookies))
	var body struct {
		Apps []map[string]string `json:"apps"`
	}
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &body) != nil || body.Apps == nil {
		f.t.Fatalf("suite apps: %d %s", res.Code, res.Body.String())
	}
	if res.Header().Get("Cache-Control") != "no-store" {
		f.t.Fatal("suite apps response is cacheable")
	}
	return body.Apps
}

func (f *suiteFixture) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

func TestSuiteAppsForSSOUser(t *testing.T) {
	f := newSuiteFixture(t)
	apps := f.apps(f.ssoCookies("alice"))
	if len(apps) != 1 || apps[0]["id"] != "kypost" || apps[0]["name"] != "KyPost for alice" || apps[0]["url"] != "https://mail.example.com/api/auth/oidc/login" {
		t.Fatalf("apps = %v", apps)
	}
	if got := f.calls(); len(got) != 1 || got[0] != "alice" {
		t.Fatalf("KyIdentity asked for %v, want the session's subject", got)
	}
}

func TestSuiteAppsEmptyForLocalUser(t *testing.T) {
	f := newSuiteFixture(t)
	userID, _ := ids.Mint("usr")
	secret, _ := auth.HashAuthSecret(strings.Repeat("a", 64))
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := f.db.Exec(`INSERT INTO users(id, username, auth_secret_hash, login_salt, login_iterations, role, account_kind, status, created_at, updated_at) VALUES(?, 'local', ?, 'salt', 600000, 'user', 'user', 'active', ?, ?)`, userID, secret, now, now); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if _, err := auth.MintSession(f.db, rec, userID, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if apps := f.apps(liveCookies(rec)); len(apps) != 0 {
		t.Fatalf("local user got %v", apps)
	}
	if got := f.calls(); len(got) != 0 {
		t.Fatalf("a local session asked KyIdentity: %v", got)
	}
	if res := f.send(httptest.NewRequest("GET", "/api/v1/suite/apps", nil)); res.Code != 401 {
		t.Fatalf("anonymous: %d", res.Code)
	}
}

func TestSuiteAppsEmptyWhenKyIdentityFails(t *testing.T) {
	var logged bytes.Buffer
	original := errorLog
	errorLog = logging.New(&logged, "info", "json")
	t.Cleanup(func() { errorLog = original })
	f := newSuiteFixture(t)
	cookies := f.ssoCookies("carol")
	f.mu.Lock()
	f.failing = true
	f.mu.Unlock()
	if apps := f.apps(cookies); len(apps) != 0 {
		t.Fatalf("failure gave %v", apps)
	}
	if !strings.Contains(logged.String(), "suite.apps") || strings.Contains(logged.String(), "carol") || strings.Contains(logged.String(), suiteSecret) {
		t.Fatalf("log = %s", logged.String())
	}
	// A failure is not cached: the next request asks again.
	f.mu.Lock()
	f.failing = false
	f.mu.Unlock()
	if apps := f.apps(cookies); len(apps) != 1 {
		t.Fatalf("recovered apps = %v", apps)
	}
}

func TestSuiteAppsCachedPerUser(t *testing.T) {
	f := newSuiteFixture(t)
	alice, bob := f.ssoCookies("alice"), f.ssoCookies("bob")
	f.apps(alice)
	if apps := f.apps(alice); apps[0]["name"] != "KyPost for alice" {
		t.Fatalf("cached apps = %v", apps)
	}
	if apps := f.apps(bob); len(apps) != 1 || apps[0]["name"] != "KyPost for bob" {
		t.Fatalf("bob got %v", apps)
	}
	if got := f.calls(); len(got) != 2 || got[0] != "alice" || got[1] != "bob" {
		t.Fatalf("KyIdentity asked %v, want alice once then bob", got)
	}
}
