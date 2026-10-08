package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Routes both kinds reach (auth.RequireAccount) and routes with no session at all.
var accountRoutes = map[string]bool{
	"GET /api/v1/auth/session": true, "GET /api/auth/session": true, "POST /api/v1/auth/logout": true, "POST /api/auth/logout": true,
	"POST /api/v1/auth/logout-all": true, "POST /api/v1/auth/password": true, "POST /api/v1/auth/step-up": true,
	"POST /api/v1/auth/oidc/step-up": true, "GET /api/v1/auth/oidc/step-up/{id}": true, "DELETE /api/v1/auth/oidc/step-up/{id}": true,
}
var publicRoutes = map[string]bool{
	"GET /api/v1/theme": true, "GET /api/theme": true, "GET /api/v1/setup": true, "GET /api/setup": true, "POST /api/v1/setup": true, "POST /api/setup": true,
	"POST /api/v1/auth/login-params": true, "POST /api/auth/login-params": true, "POST /api/v1/auth/login": true, "POST /api/auth/login": true,
	"POST /api/v1/auth/recover": true, "GET /api/v1/auth/sso-config": true, "GET /api/auth/sso-config": true,
	"GET /api/v1/auth/oidc/login": true, "GET /api/auth/oidc/login": true, "GET /auth/oidc/login": true,
	"GET /api/v1/auth/oidc/callback": true, "GET /api/auth/oidc/callback": true, "GET /auth/oidc/callback": true,
	"POST /api/v1/auth/oidc/backchannel-logout": true, "POST /api/v1/sync/readback": true, "GET /api/v1/share-links/{token}": true,
	"POST /api/v1/devices/register": true,
}

// Device-credential routes: a session of either kind gets 401.
var deviceRoutes = map[string]bool{"GET /api/v1/sync/pending": true, "POST /api/v1/push/registrations": true}

// routeLiterals finds every "METHOD /path" string literal in the package's non-test sources.
func routeLiterals(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`"((?:GET|POST|PUT|PATCH|DELETE|HEAD) /[^" ]*)"`)
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range pattern.FindAllStringSubmatch(string(b), -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	if len(out) < 60 {
		t.Fatalf("found only %d routes; the pattern no longer matches the registrations", len(out))
	}
	return out
}

var pathParam = regexp.MustCompile(`\{[^}]+\}`)

// errorCode(t, body) is teamkeys_p5_test.go's helper; a second definition here would not compile.

// kindsServer is the full router, backup routes included (newPairClient mounts none), with an
// everyday and an administrator account signed in, and one of each on a password someone else set.
func kindsServer(t *testing.T) (everyday, admin, fencedEveryday, fencedAdmin *pairClient) {
	t.Helper()
	cfg := config.Defaults()
	cfg.DataDir = t.TempDir()
	cfg.Backup.Dir = t.TempDir()
	cfg.Secrets.ServerSaltKey = strings.Repeat("s", 32)
	cfg.Secrets.PairingSecret = strings.Repeat("p", 32)
	cfg.Server.DevInsecureCookies = true
	st, err := storage.Open(filepath.Join(cfg.DataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := blobstore.New(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, st.DB(), blobs, cfg, backup.New(cfg, st, "test")))
	t.Cleanup(func() { srv.Close(); st.Close() })
	base := &pairClient{db: st.DB(), url: srv.URL}
	fencedEveryday, fencedAdmin = base.addUser(t, "fenced-everyday").pairClient, base.addAdmin(t, "fenced-admin").pairClient
	if _, err := st.DB().Exec(`UPDATE users SET password_admin_known=1 WHERE username IN ('fenced-everyday','fenced-admin')`); err != nil {
		t.Fatal(err)
	}
	return base.addUser(t, "everyday").pairClient, base.addAdmin(t, "server-admin").pairClient, fencedEveryday, fencedAdmin
}

// fenceExempt: the forced change reads the live identity first (rewrapIdentity).
const fenceExempt = "GET /api/v1/me/identity"

// Every route refuses the other kind, and its own kind while a password someone else set is still
// in use; a route added with the wrong middleware fails here.
func TestEveryRouteRefusesTheOtherKind(t *testing.T) {
	everyday, admin, fencedEveryday, fencedAdmin := kindsServer(t)
	for _, route := range routeLiterals(t) {
		method, path, _ := strings.Cut(route, " ")
		// admin.sock routes (/v1/…) and non-API pages are not on this surface.
		if !strings.HasPrefix(path, "/api/") || publicRoutes[route] || accountRoutes[route] {
			continue
		}
		path = pathParam.ReplaceAllString(path, "x")
		isAdmin := strings.HasPrefix(path, "/api/v1/admin/") || strings.HasPrefix(path, "/api/admin/")
		caller, want, wantCode := admin, http.StatusForbidden, "admin_account"
		fenced, fenceCode := fencedEveryday, "password_change_required"
		switch {
		case isAdmin:
			caller, wantCode, fenced = everyday, "forbidden", fencedAdmin
		case deviceRoutes[route]:
			want, wantCode, fenceCode = http.StatusUnauthorized, "unauthenticated", "unauthenticated"
		case route == fenceExempt:
			fenced = nil // TestPasswordChangeIsForcedAtFirstSignIn covers it
		}
		code, body := status(t, caller.do(t, method, path, nil, true, false))
		if code != want || (method != http.MethodHead && errorCode(t, body) != wantCode) {
			t.Errorf("%s: %d %s, want %d %s (classify it in account_kinds_test.go if it is public or an account route)", route, code, body, want, wantCode)
		}
		if fenced == nil {
			continue
		}
		code, body = status(t, fenced.do(t, method, path, nil, true, false))
		if method != http.MethodHead && errorCode(t, body) != fenceCode {
			t.Errorf("%s with a password someone else set: %d %s, want %s", route, code, body, fenceCode)
		}
	}
}

// Every account route reaches both kinds, also while the password must change. A logout ends the
// session, so each route gets fresh sessions.
func TestEveryAccountRouteServesBothKindsUnfenced(t *testing.T) {
	for route := range accountRoutes {
		method, path, _ := strings.Cut(route, " ")
		path = pathParam.ReplaceAllString(path, "x")
		everyday, admin, fencedEveryday, fencedAdmin := kindsServer(t)
		for _, c := range []*pairClient{everyday, admin, fencedEveryday, fencedAdmin} {
			code, body := status(t, c.do(t, method, path, nil, true, false))
			if code == http.StatusUnauthorized || code == http.StatusTooManyRequests || (code >= 400 && slices.Contains([]string{"admin_account", "forbidden", "password_change_required"}, errorCode(t, body))) {
				t.Errorf("%s refused an account route: %d %s", route, code, body)
			}
		}
	}
}

func TestAccountRoutesServeBothKinds(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	for _, c := range []*pairClient{p, admin.pairClient} {
		code, body := status(t, c.do(t, http.MethodGet, "/api/v1/auth/session", nil, false, false))
		if code != http.StatusOK {
			t.Fatalf("session=%d %s", code, body)
		}
		c.stepUp(t)
	}
	if code, body := status(t, admin.do(t, http.MethodGet, "/api/v1/admin/users", nil, false, false)); code != http.StatusOK {
		t.Fatalf("admin users=%d %s", code, body)
	}
	if code, body := status(t, p.do(t, http.MethodGet, "/api/v1/containers", nil, false, false)); code != http.StatusOK {
		t.Fatalf("containers=%d %s", code, body)
	}
}

// Every Handle/HandleFunc whose pattern is not a string literal is invisible to routeLiterals.
// Only these are allowed: their call sites pass literals, or they are HMAC/socket routes.
var dynamicRoutes = map[string]bool{
	"backup_routes.go:path":             true, // mutation("POST /api/v1/admin/backup/…") call sites are literals
	"sso_directory.go:\"POST \"+path":   true, // sync/events aliases: HMAC-authenticated, public by design
	"apply_setup.go:\"POST /v1/\"+name": true, // admin Unix socket, not on the network router
}

func TestNoRouteHidesFromTheInventory(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// A pattern built by concatenation, or held in a variable (checked with grep -P on 93b2565: exactly the three above).
	call := regexp.MustCompile(`\.Handle(?:Func)?\(\s*("[^"]*"\s*\+[^,]*|[^"\s][^,]*),`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range call.FindAllStringSubmatch(string(b), -1) {
			if !dynamicRoutes[f+":"+strings.TrimSpace(m[1])] {
				t.Errorf("%s registers %s: use a \"METHOD /path\" literal so TestEveryRouteRefusesTheOtherKind sees it, or list it here with a reason", f, m[1])
			}
		}
	}
}

func TestPasswordChangeIsForcedAtFirstSignIn(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	for _, id := range []string{pairUser, admin.id} {
		if _, err := p.db.Exec(`UPDATE users SET password_admin_known=1 WHERE id=?`, id); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		c    *pairClient
		path string
	}{{p, "/api/v1/containers"}, {admin.pairClient, "/api/v1/admin/users"}} {
		if code, body := status(t, tc.c.do(t, http.MethodGet, tc.path, nil, false, false)); code != http.StatusConflict || errorCode(t, body) != "password_change_required" {
			t.Fatalf("%s before the change=%d %s", tc.path, code, body)
		}
		// identity read: the change screen reads the live identity first (rewrapIdentity), so it is not fenced.
		want := http.StatusNotFound
		if tc.c == admin.pairClient {
			want = http.StatusForbidden
		}
		if code, body := status(t, tc.c.do(t, http.MethodGet, "/api/v1/me/identity", nil, false, false)); code != want {
			t.Fatalf("identity read before the change=%d %s", code, body)
		}
		code, body := status(t, tc.c.do(t, http.MethodGet, "/api/v1/auth/session", nil, false, false))
		var s struct {
			PasswordChangeRequired bool `json:"passwordChangeRequired"`
		}
		if code != http.StatusOK || json.Unmarshal([]byte(body), &s) != nil || !s.PasswordChangeRequired {
			t.Fatalf("session before the change=%d %s", code, body)
		}
		change := `{"currentAuthSecret":"` + strings.Repeat("a", 64) + `","newAuthSecret":"` + strings.Repeat("b", 64) + `","newLoginSalt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":100000}`
		if code, body := status(t, tc.c.do(t, http.MethodPost, "/api/v1/auth/password", []byte(change), true, false)); code != http.StatusNoContent {
			t.Fatalf("own change=%d %s", code, body)
		}
		if code, body := status(t, tc.c.do(t, http.MethodGet, tc.path, nil, false, false)); code != http.StatusOK {
			t.Fatalf("%s after the change=%d %s", tc.path, code, body)
		}
	}
}

func TestAdminAccountsCannotPairDevices(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	if code, body := status(t, admin.do(t, http.MethodPost, "/api/v1/devices/pairing-token", nil, true, false)); code != http.StatusForbidden || errorCode(t, body) != "admin_account" {
		t.Fatalf("mint=%d %s", code, body)
	}
	token, _, err := auth.MintPairingToken(strings.Repeat("p", 32), admin.id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, code := p.register(t, token, bytes.Repeat([]byte{9}, 32)); code != http.StatusUnauthorized {
		t.Fatalf("an admin account's pairing token registered a device: %d", code)
	}
}

// The middleware keeps the kinds apart on its own, also where a database edit bypassed the triggers.
func TestKindGatesHoldWithoutTheTriggers(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	for _, q := range []string{`DROP TRIGGER users_admin_role_update`, `DROP TRIGGER devices_everyday_only`} {
		if _, err := p.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.db.Exec(`UPDATE users SET role='admin' WHERE id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	if code, body := status(t, p.do(t, http.MethodGet, "/api/v1/admin/users", nil, false, false)); code != http.StatusForbidden {
		t.Fatalf("an everyday account with the grant reached an admin route: %d %s", code, body)
	}
	code, body := status(t, p.do(t, http.MethodGet, "/api/v1/auth/session", nil, false, false))
	var s struct {
		User struct{ Role, AccountKind string }
	}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &s) != nil || s.User.Role != "user" || s.User.AccountKind != "user" {
		t.Fatalf("session of an everyday account with the grant: %d %s", code, body)
	}
	secret := "admin-device-secret"
	sum := sha256.Sum256([]byte(secret))
	admin.deviceID = mint(t, "dev")
	admin.deviceSecret = secret
	if _, err := p.db.Exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,created_at) VALUES(?,?,'k','fp',?,'now')`, admin.deviceID, admin.id, "sha256:"+hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if code, _ := status(t, admin.doDeviceOnly(t, http.MethodGet, "/api/v1/sync/pending", nil)); code != http.StatusUnauthorized {
		t.Fatalf("an administrator account's device credential authenticated: %d", code)
	}
}
