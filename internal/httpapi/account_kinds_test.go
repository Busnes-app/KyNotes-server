package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Routes both kinds reach (auth.RequireAccount) and routes with no session at all.
var accountRoutes = map[string]bool{
	"GET /api/v1/auth/session": true, "GET /api/auth/session": true, "POST /api/v1/auth/logout": true, "POST /api/auth/logout": true,
	"POST /api/v1/auth/logout-all": true, "POST /api/v1/auth/password": true, "POST /api/v1/auth/step-up": true,
	"POST /api/v1/auth/oidc/step-up": true, "GET /api/v1/auth/oidc/step-up/{id}": true, "DELETE /api/v1/auth/oidc/step-up/{id}": true,
}
var publicRoutes = map[string]bool{
	"GET /healthz": true, "GET /livez": true, "GET /readyz": true,
	"POST /api/v1/sync/events": true, "POST /api/sync/events": true, "POST /sync/events": true, // HMAC-signed directory sync
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

// Patterns that are not driven: the catch-alls, which answer 405/404 or serve the static bundle.
var catchAllRoutes = map[string]bool{"/api/v1/": true, "/api/": true, "/": true}

// servedRoutes is every pattern the network router registers, read from the router itself.
func servedRoutes(t *testing.T) []string {
	t.Helper()
	cfg := config.Defaults()
	cfg.DataDir = t.TempDir()
	cfg.Backup.Dir = t.TempDir()
	st, err := storage.Open(filepath.Join(cfg.DataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	blobs, err := blobstore.New(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	mux, _, _ := buildRoutes(func() bool { return true }, st.DB(), blobs, cfg, backup.New(cfg, st, "test"), sso.NewStore(st.DB()))
	return mux.patterns
}

var routeShape = regexp.MustCompile(`^(GET|HEAD|POST|PUT|PATCH|DELETE) /[^ ]*$`)

// Every registered pattern names a method and a host-less path, or is an allowlisted catch-all, and
// every entry of the class tables is registered (so the tables cannot rot).
func TestEveryServedRouteIsClassified(t *testing.T) {
	served := map[string]bool{}
	for _, route := range servedRoutes(t) {
		served[route] = true
		if !catchAllRoutes[route] && !routeShape.MatchString(route) {
			t.Errorf("%q: register routes as \"METHOD /path\" (no host, a standard method) so TestEveryRouteRefusesTheOtherKind can drive them", route)
		}
	}
	if len(served) < 100 {
		t.Fatalf("only %d routes recorded", len(served))
	}
	for _, table := range []map[string]bool{catchAllRoutes, publicRoutes, accountRoutes, deviceRoutes} {
		for route := range table {
			if !served[route] {
				t.Errorf("%s is classified but not registered", route)
			}
		}
	}
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
	for _, route := range servedRoutes(t) {
		// TestEveryServedRouteIsClassified fails on any other shape.
		if catchAllRoutes[route] || publicRoutes[route] || accountRoutes[route] || !routeShape.MatchString(route) {
			continue
		}
		method, path, _ := strings.Cut(route, " ")
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
	for _, q := range []string{`DROP TRIGGER users_admin_role_update`, `DROP TRIGGER devices_everyday_only`, `DROP TRIGGER user_identities_everyday_only`} {
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
	// Login never hands an administrator account a wrapped identity.
	for _, q := range []string{
		`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES('dev_adminidentity',?,'pk','fp2','identity:00','identity','now')`,
		`INSERT INTO user_identities(user_id,device_id,wrapped_private_key,wrap_alg,created_at,updated_at) VALUES(?,'dev_adminidentity',x'00','aes-256-gcm','now','now')`,
	} {
		if _, err := p.db.Exec(q, admin.id); err != nil {
			t.Fatal(err)
		}
	}
	code, body = status(t, admin.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":"server-admin","authSecret":"`+strings.Repeat("a", 64)+`"}`), false, false))
	if code != http.StatusOK || strings.Contains(body, "identity") {
		t.Fatalf("administrator login: %d %s", code, body)
	}
}
func setupBody(admin, everyday string) []byte {
	account := func(name, fill string) string {
		return `{"username":` + quote(name) + `,"authSecret":"` + strings.Repeat(fill, 64) + `","loginSalt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":100000}`
	}
	return []byte(`{"admin":` + account(admin, "a") + `,"everyday":` + account(everyday, "b") + `}`)
}

func TestSetupCreatesBothAccounts(t *testing.T) {
	db, cfg := setupTestDB(t)
	mux := http.NewServeMux()
	AuthRoutes(mux, db, cfg)
	post := func(body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/setup", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	for name, body := range map[string][]byte{
		"old shape":          []byte(`{"username":"admin","authSecret":"` + strings.Repeat("a", 64) + `"}`),
		"same username":      setupBody("owner", "Owner"),
		"plaintext password": []byte(`{"admin":{"username":"admin","authSecret":"` + strings.Repeat("a", 64) + `","loginSalt":"x","iterations":100000,"password":"hunter2"},"everyday":{"username":"owner","authSecret":"` + strings.Repeat("b", 64) + `","loginSalt":"x","iterations":100000}}`),
		"no everyday":        []byte(`{"admin":{"username":"admin","authSecret":"` + strings.Repeat("a", 64) + `","loginSalt":"x","iterations":100000}}`),
	} {
		if rec := post(body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s=%d %s", name, rec.Code, rec.Body.String())
		}
	}
	var users int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil || users != 0 {
		t.Fatal("a refused setup created accounts", users, err)
	}
	rec := post(setupBody("admin", "owner"))
	var out struct {
		User struct{ ID, AccountKind string } `json:"user"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.User.AccountKind != "admin" {
		t.Fatalf("setup=%d %s", rec.Code, rec.Body.String())
	}
	for name, want := range map[string]string{"admin": "admin|admin|0", "owner": "user|user|0"} {
		var kind, role string
		var flagged int
		if err := db.QueryRow(`SELECT account_kind,role,password_admin_known FROM users WHERE username=?`, name).Scan(&kind, &role, &flagged); err != nil || kind+"|"+role+"|"+strconv.Itoa(flagged) != want {
			t.Fatalf("%s: %s|%s|%d %v", name, kind, role, flagged, err)
		}
	}
	if rec := post(setupBody("admin2", "owner2")); rec.Code != http.StatusForbidden {
		t.Fatalf("second setup=%d", rec.Code)
	}
}

func TestLoginReportsKindAndChangeFlag(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	if _, err := p.db.Exec(`UPDATE users SET password_admin_known=1 WHERE id=?`, admin.id); err != nil {
		t.Fatal(err)
	}
	res := admin.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":"server-admin","authSecret":"`+strings.Repeat("a", 64)+`"}`), false, false)
	code, body := status(t, res)
	var out struct {
		User                   struct{ AccountKind string } `json:"user"`
		PasswordChangeRequired bool                         `json:"passwordChangeRequired"`
		Identity               any                          `json:"identity"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &out) != nil || out.User.AccountKind != "admin" || !out.PasswordChangeRequired || out.Identity != nil {
		t.Fatalf("login=%d %s", code, body)
	}
}
