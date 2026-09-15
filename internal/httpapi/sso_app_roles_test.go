package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kynotes-server/internal/auth"
	"github.com/Busness-app/kynotes-server/internal/sso"
)

func roleCallback(f *logoutFixture, subject string, roles any, legacy string) *httptest.ResponseRecorder {
	f.t.Helper()
	req := f.beginLogin(subject, "role-session", time.Now().Add(time.Second))
	f.mu.Lock()
	claims := f.proofs[req.URL.Query().Get("state")]
	claims["role"] = legacy
	if roles != nil {
		claims["roles"] = roles
	}
	f.mu.Unlock()
	return f.send(req)
}

func TestSSOAppRolesRequireExplicitTokenAndAccountPermission(t *testing.T) {
	f := newLogoutFixture(t)
	f.router.(*http.ServeMux).Handle("GET /admin-protected", auth.RequireAdmin(f.db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	settings := f.settings.Load()
	settings.HMACSecret = strings.Repeat("s", 32)
	if err := f.settings.Save(settings); err != nil {
		t.Fatal(err)
	}
	admin := func(cookies []*http.Cookie) int {
		return f.send(withCookies(httptest.NewRequest("GET", "/admin-protected", nil), cookies)).Code
	}
	provision := func(version int64, roles []any, want int) {
		t.Helper()
		p := directoryPayload("alice", "alice", version, true)
		p["roles"] = roles
		r := sendDirectory(t, f.router, "/sync/events", settings.HMACSecret, "roles-"+time.Now().String(), "user.updated", p)
		if r.Code != want {
			t.Fatalf("provision %d %s", r.Code, r.Body.String())
		}
	}
	// A legacy global administrator claim never grants product administration.
	legacy := roleCallback(f, "alice", nil, "admin")
	if legacy.Code != 302 || admin(legacy.Result().Cookies()) != 403 {
		t.Fatalf("legacy role admitted %d", legacy.Code)
	}
	var role string
	if err := f.db.QueryRow(`SELECT role FROM users WHERE username='alice'`).Scan(&role); err != nil || role != "user" {
		t.Fatalf("legacy role persisted %q %v", role, err)
	}
	// The token alone is insufficient; provisioning/local account permission must agree.
	tokenOnly := roleCallback(f, "alice", []string{sso.AdminAppRole}, "admin")
	if tokenOnly.Code != 302 || admin(tokenOnly.Result().Cookies()) != 403 {
		t.Fatal("token bypassed account permission")
	}
	provision(1, []any{map[string]any{"value": "admin"}}, 200)
	if roleCallback(f, "alice", []string{"admin"}, "admin").Code != 302 {
		t.Fatal("ordinary login refused")
	}
	provision(2, []any{map[string]any{"value": sso.AdminAppRole}}, 200)
	if admin(legacy.Result().Cookies()) != 401 || admin(tokenOnly.Result().Cookies()) != 401 {
		t.Fatal("promotion revived old sessions")
	}
	user := roleCallback(f, "alice", []string{}, "admin")
	if user.Code != 302 || admin(user.Result().Cookies()) != 403 {
		t.Fatal("account role bypassed token ceiling")
	}
	me := f.send(withCookies(httptest.NewRequest("GET", "/api/v1/auth/session", nil), user.Result().Cookies()))
	var session struct{ User struct{ Role string } }
	if me.Code != 200 || json.Unmarshal(me.Body.Bytes(), &session) != nil || session.User.Role != "user" {
		t.Fatalf("session reported wrong permission: %d %s", me.Code, me.Body.String())
	}
	elevated := roleCallback(f, "alice", []string{sso.AdminAppRole}, "user")
	if elevated.Code != 302 || admin(elevated.Result().Cookies()) != 204 {
		t.Fatalf("app role not granted: %d", elevated.Code)
	}
	// A local password session has the same account role and is also revoked on loss.
	var uid string
	if err := f.db.QueryRow(`SELECT id FROM users WHERE username='alice'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	local := httptest.NewRecorder()
	if _, err := auth.MintSession(f.db, local, uid, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if admin(local.Result().Cookies()) != 204 {
		t.Fatal("local account admin denied")
	}
	if res := f.register(f.pairing(local.Result().Cookies())); res.Code != 200 {
		t.Fatalf("local device pairing: %d %s", res.Code, res.Body.String())
	}

	// Failed audit cannot partially demote or consume a role revision.
	if _, err := f.db.Exec(`CREATE TRIGGER fail_role_audit BEFORE INSERT ON audit_events WHEN NEW.event='directory.apply' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	provision(3, []any{}, 500)
	if admin(elevated.Result().Cookies()) != 204 {
		t.Fatal("failed role mutation changed access")
	}
	if _, err := f.db.Exec(`DROP TRIGGER fail_role_audit`); err != nil {
		t.Fatal(err)
	}
	pending := f.beginLogin("alice", "old-admin-proof", time.Now().Add(-time.Second))
	f.mu.Lock()
	f.proofs[pending.URL.Query().Get("state")]["roles"] = []string{sso.AdminAppRole}
	f.mu.Unlock()
	provision(3, []any{}, 200)
	if admin(elevated.Result().Cookies()) != 401 || admin(local.Result().Cookies()) != 401 {
		t.Fatal("role removal retained credentials")
	}
	var liveDevices int
	if err := f.db.QueryRow(`SELECT count(*) FROM devices WHERE user_id=? AND revoked_at=''`, uid).Scan(&liveDevices); err != nil || liveDevices != 0 {
		t.Fatalf("role removal retained devices: %d %v", liveDevices, err)
	}

	// A signed old ID token can finish login, but cannot override the newer directory role.
	old := roleCallback(f, "alice", []string{sso.AdminAppRole}, "admin")
	if old.Code != 302 || admin(old.Result().Cookies()) != 403 {
		t.Fatal("old roles overrode directory")
	}
	provision(4, []any{map[string]any{"value": sso.AdminAppRole}}, 200)
	if res := f.send(pending); res.Code != 403 {
		t.Fatalf("role regrant revived old callback: %d %s", res.Code, res.Body.String())
	}

	if admin(elevated.Result().Cookies()) != 401 {
		t.Fatal("role regrant revived session")
	}
}

func TestSSOAppRolesRejectMalformedClaims(t *testing.T) {
	f := newLogoutFixture(t)
	for _, roles := range []any{"kynotes.admin", []any{1}, []string{"bad role"}, []string{strings.Repeat("x", 65)}, make([]string, 65), json.RawMessage("null")} {
		if r := roleCallback(f, "alice", roles, "admin"); r.Code == 302 {
			t.Fatalf("accepted malformed roles %#v", roles)
		}
	}
}

func TestDirectoryAppRoleShapes(t *testing.T) {
	db, cfg := setupTestDB(t)
	store := sso.NewStore(db)
	secret := strings.Repeat("s", 32)
	if err := store.Save(sso.SSOSettings{HMACSecret: secret, IssuerURL: "https://issuer.example"}); err != nil {
		t.Fatal(err)
	}
	router := http.NewServeMux()
	SSORoutes(router, db, cfg, store)
	for _, roles := range []any{nil, "admin", []any{map[string]any{"value": 1}}, []any{map[string]any{"value": "bad role"}}, make([]any, 65)} {
		p := directoryPayload("alice", "alice", 1, true)
		p["roles"] = roles
		if r := sendDirectory(t, router, "/sync/events", secret, "bad", "user.updated", p); r.Code != 400 {
			t.Fatalf("bad roles accepted %d %s", r.Code, r.Body.String())
		}
	}
	// Omission is not an assertion of an empty set.
	p := directoryPayload("alice", "alice", 1, true)
	delete(p, "roles")
	body, _ := json.Marshal(p)
	req := httptest.NewRequest("POST", "/sync/events", bytes.NewReader(body))
	signSync(t, req, secret, "missing", "user.updated", body)
	r := httptest.NewRecorder()
	router.ServeHTTP(r, req)
	if r.Code != 400 {
		t.Fatalf("missing roles accepted %d", r.Code)
	}
}
