package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
)

// liveCookies keeps the cookies a login response set (not the ones it cleared).
func liveCookies(res *httptest.ResponseRecorder) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range res.Result().Cookies() {
		if c.Value != "" && c.MaxAge >= 0 {
			out = append(out, c)
		}
	}
	return out
}

// userReauthFixture signs bob in through SSO with no app role and mounts POST /user-action behind
// RequireUserActionStepUp and POST /action behind the admin RequireStepUp.
func userReauthFixture(t *testing.T) (*logoutFixture, []*http.Cookie) {
	f := newLogoutFixture(t)
	login := roleCallback(f, "bob", nil, "")
	if login.Code != 302 {
		t.Fatal(login.Body.String())
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	mux := f.router.(*http.ServeMux)
	mux.Handle("POST /user-action", auth.RequireUserActionStepUp(f.db, ok))
	mux.Handle("POST /action", auth.RequireStepUp(f.db, ok))
	return f, liveCookies(login)
}

func TestSSOUserStepUpNeedsNoAdminRole(t *testing.T) {
	f, cookies := userReauthFixture(t)
	// The admin route stays closed to a non-admin: no challenge is even offered.
	if r := reauthAction(f, cookies, "", "/action", `{"x":1}`); r.Code != 403 || strings.Contains(r.Body.String(), "sso_step_up_required") {
		t.Fatal("a non-admin was offered an admin challenge", r.Code, r.Body.String())
	}
	id, callback := reauthStartAt(f, cookies, "bob", "/user-action", `{"x":1}`, nil)
	if res := f.send(callback); res.Code != 200 {
		t.Fatal("user challenge refused without an admin role", res.Code, res.Body.String())
	}
	if r := reauthAction(f, cookies, id, "/user-action", `{"x":2}`); r.Code != 403 {
		t.Fatal("a grant for one body admitted another", r.Code)
	}
	if r := reauthAction(f, cookies, id, "/user-action", `{"x":1}`); r.Code != 204 {
		t.Fatal(r.Code, r.Body.String())
	}
	if r := reauthAction(f, cookies, id, "/user-action", `{"x":1}`); r.Code != 403 {
		t.Fatal("grant reused", r.Code)
	}
}

func TestSSOStepUpScopeIsBoundToTheGrant(t *testing.T) {
	f, cookies := reauthFixture(t)
	// An admin challenge answered without kynotes.admin is rejected at the callback.
	_, callback := reauthStartAt(f, cookies, "alice", "/action", `{"target":1}`, nil)
	if res := f.send(callback); res.Code != 403 {
		t.Fatal("admin challenge verified without the admin role", res.Code)
	}
	// A verified admin grant relabelled as a user grant no longer opens the admin route.
	id, callback := reauthStart(f, cookies)
	if res := f.send(callback); res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	if _, err := f.db.Exec(`UPDATE sso_stepup SET scope='user' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if r := reauthAction(f, cookies, id, "/action", `{"target":1}`); r.Code != 403 {
		t.Fatal("a user-scope grant opened an admin route", r.Code)
	}
	// And a user route refuses a grant recorded as admin.
	g, userCookies := userReauthFixture(t)
	uid, ucb := reauthStartAt(g, userCookies, "bob", "/user-action", `{"x":1}`, nil)
	if res := g.send(ucb); res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	if _, err := g.db.Exec(`UPDATE sso_stepup SET scope='admin' WHERE id=?`, uid); err != nil {
		t.Fatal(err)
	}
	if r := reauthAction(g, userCookies, uid, "/user-action", `{"x":1}`); r.Code != 403 {
		t.Fatal("an admin-scope grant opened a user route", r.Code)
	}
}

func TestSSOAdminStepUpRechecksLocalAdminAtVerification(t *testing.T) {
	f, cookies := reauthFixture(t)
	_, callback := reauthStart(f, cookies)
	// Demoted between challenge and proof: a fresh kynotes.admin claim alone does not verify it.
	if _, err := f.db.Exec(`UPDATE users SET role='user' WHERE username='alice'`); err != nil {
		t.Fatal(err)
	}
	if res := f.send(callback); res.Code != 403 {
		t.Fatal("a demoted admin verified an admin challenge", res.Code)
	}
}
