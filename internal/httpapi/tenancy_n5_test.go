package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/sso"
)

// N5: in multi mode only the staff org's administrator accounts sign in with a password. Any
// other account answers exactly as an unknown name: the same login parameters (a synthetic salt,
// not its stored one) and the same refusal.
func TestMultiModePasswordSignInIsStaffOnly(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	toMultiMode(t, p.db, "org_staff")
	staff := p.addAdminInOrg(t, "staff-admin", "org_staff")
	_ = staff
	login := func(username string) (int, string) {
		return status(t, p.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":`+quote(username)+`,"authSecret":"`+strings.Repeat("a", 64)+`"}`), false, false))
	}
	params := func(username string) string {
		_, body := status(t, p.do(t, http.MethodPost, "/api/v1/auth/login-params", []byte(`{"username":`+quote(username)+`}`), false, false))
		return body
	}
	if code, body := login("staff-admin"); code != http.StatusOK {
		t.Fatalf("staff administrator: %d %s", code, body)
	}
	customerCode, customerBody := login("pair") // the right secret, an everyday account
	unknownCode, unknownBody := login("nobody-here")
	if customerCode != http.StatusUnauthorized || customerCode != unknownCode || errorCode(t, customerBody) != errorCode(t, unknownBody) {
		t.Fatalf("customer password sign-in=%d %s; unknown name=%d %s", customerCode, customerBody, unknownCode, unknownBody)
	}
	var stored string
	if err := p.db.QueryRow(`SELECT login_salt FROM users WHERE username='pair'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(params("pair"), stored) {
		t.Fatal("login parameters disclose a customer account's stored salt")
	}
}

// N5: a hosted install is never set up or configured through KyNotes: first-run setup, the
// admin SSO writes and apply-setup answer 404 in multi mode, before any other check.
func TestMultiModeRefusesSetupAndSSOConfiguration(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	toMultiMode(t, p.db, "org_staff")
	staff := p.addAdminInOrg(t, "staff-admin", "org_staff")
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/setup", ""}, {http.MethodGet, "/api/setup", ""},
		{http.MethodPost, "/api/v1/setup", `{}`}, {http.MethodPost, "/api/setup", `{}`},
		{http.MethodPost, "/api/v1/admin/sso", `{}`}, {http.MethodPost, "/api/v1/admin/sso/pair", `{}`},
	} {
		if code, body := status(t, staff.do(t, c.method, c.path, []byte(c.body), true, false)); code != http.StatusNotFound || errorCode(t, body) != "not_found" {
			t.Errorf("%s %s: %d %s, want 404", c.method, c.path, code, body)
		}
	}
	cfg := config.Defaults()
	h := SetupHandler(SetupDeps{DB: p.db, Config: cfg, SSO: sso.NewStore(p.db), Log: logging.New(io.Discard, "info", "json")})
	res := httptest.NewRecorder()
	h.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/v1/apply-setup", strings.NewReader(`{}`)))
	if res.Code != http.StatusNotFound {
		t.Fatalf("apply-setup: %d %s", res.Code, res.Body.String())
	}
}
