package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busness-app/kynotes-server/internal/auth"
	"github.com/Busness-app/kynotes-server/internal/logging"
	"github.com/Busness-app/kynotes-server/internal/sso"
)

func reauthFixture(t *testing.T) (*logoutFixture, []*http.Cookie) {
	f := newLogoutFixture(t)
	roleCallback(f, "alice", nil, "")
	if _, err := f.db.Exec(`UPDATE users SET role='admin' WHERE username='alice'`); err != nil {
		t.Fatal(err)
	}
	login := roleCallback(f, "alice", []string{sso.AdminAppRole}, "")
	if login.Code != 302 {
		t.Fatal(login.Body.String())
	}
	for _, path := range []string{"/action", "/other"} {
		f.router.(*http.ServeMux).Handle("POST "+path, auth.RequireStepUp(f.db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	}
	var cookies []*http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Value != "" && c.MaxAge >= 0 {
			cookies = append(cookies, c)
		}
	}
	return f, cookies
}
func reauthAction(f *logoutFixture, cookies []*http.Cookie, id, path, body string) *httptest.ResponseRecorder {
	req := withCookies(httptest.NewRequest("POST", path, strings.NewReader(body)), cookies)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Kynotes-Step-Up", id)
	return f.send(req)
}
func reauthStart(f *logoutFixture, cookies []*http.Cookie) (string, *http.Request) {
	f.t.Helper()
	blocked := reauthAction(f, cookies, "", "/action", `{"target":1}`)
	var detail struct{ Error struct{ Challenge string } }
	if blocked.Code != 403 || json.Unmarshal(blocked.Body.Bytes(), &detail) != nil || detail.Error.Challenge == "" {
		f.t.Fatalf("challenge: %d %s", blocked.Code, blocked.Body.String())
	}
	id := detail.Error.Challenge
	req := withCookies(httptest.NewRequest("POST", "/api/v1/auth/oidc/step-up", strings.NewReader(`{"challenge":"`+id+`"}`)), cookies)
	res := f.send(req)
	var start struct{ URL string }
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &start) != nil {
		f.t.Fatalf("start: %d %s", res.Code, res.Body.String())
	}
	dest, err := url.Parse(start.URL)
	if err != nil {
		f.t.Fatal(err)
	}
	q := dest.Query()
	if q.Get("prompt") != "login" || q.Get("max_age") != "0" || q.Get("acr_values") != "urn:kysignon:acr:password" || q.Get("code_challenge") == "" {
		f.t.Fatal("missing fresh login binding")
	}
	state := q.Get("state")
	now := time.Now().Unix()
	f.mu.Lock()
	f.proofs[state] = map[string]any{"iss": f.issuer.URL, "aud": "kynotes", "sub": "alice", "sid": "fresh-proof", "iat": now, "exp": now + 3600, "nonce": q.Get("nonce"), "auth_time": now, "acr": "urn:kysignon:acr:password", "amr": []string{"pwd"}, "roles": []string{sso.AdminAppRole}}
	f.mu.Unlock()
	callback := withCookies(httptest.NewRequest("GET", "/api/v1/auth/oidc/callback?code="+state+"&state="+state, nil), cookies)
	for _, cookie := range res.Result().Cookies() {
		callback.AddCookie(cookie)
	}
	return id, callback
}
func TestSSOStepUpBindsActionAndConsumesOnce(t *testing.T) {
	f, cookies := reauthFixture(t)
	id, callback := reauthStart(f, cookies)
	if res := f.send(callback); res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	// Callback keeps the original session and cannot be replayed.
	if res := f.send(callback); res.Code != 400 {
		t.Fatal("callback replay", res.Code)
	}
	for _, tc := range []struct{ path, body string }{{"/other", `{"target":1}`}, {"/action", `{"target":2}`}, {"/action?extra=1", `{"target":1}`}} {
		if r := reauthAction(f, cookies, id, tc.path, tc.body); r.Code != 403 {
			t.Fatal("wrong action admitted", r.Code)
		}
	}
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- reauthAction(f, cookies, id, "/action", `{"target":1}`).Code }()
	}
	wg.Wait()
	close(codes)
	successes := 0
	for code := range codes {
		if code == 204 {
			successes++
		} else if code != 403 {
			t.Fatal(code)
		}
	}
	if successes != 1 {
		t.Fatal("grant not single-use", successes)
	}
	var verified, consumed int
	if err := f.db.QueryRow(`SELECT count(*) FROM audit_events WHERE event='auth.sso_step_up.verify'`).Scan(&verified); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM audit_events WHERE event='auth.sso_step_up.consume'`).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if verified != 1 || consumed != 1 {
		t.Fatal("audit", verified, consumed)
	}
}
func TestSSOStepUpRejectsUnprovenAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"stale", func(c map[string]any) { c["auth_time"] = time.Now().Add(-time.Hour).Unix() }},
		{"missing", func(c map[string]any) { delete(c, "auth_time") }},
		{"future", func(c map[string]any) { c["auth_time"] = time.Now().Add(time.Minute).Unix() }},
		{"recovery", func(c map[string]any) {
			c["acr"] = "urn:kysignon:acr:recovery"
			c["amr"] = []string{"pwd", "urn:kysignon:amr:recovery"}
		}},
		{"malformed-methods", func(c map[string]any) { c["amr"] = []any{"pwd", 1} }},
		{"missing-assurance", func(c map[string]any) { delete(c, "acr") }},
		{"wrong-account", func(c map[string]any) { c["sub"] = "bob" }},
		{"no-admin", func(c map[string]any) { c["roles"] = []string{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, cookies := reauthFixture(t)
			id, callback := reauthStart(f, cookies)
			f.mu.Lock()
			tc.edit(f.proofs[callback.URL.Query().Get("state")])
			f.mu.Unlock()
			if r := f.send(callback); r.Code != 403 {
				t.Fatal("invalid proof", r.Code, r.Body.String())
			}
			if r := reauthAction(f, cookies, id, "/action", `{"target":1}`); r.Code != 403 {
				t.Fatal("invalid grant", r.Code)
			}
		})
	}
}
func TestSSOStepUpCancellationRevocationAndAudit(t *testing.T) {
	for _, mode := range []string{"cancel", "expire", "logout-parent", "logout-proof", "disable", "role-loss", "settings", "verify-audit", "consume-audit", "other-session"} {
		t.Run(mode, func(t *testing.T) {
			f, cookies := reauthFixture(t)
			id, callback := reauthStart(f, cookies)
			if mode == "verify-audit" {
				if _, err := f.db.Exec(`CREATE TRIGGER reject_reauth BEFORE INSERT ON audit_events WHEN NEW.event='auth.sso_step_up.verify' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "cancel" {
				r := f.send(withCookies(httptest.NewRequest("DELETE", "/api/v1/auth/oidc/step-up/"+id, nil), cookies))
				if r.Code != 204 {
					t.Fatal(r.Code)
				}
			}
			if mode == "expire" {
				if _, err := f.db.Exec(`UPDATE sso_stepup SET expires_at=0`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "other-session" {
				other := roleCallback(f, "alice", []string{sso.AdminAppRole}, "")
				stateCookie, _ := callback.Cookie(ssoCookieName)
				callback.Header.Del("Cookie")
				for _, cookie := range other.Result().Cookies() {
					if cookie.Value != "" {
						callback.AddCookie(cookie)
					}
				}
				callback.AddCookie(stateCookie)
			}
			r := f.send(callback)
			if mode == "cancel" || mode == "expire" || mode == "verify-audit" || mode == "other-session" {
				if r.Code == 200 {
					t.Fatal("callback admitted", mode)
				}
				return
			}
			if r.Code != 200 {
				t.Fatal("verify", r.Code, r.Body.String())
			}
			switch mode {
			case "logout-parent":
				if res := f.logout(f.sign("logout+jwt", f.logoutClaims("revoke-parent", "alice", "role-session"))); res.Code != 200 {
					t.Fatal(res.Code)
				}
			case "logout-proof":
				if res := f.logout(f.sign("logout+jwt", f.logoutClaims("revoke-proof", "alice", "fresh-proof"))); res.Code != 200 {
					t.Fatal(res.Code)
				}
			case "disable":
				if _, err := f.db.Exec(`UPDATE users SET status='disabled' WHERE username='alice'`); err != nil {
					t.Fatal(err)
				}
			case "role-loss":
				if _, err := f.db.Exec(`UPDATE users SET role='user' WHERE username='alice'`); err != nil {
					t.Fatal(err)
				}
			case "settings":
				settings := f.settings.Load()
				settings.ClientID = "changed"
				if err := f.settings.Save(settings); err != nil {
					t.Fatal(err)
				}
			case "consume-audit":
				if _, err := f.db.Exec(`CREATE TRIGGER reject_reauth BEFORE INSERT ON audit_events WHEN NEW.event='auth.sso_step_up.consume' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
					t.Fatal(err)
				}
			}
			if res := reauthAction(f, cookies, id, "/action", `{"target":1}`); res.Code == 204 {
				t.Fatal("revocation bypassed", mode)
			}
		})
	}
}

func TestSSOStepUpFreshMFAAndRestart(t *testing.T) {
	f, cookies := reauthFixture(t)
	id, callback := reauthStart(f, cookies)
	f.mu.Lock()
	claims := f.proofs[callback.URL.Query().Get("state")]
	claims["acr"] = "urn:kysignon:acr:mfa"
	claims["amr"] = []string{"pwd", "otp", "mfa"}
	f.mu.Unlock()
	if r := f.send(callback); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	f.restartRouter()
	f.router.(*http.ServeMux).Handle("POST /action", auth.RequireStepUp(f.db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	if r := reauthAction(f, cookies, id, "/action", `{"target":1}`); r.Code != 204 {
		t.Fatal("verified grant across restart", r.Code, r.Body.String())
	}
	_, pending := reauthStart(f, cookies)
	f.restartRouter()
	if r := f.send(pending); r.Code != 400 {
		t.Fatal("pending callback survived lost PKCE", r.Code)
	}
}

func TestSSOStepUpAdmissionFailures(t *testing.T) {
	for _, mode := range []string{"csrf", "password-window", "audit", "revoke-during-exchange", "expire-verified", "cancel-verified"} {
		t.Run(mode, func(t *testing.T) {
			f, cookies := reauthFixture(t)
			if mode == "csrf" {
				req := withCookies(httptest.NewRequest("POST", "/action", nil), cookies)
				req.Header.Del("X-CSRF-Token")
				if r := f.send(req); r.Code != 403 {
					t.Fatal(r.Code)
				}
				var count int
				if err := f.db.QueryRow(`SELECT count(*) FROM sso_stepup`).Scan(&count); err != nil || count != 0 {
					t.Fatal("CSRF allocated a challenge", count, err)
				}
				return
			}
			if mode == "password-window" {
				if _, err := f.db.Exec(`UPDATE sessions SET stepup_at=?`, time.Now().UTC().Format(time.RFC3339)); err != nil {
					t.Fatal(err)
				}
				if r := reauthAction(f, cookies, "", "/action", ""); r.Code != 403 || !strings.Contains(r.Body.String(), "sso_step_up_required") {
					t.Fatal("password bypassed OIDC", r.Code)
				}
				return
			}
			if mode == "audit" {
				if _, err := f.db.Exec(`CREATE TRIGGER reject_start BEFORE INSERT ON audit_events WHEN NEW.event='auth.sso_step_up.start' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
					t.Fatal(err)
				}
				if r := reauthAction(f, cookies, "", "/action", ""); r.Code != 500 {
					t.Fatal("unaudited challenge", r.Code)
				}
				var count int
				if err := f.db.QueryRow(`SELECT count(*) FROM sso_stepup`).Scan(&count); err != nil || count != 0 {
					t.Fatal(count, err)
				}
				return
			}
			id, callback := reauthStart(f, cookies)
			if mode == "revoke-during-exchange" {
				f.tokenHook = func() {
					if _, err := f.db.Exec(`UPDATE sessions SET revoked_at='revoked'`); err != nil {
						t.Fatal(err)
					}
				}
			}
			r := f.send(callback)
			if mode == "revoke-during-exchange" {
				if r.Code != 403 {
					t.Fatal("raced revocation", r.Code)
				}
				return
			}
			if r.Code != 200 {
				t.Fatal(r.Code, r.Body.String())
			}
			if mode == "expire-verified" {
				if _, err := f.db.Exec(`UPDATE sso_stepup SET expires_at=0`); err != nil {
					t.Fatal(err)
				}
			} else {
				if r := f.send(withCookies(httptest.NewRequest("DELETE", "/api/v1/auth/oidc/step-up/"+id, nil), cookies)); r.Code != 204 {
					t.Fatal(r.Code)
				}
			}
			if r := reauthAction(f, cookies, id, "/action", `{"target":1}`); r.Code != 403 {
				t.Fatal("expired/cancelled grant", r.Code)
			}
		})
	}
}

func TestSSOStepUpAuditUsesTrustedRequestID(t *testing.T) {
	f, cookies := reauthFixture(t)
	wrapped := Middleware(logging.New(io.Discard, "info", "json"), 1<<20)(f.router)
	f.router = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("X-Request-Id", "forged")
		wrapped.ServeHTTP(w, r)
	})
	id, callback := reauthStart(f, cookies)
	if r := f.send(callback); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	if r := reauthAction(f, cookies, id, "/action", `{"target":1}`); r.Code != 204 {
		t.Fatal(r.Code, r.Body.String())
	}
	for _, event := range []string{"auth.sso_step_up.start", "auth.sso_step_up.consume"} {
		var requestID string
		if err := f.db.QueryRow(`SELECT request_id FROM audit_events WHERE event=?`, event).Scan(&requestID); err != nil {
			t.Fatal(err)
		}
		if requestID == "" || requestID == "forged" {
			t.Errorf("%s trusted correlation lost: %q", event, requestID)
		}
	}
}

func TestSSOStepUpCancellationAuditsOnlyOwnedDeletion(t *testing.T) {
	f, cookies := reauthFixture(t)
	missing := "rea_00000000000000000000000000"
	cancel := func(id string, cookies []*http.Cookie) int {
		return f.send(withCookies(httptest.NewRequest("DELETE", "/api/v1/auth/oidc/step-up/"+id, nil), cookies)).Code
	}
	assertCounts := func(audits, challenges int) {
		t.Helper()
		var gotAudits, gotChallenges int
		if err := f.db.QueryRow(`SELECT count(*) FROM audit_events WHERE event='auth.sso_step_up.cancel'`).Scan(&gotAudits); err != nil {
			t.Fatal(err)
		}
		if err := f.db.QueryRow(`SELECT count(*) FROM sso_stepup`).Scan(&gotChallenges); err != nil {
			t.Fatal(err)
		}
		if gotAudits != audits || gotChallenges != challenges {
			t.Errorf("cancellation audits=%d challenges=%d; want %d,%d", gotAudits, gotChallenges, audits, challenges)
		}
	}
	for i := 0; i < 2; i++ {
		if code := cancel(missing, cookies); code != 204 {
			t.Errorf("idempotent miss: %d", code)
		}
	}
	if code := cancel(strings.Repeat("x", 1<<20), cookies); code != 400 {
		t.Errorf("oversized ID: %d", code)
	}
	assertCounts(0, 0)
	ordinary := f.login("bob", "ordinary")
	if code := cancel(missing, ordinary); code != 403 {
		t.Errorf("non-admin cancellation: %d", code)
	}
	id, _ := reauthStart(f, cookies)
	other := roleCallback(f, "alice", []string{sso.AdminAppRole}, "")
	if code := cancel(id, other.Result().Cookies()); code != 204 {
		t.Errorf("foreign session: %d", code)
	}
	assertCounts(0, 1)
	if _, err := f.db.Exec(`CREATE TRIGGER reject_cancel BEFORE INSERT ON audit_events WHEN NEW.event='auth.sso_step_up.cancel' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if code := cancel(id, cookies); code != 500 {
		t.Errorf("failed audit: %d", code)
	}
	assertCounts(0, 1)
	if _, err := f.db.Exec(`DROP TRIGGER reject_cancel`); err != nil {
		t.Fatal(err)
	}
	if code := cancel(id, cookies); code != 204 {
		t.Errorf("owned cancellation: %d", code)
	}
	if code := cancel(id, cookies); code != 204 {
		t.Errorf("repeated cancellation: %d", code)
	}
	assertCounts(1, 0)
}
