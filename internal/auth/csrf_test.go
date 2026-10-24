package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// csrfCookies mints a session and returns its session cookie and CSRF token.
func csrfCookies(t *testing.T, f *sessionFixture) (session, csrf string) {
	t.Helper()
	w, _ := mintFixtureSession(t, f, time.Now().UTC(), true)
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case sessionCookie:
			session = c.Value
		case csrfCookie:
			csrf = c.Value
		}
	}
	if session == "" || csrf == "" {
		t.Fatal("session or csrf cookie missing")
	}
	return session, csrf
}

func csrfRequest(session, cookie, header string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	if session != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: csrfCookie, Value: cookie})
	}
	if header != "" {
		r.Header.Set("X-CSRF-Token", header)
	}
	return r
}

func TestCSRFTokenIsBoundToSession(t *testing.T) {
	f := newSessionFixture(t)
	defer f.close()
	sessA, csrfA := csrfCookies(t, &f)
	sessB, csrfB := csrfCookies(t, &f)
	if csrfA == csrfB {
		t.Fatal("two sessions share a CSRF token")
	}
	if f.session.CSRF != csrfB || CSRFToken(sessB) != csrfB {
		t.Fatal("CSRF token is not the session's HMAC")
	}
	if err := CheckCSRF(csrfRequest(sessA, csrfA, csrfA)); err != nil {
		t.Fatalf("legitimate request refused: %v", err)
	}
	for name, r := range map[string]*http.Request{
		// The attack: a valid pair from session A, tossed into session B's browser.
		"token from session A on session B":       csrfRequest(sessB, csrfA, csrfA),
		"session A header, session B cookie":      csrfRequest(sessB, csrfB, csrfA),
		"missing header":                          csrfRequest(sessB, csrfB, ""),
		"attacker double-submit pair":             csrfRequest(sessB, "attacker", "attacker"),
		"forged token of the right shape":         csrfRequest(sessB, "", strings.Repeat("A", len(csrfB))),
		"session token as the CSRF token":         csrfRequest(sessB, "", sessB),
		"token one character off":                 csrfRequest(sessB, "", csrfB[:len(csrfB)-1]+flip(csrfB[len(csrfB)-1])),
		"empty session cookie value, valid token": emptySession(CSRFToken("")),
	} {
		if CheckCSRF(r) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func flip(b byte) string {
	if b == 'A' {
		return "B"
	}
	return "A"
}

func emptySession(header string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Cookie", sessionCookie+"=")
	r.Header.Set("X-CSRF-Token", header)
	return r
}

func TestCSRFTokenDependsOnServerKey(t *testing.T) {
	old := csrfKey.Load()
	t.Cleanup(func() { csrfKey.Store(old) })
	SetCSRFKey(strings.Repeat("k", 32))
	first := CSRFToken("session")
	SetCSRFKey(strings.Repeat("k", 32))
	if CSRFToken("session") != first {
		t.Fatal("the same secret derived a different key")
	}
	SetCSRFKey(strings.Repeat("j", 32))
	if CSRFToken("session") == first {
		t.Fatal("a different secret produced the same token")
	}
	before := CSRFToken("session")
	SetCSRFKey("short")
	if CSRFToken("session") != before {
		t.Fatal("a too-short secret replaced the key")
	}
}

func TestRefreshCSRFCookieRebindsAPreUpgradeSession(t *testing.T) {
	f := newSessionFixture(t)
	defer f.close()
	sess, csrf := csrfCookies(t, &f)
	r := csrfRequest(sess, "random-pre-upgrade-value", "")
	w := httptest.NewRecorder()
	RefreshCSRFCookie(w, r, true)
	var got string
	for _, c := range w.Result().Cookies() {
		if c.Name == csrfCookie {
			got = c.Value
			if c.HttpOnly {
				t.Fatal("refreshed csrf cookie is HttpOnly")
			}
		}
	}
	if got != csrf {
		t.Fatalf("refreshed token %q, want the session's %q", got, csrf)
	}
}
