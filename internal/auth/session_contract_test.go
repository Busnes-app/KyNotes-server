package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/storage"
)

type sessionFixture struct {
	db      *sql.DB
	session Session
	close   func()
}

func newSessionFixture(t *testing.T) sessionFixture {
	t.Helper()
	s, err := storage.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_session','session','hash','salt',100000,'now','now')`)
	if err != nil {
		t.Fatal(err)
	}
	f := sessionFixture{db: s.DB(), close: func() { _ = s.Close() }}
	return f
}

func mintFixtureSession(t *testing.T, f *sessionFixture, now time.Time, insecure bool) (*httptest.ResponseRecorder, http.Request) {
	t.Helper()
	w := httptest.NewRecorder()
	f.session, _ = MintSession(f.db, w, "usr_session", insecure, now)
	var r http.Request
	r.Header = make(http.Header)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	return w, r
}

func TestLoginSucceedsAndSetsBothCookies(t *testing.T) {
	f := newSessionFixture(t)
	defer f.close()
	w, _ := mintFixtureSession(t, &f, time.Now().UTC(), true)
	if len(w.Result().Cookies()) != 2 {
		t.Fatalf("cookies=%d", len(w.Result().Cookies()))
	}
}

func TestSessionCookieIsHttpOnlySecureLax(t *testing.T) {
	f := newSessionFixture(t)
	defer f.close()
	w, _ := mintFixtureSession(t, &f, time.Now().UTC(), false)
	var c *http.Cookie
	for _, x := range w.Result().Cookies() {
		if x.Name == sessionCookie {
			c = x
		}
	}
	if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("bad session cookie %#v", c)
	}
}

func TestCSRFCookieIsReadableByJS(t *testing.T) {
	f := newSessionFixture(t)
	defer f.close()
	w, _ := mintFixtureSession(t, &f, time.Now().UTC(), false)
	for _, c := range w.Result().Cookies() {
		if c.Name == csrfCookie && c.HttpOnly {
			t.Fatal("csrf cookie is HttpOnly")
		}
	}
}

func TestMutatingRequestWithoutCSRFHeaderIsRejected(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "session"})
	r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf"})
	if CheckCSRF(r) == nil {
		t.Fatal("missing CSRF header accepted")
	}
}

func TestSessionSlidesOnlyPastGranularity(t *testing.T) {
	f := newSessionFixture(t)
	defer f.close()
	now := time.Now().UTC().Truncate(time.Second)
	_, r := mintFixtureSession(t, &f, now, true)
	before := f.session.ExpiresAt
	if _, err := ResolveSession(f.db, &r, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var exp string
	_ = f.db.QueryRow(`SELECT expires_at FROM sessions WHERE id=?`, f.session.ID).Scan(&exp)
	if exp != before.Format(time.RFC3339) {
		t.Fatal("session slid too early")
	}
	if _, err := ResolveSession(f.db, &r, now.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var changed string
	_ = f.db.QueryRow(`SELECT expires_at FROM sessions WHERE id=?`, f.session.ID).Scan(&changed)
	if changed == exp {
		t.Fatal("session did not slide")
	}
}

func TestSessionExpiresAfterIdleTimeout(t *testing.T) {
	f := newSessionFixture(t)
	defer f.close()
	now := time.Now().UTC()
	_, r := mintFixtureSession(t, &f, now, true)
	_, _ = f.db.Exec(`UPDATE sessions SET expires_at=? WHERE id=?`, now.Add(-time.Second).Format(time.RFC3339), f.session.ID)
	if _, err := ResolveSession(f.db, &r, now); err == nil {
		t.Fatal("idle session accepted")
	}
}

func TestSessionExpiresAtHardLifetimeDespiteActivity(t *testing.T) {
	f := newSessionFixture(t)
	defer f.close()
	now := time.Now().UTC()
	_, r := mintFixtureSession(t, &f, now, true)
	if _, err := ResolveSession(f.db, &r, now.Add(8*24*time.Hour)); err == nil {
		t.Fatal("hard-expired session accepted")
	}
}

func TestRevokedSessionIsRejectedImmediately(t *testing.T) {
	f := newSessionFixture(t)
	defer f.close()
	now := time.Now().UTC()
	_, r := mintFixtureSession(t, &f, now, true)
	_, _ = f.db.Exec(`UPDATE sessions SET revoked_at='now' WHERE id=?`, f.session.ID)
	if _, err := ResolveSession(f.db, &r, now); err == nil {
		t.Fatal("revoked session accepted")
	}
}

func TestLockoutAfterThreeFailedLogins(t *testing.T) {
	l := NewLockout(3, time.Minute, 10)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !l.Try("user\x00ip", now) {
			t.Fatal("early lock")
		}
		l.Fail("user\x00ip", now)
	}
	if l.Try("user\x00ip", now) {
		t.Fatal("lockout absent")
	}
}

func TestLockoutIsScopedToUsernameAndIP(t *testing.T) {
	l := NewLockout(1, time.Minute, 10)
	now := time.Now()
	if !l.Try("a\x001.1.1.1", now) {
		t.Fatal()
	}
	l.Fail("a\x001.1.1.1", now)
	if !l.Try("b\x001.1.1.1", now) || !l.Try("a\x002.2.2.2", now) {
		t.Fatal("lockout scope leaked")
	}
}

func TestLockoutTableShedsNewKeysWithoutEvictingLiveLockouts(t *testing.T) {
	l := NewLockout(1, time.Hour, 2)
	now := time.Now()
	if !l.Try("live", now) {
		t.Fatal()
	}
	l.Fail("live", now)
	if !l.Try("other", now) {
		t.Fatal()
	}
	l.Fail("other", now)
	if l.Try("new", now) {
		t.Fatal("capacity did not shed new key")
	}
	if l.Try("live", now) {
		t.Fatal("live lockout was evicted")
	}
}

func TestDisabledUserCannotUseValidSessionOrDevice(t *testing.T) {
	f := newSessionFixture(t)
	defer f.close()
	now := time.Now().UTC()
	_, r := mintFixtureSession(t, &f, now, true)
	_, _ = f.db.Exec(`UPDATE users SET status='disabled' WHERE id='usr_session'`)
	if _, err := ResolveSession(f.db, &r, now); err == nil {
		t.Fatal("disabled user session accepted")
	}
}
