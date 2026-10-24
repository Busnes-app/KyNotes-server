package httpapi

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// A CSRF token must only work for the session it was issued to. Before it was bound, any
// csrf_token cookie/header pair passed, so a sibling origin could toss in its own pair.
func TestCSRFTokenFromAnotherSessionIsRefused(t *testing.T) {
	root := t.TempDir()
	s, e := storage.Open(filepath.Join(root, "db.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	b, e := blobstore.New(root)
	if e != nil {
		t.Fatal(e)
	}
	secret := strings.Repeat("a", 64)
	hash, e := auth.HashAuthSecret(secret)
	if e != nil {
		t.Fatal(e)
	}
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	for _, u := range []struct{ id, name string }{{"usr_alice", "alice"}, {"usr_mallory", "mallory"}} {
		if _, e = s.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, u.id, u.name, hash, salt, 100000, "user", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); e != nil {
			t.Fatal(e)
		}
	}
	cfg := config.Defaults()
	cfg.Server.DevInsecureCookies = true
	cfg.Server.Bind = "127.0.0.1:0"
	srv := httptest.NewServer(NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, s.DB(), b, cfg))
	defer srv.Close()

	type creds struct{ session, csrf string }
	login := func(user string) creds {
		res, err := http.Post(srv.URL+"/api/v1/auth/login", "application/json", strings.NewReader(`{"username":"`+user+`","authSecret":"`+secret+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("login %s: %d", user, res.StatusCode)
		}
		var c creds
		for _, x := range res.Cookies() {
			switch x.Name {
			case "kynotes_session":
				c.session = x.Value
			case "csrf_token":
				c.csrf = x.Value
			}
		}
		if c.session == "" || c.csrf == "" {
			t.Fatalf("login %s: cookies missing", user)
		}
		return c
	}
	createContainer := func(session, csrfCookie, csrfHeader string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/containers", strings.NewReader(`{"kind":"workbook","metaCiphertext":""}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(keySchemeHeader, keySchemeShared)
		req.AddCookie(&http.Cookie{Name: "kynotes_session", Value: session})
		if csrfCookie != "" {
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfCookie})
		}
		if csrfHeader != "" {
			req.Header.Set("X-CSRF-Token", csrfHeader)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}

	victim := login("alice")
	victim2 := login("alice") // a second session of the same account
	attacker := login("mallory")

	for name, got := range map[string]int{
		"attacker's own pair tossed into the victim's browser": createContainer(victim.session, attacker.csrf, attacker.csrf),
		"another session of the same account":                  createContainer(victim.session, victim2.csrf, victim2.csrf),
		"missing token":                                        createContainer(victim.session, victim.csrf, ""),
		"forged double-submit pair":                            createContainer(victim.session, "forged", "forged"),
	} {
		if got != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", name, got)
		}
	}
	if got := createContainer(victim.session, victim.csrf, victim.csrf); got != 200 {
		t.Fatalf("legitimate request: status %d", got)
	}
	// The header alone carries the proof; the cookie only tells the web app the value.
	if got := createContainer(victim.session, "", victim.csrf); got != 200 {
		t.Fatalf("legitimate request without csrf cookie: status %d", got)
	}

	// A session minted before tokens were bound holds a random csrf_token; reading the
	// session (what the web app does on load) hands it the bound one.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: "kynotes_session", Value: victim.session})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "pre-upgrade-random-value"})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	var refreshed string
	for _, x := range res.Cookies() {
		if x.Name == "csrf_token" {
			refreshed = x.Value
		}
	}
	if res.StatusCode != 200 || refreshed != victim.csrf {
		t.Fatalf("session read: status %d, refreshed csrf %q, want %q", res.StatusCode, refreshed, victim.csrf)
	}
}
