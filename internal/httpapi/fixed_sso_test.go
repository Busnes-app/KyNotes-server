package httpapi

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func TestFixedSSOSettingsAuthenticateAcrossPoolsWithoutDatabaseSecrets(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("native PostgreSQL shared login state")
	}
	first := newLogoutFixture(t)
	second := &logoutFixture{t: t, db: replicaDB(t, first.db), cfg: first.cfg}
	toMultiMode(t, first.db, "org_staff")
	for _, org := range []string{storage.DefaultOrgID, "org_other"} {
		if _, err := first.db.Exec(`INSERT INTO orgs(id,status,home_region) VALUES(?,'active','local') ON CONFLICT(id) DO NOTHING`, org); err != nil {
			t.Fatal(err)
		}
	}
	settings := first.settings.Load()
	settings.ClientSecret = "fixed-environment-client-secret"
	settings.HMACSecret = strings.Repeat("h", 32)
	if _, err := first.db.Exec(`DELETE FROM server_settings WHERE key LIKE 'sso_%'`); err != nil {
		t.Fatal(err)
	}
	install := func(f *logoutFixture, snapshot sso.SSOSettings) {
		f.settings = sso.NewFixedStore(snapshot)
		mux := http.NewServeMux()
		SSORoutes(mux, f.db, f.cfg, f.settings)
		f.router = mux
	}
	install(first, settings)
	install(second, settings)
	request := func(org string) *http.Request {
		req := first.beginLogin("fixed-user", "sid", time.Now())
		state := req.URL.Query().Get("state")
		first.mu.Lock()
		first.proofs[state]["org_id"] = org
		first.mu.Unlock()
		return req
	}
	// Inserting stale settings cannot change either replica's deployment snapshot.
	if _, err := first.db.Exec(`INSERT INTO server_settings(key,value,updated_at) VALUES('sso_issuer_url','https://untrusted.example','t')`); err != nil {
		t.Fatal(err)
	}
	if err := second.settings.Reload(); err != nil {
		t.Fatal(err)
	}
	req := request(storage.DefaultOrgID)
	if res := second.send(req); res.Code != 302 {
		t.Fatalf("fixed cross-pool callback: %d %s", res.Code, res.Body.String())
	}
	if res := first.send(req); res.Code != 400 {
		t.Fatalf("replayed callback: %d %s", res.Code, res.Body.String())
	}
	if res := second.send(request("org_other")); res.Code != 403 || errorCode(t, res.Body.String()) != "org_mismatch" {
		t.Fatalf("wrong org: %d %s", res.Code, res.Body.String())
	}
	// A differing environment snapshot consumes/refuses the state, even with the same issuer.
	req = request(storage.DefaultOrgID)
	changed := settings
	changed.ClientSecret = "other-environment-secret"
	install(second, changed)
	if res := second.send(req); res.Code != 400 {
		t.Fatalf("changed environment accepted state: %d", res.Code)
	}
	if res := first.send(req); res.Code != 400 {
		t.Fatalf("refused state remained replayable: %d", res.Code)
	}
	var n int
	if err := first.db.QueryRow(`SELECT count(*) FROM server_settings WHERE value IN (?,?)`, settings.ClientSecret, settings.HMACSecret).Scan(&n); err != nil || n != 0 {
		t.Fatal("environment secret entered settings", n, err)
	}
	req = request(storage.DefaultOrgID)
	var payload []byte
	if err := first.db.QueryRow(`SELECT payload FROM replica_logins WHERE state_hash=?`, storage.StateHash(req.URL.Query().Get("state"))).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), settings.ClientSecret) || strings.Contains(string(payload), settings.HMACSecret) {
		t.Fatal("pending state contains deployment secrets")
	}
	readback := sendDirectory(t, first.router, "/api/v1/sync/readback", settings.HMACSecret, "fixed-readback", "user.readback", map[string]string{"subject": "fixed-user"})
	if readback.Code != 200 {
		t.Fatalf("fixed directory: %d %s", readback.Code, readback.Body.String())
	}
	refused := sendDirectory(t, first.router, "/api/v1/sync/readback", strings.Repeat("q", 32), "fixed-wrong-key", "user.readback", map[string]string{"subject": "fixed-user"})
	if refused.Code == 200 {
		t.Fatal("wrong directory signature accepted")
	}
	logout := first.sign("logout+jwt", first.logoutClaims("fixed-logout", "fixed-user", "sid"))
	if res := first.logout(logout); res.Code != 200 {
		t.Fatalf("fixed logout: %d %s", res.Code, res.Body.String())
	}
	if res := first.logout(logout); res.Code != 400 {
		t.Fatalf("logout replay: %d", res.Code)
	}
	if res := first.send(req); res.Code != 403 || errorCode(t, res.Body.String()) != "sso_login_rejected" {
		t.Fatalf("logout failed to fence an in-flight login: %d %s", res.Code, res.Body.String())
	}
	if err := first.db.QueryRow(`SELECT count(*) FROM sessions WHERE revoked_at='' AND sso_subject='fixed-user'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("logout left a live session", n, err)
	}
	if err := first.settings.Save(changed); err != sso.ErrFixedSettings {
		t.Fatal("fixed settings save succeeded", err)
	}
}

func TestFixedSSOStoreRetainsSingleModeConfigurationFences(t *testing.T) {
	f := newLogoutFixture(t)
	settings := f.settings.Load()
	settings.HMACSecret = strings.Repeat("h", 32)
	fixed := sso.NewFixedStore(settings)
	router := http.NewServeMux()
	SSORoutes(router, f.db, f.cfg, fixed)
	f.router = router
	req := f.beginLogin("single-fixed", "sid", time.Now())
	if _, err := f.db.Exec(`UPDATE server_settings SET value='false' WHERE key='sso_enabled'`); err != nil {
		t.Fatal(err)
	}
	if res := f.send(req); res.Code != 403 || errorCode(t, res.Body.String()) != "sso_login_rejected" {
		t.Fatalf("fixed flag bypassed single-mode configuration: %d %s", res.Code, res.Body.String())
	}
	if res := sendDirectory(t, router, "/api/v1/sync/readback", settings.HMACSecret, "single-fixed-read", "user.readback", map[string]string{"subject": "single-fixed"}); res.Code != 422 {
		t.Fatalf("fixed flag bypassed single directory fence: %d %s", res.Code, res.Body.String())
	}
}
