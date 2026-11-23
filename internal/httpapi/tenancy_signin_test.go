package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/orgsync"
)

// signInWith completes an OIDC sign-in whose ID token also carries extra claims.
func (f *logoutFixture) signInWith(subject string, extra map[string]any) *httptest.ResponseRecorder {
	f.t.Helper()
	req := f.beginLogin(subject, "sid-"+subject, time.Now())
	state := req.URL.Query().Get("state")
	f.mu.Lock()
	for k, v := range extra {
		f.proofs[state][k] = v
	}
	f.mu.Unlock()
	return f.send(req)
}

// Multi mode signs in only a subject of a serving org in this region, creates its account in that
// org, keeps a known subject in its own org, and never recreates an erased one (spec, Identity
// binding, Sign-in). Each refusal is audited and writes no account.
func TestMultiModeSignInNeedsAServingOrgInThisRegion(t *testing.T) {
	f := newLogoutFixture(t)
	toMultiMode(t, f.db, "org_staff")
	for _, q := range []string{
		`UPDATE server_settings SET value='eu' WHERE key='region'`,
		`INSERT INTO orgs(id,status,home_region) VALUES('org_a','active','eu'),('org_d','active','eu'),('org_paused','suspended','eu'),('org_far','active','us')`,
		`INSERT INTO orgs(id,status,enabled,home_region) VALUES('org_off','active',0,'eu')`,
		`INSERT INTO erased_subjects(subject,org_id,revision) VALUES('gone','org_a',1)`,
	} {
		if _, err := f.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	refused := func(subject string, extra map[string]any, code, reason string) {
		t.Helper()
		res := f.signInWith(subject, extra)
		if res.Code != 403 || errorCode(t, res.Body.String()) != code {
			t.Fatalf("%s %v: %d %s, want 403 %s", subject, extra, res.Code, res.Body.String(), code)
		}
		var audited int
		if err := f.db.QueryRow(`SELECT count(*) FROM audit_events WHERE event='auth.sso_refused' AND object_id=? AND reason_code=?`, subject, "reason="+reason).Scan(&audited); err != nil || audited == 0 {
			t.Fatalf("%s: refusal not audited (%d %v)", subject, audited, err)
		}
	}
	accounts := func(subject string) (n int, org string) {
		t.Helper()
		_ = f.db.QueryRow(`SELECT count(*),COALESCE(MAX(org_id),'') FROM users WHERE sso_subject=?`, subject).Scan(&n, &org)
		return
	}
	refused("no-org", nil, "org_required", "no_org")
	refused("paused", map[string]any{"org_id": "org_paused"}, "org_not_active", "org_not_active")
	refused("far", map[string]any{"org_id": "org_far"}, "org_not_active", "org_not_active")
	refused("off", map[string]any{"org_id": "org_off"}, "org_not_active", "org_not_active")
	refused("unknown", map[string]any{"org_id": "org_nowhere"}, "org_not_active", "org_not_active")
	refused("gone", map[string]any{"org_id": "org_a"}, "account_erased", "erased")
	for _, s := range []string{"no-org", "paused", "far", "off", "unknown", "gone"} {
		if n, _ := accounts(s); n != 0 {
			t.Fatalf("%s: a refused sign-in created an account", s)
		}
	}
	if res := f.signInWith("alice", map[string]any{"org_id": "org_a"}); res.Code != 302 {
		t.Fatalf("serving org: %d %s", res.Code, res.Body.String())
	}
	if n, org := accounts("alice"); n != 1 || org != "org_a" {
		t.Fatalf("alice: %d accounts in %q", n, org)
	}
	refused("alice", map[string]any{"org_id": "org_d"}, "org_mismatch", "org_mismatch")
	if _, org := accounts("alice"); org != "org_a" {
		t.Fatalf("a mismatched token moved alice to %q", org)
	}
	// N6: kynotes.admin from a customer org grants nothing; the account is an everyday one.
	if res := f.signInWith("bob", map[string]any{"org_id": "org_a", "roles": []string{"kynotes.admin"}}); res.Code != 302 {
		t.Fatalf("customer with the admin role: %d %s", res.Code, res.Body.String())
	}
	var kind string
	if err := f.db.QueryRow(`SELECT account_kind FROM users WHERE sso_subject='bob'`).Scan(&kind); err != nil || kind != "user" {
		t.Fatalf("bob is %q (%v)", kind, err)
	}
}

// Multi mode's directory webhook (spec, Directory webhook): a body without the account's org
// applies removals only, an unknown subject is never created, and user.erased for the account's
// own org ends access and records the subject so it can never sign in again.
func TestMultiModeDirectoryKeepsAccountsInTheirOrg(t *testing.T) {
	f := newLogoutFixture(t)
	settings := f.settings.Load()
	settings.HMACSecret = strings.Repeat("s", 32)
	if err := f.settings.Save(settings); err != nil {
		t.Fatal(err)
	}
	// Single mode refuses user.erased, as before.
	if res := sendDirectory(t, f.router, "/api/v1/sync/events", settings.HMACSecret, "evt-single", "user.erased", directoryPayload("alice", "alice", 1, false)); res.Code != 400 {
		t.Fatalf("single mode user.erased=%d %s", res.Code, res.Body.String())
	}
	toMultiMode(t, f.db, "org_staff")
	for _, q := range []string{`UPDATE server_settings SET value='eu' WHERE key='region'`, `INSERT INTO orgs(id,status,home_region) VALUES('org_a','active','eu'),('org_b','active','eu')`} {
		if _, err := f.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []string{"alice", "bob"} {
		if res := f.signInWith(s, map[string]any{"org_id": "org_a"}); res.Code != 302 {
			t.Fatalf("%s sign-in: %d %s", s, res.Code, res.Body.String())
		}
	}
	event := func(id, kind, subject string, version int64, active bool, org string) string {
		t.Helper()
		p := directoryPayload(subject, subject, version, active)
		if org != "" {
			p["org_id"] = org
		}
		res := sendDirectory(t, f.router, "/api/v1/sync/events", settings.HMACSecret, id, kind, p)
		var out struct{ Status string }
		if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &out) != nil {
			t.Fatalf("%s: %d %s", id, res.Code, res.Body.String())
		}
		return out.Status
	}
	state := func(subject string) (status string, live int) {
		t.Helper()
		_ = f.db.QueryRow(`SELECT u.status,(SELECT count(*) FROM sessions s WHERE s.user_id=u.id AND s.revoked_at='') FROM users u WHERE u.sso_subject=?`, subject).Scan(&status, &live)
		return
	}
	audited := func(reason string) int {
		var n int
		_ = f.db.QueryRow(`SELECT count(*) FROM audit_events WHERE event='sso.webhook_org_mismatch' AND reason_code LIKE ?`, reason+"%").Scan(&n)
		return n
	}
	if got := event("evt-1", "user.updated", "alice", 2, true, "org_b"); got != "ignored" || audited("event=evt-1") != 1 {
		t.Fatalf("another org's update: %s, audited %d", got, audited("event=evt-1"))
	}
	if st, live := state("alice"); st != "active" || live == 0 {
		t.Fatalf("an ignored update changed alice: %s, %d live sessions", st, live)
	}
	if got := event("evt-2", "user.created", "carol", 1, true, "org_a"); got != "ignored" {
		t.Fatalf("unknown subject: %s", got)
	}
	var carol int
	if _ = f.db.QueryRow(`SELECT count(*) FROM users WHERE sso_subject='carol'`).Scan(&carol); carol != 0 {
		t.Fatal("the directory created an account in multi mode")
	}
	if got := event("evt-3", "user.updated", "alice", 3, false, ""); got != "applied" || audited("removal_applied") != 1 {
		t.Fatalf("org-less removal: %s, audited %d", got, audited("removal_applied"))
	}
	if st, live := state("alice"); st != "disabled" || live != 0 {
		t.Fatalf("removal kept alice %s with %d live sessions", st, live)
	}
	if got := event("evt-4", "user.erased", "bob", 2, false, "org_a"); got != "applied" {
		t.Fatalf("user.erased: %s", got)
	}
	if st, live := state("bob"); st != "erased" || live != 0 {
		t.Fatalf("erasure left bob %s with %d live sessions", st, live)
	}
	var erased string
	if err := f.db.QueryRow(`SELECT org_id FROM erased_subjects WHERE subject='bob'`).Scan(&erased); err != nil || erased != "org_a" {
		t.Fatalf("bob not recorded as erased: %q %v", erased, err)
	}
	if res := f.signInWith("bob", map[string]any{"org_id": "org_a"}); res.Code != 403 || errorCode(t, res.Body.String()) != "account_erased" {
		t.Fatalf("erased sign-in: %d %s", res.Code, res.Body.String())
	}
}

// A logout token whose org is not the account's still ends its sessions, and is audited.
func TestMultiModeLogoutWithAnotherOrgStillEndsSessions(t *testing.T) {
	f := newLogoutFixture(t)
	toMultiMode(t, f.db, "org_staff")
	for _, q := range []string{`UPDATE server_settings SET value='eu' WHERE key='region'`, `INSERT INTO orgs(id,status,home_region) VALUES('org_a','active','eu')`} {
		if _, err := f.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	sessions := map[string][]*http.Cookie{}
	for _, s := range []string{"alice", "bob"} {
		res := f.signInWith(s, map[string]any{"org_id": "org_a"})
		if res.Code != 302 {
			t.Fatalf("%s: %d %s", s, res.Code, res.Body.String())
		}
		sessions[s] = res.Result().Cookies()
	}
	mismatches := func() int {
		var n int
		_ = f.db.QueryRow(`SELECT count(*) FROM audit_events WHERE event='auth.sso_org_mismatch'`).Scan(&n)
		return n
	}
	for _, c := range []struct {
		subject, jti, org string
		audited           int
	}{{"alice", "end-alice", "org_other", 1}, {"bob", "end-bob", "org_a", 1}} {
		claims := f.logoutClaims(c.jti, c.subject, "sid-"+c.subject)
		claims["org_id"] = c.org
		if res := f.logout(f.sign("logout+jwt", claims)); res.Code != 200 {
			t.Fatalf("%s logout: %d %s", c.subject, res.Code, res.Body.String())
		}
		if f.protected(sessions[c.subject]) != 401 {
			t.Fatalf("%s's session survived its logout", c.subject)
		}
		if got := mismatches(); got != c.audited {
			t.Fatalf("after %s: %d mismatch audits, want %d", c.subject, got, c.audited)
		}
	}
}

// A sign-in for an org not yet mirrored waits for one org poll; a forged org ID polls at most
// once every ten seconds and is refused (spec, Identity binding, Sign-in, step 2).
func TestMultiModeSignInWaitsForOnePollOfAnUnmirroredOrg(t *testing.T) {
	f := newLogoutFixture(t)
	toMultiMode(t, f.db, "org_staff")
	if _, err := f.db.Exec(`UPDATE server_settings SET value='eu' WHERE key='region'`); err != nil {
		t.Fatal(err)
	}
	polls := 0
	f.orgPoll = orgsync.New(f.db, func(context.Context, int64) ([]suitedir.Org, int64, error) {
		polls++
		return []suitedir.Org{{ID: "org_new", Status: "active", Revision: 1, HomeRegion: "eu", Enabled: true}}, 1, nil
	})
	f.restartRouter()
	if res := f.signInWith("newcomer", map[string]any{"org_id": "org_new"}); res.Code != 302 || polls != 1 {
		t.Fatalf("unmirrored listed org: %d %s after %d polls", res.Code, res.Body.String(), polls)
	}
	for range 2 {
		if res := f.signInWith("forger", map[string]any{"org_id": "org_forged"}); res.Code != 403 || errorCode(t, res.Body.String()) != "org_not_active" {
			t.Fatalf("forged org: %d %s", res.Code, res.Body.String())
		}
	}
	if polls != 2 {
		t.Fatalf("a forged org triggered %d polls in ten seconds, want 1", polls-1)
	}
}

// During deletion_scheduled only an export_only token signs in, and its session is marked.
func TestMultiModeExportOnlySignInDuringDeletion(t *testing.T) {
	f := newLogoutFixture(t)
	toMultiMode(t, f.db, "org_staff")
	for _, q := range []string{`UPDATE server_settings SET value='eu' WHERE key='region'`, `INSERT INTO orgs(id,status,home_region) VALUES('org_closing','deletion_scheduled','eu')`} {
		if _, err := f.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if res := f.signInWith("plain", map[string]any{"org_id": "org_closing"}); res.Code != 403 || errorCode(t, res.Body.String()) != "org_not_active" {
		t.Fatalf("an ordinary token during deletion: %d %s", res.Code, res.Body.String())
	}
	if res := f.signInWith("exporter", map[string]any{"org_id": "org_closing", "export_only": true}); res.Code != 302 {
		t.Fatalf("export_only during deletion: %d %s", res.Code, res.Body.String())
	}
	var marked int
	if err := f.db.QueryRow(`SELECT count(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.sso_subject='exporter' AND s.export_only=1`).Scan(&marked); err != nil || marked != 1 {
		t.Fatalf("export_only session not marked: %d %v", marked, err)
	}
	// A string "true" is not the claim.
	if res := f.signInWith("stringly", map[string]any{"org_id": "org_closing", "export_only": "true"}); res.Code != 403 {
		t.Fatalf("export_only as a string: %d", res.Code)
	}
}
