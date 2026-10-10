package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/sso"
)

func TestSSOKindsFollowTheToken(t *testing.T) {
	f := newLogoutFixture(t)
	admin := []string{sso.AdminAppRole}
	refused := func(name, subject string, roles []string, code string) {
		t.Helper()
		res := roleCallback(f, subject, roles, "")
		if res.Code != 403 || errorCode(t, res.Body.String()) != code {
			t.Fatalf("%s: %d %s", name, res.Code, res.Body.String())
		}
	}
	refused("unprovisioned admin", "boss", admin, "admin_account_not_provisioned")
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username='boss'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("a token with the admin role created an account", n, err)
	}
	if res := roleCallback(f, "alice", nil, ""); res.Code != 302 {
		t.Fatalf("everyday sign-in: %d %s", res.Code, res.Body.String())
	}
	refused("everyday with the role", "alice", admin, "admin_role_on_everyday_account")
	seedSSOAdmin(f, "ops")
	refused("admin without the role", "ops", nil, "admin_role_required")
	if res := roleCallback(f, "ops", admin, ""); res.Code != 302 {
		t.Fatalf("admin sign-in: %d %s", res.Code, res.Body.String())
	}
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='auth.sso_admin_refused' AND outcome='denied'`).Scan(&n); err != nil || n != 3 {
		t.Fatal("refusal audits", n, err)
	}
}

func TestDirectoryNeverGrantsAdminToEverydayAccounts(t *testing.T) {
	f := newLogoutFixture(t)
	settings := f.settings.Load()
	settings.HMACSecret = strings.Repeat("s", 32)
	if err := f.settings.Save(settings); err != nil {
		t.Fatal(err)
	}
	send := func(subject string, version int64, roles []any, event string) {
		t.Helper()
		p := directoryPayload(subject, subject, version, true)
		p["roles"] = roles
		if r := sendDirectory(t, f.router, "/sync/events", settings.HMACSecret, subject+"-"+time.Now().String(), event, p); r.Code != 200 {
			t.Fatalf("%s v%d: %d %s", subject, version, r.Code, r.Body.String())
		}
	}
	kind := func(subject string) (string, string) {
		var k, role string
		if err := f.db.QueryRow(`SELECT account_kind,role FROM users WHERE sso_subject=?`, subject).Scan(&k, &role); err != nil {
			t.Fatal(err)
		}
		return k, role
	}
	send("ops", 1, []any{sso.AdminAppRole}, "user.created")
	if k, role := kind("ops"); k != "admin" || role != "admin" {
		t.Fatalf("created administrator identity: %s %s", k, role)
	}
	send("alice", 1, []any{}, "user.created")
	if res := roleCallback(f, "alice", nil, ""); res.Code != 302 {
		t.Fatalf("everyday sign-in: %d %s", res.Code, res.Body.String())
	}
	send("alice", 2, []any{sso.AdminAppRole}, "user.updated")
	if k, role := kind("alice"); k != "user" || role != "user" {
		t.Fatalf("everyday account took the grant: %s %s", k, role)
	}
	// A refused grant changes nothing, so it revokes nothing.
	var live int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.sso_subject='alice' AND s.revoked_at=''`).Scan(&live); err != nil || live != 1 {
		t.Fatal("refused grant revoked the everyday session", live, err)
	}
	for subject, want := range map[string]string{"ops": "admin", "alice": "user"} {
		r := sendDirectory(t, f.router, "/api/v1/sync/readback", settings.HMACSecret, "read-"+subject, "user.readback", map[string]string{"subject": subject})
		var seen struct{ AccountKind string }
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &seen) != nil || seen.AccountKind != want {
			t.Fatalf("readback %s: %d %s", subject, r.Code, r.Body.String())
		}
	}
	var reason string
	if err := f.db.QueryRow(`SELECT reason_code FROM audit_events WHERE event='directory.apply' AND object_id='alice' ORDER BY at DESC, rowid DESC LIMIT 1`).Scan(&reason); err != nil || !strings.Contains(reason, "role=user") || !strings.HasSuffix(reason, ",role_refused=everyday_account") {
		t.Fatalf("audit %q %v", reason, err)
	}
	// Another active administrator, so revoking ops's grant is not the last-admin retention case.
	if _, err := f.db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,created_at,updated_at) VALUES('usr_spare','spare','h','s',1,'admin','admin','now','now')`); err != nil {
		t.Fatal(err)
	}
	send("ops", 2, []any{}, "user.updated")
	if k, role := kind("ops"); k != "admin" || role != "user" {
		t.Fatalf("revoked grant: %s %s", k, role)
	}
}
