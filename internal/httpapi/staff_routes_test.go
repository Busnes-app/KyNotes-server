package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func staffFixture(t *testing.T) (*pairClient, member, orgB) {
	t.Helper()
	p := newPairClient(t, strings.Repeat("p", 32))
	toMultiMode(t, p.db, "org_staff")
	staff := p.addAdminInOrg(t, "staff-reader", "org_staff")
	b := seedOrgB(t, p.db)
	return p, staff, b
}
func TestStaffReadsAreScopedAuditedAndSecretFree(t *testing.T) {
	p, staff, b := staffFixture(t)
	for _, q := range []string{
		`INSERT INTO server_settings(key,value,updated_at) VALUES('kyrecovery_token','fixture-sealed-secret','t'),('replica_config_fingerprint','fixture-fingerprint-secret','t')`,
		`INSERT INTO org_pool(org_id,seq,ceiling_bytes,expires_at,pool_bytes,org_used_bytes) VALUES('org_b',3,100,'2099',1024,33)`,
	} {
		if _, err := p.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.RecordAuditOutcome(p.db, b.owner, "b.only", "", "", "success", "org-b-only", "test"); err != nil {
		t.Fatal(err)
	}
	if err := storage.RecordAuditOutcome(p.db, "", "platform.only", "", "", "success", "platform-only", "test"); err != nil {
		t.Fatal(err)
	}
	code, body := status(t, staff.do(t, http.MethodGet, "/api/v1/admin/users?org=org_b", nil, false, false))
	if code != 200 {
		t.Fatalf("users %d %s", code, body)
	}
	var users []struct {
		ID, Username string
		UsedBytes    int64
	}
	if err := json.Unmarshal([]byte(body), &users); err != nil || len(users) != 2 {
		t.Fatalf("users %s %v", body, err)
	}
	var charged int64
	for _, u := range users {
		if u.ID != b.owner && u.ID != b.member {
			t.Fatalf("cross-org account: %s", u.ID)
		}
		if u.ID == b.owner {
			charged = u.UsedBytes
		}
	}
	// SeedOrgB: version/conflict/comment/attachment/reservation = 2 each, sealed link = 16.
	if charged != 26 {
		t.Fatalf("logical user usage=%d, want26", charged)
	}
	var reads int
	if err := p.db.QueryRow(`SELECT count(*) FROM audit_events WHERE event='staff.read' AND object_id='org_b' AND actor_user_id=? AND org_id IS NULL`, staff.id).Scan(&reads); err != nil || reads != 1 {
		t.Fatalf("staff audit %d %v", reads, err)
	}
	for _, test := range []struct{ path, want, absent string }{
		{"/api/v1/admin/audit", "platform.only", "b.only"},
		{"/api/v1/admin/audit?org=org_b", "b.only", "platform.only"},
		{"/api/v1/admin/orgs", "org_b", "fixture-sealed-secret"},
		{"/api/v1/admin/settings", "defaultTheme", "fixture-sealed-secret"},
	} {
		code, body = status(t, staff.do(t, http.MethodGet, test.path, nil, false, false))
		if code != 200 || !strings.Contains(body, test.want) || strings.Contains(body, test.absent) || strings.Contains(body, "fixture-fingerprint-secret") {
			t.Fatalf("staff response %s: %d %s", test.path, code, body)
		}
	}
	code, body = status(t, staff.do(t, http.MethodGet, "/api/v1/admin/orgs", nil, false, false))
	var orgs []struct {
		ID                                                    string
		NotesUsedBytes, PoolBytes, OrgUsedBytes, CeilingBytes int64
	}
	if code != 200 || json.Unmarshal([]byte(body), &orgs) != nil {
		t.Fatal(body)
	}
	found := false
	for _, o := range orgs {
		if o.ID == "org_b" {
			found = true
			if o.NotesUsedBytes != 26 || o.PoolBytes != 1024 || o.OrgUsedBytes != 33 || o.CeilingBytes != 100 {
				t.Fatalf("pool view %+v", o)
			}
		}
	}
	if !found {
		t.Fatal("org mirror missing")
	}
	if code, _ := status(t, staff.do(t, http.MethodGet, "/api/v1/objects/"+b.object, nil, false, false)); code != 403 {
		t.Fatalf("staff opened content: %d", code)
	}
}
func TestStaffSelectionAndAuditFailureRefuseDisclosure(t *testing.T) {
	p, staff, _ := staffFixture(t)
	for _, test := range []struct {
		path string
		code int
	}{
		{"/api/v1/admin/users", 400}, {"/api/v1/admin/users?org=org_b&org=org_staff", 400},
		{"/api/v1/admin/users?org=missing", 404}, {"/api/v1/admin/audit?org=missing", 404},
		{"/api/v1/admin/users?org=%27%20OR%201=1--", 404},
	} {
		if code, body := status(t, staff.do(t, http.MethodGet, test.path, nil, false, false)); code != test.code {
			t.Fatalf("selection %s: %d %s", test.path, code, body)
		}
	}
	refuseTrigger(t, p.db, "deny_staff_audit", "BEFORE INSERT", "audit_events", "NEW.event='staff.read'", "test audit unavailable")
	for _, path := range []string{"/api/v1/admin/users?org=org_b", "/api/v1/admin/audit?org=org_b", "/api/v1/admin/orgs"} {
		code, body := status(t, staff.do(t, http.MethodGet, path, nil, false, false))
		if code != 500 || strings.Contains(body, "b-owner") || strings.Contains(body, "poolBytes") {
			t.Fatalf("unaudited disclosure: %d %s", code, body)
		}
	}
	var n int
	if err := p.db.QueryRow(`SELECT count(*) FROM audit_events WHERE event='staff.read'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed audit retained %d %v", n, err)
	}
}
func TestStaffCustomerWritesAndTeamsAreAbsent(t *testing.T) {
	p, staff, b := staffFixture(t)
	for _, test := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/admin/teams"}, {http.MethodPost, "/api/v1/admin/teams"},
		{http.MethodPost, "/api/v1/admin/teams/" + b.container + "/members"},
		{http.MethodDelete, "/api/v1/admin/teams/" + b.container + "/members/" + b.member},
		{http.MethodPost, "/api/v1/admin/users"}, {http.MethodPatch, "/api/v1/admin/users/" + b.owner},
		{http.MethodPost, "/api/v1/admin/users/" + b.owner + "/password"},
	} {
		if code, body := status(t, staff.do(t, test.method, test.path, []byte(`{}`), true, false)); code != 404 {
			t.Fatalf("multi write %s %s: %d %s", test.method, test.path, code, body)
		}
	}
	if code, _ := status(t, p.do(t, http.MethodGet, "/api/v1/admin/orgs", nil, false, false)); code != 403 {
		t.Fatalf("everyday org list: %d", code)
	}
	var n int
	if err := p.db.QueryRow(`SELECT count(*) FROM users WHERE id=? AND status='active'`, b.owner).Scan(&n); err != nil || n != 1 {
		t.Fatal("refused mutation changed customer")
	}
}
func TestStaffReadRechecksRevokedActor(t *testing.T) {
	p, staff, _ := staffFixture(t)
	srv := httptest.NewServer(auth.RequireAdmin(p.db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := p.db.Exec(`UPDATE users SET status='disabled' WHERE id=?`, staff.id); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		staffRead(w, r, p.db, "org_b", "users", func(tx *sql.Tx) (any, error) { t.Error("revoked actor read metadata"); return nil, nil })
	})))
	defer srv.Close()
	res, err := staff.hc.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("revoked actor: %d", res.StatusCode)
	}
}
func TestStaffRoutesLeaveSingleModeUnchanged(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "single-admin")
	if code, _ := status(t, admin.do(t, http.MethodGet, "/api/v1/admin/orgs", nil, false, false)); code != 404 {
		t.Fatalf("single org directory: %d", code)
	}
	if code, body := status(t, admin.do(t, http.MethodGet, "/api/v1/admin/users", nil, false, false)); code != 200 || strings.Contains(body, "usedBytes") {
		t.Fatalf("single users changed: %d %s", code, body)
	}
}

func TestStaffDeploymentMarkerIsMultiOnly(t *testing.T) {
	p, staff, _ := staffFixture(t)
	code, body := status(t, staff.do(t, http.MethodGet, "/api/v1/auth/session", nil, false, false))
	if code != 200 || !strings.Contains(body, `"tenancy":"multi"`) {
		t.Fatalf("multi session marker: %d %s", code, body)
	}
	if _, err := p.db.Exec(`UPDATE server_settings SET value='single' WHERE key='tenancy_mode'`); err != nil {
		t.Fatal(err)
	}
	code, body = status(t, staff.do(t, http.MethodGet, "/api/v1/auth/session", nil, false, false))
	if code != 200 || strings.Contains(body, `"tenancy"`) {
		t.Fatalf("single session marker changed: %d %s", code, body)
	}
}
