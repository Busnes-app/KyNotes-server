package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAdminCreatesATeamForAnEverydayOwner(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	admin.stepUp(t) // Task 4 puts team creation behind the admin step-up
	other := p.addAdmin(t, "other-admin")
	create := func(body string) (int, string) {
		return status(t, admin.do(t, http.MethodPost, "/api/v1/admin/teams", []byte(body), true, false))
	}
	for _, body := range []string{`{}`, `{"ownerUserId":"nope"}`, `{"metaCiphertext":"eA=="}`} {
		if code, out := create(body); code != http.StatusBadRequest {
			t.Fatalf("%s=%d %s", body, code, out)
		}
	}
	disabled := p.addUser(t, "gone")
	if _, err := p.db.Exec(`UPDATE users SET status='disabled' WHERE id=?`, disabled.id); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{other.id, disabled.id, mint(t, "usr")} {
		if code, out := create(`{"ownerUserId":` + quote(id) + `}`); code != http.StatusNotFound {
			t.Fatalf("owner %s=%d %s", id, code, out)
		}
	}
	// pairUser's fixture ID is not a minted ID, so the owner is a fresh everyday account.
	owner := p.addUser(t, "owner").id
	code, out := create(`{"ownerUserId":` + quote(owner) + `}`)
	var team struct {
		ID    string `json:"id"`
		Owner string `json:"ownerUserId"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(out), &team) != nil || team.Owner != owner {
		t.Fatalf("create=%d %s", code, out)
	}
	var stored string
	var adminRows, audits int
	if err := p.db.QueryRow(`SELECT owner_user_id FROM containers WHERE id=?`, team.ID).Scan(&stored); err != nil || stored != owner {
		t.Fatal("container owner", stored, err)
	}
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM memberships WHERE container_id=? AND user_id=?`, team.ID, admin.id).Scan(&adminRows); err != nil || adminRows != 0 {
		t.Fatal("the administrator holds a membership", adminRows, err)
	}
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='admin.team.create' AND container_id=? AND object_id=? AND actor_user_id=?`, team.ID, owner, admin.id).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("audit", audits, err)
	}
}

func TestAdminUserRoutesKeepKindsApart(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	admin.stepUp(t)
	create := func(name, kind string) (int, string) {
		body := `{"username":` + quote(name) + `,"authSecret":"` + strings.Repeat("c", 64) + `","loginSalt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":100000,"accountKind":` + quote(kind) + `}`
		return status(t, admin.do(t, http.MethodPost, "/api/v1/admin/users", []byte(body), true, false))
	}
	if code, out := create("x", "root"); code != http.StatusBadRequest {
		t.Fatalf("unknown kind=%d %s", code, out)
	}
	for name, kind := range map[string]string{"alice": "user", "ops": "admin"} {
		if code, out := create(name, kind); code != http.StatusOK {
			t.Fatalf("create %s=%d %s", name, code, out)
		}
		var got, role string
		var flagged int
		if err := p.db.QueryRow(`SELECT account_kind,role,password_admin_known FROM users WHERE username=?`, name).Scan(&got, &role, &flagged); err != nil || got != kind || role != kind || flagged != 1 {
			t.Fatalf("%s: %s %s %d %v", name, got, role, flagged, err)
		}
	}
	var alice string
	if err := p.db.QueryRow(`SELECT id FROM users WHERE username='alice'`).Scan(&alice); err != nil {
		t.Fatal(err)
	}
	patch := func(id, role string) (int, string) {
		return status(t, admin.do(t, http.MethodPatch, "/api/v1/admin/users/"+id, []byte(`{"role":`+quote(role)+`,"status":"active","quotaBytes":0}`), true, false))
	}
	if code, out := patch(alice, "admin"); code != http.StatusConflict || errorCode(t, out) != "account_kind_mismatch" {
		t.Fatalf("promote everyday=%d %s", code, out)
	}
	if code, out := patch(mint(t, "usr"), "user"); code != http.StatusNotFound {
		t.Fatalf("unknown account=%d %s", code, out)
	}
	code, out := status(t, admin.do(t, http.MethodGet, "/api/v1/admin/users", nil, false, false))
	if code != http.StatusOK || !strings.Contains(out, `"accountKind":"admin"`) || !strings.Contains(out, `"accountKind":"user"`) {
		t.Fatalf("list=%d %s", code, out)
	}
}

func TestAdminTeamAccessNeedsStepUpAndListsNoNames(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	other := p.addAdmin(t, "other-admin")
	editor := p.addUser(t, "editor")
	owner := p.addUser(t, "owner") // pairUser's fixture ID is not a minted ID
	body := []byte(`{"ownerUserId":` + quote(owner.id) + `}`)
	if code, out := status(t, admin.do(t, http.MethodPost, "/api/v1/admin/teams", body, true, false)); code != http.StatusForbidden || errorCode(t, out) != "step_up_required" {
		t.Fatalf("create without step-up=%d %s", code, out)
	}
	admin.stepUp(t)
	code, out := status(t, admin.do(t, http.MethodPost, "/api/v1/admin/teams", body, true, false))
	var team struct{ ID string }
	if code != http.StatusOK || json.Unmarshal([]byte(out), &team) != nil {
		t.Fatalf("create=%d %s", code, out)
	}
	add := func(c *pairClient, user string) (int, string) {
		return status(t, c.do(t, http.MethodPost, "/api/v1/admin/teams/"+team.ID+"/members", []byte(`{"userId":`+quote(user)+`,"role":"editor"}`), true, false))
	}
	if code, out := add(other.pairClient, editor.id); code != http.StatusForbidden || errorCode(t, out) != "step_up_required" {
		t.Fatalf("add without step-up=%d %s", code, out)
	}
	if code, out := add(admin.pairClient, other.id); code != http.StatusNotFound {
		t.Fatalf("add an admin account=%d %s", code, out)
	}
	// steward role: an unapproved team admin could approve itself, rotate in a key it knows, or wrap.
	for _, role := range []string{"admin", "owner"} {
		if code, out := status(t, admin.do(t, http.MethodPost, "/api/v1/admin/teams/"+team.ID+"/members", []byte(`{"userId":`+quote(editor.id)+`,"role":`+quote(role)+`}`), true, false)); code != http.StatusBadRequest {
			t.Fatalf("add as %s=%d %s", role, code, out)
		}
	}
	if code, out := add(admin.pairClient, editor.id); code != http.StatusNoContent {
		t.Fatalf("add=%d %s", code, out)
	}
	code, out = status(t, admin.do(t, http.MethodGet, "/api/v1/admin/teams", nil, false, false))
	var list []map[string]any
	if code != http.StatusOK || json.Unmarshal([]byte(out), &list) != nil || len(list) != 1 {
		t.Fatalf("list=%d %s", code, out)
	}
	row := list[0]
	if _, leaked := row["metaCiphertext"]; leaked || row["ownerUsername"] != "owner" || row["memberCount"] != float64(2) || row["keyed"] != false || row["named"] != false {
		t.Fatalf("row %v", row)
	}
}
