package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func approvedOf(t *testing.T, c *pairClient, cid, userID string) (bool, bool) {
	t.Helper()
	code, body := status(t, c.do(t, http.MethodGet, "/api/v1/containers/"+cid+"/members", nil, false, false))
	var rows []struct {
		UserID   string `json:"userId"`
		Approved bool   `json:"approved"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &rows) != nil {
		t.Fatalf("members=%d %s", code, body)
	}
	for _, row := range rows {
		if row.UserID == userID {
			return row.Approved, true
		}
	}
	return false, false
}

func TestAdminAddedMembersWaitForApproval(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1) // generation 2 is the first key
	srv := tm.owner.addAdmin(t, "server-admin")
	srv.stepUp(t)
	puppet := tm.owner.addUser(t, "puppet")
	puppetID := puppet.createIdentity(t)
	add := func() {
		t.Helper()
		if code, out := status(t, srv.do(t, http.MethodPost, "/api/v1/admin/teams/"+tm.id+"/members", []byte(`{"userId":`+quote(puppet.id)+`,"role":"editor"}`), true, false)); code != http.StatusNoContent {
			t.Fatalf("admin add=%d %s", code, out)
		}
	}
	add()
	// A child workspace created after the add copies the team's rows, approval included.
	code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","teamId":`+quote(tm.id)+`}`), true, false))
	var later struct{ ID string }
	if code != http.StatusOK || json.Unmarshal([]byte(out), &later) != nil {
		t.Fatalf("child=%d %s", code, out)
	}
	for _, cid := range []string{tm.id, tm.child, later.ID} {
		if approved, listed := approvedOf(t, tm.owner, cid, puppet.id); !listed || approved {
			t.Fatalf("%s: listed=%v approved=%v", cid, listed, approved)
		}
	}
	// No steward may wrap for the member yet, and rotation does not wait for it.
	tm.owner.stepUp(t)
	if code, out := status(t, tm.owner.do(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", envelopesBody(envJSON(puppetID, 2, 3)), true, false)); code != http.StatusBadRequest {
		t.Fatalf("wrap for an unapproved member=%d %s", code, out)
	}
	tm.rotate(t, tm.id, 2)
	approve := func(c *pairClient, cid string) (int, string) {
		return status(t, c.do(t, http.MethodPost, "/api/v1/containers/"+cid+"/members/"+puppet.id+"/approve", nil, true, false))
	}
	if code, out := approve(tm.editor.pairClient, tm.id); code != http.StatusForbidden {
		t.Fatalf("editor approves=%d %s", code, out)
	}
	if code, out := approve(srv.pairClient, tm.id); code != http.StatusForbidden || errorCode(t, out) != "admin_account" {
		t.Fatalf("server admin approves=%d %s", code, out)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/members/"+puppet.id+"/approve", nil, false, false)); code != http.StatusForbidden {
		t.Fatalf("approve without CSRF=%d %s", code, out)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/members/"+mint(t, "usr")+"/approve", nil, true, false)); code != http.StatusNotFound {
		t.Fatalf("approve a non-member=%d %s", code, out)
	}
	// An unapproved steward approves nothing (no route admits one; the database could).
	if _, err := tm.owner.db.Exec(`UPDATE memberships SET approved=0 WHERE container_id=? AND user_id=?`, tm.id, tm.admin.id); err != nil {
		t.Fatal(err)
	}
	if code, out := approve(tm.admin.pairClient, tm.id); code != http.StatusNotFound {
		t.Fatalf("unapproved steward approves=%d %s", code, out)
	}
	if code, out := approve(tm.owner, tm.id); code != http.StatusNoContent {
		t.Fatalf("owner approves=%d %s", code, out)
	}
	for _, cid := range []string{tm.id, tm.child} {
		if approved, _ := approvedOf(t, tm.owner, cid, puppet.id); !approved {
			t.Fatalf("%s still unapproved", cid)
		}
	}
	var audits int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='container.member_approve' AND container_id=? AND object_id=?`, tm.id, puppet.id).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("approve audit", audits, err)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", envelopesBody(envJSON(puppetID, 3, 3)), true, false)); code/100 != 2 {
		t.Fatalf("wrap after approval=%d %s", code, out)
	}
	// Removal and an administrator's re-add start over: approval is not remembered.
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+puppet.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove=%d %s", code, out)
	}
	add()
	if approved, listed := approvedOf(t, tm.owner, tm.id, puppet.id); !listed || approved {
		t.Fatal("readmitted member kept its approval")
	}
	// unapproved reset: it never held a key, so its reset retires nothing (P5 retireKeysTx).
	before, _ := generationOf(t, tm.owner, tm.id)
	puppet.stepUp(t)
	if code, out := status(t, puppet.do(t, http.MethodPut, "/api/v1/me/identity", resetBody(bytes.Repeat([]byte{7}, 32), expecting(puppetID)+resetRecovery+b64s(recoveryCopy)+`"}`), true, false)); code != http.StatusOK {
		t.Fatalf("unapproved reset=%d %s", code, out)
	}
	if after, _ := generationOf(t, tm.owner, tm.id); after != before {
		t.Fatalf("an unapproved member's reset retired the team key: %d -> %d", before, after)
	}
}

func TestInvitedMembersAreApproved(t *testing.T) {
	tm := newTeam(t)
	for _, m := range []member{tm.admin, tm.editor, tm.viewer} {
		if approved, listed := approvedOf(t, tm.owner, tm.id, m.id); !listed || !approved {
			t.Fatalf("%s approved=%v", m.id, approved)
		}
	}
	guest := tm.owner.addUser(t, "guest")
	inv, code := invite(t, tm.owner, tm.id, guest.id)
	if code != http.StatusOK {
		t.Fatalf("invite=%d", code)
	}
	if code := accept(t, guest.pairClient, inv); code != http.StatusNoContent {
		t.Fatalf("accept=%d", code)
	}
	if approved, _ := approvedOf(t, tm.owner, tm.id, guest.id); !approved {
		t.Fatal("an invited member waits for approval")
	}
}
