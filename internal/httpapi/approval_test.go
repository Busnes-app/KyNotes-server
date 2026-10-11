package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
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
	// A pending member reads as a viewer: without any key it still cannot delete what is there.
	oid, code := tm.owner.save(t, tm.id, "", 2)
	if code/100 != 2 {
		t.Fatalf("owner save=%d", code)
	}
	att := mint(t, "att")
	if _, err := tm.owner.db.Exec(`INSERT INTO attachments(id,container_id,blob_digest,ciphertext_bytes,metadata_ciphertext,key_generation,change_seq,created_at) SELECT ?,?,blob_digest,1,x'00',2,1,'now' FROM object_versions WHERE object_id=? LIMIT 1`, att, tm.id, oid); err != nil {
		t.Fatal(err)
	}
	if _, err := tm.owner.db.Exec(`INSERT INTO attachment_refs(attachment_id,object_id,object_version,created_at) SELECT ?,object_id,version,'now' FROM object_versions WHERE object_id=? LIMIT 1`, att, oid); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/objects/" + oid, "/api/v1/objects/" + oid + "/attachments/" + att} {
		if code, out := status(t, puppet.do(t, http.MethodDelete, path, nil, true, false)); code != http.StatusForbidden {
			t.Fatalf("pending editor DELETE %s=%d %s", path, code, out)
		}
	}
	var deleted string
	var versions, refs int
	if err := tm.owner.db.QueryRow(`SELECT (SELECT deleted_at FROM objects WHERE id=?1),(SELECT COUNT(*) FROM object_versions WHERE object_id=?1),(SELECT COUNT(*) FROM attachment_refs WHERE object_id=?1)`, oid).Scan(&deleted, &versions, &refs); err != nil || deleted != "" || versions == 0 || refs != 1 {
		t.Fatalf("pending editor changed content: deleted=%q versions=%d refs=%d %v", deleted, versions, refs, err)
	}
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
	// An unapproved steward cannot exist: a pending member holds the viewer role (0027 triggers).
	if _, err := tm.owner.db.Exec(`UPDATE memberships SET approved=0 WHERE container_id=? AND user_id=?`, tm.id, tm.admin.id); err == nil || !strings.Contains(err.Error(), "pending_member_is_viewer") {
		t.Fatalf("unapproved steward stored: %v", err)
	}
	guest := tm.owner.addUser(t, "pending-guest")
	if _, err := tm.owner.db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at,approved,pending_role) VALUES(?,?,?,'editor','now',0,'editor')`, mint(t, "mem"), tm.id, guest.id); err == nil || !strings.Contains(err.Error(), "pending_member_is_viewer") {
		t.Fatalf("pending editor inserted: %v", err)
	}
	if code, out := approve(tm.owner, tm.id); code != http.StatusNoContent {
		t.Fatalf("owner approves=%d %s", code, out)
	}
	for _, cid := range []string{tm.id, tm.child} {
		if approved, _ := approvedOf(t, tm.owner, cid, puppet.id); !approved {
			t.Fatalf("%s still unapproved", cid)
		}
		var role, pending string
		if err := tm.owner.db.QueryRow(`SELECT role,pending_role FROM memberships WHERE container_id=? AND user_id=?`, cid, puppet.id).Scan(&role, &pending); err != nil || role != "editor" || pending != "" {
			t.Fatalf("%s approved as %q pending %q %v", cid, role, pending, err)
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

func TestOnlyWritersAttachDetachAndResolve(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.owner.save(t, tm.id, "", 2)
	if code/100 != 2 {
		t.Fatalf("owner save=%d", code)
	}
	att := mint(t, "att")
	if _, err := tm.owner.db.Exec(`INSERT INTO attachments(id,container_id,blob_digest,ciphertext_bytes,metadata_ciphertext,key_generation,change_seq,created_at) SELECT ?,?,blob_digest,1,x'00',2,1,'now' FROM object_versions WHERE object_id=? LIMIT 1`, att, tm.id, oid); err != nil {
		t.Fatal(err)
	}
	attach := func(c *pairClient) int {
		code, _ := status(t, c.do(t, http.MethodPost, "/api/v1/objects/"+oid+"/attachments", []byte(`{"attachmentId":`+quote(att)+`,"objectVersion":1}`), true, false))
		return code
	}
	detach := func(c *pairClient) int {
		code, _ := status(t, c.do(t, http.MethodDelete, "/api/v1/objects/"+oid+"/attachments/"+att, nil, true, false))
		return code
	}
	if code := attach(tm.viewer.pairClient); code != http.StatusForbidden {
		t.Fatalf("viewer attach=%d", code)
	}
	if code := attach(tm.editor.pairClient); code != http.StatusNoContent {
		t.Fatalf("editor attach=%d", code)
	}
	if code := detach(tm.viewer.pairClient); code != http.StatusForbidden {
		t.Fatalf("viewer detach=%d", code)
	}
	var refs int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM attachment_refs WHERE object_id=?`, oid).Scan(&refs); err != nil || refs != 1 {
		t.Fatalf("refs after viewer detach=%d %v", refs, err)
	}
	if code := detach(tm.editor.pairClient); code != http.StatusNoContent {
		t.Fatalf("editor detach=%d", code)
	}
	// Resolving a preserved conflict copy hides it: a writer's action too.
	cfl := mint(t, "cfl")
	if _, err := tm.owner.db.Exec(`INSERT INTO conflicts(id,object_id,container_id,base_version,current_version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at) SELECT ?,object_id,?,1,1,blob_digest,1,2,1,'now' FROM object_versions WHERE object_id=? LIMIT 1`, cfl, tm.id, oid); err != nil {
		t.Fatal(err)
	}
	resolve := func(c *pairClient) int {
		code, _ := status(t, c.do(t, http.MethodPost, "/api/v1/conflicts/"+cfl+"/resolve", nil, true, false))
		return code
	}
	if code := resolve(tm.viewer.pairClient); code != http.StatusForbidden {
		t.Fatalf("viewer resolve=%d", code)
	}
	if code := resolve(tm.editor.pairClient); code != http.StatusNoContent {
		t.Fatalf("editor resolve=%d", code)
	}
}
