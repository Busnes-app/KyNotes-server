package httpapi

import (
	"net/http"
	"slices"
	"testing"
	"time"
)

// livesOf returns userID's live and total membership rows, and its live role in cid.
func livesOf(t *testing.T, tm team, userID, cid string) (live, rows int, role string) {
	t.Helper()
	if err := tm.owner.db.QueryRow(`SELECT (SELECT COUNT(*) FROM memberships WHERE user_id=?1 AND revoked_at=''),(SELECT COUNT(*) FROM memberships WHERE user_id=?1),COALESCE((SELECT role FROM memberships WHERE user_id=?1 AND container_id=?2 AND revoked_at=''),'')`, userID, cid).Scan(&live, &rows, &role); err != nil {
		t.Fatal(err)
	}
	return
}

func TestAcceptChecksExpiryAndInviteeInsideItsTransaction(t *testing.T) {
	tm := newTeam(t)
	guest, other := tm.owner.addUser(t, "guest"), tm.owner.addUser(t, "other")
	inv, code := invite(t, tm.owner, tm.id, guest.id)
	if code != http.StatusOK {
		t.Fatalf("invite=%d", code)
	}
	if code := accept(t, other.pairClient, inv); code != http.StatusNotFound {
		t.Fatalf("another account accepted the invitation: %d", code)
	}
	if _, err := tm.owner.db.Exec(`UPDATE invitations SET expires_at=? WHERE id=?`, time.Now().UTC().Add(-time.Second).Format(time.RFC3339), inv[0]); err != nil {
		t.Fatal(err)
	}
	if code := accept(t, guest.pairClient, inv); code != http.StatusNotFound {
		t.Fatalf("accepted an expired invitation: %d", code)
	}
	var state string
	if err := tm.owner.db.QueryRow(`SELECT status FROM invitations WHERE id=?`, inv[0]).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("invitation status=%q %v", state, err)
	}
	for _, u := range []member{guest, other} {
		if live, rows, _ := livesOf(t, tm, u.id, tm.id); live != 0 || rows != 0 {
			t.Fatalf("%s: live=%d rows=%d", u.id, live, rows)
		}
	}
}

func TestRemovedMemberIsReadmittedByReactivation(t *testing.T) {
	tm := newTeam(t)
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.editor.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove=%d %s", code, out)
	}
	inv, _ := invite(t, tm.owner, tm.id, tm.editor.id) // role admin
	if code := accept(t, tm.editor.pairClient, inv); code != http.StatusNoContent {
		t.Fatalf("re-invited former member=%d", code)
	}
	if live, rows, role := livesOf(t, tm, tm.editor.id, tm.id); live != 2 || rows != 2 || role != "admin" {
		t.Fatalf("live=%d rows=%d role=%q; want team and child live as admin, no new rows", live, rows, role)
	}
	var envelopes int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM key_envelopes WHERE device_id=?`, tm.editorID).Scan(&envelopes); err != nil || envelopes != 0 {
		t.Fatalf("re-admission restored envelopes: %d %v", envelopes, err)
	}
	again, _ := invite(t, tm.owner, tm.id, tm.editor.id)
	if code := accept(t, tm.editor.pairClient, again); code != http.StatusConflict {
		t.Fatalf("live member accepted again: %d", code)
	}
	// The server-admin add route re-admits the same way.
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.viewer.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove viewer=%d %s", code, out)
	}
	admin := tm.owner.addAdmin(t, "server-admin")
	admin.stepUp(t)
	add := func() int {
		code, _ := status(t, admin.do(t, http.MethodPost, "/api/v1/admin/teams/"+tm.id+"/members", []byte(`{"userId":`+quote(tm.viewer.id)+`,"role":"commenter"}`), true, false))
		return code
	}
	if code := add(); code != http.StatusNoContent {
		t.Fatalf("admin re-add=%d", code)
	}
	if live, rows, role := livesOf(t, tm, tm.viewer.id, tm.id); live != 2 || rows != 2 || role != "commenter" {
		t.Fatalf("admin re-add: live=%d rows=%d role=%q", live, rows, role)
	}
	if code := add(); code != http.StatusConflict {
		t.Fatalf("admin add of a live member=%d", code)
	}
}

func TestTeamAdminRemovesOnlyAdminsItInvited(t *testing.T) {
	tm := newTeam(t)
	peer, other := tm.owner.addUser(t, "peer"), tm.owner.addUser(t, "other")
	remove := func(by *pairClient, target string) int {
		code, _ := status(t, by.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+target, nil, true, false))
		return code
	}
	join := func(by *pairClient, u member) {
		t.Helper()
		inv, code := invite(t, by, tm.id, u.id) // role admin
		if code != http.StatusOK {
			t.Fatalf("invite %s=%d", u.id, code)
		}
		if code := accept(t, u.pairClient, inv); code != http.StatusNoContent {
			t.Fatalf("accept %s=%d", u.id, code)
		}
	}
	join(tm.admin.pairClient, peer)
	join(tm.owner, other)
	if code := remove(tm.admin.pairClient, other.id); code != http.StatusForbidden {
		t.Fatalf("admin removed the owner's invitee: %d", code)
	}
	if code := remove(peer.pairClient, tm.admin.id); code != http.StatusForbidden {
		t.Fatalf("invited admin removed an admin it did not invite: %d", code)
	}
	if code := remove(tm.admin.pairClient, peer.id); code != http.StatusNoContent {
		t.Fatalf("admin could not remove the admin it invited: %d", code)
	}
	var audits int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='container.member_remove' AND object_id=? AND actor_user_id=?`, peer.id, tm.admin.id).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audits=%d %v", audits, err)
	}
	// Re-admitted by the owner, the peer is the owner's invitee now.
	join(tm.owner, peer)
	var invitedBy string
	if err := tm.owner.db.QueryRow(`SELECT invited_by FROM memberships WHERE container_id=? AND user_id=?`, tm.id, peer.id).Scan(&invitedBy); err != nil || invitedBy != pairUser {
		t.Fatalf("invited_by=%q %v", invitedBy, err)
	}
	if code := remove(tm.admin.pairClient, peer.id); code != http.StatusForbidden {
		t.Fatalf("admin removed an admin the owner re-invited: %d", code)
	}
}

func TestRemovalVoidsPendingInvitationsToTheRemovedMember(t *testing.T) {
	tm := newTeam(t)
	inv, code := invite(t, tm.admin.pairClient, tm.id, tm.editor.id) // live member, role admin
	if code != http.StatusOK {
		t.Fatalf("invite=%d", code)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.editor.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove=%d %s", code, out)
	}
	if code := accept(t, tm.editor.pairClient, inv); code != http.StatusNotFound {
		t.Fatalf("stale invitation re-admitted a removed member: %d", code)
	}
	if live, _, _ := livesOf(t, tm, tm.editor.id, tm.id); live != 0 {
		t.Fatalf("live=%d", live)
	}
}

func TestAcceptAndAdminAddAreAudited(t *testing.T) {
	tm := newTeam(t)
	audit := func(event, object, reason string) int {
		var n int
		if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event=? AND object_id=? AND reason_code=? AND outcome='success'`, event, object, reason).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	fresh := tm.owner.addUser(t, "fresh")
	inv, _ := invite(t, tm.owner, tm.id, fresh.id)
	if code := accept(t, fresh.pairClient, inv); code != http.StatusNoContent {
		t.Fatalf("accept=%d", code)
	}
	if n := audit("container.member_accept", pairUser, "role=admin,readmit=false"); n != 1 {
		t.Fatalf("first accept audits=%d", n)
	}
	if code, _ := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.editor.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove=%d", code)
	}
	again, _ := invite(t, tm.owner, tm.id, tm.editor.id)
	if code := accept(t, tm.editor.pairClient, again); code != http.StatusNoContent {
		t.Fatalf("re-accept=%d", code)
	}
	if n := audit("container.member_accept", pairUser, "role=admin,readmit=true"); n != 1 {
		t.Fatalf("re-admission audits=%d", n)
	}
}

func TestRefusedAcceptAndAdminAddAreAuditedWithTheResponseCodeOnly(t *testing.T) {
	tm := newTeam(t)
	type row struct{ actor, container, object, outcome, reason string }
	refusals := func(event string) []row {
		t.Helper()
		rows, err := tm.owner.db.Query(`SELECT actor_user_id,container_id,object_id,outcome,reason_code FROM audit_events WHERE event=? AND outcome<>'success' ORDER BY rowid`, event)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.actor, &r.container, &r.object, &r.outcome, &r.reason); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	guest, other := tm.owner.addUser(t, "guest"), tm.owner.addUser(t, "other")
	inv, _ := invite(t, tm.owner, tm.id, guest.id)
	// Another account's accept: the same 404 as an unknown invitation, and an audit that names neither team nor inviter.
	if code := accept(t, other.pairClient, inv); code != http.StatusNotFound {
		t.Fatalf("accept=%d", code)
	}
	live, _ := invite(t, tm.owner, tm.id, tm.editor.id)
	if code := accept(t, tm.editor.pairClient, live); code != http.StatusConflict {
		t.Fatalf("accept by a live member=%d", code)
	}
	want := []row{{other.id, "", inv[0], "denied", "not_found"}, {tm.editor.id, "", live[0], "denied", "already_exists"}}
	if got := refusals("container.member_accept"); !slices.Equal(got, want) {
		t.Fatalf("accept refusals=%+v want %+v", got, want)
	}
	// The refused attempt wrote nothing else: the invitation is still pending and no membership exists.
	var state string
	if err := tm.owner.db.QueryRow(`SELECT status FROM invitations WHERE id=?`, inv[0]).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("status=%q %v", state, err)
	}
	if n, _, _ := livesOf(t, tm, other.id, tm.id); n != 0 {
		t.Fatalf("live=%d", n)
	}
	admin := tm.owner.addAdmin(t, "server-admin")
	admin.stepUp(t)
	post := func(cid, uid string) int {
		code, _ := status(t, admin.do(t, http.MethodPost, "/api/v1/admin/teams/"+cid+"/members", []byte(`{"userId":`+quote(uid)+`,"role":"viewer"}`), true, false))
		return code
	}
	unknown := mint(t, "cnt")
	if post(tm.id, tm.editor.id) != http.StatusConflict || post(unknown, other.id) != http.StatusNotFound {
		t.Fatal("admin add did not refuse")
	}
	want = []row{{admin.id, tm.id, tm.editor.id, "denied", "already_exists"}, {admin.id, unknown, other.id, "denied", "not_found"}}
	if got := refusals("admin.team.member_add"); !slices.Equal(got, want) {
		t.Fatalf("admin add refusals=%+v want %+v", got, want)
	}
	if n, _, _ := livesOf(t, tm, other.id, tm.id); n != 0 {
		t.Fatalf("live=%d", n)
	}
}

func TestAdminAddMapsOnlyConflictsTo409(t *testing.T) {
	tm := newTeam(t)
	admin := tm.owner.addAdmin(t, "server-admin")
	admin.stepUp(t)
	post := func(cid, uid string) int {
		code, _ := status(t, admin.do(t, http.MethodPost, "/api/v1/admin/teams/"+cid+"/members", []byte(`{"userId":`+quote(uid)+`,"role":"viewer"}`), true, false))
		return code
	}
	if code := post(tm.id, tm.editor.id); code != http.StatusConflict {
		t.Fatalf("live member=%d", code)
	}
	if code := post(mint(t, "cnt"), tm.editor.id); code != http.StatusNotFound {
		t.Fatalf("unknown team=%d", code)
	}
	if code := post(tm.id, mint(t, "usr")); code != http.StatusNotFound {
		t.Fatalf("unknown user=%d", code)
	}
	if code := post("bad", tm.editor.id); code != http.StatusBadRequest {
		t.Fatalf("malformed team=%d", code)
	}
	if _, err := tm.owner.db.Exec(`DROP TABLE audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := tm.owner.db.Exec(`UPDATE memberships SET revoked_at='x' WHERE user_id=?`, tm.viewer.id); err != nil {
		t.Fatal(err)
	}
	if code := post(tm.id, tm.viewer.id); code != http.StatusInternalServerError {
		t.Fatalf("database fault=%d, want 500", code)
	}
}
