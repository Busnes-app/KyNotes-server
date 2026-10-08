package httpapi

import (
	"net/http"
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
	if _, err := tm.owner.db.Exec(`UPDATE users SET role='admin' WHERE id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	add := func() int {
		code, _ := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/admin/teams/"+tm.id+"/members", []byte(`{"userId":`+quote(tm.viewer.id)+`,"role":"commenter"}`), true, false))
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
