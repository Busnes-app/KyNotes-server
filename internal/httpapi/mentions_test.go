package httpapi

import (
	"net/http"
	"testing"
)

// A comment may mention only current members of its notebook: a stranger or a revoked member
// refuses the whole comment, so no mention notification leaks outside the notebook.
func TestCommentMentionsOnlyMembers(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.editor.save(t, tm.id, "", 2)
	if code != http.StatusOK {
		t.Fatalf("save=%d", code)
	}
	outsider := tm.owner.addUser(t, "outsider")
	comment := func(mention string) (int, string) {
		return status(t, tm.editor.do(t, http.MethodPost, "/api/v1/objects/"+oid+"/comments", []byte(`{"bodyCiphertext":"Y3Q=","keyGeneration":2,"mentions":[`+quote(mention)+`]}`), true, false))
	}
	if code, body := comment(outsider.id); code != http.StatusBadRequest {
		t.Fatalf("mention of a non-member=%d %s", code, body)
	}
	if code, body := comment(tm.viewer.id); code != http.StatusOK {
		t.Fatalf("mention of a member=%d %s", code, body)
	}
	if _, err := tm.owner.db.Exec(`UPDATE memberships SET revoked_at='now' WHERE container_id=? AND user_id=?`, tm.id, tm.viewer.id); err != nil {
		t.Fatal(err)
	}
	if code, body := comment(tm.viewer.id); code != http.StatusBadRequest {
		t.Fatalf("mention of a revoked member=%d %s", code, body)
	}
	var comments, mentions int
	_ = tm.owner.db.QueryRow(`SELECT COUNT(*) FROM comments WHERE object_id=?`, oid).Scan(&comments)
	_ = tm.owner.db.QueryRow(`SELECT COUNT(*) FROM mentions`).Scan(&mentions)
	if comments != 1 || mentions != 1 {
		t.Fatalf("comments=%d mentions=%d, want only the member's", comments, mentions)
	}
}
