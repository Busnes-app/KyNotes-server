package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/config"
)

// Deleting a page drops its open conflicts with its versions, so nothing the user cannot reach
// stays charged (hostile-review pass 4).
func TestConflictsLeaveTheQuotaWithTheirPage(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.editor.save(t, tm.id, "", 2)
	if code != http.StatusOK {
		t.Fatalf("save=%d", code)
	}
	scope := `SELECT id FROM containers WHERE owner_user_id=?1`
	before, err := usedBytes(tm.owner.db, scope, pairUser, "")
	if err != nil {
		t.Fatal(err)
	}
	conflict := func(id string) {
		if _, err := tm.owner.db.Exec(`INSERT INTO conflicts(id,object_id,container_id,base_version,current_version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at) SELECT ?,object_id,?,1,1,blob_digest,1000,2,1,'now' FROM object_versions WHERE object_id=? LIMIT 1`, id, tm.id, oid); err != nil {
			t.Fatal(err)
		}
	}
	conflict("cfl_open00000000000000000000000")
	charged := func() int64 {
		used, err := usedBytes(tm.owner.db, scope, pairUser, "")
		if err != nil {
			t.Fatal(err)
		}
		return used - before
	}
	if got := charged(); got != 1000 {
		t.Fatalf("open conflict charged %d", got)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/objects/"+oid, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("page delete=%d %s", code, out)
	}
	var open int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM conflicts WHERE object_id=?`, oid).Scan(&open); err != nil || open != 0 {
		t.Fatalf("a deleted page kept %d conflicts %v", open, err)
	}
	if got := charged(); got > 0 {
		t.Fatalf("a deleted page's conflict still charged %d", got)
	}
}

// A removed team admin stops paying for the team notebooks they created: the team's owner does.
func TestRemovedMembersTeamNotebooksPassToTheTeamOwner(t *testing.T) {
	tm := newTeam(t)
	if _, err := tm.owner.db.Exec(`UPDATE containers SET owner_user_id=? WHERE id=?`, tm.admin.id, tm.child); err != nil {
		t.Fatal(err)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.admin.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove=%d %s", code, out)
	}
	var owner string
	if err := tm.owner.db.QueryRow(`SELECT owner_user_id FROM containers WHERE id=?`, tm.child).Scan(&owner); err != nil || owner != pairUser {
		t.Fatalf("child notebook still charged to %q (%v), want the team owner", owner, err)
	}
}

// An attachment finalized into a notebook deleted meanwhile is not charged to its owner forever.
func TestDeletedNotebooksLeaveTheQuota(t *testing.T) {
	u := newUploadClient(t, func(c *config.Config) { c.Limits.UserQuotaBytes = 10 })
	if _, err := u.db.Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',10,'now')`); err != nil {
		t.Fatal(err)
	}
	if _, err := u.db.Exec(`INSERT INTO attachments(id,container_id,blob_digest,ciphertext_bytes,metadata_ciphertext,key_generation,change_seq,created_at) VALUES('att_late00000000000000000000000',?,'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',10,x'',1,1,'now')`, u.container); err != nil {
		t.Fatal(err)
	}
	if over, err := quotaExceeded(u.db, config.Limits{UserQuotaBytes: 10}, u.container, "", 1); err != nil || !over {
		t.Fatalf("live attachment not charged: %v %v", over, err)
	}
	if _, err := u.db.Exec(`UPDATE containers SET deleted_at='now' WHERE id=?`, u.container); err != nil {
		t.Fatal(err)
	}
	if over, err := userQuotaExceeded(u.db, config.Limits{UserQuotaBytes: 10}, "usr_upload_test", 0, "", 1); err != nil || over {
		t.Fatalf("deleted notebook's attachment still charged: %v %v", over, err)
	}
}

// The comment list is streamed row by row and still answers the same JSON array, empty included.
func TestCommentListStreamsTheSameArray(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.editor.save(t, tm.id, "", 2)
	if code != http.StatusOK {
		t.Fatalf("save=%d", code)
	}
	list := func() []map[string]any {
		code, out := status(t, tm.editor.do(t, http.MethodGet, "/api/v1/objects/"+oid+"/comments", nil, false, false))
		var got []map[string]any
		if code != http.StatusOK || json.Unmarshal([]byte(out), &got) != nil || got == nil {
			t.Fatalf("list=%d %q", code, out)
		}
		return got
	}
	if got := list(); len(got) != 0 {
		t.Fatalf("empty page listed %v", got)
	}
	for _, body := range []string{"Y3Q=", "ZHU="} {
		if code, out := status(t, tm.editor.do(t, http.MethodPost, "/api/v1/objects/"+oid+"/comments", []byte(`{"bodyCiphertext":"`+body+`","keyGeneration":2}`), true, false)); code != http.StatusOK {
			t.Fatalf("comment=%d %s", code, out)
		}
	}
	got := list()
	if len(got) != 2 || got[0]["bodyCiphertext"] != "Y3Q=" || got[1]["bodyCiphertext"] != "ZHU=" || got[0]["username"] == "" {
		t.Fatalf("listed %v", got)
	}
}
