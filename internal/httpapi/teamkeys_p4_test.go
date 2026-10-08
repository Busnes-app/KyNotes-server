package httpapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/config"
)

// legacyList is GET /containers/{id}/legacy as a client decodes it.
type legacyList struct {
	Complete bool `json:"complete"`
	Objects  []struct {
		ID            string `json:"id"`
		KeyGeneration int64  `json:"keyGeneration"`
	} `json:"objects"`
	Comments []struct {
		ID            string `json:"id"`
		ObjectID      string `json:"objectId"`
		AuthorUserID  string `json:"authorUserId"`
		KeyGeneration int64  `json:"keyGeneration"`
	} `json:"comments"`
	Attachments []struct {
		ID            string   `json:"id"`
		ObjectIDs     []string `json:"objectIds"`
		KeyGeneration int64    `json:"keyGeneration"`
	} `json:"attachments"`
	Conflicts []struct {
		ID            string `json:"id"`
		ObjectID      string `json:"objectId"`
		KeyGeneration int64  `json:"keyGeneration"`
	} `json:"conflicts"`
}

func legacyOf(t *testing.T, p *pairClient, cid string) (int, legacyList) {
	t.Helper()
	code, body := status(t, p.do(t, http.MethodGet, "/api/v1/containers/"+cid+"/legacy", nil, false, false))
	var out legacyList
	if code == http.StatusOK && json.Unmarshal([]byte(body), &out) != nil {
		t.Fatalf("legacy list: %s", body)
	}
	return code, out
}

func (l legacyList) objectIDs() []string {
	out := []string{}
	for _, o := range l.Objects {
		out = append(out, o.ID)
	}
	sort.Strings(out)
	return out
}

func TestLegacyRowsListOnlyRowsBelowSharing(t *testing.T) {
	tm := newTeam(t)
	// Before the first rotation (generation 1) every row is sealed with its author's login key: two authors here.
	page, _ := tm.editor.save(t, tm.id, "", 1)
	adminPage, _ := tm.admin.save(t, tm.id, "", 1)
	cmt, _ := tm.editor.comment(t, page, 1)
	if code := tm.editor.attach(t, tm.id, 1); code != http.StatusOK {
		t.Fatalf("attach=%d", code)
	}
	var att string
	if err := tm.owner.db.QueryRow(`SELECT id FROM attachments WHERE container_id=?`, tm.id).Scan(&att); err != nil {
		t.Fatal(err)
	}
	if code, out := status(t, tm.editor.do(t, http.MethodPost, "/api/v1/objects/"+page+"/attachments", []byte(`{"attachmentId":"`+att+`","objectVersion":1}`), true, false)); code != http.StatusNoContent {
		t.Fatalf("ref=%d %s", code, out)
	}
	// A stale save leaves a conflict record at generation 1.
	if code, _ := tm.editor.sendRacing(t, http.MethodPut, "/api/v1/objects/"+page, map[string]string{"X-Kynotes-Key-Generation": "1", "X-Kynotes-Base-Version": "0", keySchemeHeader: keySchemeShared}, []byte("stale"), func() {}); code != http.StatusConflict {
		t.Fatalf("stale save=%d", code)
	}
	// Never shared: nothing is legacy yet.
	if code, got := legacyOf(t, tm.owner, tm.id); code != http.StatusOK || !got.Complete || len(got.Objects)+len(got.Comments)+len(got.Attachments)+len(got.Conflicts) != 0 {
		t.Fatalf("never shared: %d %+v", code, got)
	}

	tm.rotate(t, tm.id, 1) // shared from generation 2
	if _, code := tm.editor.save(t, tm.id, "", 2); code != http.StatusOK {
		t.Fatalf("shared save=%d", code)
	}
	// Any live member reads the list, a viewer included; rows at the shared generation are not in it.
	code, got := legacyOf(t, tm.viewer.pairClient, tm.id)
	want := []string{page, adminPage}
	sort.Strings(want)
	if code != http.StatusOK || !got.Complete || len(got.objectIDs()) != 2 || got.objectIDs()[0] != want[0] || got.objectIDs()[1] != want[1] {
		t.Fatalf("objects: %d %+v", code, got.Objects)
	}
	if len(got.Comments) != 1 || got.Comments[0].ID != cmt || got.Comments[0].ObjectID != page || got.Comments[0].AuthorUserID != tm.editor.id || got.Comments[0].KeyGeneration != 1 {
		t.Fatalf("comments: %+v", got.Comments)
	}
	if len(got.Attachments) != 1 || got.Attachments[0].ID != att || len(got.Attachments[0].ObjectIDs) != 1 || got.Attachments[0].ObjectIDs[0] != page {
		t.Fatalf("attachments: %+v", got.Attachments)
	}
	if len(got.Conflicts) != 1 || got.Conflicts[0].ObjectID != page || got.Conflicts[0].KeyGeneration != 1 {
		t.Fatalf("conflicts: %+v", got.Conflicts)
	}
	// Only the fields the review reads: no version, size or timestamp the client would have to ignore.
	_, raw := status(t, tm.viewer.do(t, http.MethodGet, "/api/v1/containers/"+tm.id+"/legacy", nil, false, false))
	var wire map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		t.Fatal(err)
	}
	for kind, fields := range map[string]string{"objects": "id keyGeneration", "comments": "authorUserId bodyCiphertext id keyGeneration objectId", "attachments": "id keyGeneration metadataCiphertext objectIds", "conflicts": "id keyGeneration objectId"} {
		var rows []map[string]any
		if err := json.Unmarshal(wire[kind], &rows); err != nil || len(rows) == 0 {
			t.Fatalf("%s: %v %s", kind, err, wire[kind])
		}
		keys := []string{}
		for key := range rows[0] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if strings.Join(keys, " ") != fields {
			t.Fatalf("%s fields: %v", kind, keys)
		}
	}

	// Re-sealing each row at the shared generation takes it off the list.
	if _, code := tm.editor.save(t, tm.id, page, 2); code != http.StatusOK {
		t.Fatalf("re-seal=%d", code)
	}
	if code, out := status(t, tm.editor.do(t, http.MethodPut, "/api/v1/comments/"+cmt, []byte(`{"bodyCiphertext":"bmV3","keyGeneration":2}`), true, false)); code != http.StatusNoContent {
		t.Fatalf("comment re-seal=%d %s", code, out)
	}
	if code, out := status(t, tm.editor.do(t, http.MethodDelete, "/api/v1/objects/"+page+"/attachments/"+att, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("detach=%d %s", code, out)
	}
	if code, out := status(t, tm.editor.do(t, http.MethodPost, "/api/v1/conflicts/"+got.Conflicts[0].ID+"/resolve", nil, true, false)); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("resolve=%d %s", code, out)
	}
	_, got = legacyOf(t, tm.editor.pairClient, tm.id)
	if len(got.Objects) != 1 || got.Objects[0].ID != adminPage || len(got.Comments)+len(got.Attachments)+len(got.Conflicts) != 0 {
		t.Fatalf("after re-seal: %+v", got)
	}

	// Strangers and malformed IDs get the same 404.
	stranger := tm.owner.addUser(t, "stranger")
	for _, cid := range []string{tm.id, "cnt_bad"} {
		if code, _ := legacyOf(t, stranger.pairClient, cid); code != http.StatusNotFound {
			t.Fatalf("stranger %s=%d", cid, code)
		}
	}
}

func TestLegacyRowsReportAnIncompleteList(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	db := tm.owner.db
	if _, err := db.Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES('legacy-digest',1,'now')`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= legacyListMax; i++ {
		oid := mint(t, "obj")
		if _, err := db.Exec(`INSERT INTO objects(id,container_id,kind,current_version,change_seq,created_at,updated_at) VALUES(?,?,'note',1,1,'now','now')`, oid, tm.id); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO object_versions(object_id,version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at) VALUES(?,1,'legacy-digest',1,1,1,'now')`, oid); err != nil {
			t.Fatal(err)
		}
	}
	code, got := legacyOf(t, tm.editor.pairClient, tm.id)
	if code != http.StatusOK || got.Complete || len(got.Objects) != legacyListMax {
		t.Fatalf("over the cap: %d complete=%v objects=%d", code, got.Complete, len(got.Objects))
	}
}

func TestLegacyRowsGates(t *testing.T) {
	tm := newTeam(t)
	tm.editor.save(t, tm.id, "", 1)
	tm.rotate(t, tm.id, 1)
	res := tm.viewer.do(t, http.MethodGet, "/api/v1/containers/"+tm.id+"/legacy", nil, false, false)
	if code, _ := status(t, res); code != http.StatusOK || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("member=%d cache=%q", code, res.Header.Get("Cache-Control"))
	}
	// A revoked membership and a deleted container answer the stranger's 404.
	if _, err := tm.owner.db.Exec(`UPDATE memberships SET revoked_at='now' WHERE container_id=? AND user_id=?`, tm.id, tm.viewer.id); err != nil {
		t.Fatal(err)
	}
	if code, _ := legacyOf(t, tm.viewer.pairClient, tm.id); code != http.StatusNotFound {
		t.Fatalf("revoked=%d", code)
	}
	if _, err := tm.owner.db.Exec(`UPDATE containers SET deleted_at='now' WHERE id=?`, tm.child); err != nil {
		t.Fatal(err)
	}
	if code, _ := legacyOf(t, tm.editor.pairClient, tm.child); code != http.StatusNotFound {
		t.Fatalf("deleted=%d", code)
	}
	// Storage errors are 500, never a 404 a client could read as "not a member" or a list it could trust.
	if _, err := tm.owner.db.Exec(`DROP TABLE conflicts`); err != nil {
		t.Fatal(err)
	}
	if code, _ := legacyOf(t, tm.editor.pairClient, tm.id); code != http.StatusInternalServerError {
		t.Fatalf("rows error=%d", code)
	}
	if _, err := tm.owner.db.Exec(`ALTER TABLE memberships RENAME TO memberships_gone`); err != nil {
		t.Fatal(err)
	}
	if code, _ := legacyOf(t, tm.editor.pairClient, tm.id); code != http.StatusInternalServerError {
		t.Fatalf("membership error=%d", code)
	}
}

// Any member can trigger the comment and conflict scans: one per-account bucket at the poll rate.
func TestLegacyRowsAreRateLimitedPerAccount(t *testing.T) {
	tm := newTeam(t)
	limit := config.Defaults().RateLimit.LinkPollPerMinute
	for i := 0; i < limit; i++ {
		if code, _ := legacyOf(t, tm.editor.pairClient, tm.id); code != http.StatusOK {
			t.Fatal(i, code)
		}
	}
	res := tm.editor.do(t, http.MethodGet, "/api/v1/containers/"+tm.id+"/legacy", nil, false, false)
	if code, _ := status(t, res); code != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "1" {
		t.Fatal("past the account's bucket", code, res.Header.Get("Retry-After"))
	}
	// The /api/ alias shares the bucket; other accounts keep their own.
	if code, _ := status(t, tm.editor.do(t, http.MethodGet, "/api/containers/"+tm.id+"/legacy", nil, false, false)); code != http.StatusTooManyRequests {
		t.Fatal("alias", code)
	}
	if code, _ := legacyOf(t, tm.viewer.pairClient, tm.id); code != http.StatusOK {
		t.Fatal("other account", code)
	}
}
