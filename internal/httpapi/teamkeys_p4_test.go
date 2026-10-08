package httpapi

import (
	"encoding/json"
	"net/http"
	"sort"
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
