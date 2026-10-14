package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

type changesPage struct {
	Changes []struct {
		ID, Kind  string
		ChangeSeq int64
		Deleted   bool
	}
	NextCursor string
	HasMore    bool
}

func changes(t *testing.T, p *pairClient, cid, query string) (int, changesPage) {
	t.Helper()
	code, body := status(t, p.do(t, http.MethodGet, "/api/v1/containers/"+cid+"/changes?"+query, nil, false, false))
	var page changesPage
	if code == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &page); err != nil {
			t.Fatal(err)
		}
	}
	return code, page
}

// The cursor moves past every row of a page, so a page may not leave one out.
func TestChangesNeverSkipAnUnreadableRow(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	cid := seedContainer(t, p, "workbook", "", map[string]string{pairUser: "owner"})
	for i, seq := range []any{1, 2, "unreadable"} {
		if _, err := p.db.Exec(`INSERT INTO objects(id,container_id,kind,change_seq,created_at,updated_at) VALUES(?,?,'note',?,'now','now')`, "obj_"+strconv.Itoa(i), cid, seq); err != nil {
			t.Fatal(err)
		}
	}
	if code, page := changes(t, p, cid, "since=0"); code != http.StatusInternalServerError {
		t.Fatalf("unreadable row: %d %+v", code, page)
	}
	if _, err := p.db.Exec(`DELETE FROM objects WHERE id='obj_2'`); err != nil {
		t.Fatal(err)
	}
	if code, page := changes(t, p, cid, "since=0&limit=2"); code != http.StatusOK || len(page.Changes) != 2 || page.HasMore {
		t.Fatalf("exactly one full page: %d %+v", code, page)
	}
	if code, page := changes(t, p, cid, "since=0&limit=1"); code != http.StatusOK || len(page.Changes) != 1 || !page.HasMore || page.NextCursor != "1" {
		t.Fatalf("first of two pages: %d %+v", code, page)
	}
}

// staleConflict saves an object twice, then sends a save from the first version.
func staleConflict(t *testing.T, tm team) (string, int, string) {
	t.Helper()
	tm.rotate(t, tm.id, 1)
	oid, _ := tm.editor.save(t, tm.id, "", 2)
	if _, code := tm.editor.save(t, tm.id, oid, 2); code != http.StatusOK {
		t.Fatalf("save=%d", code)
	}
	stale := map[string]string{"X-Kynotes-Key-Generation": "2", "X-Kynotes-Base-Version": "1", keySchemeHeader: keySchemeShared}
	code, body := tm.editor.rawWrite(t, http.MethodPut, "/api/v1/objects/"+oid, stale, "rejected")
	return oid, code, body
}

func TestResolvedConflictReachesSync(t *testing.T) {
	tm := newTeam(t)
	_, code, body := staleConflict(t, tm)
	var out struct{ ConflictID string }
	if code != http.StatusConflict || json.Unmarshal([]byte(body), &out) != nil || out.ConflictID == "" {
		t.Fatalf("stale save=%d %s", code, body)
	}
	var cursor int64
	if err := tm.owner.db.QueryRow(`SELECT change_seq FROM containers WHERE id=?`, tm.id).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if code, body := status(t, tm.editor.do(t, http.MethodPost, "/api/v1/conflicts/"+out.ConflictID+"/resolve", nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("resolve=%d %s", code, body)
	}
	_, page := changes(t, tm.editor.pairClient, tm.id, "since="+strconv.FormatInt(cursor, 10))
	if len(page.Changes) != 1 || page.Changes[0].ID != out.ConflictID || !page.Changes[0].Deleted {
		t.Fatalf("a client at the cursor misses the resolution: %+v", page)
	}
}

// A conflict copy that never committed must not be reported as kept.
func TestConflictSaveThatFailsToCommitIsNotAConflict(t *testing.T) {
	tm := newTeam(t)
	// A deferred foreign key violation fails at COMMIT, after every statement succeeded.
	for _, stmt := range []string{
		`CREATE TABLE fail_parent(id INTEGER PRIMARY KEY)`,
		`CREATE TABLE fail_child(p INTEGER REFERENCES fail_parent(id) DEFERRABLE INITIALLY DEFERRED)`,
		`CREATE TRIGGER fail_commit AFTER INSERT ON conflicts BEGIN INSERT INTO fail_child VALUES(1); END`,
	} {
		if _, err := tm.owner.db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, code, body := staleConflict(t, tm); code != http.StatusInternalServerError {
		t.Fatalf("uncommitted conflict=%d %s", code, body)
	}
}

func TestListingsFailRatherThanDropARow(t *testing.T) {
	tm := newTeam(t)
	oid, _, _ := staleConflict(t, tm)
	if _, err := tm.owner.db.Exec(`UPDATE conflicts SET base_version='unreadable' WHERE object_id=?`, oid); err != nil {
		t.Fatal(err)
	}
	if code, body := status(t, tm.editor.do(t, http.MethodGet, "/api/v1/objects/"+oid+"/conflicts", nil, false, false)); code != http.StatusInternalServerError {
		t.Fatalf("conflict listing=%d %s", code, body)
	}

	p := tm.owner
	p.deviceID, p.deviceSecret, _ = p.register(t, p.mintToken(t), bytes.Repeat([]byte{7}, 32))
	for _, cid := range []string{tm.id, tm.child} {
		if _, err := p.db.Exec(`INSERT INTO device_containers(device_id,container_id,selected_at) VALUES(?,?,'now')`, p.deviceID, cid); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.db.Exec(`UPDATE containers SET change_seq='unreadable' WHERE id=?`, tm.child); err != nil {
		t.Fatal(err)
	}
	if code, body := status(t, p.doDeviceOnly(t, http.MethodGet, "/api/v1/sync/pending", nil)); code != http.StatusInternalServerError {
		t.Fatalf("pending=%d %s", code, body)
	}
}
